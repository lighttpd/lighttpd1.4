#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#if defined (USE_OPENSSL)

#include <openssl/rand.h>
#include <openssl/hmac.h>

#define TOKEN_COOKIE_LIFETIME       10*60   /* seconds (10 minutes) */
#define SECRET_SIZE_BYTES           20
/* NOTE: if you decide to change the algo or to make it configurable,
 * make sure not to forget about the TOKEN_SIZE_BYTES define */
#define TOKEN_SIZE_BYTES            20      /* size of token in bytes, sha1 */
#define TIMESTAMP_SIZE_STRING       20      /* max length of the timestamp */
#define TIMESTAMP_SIZE_STRINGZ      TIMESTAMP_SIZE_STRING + 1
#define TOKEN_SIZE_STRING           TOKEN_SIZE_BYTES * 2
#define TOKEN_SIZE_STRINGZ          TOKEN_SIZE_STRING + 1
#define TOKEN_SIZE_FULL_STRING      TIMESTAMP_SIZE_STRING + TOKEN_SIZE_STRING
#define TOKEN_SIZE_FULL_STRINGZ     TOKEN_SIZE_FULL_STRING + 1
/* plugin config for all request/connections */

enum {
    TOKEN_CHECK_OK,
    TOKEN_CHECK_OK_RENEW,
    TOKEN_CHECK_FAILED
};

typedef struct {
    buffer *send_cookie_name;
    buffer *cookie_domain;
    unsigned int cookie_lifetime; /* life time of the cookie in seconds */
    buffer *receive_header_name; /* max number of sessions, 0 == unlimited */
    unsigned short protection;
} plugin_config;

typedef struct {
    PLUGIN_DATA;

    plugin_config **config_storage;
    plugin_config conf;
    unsigned char secret[SECRET_SIZE_BYTES];
} plugin_data;

static int mod_csrf_generate_token(plugin_data *p, const char *user,
                                    time_t expires,
                                    char *out, int out_len) {
    struct tm gm;
    unsigned char *digest;
    unsigned int digest_len = 0;
    buffer *data;

    localtime_r(&expires, &gm);

    data = buffer_init();
    buffer_append_strftime(data, "%s", &gm);

    if (user != NULL) {
        buffer_append_string(data, user);
    }

    digest = HMAC(EVP_sha1(), p->secret, sizeof(p->secret),
                      (unsigned char *)data->ptr, data->used,
                      NULL, &digest_len);
    if (digest == NULL) {
        buffer_free(data);
        return 0;
    }

    buffer_reset(data);
    buffer_append_strftime(data, "%s", &gm);
    buffer_append_string_encoded(data, (char *)digest,
                                 digest_len, ENCODING_HEX);
    memset(out, 0, out_len);
    strncpy(out, data->ptr, out_len - 1);
    buffer_free(data);
    return 1;
}

int mod_csrf_check_token(server *srv, plugin_data *p,
                                 const char* token, const char* user,
                                 time_t *expires) {
    char generated[TOKEN_SIZE_FULL_STRINGZ];
    char sts[TIMESTAMP_SIZE_STRINGZ];
    size_t ts_end;
    struct tm tstm;
    time_t ts;
    int ret = TOKEN_CHECK_FAILED;
    int renew = 0;
    double diff;

    if (!token) {
        return TOKEN_CHECK_FAILED;
    }

    if (strlen(token) <= TOKEN_SIZE_STRING) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                "token check failed: invalid token length");
        return TOKEN_CHECK_FAILED;
    }

    ts_end = strlen(token) - TOKEN_SIZE_STRING;
    if (ts_end > TIMESTAMP_SIZE_STRING) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                "token check failed: invalid timestamp length");
        return TOKEN_CHECK_FAILED;
    }

    memset(sts, 0, TIMESTAMP_SIZE_STRINGZ);
    strncpy(sts, token, ts_end);
    sts[TIMESTAMP_SIZE_STRINGZ - 1] = '\0';

    if (strptime(sts, "%s", &tstm) == NULL) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                "token check failed: could not parse timestamp");
        return TOKEN_CHECK_FAILED;
    }

    ts = mktime(&tstm);
    if (ts == -1) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                "token check failed: invalid timestamp");
        return TOKEN_CHECK_FAILED;
    }

    if (!mod_csrf_generate_token(p, user, ts,
                                 generated, TOKEN_SIZE_FULL_STRINGZ)) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                "token check failed: could not generate comparison token");
        return TOKEN_CHECK_FAILED;
    }

    /* someone tried to feed us an invalid token */
    if (strncmp(token, generated, TOKEN_SIZE_FULL_STRING) != 0) {
        return TOKEN_CHECK_FAILED;
    }

    diff = difftime(ts, time(NULL));

    if ((diff < 0) || (diff > p->conf.cookie_lifetime)) {
        /* this token timed out */
        return TOKEN_CHECK_FAILED;
    }

    /* make sure that tokens are renewed before the timeout elapses */
    if (diff < p->conf.cookie_lifetime / 3) {
        renew = 1;
    }

    if (strncmp(token, generated, TOKEN_SIZE_FULL_STRING) == 0) {
        if (renew) {
            ret = TOKEN_CHECK_OK_RENEW;
        } else {
            ret = TOKEN_CHECK_OK;
        }
    }

    if (expires != NULL) {
        *expires = ts;
    }

    return ret;
}

/* init the plugin data */
INIT_FUNC(mod_csrf_init) {
    plugin_data *p;

    p = calloc(1, sizeof(*p));

    return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_csrf_free) {
    plugin_data *p = p_d;

    UNUSED(srv);

    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        size_t i;
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (NULL == s) continue;

            buffer_free(s->send_cookie_name);
            buffer_free(s->cookie_domain);
            buffer_free(s->receive_header_name);
            free(s);
        }
        free(p->config_storage);
    }

    free(p);

    return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_csrf_set_defaults) {
    plugin_data *p = p_d;
    size_t i = 0;

    config_values_t cv[] = {
        { "csrf.cookie-lifetime",     NULL, T_CONFIG_INT, T_CONFIG_SCOPE_CONNECTION },          /* 0 */
        { "csrf.cookie-domain",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
        { "csrf.send-cookie-name",    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
        { "csrf.receive-header-name", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }        /* 3 */,
        { "csrf.protection",             NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 4 */
        { NULL,                       NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

    if (RAND_bytes(p->secret, SECRET_SIZE_BYTES) == 0) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                "failed to generate secret key");
        return HANDLER_ERROR;
    }

    for (i = 0; i < srv->config_context->used; i++) {
        data_config const* config = (data_config const*)srv->config_context->data[i];
        plugin_config *s;

        s = calloc(1, sizeof(plugin_config));
        s->cookie_lifetime = TOKEN_COOKIE_LIFETIME;
        s->cookie_domain  = buffer_init();
        s->send_cookie_name    = buffer_init();
        s->receive_header_name = buffer_init();
        s->protection = 0;

        cv[0].destination = &(s->cookie_lifetime);
        cv[1].destination = s->cookie_domain;
        cv[2].destination = s->send_cookie_name;
        cv[3].destination = s->receive_header_name;
        cv[4].destination = &(s->protection);

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (buffer_string_is_empty(s->send_cookie_name)) {
            buffer_copy_string_len(s->send_cookie_name,
                                   CONST_STR_LEN("csrf-token"));
        } else {
            size_t j, len = buffer_string_length(s->send_cookie_name);
            for (j = 0; j < len; j++) {
                char c = s->send_cookie_name->ptr[j] | 32;
                if (c < 'a' || c > 'z') {
                    log_error_write(srv, __FILE__, __LINE__, "sb",
                            "invalid character in csrf.write-cookie-name:",
                            s->send_cookie_name);

                    return HANDLER_ERROR;
                }
            }
        }

        if (buffer_string_is_empty(s->receive_header_name)) {
            buffer_copy_string_len(s->receive_header_name, CONST_STR_LEN("X-Csrf-Token"));
        } else {
            size_t j, len = buffer_string_length(s->receive_header_name);
            for (j = 0; j < len; j++) {
                char c = s->receive_header_name->ptr[j] | 32;
                if (c < 'a' || c > 'z') {
                    log_error_write(srv, __FILE__, __LINE__, "sb",
                            "invalid character in csrf.read-cookie-name:",
                            s->receive_header_name);

                    return HANDLER_ERROR;
                }
            }
        }

        if (!buffer_string_is_empty(s->cookie_domain)) {
            size_t j, len = buffer_string_length(s->cookie_domain);
            for (j = 0; j < len; j++) {
                char c = s->cookie_domain->ptr[j];
                if (c <= 32 || c >= 127 || c == '"' || c == '\\') {
                    log_error_write(srv, __FILE__, __LINE__, "sb",
                            "invalid character in csrf.cookie-domain:",
                            s->cookie_domain);

                    return HANDLER_ERROR;
                }
            }
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_csrf_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH(send_cookie_name);
    PATCH(cookie_domain);
    PATCH(cookie_lifetime);
    PATCH(receive_header_name);
    PATCH(protection);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("csrf.send-cookie-name"))) {
                PATCH(send_cookie_name);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("csrf.cookie-lifetime"))) {
                PATCH(cookie_lifetime);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("csrf.cookie-domain"))) {
                PATCH(cookie_domain);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("csrf.receive-header-name"))) {
                PATCH(receive_header_name);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("csrf.protection"))) {
                PATCH(protection);
            }
        }
    }

    return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_csrf_uri_handler) {
    plugin_data *p = p_d;
    data_string *ds;
    unsigned char timestamp[TIMESTAMP_SIZE_STRINGZ];
    char x_csrf[TOKEN_SIZE_FULL_STRINGZ];
    int csrf_found = 0;
    time_t expires;
    data_string *u;
    const char *user = NULL;
    int auth_ok = 0;
    struct tm gm;
    buffer *b;

    mod_csrf_patch_connection(srv, con, p);

    memset(x_csrf, 0, TOKEN_SIZE_FULL_STRINGZ);
    memset(timestamp, 0, TIMESTAMP_SIZE_STRINGZ);

    if (NULL != (ds = (data_string *)array_get_element(con->request.headers,
                                        p->conf.receive_header_name->ptr))) {
        if (strlen(ds->value->ptr) > 0) {
            /* save token for later */
            strncpy(x_csrf, ds->value->ptr, TOKEN_SIZE_FULL_STRING);
            x_csrf[TOKEN_SIZE_FULL_STRINGZ - 1] = '\0';
            csrf_found = 1;
        }
    }

    ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING);
    if (ds == NULL) {
        ds = data_response_init();
    }

    u = (data_string *)array_get_element(con->environment, "REMOTE_USER");

    if ((u != NULL) && (u->value != NULL) && (u->value->ptr != NULL)) {
        user = u->value->ptr;
    }

    if (csrf_found) {
        int check = mod_csrf_check_token(srv, p, x_csrf, user, &expires);
        if ((check == TOKEN_CHECK_OK) || (check == TOKEN_CHECK_OK_RENEW)) {
            auth_ok = 1;
        }

        /* force new tokens if timeout is close or if token was invalid */
        if (check != TOKEN_CHECK_OK) {
            csrf_found = 0;
        }
    }

    if (!csrf_found) {
        expires = time(NULL) + p->conf.cookie_lifetime;
        if (!mod_csrf_generate_token(p, user, expires,
                                     x_csrf, TOKEN_SIZE_FULL_STRINGZ)) {
            con->http_status = 500;
            con->mode = DIRECT;
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "token generation failed");
            return HANDLER_FINISHED;
        }
    }

    buffer_copy_string_len(ds->key, CONST_STR_LEN("Set-Cookie"));

    buffer_copy_buffer(ds->value, p->conf.send_cookie_name);
    buffer_append_string_len(ds->value, CONST_STR_LEN("="));

    buffer_append_string(ds->value, x_csrf);

    buffer_append_string_len(ds->value, CONST_STR_LEN("; Path=/"));

    if (!buffer_string_is_empty(p->conf.cookie_domain)) {
        buffer_append_string_len(ds->value, CONST_STR_LEN("; Domain="));
        buffer_append_string_encoded(ds->value, CONST_BUF_LEN(p->conf.cookie_domain), ENCODING_REL_URI);
    }

    buffer_append_string_len(ds->value, CONST_STR_LEN("; expires="));
    b = buffer_init();
    localtime_r(&expires, &gm);
    buffer_string_prepare_copy(b, 255);
    buffer_append_strftime(b, "%a, %d %b %Y %H:%M:%S GMT", &gm);
    buffer_append_string_buffer(ds->value, b);
    buffer_free(b);

    array_insert_unique(con->response.headers, (data_unset *)ds);

    if (!auth_ok) {
        // deny request only for "forbidden" pages, protection parameter is
        // true if the URL condition was met and is false otherwise
        if (p->conf.protection) {
            con->http_status = 403;
            con->mode = DIRECT;
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "denying request with missing token");
            return HANDLER_FINISHED;
        }
    }

    return HANDLER_GO_ON;
}

int mod_csrf_plugin_init(plugin *p);
int mod_csrf_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("csrf");

    p->init             = mod_csrf_init;
    p->handle_uri_clean = mod_csrf_uri_handler;
    p->set_defaults     = mod_csrf_set_defaults;
    p->cleanup          = mod_csrf_free;

    p->data        = NULL;

    return 0;
}

#else

/* if we don't have openssl support, this plugin does nothing */
int mod_csrf_plugin_init(plugin *p);
int mod_csrf_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = buffer_init_string("csrf");
    return 0;
}

#endif
