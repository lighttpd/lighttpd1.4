#include "first.h"

#include "plugin.h"

#if defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER)

#define USE_LDAP
#include <ldap.h>

#include "server.h"
#include "http_auth.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>

typedef struct {
    LDAP *ldap;

    buffer *ldap_filter_pre;
    buffer *ldap_filter_post;

    buffer *auth_ldap_hostname;
    buffer *auth_ldap_basedn;
    buffer *auth_ldap_binddn;
    buffer *auth_ldap_bindpw;
    buffer *auth_ldap_filter;
    buffer *auth_ldap_cafile;
    unsigned short auth_ldap_starttls;
    unsigned short auth_ldap_allow_empty_pw;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf, *anon_conf; /* this is only used as long as no handler_ctx is setup */

    buffer *ldap_filter;
} plugin_data;

static handler_t mod_authn_ldap_basic(server *srv, connection *con, void *p_d, const buffer *username, const buffer *realm, const char *pw);

INIT_FUNC(mod_authn_ldap_init) {
    static http_auth_backend_t http_auth_backend_ldap =
      { "ldap", mod_authn_ldap_basic, NULL, NULL };
    plugin_data *p = calloc(1, sizeof(*p));
    p->ldap_filter = buffer_init();

    /* register http_auth_backend_ldap */
    http_auth_backend_ldap.p_d = p;
    http_auth_backend_set(&http_auth_backend_ldap);

    return p;
}

FREE_FUNC(mod_authn_ldap_free) {
    plugin_data *p = p_d;

    UNUSED(srv);

    if (!p) return HANDLER_GO_ON;

    buffer_free(p->ldap_filter);

    if (p->config_storage) {
        size_t i;
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (NULL == s) continue;

            buffer_free(s->auth_ldap_hostname);
            buffer_free(s->auth_ldap_basedn);
            buffer_free(s->auth_ldap_binddn);
            buffer_free(s->auth_ldap_bindpw);
            buffer_free(s->auth_ldap_filter);
            buffer_free(s->auth_ldap_cafile);

            buffer_free(s->ldap_filter_pre);
            buffer_free(s->ldap_filter_post);

            if (s->ldap) ldap_unbind_s(s->ldap);

            free(s);
        }
        free(p->config_storage);
    }

    free(p);

    return HANDLER_GO_ON;
}

static handler_t mod_authn_ldap_host_init(server *srv, plugin_config *s) {
    int ret;
#if 0
    if (s->auth_ldap_basedn->used == 0) {
        log_error_write(srv, __FILE__, __LINE__, "s", "ldap: auth.backend.ldap.base-dn has to be set");

        return HANDLER_ERROR;
    }
#endif

    if (buffer_string_is_empty(s->auth_ldap_hostname)) return HANDLER_GO_ON;

    /* free old context */
    if (NULL != s->ldap) ldap_unbind_s(s->ldap);

    if (NULL == (s->ldap = ldap_init(s->auth_ldap_hostname->ptr, LDAP_PORT))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "ldap ...", strerror(errno));

        return HANDLER_ERROR;
    }

    ret = LDAP_VERSION3;
    if (LDAP_OPT_SUCCESS != (ret = ldap_set_option(s->ldap, LDAP_OPT_PROTOCOL_VERSION, &ret))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));

        return HANDLER_ERROR;
    }

    if (s->auth_ldap_starttls) {
        /* if no CA file is given, it is ok, as we will use encryption
         * if the server requires a CAfile it will tell us */
        if (!buffer_string_is_empty(s->auth_ldap_cafile)) {
            if (LDAP_OPT_SUCCESS != (ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE,
                            s->auth_ldap_cafile->ptr))) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                        "Loading CA certificate failed:", ldap_err2string(ret));

                return HANDLER_ERROR;
            }
        }

        if (LDAP_OPT_SUCCESS != (ret = ldap_start_tls_s(s->ldap, NULL,  NULL))) {
            log_error_write(srv, __FILE__, __LINE__, "ss", "ldap startTLS failed:", ldap_err2string(ret));

            return HANDLER_ERROR;
        }
    }


    /* 1. */
    if (!buffer_string_is_empty(s->auth_ldap_binddn)) {
        if (LDAP_SUCCESS != (ret = ldap_simple_bind_s(s->ldap, s->auth_ldap_binddn->ptr, s->auth_ldap_bindpw->ptr))) {
            log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));

            return HANDLER_ERROR;
        }
    } else {
        if (LDAP_SUCCESS != (ret = ldap_simple_bind_s(s->ldap, NULL, NULL))) {
            log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));

            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_authn_ldap_set_defaults) {
    plugin_data *p = p_d;
    size_t i;
config_values_t cv[] = {
        { "auth.backend.ldap.hostname",     NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
        { "auth.backend.ldap.base-dn",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { "auth.backend.ldap.filter",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
        { "auth.backend.ldap.ca-file",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 3 */
        { "auth.backend.ldap.starttls",     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
        { "auth.backend.ldap.bind-dn",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 5 */
        { "auth.backend.ldap.bind-pw",      NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 6 */
        { "auth.backend.ldap.allow-empty-pw",     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 7 */
        { NULL,                             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        data_config const* config = (data_config const*)srv->config_context->data[i];
        plugin_config *s;

        s = calloc(1, sizeof(plugin_config));

        s->auth_ldap_hostname = buffer_init();
        s->auth_ldap_basedn = buffer_init();
        s->auth_ldap_binddn = buffer_init();
        s->auth_ldap_bindpw = buffer_init();
        s->auth_ldap_filter = buffer_init();
        s->auth_ldap_cafile = buffer_init();
        s->auth_ldap_starttls = 0;
        s->ldap_filter_pre = buffer_init();
        s->ldap_filter_post = buffer_init();
        s->ldap = NULL;

        cv[0].destination = s->auth_ldap_hostname;
        cv[1].destination = s->auth_ldap_basedn;
        cv[2].destination = s->auth_ldap_filter;
        cv[3].destination = s->auth_ldap_cafile;
        cv[4].destination = &(s->auth_ldap_starttls);
        cv[5].destination = s->auth_ldap_binddn;
        cv[6].destination = s->auth_ldap_bindpw;
        cv[7].destination = &(s->auth_ldap_allow_empty_pw);

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (!buffer_string_is_empty(s->auth_ldap_filter)) {
            char *dollar;

            /* parse filter */

            if (NULL == (dollar = strchr(s->auth_ldap_filter->ptr, '$'))) {
                log_error_write(srv, __FILE__, __LINE__, "s", "ldap: auth.backend.ldap.filter is missing a replace-operator '$'");

                return HANDLER_ERROR;
            }

            buffer_copy_string_len(s->ldap_filter_pre, s->auth_ldap_filter->ptr, dollar - s->auth_ldap_filter->ptr);
            buffer_copy_string(s->ldap_filter_post, dollar+1);
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_authn_ldap_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH(auth_ldap_hostname);
    PATCH(auth_ldap_basedn);
    PATCH(auth_ldap_binddn);
    PATCH(auth_ldap_bindpw);
    PATCH(auth_ldap_filter);
    PATCH(auth_ldap_cafile);
    PATCH(auth_ldap_starttls);
    PATCH(auth_ldap_allow_empty_pw);
    p->anon_conf = s;
    PATCH(ldap_filter_pre);
    PATCH(ldap_filter_post);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.hostname"))) {
                PATCH(auth_ldap_hostname);
                p->anon_conf = s;
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.base-dn"))) {
                PATCH(auth_ldap_basedn);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.filter"))) {
                PATCH(auth_ldap_filter);
                PATCH(ldap_filter_pre);
                PATCH(ldap_filter_post);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.ca-file"))) {
                PATCH(auth_ldap_cafile);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.starttls"))) {
                PATCH(auth_ldap_starttls);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.bind-dn"))) {
                PATCH(auth_ldap_binddn);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.bind-pw"))) {
                PATCH(auth_ldap_bindpw);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.ldap.allow-empty-pw"))) {
                PATCH(auth_ldap_allow_empty_pw);
            }
        }
    }

    return 0;
}
#undef PATCH

static handler_t mod_authn_ldap_basic(server *srv, connection *con, void *p_d, const buffer *username, const buffer *realm, const char *pw) {
    plugin_data *p = (plugin_data *)p_d;
    LDAP *ldap;
    LDAPMessage *lm, *first;
    char *dn;
    int ret;
    char *attrs[] = { LDAP_NO_ATTRS, NULL };
    size_t i, len;
    UNUSED(realm);

    mod_authn_ldap_patch_connection(srv, con, p);

    /* for now we stay synchronous */

    /*
     * 1. connect anonymously (done in plugin init)
     * 2. get DN for uid = username
     * 3. auth against ldap server
     * 4. (optional) check a field
     * 5. disconnect
     *
     */

    /* check username
     *
     * we have to protect againt username which modifies our filter in
     * an unpleasant way
     */

    len = buffer_string_length(username);
    for (i = 0; i < len; i++) {
        char c = username->ptr[i];

        if (!isalpha(c) &&
            !isdigit(c) &&
            (c != ' ') &&
            (c != '@') &&
            (c != '-') &&
            (c != '_') &&
            (c != '.') ) {

            log_error_write(srv, __FILE__, __LINE__, "sbd", "ldap: invalid character (- _.@a-zA-Z0-9 allowed) in username:", username, i);

            con->http_status = 400; /* Bad Request */
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
    }

    if (p->conf.auth_ldap_allow_empty_pw != 1 && pw[0] == '\0')
        return HANDLER_ERROR;

    /* build filter */
    buffer_copy_buffer(p->ldap_filter, p->conf.ldap_filter_pre);
    buffer_append_string_buffer(p->ldap_filter, username);
    buffer_append_string_buffer(p->ldap_filter, p->conf.ldap_filter_post);


    /* 2. */
    if (p->anon_conf->ldap == NULL ||
        LDAP_SUCCESS != (ret = ldap_search_s(p->anon_conf->ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {

        /* try again (or initial request); the ldap library sometimes fails for the first call but reconnects */
        if (p->anon_conf->ldap == NULL || ret != LDAP_SERVER_DOWN ||
            LDAP_SUCCESS != (ret = ldap_search_s(p->anon_conf->ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {

            if (mod_authn_ldap_host_init(srv, p->anon_conf) != HANDLER_GO_ON)
                return HANDLER_ERROR;

            if (NULL == p->anon_conf->ldap) return HANDLER_ERROR;

            if (LDAP_SUCCESS != (ret = ldap_search_s(p->anon_conf->ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {
                log_error_write(srv, __FILE__, __LINE__, "sssb",
                        "ldap:", ldap_err2string(ret), "filter:", p->ldap_filter);
                return HANDLER_ERROR;
            }
        }
    }

    if (NULL == (first = ldap_first_entry(p->anon_conf->ldap, lm))) {
        log_error_write(srv, __FILE__, __LINE__, "s", "ldap ...");

        ldap_msgfree(lm);

        return HANDLER_ERROR;
    }

    if (NULL == (dn = ldap_get_dn(p->anon_conf->ldap, first))) {
        log_error_write(srv, __FILE__, __LINE__, "s", "ldap ...");

        ldap_msgfree(lm);

        return HANDLER_ERROR;
    }

    ldap_msgfree(lm);


    /* 3. */
    if (NULL == (ldap = ldap_init(p->conf.auth_ldap_hostname->ptr, LDAP_PORT))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "ldap ...", strerror(errno));
        return HANDLER_ERROR;
    }

    ret = LDAP_VERSION3;
    if (LDAP_OPT_SUCCESS != (ret = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ret))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));

        ldap_unbind_s(ldap);

        return HANDLER_ERROR;
    }

    if (p->conf.auth_ldap_starttls == 1) {
        if (LDAP_OPT_SUCCESS != (ret = ldap_start_tls_s(ldap, NULL,  NULL))) {
            log_error_write(srv, __FILE__, __LINE__, "ss", "ldap startTLS failed:", ldap_err2string(ret));

            ldap_unbind_s(ldap);

            return HANDLER_ERROR;
        }
    }


    if (LDAP_SUCCESS != (ret = ldap_simple_bind_s(ldap, dn, pw))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));

        ldap_unbind_s(ldap);

        return HANDLER_ERROR;
    }

    /* 5. */
    ldap_unbind_s(ldap);

    /* everything worked, good, access granted */

    return HANDLER_GO_ON;
}

int mod_authn_ldap_plugin_init(plugin *p);
int mod_authn_ldap_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = buffer_init_string("authn_ldap");
    p->init        = mod_authn_ldap_init;
    p->set_defaults = mod_authn_ldap_set_defaults;
    p->cleanup     = mod_authn_ldap_free;

    p->data        = NULL;

    return 0;
}

#else

int mod_authn_ldap_plugin_init(plugin *p);
int mod_authn_ldap_plugin_init(plugin *p) {
        UNUSED(p);
        return -1;
}

#endif
