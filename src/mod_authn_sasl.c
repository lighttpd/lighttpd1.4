#include "first.h"

/* mod_authn_sasl
 * 
 * FUTURE POTENTIAL PERFORMANCE ENHANCEMENTS:
 * - database response is not cached
 *   TODO: db response caching (for limited time) to reduce load on db
 *     (only cache successful logins to prevent cache bloat?)
 *     (or limit number of entries (size) of cache)
 *     (maybe have negative cache (limited size) of names not found in database)
 * - database query is synchronous and blocks waiting for response
 */

#include <sasl/sasl.h>

#include "base.h"
#include "http_auth.h"
#include "log.h"
#include "plugin.h"

#include <sys/utsname.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    array *opts;
    const char *service;
    const char *fqdn;
    const buffer *pwcheck_method;
    const buffer *sasldb_path;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
    buffer *fqdn;
    int initonce;
} plugin_data;

static handler_t mod_authn_sasl_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_sasl_init) {
    static http_auth_backend_t http_auth_backend_sasl =
      { "sasl", mod_authn_sasl_basic, NULL, NULL };
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_auth_backend_sasl */
    http_auth_backend_sasl.p_d = p;
    http_auth_backend_set(&http_auth_backend_sasl);

    return p;
}

FREE_FUNC(mod_authn_sasl_free) {
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->initonce) sasl_done();

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;
            array_free(s->opts);
            free(s);
        }
        free(p->config_storage);
    }
    buffer_free(p->fqdn);
    free(p);
    UNUSED(srv);
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_authn_sasl_set_defaults) {
    plugin_data *p = p_d;
    size_t i;
    config_values_t cv[] = {
        { "auth.backend.sasl.opts",         NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
        { NULL,                             NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        data_config const *config = (data_config const*)srv->config_context->data[i];
        data_string *ds;
        plugin_config *s = calloc(1, sizeof(plugin_config));
        s->opts = array_init();

        cv[0].destination = s->opts;

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (0 == s->opts->used) continue;

        ds = (data_string *)
          array_get_element_klen(s->opts, CONST_STR_LEN("service"));
        s->service = (NULL != ds) ? ds->value->ptr : "http";

        ds = (data_string *)
          array_get_element_klen(s->opts, CONST_STR_LEN("fqdn"));
        if (NULL != ds) s->fqdn = ds->value->ptr;
        if (NULL == s->fqdn) {
            if (NULL == p->fqdn) {
                struct utsname uts;
                if (0 != uname(&uts)) {
                    log_error_write(srv, __FILE__, __LINE__, "ss",
                                    "uname():", strerror(errno));
                    return HANDLER_ERROR;
                }
                p->fqdn = buffer_init_string(uts.nodename);
            }
            s->fqdn = p->fqdn->ptr;
        }

        ds = (data_string *)
          array_get_element_klen(s->opts, CONST_STR_LEN("pwcheck_method"));
        if (NULL != ds) {
            s->pwcheck_method = ds->value;
            if (!buffer_is_equal_string(ds->value, CONST_STR_LEN("saslauthd"))
                && !buffer_is_equal_string(ds->value, CONST_STR_LEN("auxprop"))
                && !buffer_is_equal_string(ds->value, CONST_STR_LEN("sasldb"))){
                log_error_write(srv, __FILE__, __LINE__, "sb",
                                "sasl pwcheck_method must be one of saslauthd, "
                                "sasldb, or auxprop, not:", ds->value);
                return HANDLER_ERROR;
            }
            if (buffer_is_equal_string(ds->value, CONST_STR_LEN("sasldb"))) {
                /* Cyrus libsasl2 expects "auxprop" instead of "sasldb"
                 * (mod_authn_sasl_cb_getopt auxprop_plugin returns "sasldb") */
                buffer_copy_string_len(ds->value, CONST_STR_LEN("auxprop"));
            }
        }

        ds = (data_string *)
          array_get_element_klen(s->opts, CONST_STR_LEN("sasldb_path"));
        if (NULL != ds) s->sasldb_path = ds->value;
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_authn_sasl_patch_connection(server *srv, connection *con, plugin_data *p) {
    plugin_config *s = p->config_storage[0];
    PATCH(service);
    PATCH(fqdn);
    PATCH(pwcheck_method);
    PATCH(sasldb_path);

    /* skip the first, the global context */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = (data_config *)srv->config_context->data[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        s = p->config_storage[i];
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];
            if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.sasl.opts"))) {
                PATCH(service);
                PATCH(fqdn);
                PATCH(pwcheck_method);
                PATCH(sasldb_path);
            }
        }
    }

    return 0;
}
#undef PATCH

static int mod_authn_sasl_cb_getopt(void *p_d, const char *plugin_name, const char *opt, const char **res, unsigned *len) {
    plugin_data *p = (plugin_data *)p_d;
    size_t sz;

    if (0 == strcmp(opt, "pwcheck_method")) {
        if (!buffer_string_is_empty(p->conf.pwcheck_method)) {
            *res = p->conf.pwcheck_method->ptr;
            sz = buffer_string_length(p->conf.pwcheck_method);
        }
        else { /* default */
            *res = "saslauthd";
            sz = sizeof("saslauthd")-1;
        }
    }
    else if (0 == strcmp(opt, "sasldb_path")
             && !buffer_string_is_empty(p->conf.sasldb_path)) {
        *res = p->conf.sasldb_path->ptr;
        sz = buffer_string_length(p->conf.sasldb_path);
    }
    else if (0 == strcmp(opt, "auxprop_plugin")) {
        *res = "sasldb";
        sz = sizeof("sasldb")-1;
    }
    else {
        UNUSED(plugin_name);
        return SASL_FAIL;
    }
 
    if (len) *len = (unsigned int)sz;
    return SASL_OK;
}

static int mod_authn_sasl_cb_log(void *vsrv, int level, const char *message) {
    switch (level) {
     #if 0
      case SASL_LOG_NONE:
      case SASL_LOG_NOTE:
      case SASL_LOG_DEBUG:
      case SASL_LOG_TRACE:
      case SASL_LOG_PASS:
     #endif
      default:
        break;
      case SASL_LOG_ERR:
      case SASL_LOG_FAIL:
      case SASL_LOG_WARN: /* (might omit SASL_LOG_WARN if too noisy in logs) */
        log_error_write((server *)vsrv, __FILE__, __LINE__, "s", message);
        break;
    }
    return SASL_OK;
}

static handler_t mod_authn_sasl_query(server *srv, connection *con, void *p_d, const buffer *username, const char *realm, const char *pw) {
    plugin_data *p = (plugin_data *)p_d;
    sasl_conn_t *sc;
    sasl_callback_t const cb[] = {
      { SASL_CB_GETOPT,   (int(*)())mod_authn_sasl_cb_getopt, (void *) p },
      { SASL_CB_LOG,      (int(*)())mod_authn_sasl_cb_log, (void *) srv },
      { SASL_CB_LIST_END, NULL, NULL }
    };
    int rc;

    mod_authn_sasl_patch_connection(srv, con, p);

    if (!p->initonce) {
        /* must be done once, but after fork() if multiple lighttpd workers */
        rc = sasl_server_init(cb, NULL);
        if (SASL_OK != rc) return HANDLER_ERROR;
        p->initonce = 1;
    }

    rc = sasl_server_new(p->conf.service, p->conf.fqdn,
                         realm, NULL, NULL, cb, 0, &sc);
    if (SASL_OK == rc) {
        rc = sasl_checkpass(sc, CONST_BUF_LEN(username), pw, strlen(pw));
        sasl_dispose(&sc);
    }

    return (SASL_OK == rc) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static handler_t mod_authn_sasl_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw) {
    char *realm = require->realm->ptr;
    handler_t rc = mod_authn_sasl_query(srv, con, p_d, username, realm, pw);
    if (HANDLER_GO_ON != rc) return rc;
    return http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON  /* access granted */
      : HANDLER_ERROR;
}

int mod_authn_sasl_plugin_init(plugin *p);
int mod_authn_sasl_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = buffer_init_string("authn_sasl");
    p->init        = mod_authn_sasl_init;
    p->set_defaults= mod_authn_sasl_set_defaults;
    p->cleanup     = mod_authn_sasl_free;

    p->data        = NULL;

    return 0;
}
