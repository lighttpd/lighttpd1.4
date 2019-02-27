#include "first.h"

/* mod_authn_pam
 * 
 * FUTURE POTENTIAL PERFORMANCE ENHANCEMENTS:
 * - database response is not cached
 *   TODO: db response caching (for limited time) to reduce load on db
 *     (only cache successful logins to prevent cache bloat?)
 *     (or limit number of entries (size) of cache)
 *     (maybe have negative cache (limited size) of names not found in database)
 * - database query is synchronous and blocks waiting for response
 */

#include <security/pam_appl.h>

#include "base.h"
#include "http_auth.h"
#include "log.h"
#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    array *opts;
    const char *service;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

static handler_t mod_authn_pam_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_pam_init) {
    static http_auth_backend_t http_auth_backend_pam =
      { "pam", mod_authn_pam_basic, NULL, NULL };
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_auth_backend_pam */
    http_auth_backend_pam.p_d = p;
    http_auth_backend_set(&http_auth_backend_pam);

    return p;
}

FREE_FUNC(mod_authn_pam_free) {
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;
            array_free(s->opts);
            free(s);
        }
        free(p->config_storage);
    }
    free(p);
    UNUSED(srv);
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_authn_pam_set_defaults) {
    plugin_data *p = p_d;
    config_values_t cv[] = {
        { "auth.backend.pam.opts",          NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
        { NULL,                             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

    for (size_t i = 0; i < srv->config_context->used; ++i) {
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
    }

    if (p->config_storage[0]->service == NULL)
        p->config_storage[0]->service = "http";

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_authn_pam_patch_connection(server *srv, connection *con, plugin_data *p) {
    plugin_config *s = p->config_storage[0];
    PATCH(service);

    /* skip the first, the global context */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = (data_config *)srv->config_context->data[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        s = p->config_storage[i];
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];
            if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.pam.opts"))) {
                PATCH(service);
            }
        }
    }

    return 0;
}
#undef PATCH

static int mod_authn_pam_fn_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)  {
    const char * const pw = (char *)appdata_ptr;
    struct pam_response * const pr = *resp =
      (struct pam_response *)malloc(num_msg * sizeof(struct pam_response));
    for (int i = 0; i < num_msg; ++i) {
        const int style = msg[i]->msg_style;
        pr[i].resp_retcode = 0;
        pr[i].resp = (style==PAM_PROMPT_ECHO_OFF || style==PAM_PROMPT_ECHO_ON)
          ? strdup(pw)
          : NULL;
    }
    return PAM_SUCCESS;
}

static handler_t mod_authn_pam_query(server *srv, connection *con, void *p_d, const buffer *username, const char *realm, const char *pw) {
    plugin_data *p = (plugin_data *)p_d;
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { mod_authn_pam_fn_conv, NULL };
    const int flags = PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK;
    int rc;
    UNUSED(realm);
    *(const char **)&conv.appdata_ptr = pw; /*(cast away const)*/

    mod_authn_pam_patch_connection(srv, con, p);

    rc = pam_start(p->conf.service, username->ptr, &conv, &pamh);
    if (PAM_SUCCESS != rc
     || PAM_SUCCESS !=(rc = pam_set_item(pamh,PAM_RHOST,con->dst_addr_buf->ptr))
     || PAM_SUCCESS !=(rc = pam_authenticate(pamh, flags))
     || PAM_SUCCESS !=(rc = pam_acct_mgmt(pamh, flags)))
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "pam:", pam_strerror(pamh, rc));
    pam_end(pamh, rc);
    return (PAM_SUCCESS == rc) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static handler_t mod_authn_pam_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw) {
    char *realm = require->realm->ptr;
    handler_t rc = mod_authn_pam_query(srv, con, p_d, username, realm, pw);
    if (HANDLER_GO_ON != rc) return rc;
    return http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON  /* access granted */
      : HANDLER_ERROR;
}

int mod_authn_pam_plugin_init(plugin *p);
int mod_authn_pam_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = buffer_init_string("authn_pam");
    p->data        = NULL;
    p->init        = mod_authn_pam_init;
    p->cleanup     = mod_authn_pam_free;
    p->set_defaults= mod_authn_pam_set_defaults;

    return 0;
}
