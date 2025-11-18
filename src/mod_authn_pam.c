/*
 * mod_authn_pam - PAM backend for lighttpd HTTP auth
 *
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
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

#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include "mod_auth_api.h"
#include "base.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    const char *service;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

static handler_t mod_authn_pam_basic(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_pam_init) {
    static http_auth_backend_t http_auth_backend_pam =
      { "pam", mod_authn_pam_basic, NULL, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_auth_backend_pam */
    http_auth_backend_pam.p_d = p;
    http_auth_backend_set(&http_auth_backend_pam);

    return p;
}

static void mod_authn_pam_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.pam.opts */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->service = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_authn_pam_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_authn_pam_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_authn_pam_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_pam_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_authn_pam_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.pam.opts"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_pam"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.pam.opts */
                if (cpv->v.a->used) {
                    const data_string *ds = (const data_string *)
                      array_get_element_klen(cpv->v.a,CONST_STR_LEN("service"));
                    *(const void **)&cpv->v.v =
                      (NULL != ds) ? ds->value.ptr : "http";
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.service = "http";

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_pam_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static int mod_authn_pam_fn_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)  {
    const char * const pw = (char *)appdata_ptr;
    struct pam_response * const pr = *resp =
      (struct pam_response *)ck_malloc(num_msg * sizeof(struct pam_response));
    for (int i = 0; i < num_msg; ++i) {
        const int style = msg[i]->msg_style;
        pr[i].resp_retcode = 0;
        pr[i].resp = (style==PAM_PROMPT_ECHO_OFF || style==PAM_PROMPT_ECHO_ON)
          ? strdup(pw)
          : NULL;
    }
    return PAM_SUCCESS;
}

static handler_t mod_authn_pam_query(request_st * const r, void *p_d, const buffer * const username, const char * const realm, const char * const pw) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { mod_authn_pam_fn_conv, NULL };
    const int flags = PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK;
    int rc;
    UNUSED(realm);
    *(const char **)&conv.appdata_ptr = pw; /*(cast away const)*/

    plugin_config pconf;
    mod_authn_pam_patch_config(r, p_d, &pconf);

    const char * const addrstr = r->dst_addr_buf->ptr;
    rc = pam_start(pconf.service, username->ptr, &conv, &pamh);
    if (PAM_SUCCESS != rc
     || PAM_SUCCESS !=(rc = pam_set_item(pamh, PAM_RHOST, addrstr))
     || PAM_SUCCESS !=(rc = pam_authenticate(pamh, flags))
     || PAM_SUCCESS !=(rc = pam_acct_mgmt(pamh, flags)))
        log_error(r->conf.errh, __FILE__, __LINE__,
          "pam: %s", pam_strerror(pamh, rc));
    pam_end(pamh, rc);
    return (PAM_SUCCESS == rc) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static handler_t mod_authn_pam_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    char *realm = require->realm->ptr;
    handler_t rc = mod_authn_pam_query(r, p_d, username, realm, pw);
    if (HANDLER_GO_ON != rc) return rc;
    return http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON  /* access granted */
      : HANDLER_ERROR;
}


__attribute_cold__
__declspec_dllexport__
int mod_authn_pam_plugin_init(plugin *p);
int mod_authn_pam_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "authn_pam";
    p->init        = mod_authn_pam_init;
    p->set_defaults= mod_authn_pam_set_defaults;

    return 0;
}
