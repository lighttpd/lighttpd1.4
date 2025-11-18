/*
 * mod_authn_sasl - SASL backend for lighttpd HTTP auth
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
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

#ifndef _WIN32
#include <sys/utsname.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <sasl/sasl.h>

#include "mod_auth_api.h"
#include "base.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    const char *service;
    const char *fqdn;
    const buffer *pwcheck_method;
    const buffer *sasldb_path;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;

    int initonce;
} plugin_data;

static handler_t mod_authn_sasl_basic(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_sasl_init) {
    static http_auth_backend_t http_auth_backend_sasl =
      { "sasl", mod_authn_sasl_basic, NULL, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_auth_backend_sasl */
    http_auth_backend_sasl.p_d = p;
    http_auth_backend_set(&http_auth_backend_sasl);

    return p;
}

FREE_FUNC(mod_authn_sasl_free) {
    plugin_data * const p = p_d;
    if (p->initonce) sasl_done();
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.sasl.opts */
                if (cpv->vtype == T_CONFIG_LOCAL) free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static void mod_authn_sasl_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.sasl.opts */
        if (cpv->vtype == T_CONFIG_LOCAL)
            memcpy(pconf, cpv->v.v, sizeof(plugin_config));
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_authn_sasl_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_authn_sasl_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_authn_sasl_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_sasl_merge_config(pconf,
                                        p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static plugin_config * mod_authn_sasl_parse_opts(server *srv, const array * const opts) {
    const data_string *ds;
    const char *service = NULL;
    const char *fqdn = NULL;
    const buffer *pwcheck_method = NULL;
    const buffer *sasldb_path = NULL;

    ds = (const data_string *)
      array_get_element_klen(opts, CONST_STR_LEN("service"));
    service = (NULL != ds) ? ds->value.ptr : "http";

    ds = (const data_string *)
      array_get_element_klen(opts, CONST_STR_LEN("fqdn"));
    if (NULL != ds) fqdn = ds->value.ptr;
    if (NULL == fqdn) {
      #ifndef _WIN32
        static struct utsname uts;
        if (uts.nodename[0] == '\0') {
            if (0 != uname(&uts)) {
                log_perror(srv->errh, __FILE__, __LINE__, "uname()");
                return NULL;
            }
        }
        fqdn = uts.nodename;
      #else
        fqdn = getenv("HOSTNAME");
        if (NULL == fqdn) {
            log_error(srv->errh, __FILE__, __LINE__,
              "auth.backend.sasl.opts missing fqdn");
            return NULL;
        }
      #endif
    }

    ds = (const data_string *)
      array_get_element_klen(opts, CONST_STR_LEN("pwcheck_method"));
    if (NULL != ds) {
        pwcheck_method = &ds->value;
        if (!buffer_is_equal_string(&ds->value, CONST_STR_LEN("saslauthd"))
            && !buffer_is_equal_string(&ds->value, CONST_STR_LEN("auxprop"))
            && !buffer_is_equal_string(&ds->value, CONST_STR_LEN("sasldb"))){
            log_error(srv->errh, __FILE__, __LINE__,
              "sasl pwcheck_method must be one of saslauthd, "
              "sasldb, or auxprop, not: %s", ds->value.ptr);
            return NULL;
        }
        if (buffer_is_equal_string(&ds->value, CONST_STR_LEN("sasldb"))) {
            /* Cyrus libsasl2 expects "auxprop" instead of "sasldb"
             * (mod_authn_sasl_cb_getopt auxprop_plugin returns "sasldb") */
            buffer *b;
            *(const buffer **)&b = &ds->value;
            buffer_copy_string_len(b, CONST_STR_LEN("auxprop"));
        }
    }
    else {
        static const buffer saslauthd = { "saslauthd", sizeof("saslauthd"), 0 };
        pwcheck_method = &saslauthd;
    }

    ds = (const data_string *)
      array_get_element_klen(opts, CONST_STR_LEN("sasldb_path"));
    if (NULL != ds && !buffer_is_blank(&ds->value)) sasldb_path = &ds->value;

    plugin_config *pconf = ck_malloc(sizeof(plugin_config));
    pconf->service = service;
    pconf->fqdn = fqdn;
    pconf->pwcheck_method = pwcheck_method;
    pconf->sasldb_path = sasldb_path;
    return pconf;
}

SETDEFAULTS_FUNC(mod_authn_sasl_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.sasl.opts"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_sasl"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.sasl.opts */
                if (cpv->v.a->used) {
                    cpv->v.v = mod_authn_sasl_parse_opts(srv, cpv->v.a);
                    if (NULL == cpv->v.v) return HANDLER_ERROR;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_sasl_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static int mod_authn_sasl_cb_getopt(void *p_c, const char *plugin_name, const char *opt, const char **res, unsigned *len) {
    const plugin_config * const pconf = (plugin_config *)p_c;
    size_t sz;

    if (0 == strcmp(opt, "pwcheck_method")) {
        *res = pconf->pwcheck_method->ptr;
        sz = buffer_clen(pconf->pwcheck_method);
    }
    else if (0 == strcmp(opt, "sasldb_path") && pconf->sasldb_path) {
        *res = pconf->sasldb_path->ptr;
        sz = buffer_clen(pconf->sasldb_path);
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

static int mod_authn_sasl_cb_log(void *vreq, int level, const char *message) {
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
        level = (level == SASL_LOG_WARN) ? 4 : 3; /* LOG_WARNING 4, LOG_ERR 3 */
        log_pri(((request_st *)vreq)->conf.errh, __FILE__, __LINE__, level,
                "%s", message);
        break;
    }
    return SASL_OK;
}

static handler_t mod_authn_sasl_query(request_st * const r, plugin_data * const p, const buffer * const username, const char * const realm, const char * const pw) {
    plugin_config pconf;
    sasl_conn_t *sc;
    sasl_callback_t const cb[] = {
      { SASL_CB_GETOPT,   (int(*)(void))(uintptr_t)mod_authn_sasl_cb_getopt, (void *) &pconf },
      { SASL_CB_LOG,      (int(*)(void))(uintptr_t)mod_authn_sasl_cb_log, (void *) r },
      { SASL_CB_LIST_END, NULL, NULL }
    };
    int rc;

    mod_authn_sasl_patch_config(r, p, &pconf);

    if (!p->initonce) {
        /* must be done once, but after fork() if multiple lighttpd workers */
        rc = sasl_server_init(cb, NULL);
        if (SASL_OK != rc) return HANDLER_ERROR;
        p->initonce = 1;
    }

    rc = sasl_server_new(pconf.service, pconf.fqdn,
                         realm, NULL, NULL, cb, 0, &sc);
    if (SASL_OK == rc) {
        rc = sasl_checkpass(sc, BUF_PTR_LEN(username), pw, strlen(pw));
        sasl_dispose(&sc);
    }

    return (SASL_OK == rc) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static handler_t mod_authn_sasl_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    char *realm = require->realm->ptr;
    handler_t rc = mod_authn_sasl_query(r, p_d, username, realm, pw);
    if (HANDLER_GO_ON != rc) return rc;
    return http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON  /* access granted */
      : HANDLER_ERROR;
}


__attribute_cold__
__declspec_dllexport__
int mod_authn_sasl_plugin_init(plugin *p);
int mod_authn_sasl_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "authn_sasl";
    p->init        = mod_authn_sasl_init;
    p->set_defaults= mod_authn_sasl_set_defaults;
    p->cleanup     = mod_authn_sasl_free;

    return 0;
}
