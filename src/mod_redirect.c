#include "first.h"

#include "base.h"
#include "keyvalue.h"
#include "log.h"
#include "buffer.h"
#include "burl.h"
#include "http_header.h"
#include "http_status.h"
#include "http_kv.h"    /* http_method_get_or_head() */

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    pcre_keyvalue_buffer *redirect;
    int redirect_code;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

INIT_FUNC(mod_redirect_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_redirect_free) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* url.redirect */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    pcre_keyvalue_buffer_free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static void mod_redirect_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* url.redirect */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->redirect = cpv->v.v;
        break;
      case 1: /* url.redirect-code */
        pconf->redirect_code = cpv->v.shrt;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_redirect_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_redirect_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_redirect_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_redirect_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static pcre_keyvalue_buffer * mod_redirect_parse_list(server *srv, const array *a, const int condidx) {
    const int pcre_jit = config_feature_bool(srv, "server.pcre_jit", 1);
    pcre_keyvalue_buffer * const kvb = pcre_keyvalue_buffer_init();
    kvb->cfgidx = condidx;
    buffer * const tb = srv->tmp_buf;
    int percent = 0;
    for (uint32_t j = 0; j < a->used; ++j) {
        data_string *ds = (data_string *)a->data[j];
        if (srv->srvconf.http_url_normalize) {
            pcre_keyvalue_burl_normalize_key(&ds->key, tb);
            pcre_keyvalue_burl_normalize_value(&ds->value, tb);
        }
        for (const char *s = ds->value.ptr; (s = strchr(s, '%')); ++s) {
            if (s[1] == '%')
                ++s;
            else if (light_isdigit(s[1]) || s[1] == '{') {
                percent |= 1;
                break;
            }
        }
        if (!pcre_keyvalue_buffer_append(srv->errh, kvb, &ds->key, &ds->value,
                                         pcre_jit)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "pcre-compile failed for %s", ds->key.ptr);
            pcre_keyvalue_buffer_free(kvb);
            return NULL;
        }
    }
    if (percent)
        kvb->x0 = config_capture(srv, condidx);
    return kvb;
}

SETDEFAULTS_FUNC(mod_redirect_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("url.redirect"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("url.redirect-code"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_redirect"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* url.redirect */
                cpv->v.v =
                  mod_redirect_parse_list(srv, cpv->v.a, p->cvlist[i].k_id);
                if (NULL == cpv->v.v) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* url.redirect-code */
		if (cpv->v.shrt < 100 || cpv->v.shrt >= 1000) cpv->v.shrt = 0;
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
            mod_redirect_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_redirect_uri_handler) {
    struct burl_parts_t burl;
    pcre_keyvalue_ctx ctx;
    handler_t rc;

    plugin_config pconf;
    mod_redirect_patch_config(r, p_d, &pconf);
    if (!pconf.redirect || !pconf.redirect->used) return HANDLER_GO_ON;

    ctx.cache = NULL;
    if (pconf.redirect->x0) { /*(pconf.redirect->x0 is capture_idx)*/
        ctx.cache = r->cond_match[pconf.redirect->x0 - 1];
    }
    ctx.burl = &burl;
    burl.scheme    = &r->uri.scheme;
    burl.authority = &r->uri.authority;
    burl.port      = sock_addr_get_port(&r->con->srv_socket->addr);
    burl.path      = &r->target; /*(uri-encoded and includes query-part)*/
    burl.query     = &r->uri.query;
    if (buffer_is_blank(burl.authority))
        burl.authority = r->server_name;

    /* redirect URL on match
     * e.g. redirect /base/ to /index.php?section=base
     */
    buffer * const tb = r->tmp_buf;
    rc = pcre_keyvalue_buffer_process(pconf.redirect, &ctx,
                                      &r->target, tb);
    if (HANDLER_FINISHED == rc) {
        http_header_response_set(r, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 BUF_PTR_LEN(tb));
        int status = pconf.redirect_code
                       ? pconf.redirect_code
                       : http_method_get_or_head(r->http_method)
                         || r->http_version == HTTP_VERSION_1_0 ? 301 : 308;
        http_status_set_fin(r, status);
    }
    else if (HANDLER_ERROR == rc) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "pcre_exec() error while processing uri: %s",
          r->target.ptr);
    }
    return rc;
}


__attribute_cold__
__declspec_dllexport__
int mod_redirect_plugin_init(plugin *p);
int mod_redirect_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "redirect";

	p->init        = mod_redirect_init;
	p->handle_uri_clean  = mod_redirect_uri_handler;
	p->set_defaults  = mod_redirect_set_defaults;
	p->cleanup     = mod_redirect_free;

	return 0;
}
