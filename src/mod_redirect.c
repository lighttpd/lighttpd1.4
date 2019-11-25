#include "first.h"

#include "base.h"
#include "keyvalue.h"
#include "log.h"
#include "buffer.h"
#include "burl.h"
#include "http_header.h"

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
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_redirect_init) {
    return calloc(1, sizeof(plugin_data));
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

static void mod_redirect_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_redirect_merge_config(&p->conf, p->cvlist+p->cvlist[i].v.u2[0]);
    }
}

static pcre_keyvalue_buffer * mod_redirect_parse_list(server *srv, const array *a, const int condidx) {
    pcre_keyvalue_buffer * const redirect = pcre_keyvalue_buffer_init();
    redirect->x0 = (unsigned short)condidx;
    log_error_st * const errh = srv->errh;
    for (uint32_t j = 0; j < a->used; ++j) {
        data_string *ds = (data_string *)a->data[j];
        if (srv->srvconf.http_url_normalize) {
            pcre_keyvalue_burl_normalize_key(&ds->key, srv->tmp_buf);
            pcre_keyvalue_burl_normalize_value(&ds->value, srv->tmp_buf);
        }
        if (!pcre_keyvalue_buffer_append(errh, redirect, &ds->key, &ds->value)){
            log_error(errh, __FILE__, __LINE__,
              "pcre-compile failed for %s", ds->key.ptr);
            pcre_keyvalue_buffer_free(redirect);
            return NULL;
        }
    }
    return redirect;
}

SETDEFAULTS_FUNC(mod_redirect_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("url.redirect"),
        T_CONFIG_ARRAY,
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
                if (!array_is_kvstring(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s; "
                      "expected list of \"regex\" => \"redirect\"",
                      cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                cpv->v.v =
                  mod_redirect_parse_list(srv, cpv->v.a, p->cvlist[i].k_id);
                if (NULL == cpv->v.v) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* url.redirect-code */
		if (cpv->v.shrt < 100 || cpv->v.shrt >= 1000) cpv->v.shrt = 301;
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.redirect_code = 301;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_redirect_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_redirect_uri_handler) {
    plugin_data * const p = p_d;
    struct burl_parts_t burl;
    pcre_keyvalue_ctx ctx;
    handler_t rc;

    mod_redirect_patch_config(con, p);
    if (!p->conf.redirect || !p->conf.redirect->used) return HANDLER_GO_ON;

    ctx.cache = NULL;
    if (p->conf.redirect->x0) { /*(p->conf.redirect->x0 is context_idx)*/
        ctx.cond_match_count=con->cond_cache[p->conf.redirect->x0].patterncount;
        ctx.cache = con->cond_match + p->conf.redirect->x0;
    }
    ctx.burl = &burl;
    burl.scheme    = con->uri.scheme;
    burl.authority = con->uri.authority;
    burl.port      = sock_addr_get_port(&con->srv_socket->addr);
    burl.path      = con->uri.path_raw;
    burl.query     = con->uri.query;
    if (buffer_string_is_empty(burl.authority))
        burl.authority = con->server_name;

    /* redirect URL on match
     * e.g. redirect /base/ to /index.php?section=base
     */
    rc = pcre_keyvalue_buffer_process(p->conf.redirect, &ctx,
                                      con->request.uri, srv->tmp_buf);
    if (HANDLER_FINISHED == rc) {
        http_header_response_set(con, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 CONST_BUF_LEN(srv->tmp_buf));
        con->http_status = p->conf.redirect_code;
        con->mode = DIRECT;
        con->file_finished = 1;
    }
    else if (HANDLER_ERROR == rc) {
        log_error(con->conf.errh, __FILE__, __LINE__,
          "pcre_exec() error while processing uri: %s",
          con->request.uri->ptr);
    }
    return rc;
}

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
