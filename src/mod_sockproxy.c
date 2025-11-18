/*
 * mod_sockproxy - socket-level proxy support for lighttpd
 *
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "gw_backend.h"
typedef gw_plugin_config plugin_config;
typedef gw_plugin_data   plugin_data;
typedef gw_handler_ctx   handler_ctx;

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"

/**
 *
 * socket proxy (with optional buffering)
 *
 */

static void mod_sockproxy_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* sockproxy.server */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            gw_plugin_config * const gw = cpv->v.v;
            pconf->exts      = gw->exts;
            pconf->exts_auth = gw->exts_auth;
            pconf->exts_resp = gw->exts_resp;
        }
        break;
      case 1: /* sockproxy.balance */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->balance = (int)cpv->v.u;
        break;
      case 2: /* sockproxy.debug */
        pconf->debug = (int)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_sockproxy_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_sockproxy_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_sockproxy_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_sockproxy_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_sockproxy_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("sockproxy.server"),
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("sockproxy.balance"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("sockproxy.debug"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_sockproxy"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        gw_plugin_config *gw = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* sockproxy.server */
                gw = ck_calloc(1, sizeof(gw_plugin_config));
                if (!gw_set_defaults_backend(srv, p, cpv->v.a, gw, 0,
                                             cpk[cpv->k_id].k)) {
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                cpv->v.v = gw;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* sockproxy.balance */
                cpv->v.u = (unsigned int)gw_get_defaults_balance(srv, cpv->v.b);
                break;
              case 2: /* sockproxy.debug */
                break;
              default:/* should not happen */
                break;
            }
        }

        /* disable check-local for all exts (default enabled) */
        if (gw && gw->exts) { /*(check after gw_set_defaults_backend())*/
            gw_exts_clear_check_local(gw->exts);
        }
    }

    /* default is 0 */
    /*p->defaults.balance = (unsigned int)gw_get_defaults_balance(srv, NULL);*/

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_sockproxy_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


static handler_t sockproxy_create_env_connect(handler_ctx *hctx) {
	request_st * const r = hctx->r;
	r->resp_body_started = 1;
	gw_set_transparent(hctx);
	http_response_upgrade_read_body_unknown(r);

	plugin_stats_inc("sockproxy.requests");
	return HANDLER_GO_ON;
}


static handler_t mod_sockproxy_connection_accept(connection *con, void *p_d) {
	request_st * const r = &con->request;
	handler_t rc;

	if (NULL != r->handler_module) return HANDLER_GO_ON;

	plugin_config pconf;
	mod_sockproxy_patch_config(r, p_d, &pconf);
	if (NULL == pconf.exts) return HANDLER_GO_ON;

	/*(fake r->uri.path for matching purposes in gw_check_extension())*/
	buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/"));

	rc = gw_check_extension(r, &pconf, p_d, 1, 0);
	if (HANDLER_GO_ON != rc) return rc;

	const plugin_data * const p = p_d;
	if (r->handler_module == p->self) {
		handler_ctx *hctx = r->plugin_ctx[p->id];
		hctx->opts.backend = BACKEND_PROXY;
		hctx->create_env = sockproxy_create_env_connect;
		hctx->response = chunk_buffer_acquire();
		r->http_status = -1; /*(skip HTTP processing)*/
		r->http_version = HTTP_VERSION_UNSET;
	}

	return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_sockproxy_plugin_init(plugin *p);
int mod_sockproxy_plugin_init(plugin *p) {
	p->version      = LIGHTTPD_VERSION_ID;
	p->name         = "sockproxy";

	p->init         = gw_init;
	p->cleanup      = gw_free;
	p->set_defaults = mod_sockproxy_set_defaults;
	p->handle_request_reset    = gw_handle_request_reset;
	p->handle_connection_accept= mod_sockproxy_connection_accept;
	p->handle_subrequest       = gw_handle_subrequest;
	p->handle_trigger          = gw_handle_trigger;
	p->handle_waitpid          = gw_handle_waitpid_cb;

	return 0;
}
