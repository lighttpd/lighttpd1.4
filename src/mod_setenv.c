#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"
#include "http_header.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const array *request_header;
    const array *set_request_header;
    const array *response_header;
    const array *set_response_header;
    const array *environment;
    const array *set_environment;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

typedef struct {
    int handled; /* make sure that we only apply the headers once */
    plugin_config conf;
} handler_ctx;

static handler_ctx * handler_ctx_init(void) {
    handler_ctx * const hctx = calloc(1, sizeof(handler_ctx));
    force_assert(hctx);
    return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
    free(hctx);
}

INIT_FUNC(mod_setenv_init) {
    return calloc(1, sizeof(plugin_data));
}

static void mod_setenv_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* setenv.add-request-header */
        pconf->request_header = cpv->v.a;
        break;
      case 1: /* setenv.add-response-header */
        pconf->response_header = cpv->v.a;
        break;
      case 2: /* setenv.add-environment */
        pconf->environment = cpv->v.a;
        break;
      case 3: /* setenv.set-request-header */
        pconf->set_request_header = cpv->v.a;
        break;
      case 4: /* setenv.set-response-header */
        pconf->set_response_header = cpv->v.a;
        break;
      case 5: /* setenv.set-environment */
        pconf->set_environment = cpv->v.a;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_setenv_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_setenv_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_setenv_patch_config(request_st * const r, plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_setenv_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_setenv_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("setenv.add-request-header"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("setenv.add-response-header"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("setenv.add-environment"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("setenv.set-request-header"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("setenv.set-response-header"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("setenv.set-environment"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_setenv"))
        return HANDLER_ERROR;

    /* future: might create custom data structures here
     * then look up and store http_header_e at config time
     *   enum http_header_e id = http_header_hkey_get(CONST_BUF_LEN(&ds->key));
     */

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* setenv.add-request-header */
              case 1: /* setenv.add-response-header */
              case 2: /* setenv.add-environment */
              case 3: /* setenv.set-request-header */
              case 4: /* setenv.set-response-header */
              case 5: /* setenv.set-environment */
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
            mod_setenv_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_setenv_uri_handler) {
    plugin_data *p = p_d;
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (!hctx)
        r->plugin_ctx[p->id] = hctx = handler_ctx_init();
    else if (hctx->handled)
        return HANDLER_GO_ON;
    hctx->handled = 1;

    mod_setenv_patch_config(r, p, &hctx->conf);

    const array * const aa = hctx->conf.request_header;
    const array * const as = hctx->conf.set_request_header;

    if (aa) {
        for (uint32_t k = 0; k < aa->used; ++k) {
            const data_string * const ds = (const data_string *)aa->data[k];
            const enum http_header_e id =
              http_header_hkey_get(CONST_BUF_LEN(&ds->key));
            http_header_request_append(r, id, CONST_BUF_LEN(&ds->key),
                                                CONST_BUF_LEN(&ds->value));
        }
    }

    if (as) {
        for (uint32_t k = 0; k < as->used; ++k) {
            const data_string * const ds = (const data_string *)as->data[k];
            const enum http_header_e id =
              http_header_hkey_get(CONST_BUF_LEN(&ds->key));
            !buffer_string_is_empty(&ds->value)
              ? http_header_request_set(r, id, CONST_BUF_LEN(&ds->key),
                                               CONST_BUF_LEN(&ds->value))
              : http_header_request_unset(r, id, CONST_BUF_LEN(&ds->key));
        }
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_setenv_handle_request_env) {
    plugin_data *p = p_d;
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    if (hctx->handled > 1) return HANDLER_GO_ON;
    hctx->handled = 2;

    const array * const aa = hctx->conf.environment;
    const array * const as = hctx->conf.set_environment;

    if (aa) {
        for (uint32_t k = 0; k < hctx->conf.environment->used; ++k) {
            const data_string * const ds = (const data_string *)aa->data[k];
            http_header_env_append(r, CONST_BUF_LEN(&ds->key),
                                      CONST_BUF_LEN(&ds->value));
        }
    }

    if (as) {
        for (uint32_t k = 0; k < as->used; ++k) {
            const data_string * const ds = (const data_string *)as->data[k];
            http_header_env_set(r, CONST_BUF_LEN(&ds->key),
                                   CONST_BUF_LEN(&ds->value));
        }
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_setenv_handle_response_start) {
    plugin_data *p = p_d;
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    const array * const aa = hctx->conf.response_header;
    const array * const as = hctx->conf.set_response_header;

    if (aa) {
        for (uint32_t k = 0; k < aa->used; ++k) {
            const data_string * const ds = (const data_string *)aa->data[k];
            const enum http_header_e id =
              http_header_hkey_get(CONST_BUF_LEN(&ds->key));
            http_header_response_insert(r, id, CONST_BUF_LEN(&ds->key),
                                               CONST_BUF_LEN(&ds->value));
        }
    }

    if (as) {
        for (uint32_t k = 0; k < as->used; ++k) {
            const data_string * const ds = (const data_string *)as->data[k];
            const enum http_header_e id =
              http_header_hkey_get(CONST_BUF_LEN(&ds->key));
            !buffer_string_is_empty(&ds->value)
              ? http_header_response_set(r, id, CONST_BUF_LEN(&ds->key),
                                                CONST_BUF_LEN(&ds->value))
              : http_header_response_unset(r, id, CONST_BUF_LEN(&ds->key));
        }
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_setenv_reset) {
    void ** const hctx = r->plugin_ctx+((plugin_data_base *)p_d)->id;
    if (*hctx) { handler_ctx_free(*hctx); *hctx = NULL; }
    return HANDLER_GO_ON;
}

int mod_setenv_plugin_init(plugin *p);
int mod_setenv_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "setenv";

	p->init        = mod_setenv_init;
	p->handle_uri_clean  = mod_setenv_uri_handler;
	p->handle_request_env    = mod_setenv_handle_request_env;
	p->handle_response_start = mod_setenv_handle_response_start;
	p->set_defaults  = mod_setenv_set_defaults;

	p->connection_reset  = mod_setenv_reset;

	return 0;
}
