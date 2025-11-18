#include "first.h"

#include "array.h"
#include "buffer.h"
#include "log.h"
#include "http_header.h"
#include "plugin.h"
#include "request.h"

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
} plugin_data;

typedef struct {
    int handled; /* make sure that we only apply the headers once */
    plugin_config conf;
} handler_ctx;

__attribute_malloc__
__attribute_returns_nonnull__
static handler_ctx * handler_ctx_init(void) {
    return ck_calloc(1, sizeof(handler_ctx));
}

static void handler_ctx_free(handler_ctx *hctx) {
    free(hctx);
}

INIT_FUNC(mod_setenv_init) {
    return ck_calloc(1, sizeof(plugin_data));
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

static void mod_setenv_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_setenv_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static void mod_setenv_prep_ext (const array * const ac) {
    array *a;
    *(const array **)&a = ac;
    for (uint32_t i = 0; i < a->used; ++i) {
        data_string * const ds = (data_string *)a->data[i];
        ds->ext = http_header_hkey_get(BUF_PTR_LEN(&ds->key));
        /*(convenience: change all \t \r \n to space)*/
        for (char *s = ds->value.ptr; *s; ++s) {
            if (*s == '\t' || *s == '\r' || *s == '\n') *s = ' ';
        }
        /*(strip trailing and leading whitespace)*/
        const char *s = ds->value.ptr;
        uint32_t n = buffer_clen(&ds->value);
      #ifdef __COVERITY__
        /* coverity narrow-mindedly warns about integer underflow,
         * which is well-defined in C for uint32_t, and even if
         * n == 0 and underflows, is corrected on next line w/ ++n */
        if (0 == n) continue; /*(actually doing this would skip checks; don't)*/
      #endif
        while (n-- && s[n] == ' ') ;
        buffer_truncate(&ds->value, ++n);
        s = ds->value.ptr;
        if (*s == ' ') {
            while (*++s == ' ') ;
            n -= (uint32_t)(s - ds->value.ptr);
            memmove(ds->value.ptr, s, n);
            buffer_truncate(&ds->value, n);
        }
        if ((ds->ext == HTTP_HEADER_OTHER
             && http_request_field_check_name(BUF_PTR_LEN(&ds->key), 1))
            || http_request_field_check_value(BUF_PTR_LEN(&ds->value), 1)) {
            log_warn(NULL, __FILE__, __LINE__,
               "WARNING: setenv.*-header contains invalid char: "
               "%s: %s", ds->key.ptr, ds->value.ptr);
            log_warn(NULL, __FILE__, __LINE__,
              "Use mod_magnet for finer control of request, response headers.");
        }
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

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* setenv.add-request-header */
              case 1: /* setenv.add-response-header */
                mod_setenv_prep_ext(cpv->v.a);
                break;
              case 2: /* setenv.add-environment */
                break;
              case 3: /* setenv.set-request-header */
              case 4: /* setenv.set-response-header */
                mod_setenv_prep_ext(cpv->v.a);
                break;
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
            http_header_request_append(r, ds->ext, BUF_PTR_LEN(&ds->key),
                                                   BUF_PTR_LEN(&ds->value));
        }
    }

    if (as) {
        for (uint32_t k = 0; k < as->used; ++k) {
            const data_string * const ds = (const data_string *)as->data[k];
            !buffer_is_blank(&ds->value)
              ? http_header_request_set(r, ds->ext, BUF_PTR_LEN(&ds->key),
                                                    BUF_PTR_LEN(&ds->value))
              : http_header_request_unset(r, ds->ext, BUF_PTR_LEN(&ds->key));
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
        for (uint32_t k = 0; k < aa->used; ++k) {
            const data_string * const ds = (const data_string *)aa->data[k];
            http_header_env_append(r, BUF_PTR_LEN(&ds->key),
                                      BUF_PTR_LEN(&ds->value));
        }
    }

    if (as) {
        for (uint32_t k = 0; k < as->used; ++k) {
            const data_string * const ds = (const data_string *)as->data[k];
            http_header_env_set(r, BUF_PTR_LEN(&ds->key),
                                   BUF_PTR_LEN(&ds->value));
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
            http_header_response_insert(r, ds->ext, BUF_PTR_LEN(&ds->key),
                                                    BUF_PTR_LEN(&ds->value));
        }
    }

    if (as) {
        for (uint32_t k = 0; k < as->used; ++k) {
            const data_string * const ds = (const data_string *)as->data[k];
            !buffer_is_blank(&ds->value)
              ? http_header_response_set(r, ds->ext, BUF_PTR_LEN(&ds->key),
                                                     BUF_PTR_LEN(&ds->value))
              : http_header_response_unset(r, ds->ext, BUF_PTR_LEN(&ds->key));
        }
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_setenv_handle_request_reset) {
    void ** const hctx = r->plugin_ctx+((plugin_data_base *)p_d)->id;
    if (*hctx) { handler_ctx_free(*hctx); *hctx = NULL; }
    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_setenv_plugin_init(plugin *p);
int mod_setenv_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "setenv";

	p->init        = mod_setenv_init;
	p->set_defaults= mod_setenv_set_defaults;
	p->handle_uri_clean  = mod_setenv_uri_handler;
	p->handle_request_env    = mod_setenv_handle_request_env;
	p->handle_response_start = mod_setenv_handle_response_start;
	p->handle_request_reset  = mod_setenv_handle_request_reset;


	return 0;
}
