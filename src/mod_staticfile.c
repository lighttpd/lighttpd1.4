#include "first.h"

#include "log.h"
#include "array.h"
#include "buffer.h"

#include "plugin.h"

#include "request.h"
#include "response.h"
#include "stat_cache.h"

typedef struct {
	const array *exclude_ext;
	unsigned short etags_used;
	unsigned short pathinfo;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

INIT_FUNC(mod_staticfile_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

static void mod_staticfile_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* static-file.exclude-extensions */
        pconf->exclude_ext = cpv->v.a;
        break;
      case 1: /* static-file.etags */
        pconf->etags_used = cpv->v.u;
        break;
      case 2: /* static-file.disable-pathinfo */
        pconf->pathinfo = (0 == cpv->v.u); /*(invert)*/
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_staticfile_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_staticfile_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_staticfile_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_staticfile_merge_config(pconf,
                                        p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_staticfile_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("static-file.exclude-extensions"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("static-file.etags"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("static-file.disable-pathinfo"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_staticfile"))
        return HANDLER_ERROR;

    /* initialize p->defaults from global config context */
    p->defaults.etags_used = 1; /* etags enabled */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_staticfile_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

__attribute_cold__
__attribute_noinline__
static handler_t
mod_staticfile_not_handled(request_st * const r, const char * const msg)
{
    if (r->conf.log_request_handling)
        log_debug(r->conf.errh, __FILE__, __LINE__,
          "-- NOT handling file as static file, %s forbidden", msg);
    return HANDLER_GO_ON;
}

static handler_t
mod_staticfile_process (request_st * const r, plugin_config * const pconf)
{
    if (!pconf->pathinfo && !buffer_is_blank(&r->pathinfo)) {
        return mod_staticfile_not_handled(r, "pathinfo");
    }

    if (pconf->exclude_ext
        && array_match_value_suffix(pconf->exclude_ext, &r->physical.path)) {
        return mod_staticfile_not_handled(r, "extension");
    }

    if (!pconf->etags_used) r->conf.etag_flags = 0;

    /* r->tmp_sce is set in http_response_physical_path_check() and is valid
     * in handle_subrequest_start callback -- handle_subrequest_start callbacks
     * should not change r->physical.path (or should invalidate r->tmp_sce) */
    if (r->tmp_sce && !buffer_is_equal(&r->tmp_sce->name, &r->physical.path))
        r->tmp_sce = NULL;

    http_response_send_file(r, &r->physical.path, r->tmp_sce);

    return HANDLER_FINISHED;
}

URIHANDLER_FUNC(mod_staticfile_subrequest) {
    if (NULL != r->handler_module) return HANDLER_GO_ON;
    if (!http_method_get_head_query_post(r->http_method)) return HANDLER_GO_ON;
    /* r->physical.path is non-empty for handle_subrequest_start */
    /*if (buffer_is_blank(&r->physical.path)) return HANDLER_GO_ON;*/

    plugin_config pconf;
    mod_staticfile_patch_config(r, p_d, &pconf);

    return mod_staticfile_process(r, &pconf);
}


__attribute_cold__
__declspec_dllexport__
int mod_staticfile_plugin_init(plugin *p);
int mod_staticfile_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "staticfile";

	p->init        = mod_staticfile_init;
	p->handle_subrequest_start = mod_staticfile_subrequest;
	p->set_defaults  = mod_staticfile_set_defaults;

	return 0;
}
