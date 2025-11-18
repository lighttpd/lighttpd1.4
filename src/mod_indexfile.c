#include "first.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "http_header.h"
#include "log.h"
#include "plugin.h"
#include "request.h"
#include "stat_cache.h"

typedef struct {
    const array *indexfiles;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

INIT_FUNC(mod_indexfile_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

static void mod_indexfile_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* index-file.names */
      case 1: /* server.indexfiles */
        pconf->indexfiles = cpv->v.a;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_indexfile_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_indexfile_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_indexfile_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_indexfile_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_indexfile_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("index-file.names"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.indexfiles"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_indexfile"))
        return HANDLER_ERROR;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_indexfile_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

__attribute_nonnull__()
static handler_t mod_indexfile_tryfiles(request_st * const r, const array * const indexfiles) {
	for (uint32_t k = 0; k < indexfiles->used; ++k) {
		const buffer * const v = &((data_string *)indexfiles->data[k])->value;
		buffer * const b = (v->ptr[0] != '/')
		  ? &r->physical.path
		  : &r->physical.doc_root; /* index file relative to doc_root */
			/* if the index-file starts with a prefix as use this file as
			 * index-generator */

		/* temporarily append to base-path buffer to check existence */
		const uint32_t len = buffer_clen(b);
		buffer_append_path_len(b, BUF_PTR_LEN(v));

		const stat_cache_st * const st = stat_cache_path_stat(b);

		buffer_truncate(b, len);

		if (NULL == st) {
			switch (errno) {
			case ENOENT:
			case ENOTDIR:
				continue;
			case EACCES:
				r->http_status = 403;
				return HANDLER_FINISHED;
			default:
				/* we have no idea what happened. let's tell the user so. */
				r->http_status = 500;
				log_perror(r->conf.errh, __FILE__, __LINE__,
				  "index file error for request: %s -> %s",
				  r->uri.path.ptr, r->physical.path.ptr);
				return HANDLER_FINISHED;
			}
		}

		/* found */
		if (v->ptr[0] == '/') {
			/* replace uri.path */
			buffer_copy_buffer(&r->uri.path, v);
			http_header_env_set(r, CONST_STR_LEN("PATH_TRANSLATED_DIRINDEX"),
			                       BUF_PTR_LEN(&r->physical.path));
			buffer_copy_path_len2(&r->physical.path,
			                      BUF_PTR_LEN(&r->physical.doc_root),
			                      BUF_PTR_LEN(v));
			/*(XXX: not done historical, but rel_path probably should be updated)*/
			/*buffer_copy_buffer(&r->physical.rel_path, v);*/
		} else {
			/* append to uri.path the relative path to index file (/ -> /index.php) */
			buffer_append_string_buffer(&r->uri.path, v);
			buffer_append_path_len(&r->physical.path, BUF_PTR_LEN(v));
			/*(XXX: not done historical, but rel_path probably should be updated)*/
			/*buffer_append_path_len(&r->physical.rel_path, BUF_PTR_LEN(v));*/
		}
		return HANDLER_GO_ON;
	}

	/* not found */
	return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_indexfile_subrequest) {
    if (NULL != r->handler_module) return HANDLER_GO_ON;
    if (!buffer_has_slash_suffix(&r->uri.path)) return HANDLER_GO_ON;

    plugin_config pconf;
    mod_indexfile_patch_config(r, p_d, &pconf);
    if (NULL == pconf.indexfiles) return HANDLER_GO_ON;

    if (r->conf.log_request_handling) {
        log_debug(r->conf.errh, __FILE__, __LINE__,
          "-- handling the request as Indexfile");
        log_debug(r->conf.errh, __FILE__, __LINE__,
          "URI          : %s", r->uri.path.ptr);
    }

    return mod_indexfile_tryfiles(r, pconf.indexfiles);
}


__attribute_cold__
__declspec_dllexport__
int mod_indexfile_plugin_init(plugin *p);
int mod_indexfile_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "indexfile";

	p->init        = mod_indexfile_init;
	p->handle_subrequest_start = mod_indexfile_subrequest;
	p->set_defaults  = mod_indexfile_set_defaults;

	return 0;
}
