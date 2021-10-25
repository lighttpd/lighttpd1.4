#include "first.h"

#include "array.h"
#include "buffer.h"
#include "log.h"
#include "http_chunk.h"
#include "http_header.h"
#include "request.h"
#include "stat_cache.h"

#include "plugin.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const array *extensions;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_flv_streaming_init) {
    return calloc(1, sizeof(plugin_data));
}

static void mod_flv_streaming_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* flv-streaming.extensions */
        pconf->extensions = cpv->v.a;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_flv_streaming_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_flv_streaming_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_flv_streaming_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_flv_streaming_merge_config(&p->conf,
                                           p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_flv_streaming_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("flv-streaming.extensions"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_flv_streaming"))
        return HANDLER_ERROR;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_flv_streaming_merge_config(&p->defaults, cpv);
    }

    log_error(NULL, __FILE__, __LINE__,
      "Warning: mod_%s is deprecated "
      "and will be removed from a future lighttpd release in early 2022. "
      "https://wiki.lighttpd.net/Docs_ConfigurationOptions#Deprecated",
      p->self->name);

    return HANDLER_GO_ON;
}

static off_t get_param_value(buffer *qb, const char *m, size_t mlen) {
    const char * const q = qb->ptr;
    size_t len = buffer_clen(qb);
    if (len < mlen+2) return -1;
    len -= (mlen+2);
    for (size_t i = 0; i <= len; ++i) {
        if (0 == memcmp(q+i, m, mlen) && q[i+mlen] == '=') {
            char *err;
            off_t n = strtoll(q+i+mlen+1, &err, 10);
            return (*err == '\0' || *err == '&') ? n : -1;
        }
        do { ++i; } while (i < len && q[i] != '&');
    }
    return -1;
}

URIHANDLER_FUNC(mod_flv_streaming_path_handler) {
	plugin_data *p = p_d;

	if (NULL != r->handler_module) return HANDLER_GO_ON;
	if (buffer_is_blank(&r->physical.path)) return HANDLER_GO_ON;

	mod_flv_streaming_patch_config(r, p);
	if (NULL == p->conf.extensions) return HANDLER_GO_ON;

	if (!array_match_value_suffix(p->conf.extensions, &r->physical.path)) {
		/* not found */
		return HANDLER_GO_ON;
	}

	off_t start = get_param_value(&r->uri.query, CONST_STR_LEN("start"));
	off_t end = get_param_value(&r->uri.query, CONST_STR_LEN("end"));
	off_t len = -1;
	if (start < 0) start = 0;
	if (start < end)
		len = end - start + 1;
	else if (0 == start)
		return HANDLER_GO_ON; /* let mod_staticfile send whole file */

	stat_cache_entry * const sce =
	  stat_cache_get_entry_open(&r->physical.path, r->conf.follow_symlink);
	if (NULL == sce || (sce->fd < 0 && 0 != sce->st.st_size)) {
		r->http_status = (errno == ENOENT) ? 404 : 403;
		return HANDLER_FINISHED;
	}
	if (len == -1 || sce->st.st_size - start < len)
		len = sce->st.st_size - start;
	if (len <= 0)
		return HANDLER_FINISHED;

			/* if there is a start=[0-9]+ in the header use it as start,
			 * otherwise set start to beginning of file */
			/* if there is a end=[0-9]+ in the header use it as end pos,
			 * otherwise send rest of file, starting from start */

			/* let's build a flv header */
			http_chunk_append_mem(r, CONST_STR_LEN("FLV\x1\x1\0\0\0\x9\0\0\0\x9"));
			http_chunk_append_file_ref_range(r, sce, start, len);
			http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("video/x-flv"));
			r->resp_body_finished = 1;
			return HANDLER_FINISHED;
}


int mod_flv_streaming_plugin_init(plugin *p);
int mod_flv_streaming_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "flv_streaming";

	p->init        = mod_flv_streaming_init;
	p->handle_physical = mod_flv_streaming_path_handler;
	p->set_defaults  = mod_flv_streaming_set_defaults;

	return 0;
}
