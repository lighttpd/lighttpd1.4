#include "first.h"

#include "mod_cml.h"

#include "base.h"
#include "buffer.h"
#include "log.h"
#include "plugin.h"

#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>

INIT_FUNC(mod_cml_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_cml_free) {
    plugin_data * const p = p_d;
    free(p->trigger_handler.ptr);
    free(p->basedir.ptr);
    free(p->baseurl.ptr);
    if (NULL == p->cvlist) return;
  #if defined(USE_MEMCACHED)
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 1: /* cml.memcache-hosts */
                if (cpv->vtype == T_CONFIG_LOCAL && NULL != cpv->v.v)
                    memcached_free(cpv->v.v); /* mod_cml_free_memcached() */
                break;
              default:
                break;
            }
        }
    }
  #endif
}

static int mod_cml_init_memcached(server *srv, config_plugin_value_t * const cpv) {
    const array * const mc_hosts = cpv->v.a;
    if (0 == mc_hosts->used) {
        cpv->v.v = NULL;
        return 1;
    }

  #if defined(USE_MEMCACHED)

    buffer * const opts = srv->tmp_buf;
    buffer_clear(opts);
    for (uint32_t k = 0; k < mc_hosts->used; ++k) {
        const data_string * const ds = (const data_string *)mc_hosts->data[k];
        buffer_append_string_len(opts, CONST_STR_LEN(" --SERVER="));
        buffer_append_string_buffer(opts, &ds->value);
    }

    cpv->v.v = memcached(opts->ptr+1, buffer_clen(opts)-1);

    if (cpv->v.v) {
        cpv->vtype = T_CONFIG_LOCAL;
        return 1;
    }
    else {
        log_error(srv->errh, __FILE__, __LINE__,
          "configuring memcached failed for option string: %s", opts->ptr);
        return 0;
    }

  #else

    log_error(srv->errh, __FILE__, __LINE__,
      "memcache support is not compiled in but cml.memcache-hosts is set, "
      "aborting");
    return 0;

  #endif
}

static void mod_cml_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* cml.extension */
        pconf->ext = cpv->v.b;
        break;
      case 1: /* cml.memcache-hosts *//* setdefaults inits memcached_st *memc */
       #if defined(USE_MEMCACHED)
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->memc = cpv->v.v;
       #endif
        break;
      case 2: /* cml.memcache-namespace */
        /*pconf->mc_namespace = cpv->v.b;*//*(unused)*/
        break;
      case 3: /* cml.power-magnet */
        pconf->power_magnet = cpv->v.b;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_cml_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_cml_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_cml_patch_config(request_st * const r, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_cml_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_cml_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("cml.extension"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cml.memcache-hosts"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cml.memcache-namespace"), /*(unused)*/
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cml.power-magnet"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_cml"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* cml.extension */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 1: /* cml.memcache-hosts */ /* config converted to memc handles */
                if (!mod_cml_init_memcached(srv, cpv)) {
                    return HANDLER_ERROR;
                }
                break;
              case 2: /* cml.memcache-namespace *//*(unused)*/
                break;
              case 3: /* cml.power-magnet */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
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
            mod_cml_merge_config(&p->defaults, cpv);
    }

    log_error(srv->errh, __FILE__, __LINE__,
      "Warning: mod_%s is deprecated "
      "and will be removed from a future lighttpd release in early 2022. "
      "https://wiki.lighttpd.net/Docs_ConfigurationOptions#Deprecated",
      p->self->name);

    return HANDLER_GO_ON;
}

static int cache_call_lua(request_st * const r, plugin_data * const p, const buffer * const cml_file) {
	buffer *b;
	char *c;

	/* cleanup basedir */
	b = &p->baseurl;
	buffer_copy_buffer(b, &r->uri.path);
	for (c = b->ptr + buffer_clen(b); c > b->ptr && *c != '/'; c--);

	if (*c == '/') {
		buffer_truncate(b, c - b->ptr + 1);
	}

	b = &p->basedir;
	buffer_copy_buffer(b, &r->physical.path);
	for (c = b->ptr + buffer_clen(b); c > b->ptr && *c != '/'; c--);

	if (*c == '/') {
		buffer_truncate(b, c - b->ptr + 1);
	}


	/* prepare variables
	 *   - cookie-based
	 *   - get-param-based
	 */
	return cache_parse_lua(r, p, cml_file);
}

URIHANDLER_FUNC(mod_cml_power_magnet) {
	plugin_data *p = p_d;

	mod_cml_patch_config(r, p);

	if (!p->conf.power_magnet) return HANDLER_GO_ON;

	buffer_clear(&p->basedir);
	buffer_clear(&p->baseurl);
	buffer_clear(&p->trigger_handler);

	/*
	 * power-magnet:
	 * cml.power-magnet = server.docroot + "/rewrite.cml"
	 *
	 * is called on EACH request, take the original REQUEST_URI and modifies the
	 * request header as necessary.
	 *
	 * First use:
	 * if file_exists("/maintenance.html") {
	 *   output_include = ( "/maintenance.html" )
	 *   return CACHE_HIT
	 * }
	 *
	 * as we only want to rewrite HTML like requests we should cover it in a conditional
	 *
	 * */

	switch(cache_call_lua(r, p, p->conf.power_magnet)) {
	case -1:
		/* error */
		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__, "cache-error");
		}
		r->http_status = 500;
		return HANDLER_COMEBACK;
	case 0:
		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__, "cache-hit");
		}
		/* cache-hit */
		return HANDLER_FINISHED;
	case 1:
		/* cache miss */
		return HANDLER_GO_ON;
	default:
		r->http_status = 500;
		return HANDLER_COMEBACK;
	}
}

URIHANDLER_FUNC(mod_cml_is_handled) {
	plugin_data *p = p_d;

	/* r->physical.path is non-empty for handle_subrequest_start */
	/*if (buffer_is_blank(&r->physical.path)) return HANDLER_ERROR;*/

	mod_cml_patch_config(r, p);
	if (!p->conf.ext) return HANDLER_GO_ON;

	const uint32_t elen = buffer_clen(p->conf.ext);
	const uint32_t plen = buffer_clen(&r->physical.path);
	if (plen < elen || 0 != memcmp(r->physical.path.ptr+plen-elen, p->conf.ext->ptr, elen)) {
		return HANDLER_GO_ON;
	}

	buffer_clear(&p->basedir);
	buffer_clear(&p->baseurl);
	buffer_clear(&p->trigger_handler);

	switch(cache_call_lua(r, p, &r->physical.path)) {
	case -1:
		/* error */
		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__, "cache-error");
		}
		r->http_status = 500;
		return HANDLER_COMEBACK;
	case 0:
		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__, "cache-hit");
		}
		/* cache-hit */
		return HANDLER_FINISHED;
	case 1:
		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__, "cache-miss");
		}
		/* cache miss */
		return HANDLER_COMEBACK;
	default:
		r->http_status = 500;
		return HANDLER_COMEBACK;
	}
}


int mod_cml_plugin_init(plugin *p);
int mod_cml_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "cache";

	p->init        = mod_cml_init;
	p->cleanup     = mod_cml_free;
	p->set_defaults  = mod_cml_set_defaults;

	p->handle_subrequest_start = mod_cml_is_handled;
	p->handle_physical         = mod_cml_power_magnet;

	return 0;
}
