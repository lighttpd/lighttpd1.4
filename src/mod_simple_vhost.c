#include "first.h"

#include "log.h"
#include "buffer.h"
#include "request.h"
#include "stat_cache.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const buffer *server_root;
    const buffer *default_host;
    const buffer *document_root;
    unsigned short debug;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    buffer last_root;
} plugin_data;

INIT_FUNC(mod_simple_vhost_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_simple_vhost_free) {
    plugin_data *p = p_d;
    free(p->last_root.ptr);
}

static void mod_simple_vhost_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* simple-vhost.server-root */
        pconf->server_root = cpv->v.b;
        break;
      case 1: /* simple-vhost.default-host */
        pconf->default_host = cpv->v.b;
        break;
      case 2: /* simple-vhost.document-root */
        pconf->document_root = cpv->v.b;
        break;
      case 3: /* simple-vhost.debug */
        pconf->debug = cpv->v.shrt;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_simple_vhost_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_simple_vhost_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_simple_vhost_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_simple_vhost_merge_config(&p->conf,
                                          p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_simple_vhost_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("simple-vhost.server-root"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("simple-vhost.default-host"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("simple-vhost.document-root"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("simple-vhost.debug"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_simple_vhost"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* simple-vhost.server-root */
              case 2: /* simple-vhost.document-root */
                if (!buffer_is_blank(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    buffer_append_slash(b);
                }
                else
                    cpv->v.b = NULL;
                break;
              case 1: /* simple-vhost.default-host */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
              case 3: /* simple-vhost.debug */
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
            mod_simple_vhost_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static void build_doc_root_path(buffer *out, const buffer *sroot, const buffer *host, const buffer *droot) {
	buffer_copy_buffer(out, sroot);

	if (host) {
		/* a hostname has to start with a alpha-numerical character
		 * and must not contain a slash "/"
		 */
		char *dp;
		if (NULL == (dp = strchr(host->ptr, ':'))) {
			buffer_append_string_buffer(out, host);
		} else {
			buffer_append_string_len(out, host->ptr, dp - host->ptr);
		}
	}

	if (droot) {
		buffer_append_path_len(out, BUF_PTR_LEN(droot));
	}
	else {
		buffer_append_slash(out);
	}
}

static int build_doc_root(request_st * const r, plugin_data *p, buffer *out, const buffer *host) {

	build_doc_root_path(out, p->conf.server_root, host, p->conf.document_root);

	/* one-element cache (positive cache, not negative cache) */
	if (buffer_is_equal(out, &p->last_root)) return 1;

	if (!stat_cache_path_isdir(out)) {
		if (p->conf.debug) {
			log_perror(r->conf.errh, __FILE__, __LINE__, "%s", out->ptr);
		}
		return 0;
	}

	buffer_copy_buffer(&p->last_root, out);
	return 1;
}

static handler_t mod_simple_vhost_docroot(request_st * const r, void *p_data) {
    plugin_data * const p = p_data;
    mod_simple_vhost_patch_config(r, p);
    if (!p->conf.server_root) return HANDLER_GO_ON;
    /* build_doc_root() requires p->conf.server_root;
     * skip module if simple-vhost.server-root not set or set to empty string */

    /* (default host and HANDLER_GO_ON instead of HANDLER_ERROR (on error)
     *  are the two differences between mod_simple_vhost and mod_vhostdb) */

    /* build document-root */
    buffer * const b = r->tmp_buf;/*(tmp_buf cleared before use in call below)*/
    const buffer *host = &r->uri.authority;
    if ((!buffer_is_blank(host) && build_doc_root(r, p, b, host))
        || build_doc_root(r, p, b, (host = p->conf.default_host))) {
        if (host) {
            r->server_name = &r->server_name_buf;
            buffer_copy_buffer(&r->server_name_buf, host);
        }
        buffer_copy_buffer(&r->physical.doc_root, b);
    }

    return HANDLER_GO_ON;
}


int mod_simple_vhost_plugin_init(plugin *p);
int mod_simple_vhost_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "simple_vhost";

	p->init        = mod_simple_vhost_init;
	p->set_defaults = mod_simple_vhost_set_defaults;
	p->handle_docroot  = mod_simple_vhost_docroot;
	p->cleanup     = mod_simple_vhost_free;

	return 0;
}
