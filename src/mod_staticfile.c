#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "response.h"

#include <stdlib.h>
#include <string.h>

/**
 * this is a staticfile for a lighttpd plugin
 *
 */


typedef struct {
	const array *exclude_ext;
	unsigned short etags_used;
	unsigned short disable_pathinfo;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_staticfile_init) {
    return calloc(1, sizeof(plugin_data));
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
        pconf->disable_pathinfo = cpv->v.u;
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

static void mod_staticfile_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_staticfile_merge_config(&p->conf,
                                        p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_staticfile_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("static-file.exclude-extensions"),
        T_CONFIG_ARRAY,
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

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* static-file.exclude-extensions */
                if (!array_is_vlist(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s; "
                      "expected list of \"ext\"", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    p->defaults.etags_used = 1; /* etags enabled */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_staticfile_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_staticfile_subrequest) {
	plugin_data *p = p_d;

	/* someone else has done a decision for us */
	if (con->http_status != 0) return HANDLER_GO_ON;
	if (buffer_is_empty(con->physical.path)) return HANDLER_GO_ON;

	/* someone else has handled this request */
	if (con->mode != DIRECT) return HANDLER_GO_ON;

	/* we only handle GET, POST and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}

	mod_staticfile_patch_config(con, p);

	if (p->conf.disable_pathinfo && !buffer_string_is_empty(con->request.pathinfo)) {
		if (con->conf.log_request_handling) {
			log_error(con->conf.errh, __FILE__, __LINE__,
			  "-- NOT handling file as static file, pathinfo forbidden");
		}
		return HANDLER_GO_ON;
	}

	/* ignore certain extensions */
	if (p->conf.exclude_ext && array_match_value_suffix(p->conf.exclude_ext, con->physical.path)) {
			if (con->conf.log_request_handling) {
				log_error(con->conf.errh, __FILE__, __LINE__,
				  "-- NOT handling file as static file, extension forbidden");
			}
			return HANDLER_GO_ON;
	}


	if (con->conf.log_request_handling) {
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "-- handling file as static file");
	}

	if (!p->conf.etags_used) con->conf.etag_flags = 0;
	http_response_send_file(con, con->physical.path);

	return HANDLER_FINISHED;
}


int mod_staticfile_plugin_init(plugin *p);
int mod_staticfile_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "staticfile";

	p->init        = mod_staticfile_init;
	p->handle_subrequest_start = mod_staticfile_subrequest;
	p->set_defaults  = mod_staticfile_set_defaults;

	return 0;
}
