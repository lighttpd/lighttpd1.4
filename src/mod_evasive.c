#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"
#include "sock_addr.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

/**
 * mod_evasive
 *
 * we indent to implement all features the mod_evasive from apache has
 *
 * - limit of connections per IP
 * - provide a list of block-listed ip/networks (no access)
 * - provide a white-list of ips/network which is not affected by the limit
 *   (hmm, conditionals might be enough)
 * - provide a bandwidth limiter per IP
 *
 * started by:
 * - w1zzard@techpowerup.com
 */

typedef struct {
    unsigned short max_conns;
    unsigned short silent;
    const buffer *location;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_evasive_init) {
    return calloc(1, sizeof(plugin_data));
}

static void mod_evasive_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* evasive.max-conns-per-ip */
        pconf->max_conns = cpv->v.shrt;
        break;
      case 1: /* evasive.silent */
        pconf->silent = (0 != cpv->v.u);
        break;
      case 2: /* evasive.location */
        pconf->location = cpv->v.b;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_evasive_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_evasive_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_evasive_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_evasive_merge_config(&p->conf,p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_evasive_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("evasive.max-conns-per-ip"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("evasive.silent"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("evasive.location"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_evasive"))
        return HANDLER_ERROR;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_evasive_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_evasive_uri_handler) {
	plugin_data *p = p_d;

	mod_evasive_patch_config(con, p);

	/* no limit set, nothing to block */
	if (p->conf.max_conns == 0) return HANDLER_GO_ON;

	const connections * const conns = &con->srv->conns;
	for (uint32_t i = 0, conns_by_ip = 0; i < conns->used; ++i) {
		connection *c = conns->ptr[i];

		/* check if other connections are already actively serving data for the same IP
		 * we can only ban connections which are already behind the 'read request' state
		 * */
		if (c->state <= CON_STATE_REQUEST_END) continue;

		if (!sock_addr_is_addr_eq(&c->dst_addr, &con->dst_addr)) continue;
		conns_by_ip++;

		if (conns_by_ip > p->conf.max_conns) {
			if (!p->conf.silent) {
				log_error(con->conf.errh, __FILE__, __LINE__,
				  "%s turned away. Too many connections.",
				  con->dst_addr_buf->ptr);
			}

			if (!buffer_is_empty(p->conf.location)) {
				http_header_response_set(con, HTTP_HEADER_LOCATION, CONST_STR_LEN("Location"), CONST_BUF_LEN(p->conf.location));
				con->http_status = 302;
				con->file_finished = 1;
			} else {
				con->http_status = 403;
			}
			con->mode = DIRECT;
			return HANDLER_FINISHED;
		}
	}

	return HANDLER_GO_ON;
}


int mod_evasive_plugin_init(plugin *p);
int mod_evasive_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "evasive";

	p->init        = mod_evasive_init;
	p->set_defaults = mod_evasive_set_defaults;
	p->handle_uri_clean  = mod_evasive_uri_handler;

	return 0;
}
