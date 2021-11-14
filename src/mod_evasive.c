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
 * A combination of lighttpd modules provides similar features
 * to those in (old) Apache mod_evasive
 *
 * - limit of connections per IP
 *     ==> mod_evasive
 * - provide a list of block-listed ip/networks (no access)
 *     ==> block at firewall
 *     ==> block using lighttpd.conf conditionals and mod_access
 *     ==> block using mod_magnet and an external (updatable) constant database
 *         https://wiki.lighttpd.net/AbsoLUAtion#Fight-DDoS
 * - provide a white-list of ips/network which is not affected by the limit
 *     ==> allow using lighttpd.conf conditionals
 *         and configure evasive.max-conns-per-ip = 0 for whitelist
 * - provide a bandwidth limiter per IP
 *     ==> set using lighttpd.conf conditionals
 *         and configure connection.kbytes-per-second
 * - enforce additional policy using mod_magnet and libmodsecurity
 *     ==> https://wiki.lighttpd.net/AbsoLUAtion#Mod_Security
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

static void mod_evasive_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
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

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* evasive.max-conns-per-ip */
              case 1: /* evasive.silent */
                break;
              case 2: /* evasive.location */
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
            mod_evasive_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

__attribute_cold__
__attribute_noinline__
static handler_t
mod_evasive_reached_per_ip_limit (request_st * const r, const plugin_data * const p)
{
			if (!p->conf.silent) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "%s turned away. Too many connections.",
				  r->con->dst_addr_buf.ptr);
			}

			if (p->conf.location) {
				http_header_response_set(r, HTTP_HEADER_LOCATION,
				                         CONST_STR_LEN("Location"),
				                         BUF_PTR_LEN(p->conf.location));
				r->http_status = 302;
				r->resp_body_finished = 1;
			} else {
				r->http_status = 403;
			}
			r->handler_module = NULL;
			return HANDLER_FINISHED;
}

static handler_t
mod_evasive_check_per_ip_limit (request_st * const r, const plugin_data * const p, const connection *c)
{
    const sock_addr * const dst_addr = &r->con->dst_addr;
    for (uint_fast32_t conns_by_ip = 0; c; c = c->next) {
        /* count connections already actively serving data for the same IP
         * (only count connections already behind the 'read request' state) */
        if (c->request.state > CON_STATE_REQUEST_END
            && sock_addr_is_addr_eq(&c->dst_addr, dst_addr)
            && ++conns_by_ip > p->conf.max_conns)
            return mod_evasive_reached_per_ip_limit(r, p);/* HANDLER_FINISHED */
    }
    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_evasive_uri_handler) {
    plugin_data * const p = p_d;
    mod_evasive_patch_config(r, p);
    return (p->conf.max_conns == 0) /* no limit set, nothing to block */
      ? HANDLER_GO_ON
      : mod_evasive_check_per_ip_limit(r, p, r->con->srv->conns);
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
