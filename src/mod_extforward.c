#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"
#include "http_status.h"
#include "request.h"
#include "sock_addr.h"
#include "plugin.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sys-socket.h"

#ifndef _WIN32
#include <arpa/inet.h>  /* ntohs() */
#else
#include <winsock2.h>   /* ntohs() */
#endif

/**
 * mod_extforward.c for lighttpd, by comman.kang <at> gmail <dot> com
 *                  extended, modified by Lionel Elie Mamane (LEM), lionel <at> mamane <dot> lu
 *                  support chained proxies by glen@delfi.ee, #1528
 *
 *
 * Mostly rewritten
 * Portions:
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * Config example:
 *
 *       Trust proxy 10.0.0.232 and 10.0.0.232
 *       extforward.forwarder = ( "10.0.0.232" => "trust",
 *                                "10.0.0.233" => "trust" )
 *
 *       Trust all proxies  (NOT RECOMMENDED!)
 *       extforward.forwarder = ( "all" => "trust")
 *
 *       Note that "all" has precedence over specific entries,
 *       so "all except" setups will not work.
 *
 *       In case you have chained proxies, you can add all their IP's to the
 *       config. However "all" has effect only on connecting IP, as the
 *       X-Forwarded-For header can not be trusted.
 *
 * Note: The effect of this module is variable on $HTTP["remoteip"] directives and
 *       other module's remote ip dependent actions.
 *  Things done by modules before we change the remoteip or after we reset it will match on the proxy's IP.
 *  Things done in between these two moments will match on the real client's IP.
 *  The moment things are done by a module depends on in which hook it does things and within the same hook
 *  on whether they are before/after us in the module loading order
 *  (order in the server.modules directive in the config file).
 */


typedef enum {
	PROXY_FORWARDED_NONE         = 0x00,
	PROXY_FORWARDED_FOR          = 0x01,
	PROXY_FORWARDED_PROTO        = 0x02,
	PROXY_FORWARDED_HOST         = 0x04,
	PROXY_FORWARDED_BY           = 0x08,
	PROXY_FORWARDED_REMOTE_USER  = 0x10
} proxy_forwarded_t;

struct sock_addr_mask {
  sock_addr addr;
  int bits;
};

struct forwarder_cfg {
  const array *forwarder;
  int forward_all;
  uint32_t addrs_used;
 #if defined(__STDC_VERSION__) && __STDC_VERSION__-0 >= 199901L /* C99 */
  struct sock_addr_mask addrs[];
 #else
  struct sock_addr_mask addrs[1];
 #endif
};

typedef struct {
    const array *forwarder;
    int forward_all;
    uint32_t forward_masks_used;
    const struct sock_addr_mask *forward_masks;
    const array *headers;
    unsigned int opts;
    char hap_PROXY;
    char hap_PROXY_ssl_client_verify;
    int plid;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    array *default_headers;
    array tokens;
} plugin_data;

static plugin_data *mod_extforward_plugin_data;
static int extforward_check_proxy;


/* context , used for restore remote ip */

typedef struct {
    /* per-request state */
    sock_addr dst_addr;
    buffer dst_addr_buf;
} handler_rctx;

typedef struct {
    int con_is_trusted;

    /* connection-level state applied to requests in handle_request_env */
    int ssl_client_verify;
    array *env;

    /* hap-PROXY protocol prior to receiving first request */
    int(*saved_network_read)(connection *, chunkqueue *, off_t);
} handler_ctx;


__attribute_malloc__
__attribute_returns_nonnull__
static handler_rctx * handler_rctx_init(void) {
    return ck_calloc(1, sizeof(handler_rctx));
}

static void handler_rctx_free(handler_rctx *rctx) {
    free(rctx->dst_addr_buf.ptr);
    free(rctx);
}

__attribute_malloc__
__attribute_returns_nonnull__
static handler_ctx * handler_ctx_init(void) {
    return ck_calloc(1, sizeof(handler_ctx));
}

static void handler_ctx_free(handler_ctx *hctx) {
    if (NULL != hctx->env)
        array_free(hctx->env);
    free(hctx);
}

INIT_FUNC(mod_extforward_init) {
    return (mod_extforward_plugin_data = ck_calloc(1, sizeof(plugin_data)));
}

FREE_FUNC(mod_extforward_free) {
    plugin_data * const p = p_d;
    array_free(p->default_headers);
    array_free_data(&p->tokens);
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* extforward.forwarder */
                if (cpv->vtype == T_CONFIG_LOCAL) free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static void mod_extforward_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* extforward.forwarder */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            const struct forwarder_cfg * const fwd = cpv->v.v;
            pconf->forwarder = fwd->forwarder;
            pconf->forward_all = fwd->forward_all;
            pconf->forward_masks_used = fwd->addrs_used;
            pconf->forward_masks = fwd->addrs;
        }
        break;
      case 1: /* extforward.headers */
        pconf->headers = cpv->v.a;
        break;
      case 2: /* extforward.params */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->opts = cpv->v.u;
        break;
      case 3: /* extforward.hap-PROXY */
        pconf->hap_PROXY = (char)cpv->v.u;
        break;
      case 4: /* extforward.hap-PROXY-ssl-client-verify */
        pconf->hap_PROXY_ssl_client_verify = (char)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_extforward_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_extforward_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_extforward_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_extforward_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static void * mod_extforward_parse_forwarder(server *srv, const array *forwarder) {
    const data_string * const allds = (const data_string *)
      array_get_element_klen(forwarder, CONST_STR_LEN("all"));
    const int forward_all = (NULL == allds)
      ? 0
      : buffer_eq_icase_slen(&allds->value, CONST_STR_LEN("trust")) ? 1 : -1;
    uint32_t nmasks = 0;
    for (uint32_t j = 0; j < forwarder->used; ++j) {
        data_string * const ds = (data_string *)forwarder->data[j];
        char * const nm_slash = strchr(ds->key.ptr, '/');
        if (NULL != nm_slash) ++nmasks;
        if (!buffer_eq_icase_slen(&ds->value, CONST_STR_LEN("trust"))) {
            if (!buffer_eq_icase_slen(&ds->value, CONST_STR_LEN("untrusted")))
                log_error(srv->errh, __FILE__, __LINE__,
                  "ERROR: expect \"trust\", not \"%s\" => \"%s\"; "
                  "treating as untrusted", ds->key.ptr, ds->value.ptr);
            if (NULL != nm_slash) {
                /* future: consider adding member next to bits in sock_addr_mask
                 *         with bool trusted/untrusted member */
                --nmasks;
                log_error(srv->errh, __FILE__, __LINE__,
                  "ERROR: untrusted CIDR masks are ignored (\"%s\" => \"%s\")",
                  ds->key.ptr, ds->value.ptr);
            }
            buffer_clear(&ds->value); /* empty is untrusted */
            continue;
        }
    }

    struct forwarder_cfg * const fwd =
      ck_calloc(1, sizeof(struct forwarder_cfg)
                 + sizeof(struct sock_addr_mask)*nmasks);
    fwd->forwarder = forwarder;
    fwd->forward_all = forward_all;
    fwd->addrs_used = 0;
    for (uint32_t j = 0; j < forwarder->used; ++j) {
        data_string * const ds = (data_string *)forwarder->data[j];
        char * const nm_slash = strchr(ds->key.ptr, '/');
        if (NULL == nm_slash) continue;
        if (ds->key.ptr[0] == '/') continue; /*no mask for unix domain sockets*/
        if (buffer_is_blank(&ds->value)) continue; /* ignored */

        char *err;
        const int nm_bits = strtol(nm_slash + 1, &err, 10);
        int rc;
        if (*err || nm_bits <= 0 || !light_isdigit(nm_slash[1])) {
            log_error(srv->errh, __FILE__, __LINE__,
              "ERROR: invalid netmask: %s %s", ds->key.ptr, err);
            free(fwd);
            return NULL;
        }
        struct sock_addr_mask * const sm = fwd->addrs + fwd->addrs_used++;
        sm->bits = nm_bits;
        *nm_slash = '\0';
        if (ds->key.ptr[0] == '['
            && ds->key.ptr+1 < nm_slash && nm_slash[-1] == ']') {
            nm_slash[-1] = '\0';
            rc = sock_addr_from_str_numeric(&sm->addr,ds->key.ptr+1,srv->errh);
            nm_slash[-1] = ']';
        }
        else
            rc = sock_addr_from_str_numeric(&sm->addr,ds->key.ptr,  srv->errh);
        *nm_slash = '/';
        if (1 != rc) {
            free(fwd);
            return NULL;
        }
        buffer_clear(&ds->value);
        /* empty is untrusted,
         * e.g. if subnet (incorrectly) appears in X-Forwarded-For */
    }

    return fwd;
}

static unsigned int mod_extforward_parse_opts(server *srv, const array *opts_params) {
    unsigned int opts = 0;
    for (uint32_t j = 0, used = opts_params->used; j < used; ++j) {
        proxy_forwarded_t param;
        data_unset *du = opts_params->data[j];
      #if 0  /*("for" and "proto" historical behavior: always enabled)*/
        if (buffer_eq_slen(&du->key, CONST_STR_LEN("by")))
            param = PROXY_FORWARDED_BY;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("for")))
            param = PROXY_FORWARDED_FOR;
        else
      #endif
        if (buffer_eq_slen(&du->key, CONST_STR_LEN("host")))
            param = PROXY_FORWARDED_HOST;
      #if 0
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("proto")))
            param = PROXY_FORWARDED_PROTO;
      #endif
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("remote_user")))
            param = PROXY_FORWARDED_REMOTE_USER;
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "extforward.params keys must be one of: "
              "host, remote_user, but not: %s", du->key.ptr);
            return UINT_MAX;
        }

        int val = config_plugin_value_to_bool(du, 2);
        if (2 == val) {
            log_error(srv->errh, __FILE__, __LINE__,
              "extforward.params values must be one of: "
              "0, 1, enable, disable; error for key: %s", du->key.ptr);
            return UINT_MAX;
        }
        if (val)
            opts |= param;
    }
    return opts;
}

SETDEFAULTS_FUNC(mod_extforward_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("extforward.forwarder"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("extforward.headers"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("extforward.params"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("extforward.hap-PROXY"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("extforward.hap-PROXY-ssl-client-verify"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_extforward"))
        return HANDLER_ERROR;

    int hap_PROXY = 0;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* extforward.forwarder */
                cpv->v.v = mod_extforward_parse_forwarder(srv, cpv->v.a);
                if (NULL == cpv->v.v) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* extforward.headers */
                if (cpv->v.a->used) {
                    array *a;
                    *(const array **)&a = cpv->v.a;
                    for (uint32_t j = 0; j < a->used; ++j) {
                        data_string * const ds = (data_string *)a->data[j];
                        ds->ext =
                          http_header_hkey_get(BUF_PTR_LEN(&ds->value));
                    }
                }
                break;
              case 2: /* extforward.params */
                cpv->v.u = mod_extforward_parse_opts(srv, cpv->v.a);
                if (UINT_MAX == cpv->v.u)
                    return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 3: /* extforward.hap-PROXY */
                if (cpv->v.u) hap_PROXY = 1;
                break;
              case 4: /* extforward.hap-PROXY-ssl-client-verify */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.opts = PROXY_FORWARDED_NONE;
    p->defaults.plid = p->id; /*(not a config option; for convenient access)*/

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_extforward_merge_config(&p->defaults, cpv);
    }

    /* default to "X-Forwarded-For" or "Forwarded-For" if extforward.headers
     * is not specified or is empty (and not using hap_PROXY) */
    if (!p->defaults.hap_PROXY
        && (NULL == p->defaults.headers || 0 == p->defaults.headers->used)) {
        p->defaults.headers = p->default_headers = array_init(2);
        array_insert_value(p->default_headers,CONST_STR_LEN("X-Forwarded-For"));
        array_insert_value(p->default_headers,CONST_STR_LEN("Forwarded-For"));
        for (uint32_t i = 0; i < p->default_headers->used; ++i) {
            data_string * const ds = (data_string *)p->default_headers->data[i];
            ds->ext = http_header_hkey_get(BUF_PTR_LEN(&ds->value));
        }
    }

    /* attempt to warn if mod_extforward is not last module loaded to hook
     * handle_connection_accept.  (Nice to have, but remove this check if
     * it reaches too far into internals and prevents other code changes.)
     * While it would be nice to check handle_connection_accept plugin slot
     * to make sure mod_extforward is last, that info is private to plugin.c
     * so merely warn if mod_openssl is loaded after mod_extforward, though
     * future modules which hook handle_connection_accept might be missed.*/
    if (hap_PROXY) {
        uint32_t i;
        for (i = 0; i < srv->srvconf.modules->used; ++i) {
            data_string *ds = (data_string *)srv->srvconf.modules->data[i];
            if (buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_extforward")))
                break;
        }
        for (; i < srv->srvconf.modules->used; ++i) {
            data_string *ds = (data_string *)srv->srvconf.modules->data[i];
            if (buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_openssl"))
                || buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_mbedtls"))
                || buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_wolfssl"))
                || buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_nss"))
                || buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_gnutls"))) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "mod_extforward must be loaded after %s in "
                  "server.modules when extforward.hap-PROXY = \"enable\"",
                  ds->value.ptr);
                break;
            }
        }
    }

    for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
        data_string *ds = (data_string *)srv->srvconf.modules->data[i];
        if (buffer_is_equal_string(&ds->value, CONST_STR_LEN("mod_proxy"))) {
            extforward_check_proxy = 1;
            break;
        }
    }

    return HANDLER_GO_ON;
}


/*
   extract a forward array from the environment
*/
static void extract_forward_array(array * const result, const buffer *pbuffer)
{
		/*force_assert(!buffer_is_blank(pbuffer));*/
		const char *base, *curr;
		/* state variable, 0 means not in string, 1 means in string */
		int in_str = 0;
		for (base = pbuffer->ptr, curr = pbuffer->ptr; *curr; curr++) {
			int hex_or_colon = (light_isxdigit(*curr) || *curr == ':');
			if (in_str) {
				if (!hex_or_colon && *curr != '.') {
					/* found an separator , insert value into result array */
					array_insert_value(result, base, curr - base);
					/* change state to not in string */
					in_str = 0;
				}
			} else {
				if (hex_or_colon) {
					/* found leading char of an IP address, move base pointer and change state */
					base = curr;
					in_str = 1;
				}
			}
		}
		/* if breaking out while in str, we got to the end of string, so add it */
		if (in_str) {
			array_insert_value(result, base, curr - base);
		}
}

/*
 * check whether ip is trusted, return 1 for trusted , 0 for untrusted
 */
static int is_proxy_trusted(const plugin_config *pconf, const char * const ip, size_t iplen)
{
    const data_string *ds =
      (const data_string *)array_get_element_klen(pconf->forwarder, ip, iplen);
    if (NULL != ds) return !buffer_is_blank(&ds->value);

    if (pconf->forward_masks_used) {
        const struct sock_addr_mask * const addrs = pconf->forward_masks;
        const uint32_t aused = pconf->forward_masks_used;
        sock_addr addr;
        /* C funcs inet_aton(), inet_pton() require '\0'-terminated IP str */
        char addrstr[64]; /*(larger than INET_ADDRSTRLEN and INET6_ADDRSTRLEN)*/
        if (0 == iplen || iplen >= sizeof(addrstr)) return 0;
        memcpy(addrstr, ip, iplen);
        addrstr[iplen] = '\0';

        if (1 != sock_addr_inet_pton(&addr, addrstr, AF_INET,  0)
         && 1 != sock_addr_inet_pton(&addr, addrstr, AF_INET6, 0)) return 0;

        for (uint32_t i = 0; i < aused; ++i) {
            if (sock_addr_is_addr_eq_bits(&addr, &addrs[i].addr, addrs[i].bits))
                return 1;
        }
    }

    return 0;
}

static int is_connection_trusted(connection * const con, const plugin_config *pconf)
{
    if (pconf->forward_all) return (1 == pconf->forward_all);
    return is_proxy_trusted(pconf, BUF_PTR_LEN(&con->dst_addr_buf));
}

static int is_connection_trusted_cached(connection * const con, const plugin_config * const pconf)
{
    if (pconf->forward_all) return (1 == pconf->forward_all);

    handler_ctx ** const hctx = (handler_ctx **)&con->plugin_ctx[pconf->plid];
    if (!*hctx)
        *hctx = handler_ctx_init();
    else if ((*hctx)->con_is_trusted != -1)
        return (*hctx)->con_is_trusted;
    return ((*hctx)->con_is_trusted =
      is_proxy_trusted(pconf, BUF_PTR_LEN(&con->dst_addr_buf)));
}

/*
 * Return last address of proxy that is not trusted.
 * Do not accept "all" keyword here.
 */
static const buffer *last_not_in_array(array *a, plugin_config *pconf)
{
	int i;

	for (i = a->used - 1; i >= 0; i--) {
		data_string *ds = (data_string *)a->data[i];
		if (!is_proxy_trusted(pconf, BUF_PTR_LEN(&ds->value))) {
			return &ds->value;
		}
	}
	return NULL;
}

static int mod_extforward_set_addr(request_st * const r, const plugin_config * const pconf, const char *addr, size_t addrlen) {
	sock_addr sock;
	sock.plain.sa_family = AF_UNSPEC;
	if (1 != sock_addr_from_str_numeric(&sock, addr, r->conf.errh)) return 0;
	if (sock.plain.sa_family == AF_UNSPEC) return 0;

	const int plid = pconf->plid;
	if (!r->plugin_ctx[plid]) {
		handler_rctx * const rctx = r->plugin_ctx[plid] = handler_rctx_init();
		r->dst_addr = &rctx->dst_addr;
		r->dst_addr_buf = &rctx->dst_addr_buf;
	}
  #if 0 /*(not expected)*/
	else if (r->conf.log_request_handling)
		log_debug(r->conf.errh, __FILE__, __LINE__,
		  "-- mod_extforward_uri_handler already patched this connection, resetting state");
  #endif

	if (r->conf.log_request_handling)
		log_debug(r->conf.errh, __FILE__, __LINE__, "using address: %s", addr);

  #if 0 /*(no longer necessary since not overwriting con->dst_addr_buf)*/
	/* save old address */
	if (extforward_check_proxy) {
		http_header_env_set(r, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_FOR"),
		                    BUF_PTR_LEN(&con->dst_addr_buf));
	}
  #endif

	/* set (virtual) remote address for request */
	*(sock_addr *)r->dst_addr = sock;
	buffer_copy_string_len(r->dst_addr_buf, addr, addrlen);
	/* reset conf_cond cache; results may change */
	config_cond_cache_reset_item(r, COMP_HTTP_REMOTE_IP);

	return 1;
}

static void mod_extforward_set_proto(request_st * const r, const char * const proto, size_t protolen) {
	if (0 != protolen && !buffer_eq_icase_slen(&r->uri.scheme, proto, protolen)) {
		/* update scheme if X-Forwarded-Proto is set
		 * Limitations:
		 * - Only "http" or "https" are currently accepted since the request to lighttpd currently has to
		 *   be HTTP/1.0 or HTTP/1.1 using http or https.  If this is changed, then the scheme from this
		 *   untrusted header must be checked to contain only alphanumeric characters, and to be a
		 *   reasonable length, e.g. < 256 chars.
		 * - r->uri.scheme is not reset in mod_extforward_restore() but is currently not an issues since
		 *   r->uri.scheme will be reset by next request.  If a new module uses r->uri.scheme in the
		 *   handle_request_done hook, then should evaluate if that module should use the forwarded value
		 *   (probably) or the original value.
		 */
		if (extforward_check_proxy) {
			http_header_env_set(r, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_PROTO"), BUF_PTR_LEN(&r->uri.scheme));
		}
		if (buffer_eq_icase_ss(proto, protolen, CONST_STR_LEN("https"))) {
	                r->con->proto_default_port = 443; /* "https" */
			buffer_copy_string_len(&r->uri.scheme, CONST_STR_LEN("https"));
			config_cond_cache_reset_item(r, COMP_HTTP_SCHEME);
		} else if (buffer_eq_icase_ss(proto, protolen, CONST_STR_LEN("http"))) {
	                r->con->proto_default_port = 80; /* "http" */
			buffer_copy_string_len(&r->uri.scheme, CONST_STR_LEN("http"));
			config_cond_cache_reset_item(r, COMP_HTTP_SCHEME);
		}
	}
}

static handler_t mod_extforward_X_Forwarded_For(request_st * const r, plugin_config * const pconf, const buffer * const x_forwarded_for) {
	/* build forward_array from forwarded data_string */
	/* thread-safety todo: allocate/free (array *) locally, or per-thread */
	plugin_data * const p = mod_extforward_plugin_data;
	array * const forward_array = &p->tokens;
	extract_forward_array(forward_array, x_forwarded_for);
	const buffer *real_remote_addr = last_not_in_array(forward_array, pconf);
	if (real_remote_addr != NULL) { /* parsed */
		/* get scheme if X-Forwarded-Proto is set
		 * Limitations:
		 * - X-Forwarded-Proto may or may not be set by proxies, even if X-Forwarded-For is set
		 * - X-Forwarded-Proto may be a comma-separated list if there are multiple proxies,
		 *   but the historical behavior of the code below only honored it if there was exactly one value
		 *   (not done: walking backwards in X-Forwarded-Proto the same num of steps
		 *    as in X-Forwarded-For to find proto set by last trusted proxy)
		 */
		const buffer *x_forwarded_proto = http_header_request_get(r, HTTP_HEADER_X_FORWARDED_PROTO, CONST_STR_LEN("X-Forwarded-Proto"));
		if (mod_extforward_set_addr(r, pconf, BUF_PTR_LEN(real_remote_addr)) && NULL != x_forwarded_proto) {
			mod_extforward_set_proto(r, BUF_PTR_LEN(x_forwarded_proto));
		}
	}
	array_reset_data_strings(forward_array);
	return HANDLER_GO_ON;
}

__attribute_pure__
static int find_end_quoted_string (const char * const s, int i) {
    do {
        ++i;
    } while (s[i] != '"' && s[i] != '\0' && (s[i] != '\\' || s[++i] != '\0'));
    return i;
}

__attribute_pure__
static int find_next_semicolon_or_comma_or_eq (const char * const s, int i) {
    for (; s[i] != '=' && s[i] != ';' && s[i] != ',' && s[i] != '\0'; ++i) {
        if (s[i] == '"') {
            i = find_end_quoted_string(s, i);
            if (s[i] == '\0') return -1;
        }
    }
    return i;
}

__attribute_pure__
static int find_next_semicolon_or_comma (const char * const s, int i) {
    for (; s[i] != ';' && s[i] != ',' && s[i] != '\0'; ++i) {
        if (s[i] == '"') {
            i = find_end_quoted_string(s, i);
            if (s[i] == '\0') return -1;
        }
    }
    return i;
}

static int buffer_backslash_unescape (buffer * const b) {
    /* (future: might move to buffer.c) */
    size_t j = 0;
    size_t len = buffer_clen(b);
    char *p = memchr(b->ptr, '\\', len);

    if (NULL == p) return 1; /*(nothing to do)*/

    len -= (size_t)(p - b->ptr);
    for (size_t i = 0; i < len; ++i) {
        if (p[i] == '\\') {
            if (++i == len) return 0; /*(invalid trailing backslash)*/
        }
        p[j++] = p[i];
    }
    buffer_truncate(b, (size_t)(p+j - b->ptr));
    return 1;
}

__attribute_cold__
static handler_t mod_extforward_bad_request (request_st * const r, const unsigned int line, const char * const msg)
{
    log_error(r->conf.errh, __FILE__, line, "%s", msg);
    return http_status_set_err(r, 400); /* Bad Request */
}

static handler_t mod_extforward_Forwarded (request_st * const r, plugin_config * const pconf, const buffer * const forwarded) {
    /* HTTP list need not consist of param=value tokens,
     * but this routine expect such for HTTP Forwarded header
     * Since info in each set of params is only used if from
     * admin-specified trusted proxy:
     * - invalid param=value tokens are ignored and skipped
     * - not checking "for" exists in each set of params
     * - not checking for duplicated params in each set of params
     * - not checking canonical form of addr (also might be obfuscated)
     * - obfuscated tokens permitted in chain, though end of trust is expected
     *   to be non-obfuscated IP for mod_extforward to masquerade as remote IP
     * future: since (potentially) trusted proxies begin at end of string,
     *   it might be better to parse from end of string rather than parsing from
     *   beginning.  Doing so would also allow reducing arbitrary param limit
     *   to number of params permitted per proxy.
     */
    char * const s = forwarded->ptr;
    int i = 0, j = -1, v, vlen, k, klen;
    int used = (int)buffer_clen(forwarded);
    int ofor = -1, oproto, ohost, oby, oremote_user;
    int offsets[256];/*(~50 params is more than reasonably expected to handle)*/
    while (i < used) {
        while (s[i] == ' ' || s[i] == '\t') ++i;
        if (s[i] == ';') { ++i; continue; }
        if (s[i] == ',') {
            if (j >= (int)(sizeof(offsets)/sizeof(int))-1) break;
            offsets[++j] = -1; /*("offset" separating params from next proxy)*/
            ++i;
            continue;
        }
        if (s[i] == '\0') break;

        k = i;
        i = find_next_semicolon_or_comma_or_eq(s, i);
        if (i < 0) {
            /*(reject IP spoofing if attacker sets improper quoted-string)*/
            return mod_extforward_bad_request(r, __LINE__,
              "invalid quoted-string in Forwarded header");
        }
        if (s[i] != '=') continue;
        klen = i - k;
        v = ++i;
        i = find_next_semicolon_or_comma(s, i);
        if (i < 0) {
            /*(reject IP spoofing if attacker sets improper quoted-string)*/
            return mod_extforward_bad_request(r, __LINE__,
              "invalid quoted-string in Forwarded header");
        }
        vlen = i - v;              /* might be 0 */

        /* have k, klen, v, vlen
         * (might contain quoted string) (contents not validated or decoded)
         * (might be repeated k)
         */
        if (0 == klen) continue;   /* invalid k */
        if (j >= (int)(sizeof(offsets)/sizeof(int))-4) break;
        offsets[j+1] = k;
        offsets[j+2] = klen;
        offsets[j+3] = v;
        offsets[j+4] = vlen;
        j += 4;
    }

    if (j >= (int)(sizeof(offsets)/sizeof(int))-4) {
        /* error processing Forwarded; too many params; fail closed */
        return mod_extforward_bad_request(r, __LINE__,
          "Too many params in Forwarded header");
    }

    if (-1 == j) return HANDLER_GO_ON;  /* make no changes */
    used = j+1;
    offsets[used] = -1; /* mark end of last set of params */

    while (j >= 4) { /*(param=value pairs)*/
        if (-1 == offsets[j]) { --j; continue; }
        do {
            j -= 3; /*(k, klen, v, vlen come in sets of 4)*/
        } while ((3 != offsets[j+1]  /* 3 == sizeof("for")-1 */
                  || !buffer_eq_icase_ssn(s+offsets[j], "for", 3))
                 && 0 != j-- && -1 != offsets[j]);
        if (j < 0) break;
        if (-1 == offsets[j]) { --j; continue; }

        /* remove trailing spaces/tabs and double-quotes from string
         * (note: not unescaping backslash escapes in quoted string) */
        v = offsets[j+2];
        vlen = v + offsets[j+3];
        while (vlen > v && (s[vlen-1] == ' ' || s[vlen-1] == '\t')) --vlen;
        if (vlen > v+1 && s[v] == '"' && s[vlen-1] == '"') {
            offsets[j+2] = ++v;
            --vlen;
            if (s[v] == '[') {
                /* remove "[]" surrounding IPv6, as well as (optional) port
                 * (assumes properly formatted IPv6 addr from trusted proxy) */
                ++v;
                do { --vlen; } while (vlen > v && s[vlen] != ']');
                if (v == vlen) {
                    return mod_extforward_bad_request(r, __LINE__,
                      "Invalid IPv6 addr in Forwarded header");
                }
            }
            else if (s[v] != '_' && s[v] != '/' && s[v] != 'u') {
                /* remove (optional) port from non-obfuscated IPv4 */
                for (klen=vlen, vlen=v; vlen < klen && s[vlen] != ':'; ++vlen) ;
            }
            offsets[j+2] = v;
        }
        offsets[j+3] = vlen - v;

        /* obfuscated ipstr and obfuscated port are also accepted here, as
         * is path to unix domain socket, but note that backslash escapes
         * in quoted-string were not unescaped above.  Also, if obfuscated
         * identifiers are rotated by proxies as recommended by RFC, then
         * maintaining list of trusted identifiers is non-trivial and is not
         * attempted by this module. */

        if (v != vlen) {
            int trusted = is_proxy_trusted(pconf, s+v, vlen-v);

            if (s[v] != '_' && s[v] != '/'
                && (7 != (vlen - v) || 0 != memcmp(s+v, "unknown", 7))) {
                ofor = j; /* save most recent non-obfuscated ipstr */
            }

            if (!trusted) break;
        }

        do { --j; } while (j > 0 && -1 != offsets[j]);
        if (j <= 0) break;
        --j;
    }

    if (-1 != ofor) {
        /* C funcs getaddrinfo(), inet_addr() require '\0'-terminated IP str */
        char *ipend = s+offsets[ofor+2]+offsets[ofor+3];
        char c = *ipend;
        int rc;
        *ipend = '\0';
        rc = mod_extforward_set_addr(r, pconf,
                                     s+offsets[ofor+2], offsets[ofor+3]);
        *ipend = c;
        if (!rc) return HANDLER_GO_ON; /* invalid addr; make no changes */
    }
    else {
        return HANDLER_GO_ON; /* make no changes */
    }

    /* parse out params associated with for=<ip> addr set above */
    oproto = ohost = oby = oremote_user = -1;
    UNUSED(oby);
    j = ofor;
    if (j > 0) { do { --j; } while (j > 0 && -1 != offsets[j]); }
    if (-1 == offsets[j]) ++j;
    if (j == ofor) j += 4;
    for (; -1 != offsets[j]; j+=4) { /*(k, klen, v, vlen come in sets of 4)*/
        switch (offsets[j+1]) {
         #if 0
          case 2:
            if (buffer_eq_icase_ssn(s+offsets[j], "by", 2))
                oby = j;
            break;
         #endif
         #if 0
          /*(already handled above to find IP prior to earliest trusted proxy)*/
          case 3:
            if (buffer_eq_icase_ssn(s+offsets[j], "for", 3))
                ofor = j;
            break;
         #endif
          case 4:
            if (buffer_eq_icase_ssn(s+offsets[j], "host", 4))
                ohost = j;
            break;
          case 5:
            if (buffer_eq_icase_ssn(s+offsets[j], "proto", 5))
                oproto = j;
            break;
          case 11:
            if (buffer_eq_icase_ssn(s+offsets[j], "remote_user", 11))
                oremote_user = j;
            break;
          default:
            break;
        }
    }
    i = j+1;

    if (-1 != oproto) {
        /* remove trailing spaces/tabs, and double-quotes from proto
         * (note: not unescaping backslash escapes in quoted string) */
        v = offsets[oproto+2];
        vlen = v + offsets[oproto+3];
        while (vlen > v && (s[vlen-1] == ' ' || s[vlen-1] == '\t')) --vlen;
        if (vlen > v+1 && s[v] == '"' && s[vlen-1] == '"') { ++v; --vlen; }
        mod_extforward_set_proto(r, s+v, vlen-v);
    }

    if (pconf->opts & PROXY_FORWARDED_HOST) {
        /* Limitations:
         * - r->http_host is not reset in mod_extforward_restore()
         *   but is currently not an issues since r->http_host will be
         *   reset by next request.  If a new module uses r->http_host
         *   in the handle_request_done hook, then should evaluate if that
         *   module should use the forwarded value (probably) or original value.
         * - due to need to decode and unescape host=..., some extra work is
         *   done in the case where host matches current Host header.
         *   future: might add code to check if Host has actually changed or not
         *
         * note: change host after mod_extforward_set_proto() since that may
         *       affect scheme port used in http_request_host_policy() host
         *       normalization
         */

        /* find host param set by earliest trusted proxy in proxy chain
         * (host might be changed anywhere along the chain) */
        for (j = i; j < used && -1 == ohost; ) {
            if (-1 == offsets[j]) { ++j; continue; }
            if (4 == offsets[j+1]
                && buffer_eq_icase_ssn(s+offsets[j], "host", 4))
                ohost = j;
            j += 4; /*(k, klen, v, vlen come in sets of 4)*/
        }
        if (-1 != ohost) {
            if (r->http_host && !buffer_is_blank(r->http_host)) {
                if (extforward_check_proxy)
                    http_header_env_set(r,
                      CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_HOST"),
                      BUF_PTR_LEN(r->http_host));
            }
            else {
                r->http_host =
                  http_header_request_set_ptr(r, HTTP_HEADER_HOST,
                                              CONST_STR_LEN("Host"));
            }
            /* remove trailing spaces/tabs, and double-quotes from host */
            v = offsets[ohost+2];
            vlen = v + offsets[ohost+3];
            while (vlen > v && (s[vlen-1] == ' ' || s[vlen-1] == '\t')) --vlen;
            if (vlen > v+1 && s[v] == '"' && s[vlen-1] == '"') {
                ++v; --vlen;
                buffer_copy_string_len_lc(r->http_host, s+v, vlen-v);
                if (!buffer_backslash_unescape(r->http_host)) {
                    return mod_extforward_bad_request(r, __LINE__,
                      "invalid host= value in Forwarded header");
                }
            }
            else {
                buffer_copy_string_len_lc(r->http_host, s+v, vlen-v);
            }

            if (0 != http_request_host_policy(r->http_host,
                                              r->conf.http_parseopts,
                                              r->con->proto_default_port)) {
                /*(reject invalid chars in Host)*/
                return mod_extforward_bad_request(r, __LINE__,
                  "invalid host= value in Forwarded header");
            }

            config_cond_cache_reset_item(r, COMP_HTTP_HOST);
        }
    }

    if (pconf->opts & PROXY_FORWARDED_REMOTE_USER) {
        /* find remote_user param set by closest proxy
         * (auth may have been handled by any trusted proxy in proxy chain) */
        for (j = i; j < used; ) {
            if (-1 == offsets[j]) { ++j; continue; }
            if (11 == offsets[j+1]
                && buffer_eq_icase_ssn(s+offsets[j], "remote_user", 11))
                oremote_user = j;
            j += 4; /*(k, klen, v, vlen come in sets of 4)*/
        }
        if (-1 != oremote_user) {
            /* ???: should we also support param for auth_type ??? */
            /* remove trailing spaces/tabs, and double-quotes from remote_user*/
            v = offsets[oremote_user+2];
            vlen = v + offsets[oremote_user+3];
            while (vlen > v && (s[vlen-1] == ' ' || s[vlen-1] == '\t')) --vlen;
            if (vlen > v+1 && s[v] == '"' && s[vlen-1] == '"') {
                buffer *euser;
                ++v; --vlen;
                http_header_env_set(r,
                                    CONST_STR_LEN("REMOTE_USER"), s+v, vlen-v);
                euser = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
                force_assert(NULL != euser);
                if (!buffer_backslash_unescape(euser)) {
                    return mod_extforward_bad_request(r, __LINE__,
                      "invalid remote_user= value in Forwarded header");
                }
            }
            else {
                http_header_env_set(r,
                                    CONST_STR_LEN("REMOTE_USER"), s+v, vlen-v);
            }
        }
    }

  #if 0
    if ((pconf->opts & PROXY_FORWARDED_CREATE_XFF)
        && !light_btst(r->rqst_htags, HTTP_HEADER_X_FORWARDED_FOR)) {
        /* create X-Forwarded-For if not present
         * (and at least original connecting IP is a trusted proxy) */
        buffer * const xff =
          http_header_request_set_ptr(r, HTTP_HEADER_X_FORWARDED_FOR,
                                      CONST_STR_LEN("X-Forwarded-For"));
        for (j = 0; j < used; ) {
            if (-1 == offsets[j]) { ++j; continue; }
            if (3 == offsets[j+1]
                && buffer_eq_icase_ssn(s+offsets[j], "for", 3)) {
                if (!buffer_is_blank(xff))
                    buffer_append_string_len(xff, CONST_STR_LEN(", "));
                /* quoted-string, IPv6 brackets, and :port already removed */
                v = offsets[j+2];
                vlen = offsets[j+3];
                buffer_append_string_len(xff, s+v, vlen);
                if (s[v-1] != '=') { /*(must have been quoted-string)*/
                    char *x =
                      memchr(xff->ptr + buffer_clen(xff) - vlen, '\\', vlen);
                    if (NULL != x) { /* backslash unescape in-place */
                        for (v = 0; x[v]; ++x) {
                            if (x[v] == '\\' && x[++v] == '\0')
                                break; /*(invalid trailing backslash)*/
                            *x = x[v];
                        }
                        buffer_truncate(xff, x - xff->ptr);
                    }
                }
                /* skip to next group; take first "for=..." in group
                 * (should be 0 or 1 "for=..." per group, but not trusted) */
                do { j += 4; } while (-1 != offsets[j]);
                ++j;
                continue;
            }
            j += 4; /*(k, klen, v, vlen come in sets of 4)*/
        }
    }
  #endif

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_extforward_uri_handler) {
	plugin_config pconf;
	mod_extforward_patch_config(r, p_d, &pconf);
	if (NULL == pconf.forwarder) return HANDLER_GO_ON;

	if (pconf.hap_PROXY_ssl_client_verify) {
		const data_string *ds;
		handler_ctx *hctx = r->con->plugin_ctx[pconf.plid];
		if (NULL != hctx && hctx->ssl_client_verify && NULL != hctx->env
		    && NULL != (ds = (const data_string *)array_get_element_klen(hctx->env, CONST_STR_LEN("SSL_CLIENT_S_DN_CN")))) {
			http_header_env_set(r,
					    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
					    CONST_STR_LEN("SUCCESS"));
			http_header_env_set(r,
					    CONST_STR_LEN("REMOTE_USER"),
					    BUF_PTR_LEN(&ds->value));
			http_header_env_set(r,
					    CONST_STR_LEN("AUTH_TYPE"),
					    CONST_STR_LEN("SSL_CLIENT_VERIFY"));
		} else {
			http_header_env_set(r,
					    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
					    CONST_STR_LEN("NONE"));
		}
	}

	/* Note: headers are parsed per-request even when using HAProxy PROXY
	 * protocol since Forwarded header might provide additional info and
	 * internal _L_ vars might be set for later use by mod_proxy or others*/
	/*if (pconf.hap_PROXY) return HANDLER_GO_ON;*/

	if (NULL == pconf.headers) return HANDLER_GO_ON;

	/* Do not reparse headers for same request, e.g. after HANDLER_COMEBACK
	 * from mod_rewrite, mod_magnet MAGNET_RESTART_REQUEST, mod_cgi
	 * cgi.local-redir, or gw_backend reconnect.  This has the implication
	 * that mod_magnet and mod_cgi with local-redir should not modify
	 * Forwarded or related headers and expect effects here */
	if (r->plugin_ctx[pconf.plid]) return HANDLER_GO_ON;

	const buffer *forwarded = NULL;
	int is_forwarded_header = 0;
	for (uint32_t k = 0; k < pconf.headers->used; ++k) {
		const data_string * const ds = (data_string *)pconf.headers->data[k];
		const buffer * const hdr = &ds->value;
		forwarded = http_header_request_get(r, ds->ext, BUF_PTR_LEN(hdr));
		if (forwarded) {
			is_forwarded_header = (ds->ext == HTTP_HEADER_FORWARDED);
			break;
		}
	}

	if (forwarded && is_connection_trusted_cached(r->con, &pconf)) {
		return (is_forwarded_header)
		  ? mod_extforward_Forwarded(r, &pconf, forwarded)
		  : mod_extforward_X_Forwarded_For(r, &pconf, forwarded);
	}
	else {
		if (r->conf.log_request_handling) {
			log_debug(r->conf.errh, __FILE__, __LINE__,
			  "no forward header found or "
			  "remote address %s is NOT a trusted proxy, skipping",
			  r->con->dst_addr_buf.ptr);
		}
		return HANDLER_GO_ON;
	}
}


REQUEST_FUNC(mod_extforward_handle_request_env) {
    handler_ctx * const hctx = r->con->plugin_ctx[((plugin_data *)p_d)->id];
    if (NULL == hctx || NULL == hctx->env) return HANDLER_GO_ON;
    const array * restrict env = hctx->env;
    for (uint32_t i = 0; i < env->used; ++i) {
        /* note: replaces values which may have been set by mod_openssl
         * (when mod_extforward is listed after mod_openssl in server.modules)*/
        const data_string *ds = (const data_string *)env->data[i];
        http_header_env_set(r, BUF_PTR_LEN(&ds->key), BUF_PTR_LEN(&ds->value));
    }
    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_extforward_restore) {
    handler_rctx **rctx =
      (handler_rctx **)&r->plugin_ctx[((plugin_data *)p_d)->id];
    if (*rctx) {
        handler_rctx_free(*rctx);
        *rctx = NULL;

        connection * const con = r->con;
        r->dst_addr = &con->dst_addr;
        r->dst_addr_buf = &con->dst_addr_buf;
        /* reset conf_cond cache; results may change */
        /* (even though other mods not expected to parse config in reset hook)*/
        config_cond_cache_reset_item(r, COMP_HTTP_REMOTE_IP);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_extforward_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL != hctx) {
        con->plugin_ctx[p->id] = NULL;
        if (NULL != hctx->saved_network_read)
            con->network_read = hctx->saved_network_read;
        handler_ctx_free(hctx);
    }

    return HANDLER_GO_ON;
}


static int mod_extforward_network_read (connection *con, chunkqueue *cq, off_t max_bytes);

CONNECTION_FUNC(mod_extforward_handle_con_accept)
{
    request_st * const r = &con->request;
    plugin_config pconf;
    mod_extforward_patch_config(r, p_d, &pconf);
    if (!pconf.hap_PROXY) return HANDLER_GO_ON;
    if (NULL == pconf.forwarder) return HANDLER_GO_ON;
    if (is_connection_trusted(con, &pconf)) {
        handler_ctx *hctx = handler_ctx_init();
        con->plugin_ctx[pconf.plid] = hctx;
        hctx->con_is_trusted = -1; /*(masquerade IP not yet known/checked)*/
        hctx->saved_network_read = con->network_read;
        con->network_read = mod_extforward_network_read;
    }
    else {
        if (r->conf.log_request_handling) {
            log_debug(r->conf.errh, __FILE__, __LINE__,
              "remote address %s is NOT a trusted proxy, skipping",
              con->dst_addr_buf.ptr);
        }
    }
    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_extforward_plugin_init(plugin *p);
int mod_extforward_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "extforward";

	p->init        = mod_extforward_init;
	p->handle_connection_accept = mod_extforward_handle_con_accept;
	p->handle_uri_raw = mod_extforward_uri_handler;
	p->handle_request_env = mod_extforward_handle_request_env;
	p->handle_request_reset = mod_extforward_restore;
	p->handle_connection_close = mod_extforward_handle_con_close;
	p->set_defaults  = mod_extforward_set_defaults;
	p->cleanup     = mod_extforward_free;

	return 0;
}




/* Modified from:
 *   http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 *
9. Sample code

The code below is an example of how a receiver may deal with both versions of
the protocol header for TCP over IPv4 or IPv6. The function is supposed to be
called upon a read event. Addresses may be directly copied into their final
memory location since they're transported in network byte order. The sending
side is even simpler and can easily be deduced from this sample code.
 *
 */

union hap_PROXY_hdr {
    struct {
        char line[108];
    } v1;
    struct {
        uint8_t sig[12];
        uint8_t ver_cmd;
        uint8_t fam;
        uint16_t len;
        union {
            struct {  /* for TCP/UDP over IPv4, len = 12 */
                uint32_t src_addr;
                uint32_t dst_addr;
                uint16_t src_port;
                uint16_t dst_port;
            } ip4;
            struct {  /* for TCP/UDP over IPv6, len = 36 */
                 uint8_t  src_addr[16];
                 uint8_t  dst_addr[16];
                 uint16_t src_port;
                 uint16_t dst_port;
            } ip6;
            struct {  /* for AF_UNIX sockets, len = 216 */
                 uint8_t src_addr[108];
                 uint8_t dst_addr[108];
            } unx;
        } addr;
    } v2;
    uint64_t ext[32]; /* 2k (- hdr) for v2 TLV extensions (at least 1536 MTU) */
};

/*
If the length specified in the PROXY protocol header indicates that additional
bytes are part of the header beyond the address information, a receiver may
choose to skip over and ignore those bytes, or attempt to interpret those
bytes.

The information in those bytes will be arranged in Type-Length-Value (TLV
vectors) in the following format.  The first byte is the Type of the vector.
The second two bytes represent the length in bytes of the value (not included
the Type and Length bytes), and following the length field is the number of
bytes specified by the length.
 */
struct pp2_tlv {
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    /*uint8_t value[0];*//* C99 zero-length array */
};

/*
The following types have already been registered for the <type> field :
 */

#define PP2_TYPE_ALPN             0x01
#define PP2_TYPE_AUTHORITY        0x02
#define PP2_TYPE_CRC32C           0x03
#define PP2_TYPE_NOOP             0x04
#define PP2_TYPE_UNIQUE_ID        0x05
#define PP2_TYPE_SSL              0x20
#define PP2_SUBTYPE_SSL_VERSION   0x21
#define PP2_SUBTYPE_SSL_CN        0x22
#define PP2_SUBTYPE_SSL_CIPHER    0x23
#define PP2_SUBTYPE_SSL_SIG_ALG   0x24
#define PP2_SUBTYPE_SSL_KEY_ALG   0x25
#define PP2_TYPE_NETNS            0x30

/*
For the type PP2_TYPE_SSL, the value is itself defined like this :
 */

struct pp2_tlv_ssl {
    uint8_t  client;
    uint32_t verify;
    /*struct pp2_tlv sub_tlv[0];*//* C99 zero-length array */
};

/*
And the <client> field is made of a bit field from the following values,
indicating which element is present :
 */

#define PP2_CLIENT_SSL            0x01
#define PP2_CLIENT_CERT_CONN      0x02
#define PP2_CLIENT_CERT_SESS      0x04




#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* returns 0 if needs to poll, <0 upon error or >0 is protocol vers (success) */
static int hap_PROXY_recv (const int fd, union hap_PROXY_hdr * const hdr, const int family, const int so_type)
{
    /*static const char v2sig[] =
        "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";*/
    static const char v2sig[12] =
        {0x0D,0x0A,0x0D,0x0A,0x00,0x0D,0x0A,0x51,0x55,0x49,0x54,0x0A};

    ssize_t ret;
    size_t sz;
    int ver;

    do {
        ret = recv(fd, hdr, sizeof(*hdr), MSG_PEEK|MSG_DONTWAIT|MSG_NOSIGNAL);
    }
  #ifdef _WIN32
    while (-1 == ret && WSAGetLastError() == WSAEINTR);
  #else
    while (-1 == ret && errno == EINTR);
  #endif

    if (-1 == ret)
      #ifdef _WIN32
        return (WSAGetLastError() == WSAEWOULDBLOCK) ? 0 : -1;
      #else
        return (errno == EAGAIN
                #ifdef EWOULDBLOCK
                #if EAGAIN != EWOULDBLOCK
                || errno == EWOULDBLOCK
                #endif
                #endif
               ) ? 0 : -1;
      #endif

    if (ret >= 16 && 0 == memcmp(&hdr->v2, v2sig, 12)
        && (hdr->v2.ver_cmd & 0xF0) == 0x20) {
        ver = 2;
        sz = 16 + (size_t)ntohs(hdr->v2.len);
        if ((size_t)ret < sz)
            return -2; /* truncated or too large header */

        switch (hdr->v2.ver_cmd & 0xF) {
          case 0x01: break; /* PROXY command */
          case 0x00: break; /* LOCAL command */
          default:   return -2; /* not a supported command */
        }
    }
    else if (ret >= 8 && 0 == memcmp(hdr->v1.line, "PROXY", 5)) {
        const char *end = memchr(hdr->v1.line, '\r', ret - 1);
        if (!end || end[1] != '\n')
            return -2; /* partial or invalid header */
        ver = 1;
        sz = (size_t)(end + 2 - hdr->v1.line); /* skip header + CRLF */
    }
    else {
        /* Wrong protocol */
        return -2;
    }

    /* we need to consume the appropriate amount of data from the socket
     * (overwrites existing contents of hdr with same data) */
    UNUSED(family);
    UNUSED(so_type);
    do {
      #if defined(MSG_TRUNC) && defined(__linux__)
        if ((family==AF_INET || family==AF_INET6) && so_type == SOCK_STREAM) {
            ret = recv(fd, hdr, sz, MSG_TRUNC|MSG_DONTWAIT|MSG_NOSIGNAL);
            if (ret >= 0 || errno != EINVAL) continue;
        }
      #endif
        ret = recv(fd, hdr, sz, MSG_DONTWAIT|MSG_NOSIGNAL);
    } while (-1 == ret && errno == EINTR);
    if (ret < 0) return -1;
    if (ret != (ssize_t)sz) {
        errno = EIO; /*(partial read; valid but unexpected; not handled)*/
        return -1;
    }
    if (1 == ver) hdr->v1.line[sz-2] = '\0'; /*terminate str to ease parsing*/
    return ver;
}


__attribute_pure__
static int mod_extforward_str_to_port (const char * const s)
{
    /*(more strict than strtol(); digits only)*/
    int port = 0;
    for (int i = 0; i < 5; ++i, port *= 10) {
        if (!light_isdigit(s[i])) return -1;
        port += (s[i] - '0');
        if (s[i+1] == '\0') return port;
    }
    return -1;
}

/* coverity[-tainted_data_sink: arg-1] */
static int mod_extforward_hap_PROXY_v1 (connection * const con,
                                        union hap_PROXY_hdr * const hdr)
{
  #ifdef __COVERITY__
    __coverity_tainted_data_sink__(hdr);
  #endif

    /* samples
     *   "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"
     *   "PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
     *   "PROXY UNKNOWN\r\n"
     *   "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
     */
    char *s = hdr->v1.line + sizeof("PROXY")-1; /*checked in hap_PROXY_recv()*/
    char *src_addr, *dst_addr, *src_port, *dst_port;
    int family;
    int src_lport, dst_lport;
    if (*s != ' ') return -1;
    ++s;
    if (s[0] == 'T' && s[1] == 'C' && s[2] == 'P' && s[4] == ' ') {
        if (s[3] == '4') {
            family = AF_INET;
        } else if (s[3] == '6') {
            family = AF_INET6;
        }
        else {
            return -1;
        }
        s += 5;
    }
    else if (0 == memcmp(s, "UNKNOWN", sizeof("UNKNOWN")-1)
             && (s[7] == '\0' || s[7] == ' ')) {
        return 0;     /* keep local connection address */
    }
    else {
        return -1;
    }

    /*(strsep() should be fairly portable, but is not standard)*/
    src_addr = s;
    dst_addr = strchr(src_addr, ' ');
    if (NULL == dst_addr) return -1;
    *dst_addr++ = '\0';
    src_port = strchr(dst_addr, ' ');
    if (NULL == src_port) return -1;
    *src_port++ = '\0';
    dst_port = strchr(src_port, ' ');
    if (NULL == dst_port) return -1;
    *dst_port++ = '\0';

    src_lport = mod_extforward_str_to_port(src_port);
    if (src_lport <= 0) return -1;
    dst_lport = mod_extforward_str_to_port(dst_port);
    if (dst_lport <= 0) return -1;

    if (1 != sock_addr_inet_pton(&con->dst_addr,
                                 src_addr, family, (unsigned short)src_lport))
        return -1;
    /* Forwarded by=... could be saved here.
     * (see additional comments in mod_extforward_hap_PROXY_v2()) */

    /* re-parse addr to string to normalize
     * (instead of trusting PROXY to provide canonicalized src_addr string)
     * (should prefer PROXY v2 protocol if concerned about performance) */
    sock_addr_inet_ntop_copy_buffer(&con->dst_addr_buf, &con->dst_addr);

    return 0;
}


/* coverity[-tainted_data_sink: arg-1] */
static int mod_extforward_hap_PROXY_v2 (connection * const con,
                                        union hap_PROXY_hdr * const hdr)
{
  #ifdef __COVERITY__
    __coverity_tainted_data_sink__(hdr);
  #endif

    /* If HAProxy-PROXY protocol used, then lighttpd acts as transparent proxy,
     * masquerading as servicing the client IP provided in by HAProxy-PROXY hdr.
     * The connecting con->dst_addr and con->dst_addr_buf are not saved here,
     * so that info is lost unless getsockname() and getpeername() are used.
     * One result is that mod_proxy will use the masqueraded IP instead of the
     * actual IP when updated Forwarded and X-Forwarded-For (but if actual
     * connection IPs needed, better to save the info here rather than use
     * syscalls to retrieve the info later).
     * (Exception: con->dst_addr can be further changed if mod_extforward parses
     *  Forwarded or X-Forwarded-For request headers later, after request headers
     *  have been received.)
     */

    /* Forwarded by=... could be saved here.  The by param is for backends to be
     * able to construct URIs for that interface (interface on server which
     * received request and made PROXY connection here), though that server
     * should provide that information in updated Forwarded or X-Forwarded-For
     * HTTP headers */
    /*struct sockaddr_storage by;*/

    /* Addresses provided by HAProxy-PROXY protocol are in network byte order.
     * Note: addr info is not validated, so do not accept HAProxy-PROXY
     * protocol from untrusted servers.  For example, untrusted servers from
     * which HAProxy-PROXY protocol is accepted (don't do that) could pretend
     * to be from the internal network and might thereby bypass security policy.
     */

    /* (Clear con->dst_addr with memset() in case actual and proxies IPs
     *  are different domains, e.g. one is IPv4 and the other is IPv6) */

    struct pp2_tlv *tlv;
    uint32_t sz = ntohs(hdr->v2.len);
    uint32_t len = 0;

    switch (hdr->v2.ver_cmd & 0xF) {
      case 0x01: break;    /* PROXY command */
      case 0x00: return  0;/* LOCAL command; keep local connection address */
      default:   return -1;/* should not happen; validated in hap_PROXY_recv()*/
    }

    /* PROXY command */

    switch (hdr->v2.fam) {
      case 0x11:  /* TCPv4 */
        sock_addr_assign(&con->dst_addr, AF_INET, hdr->v2.addr.ip4.src_port,
                                                 &hdr->v2.addr.ip4.src_addr);
        sock_addr_inet_ntop_copy_buffer(&con->dst_addr_buf, &con->dst_addr);
       #if 0
        ((struct sockaddr_in *)&by)->sin_family = AF_INET;
        ((struct sockaddr_in *)&by)->sin_addr.s_addr =
            hdr->v2.addr.ip4.dst_addr;
        ((struct sockaddr_in *)&by)->sin_port =
            hdr->v2.addr.ip4.dst_port;
       #endif
        len = (uint32_t)sizeof(hdr->v2.addr.ip4);
        break;
     #ifdef HAVE_IPV6
      case 0x21:  /* TCPv6 */
        sock_addr_assign(&con->dst_addr, AF_INET6, hdr->v2.addr.ip6.src_port,
                                                  &hdr->v2.addr.ip6.src_addr);
        sock_addr_inet_ntop_copy_buffer(&con->dst_addr_buf, &con->dst_addr);
       #if 0
        ((struct sockaddr_in6 *)&by)->sin6_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)&by)->sin6_addr,
            hdr->v2.addr.ip6.dst_addr, 16);
        ((struct sockaddr_in6 *)&by)->sin6_port =
            hdr->v2.addr.ip6.dst_port;
       #endif
        len = (uint32_t)sizeof(hdr->v2.addr.ip6);
        break;
     #endif
     #ifdef HAVE_SYS_UN_H
      case 0x31:  /* UNIX domain socket */
        {
            char *src_addr = (char *)hdr->v2.addr.unx.src_addr;
            char *z = memchr(src_addr, '\0', sizeof(hdr->v2.addr.unx.src_addr));
            if (NULL == z) return -1; /* invalid addr; too long */
            len = (uint32_t)(z - src_addr);
            /*if (0 == len) return -1;*//* abstract socket not supported; err?*/
            if (0 != sock_addr_assign(&con->dst_addr, AF_UNIX, 0, src_addr))
                return -1; /* invalid addr; too long */
            buffer_copy_string_len(&con->dst_addr_buf, src_addr, len);
        }
       #if 0 /*(dst_addr should be identical to src_addr for AF_UNIX)*/
        ((struct sockaddr_un *)&by)->sun_family = AF_UNIX;
        memcpy(&((struct sockaddr_un *)&by)->sun_path,
            hdr->v2.addr.unx.dst_addr, 108);
       #endif
        len = (uint32_t)sizeof(hdr->v2.addr.unx);
        break;
     #endif
      default:    /* keep local connection address; unsupported protocol */
        return 0;
    }

    /* (optional) Type-Length-Value (TLV vectors) follow addresses */

    if (3 + len > sz) return 0;

    handler_ctx * const hctx = con->plugin_ctx[mod_extforward_plugin_data->id];
    tlv = (struct pp2_tlv *)((char *)hdr + 16);
    for (sz -= len, len -= 3; sz >= 3; sz -= 3 + len) {
        tlv = (struct pp2_tlv *)((char *)tlv + 3 + len);
        len = ((uint32_t)tlv->length_hi << 8) | tlv->length_lo;
        if (3 + len > sz) break; /*(invalid TLV)*/
        const char *k;
        uint32_t klen;
        switch (tlv->type) {
         #if 0 /*(not implemented here)*/
          case PP2_TYPE_ALPN:
          case PP2_TYPE_AUTHORITY:
          case PP2_TYPE_CRC32C:
         #endif
          case PP2_TYPE_SSL: {
            if (len < 5) continue;
            static const uint32_t zero = 0;
            struct pp2_tlv_ssl *tlv_ssl =
              (struct pp2_tlv_ssl *)(void *)((char *)tlv+3);
            struct pp2_tlv *subtlv = tlv;
            if (tlv_ssl->client & PP2_CLIENT_SSL) {
                con->proto_default_port = 443; /* "https" */
            }
            if ((tlv_ssl->client & (PP2_CLIENT_CERT_CONN|PP2_CLIENT_CERT_SESS))
                && 0 == memcmp(&tlv_ssl->verify, &zero, 4)) { /* misaligned */
                hctx->ssl_client_verify = 1;
            }
            if (len < 5 + 3) continue;
            if (NULL == hctx->env) hctx->env = array_init(8);
            for (uint32_t subsz = len-5, n = 5; subsz >= 3; subsz -= 3 + n) {
                subtlv = (struct pp2_tlv *)((char *)subtlv + 3 + n);
                n = ((uint32_t)subtlv->length_hi << 8) | subtlv->length_lo;
                if (3 + n > subsz) break; /*(invalid TLV)*/
                switch (subtlv->type) {
                  case PP2_SUBTYPE_SSL_VERSION:
                    k = "SSL_PROTOCOL";
                    klen = sizeof("SSL_PROTOCOL")-1;
                    break;
                  case PP2_SUBTYPE_SSL_CN:
                    /* (tlv_ssl->client & PP2_CLIENT_CERT_CONN)
                     *   or
                     * (tlv_ssl->client & PP2_CLIENT_CERT_SESS) */
                    k = "SSL_CLIENT_S_DN_CN";
                    klen = sizeof("SSL_CLIENT_S_DN_CN")-1;
                    break;
                  case PP2_SUBTYPE_SSL_CIPHER:
                    k = "SSL_CIPHER";
                    klen = sizeof("SSL_CIPHER")-1;
                    break;
                  case PP2_SUBTYPE_SSL_SIG_ALG:
                    k = "SSL_SERVER_A_SIG";
                    klen = sizeof("SSL_SERVER_A_SIG")-1;
                    break;
                  case PP2_SUBTYPE_SSL_KEY_ALG:
                    k = "SSL_SERVER_A_KEY";
                    klen = sizeof("SSL_SERVER_A_KEY")-1;
                    break;
                  default:
                    continue;
                }
                array_set_key_value(hctx->env, k, klen, (char *)subtlv+3, n);
            }
            continue;
          }
          case PP2_TYPE_UNIQUE_ID:
            k = "PP2_UNIQUE_ID";
            klen = sizeof("PP2_UNIQUE_ID")-1;
            break;
         #if 0 /*(not implemented here)*/
          case PP2_TYPE_NETNS:
         #endif
          /*case PP2_TYPE_NOOP:*//* no-op */
          default:
            continue;
        }
        if (NULL == hctx->env) hctx->env = array_init(8);
        array_set_key_value(hctx->env, k, klen, (char *)tlv+3, len);
    }

    return 0;
}


static int mod_extforward_network_read (connection *con,
                                        chunkqueue *cq, off_t max_bytes)
{
    /* XXX: when using hap-PROXY protocol, currently avoid overhead of setting
     * _L_ environment variables for mod_proxy to accurately set Forwarded hdr
     * In the future, might add config switch to enable doing this extra work */

    union hap_PROXY_hdr hdr;
    log_error_st *errh;
    const int family = sock_addr_get_family(&con->dst_addr);
    int rc = hap_PROXY_recv(con->fd, &hdr, family, SOCK_STREAM);
    switch (rc) {
      case  2: rc = mod_extforward_hap_PROXY_v2(con, &hdr); break;
      case  1: rc = mod_extforward_hap_PROXY_v1(con, &hdr); break;
      case  0: return  0; /*(errno == EAGAIN || errno == EWOULDBLOCK)*/
      case -1: errh = con->srv->errh;
               log_perror(errh,__FILE__,__LINE__,"hap-PROXY recv()");
               rc = -1; break;
      case -2: errh = con->srv->errh;
               log_error(errh,__FILE__,__LINE__,
                 "hap-PROXY proto received invalid/unsupported request");
               __attribute_fallthrough__
      default: rc = -1; break;
    }

    handler_ctx * const hctx = con->plugin_ctx[mod_extforward_plugin_data->id];
    con->network_read = hctx->saved_network_read;
    hctx->saved_network_read = NULL;
    return (0 == rc) ? con->network_read(con, cq, max_bytes) : rc;
}
