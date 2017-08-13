#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "request.h"
#include "inet_ntop_cache.h"

#include "plugin.h"

#include "configfile.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sys-socket.h"

/**
 * mod_extforward.c for lighttpd, by comman.kang <at> gmail <dot> com
 *                  extended, modified by Lionel Elie Mamane (LEM), lionel <at> mamane <dot> lu
 *                  support chained proxies by glen@delfi.ee, #1528
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
 * Note: The effect of this module is variable on $HTTP["remotip"] directives and
 *       other module's remote ip dependent actions.
 *  Things done by modules before we change the remoteip or after we reset it will match on the proxy's IP.
 *  Things done in between these two moments will match on the real client's IP.
 *  The moment things are done by a module depends on in which hook it does things and within the same hook
 *  on whether they are before/after us in the module loading order
 *  (order in the server.modules directive in the config file).
 *
 * Tested behaviours:
 *
 *  mod_access: Will match on the real client.
 *
 *  mod_accesslog:
 *   In order to see the "real" ip address in access log ,
 *   you'll have to load mod_extforward after mod_accesslog.
 *   like this:
 *
 *    server.modules  = (
 *       .....
 *       mod_accesslog,
 *       mod_extforward
 *    )
 */


/* plugin config for all request/connections */

typedef enum {
	PROXY_FORWARDED_NONE         = 0x00,
	PROXY_FORWARDED_FOR          = 0x01,
	PROXY_FORWARDED_PROTO        = 0x02,
	PROXY_FORWARDED_HOST         = 0x04,
	PROXY_FORWARDED_BY           = 0x08,
	PROXY_FORWARDED_REMOTE_USER  = 0x10
} proxy_forwarded_t;

typedef struct {
	array *forwarder;
	array *headers;
	array *opts_params;
	unsigned int opts;
	unsigned short int hap_PROXY;
	unsigned short int hap_PROXY_ssl_client_verify;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

static plugin_data *mod_extforward_plugin_data_singleton;
static int extforward_check_proxy;


/* context , used for restore remote ip */

typedef struct {
	/* per-request state */
	sock_addr saved_remote_addr;
	buffer *saved_remote_addr_buf;

	/* hap-PROXY protocol prior to receiving first request */
	int(*saved_network_read)(server *, connection *, chunkqueue *, off_t);

	/* connection-level state applied to requests in handle_request_env */
	array *env;
	int ssl_client_verify;
} handler_ctx;


static handler_ctx * handler_ctx_init(void) {
	handler_ctx * hctx;
	hctx = calloc(1, sizeof(*hctx));
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	free(hctx);
}

/* init the plugin data */
INIT_FUNC(mod_extforward_init) {
	plugin_data *p;
	p = calloc(1, sizeof(*p));
	mod_extforward_plugin_data_singleton = p;
	return p;
}

/* destroy the plugin data */
FREE_FUNC(mod_extforward_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->forwarder);
			array_free(s->headers);
			array_free(s->opts_params);

			free(s);
		}
		free(p->config_storage);
	}


	free(p);

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_extforward_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "extforward.forwarder",       NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "extforward.headers",         NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "extforward.params",          NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ "extforward.hap-PROXY",       NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 3 */
		{ "extforward.hap-PROXY-ssl-client-verify", NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->forwarder    = array_init();
		s->headers      = array_init();
		s->opts_params  = array_init();
		s->opts         = PROXY_FORWARDED_NONE;

		cv[0].destination = s->forwarder;
		cv[1].destination = s->headers;
		cv[2].destination = s->opts_params;
		cv[3].destination = &s->hap_PROXY;
		cv[4].destination = &s->hap_PROXY_ssl_client_verify;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!array_is_kvstring(s->forwarder)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for extforward.forwarder; expected list of \"IPaddr\" => \"trust\"");
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->headers)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for extforward.headers; expected list of \"headername\"");
			return HANDLER_ERROR;
		}

		/* default to "X-Forwarded-For" or "Forwarded-For" if extforward.headers not specified or empty */
		if (!s->hap_PROXY && 0 == s->headers->used && (0 == i || NULL != array_get_element(config->value, "extforward.headers"))) {
			data_string *ds;
			ds = data_string_init();
			buffer_copy_string_len(ds->value, CONST_STR_LEN("X-Forwarded-For"));
			array_insert_unique(s->headers, (data_unset *)ds);
			ds = data_string_init();
			buffer_copy_string_len(ds->value, CONST_STR_LEN("Forwarded-For"));
			array_insert_unique(s->headers, (data_unset *)ds);
		}

		if (!array_is_kvany(s->opts_params)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for extforward.params; expected ( \"param\" => \"value\" )");
			return HANDLER_ERROR;
		}
		for (size_t j = 0, used = s->opts_params->used; j < used; ++j) {
			proxy_forwarded_t param;
			data_unset *du = s->opts_params->data[j];
		      #if 0  /*("for" and "proto" historical behavior: always enabled)*/
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("by"))) {
				param = PROXY_FORWARDED_BY;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("for"))) {
				param = PROXY_FORWARDED_FOR;
			} else
		      #endif
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("host"))) {
				param = PROXY_FORWARDED_HOST;
		      #if 0
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proto"))) {
				param = PROXY_FORWARDED_PROTO;
		      #endif
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("remote_user"))) {
				param = PROXY_FORWARDED_REMOTE_USER;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					        "extforward.params keys must be one of: host, remote_user, but not:", du->key);
				return HANDLER_ERROR;
			}
			if (du->type == TYPE_STRING) {
				data_string *ds = (data_string *)du;
				if (buffer_is_equal_string(ds->value, CONST_STR_LEN("enable"))) {
					s->opts |= param;
				} else if (!buffer_is_equal_string(ds->value, CONST_STR_LEN("disable"))) {
					log_error_write(srv, __FILE__, __LINE__, "sb",
						        "extforward.params values must be one of: 0, 1, enable, disable; error for key:", du->key);
					return HANDLER_ERROR;
				}
			} else if (du->type == TYPE_INTEGER) {
				data_integer *di = (data_integer *)du;
				if (di->value) s->opts |= param;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					        "extforward.params values must be one of: 0, 1, enable, disable; error for key:", du->key);
				return HANDLER_ERROR;
			}
		}
	}

	/* attempt to warn if mod_extforward is not last module loaded to hook
	 * handle_connection_accept.  (Nice to have, but remove this check if
	 * it reaches too far into internals and prevents other code changes.)
	 * While it would be nice to check connection_handle_accept plugin slot
	 * to make sure mod_extforward is last, that info is private to plugin.c
	 * so merely warn if mod_openssl is loaded after mod_extforward, though
	 * future modules which hook connection_handle_accept might be missed.*/
	for (i = 0; i < srv->config_context->used; ++i) {
		plugin_config *s = p->config_storage[i];
		if (s->hap_PROXY) {
			size_t j;
			for (j = 0; j < srv->srvconf.modules->used; ++j) {
				data_string *ds = (data_string *)srv->srvconf.modules->data[j];
				if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_extforward"))) {
					break;
				}
			}
			for (; j < srv->srvconf.modules->used; ++j) {
				data_string *ds = (data_string *)srv->srvconf.modules->data[j];
				if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_openssl"))) {
					log_error_write(srv, __FILE__, __LINE__, "s",
						        "mod_extforward must be loaded after mod_openssl in server.modules when extforward.hap-PROXY = \"enable\"");
					break;
				}
			}
			break;
		}
	}

	for (i = 0; i < srv->srvconf.modules->used; i++) {
		data_string *ds = (data_string *)srv->srvconf.modules->data[i];
		if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_proxy"))) {
			extforward_check_proxy = 1;
			break;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_extforward_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(forwarder);
	PATCH(headers);
	PATCH(opts);
	PATCH(hap_PROXY);
	PATCH(hap_PROXY_ssl_client_verify);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("extforward.forwarder"))) {
				PATCH(forwarder);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("extforward.headers"))) {
				PATCH(headers);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("extforward.params"))) {
				PATCH(opts);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("extforward.hap-PROXY"))) {
				PATCH(hap_PROXY);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("extforward.hap-PROXY-ssl-client-verify"))) {
				PATCH(hap_PROXY_ssl_client_verify);
			}
		}
	}

	return 0;
}
#undef PATCH


static void put_string_into_array_len(array *ary, const char *str, int len)
{
	data_string *tempdata;
	if (len == 0)
		return;
	tempdata = data_string_init();
	buffer_copy_string_len(tempdata->value,str,len);
	array_insert_unique(ary,(data_unset *)tempdata);
}
/*
   extract a forward array from the environment
*/
static array *extract_forward_array(buffer *pbuffer)
{
	array *result = array_init();
	if (!buffer_string_is_empty(pbuffer)) {
		char *base, *curr;
		/* state variable, 0 means not in string, 1 means in string */
		int in_str = 0;
		for (base = pbuffer->ptr, curr = pbuffer->ptr; *curr; curr++) {
			if (in_str) {
				if ((*curr > '9' || *curr < '0') && *curr != '.' && *curr != ':' && (*curr < 'a' || *curr > 'f') && (*curr < 'A' || *curr > 'F')) {
					/* found an separator , insert value into result array */
					put_string_into_array_len(result, base, curr - base);
					/* change state to not in string */
					in_str = 0;
				}
			} else {
				if ((*curr >= '0' && *curr <= '9') || *curr == ':' || (*curr >= 'a' && *curr <= 'f') || (*curr >= 'A' && *curr <= 'F')) {
					/* found leading char of an IP address, move base pointer and change state */
					base = curr;
					in_str = 1;
				}
			}
		}
		/* if breaking out while in str, we got to the end of string, so add it */
		if (in_str) {
			put_string_into_array_len(result, base, curr - base);
		}
	}
	return result;
}

#define IP_TRUSTED 1
#define IP_UNTRUSTED 0
/*
 * check whether ip is trusted, return 1 for trusted , 0 for untrusted
 */
static int is_proxy_trusted(const buffer *ipstr, plugin_data *p)
{
	data_string* allds = (data_string *)array_get_element(p->conf.forwarder, "all");

	if (allds) {
		if (strcasecmp(allds->value->ptr, "trust") == 0) {
			return IP_TRUSTED;
		} else {
			return IP_UNTRUSTED;
		}
	}

	return (data_string *)array_get_element_klen(p->conf.forwarder, CONST_BUF_LEN(ipstr)) ? IP_TRUSTED : IP_UNTRUSTED;
}

/*
 * Return last address of proxy that is not trusted.
 * Do not accept "all" keyword here.
 */
static const char *last_not_in_array(array *a, plugin_data *p)
{
	array *forwarder = p->conf.forwarder;
	int i;

	for (i = a->used - 1; i >= 0; i--) {
		data_string *ds = (data_string *)a->data[i];
		if (!array_get_element_klen(forwarder, CONST_BUF_LEN(ds->value))) {
			return ds->value->ptr;
		}
	}
	return NULL;
}

static int mod_extforward_set_addr(server *srv, connection *con, plugin_data *p, const char *addr) {
	sock_addr sock;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "using address:", addr);
	}

	sock.plain.sa_family = AF_UNSPEC;
	if (1 != sock_addr_from_str_numeric(srv, &sock, addr)) return 0;
	if (sock.plain.sa_family == AF_UNSPEC) return 0;

	/* we found the remote address, modify current connection and save the old address */
	if (hctx) {
		if (hctx->saved_remote_addr_buf) {
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__, "s",
					"-- mod_extforward_uri_handler already patched this connection, resetting state");
			}
			con->dst_addr = hctx->saved_remote_addr;
			buffer_free(con->dst_addr_buf);
			con->dst_addr_buf = hctx->saved_remote_addr_buf;
			hctx->saved_remote_addr_buf = NULL;
		}
	} else {
		con->plugin_ctx[p->id] = hctx = handler_ctx_init();
	}
	/* save old address */
	if (extforward_check_proxy) {
		array_set_key_value(con->environment, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_FOR"), CONST_BUF_LEN(con->dst_addr_buf));
	}
	hctx->saved_remote_addr = con->dst_addr;
	hctx->saved_remote_addr_buf = con->dst_addr_buf;
	/* patch connection address */
	con->dst_addr = sock;
	con->dst_addr_buf = buffer_init_string(addr);

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "ss",
				"patching con->dst_addr_buf for the accesslog:", addr);
	}

	/* Now, clean the conf_cond cache, because we may have changed the results of tests */
	config_cond_cache_reset_item(srv, con, COMP_HTTP_REMOTE_IP);

	return 1;
}

static void mod_extforward_set_proto(server *srv, connection *con, const char *proto, size_t protolen) {
	if (0 != protolen && !buffer_is_equal_caseless_string(con->uri.scheme, proto, protolen)) {
		/* update scheme if X-Forwarded-Proto is set
		 * Limitations:
		 * - Only "http" or "https" are currently accepted since the request to lighttpd currently has to
		 *   be HTTP/1.0 or HTTP/1.1 using http or https.  If this is changed, then the scheme from this
		 *   untrusted header must be checked to contain only alphanumeric characters, and to be a
		 *   reasonable length, e.g. < 256 chars.
		 * - con->uri.scheme is not reset in mod_extforward_restore() but is currently not an issues since
		 *   con->uri.scheme will be reset by next request.  If a new module uses con->uri.scheme in the
		 *   handle_request_done hook, then should evaluate if that module should use the forwarded value
		 *   (probably) or the original value.
		 */
		if (extforward_check_proxy) {
			array_set_key_value(con->environment, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_PROTO"), CONST_BUF_LEN(con->uri.scheme));
		}
		if (0 == buffer_caseless_compare(proto, protolen, CONST_STR_LEN("https"))) {
			buffer_copy_string_len(con->uri.scheme, CONST_STR_LEN("https"));
			config_cond_cache_reset_item(srv, con, COMP_HTTP_SCHEME);
		} else if (0 == buffer_caseless_compare(proto, protolen, CONST_STR_LEN("http"))) {
			buffer_copy_string_len(con->uri.scheme, CONST_STR_LEN("http"));
			config_cond_cache_reset_item(srv, con, COMP_HTTP_SCHEME);
		}
	}
}

static handler_t mod_extforward_X_Forwarded_For(server *srv, connection *con, plugin_data *p, buffer *x_forwarded_for) {
	/* build forward_array from forwarded data_string */
	array *forward_array = extract_forward_array(x_forwarded_for);
	const char *real_remote_addr = last_not_in_array(forward_array, p);
	if (real_remote_addr != NULL) { /* parsed */
		/* get scheme if X-Forwarded-Proto is set
		 * Limitations:
		 * - X-Forwarded-Proto may or may not be set by proxies, even if X-Forwarded-For is set
		 * - X-Forwarded-Proto may be a comma-separated list if there are multiple proxies,
		 *   but the historical behavior of the code below only honored it if there was exactly one value
		 *   (not done: walking backwards in X-Forwarded-Proto the same num of steps
		 *    as in X-Forwarded-For to find proto set by last trusted proxy)
		 */
		data_string *x_forwarded_proto = (data_string *)array_get_element(con->request.headers, "X-Forwarded-Proto");
		if (mod_extforward_set_addr(srv, con, p, real_remote_addr) && NULL != x_forwarded_proto) {
			mod_extforward_set_proto(srv, con, CONST_BUF_LEN(x_forwarded_proto->value));
		}
	}
	array_free(forward_array);
	return HANDLER_GO_ON;
}

static int find_end_quoted_string (const char * const s, int i) {
    do {
        ++i;
    } while (s[i] != '"' && s[i] != '\0' && (s[i] != '\\' || s[++i] != '\0'));
    return i;
}

static int find_next_semicolon_or_comma_or_eq (const char * const s, int i) {
    for (; s[i] != '=' && s[i] != ';' && s[i] != ',' && s[i] != '\0'; ++i) {
        if (s[i] == '"') {
            i = find_end_quoted_string(s, i);
            if (s[i] == '\0') return -1;
        }
    }
    return i;
}

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
    size_t len = buffer_string_length(b);
    char *p = memchr(b->ptr, '\\', len);

    if (NULL == p) return 1; /*(nothing to do)*/

    len -= (size_t)(p - b->ptr);
    for (size_t i = 0; i < len; ++i) {
        if (p[i] == '\\') {
            if (++i == len) return 0; /*(invalid trailing backslash)*/
        }
        p[j++] = p[i];
    }
    buffer_string_set_length(b, (size_t)(p+j - b->ptr));
    return 1;
}

static handler_t mod_extforward_Forwarded (server *srv, connection *con, plugin_data *p, buffer *forwarded) {
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
    int used = (int)buffer_string_length(forwarded);
    int ofor = -1, oproto, ohost, oby, oremote_user;
    int offsets[256];/*(~50 params is more than reasonably expected to handle)*/
    while (i < used) {
        while (s[i] == ' ' || s[i] == '\t') ++i;
        if (s[i] == ';') { ++i; continue; }
        if (s[i] == ',') {
            if (j >= (int)(sizeof(offsets)/sizeof(int))) break;
            offsets[++j] = -1; /*("offset" separating params from next proxy)*/
            ++i;
            continue;
        }
        if (s[i] == '\0') break;

        k = i;
        i = find_next_semicolon_or_comma_or_eq(s, i);
        if (i < 0) {
            /*(reject IP spoofing if attacker sets improper quoted-string)*/
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "invalid quoted-string in Forwarded header");
            con->http_status = 400; /* Bad Request */
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        if (s[i] != '=') continue;
        klen = i - k;
        v = ++i;
        i = find_next_semicolon_or_comma(s, i);
        if (i < 0) {
            /*(reject IP spoofing if attacker sets improper quoted-string)*/
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "invalid quoted-string in Forwarded header");
            con->http_status = 400; /* Bad Request */
            con->mode = DIRECT;
            return HANDLER_FINISHED;
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
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "Too many params in Forwarded header");
        con->http_status = 400; /* Bad Request */
        con->mode = DIRECT;
        return HANDLER_FINISHED;
    }

    if (-1 == j) return HANDLER_GO_ON;  /* make no changes */
    used = j+1;
    offsets[used] = -1; /* mark end of last set of params */

    while (j > 0) { /*(param=value pairs, so j > 0, not j >= 0)*/
        if (-1 == offsets[j]) { --j; continue; }
        do {
            j -= 3; /*(k, klen, v, vlen come in sets of 4)*/
        } while ((3 != offsets[j+1]  /* 3 == sizeof("for")-1 */
                  || 0 != buffer_caseless_compare(s+offsets[j], 3, "for", 3))
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
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "Invalid IPv6 addr in Forwarded header");
                    con->http_status = 400; /* Bad Request */
                    con->mode = DIRECT;
                    return HANDLER_FINISHED;
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
            int trusted = (NULL != array_get_element_klen(p->conf.forwarder, s+v, vlen-v));

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
        rc = mod_extforward_set_addr(srv, con, p, s+offsets[ofor+2]);
        *ipend = c;
        if (!rc) return HANDLER_GO_ON; /* invalid addr; make no changes */
    }
    else {
        return HANDLER_GO_ON; /* make no changes */
    }

    /* parse out params associated with for=<ip> addr set above */
    oproto = ohost = oby = oremote_user = -1;
    j = ofor;
    if (j > 0) { do { --j; } while (j > 0 && -1 != offsets[j]); }
    if (-1 == offsets[j]) ++j;
    if (j == ofor) j += 4;
    for (; -1 != offsets[j]; j+=4) { /*(k, klen, v, vlen come in sets of 4)*/
        switch (offsets[j+1]) {
         #if 0
          case 2:
            if (0 == buffer_caseless_compare(s+offsets[j],2,"by",2))
                oby = j;
            break;
         #endif
         #if 0
          /*(already handled above to find IP prior to earliest trusted proxy)*/
          case 3:
            if (0 == buffer_caseless_compare(s+offsets[j],3,"for",3))
                ofor = j;
            break;
         #endif
          case 4:
            if (0 == buffer_caseless_compare(s+offsets[j],4,"host",4))
                ohost = j;
            break;
          case 5:
            if (0 == buffer_caseless_compare(s+offsets[j],5,"proto",5))
                oproto = j;
            break;
          case 11:
            if (0 == buffer_caseless_compare(s+offsets[j],11,"remote_user",11))
                oremote_user = j;
            break;
          default:
            break;
        }
    }
    i = ++j;

    if (-1 != oproto) {
        /* remove trailing spaces/tabs, and double-quotes from proto
         * (note: not unescaping backslash escapes in quoted string) */
        v = offsets[oproto+2];
        vlen = v + offsets[oproto+3];
        while (vlen > v && (s[vlen-1] == ' ' || s[vlen-1] == '\t')) --vlen;
        if (vlen > v+1 && s[v] == '"' && s[vlen-1] == '"') { ++v; --vlen; }
        mod_extforward_set_proto(srv, con, s+v, vlen-v);
    }

    if (p->conf.opts & PROXY_FORWARDED_HOST) {
        /* Limitations:
         * - con->request.http_host is not reset in mod_extforward_restore()
         *   but is currently not an issues since con->request.http_host will be
         *   reset by next request.  If a new module uses con->request.http_host
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
                && 0 == buffer_caseless_compare(s+offsets[j], 4, "host", 4))
                ohost = j;
            j += 4; /*(k, klen, v, vlen come in sets of 4)*/
        }
        if (-1 != ohost) {
            if (extforward_check_proxy
                && !buffer_string_is_empty(con->request.http_host)) {
                array_set_key_value(con->environment,
                                    CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_HOST"),
                                    CONST_BUF_LEN(con->request.http_host));
            }
            /* remove trailing spaces/tabs, and double-quotes from host */
            v = offsets[ohost+2];
            vlen = v + offsets[ohost+3];
            while (vlen > v && (s[vlen-1] == ' ' || s[vlen-1] == '\t')) --vlen;
            if (vlen > v+1 && s[v] == '"' && s[vlen-1] == '"') {
                ++v; --vlen;
                buffer_copy_string_len(con->request.http_host, s+v, vlen-v);
                if (!buffer_backslash_unescape(con->request.http_host)) {
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "invalid host= value in Forwarded header");
                    con->http_status = 400; /* Bad Request */
                    con->mode = DIRECT;
                    return HANDLER_FINISHED;
                }
            }
            else {
                buffer_copy_string_len(con->request.http_host, s+v, vlen-v);
            }

            if (0 != http_request_host_policy(con, con->request.http_host,
                                              con->uri.scheme)) {
                /*(reject invalid chars in Host)*/
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "invalid host= value in Forwarded header");
                con->http_status = 400; /* Bad Request */
                con->mode = DIRECT;
                return HANDLER_FINISHED;
            }

            config_cond_cache_reset_item(srv, con, COMP_HTTP_HOST);
        }
    }

    if (p->conf.opts & PROXY_FORWARDED_REMOTE_USER) {
        /* find remote_user param set by closest proxy
         * (auth may have been handled by any trusted proxy in proxy chain) */
        for (j = i; j < used; ) {
            if (-1 == offsets[j]) { ++j; continue; }
            if (11 == offsets[j+1]
                && 0==buffer_caseless_compare(s+offsets[j],11,"remote_user",11))
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
                data_string *dsuser;
                ++v; --vlen;
                array_set_key_value(con->environment,
                                    CONST_STR_LEN("REMOTE_USER"), s+v, vlen-v);
                dsuser = (data_string *)
                  array_get_element(con->environment, "REMOTE_USER");
                force_assert(NULL != dsuser);
                if (!buffer_backslash_unescape(dsuser->value)) {
                    log_error_write(srv, __FILE__, __LINE__, "s",
                      "invalid remote_user= value in Forwarded header");
                    con->http_status = 400; /* Bad Request */
                    con->mode = DIRECT;
                    return HANDLER_FINISHED;
                }
            }
            else {
                array_set_key_value(con->environment,
                                    CONST_STR_LEN("REMOTE_USER"), s+v, vlen-v);
            }
        }
    }

  #if 0
    if ((p->conf.opts & PROXY_FORWARDED_CREATE_XFF)
        && NULL == array_get_element(con->request.headers, "X-Forwarded-For")) {
        /* create X-Forwarded-For if not present
         * (and at least original connecting IP is a trusted proxy) */
        buffer *xff;
        data_string *dsxff = (data_string *)
          array_get_unused_element(con->request.headers, TYPE_STRING);
        if (NULL == dsxff) dsxff = data_string_init();
        buffer_copy_string_len(dsxff->key, CONST_STR_LEN("X-Forwarded-For"));
        array_insert_unique(con->request.headers, (data_unset *)dsxff);
        xff = dsxff->value;
        for (j = 0; j < used; ) {
            if (-1 == offsets[j]) { ++j; continue; }
            if (3 == offsets[j+1]
                && 0 == buffer_caseless_compare(s+offsets[j], 3, "for", 3)) {
                if (!buffer_string_is_empty(xff))
                    buffer_append_string_len(xff, CONST_STR_LEN(", "));
                /* quoted-string, IPv6 brackets, and :port already removed */
                v = offsets[j+2];
                vlen = offsets[j+3];
                buffer_append_string_len(xff, s+v, vlen);
                if (s[v-1] != '=') { /*(must have been quoted-string)*/
                    char *x =
                      memchr(xff->ptr+buffer_string_length(xff)-vlen,'\\',vlen);
                    if (NULL != x) { /* backslash unescape in-place */
                        for (v = 0; x[v]; ++x) {
                            if (x[v] == '\\' && x[++v] == '\0')
                                break; /*(invalid trailing backslash)*/
                            *x = x[v];
                        }
                        buffer_string_set_length(xff, x - xff->ptr);
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
	plugin_data *p = p_d;
	data_string *forwarded = NULL;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	mod_extforward_patch_connection(srv, con, p);

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "s",
			"-- mod_extforward_uri_handler called");
	}

	if (p->conf.hap_PROXY_ssl_client_verify) {
		data_string *ds;
		if (NULL != hctx && hctx->ssl_client_verify && NULL != hctx->env
		    && NULL != (ds = (data_string *)array_get_element(hctx->env, "SSL_CLIENT_S_DN_CN"))) {
			array_set_key_value(con->environment,
					    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
					    CONST_STR_LEN("SUCCESS"));
			array_set_key_value(con->environment,
					    CONST_STR_LEN("REMOTE_USER"),
					    CONST_BUF_LEN(ds->value));
			array_set_key_value(con->environment,
					    CONST_STR_LEN("AUTH_TYPE"),
					    CONST_STR_LEN("SSL_CLIENT_VERIFY"));
		} else {
			array_set_key_value(con->environment,
					    CONST_STR_LEN("SSL_CLIENT_VERIFY"),
					    CONST_STR_LEN("NONE"));
		}
	}

	for (size_t k = 0; k < p->conf.headers->used && NULL == forwarded; ++k) {
		forwarded = (data_string *) array_get_element_klen(con->request.headers, CONST_BUF_LEN(((data_string *)p->conf.headers->data[k])->value));
	}
	if (NULL == forwarded) {
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "s", "no forward header found, skipping");
		}

		return HANDLER_GO_ON;
	}

	/* if the remote ip itself is not trusted, then do nothing */
	if (IP_UNTRUSTED == is_proxy_trusted(con->dst_addr_buf, p)) {
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "sbs",
					"remote address", con->dst_addr_buf, "is NOT a trusted proxy, skipping");
		}

		return HANDLER_GO_ON;
	}

	if (buffer_is_equal_caseless_string(forwarded->key, CONST_STR_LEN("Forwarded"))) {
		return mod_extforward_Forwarded(srv, con, p, forwarded->value);
	}

	return mod_extforward_X_Forwarded_For(srv, con, p, forwarded->value);
}


CONNECTION_FUNC(mod_extforward_handle_request_env) {
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    UNUSED(srv);
    if (NULL == hctx || NULL == hctx->env) return HANDLER_GO_ON;
    for (size_t i=0; i < hctx->env->used; ++i) {
        /* note: replaces values which may have been set by mod_openssl
         * (when mod_extforward is listed after mod_openssl in server.modules)*/
        data_string *ds = (data_string *)hctx->env->data[i];
        array_set_key_value(con->environment,
                            CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
    }
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_extforward_restore) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (!hctx) return HANDLER_GO_ON;

	if (NULL != hctx->saved_network_read) {
		con->network_read = hctx->saved_network_read;
		hctx->saved_network_read = NULL;
	}

	if (NULL != hctx->saved_remote_addr_buf) {
		con->dst_addr = hctx->saved_remote_addr;
		buffer_free(con->dst_addr_buf);
		con->dst_addr_buf = hctx->saved_remote_addr_buf;
		hctx->saved_remote_addr_buf = NULL;
		/* Now, clean the conf_cond cache, because we may have changed the results of tests */
		config_cond_cache_reset_item(srv, con, COMP_HTTP_REMOTE_IP);
	}

	if (NULL == hctx->env) {
		handler_ctx_free(hctx);
		con->plugin_ctx[p->id] = NULL;
	}

	return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_extforward_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    UNUSED(srv);
    if (NULL != hctx) {
        if (NULL != hctx->saved_network_read) {
            con->network_read = hctx->saved_network_read;
        }
        if (NULL != hctx->saved_remote_addr_buf) {
            con->dst_addr = hctx->saved_remote_addr;
            buffer_free(con->dst_addr_buf);
            con->dst_addr_buf = hctx->saved_remote_addr_buf;
        }
        if (NULL != hctx->env) {
            array_free(hctx->env);
        }
        handler_ctx_free(hctx);
        con->plugin_ctx[p->id] = NULL;
    }

    return HANDLER_GO_ON;
}


static int mod_extforward_network_read (server *srv, connection *con, chunkqueue *cq, off_t max_bytes);

CONNECTION_FUNC(mod_extforward_handle_con_accept)
{
    plugin_data *p = p_d;
    mod_extforward_patch_connection(srv, con, p);
    if (!p->conf.hap_PROXY) return HANDLER_GO_ON;
    if (IP_TRUSTED == is_proxy_trusted(con->dst_addr_buf, p)) {
        handler_ctx *hctx = handler_ctx_init();
        con->plugin_ctx[p->id] = hctx;
        hctx->saved_network_read = con->network_read;
        con->network_read = mod_extforward_network_read;
    }
    else {
        if (con->conf.log_request_handling) {
            log_error_write(srv, __FILE__, __LINE__, "sbs",
                    "remote address", con->dst_addr_buf,
                    "is NOT a trusted proxy, skipping");
        }
    }
    return HANDLER_GO_ON;
}


/* this function is called at dlopen() time and inits the callbacks */

int mod_extforward_plugin_init(plugin *p);
int mod_extforward_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("extforward");

	p->init        = mod_extforward_init;
	p->handle_connection_accept = mod_extforward_handle_con_accept;
	p->handle_uri_raw = mod_extforward_uri_handler;
	p->handle_request_env = mod_extforward_handle_request_env;
	p->handle_request_done = mod_extforward_restore;
	p->connection_reset = mod_extforward_restore;
	p->handle_connection_close = mod_extforward_handle_con_close;
	p->set_defaults  = mod_extforward_set_defaults;
	p->cleanup     = mod_extforward_free;

	p->data        = NULL;

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
#define PP2_TYPE_SSL              0x20
#define PP2_SUBTYPE_SSL_VERSION   0x21
#define PP2_SUBTYPE_SSL_CN        0x22
#define PP2_SUBTYPE_SSL_CIPHER    0x23
#define PP2_SUBTYPE_SSL_SIG_ALG   0x24
#define PP2_SUBTYPE_SSL_KEY_ALG   0x25
#define PP2_TYPE_NETNS            0x30

/*
For the type PP2_TYPE_SSL, the value is itselv a defined like this :
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
static int hap_PROXY_recv (const int fd, union hap_PROXY_hdr * const hdr)
{
    static const char v2sig[12] =
        "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

    ssize_t ret;
    size_t sz;
    int ver;

    do {
        ret = recv(fd, hdr, sizeof(*hdr), MSG_PEEK|MSG_DONTWAIT|MSG_NOSIGNAL);
    } while (-1 == ret && errno == EINTR);

    if (-1 == ret)
        return (errno == EAGAIN
                #ifdef EWOULDBLOCK
                #if EAGAIN != EWOULDBLOCK
                || errno == EWOULDBLOCK
                #endif
                #endif
               ) ? 0 : -1;

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
    do {
        ret = recv(fd, hdr, sz, MSG_DONTWAIT|MSG_NOSIGNAL);
    } while (-1 == ret && errno == EINTR);
    if (ret < 0) return -1;
    if (1 == ver) hdr->v1.line[sz-2] = '\0'; /*terminate str to ease parsing*/
    return ver;
}


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
    char *src_addr, *dst_addr, *src_port, *dst_port, *e;
    int family;
    long src_lport, dst_lport;
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

    src_lport = strtol(src_port, &e, 10);
    if (src_lport <= 0 || src_lport > USHRT_MAX || *e != '\0') return -1;
    dst_lport = strtol(dst_port, &e, 10);
    if (dst_lport <= 0 || dst_lport > USHRT_MAX || *e != '\0') return -1;

    if (1 != sock_addr_inet_pton(&con->dst_addr,
                                 src_addr, family, (unsigned short)src_lport))
        return -1;
    /* Forwarded by=... could be saved here.
     * (see additional comments in mod_extforward_hap_PROXY_v2()) */

    /* re-parse addr to string to normalize
     * (instead of trusting PROXY to provide canonicalized src_addr string)
     * (should prefer PROXY v2 protocol if concerned about performance) */
    sock_addr_inet_ntop_copy_buffer(con->dst_addr_buf, &con->dst_addr);

    return 0;
}


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
     *  Forwaded or X-Forwarded-For request headers later, after request headers
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
        memset(&con->dst_addr.ipv4, 0, sizeof(struct sockaddr_in));
        con->dst_addr.ipv4.sin_family      = AF_INET;
        con->dst_addr.ipv4.sin_port        = hdr->v2.addr.ip4.src_port;
        con->dst_addr.ipv4.sin_addr.s_addr = hdr->v2.addr.ip4.src_addr;
        sock_addr_inet_ntop_copy_buffer(con->dst_addr_buf, &con->dst_addr);
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
        memset(&con->dst_addr.ipv6, 0, sizeof(struct sockaddr_in6));
        con->dst_addr.ipv6.sin6_family      = AF_INET6;
        con->dst_addr.ipv6.sin6_port        = hdr->v2.addr.ip6.src_port;
        memcpy(&con->dst_addr.ipv6.sin6_addr, hdr->v2.addr.ip6.src_addr, 16);
        sock_addr_inet_ntop_copy_buffer(con->dst_addr_buf, &con->dst_addr);
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
            char *z = memchr(src_addr, '\0', UNIX_PATH_MAX);
            if (NULL == z) return -1; /* invalid addr; too long */
            len = (uint32_t)(z - src_addr + 1); /*(+1 for '\0')*/
            memset(&con->dst_addr.un, 0, sizeof(struct sockaddr_un));
            con->dst_addr.un.sun_family = AF_UNIX;
            memcpy(&con->dst_addr.un.sun_path, src_addr, len);
            buffer_copy_string_len(con->dst_addr_buf, src_addr, len);
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

    tlv = (struct pp2_tlv *)((char *)hdr + 16);
    for (sz -= len, len -= 3; sz >= 3; sz -= 3 + len) {
        tlv = (struct pp2_tlv *)((char *)tlv + 3 + len);
        len = ((uint32_t)tlv->length_hi << 8) | tlv->length_lo;
        if (3 + len > sz) break; /*(invalid TLV)*/
        switch (tlv->type) {
         #if 0 /*(not implemented here)*/
          case PP2_TYPE_ALPN:
          case PP2_TYPE_AUTHORITY:
          case PP2_TYPE_CRC32C:
         #endif
          case PP2_TYPE_SSL: {
            static const uint32_t zero = 0;
            handler_ctx *hctx =
              con->plugin_ctx[mod_extforward_plugin_data_singleton->id];
            struct pp2_tlv_ssl *tlv_ssl =
              (struct pp2_tlv_ssl *)(void *)((char *)tlv+3);
            struct pp2_tlv *subtlv = tlv;
            if (tlv_ssl->client & PP2_CLIENT_SSL) {
                buffer_copy_string_len(con->proto, CONST_STR_LEN("https"));
            }
            if ((tlv_ssl->client & (PP2_CLIENT_CERT_CONN|PP2_CLIENT_CERT_SESS))
                && 0 == memcmp(&tlv_ssl->verify, &zero, 4)) { /* misaligned */
                hctx->ssl_client_verify = 1;
            }
            for (uint32_t subsz = len-5, n = 5; subsz >= 3; subsz -= 3 + n) {
                subtlv = (struct pp2_tlv *)((char *)subtlv + 3 + n);
                n = ((uint32_t)subtlv->length_hi << 8) | subtlv->length_lo;
                if (3 + n > subsz) break; /*(invalid TLV)*/
                if (NULL == hctx->env) hctx->env = array_init();
                switch (subtlv->type) {
                  case PP2_SUBTYPE_SSL_VERSION:
                    array_set_key_value(hctx->env,
                                        CONST_STR_LEN("SSL_PROTOCOL"),
                                        (char *)subtlv+3, n);
                    break;
                  case PP2_SUBTYPE_SSL_CN:
                    /* (tlv_ssl->client & PP2_CLIENT_CERT_CONN)
                     *   or
                     * (tlv_ssl->client & PP2_CLIENT_CERT_SESS) */
                    array_set_key_value(hctx->env,
                                        CONST_STR_LEN("SSL_CLIENT_S_DN_CN"),
                                        (char *)subtlv+3, n);
                    break;
                  case PP2_SUBTYPE_SSL_CIPHER:
                    array_set_key_value(hctx->env,
                                        CONST_STR_LEN("SSL_CIPHER"),
                                        (char *)subtlv+3, n);
                    break;
                  case PP2_SUBTYPE_SSL_SIG_ALG:
                    array_set_key_value(hctx->env,
                                        CONST_STR_LEN("SSL_SERVER_A_SIG"),
                                        (char *)subtlv+3, n);
                    break;
                  case PP2_SUBTYPE_SSL_KEY_ALG:
                    array_set_key_value(hctx->env,
                                        CONST_STR_LEN("SSL_SERVER_A_KEY"),
                                        (char *)subtlv+3, n);
                    break;
                  default:
                    break;
                }
            }
            break;
          }
         #if 0 /*(not implemented here)*/
          case PP2_TYPE_NETNS:
         #endif
          /*case PP2_TYPE_NOOP:*//* no-op */
          default:
            break;
        }
    }

    return 0;
}


static int mod_extforward_network_read (server *srv, connection *con,
                                        chunkqueue *cq, off_t max_bytes)
{
    /* XXX: when using hap-PROXY protocol, currently avoid overhead of setting
     * _L_ environment variables for mod_proxy to accurately set Forwarded hdr
     * In the future, might add config switch to enable doing this extra work */

    union hap_PROXY_hdr hdr;
    int rc = hap_PROXY_recv(con->fd, &hdr);
    switch (rc) {
      case  2: rc = mod_extforward_hap_PROXY_v2(con, &hdr); break;
      case  1: rc = mod_extforward_hap_PROXY_v1(con, &hdr); break;
      case  0: return  0; /*(errno == EAGAIN || errno == EWOULDBLOCK)*/
      case -1: log_error_write(srv, __FILE__, __LINE__, "ss",
                               "hap-PROXY recv()", strerror(errno));
               rc = -1; break;
      case -2: log_error_write(srv, __FILE__, __LINE__, "s",
                               "hap-PROXY proto received "
                               "invalid/unsupported request");
               /* fall through */
      default: rc = -1; break;
    }

    mod_extforward_restore(srv, con, mod_extforward_plugin_data_singleton);
    return (0 == rc) ? con->network_read(srv, con, cq, max_bytes) : rc;
}
