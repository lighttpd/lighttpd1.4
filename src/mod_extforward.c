#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "request.h"

#include "plugin.h"

#include "configfile.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sys-socket.h"
#ifndef _WIN32
#include <netdb.h>
#endif

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
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

static int extforward_check_proxy;


/* context , used for restore remote ip */

typedef struct {
	sock_addr saved_remote_addr;
	buffer *saved_remote_addr_buf;
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
		if (0 == s->headers->used && (0 == i || NULL != array_get_element(config->value, "extforward.headers"))) {
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
static int is_proxy_trusted(const char *ipstr, plugin_data *p)
{
	data_string* allds = (data_string *)array_get_element(p->conf.forwarder, "all");

	if (allds) {
		if (strcasecmp(allds->value->ptr, "trust") == 0) {
			return IP_TRUSTED;
		} else {
			return IP_UNTRUSTED;
		}
	}

	return (data_string *)array_get_element(p->conf.forwarder, ipstr) ? IP_TRUSTED : IP_UNTRUSTED;
}

/*
 * Return char *ip of last address of proxy that is not trusted.
 * Do not accept "all" keyword here.
 */
static const char *last_not_in_array(array *a, plugin_data *p)
{
	array *forwarder = p->conf.forwarder;
	int i;

	for (i = a->used - 1; i >= 0; i--) {
		data_string *ds = (data_string *)a->data[i];
		const char *ip = ds->value->ptr;

		if (!array_get_element(forwarder, ip)) {
			return ip;
		}
	}
	return NULL;
}

static void ipstr_to_sockaddr(server *srv, const char *host, sock_addr *sock) {
#ifdef HAVE_IPV6
	struct addrinfo hints, *addrlist = NULL;
	int result;

	memset(&hints, 0, sizeof(hints));
	sock->plain.sa_family = AF_UNSPEC;

#ifndef AI_NUMERICSERV
	/**
	  * quoting $ man getaddrinfo
	  *
	  * NOTES
	  *        AI_ADDRCONFIG, AI_ALL, and AI_V4MAPPED are available since glibc 2.3.3.
	  *        AI_NUMERICSERV is available since glibc 2.3.4.
	  */
#define AI_NUMERICSERV 0
#endif
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	errno = 0;
	result = getaddrinfo(host, NULL, &hints, &addrlist);

	if (result != 0) {
		log_error_write(srv, __FILE__, __LINE__, "SSSs(S)",
			"could not parse ip address ", host, " because ", gai_strerror(result), strerror(errno));
	} else if (addrlist == NULL) {
		log_error_write(srv, __FILE__, __LINE__, "SSS",
			"Problem in parsing ip address ", host, ": succeeded, but no information returned");
	} else switch (addrlist->ai_family) {
	case AF_INET:
		memcpy(&sock->ipv4, addrlist->ai_addr, sizeof(sock->ipv4));
		force_assert(AF_INET == sock->plain.sa_family);
		break;
	case AF_INET6:
		memcpy(&sock->ipv6, addrlist->ai_addr, sizeof(sock->ipv6));
		force_assert(AF_INET6 == sock->plain.sa_family);
		break;
	default:
		log_error_write(srv, __FILE__, __LINE__, "SSS",
			"Problem in parsing ip address ", host, ": succeeded, but unknown family");
	}

	freeaddrinfo(addrlist);
#else
	UNUSED(srv);
	sock->ipv4.sin_addr.s_addr = inet_addr(host);
	sock->plain.sa_family = (sock->ipv4.sin_addr.s_addr == 0xFFFFFFFF) ? AF_UNSPEC : AF_INET;
#endif
}

static int mod_extforward_set_addr(server *srv, connection *con, plugin_data *p, const char *addr) {
	sock_addr sock;
	handler_ctx *hctx;

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "using address:", addr);
	}

	sock.plain.sa_family = AF_UNSPEC;
	ipstr_to_sockaddr(srv, addr, &sock);
	if (sock.plain.sa_family == AF_UNSPEC) return 0;

	/* we found the remote address, modify current connection and save the old address */
	if (con->plugin_ctx[p->id]) {
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "s",
				"-- mod_extforward_uri_handler already patched this connection, resetting state");
		}
		handler_ctx_free(con->plugin_ctx[p->id]);
		con->plugin_ctx[p->id] = NULL;
	}
	/* save old address */
	if (extforward_check_proxy) {
		array_set_key_value(con->environment, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_FOR"), CONST_BUF_LEN(con->dst_addr_buf));
	}
	con->plugin_ctx[p->id] = hctx = handler_ctx_init();
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
            char *ipend = s+vlen;
            int trusted;
            char c = *ipend;
            *ipend = '\0';
            trusted = (NULL != array_get_element(p->conf.forwarder, s+v));
            *ipend = c;

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
                oproto = j;
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

            if (0 != http_request_host_policy(con, con->request.http_host)) {
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
            v = offsets[oproto+2];
            vlen = v + offsets[oproto+3];
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

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_extforward_uri_handler) {
	plugin_data *p = p_d;
	data_string *forwarded = NULL;

	mod_extforward_patch_connection(srv, con, p);

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "s",
			"-- mod_extforward_uri_handler called");
	}

	for (size_t k = 0; k < p->conf.headers->used && NULL == forwarded; ++k) {
		forwarded = (data_string *) array_get_element(con->request.headers, ((data_string *)p->conf.headers->data[k])->value->ptr);
	}
	if (NULL == forwarded) {
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "s", "no forward header found, skipping");
		}

		return HANDLER_GO_ON;
	}

	/* if the remote ip itself is not trusted, then do nothing */
	if (IP_UNTRUSTED == is_proxy_trusted(con->dst_addr_buf->ptr, p)) {
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

CONNECTION_FUNC(mod_extforward_restore) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (!hctx) return HANDLER_GO_ON;
	
	con->dst_addr = hctx->saved_remote_addr;
	buffer_free(con->dst_addr_buf);

	con->dst_addr_buf = hctx->saved_remote_addr_buf;
	
	handler_ctx_free(hctx);

	con->plugin_ctx[p->id] = NULL;

	/* Now, clean the conf_cond cache, because we may have changed the results of tests */
	config_cond_cache_reset_item(srv, con, COMP_HTTP_REMOTE_IP);

	return HANDLER_GO_ON;
}


/* this function is called at dlopen() time and inits the callbacks */

int mod_extforward_plugin_init(plugin *p);
int mod_extforward_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("extforward");

	p->init        = mod_extforward_init;
	p->handle_uri_raw = mod_extforward_uri_handler;
	p->handle_request_done = mod_extforward_restore;
	p->connection_reset = mod_extforward_restore;
	p->set_defaults  = mod_extforward_set_defaults;
	p->cleanup     = mod_extforward_free;

	p->data        = NULL;

	return 0;
}

