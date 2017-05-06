#include "first.h"

#include "buffer.h"
#include "server.h"
#include "keyvalue.h"
#include "log.h"

#include "http_chunk.h"
#include "fdevent.h"
#include "inet_ntop_cache.h"
#include "connections.h"
#include "response.h"
#include "joblist.h"

#include "plugin.h"

#include "crc32.h"

#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "sys-socket.h"

#define data_proxy data_fastcgi
#define data_proxy_init data_fastcgi_init

#define PROXY_RETRY_TIMEOUT 60

/**
 *
 * HTTP reverse proxy
 *
 * TODO:      - HTTP/1.1
 *            - HTTP/1.1 persistent connection with upstream servers
 */

/* (future: might split struct and move part to http-header-glue.c) */
typedef struct http_header_remap_opts {
    const array *urlpaths;
    const array *hosts_request;
    const array *hosts_response;
    int https_remap;
    /*(not used in plugin_config, but used in handler_ctx)*/
    const buffer *http_host;
    const buffer *forwarded_host;
    const data_string *forwarded_urlpath;
} http_header_remap_opts;

typedef enum {
	PROXY_BALANCE_UNSET,
	PROXY_BALANCE_FAIR,
	PROXY_BALANCE_HASH,
	PROXY_BALANCE_RR,
	PROXY_BALANCE_STICKY
} proxy_balance_t;

typedef enum {
	PROXY_FORWARDED_NONE         = 0x00,
	PROXY_FORWARDED_FOR          = 0x01,
	PROXY_FORWARDED_PROTO        = 0x02,
	PROXY_FORWARDED_HOST         = 0x04,
	PROXY_FORWARDED_BY           = 0x08,
	PROXY_FORWARDED_REMOTE_USER  = 0x10
} proxy_forwarded_t;

typedef struct {
	array *extensions;
	array *forwarded_params;
	array *header_params;
	unsigned short debug;
	unsigned short replace_http_host;
	unsigned int forwarded;

	proxy_balance_t balance;
	http_header_remap_opts header;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	buffer *balance_buf;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

static int proxy_check_extforward;

typedef enum {
	PROXY_STATE_INIT,
	PROXY_STATE_CONNECT,
	PROXY_STATE_PREPARE_WRITE,
	PROXY_STATE_WRITE,
	PROXY_STATE_READ
} proxy_connection_state_t;

enum { PROXY_STDOUT, PROXY_END_REQUEST };

typedef struct {
	proxy_connection_state_t state;
	time_t state_timestamp;

	data_proxy *host;

	buffer *response;

	chunkqueue *wb;
	off_t wb_reqlen;

	int fd; /* fd to the proxy process */
	int fde_ndx; /* index into the fd-event buffer */

	http_response_opts opts;
	http_header_remap_opts remap_hdrs;
	plugin_config conf;

	connection *remote_conn;  /* dumb pointer */
	plugin_data *plugin_data; /* dumb pointer */
	data_array *ext;
} handler_ctx;

/* ok, we need a prototype */
static handler_t proxy_handle_fdevent(server *srv, void *ctx, int revents);

static handler_ctx * handler_ctx_init(void) {
	handler_ctx * hctx;


	hctx = calloc(1, sizeof(*hctx));

	hctx->state = PROXY_STATE_INIT;
	hctx->host = NULL;

	hctx->response = buffer_init();

	hctx->wb = chunkqueue_init();
	hctx->wb_reqlen = 0;

	hctx->fd = -1;
	hctx->fde_ndx = -1;

	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	buffer_free(hctx->response);
	chunkqueue_free(hctx->wb);

	free(hctx);
}

INIT_FUNC(mod_proxy_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->balance_buf = buffer_init();

	return p;
}


FREE_FUNC(mod_proxy_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	buffer_free(p->balance_buf);

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->extensions);
			array_free(s->forwarded_params);
			array_free(s->header_params);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_proxy_set_defaults) {
	plugin_data *p = p_d;
	data_unset *du;
	size_t i = 0;

	config_values_t cv[] = {
		{ "proxy.server",              NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "proxy.debug",               NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "proxy.balance",             NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },      /* 2 */
		{ "proxy.replace-http-host",   NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 3 */
		{ "proxy.forwarded",           NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 4 */
		{ "proxy.header",              NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 5 */
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->extensions    = array_init();
		s->debug         = 0;
		s->replace_http_host = 0;
		s->forwarded_params  = array_init();
		s->forwarded         = PROXY_FORWARDED_NONE;
		s->header_params     = array_init();

		cv[0].destination = s->extensions;
		cv[1].destination = &(s->debug);
		cv[2].destination = p->balance_buf;
		cv[3].destination = &(s->replace_http_host);
		cv[4].destination = s->forwarded_params;
		cv[5].destination = s->header_params;

		buffer_reset(p->balance_buf);

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (buffer_string_is_empty(p->balance_buf)) {
			s->balance = PROXY_BALANCE_FAIR;
		} else if (buffer_is_equal_string(p->balance_buf, CONST_STR_LEN("fair"))) {
			s->balance = PROXY_BALANCE_FAIR;
		} else if (buffer_is_equal_string(p->balance_buf, CONST_STR_LEN("round-robin"))) {
			s->balance = PROXY_BALANCE_RR;
		} else if (buffer_is_equal_string(p->balance_buf, CONST_STR_LEN("hash"))) {
			s->balance = PROXY_BALANCE_HASH;
		} else if (buffer_is_equal_string(p->balance_buf, CONST_STR_LEN("sticky"))) {
					s->balance = PROXY_BALANCE_STICKY;
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sb",
				        "proxy.balance has to be one of: fair, round-robin, hash, sticky, but not:", p->balance_buf);
			return HANDLER_ERROR;
		}

		if (!array_is_kvany(s->forwarded_params)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for proxy.forwarded; expected ( \"param\" => \"value\" )");
			return HANDLER_ERROR;
		}
		for (size_t j = 0, used = s->forwarded_params->used; j < used; ++j) {
			proxy_forwarded_t param;
			du = s->forwarded_params->data[j];
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("by"))) {
				param = PROXY_FORWARDED_BY;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("for"))) {
				param = PROXY_FORWARDED_FOR;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("host"))) {
				param = PROXY_FORWARDED_HOST;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proto"))) {
				param = PROXY_FORWARDED_PROTO;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("remote_user"))) {
				param = PROXY_FORWARDED_REMOTE_USER;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					        "proxy.forwarded keys must be one of: by, for, host, proto, remote_user, but not:", du->key);
				return HANDLER_ERROR;
			}
			if (du->type == TYPE_STRING) {
				data_string *ds = (data_string *)du;
				if (buffer_is_equal_string(ds->value, CONST_STR_LEN("enable"))) {
					s->forwarded |= param;
				} else if (!buffer_is_equal_string(ds->value, CONST_STR_LEN("disable"))) {
					log_error_write(srv, __FILE__, __LINE__, "sb",
						        "proxy.forwarded values must be one of: 0, 1, enable, disable; error for key:", du->key);
					return HANDLER_ERROR;
				}
			} else if (du->type == TYPE_INTEGER) {
				data_integer *di = (data_integer *)du;
				if (di->value) s->forwarded |= param;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					        "proxy.forwarded values must be one of: 0, 1, enable, disable; error for key:", du->key);
				return HANDLER_ERROR;
			}
		}

		if (!array_is_kvany(s->header_params)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for proxy.header; expected ( \"param\" => ( \"key\" => \"value\" ) )");
			return HANDLER_ERROR;
		}
		for (size_t j = 0, used = s->header_params->used; j < used; ++j) {
			data_array *da = (data_array *)s->header_params->data[j];
			if (buffer_is_equal_string(da->key, CONST_STR_LEN("https-remap"))) {
				data_string *ds = (data_string *)da;
				if (ds->type != TYPE_STRING) {
					log_error_write(srv, __FILE__, __LINE__, "s",
							"unexpected value for proxy.header; expected \"enable\" or \"disable\" for https-remap");
					return HANDLER_ERROR;
				}
				s->header.https_remap = !buffer_is_equal_string(ds->value, CONST_STR_LEN("disable"))
						     && !buffer_is_equal_string(ds->value, CONST_STR_LEN("0"));
				continue;
			}
			if (da->type != TYPE_ARRAY || !array_is_kvstring(da->value)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"unexpected value for proxy.header; expected ( \"param\" => ( \"key\" => \"value\" ) ) near key", da->key);
				return HANDLER_ERROR;
			}
			if (buffer_is_equal_string(da->key, CONST_STR_LEN("map-urlpath"))) {
				s->header.urlpaths = da->value;
			}
			else if (buffer_is_equal_string(da->key, CONST_STR_LEN("map-host-request"))) {
				s->header.hosts_request = da->value;
			}
			else if (buffer_is_equal_string(da->key, CONST_STR_LEN("map-host-response"))) {
				s->header.hosts_response = da->value;
			}
			else {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"unexpected key for proxy.header; expected ( \"param\" => ( \"key\" => \"value\" ) ) near key", da->key);
				return HANDLER_ERROR;
			}
		}

		if (NULL != (du = array_get_element(config->value, "proxy.server"))) {
			size_t j;
			data_array *da = (data_array *)du;

			if (du->type != TYPE_ARRAY || !array_is_kvarray(da->value)) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"unexpected value for proxy.server; expected ( \"ext\" => ( \"backend-label\" => ( \"key\" => \"value\" )))");

				return HANDLER_ERROR;
			}

			/*
			 * proxy.server = ( "<ext>" => ...,
			 *                  "<ext>" => ... )
			 */

			for (j = 0; j < da->value->used; j++) {
				data_array *da_ext = (data_array *)da->value->data[j];
				size_t n;

				/*
				 * proxy.server = ( "<ext>" =>
				 *                     ( "<host>" => ( ... ),
				 *                       "<host>" => ( ... )
				 *                     ),
				 *                    "<ext>" => ... )
				 */

				for (n = 0; n < da_ext->value->used; n++) {
					data_array *da_host = (data_array *)da_ext->value->data[n];

					data_proxy *df;
					data_array *dfa;

					config_values_t pcv[] = {
						{ "host",              NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },      /* 0 */
						{ "port",              NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
						{ NULL,                NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
					};

					if (da_host->type != TYPE_ARRAY || !array_is_kvany(da_host->value)) {
						log_error_write(srv, __FILE__, __LINE__, "SBS",
								"unexpected value for proxy.server near [",
								da_host->key, "](string); expected ( \"ext\" => ( \"backend-label\" => ( \"key\" => \"value\" )))");

						return HANDLER_ERROR;
					}

					df = data_proxy_init();

					df->port = 80;

					buffer_copy_buffer(df->key, da_host->key);

					pcv[0].destination = df->host;
					pcv[1].destination = &(df->port);

					if (0 != config_insert_values_internal(srv, da_host->value, pcv, T_CONFIG_SCOPE_CONNECTION)) {
						df->free((data_unset*) df);
						return HANDLER_ERROR;
					}

					if (buffer_string_is_empty(df->host)) {
						log_error_write(srv, __FILE__, __LINE__, "sbbbs",
								"missing key (string):",
								da->key,
								da_ext->key,
								da_host->key,
								"host");

						df->free((data_unset*) df);
						return HANDLER_ERROR;
					}

					/* if extension already exists, take it */

					if (NULL == (dfa = (data_array *)array_get_element(s->extensions, da_ext->key->ptr))) {
						dfa = data_array_init();

						buffer_copy_buffer(dfa->key, da_ext->key);

						array_insert_unique(dfa->value, (data_unset *)df);
						array_insert_unique(s->extensions, (data_unset *)dfa);
					} else {
						array_insert_unique(dfa->value, (data_unset *)df);
					}
				}
			}
		}
	}

	for (i = 0; i < srv->srvconf.modules->used; i++) {
		data_string *ds = (data_string *)srv->srvconf.modules->data[i];
		if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_extforward"))) {
			proxy_check_extforward = 1;
			break;
		}
	}

	return HANDLER_GO_ON;
}


static void proxy_backend_close(server *srv, handler_ctx *hctx) {
	if (hctx->fd != -1) {
		fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
		fdevent_unregister(srv->ev, hctx->fd);
		fdevent_sched_close(srv->ev, hctx->fd, 1);
		hctx->fd = -1;
		hctx->fde_ndx = -1;
	}

	if (hctx->host) {
		hctx->host->usage--;
		hctx->host = NULL;
	}
}

static data_proxy * mod_proxy_extension_host_get(server *srv, connection *con, data_array *extension, proxy_balance_t balance, int debug) {
	unsigned long last_max = ULONG_MAX;
	int max_usage = INT_MAX;
	int ndx = -1;
	size_t k;

	if (extension->value->used == 1) {
		if ( ((data_proxy *)extension->value->data[0])->is_disabled ) {
			ndx = -1;
		} else {
			ndx = 0;
		}
	} else if (extension->value->used != 0) switch(balance) {
	case PROXY_BALANCE_HASH:
		/* hash balancing */

		if (debug) {
			log_error_write(srv, __FILE__, __LINE__,  "sd",
					"proxy - used hash balancing, hosts:", extension->value->used);
		}

		for (k = 0, ndx = -1, last_max = ULONG_MAX; k < extension->value->used; k++) {
			data_proxy *host = (data_proxy *)extension->value->data[k];
			unsigned long cur_max;

			if (host->is_disabled) continue;

			cur_max = generate_crc32c(CONST_BUF_LEN(con->uri.path)) +
				generate_crc32c(CONST_BUF_LEN(host->host)) + /* we can cache this */
				generate_crc32c(CONST_BUF_LEN(con->uri.authority));

			if (debug) {
				log_error_write(srv, __FILE__, __LINE__,  "sbbbd",
						"proxy - election:",
						con->uri.path,
						host->host,
						con->uri.authority,
						cur_max);
			}

			if ((last_max == ULONG_MAX) || /* first round */
			    (cur_max > last_max)) {
				last_max = cur_max;

				ndx = k;
			}
		}

		break;
	case PROXY_BALANCE_FAIR:
		/* fair balancing */
		if (debug) {
			log_error_write(srv, __FILE__, __LINE__,  "s",
					"proxy - used fair balancing");
		}

		for (k = 0, ndx = -1, max_usage = INT_MAX; k < extension->value->used; k++) {
			data_proxy *host = (data_proxy *)extension->value->data[k];

			if (host->is_disabled) continue;

			if (host->usage < max_usage) {
				max_usage = host->usage;

				ndx = k;
			}
		}

		break;
	case PROXY_BALANCE_RR: {
		data_proxy *host;

		/* round robin */
		if (debug) {
			log_error_write(srv, __FILE__, __LINE__,  "s",
					"proxy - used round-robin balancing");
		}

		/* just to be sure */
		force_assert(extension->value->used < INT_MAX);

		host = (data_proxy *)extension->value->data[0];

		/* Use last_used_ndx from first host in list */
		k = host->last_used_ndx;
		ndx = k + 1; /* use next host after the last one */
		if (ndx < 0) ndx = 0;

		/* Search first active host after last_used_ndx */
		while ( ndx < (int) extension->value->used
				&& (host = (data_proxy *)extension->value->data[ndx])->is_disabled ) ndx++;

		if (ndx >= (int) extension->value->used) {
			/* didn't found a higher id, wrap to the start */
			for (ndx = 0; ndx <= (int) k; ndx++) {
				host = (data_proxy *)extension->value->data[ndx];
				if (!host->is_disabled) break;
			}

			/* No active host found */
			if (host->is_disabled) ndx = -1;
		}

		/* Save new index for next round */
		((data_proxy *)extension->value->data[0])->last_used_ndx = ndx;

		break;
	}
	case PROXY_BALANCE_STICKY:
		/* source sticky balancing */

		if (debug) {
			log_error_write(srv, __FILE__, __LINE__,  "sd",
					"proxy - used sticky balancing, hosts:", extension->value->used);
		}

		for (k = 0, ndx = -1, last_max = ULONG_MAX; k < extension->value->used; k++) {
			data_proxy *host = (data_proxy *)extension->value->data[k];
			unsigned long cur_max;

			if (host->is_disabled) continue;

			cur_max = generate_crc32c(CONST_BUF_LEN(con->dst_addr_buf)) +
				generate_crc32c(CONST_BUF_LEN(host->host)) +
				host->port;

			if (debug) {
				log_error_write(srv, __FILE__, __LINE__,  "sbbdd",
						"proxy - election:",
						con->dst_addr_buf,
						host->host,
						host->port,
						cur_max);
			}

			if ((last_max == ULONG_MAX) || /* first round */
				(cur_max > last_max)) {
				last_max = cur_max;

				ndx = k;
			}
		}

		break;
	default:
		break;
	}

	/* found a server */
	if (ndx != -1) {
		data_proxy *host = (data_proxy *)extension->value->data[ndx];

		if (debug) {
			log_error_write(srv, __FILE__, __LINE__,  "sbd",
					"proxy - found a host",
					host->host, host->port);
		}

		host->usage++;
		return host;
	} else {
		/* no handler found */
		con->http_status = 503; /* Service Unavailable */
		con->mode = DIRECT;

		log_error_write(srv, __FILE__, __LINE__,  "sb",
				"no proxy-handler found for:",
				con->uri.path);

		return NULL;
	}
}

static void proxy_connection_close(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection *con;

	p    = hctx->plugin_data;
	con  = hctx->remote_conn;

	proxy_backend_close(srv, hctx);
	handler_ctx_free(hctx);
	con->plugin_ctx[p->id] = NULL;

	/* finish response (if not already con->file_started, con->file_finished) */
	if (con->mode == p->id) {
		http_response_backend_done(srv, con);
	}
}

static handler_t proxy_reconnect(server *srv, handler_ctx *hctx) {
	proxy_backend_close(srv, hctx);

	hctx->host = mod_proxy_extension_host_get(srv, hctx->remote_conn, hctx->ext, hctx->conf.balance, (int)hctx->conf.debug);
	if (NULL == hctx->host) return HANDLER_FINISHED;

	hctx->state = PROXY_STATE_INIT;
	return HANDLER_COMEBACK;
}

static int proxy_establish_connection(server *srv, handler_ctx *hctx) {
	struct sockaddr *proxy_addr;
	struct sockaddr_in proxy_addr_in;
#if defined(HAVE_SYS_UN_H)
	struct sockaddr_un proxy_addr_un;
#endif
#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
	struct sockaddr_in6 proxy_addr_in6;
#endif
	socklen_t servlen;

	data_proxy *host= hctx->host;
	int proxy_fd       = hctx->fd;


#if defined(HAVE_SYS_UN_H)
	if (strstr(host->host->ptr, "/")) {
		if (buffer_string_length(host->host) + 1 > sizeof(proxy_addr_un.sun_path)) {
			log_error_write(srv, __FILE__, __LINE__, "sB",
				"ERROR: Unix Domain socket filename too long:",
				host->host);
			return -1;
		}

		memset(&proxy_addr_un, 0, sizeof(proxy_addr_un));
		proxy_addr_un.sun_family = AF_UNIX;
		memcpy(proxy_addr_un.sun_path, host->host->ptr, buffer_string_length(host->host) + 1);
		servlen = sizeof(proxy_addr_un);
		proxy_addr = (struct sockaddr *) &proxy_addr_un;
	} else
#endif
#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
	if (strstr(host->host->ptr, ":")) {
		memset(&proxy_addr_in6, 0, sizeof(proxy_addr_in6));
		proxy_addr_in6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, host->host->ptr, (char *) &proxy_addr_in6.sin6_addr);
		proxy_addr_in6.sin6_port = htons(host->port);
		servlen = sizeof(proxy_addr_in6);
		proxy_addr = (struct sockaddr *) &proxy_addr_in6;
	} else
#endif
	{
		memset(&proxy_addr_in, 0, sizeof(proxy_addr_in));
		proxy_addr_in.sin_family = AF_INET;
		proxy_addr_in.sin_addr.s_addr = inet_addr(host->host->ptr);
		proxy_addr_in.sin_port = htons(host->port);
		servlen = sizeof(proxy_addr_in);
		proxy_addr = (struct sockaddr *) &proxy_addr_in;
	}


	if (-1 == connect(proxy_fd, proxy_addr, servlen)) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			if (hctx->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"connect delayed:", proxy_fd);
			}

			return 1;
		} else {

			log_error_write(srv, __FILE__, __LINE__, "sdsd",
					"connect failed:", proxy_fd, strerror(errno), errno);

			return -1;
		}
	}
	if (hctx->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"connect succeeded: ", proxy_fd);
	}

	return 0;
}


/* (future: might move to http-header-glue.c) */
static const buffer * http_header_remap_host_match (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req, size_t alen)
{
    const array *hosts = is_req
      ? remap_hdrs->hosts_request
      : remap_hdrs->hosts_response;
    if (hosts) {
        const char * const s = b->ptr+off;
        for (size_t i = 0, used = hosts->used; i < used; ++i) {
            const data_string * const ds = (data_string *)hosts->data[i];
            const buffer *k = ds->key;
            size_t mlen = buffer_string_length(k);
            if (1 == mlen && k->ptr[0] == '-') {
                /* match with authority provided in Host (if is_req)
                 * (If no Host in client request, then matching against empty
                 *  string will probably not match, and no remap will be
                 *  performed) */
                k = is_req
                  ? remap_hdrs->http_host
                  : remap_hdrs->forwarded_host;
                if (NULL == k) continue;
                mlen = buffer_string_length(k);
            }
            if (mlen == alen && 0 == strncasecmp(s, k->ptr, alen)) {
                if (buffer_is_equal_string(ds->value, CONST_STR_LEN("-"))) {
                    return remap_hdrs->http_host;
                }
                else if (!buffer_string_is_empty(ds->value)) {
                    /*(save first matched request host for response match)*/
                    if (is_req && NULL == remap_hdrs->forwarded_host)
                        remap_hdrs->forwarded_host = ds->value;
                    return ds->value;
                } /*(else leave authority as-is and stop matching)*/
                break;
            }
        }
    }
    return NULL;
}


/* (future: might move to http-header-glue.c) */
static size_t http_header_remap_host (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req, size_t alen)
{
    const buffer * const m =
      http_header_remap_host_match(b, off, remap_hdrs, is_req, alen);
    if (NULL == m) return alen; /*(no match; return original authority length)*/

    buffer_substr_replace(b, off, alen, m);
    return buffer_string_length(m); /*(length of replacement authority)*/
}


/* (future: might move to http-header-glue.c) */
static void http_header_remap_urlpath (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req)
{
    const array *urlpaths = remap_hdrs->urlpaths;
    if (urlpaths) {
        const char * const s = b->ptr+off;
        const size_t plen = buffer_string_length(b) - off; /*(urlpath len)*/
        if (is_req) { /* request */
            for (size_t i = 0, used = urlpaths->used; i < used; ++i) {
                const data_string * const ds = (data_string *)urlpaths->data[i];
                const size_t mlen = buffer_string_length(ds->key);
                if (mlen <= plen && 0 == memcmp(s, ds->key->ptr, mlen)) {
                    if (NULL == remap_hdrs->forwarded_urlpath)
                        remap_hdrs->forwarded_urlpath = ds;
                    buffer_substr_replace(b, off, mlen, ds->value);
                    break;
                }
            }
        }
        else {        /* response; perform reverse map */
            if (NULL != remap_hdrs->forwarded_urlpath) {
                const data_string * const ds = remap_hdrs->forwarded_urlpath;
                const size_t mlen = buffer_string_length(ds->value);
                if (mlen <= plen && 0 == memcmp(s, ds->value->ptr, mlen)) {
                    buffer_substr_replace(b, off, mlen, ds->key);
                    return;
                }
            }
            for (size_t i = 0, used = urlpaths->used; i < used; ++i) {
                const data_string * const ds = (data_string *)urlpaths->data[i];
                const size_t mlen = buffer_string_length(ds->value);
                if (mlen <= plen && 0 == memcmp(s, ds->value->ptr, mlen)) {
                    buffer_substr_replace(b, off, mlen, ds->key);
                    break;
                }
            }
        }
    }
}


/* (future: might move to http-header-glue.c) */
static void http_header_remap_uri (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req)
{
    /* find beginning of URL-path (might be preceded by scheme://authority
     * (caller should make sure any leading whitespace is prior to offset) */
    if (b->ptr[off] != '/') {
        char *s = b->ptr+off;
        size_t alen; /*(authority len (host len))*/
        size_t slen; /*(scheme len)*/
        const buffer *m;
        /* skip over scheme and authority of URI to find beginning of URL-path
         * (value might conceivably be relative URL-path instead of URI) */
        if (NULL == (s = strchr(s, ':')) || s[1] != '/' || s[2] != '/') return;
        slen = s - (b->ptr+off);
        s += 3;
        off = (size_t)(s - b->ptr);
        if (NULL != (s = strchr(s, '/'))) {
            alen = (size_t)(s - b->ptr) - off;
            if (0 == alen) return; /*(empty authority, e.g. "http:///")*/
        }
        else {
            alen = buffer_string_length(b) - off;
            if (0 == alen) return; /*(empty authority, e.g. "http:///")*/
            buffer_append_string_len(b, CONST_STR_LEN("/"));
        }

        /* remap authority (if configured) and set offset to url-path */
        m = http_header_remap_host_match(b, off, remap_hdrs, is_req, alen);
        if (NULL != m) {
            if (remap_hdrs->https_remap
                && (is_req ? 5==slen && 0==memcmp(b->ptr+off-slen-3,"https",5)
                           : 4==slen && 0==memcmp(b->ptr+off-slen-3,"http",4))){
                if (is_req) {
                    memcpy(b->ptr+off-slen-3+4,"://",3);  /*("https"=>"http")*/
                    --off;
                    ++alen;
                }
                else {/*(!is_req)*/
                    memcpy(b->ptr+off-slen-3+4,"s://",4); /*("http" =>"https")*/
                    ++off;
                    --alen;
                }
            }
            buffer_substr_replace(b, off, alen, m);
            alen = buffer_string_length(m);/*(length of replacement authority)*/
        }
        off += alen;
    }

    /* remap URLs (if configured) */
    http_header_remap_urlpath(b, off, remap_hdrs, is_req);
}


/* (future: might move to http-header-glue.c) */
static void http_header_remap_setcookie (buffer *b, size_t off, http_header_remap_opts *remap_hdrs)
{
    /* Given the special-case of Set-Cookie and the (too) loosely restricted
     * characters allowed, for best results, the Set-Cookie value should be the
     * entire string in b from offset to end of string.  In response headers,
     * lighttpd may concatenate multiple Set-Cookie headers into single entry
     * in con->response.headers, separated by "\r\nSet-Cookie: " */
    for (char *s, *n = b->ptr+off; (s = n); ) {
        size_t len;
        n = strchr(s, '\n');
        if (NULL == n) {
            len = (size_t)(b->ptr + buffer_string_length(b) - s);
        }
        else {
            len = (size_t)(n - s);
            n += sizeof("Set-Cookie: "); /*(include +1 for '\n')*/
        }
        for (char *e = s; NULL != (s = memchr(e, ';', len)); ) {
            do { ++s; } while (*s == ' ' || *s == '\t');
            if ('\0' == s) return;
            /*(interested only in Domain and Path attributes)*/
            e = memchr(s, '=', len - (size_t)(s - e));
            if (NULL == e) { e = s+1; continue; }
            ++e;
            switch ((int)(e - s - 1)) {
              case 4:
                if (0 == strncasecmp(s, "path", 4)) {
                    if (*e == '"') ++e;
                    if (*e != '/') continue;
                    off = (size_t)(e - b->ptr);
                    http_header_remap_urlpath(b, off, remap_hdrs, 0);
                    e = b->ptr+off; /*(b may have been reallocated)*/
                    continue;
                }
                break;
              case 6:
                if (0 == strncasecmp(s, "domain", 6)) {
                    size_t alen = 0;
                    if (*e == '"') ++e;
                    if (*e == '.') ++e;
                    if (*e == ';') continue;
                    off = (size_t)(e - b->ptr);
                    for (char c; (c = e[alen]) != ';' && c != ' ' && c != '\t'
                                          && c != '\r' && c != '\0'; ++alen);
                    len = http_header_remap_host(b, off, remap_hdrs, 0, alen);
                    e = b->ptr+off+len; /*(b may have been reallocated)*/
                    continue;
                }
                break;
              default:
                break;
            }
        }
    }
}


static void proxy_append_header(connection *con, const char *key, const size_t klen, const char *value, const size_t vlen) {
	data_string *ds_dst;

	if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
		ds_dst = data_string_init();
	}

	buffer_copy_string_len(ds_dst->key, key, klen);
	buffer_copy_string_len(ds_dst->value, value, vlen);
	array_insert_unique(con->request.headers, (data_unset *)ds_dst);
}

static void buffer_append_string_backslash_escaped(buffer *b, const char *s, size_t len) {
    /* (future: might move to buffer.c) */
    size_t j = 0;
    char *p;

    buffer_string_prepare_append(b, len*2 + 4);
    p = b->ptr + buffer_string_length(b);

    for (size_t i = 0; i < len; ++i) {
        int c = s[i];
        if (c == '"' || c == '\\' || c == 0x7F || (c < 0x20 && c != '\t'))
            p[j++] = '\\';
        p[j++] = c;
    }

    buffer_commit(b, j);
}

static void proxy_set_Forwarded(connection *con, const unsigned int flags) {
    data_string *ds = NULL, *dsfor = NULL, *dsproto = NULL, *dshost = NULL;
    buffer *b;
    int semicolon = 0;

    if (proxy_check_extforward) {
        dsfor   = (data_string *)
          array_get_element(con->environment, "_L_EXTFORWARD_ACTUAL_FOR");
        dsproto = (data_string *)
          array_get_element(con->environment, "_L_EXTFORWARD_ACTUAL_PROTO");
        dshost  = (data_string *)
          array_get_element(con->environment, "_L_EXTFORWARD_ACTUAL_HOST");
    }

    /* note: set "Forwarded" prior to updating X-Forwarded-For (below) */

    if (flags)
        ds = (data_string *)
          array_get_element(con->request.headers, "Forwarded");

    if (flags && NULL == ds) {
        data_string *xff;
        ds = (data_string *)
          array_get_unused_element(con->request.headers, TYPE_STRING);
        if (NULL == ds) ds = data_string_init();
        buffer_copy_string_len(ds->key, CONST_STR_LEN("Forwarded"));
        array_insert_unique(con->request.headers, (data_unset *)ds);
        xff = (data_string *)
          array_get_element(con->request.headers, "X-Forwarded-For");
        if (NULL != xff && !buffer_string_is_empty(xff->value)) {
            /* use X-Forwarded-For contents to seed Forwarded */
            char *s = xff->value->ptr;
            size_t used = buffer_string_length(xff->value);
            for (size_t i=0, j, ipv6; i < used; ++i) {
                while (s[i] == ' ' || s[i] == '\t' || s[i] == ',') ++i;
                if (s[i] == '\0') break;
                j = i;
                do {
                    ++i;
                } while (s[i]!=' ' && s[i]!='\t' && s[i]!=',' && s[i]!='\0');
                buffer_append_string_len(ds->value, CONST_STR_LEN("for="));
                /* over-simplified test expecting only IPv4 or IPv6 addresses,
                 * (not expecting :port, so treat existence of colon as IPv6,
                 *  and not expecting unix paths, especially not containing ':')
                 * quote all strings, backslash-escape since IPs not validated*/
                ipv6 = (NULL != memchr(s+j, ':', i-j)); /*(over-simplified) */
                buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
                if (ipv6)
                    buffer_append_string_len(ds->value, CONST_STR_LEN("["));
                buffer_append_string_backslash_escaped(ds->value, s+j, i-j);
                if (ipv6)
                    buffer_append_string_len(ds->value, CONST_STR_LEN("]"));
                buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
                buffer_append_string_len(ds->value, CONST_STR_LEN(", "));
            }
        }
    } else if (flags) { /*(NULL != ds)*/
        buffer_append_string_len(ds->value, CONST_STR_LEN(", "));
    }

    if (flags & PROXY_FORWARDED_FOR) {
        buffer_append_string_len(ds->value, CONST_STR_LEN("for="));
        if (NULL != dsfor) {
            /* over-simplified test expecting only IPv4 or IPv6 addresses,
             * (not expecting :port, so treat existence of colon as IPv6,
             *  and not expecting unix paths, especially not containing ':')
             * quote all strings and backslash-escape since IPs not validated
             * (should be IP from original con->dst_addr_buf,
             *  so trustable and without :port) */
            int ipv6 = (NULL != strchr(dsfor->value->ptr, ':'));
            buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
            if (ipv6) buffer_append_string_len(ds->value, CONST_STR_LEN("["));
            buffer_append_string_backslash_escaped(
              ds->value, CONST_BUF_LEN(dsfor->value));
            if (ipv6) buffer_append_string_len(ds->value, CONST_STR_LEN("]"));
            buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
        } else if (con->dst_addr.plain.sa_family == AF_INET) {
            /*(Note: if :port is added, then must be quoted-string:
             * e.g. for="...:port")*/
            buffer_append_string_buffer(ds->value, con->dst_addr_buf);
      #ifdef HAVE_IPV6
        } else if (con->dst_addr.plain.sa_family == AF_INET6) {
            buffer_append_string_len(ds->value, CONST_STR_LEN("\"["));
            buffer_append_string_buffer(ds->value, con->dst_addr_buf);
            buffer_append_string_len(ds->value, CONST_STR_LEN("]\""));
      #endif
        } else {
            buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
            buffer_append_string_backslash_escaped(
              ds->value, CONST_BUF_LEN(con->dst_addr_buf));
            buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
        }
        semicolon = 1;
    }

    if (flags & PROXY_FORWARDED_BY) {
        /* Note: getsockname() and inet_ntop() are expensive operations.
         * (recommendation: do not to enable by=... unless required)
         * future: might use con->srv_socket->srv_token if addr is not
         *   INADDR_ANY or in6addr_any, but must omit optional :port
         *   from con->srv_socket->srv_token for consistency */
        sock_addr *addr = &con->srv_socket->addr;
        sock_addr addrbuf;
        socklen_t addrlen = sizeof(addrbuf);

        if (semicolon) buffer_append_string_len(ds->value, CONST_STR_LEN(";"));
        buffer_append_string_len(ds->value, CONST_STR_LEN("by="));
        buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
        if (addr->plain.sa_family == AF_INET) {
            if (0==getsockname(con->fd,(struct sockaddr *)&addrbuf,&addrlen)) {
                sock_addr_inet_ntop_append_buffer(ds->value, &addrbuf);
            }
            buffer_append_string_len(ds->value, CONST_STR_LEN(":"));
            buffer_append_int(ds->value, ntohs(addr->ipv4.sin_port));
      #ifdef HAVE_IPV6
        } else if (addr->plain.sa_family == AF_INET6) {
            if (0 == getsockname(con->fd,(struct sockaddr *)&addrbuf,&addrlen)){
                buffer_append_string_len(ds->value, CONST_STR_LEN("["));
                sock_addr_inet_ntop_append_buffer(ds->value, &addrbuf);
                buffer_append_string_len(ds->value, CONST_STR_LEN("]"));
                buffer_append_string_len(ds->value, CONST_STR_LEN(":"));
                buffer_append_int(ds->value, ntohs(addr->ipv6.sin6_port));
            }
      #endif
      #ifdef HAVE_SYS_UN_H
        } else if (addr->plain.sa_family == AF_UNIX) {
            buffer_append_string_backslash_escaped(
              ds->value, CONST_BUF_LEN(con->srv_socket->srv_token));
      #endif
        }
        buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
        semicolon = 1;
    }

    if (flags & PROXY_FORWARDED_PROTO) {
        /* expecting "http" or "https"
         * (not checking if quoted-string and encoding needed) */
        if (semicolon) buffer_append_string_len(ds->value, CONST_STR_LEN(";"));
        buffer_append_string_len(ds->value, CONST_STR_LEN("proto="));
        if (NULL != dsproto) {
            buffer_append_string_buffer(ds->value, dsproto->value);
        } else if (con->srv_socket->is_ssl) {
            buffer_append_string_len(ds->value, CONST_STR_LEN("https"));
        } else {
            buffer_append_string_len(ds->value, CONST_STR_LEN("http"));
        }
        semicolon = 1;
    }

    if (flags & PROXY_FORWARDED_HOST) {
        if (NULL != dshost) {
            if (semicolon)
                buffer_append_string_len(ds->value, CONST_STR_LEN(";"));
            buffer_append_string_len(ds->value, CONST_STR_LEN("host=\""));
            buffer_append_string_backslash_escaped(
              ds->value, CONST_BUF_LEN(dshost->value));
            buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
            semicolon = 1;
        } else if (!buffer_string_is_empty(con->request.http_host)) {
            if (semicolon)
                buffer_append_string_len(ds->value, CONST_STR_LEN(";"));
            buffer_append_string_len(ds->value, CONST_STR_LEN("host=\""));
            buffer_append_string_backslash_escaped(
              ds->value, CONST_BUF_LEN(con->request.http_host));
            buffer_append_string_len(ds->value, CONST_STR_LEN("\""));
            semicolon = 1;
        }
    }

    if (flags & PROXY_FORWARDED_REMOTE_USER) {
        data_string *remote_user = (data_string *)
          array_get_element(con->environment, "REMOTE_USER");
        if (NULL != remote_user) {
            if (semicolon)
                buffer_append_string_len(ds->value, CONST_STR_LEN(";"));
            buffer_append_string_len(ds->value,CONST_STR_LEN("remote_user=\""));
            buffer_append_string_backslash_escaped(
              ds->value, CONST_BUF_LEN(remote_user->value));
            buffer_append_string_len(ds->value,CONST_STR_LEN("\""));
            semicolon = 1;
        }
    }

    /* legacy X-* headers, including X-Forwarded-For */

    b = (NULL != dsfor) ? dsfor->value : con->dst_addr_buf;
    proxy_append_header(con, CONST_STR_LEN("X-Forwarded-For"),
                             CONST_BUF_LEN(b));

    b = (NULL != dshost) ? dshost->value : con->request.http_host;
    if (!buffer_string_is_empty(b)) {
        proxy_append_header(con, CONST_STR_LEN("X-Host"),
                                 CONST_BUF_LEN(b));
        proxy_append_header(con, CONST_STR_LEN("X-Forwarded-Host"),
                                 CONST_BUF_LEN(b));
    }

    b = (NULL != dsproto) ? dsproto->value : con->uri.scheme;
    proxy_append_header(con, CONST_STR_LEN("X-Forwarded-Proto"),
                             CONST_BUF_LEN(b));
}


static int proxy_create_env(server *srv, handler_ctx *hctx) {
	connection *con   = hctx->remote_conn;
	buffer *b = buffer_init();
	const int remap_headers = (NULL != hctx->remap_hdrs.urlpaths
				   || NULL != hctx->remap_hdrs.hosts_request);
	buffer_string_prepare_copy(b, 8192-1);

	/* build header */

	/* request line */
	buffer_copy_string(b, get_http_method_name(con->request.http_method));
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	buffer_append_string_buffer(b, con->request.uri);
	if (remap_headers)
		http_header_remap_uri(b, buffer_string_length(b) - buffer_string_length(con->request.uri), &hctx->remap_hdrs, 1);
	buffer_append_string_len(b, CONST_STR_LEN(" HTTP/1.0\r\n"));

	if (hctx->conf.replace_http_host && !buffer_string_is_empty(hctx->host->key)) {
		if (hctx->conf.debug > 1) {
			log_error_write(srv, __FILE__, __LINE__,  "SBS",
					"proxy - using \"", hctx->host->key, "\" as HTTP Host");
		}
		buffer_append_string_len(b, CONST_STR_LEN("Host: "));
		buffer_append_string_buffer(b, hctx->host->key);
		buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
	} else if (!buffer_string_is_empty(con->request.http_host)) {
		buffer_append_string_len(b, CONST_STR_LEN("Host: "));
		buffer_append_string_buffer(b, con->request.http_host);
		if (remap_headers) {
			size_t alen = buffer_string_length(con->request.http_host);
			http_header_remap_host(b, buffer_string_length(b) - alen, &hctx->remap_hdrs, 1, alen);
		}
		buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
	}

	/* "Forwarded" and legacy X- headers */
	proxy_set_Forwarded(con, hctx->conf.forwarded);

	if (HTTP_METHOD_GET != con->request.http_method
	    && HTTP_METHOD_HEAD != con->request.http_method
	    && con->request.content_length >= 0) {
		/* set Content-Length if client sent Transfer-Encoding: chunked
		 * and not streaming to backend (request body has been fully received) */
		data_string *ds = (data_string *) array_get_element(con->request.headers, "Content-Length");
		if (NULL == ds || buffer_string_is_empty(ds->value)) {
			char buf[LI_ITOSTRING_LENGTH];
			li_itostrn(buf, sizeof(buf), con->request.content_length);
			if (NULL == ds) {
				proxy_append_header(con, CONST_STR_LEN("Content-Length"), buf, strlen(buf));
			} else {
				buffer_copy_string(ds->value, buf);
			}
		}
	}

	/* request header */
	for (size_t i = 0, used = con->request.headers->used; i < used; ++i) {
		data_string *ds = (data_string *)con->request.headers->data[i];
		const size_t klen = buffer_string_length(ds->key);
		size_t vlen;
		switch (klen) {
		default:
			break;
		case 4:
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Host"))) continue; /*(handled further above)*/
			break;
		case 10:
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Connection"))) continue;
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Set-Cookie"))) continue; /*(response header only; avoid accidental reflection)*/
			break;
		case 16:
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Proxy-Connection"))) continue;
			break;
		case 5:
			/* Do not emit HTTP_PROXY in environment.
			 * Some executables use HTTP_PROXY to configure
			 * outgoing proxy.  See also https://httpoxy.org/ */
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Proxy"))) continue;
			break;
		case 0:
			continue;
		}

		vlen = buffer_string_length(ds->value);
		if (0 == vlen) continue;

		buffer_append_string_len(b, ds->key->ptr, klen);
		buffer_append_string_len(b, CONST_STR_LEN(": "));
		buffer_append_string_len(b, ds->value->ptr, vlen);
		buffer_append_string_len(b, CONST_STR_LEN("\r\n"));

		if (!remap_headers) continue;

		/* check for hdrs for which to remap URIs in-place after append to b */

		switch (klen) {
		default:
			continue;
	      #if 0 /* "URI" is HTTP response header (non-standard; historical in Apache) */
		case 3:
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("URI"))) break;
			continue;
	      #endif
	      #if 0 /* "Location" is HTTP response header */
		case 8:
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Location"))) break;
			continue;
	      #endif
		case 11: /* "Destination" is WebDAV request header */
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Destination"))) break;
			continue;
		case 16: /* "Content-Location" may be HTTP request or response header */
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Content-Location"))) break;
			continue;
		}

		http_header_remap_uri(b, buffer_string_length(b) - vlen - 2, &hctx->remap_hdrs, 1);
	}

	buffer_append_string_len(b, CONST_STR_LEN("Connection: close\r\n\r\n"));

	hctx->wb_reqlen = buffer_string_length(b);
	chunkqueue_append_buffer(hctx->wb, b);
	buffer_free(b);

	/* body */

	if (con->request.content_length) {
		chunkqueue_append_chunkqueue(hctx->wb, con->request_content_queue);
		hctx->wb_reqlen += con->request.content_length;/* (eventual) total request size */
	}

	return 0;
}

static int proxy_set_state(server *srv, handler_ctx *hctx, proxy_connection_state_t state) {
	hctx->state = state;
	hctx->state_timestamp = srv->cur_ts;

	return 0;
}


static handler_t proxy_write_request(server *srv, handler_ctx *hctx) {
	data_proxy *host= hctx->host;
	connection *con   = hctx->remote_conn;

	int ret;

	switch(hctx->state) {
	case PROXY_STATE_INIT:
#if defined(HAVE_SYS_UN_H)
		if (strstr(host->host->ptr,"/")) {
			if (-1 == (hctx->fd = fdevent_socket_nb_cloexec(AF_UNIX, SOCK_STREAM, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
				return HANDLER_ERROR;
			}
		} else
#endif
#if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
		if (strstr(host->host->ptr,":")) {
			if (-1 == (hctx->fd = fdevent_socket_nb_cloexec(AF_INET6, SOCK_STREAM, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
				return HANDLER_ERROR;
			}
		} else
#endif
		{
			if (-1 == (hctx->fd = fdevent_socket_nb_cloexec(AF_INET, SOCK_STREAM, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
				return HANDLER_ERROR;
			}
		}
		hctx->fde_ndx = -1;

		srv->cur_fds++;

		fdevent_register(srv->ev, hctx->fd, proxy_handle_fdevent, hctx);

		if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed: ", strerror(errno));

			return HANDLER_ERROR;
		}

		/* fall through */
	case PROXY_STATE_CONNECT:
		if (hctx->state == PROXY_STATE_INIT) {
			switch (proxy_establish_connection(srv, hctx)) {
			case 1:
				proxy_set_state(srv, hctx, PROXY_STATE_CONNECT);

				/* connection is in progress, wait for an event and call getsockopt() below */

				fdevent_event_set(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);

				return HANDLER_WAIT_FOR_EVENT;
			case -1:
				/* if ECONNREFUSED choose another connection */
				hctx->fde_ndx = -1;

				return HANDLER_ERROR;
			default:
				/* everything is ok, go on */
				break;
			}
		} else {
			int socket_error;
			socklen_t socket_error_len = sizeof(socket_error);

			/* try to finish the connect() */
			if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len)) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"getsockopt failed:", strerror(errno));

				return HANDLER_ERROR;
			}
			if (socket_error != 0) {
				log_error_write(srv, __FILE__, __LINE__, "sssd",
						"establishing connection failed:", strerror(socket_error),
						"port:", hctx->host->port);

				return HANDLER_ERROR;
			}
			if (hctx->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__,  "s", "proxy - connect - delayed success");
			}
		}

		/* ok, we have the connection */

		proxy_set_state(srv, hctx, PROXY_STATE_PREPARE_WRITE);
		/* fall through */
	case PROXY_STATE_PREPARE_WRITE:
		proxy_create_env(srv, hctx);

		fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
		proxy_set_state(srv, hctx, PROXY_STATE_WRITE);

		/* fall through */
	case PROXY_STATE_WRITE:;
		ret = srv->network_backend_write(srv, con, hctx->fd, hctx->wb, MAX_WRITE_LIMIT);

		chunkqueue_remove_finished_chunks(hctx->wb);

		if (-1 == ret) { /* error on our side */
			log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed:", strerror(errno), errno);

			return HANDLER_ERROR;
		} else if (-2 == ret) { /* remote close */
			log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed, remote connection close:", strerror(errno), errno);

			return HANDLER_ERROR;
		}

		if (hctx->wb->bytes_out == hctx->wb_reqlen) {
			fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
			proxy_set_state(srv, hctx, PROXY_STATE_READ);
		} else {
			off_t wblen = hctx->wb->bytes_in - hctx->wb->bytes_out;
			if (hctx->wb->bytes_in < hctx->wb_reqlen && wblen < 65536 - 16384) {
				/*(con->conf.stream_request_body & FDEVENT_STREAM_REQUEST)*/
				if (!(con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN)) {
					con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
					con->is_readable = 1; /* trigger optimistic read from client */
				}
			}
			if (0 == wblen) {
				fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
			} else {
				fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
			}
		}

		return HANDLER_WAIT_FOR_EVENT;
	case PROXY_STATE_READ:
		/* waiting for a response */
		return HANDLER_WAIT_FOR_EVENT;
	default:
		log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
		return HANDLER_ERROR;
	}
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_proxy_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(extensions);
	PATCH(debug);
	PATCH(balance);
	PATCH(replace_http_host);
	PATCH(forwarded);
	PATCH(header); /*(copies struct)*/

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.server"))) {
				PATCH(extensions);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.debug"))) {
				PATCH(debug);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.balance"))) {
				PATCH(balance);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.replace-http-host"))) {
				PATCH(replace_http_host);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.forwarded"))) {
				PATCH(forwarded);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.header"))) {
				PATCH(header); /*(copies struct)*/
			}
		}
	}

	return 0;
}
#undef PATCH

static handler_t proxy_send_request(server *srv, handler_ctx *hctx) {
	/* ok, create the request */
	handler_t rc = proxy_write_request(srv, hctx);
	if (HANDLER_ERROR != rc) {
		return rc;
	} else {
		data_proxy *host = hctx->host;
		log_error_write(srv, __FILE__, __LINE__,  "sbdd", "proxy-server disabled:",
				host->host,
				host->port,
				hctx->fd);

		/* disable this server */
		host->is_disabled = 1;
		host->disable_ts = srv->cur_ts;

		/* reset the environment and restart the sub-request */
		return proxy_reconnect(srv, hctx);
	}
}


static handler_t proxy_recv_response(server *srv, handler_ctx *hctx);


SUBREQUEST_FUNC(mod_proxy_handle_subrequest) {
	plugin_data *p = p_d;

	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (NULL == hctx) return HANDLER_GO_ON;

	/* not my job */
	if (con->mode != p->id) return HANDLER_GO_ON;

	if ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
	    && con->file_started) {
		if (chunkqueue_length(con->write_queue) > 65536 - 4096) {
			fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
		} else if (!(fdevent_event_get_interest(srv->ev, hctx->fd) & FDEVENT_IN)) {
			/* optimistic read from backend */
			handler_t rc = proxy_recv_response(srv, hctx); /*(might invalidate hctx)*/
			if (rc != HANDLER_GO_ON) return rc;            /*(unless HANDLER_GO_ON)*/
			fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
		}
	}

	if (0 == hctx->wb->bytes_in
	    ? con->state == CON_STATE_READ_POST
	    : hctx->wb->bytes_in < hctx->wb_reqlen) {
		/*(64k - 4k to attempt to avoid temporary files
		 * in conjunction with FDEVENT_STREAM_REQUEST_BUFMIN)*/
		if (hctx->wb->bytes_in - hctx->wb->bytes_out > 65536 - 4096
		    && (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN)){
			con->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
			if (0 != hctx->wb->bytes_in) return HANDLER_WAIT_FOR_EVENT;
		} else {
			handler_t r = connection_handle_read_post_state(srv, con);
			chunkqueue *req_cq = con->request_content_queue;
			if (0 != hctx->wb->bytes_in && !chunkqueue_is_empty(req_cq)) {
				chunkqueue_append_chunkqueue(hctx->wb, req_cq);
				if (fdevent_event_get_interest(srv->ev, hctx->fd) & FDEVENT_OUT) {
					return (r == HANDLER_GO_ON) ? HANDLER_WAIT_FOR_EVENT : r;
				}
			}
			if (r != HANDLER_GO_ON) return r;

			/* mod_proxy sends HTTP/1.0 request and ideally should send
			 * Content-Length with request if request body is present, so
			 * send 411 Length Required if Content-Length missing.
			 * (occurs here if client sends Transfer-Encoding: chunked
			 *  and module is flagged to stream request body to backend) */
			if (-1 == con->request.content_length) {
				return connection_handle_read_post_error(srv, con, 411);
			}
		}
	}

	return ((0 == hctx->wb->bytes_in || !chunkqueue_is_empty(hctx->wb))
		&& hctx->state != PROXY_STATE_CONNECT)
	  ? proxy_send_request(srv, hctx)
	  : HANDLER_WAIT_FOR_EVENT;
}


static handler_t proxy_response_read(server *srv, handler_ctx *hctx) {
    connection * const con = hctx->remote_conn;
    const int file_started = con->file_started;
    const handler_t rc =
      http_response_read(srv, con, &hctx->opts,
                         hctx->response, hctx->fd, &hctx->fde_ndx);

    if (file_started || !con->file_started || con->mode == DIRECT) return rc;

    /* response headers just completed */

    /* rewrite paths, if needed */

    if (NULL == hctx->remap_hdrs.urlpaths
        && NULL == hctx->remap_hdrs.hosts_response)
        return rc;

    if (con->parsed_response & HTTP_LOCATION) {
        data_string *ds = (data_string *)
          array_get_element(con->response.headers, "Location");
        if (ds) http_header_remap_uri(ds->value, 0, &hctx->remap_hdrs, 0);
    }
    if (con->parsed_response & HTTP_CONTENT_LOCATION) {
        data_string *ds = (data_string *)
          array_get_element(con->response.headers, "Content-Location");
        if (ds) http_header_remap_uri(ds->value, 0, &hctx->remap_hdrs, 0);
    }
    if (con->parsed_response & HTTP_SET_COOKIE) {
        data_string *ds = (data_string *)
          array_get_element(con->response.headers, "Set-Cookie");
        if (ds) http_header_remap_setcookie(ds->value, 0, &hctx->remap_hdrs);
    }

    return rc;
}

static handler_t proxy_recv_response(server *srv, handler_ctx *hctx) {
	switch (proxy_response_read(srv, hctx)) {
	default:
		return HANDLER_GO_ON;
	case HANDLER_ERROR:
	case HANDLER_COMEBACK: /*(not expected; treat as error)*/
		http_response_backend_error(srv, hctx->remote_conn);
		/* fall through */
	case HANDLER_FINISHED:
		proxy_connection_close(srv, hctx);
		return HANDLER_FINISHED;
	}
}


static handler_t proxy_handle_fdevent(server *srv, void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;

	joblist_append(srv, con);

	if (revents & FDEVENT_IN) {
		handler_t rc = proxy_recv_response(srv,hctx);/*(might invalidate hctx)*/
		if (rc != HANDLER_GO_ON) return rc;          /*(unless HANDLER_GO_ON)*/
	}

	if (revents & FDEVENT_OUT) {
		return proxy_send_request(srv, hctx); /*(might invalidate hctx)*/
	}

	/* perhaps this issue is already handled */
	if (revents & FDEVENT_HUP) {
		if (hctx->state == PROXY_STATE_CONNECT) {
			/* connect() -> EINPROGRESS -> HUP */
			proxy_send_request(srv, hctx); /*(might invalidate hctx)*/
		} else if (con->file_started) {
			/* drain any remaining data from kernel pipe buffers
			 * even if (con->conf.stream_response_body
			 *          & FDEVENT_STREAM_RESPONSE_BUFMIN)
			 * since event loop will spin on fd FDEVENT_HUP event
			 * until unregistered. */
			handler_t rc;
			do {
				rc = proxy_recv_response(srv,hctx);/*(might invalidate hctx)*/
			} while (rc == HANDLER_GO_ON);             /*(unless HANDLER_GO_ON)*/
			return rc; /* HANDLER_FINISHED or HANDLER_ERROR */
		} else {
			proxy_connection_close(srv, hctx);
		}
	} else if (revents & FDEVENT_ERR) {
		log_error_write(srv, __FILE__, __LINE__, "sd", "proxy-FDEVENT_ERR, but no HUP", revents);

		http_response_backend_error(srv, con);
		proxy_connection_close(srv, hctx);
	}

	return HANDLER_FINISHED;
}

static handler_t mod_proxy_check_extension(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	size_t s_len;
	size_t k;
	buffer *fn;
	data_array *extension = NULL;
	data_proxy *host;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	/* Possibly, we processed already this request */
	if (con->file_started == 1) return HANDLER_GO_ON;

	mod_proxy_patch_connection(srv, con, p);

	fn = con->uri.path;
	if (buffer_string_is_empty(fn)) return HANDLER_ERROR;
	s_len = buffer_string_length(fn);

	/* check if extension matches */
	for (k = 0; k < p->conf.extensions->used; k++) {
		data_array *ext = NULL;
		size_t ct_len;

		ext = (data_array *)p->conf.extensions->data[k];

		if (buffer_is_empty(ext->key)) continue;

		ct_len = buffer_string_length(ext->key);

		if (s_len < ct_len) continue;

		/* check extension in the form "/proxy_pattern" */
		if (*(ext->key->ptr) == '/') {
			if (strncmp(fn->ptr, ext->key->ptr, ct_len) == 0) {
				extension = ext;
				break;
			}
		} else if (0 == strncmp(fn->ptr + s_len - ct_len, ext->key->ptr, ct_len)) {
			/* check extension in the form ".fcg" */
			extension = ext;
			break;
		}
	}

	if (NULL == extension) {
		return HANDLER_GO_ON;
	}

	host = mod_proxy_extension_host_get(srv, con, extension, p->conf.balance, (int)p->conf.debug);
	if (NULL == host) {
		return HANDLER_FINISHED;
	}

	/* found a server */
	{

		/*
		 * if check-local is disabled, use the uri.path handler
		 *
		 */

		/* init handler-context */
		handler_ctx *hctx;
		hctx = handler_ctx_init();

		hctx->remote_conn      = con;
		hctx->plugin_data      = p;
		hctx->host             = host;
		hctx->ext              = extension;

		hctx->conf.balance     = p->conf.balance;
		hctx->conf.debug       = p->conf.debug;
		hctx->conf.replace_http_host = p->conf.replace_http_host;
		hctx->conf.forwarded   = p->conf.forwarded;

		hctx->opts.fdfmt = S_IFSOCK;
		hctx->opts.backend = BACKEND_PROXY;
		hctx->opts.authorizer = 0;
		hctx->opts.local_redir = 0;
		hctx->opts.xsendfile_allow = 0;
		hctx->opts.xsendfile_docroot = NULL;

		hctx->remap_hdrs           = p->conf.header; /*(copies struct)*/
		hctx->remap_hdrs.http_host = con->request.http_host;
		/* mod_proxy currently sends all backend requests as http.
		 * https-remap is a flag since it might not be needed if backend
		 * honors Forwarded or X-Forwarded-Proto headers, e.g. by using
		 * lighttpd mod_extforward or similar functionality in backend*/
		if (hctx->remap_hdrs.https_remap) {
			hctx->remap_hdrs.https_remap =
			  buffer_is_equal_string(con->uri.scheme, CONST_STR_LEN("https"));
		}

		con->plugin_ctx[p->id] = hctx;
		con->mode = p->id;

		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__,  "sbd",
					"proxy - found a host",
					host->host, host->port);
		}

		return HANDLER_GO_ON;
	}
}

static handler_t mod_proxy_connection_reset(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	if (hctx) proxy_connection_close(srv, hctx);

	return HANDLER_GO_ON;
}

/**
 *
 * the trigger re-enables the disabled connections after the timeout is over
 *
 * */

TRIGGER_FUNC(mod_proxy_trigger) {
	plugin_data *p = p_d;

	if (p->config_storage) {
		size_t i, n, k;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			/* get the extensions for all configs */

			for (k = 0; k < s->extensions->used; k++) {
				data_array *extension = (data_array *)s->extensions->data[k];

				/* get all hosts */
				for (n = 0; n < extension->value->used; n++) {
					data_proxy *host = (data_proxy *)extension->value->data[n];

					if (!host->is_disabled ||
					    srv->cur_ts - host->disable_ts < 5) continue;

					log_error_write(srv, __FILE__, __LINE__,  "sbd",
							"proxy - re-enabled:",
							host->host, host->port);

					host->is_disabled = 0;
				}
			}
		}
	}

	return HANDLER_GO_ON;
}


int mod_proxy_plugin_init(plugin *p);
int mod_proxy_plugin_init(plugin *p) {
	p->version      = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("proxy");

	p->init         = mod_proxy_init;
	p->cleanup      = mod_proxy_free;
	p->set_defaults = mod_proxy_set_defaults;
	p->connection_reset        = mod_proxy_connection_reset; /* end of req-resp cycle */
	p->handle_uri_clean        = mod_proxy_check_extension;
	p->handle_subrequest       = mod_proxy_handle_subrequest;
	p->handle_trigger          = mod_proxy_trigger;

	p->data         = NULL;

	return 0;
}
