#include "first.h"

#include "buffer.h"
#include "server.h"
#include "keyvalue.h"
#include "log.h"

#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "response.h"
#include "joblist.h"

#include "plugin.h"

#include "inet_ntop_cache.h"
#include "crc32.h"

#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include <stdio.h>

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

typedef enum {
	PROXY_BALANCE_UNSET,
	PROXY_BALANCE_FAIR,
	PROXY_BALANCE_HASH,
	PROXY_BALANCE_RR,
	PROXY_BALANCE_STICKY
} proxy_balance_t;

typedef struct {
	array *extensions;
	unsigned short debug;
	unsigned short replace_http_host;

	proxy_balance_t balance;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	buffer *balance_buf;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

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
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = malloc(sizeof(plugin_config));
		s->extensions    = array_init();
		s->debug         = 0;
		s->replace_http_host = 0;

		cv[0].destination = s->extensions;
		cv[1].destination = &(s->debug);
		cv[2].destination = p->balance_buf;
		cv[3].destination = &(s->replace_http_host);

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

static void proxy_set_header(connection *con, const char *key, const char *value) {
	data_string *ds_dst;

	if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
		ds_dst = data_string_init();
	}

	buffer_copy_string(ds_dst->key, key);
	buffer_copy_string(ds_dst->value, value);
	array_insert_unique(con->request.headers, (data_unset *)ds_dst);
}

static void proxy_append_header(connection *con, const char *key, const char *value) {
	data_string *ds_dst;

	if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
		ds_dst = data_string_init();
	}

	buffer_copy_string(ds_dst->key, key);
	buffer_append_string(ds_dst->value, value);
	array_insert_unique(con->request.headers, (data_unset *)ds_dst);
}


static int proxy_create_env(server *srv, handler_ctx *hctx) {
	size_t i;

	connection *con   = hctx->remote_conn;
	buffer *b;
	int replace_http_host = 0;

	/* build header */

	b = buffer_init();

	/* request line */
	buffer_copy_string(b, get_http_method_name(con->request.http_method));
	buffer_append_string_len(b, CONST_STR_LEN(" "));

	buffer_append_string_buffer(b, con->request.uri);
	buffer_append_string_len(b, CONST_STR_LEN(" HTTP/1.0\r\n"));
	if (hctx->conf.replace_http_host && !buffer_string_is_empty(hctx->host->key)) {
		replace_http_host = 1;
		if (hctx->conf.debug > 1) {
			log_error_write(srv, __FILE__, __LINE__,  "SBS",
					"proxy - using \"", hctx->host->key, "\" as HTTP Host");
		}
		buffer_append_string_len(b, CONST_STR_LEN("Host: "));
		buffer_append_string_buffer(b, hctx->host->key);
		buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
	}

	proxy_append_header(con, "X-Forwarded-For", (char *)inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
	/* http_host is NOT is just a pointer to a buffer
	 * which is NULL if it is not set */
	if (!buffer_string_is_empty(con->request.http_host)) {
		proxy_set_header(con, "X-Host", con->request.http_host->ptr);
	}
	proxy_set_header(con, "X-Forwarded-Proto", con->uri.scheme->ptr);

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
				proxy_set_header(con, "Content-Length", buf);
			} else {
				buffer_copy_string(ds->value, buf);
			}
		}
	}

	/* request header */
	for (i = 0; i < con->request.headers->used; i++) {
		data_string *ds;

		ds = (data_string *)con->request.headers->data[i];

		if (!buffer_string_is_empty(ds->value) && !buffer_is_empty(ds->key)) {
			if (replace_http_host &&
			    buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Host"))) continue;
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Connection"))) continue;
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Proxy-Connection"))) continue;
			/* Do not emit HTTP_PROXY in environment.
			 * Some executables use HTTP_PROXY to configure
			 * outgoing proxy.  See also https://httpoxy.org/ */
			if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("Proxy"))) continue;

			buffer_append_string_buffer(b, ds->key);
			buffer_append_string_len(b, CONST_STR_LEN(": "));
			buffer_append_string_buffer(b, ds->value);
			buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
		}
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
				log_error_write(srv, __FILE__, __LINE__, "ss",
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


static handler_t proxy_recv_response(server *srv, handler_ctx *hctx) {
	switch (http_response_read(srv, hctx->remote_conn, &hctx->opts,
				   hctx->response, hctx->fd, &hctx->fde_ndx)) {
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

		hctx->opts.backend = BACKEND_PROXY;
		hctx->opts.authorizer = 0;
		hctx->opts.local_redir = 0;
		hctx->opts.xsendfile_allow = 0;
		hctx->opts.xsendfile_docroot = NULL;

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
