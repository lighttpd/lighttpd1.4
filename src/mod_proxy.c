#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

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

#include <stdio.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"

#define data_proxy data_fastcgi
#define data_proxy_init data_fastcgi_init

#define PROXY_RETRY_TIMEOUT 60

/**
 * 
 * the proxy module is based on the fastcgi module 
 * 
 * 28.06.2004 Jan Kneschke     The first release
 * 01.07.2004 Evgeny Rodichev  Several bugfixes and cleanups
 *            - co-ordinate up- and downstream flows correctly (proxy_demux_response
 *              and proxy_handle_fdevent)
 *            - correctly transfer upstream http_response_status;
 *            - some unused structures removed.
 * 
 * TODO:      - delay upstream read if write_queue is too large
 *              (to prevent memory eating, like in apache). Shoud be
 *              configurable).
 *            - persistent connection with upstream servers
 *            - HTTP/1.1
 */

typedef struct {
	array *extensions;
	int debug;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	buffer *parse_response;
	
	plugin_config **config_storage;
	
	plugin_config conf;
} plugin_data;

typedef enum { PROXY_STATE_INIT, PROXY_STATE_CONNECT, PROXY_STATE_PREPARE_WRITE, PROXY_STATE_WRITE, PROXY_STATE_READ, PROXY_STATE_ERROR } proxy_connection_state_t;
enum { PROXY_STDOUT, PROXY_END_REQUEST };
typedef struct {
	proxy_connection_state_t state;
	time_t state_timestamp;
	
	data_proxy *host;
	
	buffer *response;
	buffer *response_header;
	
	buffer *write_buffer;
	size_t  write_offset;
	

	int fd; /* fd to the proxy process */
	int fde_ndx; /* index into the fd-event buffer */

	size_t path_info_offset; /* start of path_info in uri.path */
	
	connection *remote_conn;  /* dump pointer */
	plugin_data *plugin_data; /* dump pointer */
} handler_ctx;


/* ok, we need a prototype */
static handler_t proxy_handle_fdevent(void *s, void *ctx, int revents);

static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx;
	

	hctx = calloc(1, sizeof(*hctx));
	
	hctx->state = PROXY_STATE_INIT;
	hctx->host = NULL;
	
	hctx->response = buffer_init();
	hctx->response_header = buffer_init();

	hctx->write_buffer = buffer_init();

	hctx->fd = -1;
	hctx->fde_ndx = -1;
	
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	buffer_free(hctx->response);
	buffer_free(hctx->response_header);
	buffer_free(hctx->write_buffer);
	
	free(hctx);
}

INIT_FUNC(mod_proxy_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->parse_response = buffer_init();
	
	return p;
}


FREE_FUNC(mod_proxy_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	buffer_free(p->parse_response);
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			if (s) {
			
				array_free(s->extensions);
			
				free(s);
			}
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
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		array *ca;
		
		s = malloc(sizeof(plugin_config));
		s->extensions    = array_init();
		s->debug         = 0;
		
		cv[0].destination = s->extensions;
		cv[1].destination = &(s->debug);
		
		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;
	
		if (0 != config_insert_values_global(srv, ca, cv)) {
			return HANDLER_ERROR;
		}
	
		if (NULL != (du = array_get_element(ca, "proxy.server"))) {
			size_t j;
			data_array *da = (data_array *)du;
			
			if (du->type != TYPE_ARRAY) {
				log_error_write(srv, __FILE__, __LINE__, "sss", 
						"unexpected type for key: ", "proxy.server", "array of strings");
				
				return HANDLER_ERROR;
			}
			
			/* 
			 * proxy.server = ( "<ext>" => ...,
			 *                  "<ext>" => ... )
			 */
			
			for (j = 0; j < da->value->used; j++) {
				data_array *da_ext = (data_array *)da->value->data[j];
				size_t n;
				
				if (da_ext->type != TYPE_ARRAY) {
					log_error_write(srv, __FILE__, __LINE__, "sssbs", 
							"unexpected type for key: ", "proxy.server", 
							"[", da->value->data[j]->key, "](string)");
					
					return HANDLER_ERROR;
				}
				
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
					
					if (da_host->type != TYPE_ARRAY) {
						log_error_write(srv, __FILE__, __LINE__, "ssSBS", 
								"unexpected type for key:", 
								"proxy.server", 
								"[", da_ext->value->data[n]->key, "](string)");
						
						return HANDLER_ERROR;
					}
					
					df = data_proxy_init();
					
					buffer_copy_string_buffer(df->key, da_host->key);
					
					pcv[0].destination = df->host;
					pcv[1].destination = &(df->port);
					
					if (0 != config_insert_values_internal(srv, da_host->value, pcv)) {
						return HANDLER_ERROR;
					}
					
					if (buffer_is_empty(df->host)) {
						log_error_write(srv, __FILE__, __LINE__, "sbbbs", 
								"missing key (string):", 
								da->key,
								da_ext->key,
								da_host->key,
								"host");
						
						return HANDLER_ERROR;
					} else if (df->port == 0) {
						log_error_write(srv, __FILE__, __LINE__, "sbbbs", 
								"missing key (short):", 
								da->key,
								da_ext->key,
								da_host->key,
								"port");
						return HANDLER_ERROR;
					}
					
					/* if extension already exists, take it */
					
					if (NULL == (dfa = (data_array *)array_get_element(s->extensions, da_ext->key->ptr))) {
						dfa = data_array_init();
						
						buffer_copy_string_buffer(dfa->key, da_ext->key);
						
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

void proxy_connection_cleanup(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection  *con;
	
	if (NULL == hctx) return;
	
	p    = hctx->plugin_data;
	con  = hctx->remote_conn;
	
	if (con->mode != p->id) return;
	
	fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
	fdevent_unregister(srv->ev, hctx->fd);
	if (hctx->fd != -1) {
		close(hctx->fd);
		srv->cur_fds--;
	}
	
	handler_ctx_free(hctx);
	con->plugin_ctx[p->id] = NULL;	
}

static handler_t mod_proxy_connection_reset(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	
	proxy_connection_cleanup(srv, con->plugin_ctx[p->id]);
	
	return HANDLER_GO_ON;
}

static int proxy_establish_connection(server *srv, handler_ctx *hctx) {
	struct sockaddr *proxy_addr;
	struct sockaddr_in proxy_addr_in;
	socklen_t servlen;
	
	plugin_data *p    = hctx->plugin_data;
	data_proxy *host= hctx->host;
	int proxy_fd       = hctx->fd;
	
	memset(&proxy_addr, 0, sizeof(proxy_addr));
	
	proxy_addr_in.sin_family = AF_INET;
	proxy_addr_in.sin_addr.s_addr = inet_addr(host->host->ptr);
	proxy_addr_in.sin_port = htons(host->port);
	servlen = sizeof(proxy_addr_in);
		
	proxy_addr = (struct sockaddr *) &proxy_addr_in;
	
	if (-1 == connect(proxy_fd, proxy_addr, servlen)) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			if (p->conf.debug) {
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
	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"connect succeeded: ", proxy_fd);
	}
	return 0;
}

static int proxy_create_env(server *srv, handler_ctx *hctx) {
	size_t i;
	
	connection *con   = hctx->remote_conn;
	UNUSED(srv);
	
	/* build header */
	
	buffer_reset(hctx->write_buffer);
	
	/* request line */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
		BUFFER_COPY_STRING_CONST(hctx->write_buffer, "GET ");
		break;
	case HTTP_METHOD_POST:
		BUFFER_COPY_STRING_CONST(hctx->write_buffer, "POST ");
		break;
	case HTTP_METHOD_HEAD:
		BUFFER_COPY_STRING_CONST(hctx->write_buffer, "HEAD ");
		break;
	default:
		return -1;
	}
	
	buffer_append_string_buffer(hctx->write_buffer, con->request.uri);
	BUFFER_APPEND_STRING_CONST(hctx->write_buffer, " HTTP/1.0\r\n");
	
	/* request header */
	for (i = 0; i < con->request.headers->used; i++) {
		data_string *ds;
		
		ds = (data_string *)con->request.headers->data[i];
		
		if (ds->value->used && ds->key->used) {
			if (0 == strcmp(ds->key->ptr, "Connection")) continue;
			
			buffer_append_string_buffer(hctx->write_buffer, ds->key);
			BUFFER_APPEND_STRING_CONST(hctx->write_buffer, ": ");
			buffer_append_string_buffer(hctx->write_buffer, ds->value);
			BUFFER_APPEND_STRING_CONST(hctx->write_buffer, "\r\n");
		}
	}
	
	BUFFER_APPEND_STRING_CONST(hctx->write_buffer, "X-Forwarded-For: ");
	buffer_append_string(hctx->write_buffer, inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
	BUFFER_APPEND_STRING_CONST(hctx->write_buffer, "\r\n");
	
	BUFFER_APPEND_STRING_CONST(hctx->write_buffer, "\r\n");
	
	/* body */
	
	if (con->request.http_method == HTTP_METHOD_POST &&
	    con->request.content_length) {
		/* the buffer-string functions add an extra \0 at the end the memory-function don't */
		hctx->write_buffer->used--;
		buffer_append_memory(hctx->write_buffer, con->request.content->ptr, con->request.content_length);
	}
	
	return 0;
}

static int proxy_set_state(server *srv, handler_ctx *hctx, proxy_connection_state_t state) {
	hctx->state = state;
	hctx->state_timestamp = srv->cur_ts;
	
	return 0;
}


static int proxy_response_parse(server *srv, connection *con, plugin_data *p, buffer *in) {
	char *s, *ns;
	int http_response_status = -1;
	
	UNUSED(srv);

	/* \r\n -> \0\0 */
	
	buffer_copy_string_buffer(p->parse_response, in);
	
	for (s = p->parse_response->ptr; NULL != (ns = strstr(s, "\r\n")); s = ns + 2) {
		char *key, *value;
		int key_len;
		data_string *ds;
		
		ns[0] = '\0';
		ns[1] = '\0';

		if (-1 == http_response_status) {
			/* The first line of a Response message is the Status-Line */

			for (key=s; *key && *key != ' '; key++);

			if (*key) {
				http_response_status = (int) strtol(key, NULL, 10);
				if (http_response_status <= 0) http_response_status = 502;
			} else {
				http_response_status = 502;
			}

			con->http_status = http_response_status;
			con->parsed_response |= HTTP_STATUS;
			continue;
		}
		
		if (NULL == (value = strchr(s, ':'))) {
			/* now we expect: "<key>: <value>\n" */

			continue;
		}

		key = s;
		key_len = value - key;
		
		value++;
		/* strip WS */
		while (*value == ' ' || *value == '\t') value++;
		
		
		if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
			ds = data_response_init();
		}
		buffer_copy_string_len(ds->key, key, key_len);
		buffer_copy_string(ds->value, value);
			
		array_insert_unique(con->response.headers, (data_unset *)ds);
		
		switch(key_len) {
		case 4:
			if (0 == strncasecmp(key, "Date", key_len)) {
				con->parsed_response |= HTTP_DATE;
			}
			break;
		case 8:
			if (0 == strncasecmp(key, "Location", key_len)) {
				con->parsed_response |= HTTP_LOCATION;
			}
			break;
		case 10:
			if (0 == strncasecmp(key, "Connection", key_len)) {
				con->response.keep_alive = (0 == strcasecmp(value, "Keep-Alive")) ? 1 : 0;
				con->parsed_response |= HTTP_CONNECTION;
			}
			break;
		case 14:
			if (0 == strncasecmp(key, "Content-Length", key_len)) {
				con->response.content_length = strtol(value, NULL, 10);
				con->parsed_response |= HTTP_CONTENT_LENGTH;
			}
			break;
		default:
			break;
		}
	}
	
	return 0;
}


static int proxy_demux_response(server *srv, handler_ctx *hctx) {
	int fin = 0;
	int b;
	ssize_t r;
	
	plugin_data *p    = hctx->plugin_data;
	connection *con   = hctx->remote_conn;
	int proxy_fd       = hctx->fd;
	
	/* check how much we have to read */
	if (ioctl(hctx->fd, FIONREAD, &b)) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"ioctl failed: ",
				proxy_fd);
		return -1;
	}

	if (b > 0) {
		if (hctx->response->used == 0) {
			/* avoid too small buffer */
			buffer_prepare_append(hctx->response, b + 1);
			hctx->response->used = 1;
		} else {
			buffer_prepare_append(hctx->response, hctx->response->used + b);
		}
		
		if (-1 == (r = read(hctx->fd, hctx->response->ptr + hctx->response->used - 1, b))) {
			log_error_write(srv, __FILE__, __LINE__, "sds", 
					"unexpected end-of-file (perhaps the proxy process died):",
					proxy_fd, strerror(errno));
			return -1;
		}
		
		/* this should be catched by the b > 0 above */
		assert(r);
		
		hctx->response->used += r;
		hctx->response->ptr[hctx->response->used - 1] = '\0';

#if 0
		log_error_write(srv, __FILE__, __LINE__, "sdsbs", 
				"demux: Response buffer len", hctx->response->used, ":", hctx->response, ":");
#endif

		if (0 == con->got_response) {
			con->got_response = 1;
			buffer_prepare_copy(hctx->response_header, 128);
		}
				
		if (0 == con->file_started) {
			char *c;
				
			/* search for the \r\n\r\n in the string */
			if (NULL != (c = buffer_search_string_len(hctx->response, "\r\n\r\n", 4))) {
				size_t hlen = c - hctx->response->ptr + 4;
				size_t blen = hctx->response->used - hlen - 1;
				/* found */
				
				buffer_append_string_len(hctx->response_header, hctx->response->ptr, c - hctx->response->ptr + 4);
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sb", "Header:", hctx->response_header);
#endif
				/* parse the response header */
				proxy_response_parse(srv, con, p, hctx->response_header);
					
				/* enable chunked-transfer-encoding */
				if (con->request.http_version == HTTP_VERSION_1_1 &&
				    !(con->parsed_response & HTTP_CONTENT_LENGTH)) {
					con->response.transfer_encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
				}
					
				con->file_started = 1;
				if (blen) {
					http_chunk_append_mem(srv, con, c + 4, blen + 1);
					joblist_append(srv, con);
				}
				hctx->response->used = 0;
			}
		} else {
			http_chunk_append_mem(srv, con, hctx->response->ptr, hctx->response->used);
			joblist_append(srv, con);
			hctx->response->used = 0;
		}
		
	} else {
		/* reading from upstream done */
		con->file_finished = 1;
		
		http_chunk_append_mem(srv, con, NULL, 0);
		joblist_append(srv, con);
		
		fin = 1;
	}
	
	return fin;
}


static handler_t proxy_write_request(server *srv, handler_ctx *hctx) {
	data_proxy *host= hctx->host;
	
	int r;
	
	if (!host || 
	    (!host->host->used || !host->port)) return -1;
	
	switch(hctx->state) {
	case PROXY_STATE_INIT:
		r = AF_INET;
		
		if (-1 == (hctx->fd = socket(r, SOCK_STREAM, 0))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed: ", strerror(errno));
			return HANDLER_ERROR;
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
		/* try to finish the connect() */
		if (hctx->state == PROXY_STATE_INIT) {
			/* first round */
			switch (proxy_establish_connection(srv, hctx)) {
			case 1:
				proxy_set_state(srv, hctx, PROXY_STATE_CONNECT);
				
				/* connection is in progress, wait for an event and call getsockopt() below */
				
				fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
				
				return HANDLER_WAIT_FOR_EVENT;
			case -1:
				/* if ECONNREFUSED choose another connection -> FIXME */
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
		}
		
		proxy_set_state(srv, hctx, PROXY_STATE_PREPARE_WRITE);
		/* fall through */
	case PROXY_STATE_PREPARE_WRITE:
		proxy_create_env(srv, hctx);
		
		proxy_set_state(srv, hctx, PROXY_STATE_WRITE);
		hctx->write_offset = 0;
		
		/* fall through */
	case PROXY_STATE_WRITE:
		/* continue with the code after the switch */
		if (-1 == (r = write(hctx->fd, 
				     hctx->write_buffer->ptr + hctx->write_offset, 
				     hctx->write_buffer->used - hctx->write_offset))) {
			if (errno != EAGAIN) {
				log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed:", strerror(errno), r);
				
				return -1;
			} else {
				return 0;
			}
		}
		
		hctx->write_offset += r;
		
		if (hctx->write_offset == hctx->write_buffer->used) {
			proxy_set_state(srv, hctx, PROXY_STATE_READ);
		}
		
		break;
	case PROXY_STATE_READ:
		/* waiting for a response */
		break;
	default:
		log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
		return HANDLER_ERROR;
	}
	
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_proxy_patch_connection(server *srv, connection *con, plugin_data *p, const char *stage, size_t stage_len) {
	size_t i, j;
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		plugin_config *s = p->config_storage[i];
		
		/* not our stage */
		if (!buffer_is_equal_string(dc->comp_key, stage, stage_len)) continue;
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.server"))) {
				PATCH(extensions);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("proxy.debug"))) {
				PATCH(debug);
			}
		}
	}
	
	return 0;
}

static int mod_proxy_setup_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	UNUSED(srv);
	UNUSED(con);
	
	PATCH(extensions);
	PATCH(debug);
	
	return 0;
}
#undef PATCH


SUBREQUEST_FUNC(mod_proxy_handle_subrequest) {
	plugin_data *p = p_d;
	
	handler_ctx *hctx = con->plugin_ctx[p->id];
	data_proxy *host;
	size_t i;
	
	if (NULL == hctx) return HANDLER_GO_ON;
	
	/* select the right config */
	mod_proxy_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		mod_proxy_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	host = hctx->host;
	
	/* not my job */
	if (con->mode != p->id) return HANDLER_GO_ON;
	
	/* ok, create the request */
	switch(proxy_write_request(srv, hctx)) {
	case HANDLER_ERROR:
		log_error_write(srv, __FILE__, __LINE__,  "sbdd", "proxy-server disabled:", 
				host->host,
				host->port,
				hctx->fd);
		
		/* disable this server */
		host->usage = -1;
		host->disable_ts = srv->cur_ts;
		
		proxy_connection_cleanup(srv, hctx);
		
		con->mode = DIRECT;
		con->http_status = 503;
		return HANDLER_FINISHED;
	case HANDLER_WAIT_FOR_EVENT:
		return HANDLER_WAIT_FOR_EVENT;
	case HANDLER_WAIT_FOR_FD:
		return HANDLER_WAIT_FOR_FD;
	default:
		break;
	}
	
	if (con->file_started == 1) {
		return HANDLER_FINISHED;
	} else {
		return HANDLER_WAIT_FOR_EVENT;
	}
}

static handler_t proxy_connection_close(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection  *con;
	
	if (NULL == hctx) return HANDLER_GO_ON;
	
	p    = hctx->plugin_data;
	con  = hctx->remote_conn;
	
	if (con->mode != p->id) return HANDLER_GO_ON;
	
	log_error_write(srv, __FILE__, __LINE__, "ssdsd", 
			"emergency exit: proxy:", 
			"connection-fd:", con->fd,
			"proxy-fd:", hctx->fd);
	
	
	
	proxy_connection_cleanup(srv, hctx);
	
	return HANDLER_FINISHED;
}


static handler_t proxy_handle_fdevent(void *s, void *ctx, int revents) {
	server      *srv  = (server *)s;
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;
	plugin_data *p    = hctx->plugin_data;
	
	joblist_append(srv, con);
	
	if ((revents & FDEVENT_IN) &&
	    hctx->state == PROXY_STATE_READ) {
		switch (proxy_demux_response(srv, hctx)) {
		case 0:
			break;
		case 1:
			hctx->host->usage--;
			
			/* we are done */

			if (chunkqueue_is_empty(con->write_queue)) {
				connection_set_state(srv, con, CON_STATE_RESPONSE_END);
			}

			proxy_connection_cleanup(srv, hctx);
			
			return HANDLER_FINISHED;
		case -1:
			if (con->file_started == 0) {
				/* nothing has been send out yet, send a 500 */
				connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
				con->http_status = 500;
				con->mode = DIRECT;
			} else {
				/* response might have been already started, kill the connection */
				connection_set_state(srv, con, CON_STATE_ERROR);
			}
			
			return HANDLER_FINISHED;
		}
	}
	
	if (revents & FDEVENT_OUT) {
		if (hctx->state == PROXY_STATE_CONNECT ||
		    hctx->state == PROXY_STATE_WRITE) {
			/* we are allowed to send something out
			 * 
			 * 1. in a unfinished connect() call
			 * 2. in a unfinished write() call (long POST request)
			 */
			return mod_proxy_handle_subrequest(srv, con, p);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd", "proxy: out", hctx->state);
		}
	}
	
	/* perhaps this issue is already handled */
	if (revents & FDEVENT_HUP) {
		log_error_write(srv, __FILE__, __LINE__, "sbSBSDS", 
				"error: unexpected close of proxy connection for", 
				con->uri.path,
				"(no proxy process on host: ", 
				hctx->host->host,
				", port: ", 
				hctx->host->port,
				" ?)" );
		
#ifndef USE_LINUX_SIGIO
		proxy_connection_close(srv, hctx);
# if 0
		log_error_write(srv, __FILE__, __LINE__, "sd", "proxy-FDEVENT_HUP", con->fd);
# endif			
		return HANDLER_ERROR;
#endif
	} else if (revents & FDEVENT_ERR) {
		log_error_write(srv, __FILE__, __LINE__, "s", "proxy: err");
		/* kill all connections to the proxy process */
		
		proxy_connection_close(srv, hctx);
#if 1
		log_error_write(srv, __FILE__, __LINE__, "s", "proxy-FDEVENT_ERR");
#endif			
		return HANDLER_ERROR;
	}
	
	return HANDLER_FINISHED;
}

static handler_t mod_proxy_check_extension(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	size_t s_len;
	int used = -1;
	int ndx;
	size_t k, i;
	buffer *fn;
	data_array *extension = NULL;
	size_t path_info_offset;
	
	/* Possibly, we processed already this request */
	if (con->file_started == 1) return HANDLER_GO_ON;
	
	/* select the right config */
	mod_proxy_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		mod_proxy_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	fn = con->uri.path;

	if (fn->used == 0) {
		return HANDLER_ERROR;
	}
	
	s_len = fn->used - 1;
	
	
	path_info_offset = 0;
	
	/* check if extension matches */
	for (k = 0; k < p->conf.extensions->used; k++) {
		size_t ct_len;
		
		extension = (data_array *)p->conf.extensions->data[k];
		
		if (extension->key->used == 0) continue;
		
		ct_len = extension->key->used - 1;
		
		if (s_len < ct_len) continue;
		
		/* check extension in the form "/proxy_pattern" */
		if (*(extension->key->ptr) == '/' && strncmp(fn->ptr, extension->key->ptr, ct_len) == 0) {
			if (s_len > ct_len + 1) {
				char *pi_offset;
				
				if (0 != (pi_offset = strchr(fn->ptr + ct_len + 1, '/'))) {
					path_info_offset = pi_offset - fn->ptr;
				}
			}
			break;
		} else if (0 == strncmp(fn->ptr + s_len - ct_len, extension->key->ptr, ct_len)) {
			/* check extension in the form ".fcg" */
			break;
		}
	}
	
	/* extension doesn't match */
	if (k == p->conf.extensions->used) {
		return HANDLER_GO_ON;
	}
	
	/* get best server */
	for (k = 0, ndx = -1; k < extension->value->used; k++) {
		data_proxy *host = (data_proxy *)extension->value->data[k];
		
		/* enable the server again, perhaps it is back again */
		if ((host->usage == -1) &&
		    (srv->cur_ts - host->disable_ts > PROXY_RETRY_TIMEOUT)) {
			host->usage = 0;
			
			log_error_write(srv, __FILE__, __LINE__,  "sbd", "proxy-server re-enabled:", 
					host->host, host->port);
		}
		
		if (host->usage != -1 && (used == -1 || host->usage < used)) {
			used = host->usage;
			
			ndx = k;
		}
	}
	
	/* found a server */
	if (ndx != -1) {
		data_proxy *host = (data_proxy *)extension->value->data[ndx];
		
		/* 
		 * if check-local is disabled, use the uri.path handler 
		 * 
		 */
		
		/* init handler-context */
		handler_ctx *hctx;
		hctx = handler_ctx_init();
				
		hctx->path_info_offset = path_info_offset;
		hctx->remote_conn      = con;
		hctx->plugin_data      = p;
		hctx->host             = host;
				
		con->plugin_ctx[p->id] = hctx;
		
		host->usage++;
		
		con->mode = p->id;
		
		return HANDLER_GO_ON;
	} else {
		/* no handler found */
		con->http_status = 500;
		
		log_error_write(srv, __FILE__, __LINE__,  "sb", 
				"no proxy-handler found for:", 
				fn);
		
		return HANDLER_FINISHED;
	}
	return HANDLER_GO_ON;
}

JOBLIST_FUNC(mod_proxy_handle_joblist) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	
	if (hctx == NULL) return HANDLER_GO_ON;

	if (hctx->fd != -1) {
		switch (hctx->state) {
		case PROXY_STATE_READ:
			fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
			
			break;
		case PROXY_STATE_CONNECT:
			fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
			
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sd", "unhandled proxy.state", hctx->state);
			break;
		}
	}

	return HANDLER_GO_ON;
}


static handler_t mod_proxy_connection_close_callback(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	
	return proxy_connection_close(srv, con->plugin_ctx[p->id]);
}

int mod_proxy_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("proxy");

	p->init         = mod_proxy_init;
	p->cleanup      = mod_proxy_free;
	p->set_defaults = mod_proxy_set_defaults;
	p->connection_reset        = mod_proxy_connection_reset;
	p->handle_connection_close = mod_proxy_connection_close_callback;
	p->handle_uri_clean        = mod_proxy_check_extension;
	p->handle_subrequest       = mod_proxy_handle_subrequest;
	p->handle_joblist          = mod_proxy_handle_joblist;
	
	p->data         = NULL;
	
	return 0;
}
