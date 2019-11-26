#include "first.h"

#include "base.h"
#include "buffer.h"
#include "burl.h"       /* HTTP_PARSEOPT_HEADER_STRICT */
#include "settings.h"   /* BUFFER_MAX_REUSE_SIZE */
#include "log.h"
#include "connections.h"
#include "fdevent.h"
#include "http_header.h"

#include "request.h"
#include "response.h"
#include "network.h"
#include "http_chunk.h"
#include "stat_cache.h"

#include "plugin.h"

#include "inet_ntop_cache.h"

#include <sys/stat.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"

#define HTTP_LINGER_TIMEOUT 5

#define connection_set_state(con, n) ((con)->state = (n))

__attribute_cold__
static connection *connection_init(server *srv);

static int connection_reset(connection *con);


static connection *connections_get_new_connection(server *srv) {
	connections * const conns = &srv->conns;
	size_t i;

	if (conns->size == conns->used) {
		conns->size += srv->max_conns >= 128 ? 128 : srv->max_conns > 16 ? 16 : srv->max_conns;
		conns->ptr = realloc(conns->ptr, sizeof(*conns->ptr) * conns->size);
		force_assert(NULL != conns->ptr);

		for (i = conns->used; i < conns->size; i++) {
			conns->ptr[i] = connection_init(srv);
			connection_reset(conns->ptr[i]);
		}
	}

	conns->ptr[conns->used]->ndx = conns->used;
	return conns->ptr[conns->used++];
}

static int connection_del(server *srv, connection *con) {
	if (-1 == con->ndx) return -1;

	buffer_clear(con->uri.authority);
	buffer_reset(con->uri.path);
	buffer_reset(con->uri.query);
	buffer_reset(con->request.orig_uri);

	connections * const conns = &srv->conns;

	uint32_t i = con->ndx;

	/* not last element */

	if (i != conns->used - 1) {
		connection * const temp = conns->ptr[i];
		conns->ptr[i] = conns->ptr[conns->used - 1];
		conns->ptr[conns->used - 1] = temp;

		conns->ptr[i]->ndx = i;
		conns->ptr[conns->used - 1]->ndx = -1;
	}

	conns->used--;

	con->ndx = -1;
#if 0
	fprintf(stderr, "%s.%d: del: (%d)", __FILE__, __LINE__, conns->used);
	for (i = 0; i < conns->used; i++) {
		fprintf(stderr, "%d ", conns->ptr[i]->fd);
	}
	fprintf(stderr, "\n");
#endif
	return 0;
}

__attribute_cold__
static void connection_plugin_ctx_check(server *srv, connection *con) {
	/* plugins should have cleaned themselves up */
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		plugin *p = ((plugin **)(srv->plugins.ptr))[i];
		plugin_data_base *pd = p->data;
		if (!pd || NULL == con->plugin_ctx[pd->id]) continue;
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "missing cleanup in %s", p->name);
		con->plugin_ctx[pd->id] = NULL;
	}
}

static int connection_close(server *srv, connection *con) {
	if (con->fd < 0) con->fd = -con->fd;

	plugins_call_handle_connection_close(con);

	con->request_count = 0;
	chunkqueue_reset(con->read_queue);

	fdevent_fdnode_event_del(srv->ev, con->fdn);
	fdevent_unregister(srv->ev, con->fd);
	con->fdn = NULL;
#ifdef __WIN32
	if (0 == closesocket(con->fd))
#else
	if (0 == close(con->fd))
#endif
		--srv->cur_fds;
	else
		log_perror(con->conf.errh, __FILE__, __LINE__,
		  "(warning) close: %d", con->fd);

	if (srv->srvconf.log_state_handling) {
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "connection closed for fd %d", con->fd);
	}
	con->fd = -1;
	con->is_ssl_sock = 0;

	/* plugins should have cleaned themselves up */
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		if (NULL != con->plugin_ctx[i]) {
			connection_plugin_ctx_check(srv, con);
			break;
		}
	}

	connection_del(srv, con);
	connection_set_state(con, CON_STATE_CONNECT);

	return 0;
}

static void connection_read_for_eos_plain(server *srv, connection *con) {
	/* we have to do the linger_on_close stuff regardless
	 * of con->keep_alive; even non-keepalive sockets may
	 * still have unread data, and closing before reading
	 * it will make the client not see all our output.
	 */
	ssize_t len;
	const int type = con->dst_addr.plain.sa_family;
	char buf[16384];
	do {
		len = fdevent_socket_read_discard(con->fd, buf, sizeof(buf),
						  type, SOCK_STREAM);
	} while (len > 0 || (len < 0 && errno == EINTR));

	if (len < 0 && errno == EAGAIN) return;
      #if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
	if (len < 0 && errno == EWOULDBLOCK) return;
      #endif

	/* 0 == len || (len < 0 && (errno is a non-recoverable error)) */
		con->close_timeout_ts = srv->cur_ts - (HTTP_LINGER_TIMEOUT+1);
}

static void connection_read_for_eos_ssl(server *srv, connection *con) {
	if (con->network_read(con, con->read_queue, MAX_READ_LIMIT) < 0)
		con->close_timeout_ts = srv->cur_ts - (HTTP_LINGER_TIMEOUT+1);
	chunkqueue_reset(con->read_queue);
}

static void connection_read_for_eos(server *srv, connection *con) {
	!con->is_ssl_sock
	  ? connection_read_for_eos_plain(srv, con)
	  : connection_read_for_eos_ssl(srv, con);
}

static void connection_handle_close_state(server *srv, connection *con) {
	connection_read_for_eos(srv, con);

	if (srv->cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT) {
		connection_close(srv, con);
	}
}

static void connection_handle_shutdown(server *srv, connection *con) {
	plugins_call_handle_connection_shut_wr(con);

	srv->con_closed++;
	connection_reset(con);

	/* close the connection */
	if (con->fd >= 0
	    && (con->is_ssl_sock || 0 == shutdown(con->fd, SHUT_WR))) {
		con->close_timeout_ts = srv->cur_ts;
		connection_set_state(con, CON_STATE_CLOSE);

		if (srv->srvconf.log_state_handling) {
			log_error(con->conf.errh, __FILE__, __LINE__,
			  "shutdown for fd %d", con->fd);
		}
	} else {
		connection_close(srv, con);
	}
}

__attribute_cold__
static void connection_fdwaitqueue_append(connection *con) {
    connection_list_append(&con->srv->fdwaitqueue, con);
}

static void connection_handle_response_end_state(connection *con) {
        /* log the request */
        /* (even if error, connection dropped, still write to access log if http_status) */
	if (con->http_status) {
		plugins_call_handle_request_done(con);
	}

	server * const srv = con->srv;

	if (con->state != CON_STATE_ERROR) srv->con_written++;

	if (con->request.content_length != con->request_content_queue->bytes_in
	    || con->state == CON_STATE_ERROR) {
		/* request body is present and has not been read completely */
		con->keep_alive = 0;
	}

        if (con->keep_alive) {
		connection_reset(con);
#if 0
		con->request_start = srv->cur_ts;
		con->read_idle_ts = srv->cur_ts;
#endif
		connection_set_state(con, CON_STATE_REQUEST_START);
	} else {
		connection_handle_shutdown(srv, con);
	}
}

__attribute_cold__
static void connection_handle_errdoc_init(connection *con) {
	/* modules that produce headers required with error response should
	 * typically also produce an error document.  Make an exception for
	 * mod_auth WWW-Authenticate response header. */
	buffer *www_auth = NULL;
	if (401 == con->http_status) {
		const buffer *vb = http_header_response_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"));
		if (NULL != vb) www_auth = buffer_init_buffer(vb);
	}

	buffer_reset(con->physical.path);
	con->response.htags = 0;
	array_reset_data_strings(&con->response.headers);
	http_response_body_clear(con, 0);

	if (NULL != www_auth) {
		http_header_response_set(con, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(www_auth));
		buffer_free(www_auth);
	}
}

__attribute_cold__
static void connection_handle_errdoc(connection *con) {
    if (con->mode == DIRECT
        ? con->error_handler_saved_status >= 65535
        : (!con->conf.error_intercept || con->error_handler_saved_status))
        return;

    connection_handle_errdoc_init(con);
    con->file_finished = 1;

    /* try to send static errorfile */
    if (!buffer_string_is_empty(con->conf.errorfile_prefix)) {
        buffer_copy_buffer(con->physical.path, con->conf.errorfile_prefix);
        buffer_append_int(con->physical.path, con->http_status);
        buffer_append_string_len(con->physical.path, CONST_STR_LEN(".html"));
        if (0 == http_chunk_append_file(con, con->physical.path)) {
            stat_cache_entry *sce = NULL;
            if (stat_cache_get_entry(con, con->physical.path, &sce)
                != HANDLER_ERROR) {
                stat_cache_content_type_get(con, con->physical.path, sce);
                http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE,
                                         CONST_STR_LEN("Content-Type"),
                                         CONST_BUF_LEN(sce->content_type));
            }
            return;
        }
    }

    /* build default error-page */
    buffer_reset(con->physical.path);
    buffer * const b = con->srv->tmp_buf;
    buffer_copy_string_len(b, CONST_STR_LEN(
      "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
      "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
      "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
      " <head>\n"
      "  <title>"));
    http_status_append(b, con->http_status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</title>\n"
      " </head>\n"
      " <body>\n"
      "  <h1>"));
    http_status_append(b, con->http_status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</h1>\n"
      " </body>\n"
      "</html>\n"));
    (void)http_chunk_append_mem(con, CONST_BUF_LEN(b));

    http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE,
                             CONST_STR_LEN("Content-Type"),
                             CONST_STR_LEN("text/html"));
}

static int connection_handle_write_prepare(connection *con) {
	if (con->mode == DIRECT) {
		/* static files */
		switch(con->request.http_method) {
		case HTTP_METHOD_GET:
		case HTTP_METHOD_POST:
		case HTTP_METHOD_HEAD:
			break;
		case HTTP_METHOD_OPTIONS:
			/*
			 * 400 is coming from the request-parser BEFORE uri.path is set
			 * 403 is from the response handler when noone else catched it
			 *
			 * */
			if ((!con->http_status || con->http_status == 200) && !buffer_string_is_empty(con->uri.path) &&
			    con->uri.path->ptr[0] != '*') {
				http_response_body_clear(con, 0);
				http_header_response_append(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Allow"), CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));
				con->http_status = 200;
				con->file_finished = 1;

			}
			break;
		default:
			if (0 == con->http_status) {
				con->http_status = 501;
			}
			break;
		}
	}

	if (con->http_status == 0) {
		con->http_status = 403;
	}

	switch(con->http_status) {
	case 204: /* class: header only */
	case 205:
	case 304:
		/* disable chunked encoding again as we have no body */
		http_response_body_clear(con, 1);
		con->file_finished = 1;
		break;
	default: /* class: header + body */
		/* only custom body for 4xx and 5xx */
		if (con->http_status >= 400 && con->http_status < 600)
			connection_handle_errdoc(con);
		break;
	}

	/* Allow filter plugins to change response headers before they are written. */
	switch(plugins_call_handle_response_start(con)) {
	case HANDLER_GO_ON:
	case HANDLER_FINISHED:
		break;
	default:
		log_error(con->conf.errh,__FILE__,__LINE__,"response_start plugin failed");
		return -1;
	}

	if (con->file_finished) {
		/* we have all the content and chunked encoding is not used, set a content-length */

		if (!(con->response.htags & (HTTP_HEADER_CONTENT_LENGTH|HTTP_HEADER_TRANSFER_ENCODING))) {
			off_t qlen = chunkqueue_length(con->write_queue);

			/**
			 * The Content-Length header only can be sent if we have content:
			 * - HEAD doesn't have a content-body (but have a content-length)
			 * - 1xx, 204 and 304 don't have a content-body (RFC 2616 Section 4.3)
			 *
			 * Otherwise generate a Content-Length header as chunked encoding is not 
			 * available
			 */
			if ((con->http_status >= 100 && con->http_status < 200) ||
			    con->http_status == 204 ||
			    con->http_status == 304) {
				/* no Content-Body, no Content-Length */
				http_header_response_unset(con, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
			} else if (qlen > 0 || con->request.http_method != HTTP_METHOD_HEAD) {
				/* qlen = 0 is important for Redirects (301, ...) as they MAY have
				 * a content. Browsers are waiting for a Content otherwise
				 */
				buffer * const tb = con->srv->tmp_buf;
				buffer_copy_int(tb, qlen);
				http_header_response_set(con, HTTP_HEADER_CONTENT_LENGTH,
				                         CONST_STR_LEN("Content-Length"),
				                         CONST_BUF_LEN(tb));
			}
		}
	} else {
		/**
		 * the file isn't finished yet, but we have all headers
		 *
		 * to get keep-alive we either need:
		 * - Content-Length: ... (HTTP/1.0 and HTTP/1.0) or
		 * - Transfer-Encoding: chunked (HTTP/1.1)
		 * - Upgrade: ... (lighttpd then acts as transparent proxy)
		 */

		if (!(con->response.htags & (HTTP_HEADER_CONTENT_LENGTH|HTTP_HEADER_TRANSFER_ENCODING|HTTP_HEADER_UPGRADE))) {
			if (con->request.http_method == HTTP_METHOD_CONNECT
			    && con->http_status == 200) {
				/*(no transfer-encoding if successful CONNECT)*/
			} else if (con->request.http_version == HTTP_VERSION_1_1) {
				off_t qlen = chunkqueue_length(con->write_queue);
				con->response.send_chunked = 1;
				if (qlen) {
					/* create initial Transfer-Encoding: chunked segment */
					buffer * const b = chunkqueue_prepend_buffer_open(con->write_queue);
					buffer_append_uint_hex(b, (uintmax_t)qlen);
					buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
					chunkqueue_prepend_buffer_commit(con->write_queue);
					chunkqueue_append_mem(con->write_queue, CONST_STR_LEN("\r\n"));
				}
				http_header_response_append(con, HTTP_HEADER_TRANSFER_ENCODING, CONST_STR_LEN("Transfer-Encoding"), CONST_STR_LEN("chunked"));
			} else {
				con->keep_alive = 0;
			}
		}
	}

	if (con->request.http_method == HTTP_METHOD_HEAD) {
		/**
		 * a HEAD request has the same as a GET 
		 * without the content
		 */
		http_response_body_clear(con, 1);
		con->file_finished = 1;
	}

	http_response_write_header(con);

	return 0;
}

static void connection_handle_write(connection *con) {
	switch(connection_write_chunkqueue(con, con->write_queue, MAX_WRITE_LIMIT)) {
	case 0:
		if (con->file_finished) {
			connection_set_state(con, CON_STATE_RESPONSE_END);
		}
		break;
	case -1: /* error on our side */
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "connection closed: write failed on fd %d", con->fd);
		connection_set_state(con, CON_STATE_ERROR);
		break;
	case -2: /* remote close */
		connection_set_state(con, CON_STATE_ERROR);
		break;
	case 1:
		con->is_writable = 0;

		/* not finished yet -> WRITE */
		break;
	}
	con->write_request_ts = con->srv->cur_ts;
}

static void connection_handle_write_state(connection *con) {
    do {
        /* only try to write if we have something in the queue */
        if (!chunkqueue_is_empty(con->write_queue)) {
            if (con->is_writable) {
                connection_handle_write(con);
                if (con->state != CON_STATE_WRITE) break;
            }
        } else if (con->file_finished) {
            connection_set_state(con, CON_STATE_RESPONSE_END);
            break;
        }

        if (con->mode != DIRECT && !con->file_finished) {
            int r = plugins_call_handle_subrequest(con);
            switch(r) {
            case HANDLER_WAIT_FOR_EVENT:
            case HANDLER_FINISHED:
            case HANDLER_GO_ON:
                break;
            case HANDLER_WAIT_FOR_FD:
                connection_fdwaitqueue_append(con);
                break;
            case HANDLER_COMEBACK:
            default:
                log_error(con->conf.errh, __FILE__, __LINE__,
                  "unexpected subrequest handler ret-value: %d %d",
                  con->fd, r);
                /* fall through */
            case HANDLER_ERROR:
                connection_set_state(con, CON_STATE_ERROR);
                break;
            }
        }
    } while (con->state == CON_STATE_WRITE
             && (!chunkqueue_is_empty(con->write_queue)
                 ? con->is_writable
                 : con->file_finished));
}


__attribute_cold__
static connection *connection_init(server *srv) {
	connection *con;

	con = calloc(1, sizeof(*con));
	force_assert(NULL != con);

	con->fd = 0;
	con->ndx = -1;
	con->bytes_written = 0;
	con->bytes_read = 0;
	con->bytes_header = 0;
	con->loops_per_request = 0;

#define CLEAN(x) \
	con->x = buffer_init();

	CLEAN(request.uri);
	CLEAN(request.request);
	CLEAN(request.pathinfo);

	CLEAN(request.orig_uri);

	CLEAN(uri.scheme);
	CLEAN(uri.authority);
	CLEAN(uri.path);
	CLEAN(uri.path_raw);
	CLEAN(uri.query);

	CLEAN(physical.doc_root);
	CLEAN(physical.path);
	CLEAN(physical.basedir);
	CLEAN(physical.rel_path);
	CLEAN(physical.etag);

	CLEAN(server_name_buf);
	CLEAN(proto);
	CLEAN(dst_addr_buf);

#undef CLEAN
	con->write_queue = chunkqueue_init();
	con->read_queue = chunkqueue_init();
	con->request_content_queue = chunkqueue_init();

	con->srv  = srv;
	con->plugin_slots = srv->plugin_slots;
	con->config_data_base = srv->config_data_base;

	/* init plugin specific connection structures */

	con->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));
	force_assert(NULL != con->plugin_ctx);

	con->cond_cache = calloc(srv->config_context->used, sizeof(cond_cache_t));
	force_assert(NULL != con->cond_cache);
      #ifdef HAVE_PCRE_H
	if (srv->config_context->used > 1) {/*save 128b per con if no conditions)*/
		con->cond_match=calloc(srv->config_context->used, sizeof(cond_match_t));
		force_assert(NULL != con->cond_match);
	}
      #endif
	config_reset_config(con);

	return con;
}

void connections_free(server *srv) {
	connections * const conns = &srv->conns;
	for (uint32_t i = 0; i < conns->size; ++i) {
		connection *con = conns->ptr[i];

		connection_reset(con);

		chunkqueue_free(con->write_queue);
		chunkqueue_free(con->read_queue);
		chunkqueue_free(con->request_content_queue);
		array_free_data(&con->request.headers);
		array_free_data(&con->response.headers);
		array_free_data(&con->environment);

#define CLEAN(x) \
	buffer_free(con->x);

		CLEAN(request.uri);
		CLEAN(request.request);
		CLEAN(request.pathinfo);

		CLEAN(request.orig_uri);

		CLEAN(uri.scheme);
		CLEAN(uri.authority);
		CLEAN(uri.path);
		CLEAN(uri.path_raw);
		CLEAN(uri.query);

		CLEAN(physical.doc_root);
		CLEAN(physical.path);
		CLEAN(physical.basedir);
		CLEAN(physical.etag);
		CLEAN(physical.rel_path);

		CLEAN(server_name_buf);
		CLEAN(proto);
		CLEAN(dst_addr_buf);
#undef CLEAN
		free(con->plugin_ctx);
		free(con->cond_cache);
		free(con->cond_match);

		free(con);
	}

	free(conns->ptr);
	conns->ptr = NULL;
}


static int connection_reset(connection *con) {
	plugins_call_connection_reset(con);

	connection_response_reset(con);
	con->is_readable = 1;

	con->bytes_written = 0;
	con->bytes_written_cur_second = 0;
	con->bytes_read = 0;
	con->bytes_header = 0;
	con->loops_per_request = 0;

	con->request.http_method = HTTP_METHOD_UNSET;
	con->request.http_version = HTTP_VERSION_UNSET;

#define CLEAN(x) \
	buffer_reset(con->x);

	CLEAN(request.uri);
	CLEAN(request.pathinfo);

	/* CLEAN(request.orig_uri); */

	/* CLEAN(uri.path); */
	CLEAN(uri.path_raw);
	/* CLEAN(uri.query); */
#undef CLEAN

	buffer_clear(con->uri.scheme);
	/*buffer_clear(con->proto);*//* set to default in connection_accepted() */
	/*buffer_clear(con->uri.authority);*/
	/*buffer_clear(con->server_name_buf);*//* reset when used */

	con->request.http_host = NULL;
	con->request.content_length = 0;
	con->request.te_chunked = 0;
	con->request.htags = 0;

	if (con->header_len <= BUFFER_MAX_REUSE_SIZE)
		con->request.headers.used = 0;
	else
		array_reset_data_strings(&con->request.headers);
	con->header_len = 0;
	if (0 != con->environment.used)
		array_reset_data_strings(&con->environment);

	chunkqueue_reset(con->request_content_queue);

	/* The cond_cache gets reset in response.c */
	/* config_cond_cache_reset(con); */

	con->async_callback = 0;
	con->error_handler_saved_status = 0;
	/*con->error_handler_saved_method = HTTP_METHOD_UNSET;*/
	/*(error_handler_saved_method value is not valid unless error_handler_saved_status is set)*/

	config_reset_config(con);

	return 0;
}

__attribute_noinline__
static void connection_discard_blank_line(connection *con, const char * const s, unsigned short *hoff)  {
    if ((s[0] == '\r' && s[1] == '\n')
        || (s[0] == '\n'
            && !(con->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT))) {
        hoff[2] += hoff[1];
        memmove(hoff+1, hoff+2, (--hoff[0] - 1) * sizeof(unsigned short));
    }
}

static chunk * connection_read_header_more(connection *con, chunkqueue *cq, chunk *c, const size_t olen) {
    if ((NULL == c || NULL == c->next) && con->is_readable) {
        server * const srv = con->srv;
        con->read_idle_ts = srv->cur_ts;
        if (0 != con->network_read(con, cq, MAX_READ_LIMIT))
            connection_set_state(con, CON_STATE_ERROR);
    }

    if (cq->first != cq->last && 0 != olen) {
        const size_t clen = chunkqueue_length(cq);
        size_t block = (olen + (16384-1)) & (16384-1);
        block += (block - olen > 1024 ? 0 : 16384);
        chunkqueue_compact_mem(cq, block > clen ? clen : block);
    }

    /* detect if data is added to chunk */
    c = cq->first;
    return (c && (size_t)c->offset + olen < buffer_string_length(c->mem))
      ? c
      : NULL;
}

__attribute_hot__
static uint32_t connection_read_header_hoff(const char *n, const uint32_t clen, unsigned short hoff[8192]) {
    uint32_t hlen = 0;
    for (const char *b; (n = memchr((b = n),'\n',clen-hlen)); ++n) {
        uint32_t x = (uint32_t)(n - b + 1);
        hlen += x;
        if (x <= 2 && (x == 1 || n[-1] == '\r')) {
            hoff[hoff[0]+1] = hlen;
            return hlen;
        }
        if (++hoff[0] >= /*sizeof(hoff)/sizeof(hoff[0])-1*/ 8192-1) break;
        hoff[hoff[0]] = hlen;
    }
    return 0;
}

/**
 * handle request header read
 *
 * we get called by the state-engine and by the fdevent-handler
 */
static int connection_handle_read_state(server * const srv, connection * const con)  {
    int keepalive_request_start = 0;
    int pipelined_request_start = 0;

    if (con->request_count > 1 && 0 == con->bytes_read) {
        keepalive_request_start = 1;
        if (!chunkqueue_is_empty(con->read_queue)) {
            pipelined_request_start = 1;
            /* partial header of next request has already been read,
             * so optimistically check for more data received on
             * socket while processing the previous request */
            con->is_readable = 1;
            /*(if partially read next request and unable to read() any bytes,
             * then will unnecessarily scan again before subsequent read())*/
        }
    }

    chunkqueue * const cq = con->read_queue;
    chunk *c = cq->first;
    uint32_t clen = 0;
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */

    do {
        if (NULL == c) continue;
        clen = buffer_string_length(c->mem) - c->offset;
        if (0 == clen) continue;
        if (c->offset > USHRT_MAX) /*(highly unlikely)*/
            chunkqueue_compact_mem(cq, clen);

        hoff[0] = 1;                         /* number of lines */
        hoff[1] = (unsigned short)c->offset; /* base offset for all lines */
        /*hoff[2] = ...;*/                   /* offset from base for 2nd line */

        con->header_len =
          connection_read_header_hoff(c->mem->ptr + c->offset, clen, hoff);

        /* casting to (unsigned short) might truncate, and the hoff[]
         * addition might overflow, but max_request_field_size is USHRT_MAX,
         * so failure will be detected below */
        const unsigned int max_request_field_size =
          srv->srvconf.max_request_field_size;
        if ((con->header_len ? con->header_len : clen) > max_request_field_size
            || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1) {
            log_error(con->conf.errh, __FILE__, __LINE__, "%s",
                      "oversized request-header -> sending Status 431");
            con->http_status = 431; /* Request Header Fields Too Large */
            con->keep_alive = 0;
            return 1;
        }

        if (0 != con->header_len) break;
    } while ((c = connection_read_header_more(con, cq, c, clen)));

    if (keepalive_request_start) {
        if (0 != con->bytes_read) {
            /* update request_start timestamp when first byte of
             * next request is received on a keep-alive connection */
            con->request_start = srv->cur_ts;
            if (con->conf.high_precision_timestamps)
                log_clock_gettime_realtime(&con->request_start_hp);
        }
        if (pipelined_request_start && c) con->read_idle_ts = srv->cur_ts;
    }

    if (NULL == c) return 0; /* incomplete request headers */

  #ifdef __COVERITY__
    if (buffer_string_length(c->mem) < hoff[1]) {
        return 1;
    }
  #endif

    char * const hdrs = c->mem->ptr + hoff[1];

    if (con->request_count > 1) {
        /* skip past \r\n or \n after previous POST request when keep-alive */
        if (hoff[2] - hoff[1] <= 2)
            connection_discard_blank_line(con, hdrs, hoff);

        /* clear buffers which may have been kept for reporting on keep-alive,
         * (e.g. mod_status) */
        buffer_clear(con->uri.authority);
        buffer_reset(con->uri.path);
        buffer_reset(con->uri.query);
        buffer_reset(con->request.orig_uri);
    }

    if (con->conf.log_request_header) {
        log_error(con->conf.errh, __FILE__, __LINE__,
                  "fd: %d request-len: %d\n%.*s", con->fd, (int)con->header_len,
                  (int)con->header_len, hdrs);
    }

    con->http_status = http_request_parse(con, hdrs, hoff);
    if (0 != con->http_status) {
        con->keep_alive = 0;
        con->request.content_length = 0;

        if (srv->srvconf.log_request_header_on_error) {
            /*(http_request_parse() modifies hdrs only to
             * undo line-wrapping in-place using spaces)*/
            log_error(con->conf.errh, __FILE__, __LINE__, "request-header:\n%.*s",
                      (int)con->header_len, hdrs);
        }
    }

    chunkqueue_mark_written(cq, con->header_len);
    connection_set_state(con, CON_STATE_REQUEST_END);
    return 1;
}

static handler_t connection_handle_fdevent(server *srv, void *context, int revents) {
	connection *con = context;

	joblist_append(srv, con);

	if (con->is_ssl_sock) {
		/* ssl may read and write for both reads and writes */
		if (revents & (FDEVENT_IN | FDEVENT_OUT)) {
			con->is_readable = 1;
			con->is_writable = 1;
		}
	} else {
		if (revents & FDEVENT_IN) {
			con->is_readable = 1;
		}
		if (revents & FDEVENT_OUT) {
			con->is_writable = 1;
			/* we don't need the event twice */
		}
	}


	if (con->state == CON_STATE_READ) {
		connection_handle_read_state(srv, con);
	}

	if (con->state == CON_STATE_WRITE &&
	    !chunkqueue_is_empty(con->write_queue) &&
	    con->is_writable) {
		connection_handle_write(con);
	}

	if (con->state == CON_STATE_CLOSE) {
		/* flush the read buffers */
		connection_read_for_eos(srv, con);
	}


	/* attempt (above) to read data in kernel socket buffers
	 * prior to handling FDEVENT_HUP and FDEVENT_ERR */

	if ((revents & ~(FDEVENT_IN | FDEVENT_OUT)) && con->state != CON_STATE_ERROR) {
		if (con->state == CON_STATE_CLOSE) {
			con->close_timeout_ts = srv->cur_ts - (HTTP_LINGER_TIMEOUT+1);
		} else if (revents & FDEVENT_HUP) {
			connection_set_state(con, CON_STATE_ERROR);
		} else if (revents & FDEVENT_RDHUP) {
			int events = fdevent_fdnode_interest(con->fdn);
			events &= ~(FDEVENT_IN|FDEVENT_RDHUP);
			con->conf.stream_request_body &= ~(FDEVENT_STREAM_REQUEST_BUFMIN|FDEVENT_STREAM_REQUEST_POLLIN);
			con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLRDHUP;
			con->is_readable = 1; /*(can read 0 for end-of-stream)*/
			if (chunkqueue_is_empty(con->read_queue)) con->keep_alive = 0;
			if (con->request.content_length < -1) { /*(transparent proxy mode; no more data to read)*/
				con->request.content_length = con->request_content_queue->bytes_in;
			}
			if (sock_addr_get_family(&con->dst_addr) == AF_UNIX) {
				/* future: will getpeername() on AF_UNIX properly check if still connected? */
				fdevent_fdnode_event_set(srv->ev, con->fdn, events);
			} else if (fdevent_is_tcp_half_closed(con->fd)) {
				/* Success of fdevent_is_tcp_half_closed() after FDEVENT_RDHUP indicates TCP FIN received,
				 * but does not distinguish between client shutdown(fd, SHUT_WR) and client close(fd).
				 * Remove FDEVENT_RDHUP so that we do not spin on the ready event.
				 * However, a later TCP RST will not be detected until next write to socket.
				 * future: might getpeername() to check for TCP RST on half-closed sockets
				 * (without FDEVENT_RDHUP interest) when checking for write timeouts
				 * once a second in server.c, though getpeername() on Windows might not indicate this */
				con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;
				fdevent_fdnode_event_set(srv->ev, con->fdn, events);
			} else {
				/* Failure of fdevent_is_tcp_half_closed() indicates TCP RST
				 * (or unable to tell (unsupported OS), though should not
				 * be setting FDEVENT_RDHUP in that case) */
				connection_set_state(con, CON_STATE_ERROR);
			}
		} else if (revents & FDEVENT_ERR) { /* error, connection reset */
			connection_set_state(con, CON_STATE_ERROR);
		} else {
			log_error(con->conf.errh, __FILE__, __LINE__,
			  "connection closed: poll() -> ??? %d", revents);
		}
	}

	return HANDLER_FINISHED;
}


connection *connection_accept(server *srv, server_socket *srv_socket) {
	int cnt;
	sock_addr cnt_addr;
	size_t cnt_len = sizeof(cnt_addr); /*(size_t intentional; not socklen_t)*/

	/**
	 * check if we can still open a new connections
	 *
	 * see #1216
	 */

	if (srv->conns.used >= srv->max_conns) {
		return NULL;
	}

	cnt = fdevent_accept_listenfd(srv_socket->fd, (struct sockaddr *) &cnt_addr, &cnt_len);
	if (-1 == cnt) {
		switch (errno) {
		case EAGAIN:
#if EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
#endif
		case EINTR:
			/* we were stopped _before_ we had a connection */
		case ECONNABORTED: /* this is a FreeBSD thingy */
			/* we were stopped _after_ we had a connection */
			break;
		case EMFILE:
			/* out of fds */
			break;
		default:
			log_perror(srv->errh, __FILE__, __LINE__, "accept failed");
		}
		return NULL;
	} else {
		if (sock_addr_get_family(&cnt_addr) != AF_UNIX) {
			network_accept_tcp_nagle_disable(cnt);
		}
		return connection_accepted(srv, srv_socket, &cnt_addr, cnt);
	}
}


/* 0: everything ok, -1: error, -2: con closed */
static int connection_read_cq(connection *con, chunkqueue *cq, off_t max_bytes) {
	ssize_t len;
	char *mem = NULL;
	size_t mem_len = 0;
	force_assert(cq == con->read_queue);       /*(code transform assumption; minimize diff)*/
	force_assert(max_bytes == MAX_READ_LIMIT); /*(code transform assumption; minimize diff)*/

	/* check avail data to read and obtain memory into which to read
	 * fill previous chunk if it has sufficient space
	 * (use mem_len=0 to obtain large buffer at least half of chunk_buf_sz)
	 */
	{
		int frd;
		if (0 == fdevent_ioctl_fionread(con->fd, S_IFSOCK, &frd)) {
			mem_len = (frd < MAX_READ_LIMIT) ? (size_t)frd : MAX_READ_LIMIT;
		}
	}
	mem = chunkqueue_get_memory(con->read_queue, &mem_len);

#if defined(__WIN32)
	len = recv(con->fd, mem, mem_len, 0);
#else
	len = read(con->fd, mem, mem_len);
#endif /* __WIN32 */

	chunkqueue_use_memory(con->read_queue, len > 0 ? len : 0);

	if (len < 0) {
		con->is_readable = 0;

#if defined(__WIN32)
		{
			int lastError = WSAGetLastError();
			switch (lastError) {
			case EAGAIN:
				return 0;
			case EINTR:
				/* we have been interrupted before we could read */
				con->is_readable = 1;
				return 0;
			case ECONNRESET:
				/* suppress logging for this error, expected for keep-alive */
				break;
			default:
				log_error(con->conf.errh, __FILE__, __LINE__, "connection closed - recv failed: %d", lastError);
				break;
			}
		}
#else /* __WIN32 */
		switch (errno) {
		case EAGAIN:
			return 0;
		case EINTR:
			/* we have been interrupted before we could read */
			con->is_readable = 1;
			return 0;
		case ECONNRESET:
			/* suppress logging for this error, expected for keep-alive */
			break;
		default:
			log_perror(con->conf.errh, __FILE__, __LINE__, "connection closed - read failed");
			break;
		}
#endif /* __WIN32 */

		connection_set_state(con, CON_STATE_ERROR);

		return -1;
	} else if (len == 0) {
		con->is_readable = 0;
		/* the other end close the connection -> KEEP-ALIVE */

		/* pipelining */

		return -2;
	} else if (len != (ssize_t) mem_len) {
		/* we got less then expected, wait for the next fd-event */

		con->is_readable = 0;
	}

	con->bytes_read += len;
	return 0;
}


static int connection_write_cq(connection *con, chunkqueue *cq, off_t max_bytes) {
	server * const srv = con->srv;
	return srv->network_backend_write(con->fd, cq, max_bytes, con->conf.errh);
}


connection *connection_accepted(server *srv, server_socket *srv_socket, sock_addr *cnt_addr, int cnt) {
		connection *con;

		srv->cur_fds++;

		/* ok, we have the connection, register it */
#if 0
		log_error(srv->errh, __FILE__, __LINE__, "accepted() %d", cnt);
#endif
		srv->con_opened++;

		con = connections_get_new_connection(srv);

		con->fd = cnt;
		con->fdn = fdevent_register(srv->ev, con->fd, connection_handle_fdevent, con);
		con->network_read = connection_read_cq;
		con->network_write = connection_write_cq;

		connection_set_state(con, CON_STATE_REQUEST_START);

		con->connection_start = srv->cur_ts;
		con->dst_addr = *cnt_addr;
		buffer_copy_string(con->dst_addr_buf, inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
		con->srv_socket = srv_socket;
		con->is_ssl_sock = srv_socket->is_ssl;

		config_cond_cache_reset(con);
		con->conditional_is_valid |= (1 << COMP_SERVER_SOCKET)
					  |  (1 << COMP_HTTP_REMOTE_IP);

		buffer_copy_string_len(con->proto, CONST_STR_LEN("http"));
		if (HANDLER_GO_ON != plugins_call_handle_connection_accept(con)) {
			connection_reset(con);
			connection_close(srv, con);
			return NULL;
		}
		if (con->http_status < 0) connection_set_state(con, CON_STATE_WRITE);
		return con;
}


static int connection_handle_request(connection *con) {
			int r = http_response_prepare(con);
			switch (r) {
			case HANDLER_WAIT_FOR_EVENT:
				if (!con->file_finished && (!con->file_started || 0 == con->conf.stream_response_body)) {
					break; /* come back here */
				}
				/* response headers received from backend; fall through to start response */
				/* fall through */
			case HANDLER_FINISHED:
				if (con->http_status == 0) con->http_status = 200;
				if (con->error_handler_saved_status > 0) {
					con->request.http_method = con->error_handler_saved_method;
				}
				if (con->mode == DIRECT || con->conf.error_intercept) {
					if (con->error_handler_saved_status) {
						const int subreq_status = con->http_status;
						if (con->error_handler_saved_status > 0) {
							con->http_status = con->error_handler_saved_status;
						} else if (con->http_status == 404 || con->http_status == 403) {
							/* error-handler-404 is a 404 */
							con->http_status = -con->error_handler_saved_status;
						} else {
							/* error-handler-404 is back and has generated content */
							/* if Status: was set, take it otherwise use 200 */
						}
						if (200 <= subreq_status && subreq_status <= 299) {
							/*(flag value to indicate that error handler succeeded)
							 *(for (con->mode == DIRECT))*/
							con->error_handler_saved_status = 65535; /* >= 1000 */
						}
					} else if (con->http_status >= 400) {
						const buffer *error_handler = NULL;
						if (!buffer_string_is_empty(con->conf.error_handler)) {
							error_handler = con->conf.error_handler;
						} else if ((con->http_status == 404 || con->http_status == 403)
							   && !buffer_string_is_empty(con->conf.error_handler_404)) {
							error_handler = con->conf.error_handler_404;
						}

						if (error_handler) {
							/* call error-handler */

							/* set REDIRECT_STATUS to save current HTTP status code
							 * for access by dynamic handlers
							 * https://redmine.lighttpd.net/issues/1828 */
							buffer * const tb = con->srv->tmp_buf;
							buffer_copy_int(tb, con->http_status);
							http_header_env_set(con, CONST_STR_LEN("REDIRECT_STATUS"), CONST_BUF_LEN(tb));

							if (error_handler == con->conf.error_handler) {
								plugins_call_connection_reset(con);

								if (con->request.content_length) {
									if (con->request.content_length != con->request_content_queue->bytes_in) {
										con->keep_alive = 0;
									}
									con->request.content_length = 0;
									chunkqueue_reset(con->request_content_queue);
								}

								con->is_writable = 1;
								con->file_finished = 0;
								con->file_started = 0;

								con->error_handler_saved_status = con->http_status;
								con->error_handler_saved_method = con->request.http_method;

								con->request.http_method = HTTP_METHOD_GET;
							} else { /*(preserve behavior for server.error-handler-404)*/
								con->error_handler_saved_status = -con->http_status; /*(negative to flag old behavior)*/
							}

							if (con->request.http_version == HTTP_VERSION_UNSET) con->request.http_version = HTTP_VERSION_1_0;

							buffer_copy_buffer(con->request.uri, error_handler);
							connection_handle_errdoc_init(con);
							con->http_status = 0; /*(after connection_handle_errdoc_init())*/

							return 1;
						}
					}
				}

				/* we have something to send, go on */
				connection_set_state(con, CON_STATE_RESPONSE_START);
				break;
			case HANDLER_WAIT_FOR_FD:
				connection_fdwaitqueue_append(con);
				break;
			case HANDLER_COMEBACK:
				if (con->mode == DIRECT && buffer_is_empty(con->physical.path)) {
					config_reset_config(con);
				}
				return 1;
			case HANDLER_ERROR:
				/* something went wrong */
				connection_set_state(con, CON_STATE_ERROR);
				break;
			default:
				log_error(con->conf.errh, __FILE__, __LINE__, "unknown ret-value: %d %d", con->fd, r);
				break;
			}

			return 0;
}


int connection_state_machine(server *srv, connection *con) {
	connection_state_t ostate;
	int r;
	const int log_state_handling = srv->srvconf.log_state_handling;

	if (log_state_handling) {
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "state at enter %d %s", con->fd, connection_get_state(con->state));
	}

	do {
		if (log_state_handling) {
			log_error(con->conf.errh, __FILE__, __LINE__,
			  "state for fd %d %s", con->fd, connection_get_state(con->state));
		}

		switch ((ostate = con->state)) {
		case CON_STATE_REQUEST_START: /* transient */
			con->request_start = srv->cur_ts;
			con->read_idle_ts = srv->cur_ts;
			if (con->conf.high_precision_timestamps)
				log_clock_gettime_realtime(&con->request_start_hp);

			con->request_count++;
			con->loops_per_request = 0;

			connection_set_state(con, CON_STATE_READ);
			/* fall through */
		case CON_STATE_READ:
			if (!connection_handle_read_state(srv, con)) break;
			/*if (con->state != CON_STATE_REQUEST_END) break;*/
			/* fall through */
		case CON_STATE_REQUEST_END: /* transient */
			ostate = (0 == con->request.content_length)
			  ? CON_STATE_HANDLE_REQUEST
			  : CON_STATE_READ_POST;
			connection_set_state(con, ostate);
			/* fall through */
		case CON_STATE_READ_POST:
		case CON_STATE_HANDLE_REQUEST:
			if (connection_handle_request(con)) {
				/* redo loop; will not match con->state */
				ostate = CON_STATE_CONNECT;
				break;
			}

			if (con->state == CON_STATE_HANDLE_REQUEST
			    && ostate == CON_STATE_READ_POST) {
				ostate = CON_STATE_HANDLE_REQUEST;
			}

			if (con->state != CON_STATE_RESPONSE_START) break;
			/* fall through */
		case CON_STATE_RESPONSE_START: /* transient */
			if (-1 == connection_handle_write_prepare(con)) {
				connection_set_state(con, CON_STATE_ERROR);
				break;
			}
			connection_set_state(con, CON_STATE_WRITE);
			/* fall through */
		case CON_STATE_WRITE:
			connection_handle_write_state(con);
			if (con->state != CON_STATE_RESPONSE_END) break;
			/* fall through */
		case CON_STATE_RESPONSE_END: /* transient */
		case CON_STATE_ERROR:        /* transient */
			connection_handle_response_end_state(con);
			break;
		case CON_STATE_CLOSE:
			connection_handle_close_state(srv, con);
			break;
		case CON_STATE_CONNECT:
			break;
		default:
			log_error(con->conf.errh, __FILE__, __LINE__,
			  "unknown state: %d %d", con->fd, con->state);
			break;
		}
	} while (ostate != con->state);

	if (log_state_handling) {
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "state at exit: %d %s", con->fd, connection_get_state(con->state));
	}

	r = 0;
	switch(con->state) {
	case CON_STATE_READ:
		r = FDEVENT_IN | FDEVENT_RDHUP;
		break;
	case CON_STATE_WRITE:
		/* request write-fdevent only if we really need it
		 * - if we have data to write
		 * - if the socket is not writable yet
		 */
		if (!chunkqueue_is_empty(con->write_queue) &&
		    (con->is_writable == 0) &&
		    (con->traffic_limit_reached == 0)) {
			r |= FDEVENT_OUT;
		}
		/* fall through */
	case CON_STATE_READ_POST:
		if (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN) {
			r |= FDEVENT_IN | FDEVENT_RDHUP;
		}
		break;
	case CON_STATE_CLOSE:
		r = FDEVENT_IN;
		break;
	default:
		break;
	}
	if (con->fd >= 0) {
		const int events = fdevent_fdnode_interest(con->fdn);
		if (con->is_readable < 0) {
			con->is_readable = 0;
			r |= FDEVENT_IN;
		}
		if (con->is_writable < 0) {
			con->is_writable = 0;
			r |= FDEVENT_OUT;
		}
		if (events & FDEVENT_RDHUP) {
			r |= FDEVENT_RDHUP;
		}
		if (r != events) {
			/* update timestamps when enabling interest in events */
			if ((r & FDEVENT_IN) && !(events & FDEVENT_IN)) {
				con->read_idle_ts = srv->cur_ts;
			}
			if ((r & FDEVENT_OUT) && !(events & FDEVENT_OUT)) {
				con->write_request_ts = srv->cur_ts;
			}
			fdevent_fdnode_event_set(srv->ev, con->fdn, r);
		}
	}

	return 0;
}

static void connection_check_timeout (server * const srv, const time_t cur_ts, connection * const con) {
    const int waitevents = fdevent_fdnode_interest(con->fdn);
    int changed = 0;
    int t_diff;

    if (con->state == CON_STATE_CLOSE) {
        if (cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT) {
            changed = 1;
        }
    } else if (waitevents & FDEVENT_IN) {
        if (con->request_count == 1 || con->state != CON_STATE_READ) {
            /* e.g. CON_STATE_READ_POST || CON_STATE_WRITE */
            if (cur_ts - con->read_idle_ts > con->conf.max_read_idle) {
                /* time - out */
                if (con->conf.log_request_handling) {
                    log_error(con->conf.errh, __FILE__, __LINE__,
                              "connection closed - read timeout: %d", con->fd);
                }

                connection_set_state(con, CON_STATE_ERROR);
                changed = 1;
            }
        } else {
            if (cur_ts - con->read_idle_ts > con->keep_alive_idle) {
                /* time - out */
                if (con->conf.log_request_handling) {
                    log_error(con->conf.errh, __FILE__, __LINE__,
                              "connection closed - keep-alive timeout: %d",
                              con->fd);
                }

                connection_set_state(con, CON_STATE_ERROR);
                changed = 1;
            }
        }
    }

    /* max_write_idle timeout currently functions as backend timeout,
     * too, after response has been started.
     * future: have separate backend timeout, and then change this
     * to check for write interest before checking for timeout */
    /*if (waitevents & FDEVENT_OUT)*/
    if ((con->state == CON_STATE_WRITE) &&
        (con->write_request_ts != 0)) {
      #if 0
        if (cur_ts - con->write_request_ts > 60) {
            log_error(con->conf.errh, __FILE__, __LINE__,
                      "connection closed - pre-write-request-timeout: %d %d",
                      con->fd, cur_ts - con->write_request_ts);
        }
      #endif

        if (cur_ts - con->write_request_ts > con->conf.max_write_idle) {
            /* time - out */
            if (con->conf.log_timeouts) {
                log_error(con->conf.errh, __FILE__, __LINE__,
                  "NOTE: a request from %.*s for %.*s timed out after writing "
                  "%zd bytes. We waited %d seconds.  If this is a problem, "
                  "increase server.max-write-idle",
                  BUFFER_INTLEN_PTR(con->dst_addr_buf),
                  BUFFER_INTLEN_PTR(con->request.uri),
                  con->bytes_written, (int)con->conf.max_write_idle);
            }
            connection_set_state(con, CON_STATE_ERROR);
            changed = 1;
        }
    }

    if (0 == (t_diff = cur_ts - con->connection_start)) t_diff = 1;

    if (con->traffic_limit_reached &&
        (con->conf.bytes_per_second == 0 ||
         con->bytes_written < (off_t)con->conf.bytes_per_second * t_diff)) {
        /* enable connection again */
        con->traffic_limit_reached = 0;

        changed = 1;
    }

    con->bytes_written_cur_second = 0;

    if (changed) {
        connection_state_machine(srv, con);
    }
}

void connection_periodic_maint (server * const srv, const time_t cur_ts) {
    /* check all connections for timeouts */
    connections * const conns = &srv->conns;
    for (size_t ndx = 0; ndx < conns->used; ++ndx) {
        connection_check_timeout(srv, cur_ts, conns->ptr[ndx]);
    }
}

void connection_graceful_shutdown_maint (server *srv) {
    connections * const conns = &srv->conns;
    for (size_t ndx = 0; ndx < conns->used; ++ndx) {
        connection * const con = conns->ptr[ndx];
        int changed = 0;

        if (con->state == CON_STATE_CLOSE) {
            /* reduce remaining linger timeout to be
             * (from zero) *up to* one more second, but no more */
            if (HTTP_LINGER_TIMEOUT > 1)
                con->close_timeout_ts -= (HTTP_LINGER_TIMEOUT - 1);
            if (srv->cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT)
                changed = 1;
        }
        else if (con->state == CON_STATE_READ && con->request_count > 1
                 && chunkqueue_is_empty(con->read_queue)) {
            /* close connections in keep-alive waiting for next request */
            connection_set_state(con, CON_STATE_ERROR);
            changed = 1;
        }

        con->keep_alive = 0;                    /* disable keep-alive */

        con->conf.bytes_per_second = 0;         /* disable rate limit */
        con->conf.global_bytes_per_second = 0;  /* disable rate limit */
        if (con->traffic_limit_reached) {
            con->traffic_limit_reached = 0;
            changed = 1;
        }

        if (changed) {
            connection_state_machine(srv, con);
        }
    }
}
