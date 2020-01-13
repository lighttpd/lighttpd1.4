#include "first.h"

#include "base.h"
#include "buffer.h"
#include "burl.h"       /* HTTP_PARSEOPT_HEADER_STRICT */
#include "settings.h"   /* BUFFER_MAX_REUSE_SIZE MAX_READ_LIMIT MAX_WRITE_LIMIT */
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

#define connection_set_state(r, n) ((r)->state = (n))

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

static void connection_del(server *srv, connection *con) {
	connections * const conns = &srv->conns;

	if (-1 == con->ndx) return;
	uint32_t i = (uint32_t)con->ndx;

	/* not last element */

	if (i != --conns->used) {
		connection * const temp = conns->ptr[i];
		conns->ptr[i] = conns->ptr[conns->used];
		conns->ptr[conns->used] = temp;

		conns->ptr[i]->ndx = i;
		conns->ptr[conns->used]->ndx = -1;
	}

	con->ndx = -1;
#if 0
	fprintf(stderr, "%s.%d: del: (%d)", __FILE__, __LINE__, conns->used);
	for (i = 0; i < conns->used; i++) {
		fprintf(stderr, "%d ", conns->ptr[i]->fd);
	}
	fprintf(stderr, "\n");
#endif
}

__attribute_cold__
static void connection_plugin_ctx_check(server * const srv, request_st * const r) {
	/* plugins should have cleaned themselves up */
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		plugin *p = ((plugin **)(srv->plugins.ptr))[i];
		plugin_data_base *pd = p->data;
		if (!pd || NULL == r->plugin_ctx[pd->id]) continue;
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "missing cleanup in %s", p->name);
		r->plugin_ctx[pd->id] = NULL;
	}
}

static void connection_close(connection *con) {
	if (con->fd < 0) con->fd = -con->fd;

	plugins_call_handle_connection_close(con);

	server * const srv = con->srv;
	request_st * const r = &con->request;

	/* plugins should have cleaned themselves up */
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		if (NULL != r->plugin_ctx[i]) {
			connection_plugin_ctx_check(srv, r);
			break;
		}
	}

	connection_set_state(r, CON_STATE_CONNECT);
	buffer_clear(&r->uri.authority);
	buffer_reset(&r->uri.path);
	buffer_reset(&r->uri.query);
	buffer_reset(&r->target_orig);
	buffer_reset(&r->target);       /*(see comments in connection_reset())*/
	buffer_reset(&r->pathinfo);     /*(see comments in connection_reset())*/
	buffer_reset(&r->uri.path_raw); /*(see comments in connection_reset())*/

	chunkqueue_reset(con->read_queue);
	con->request_count = 0;
	con->is_ssl_sock = 0;

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
		log_perror(r->conf.errh, __FILE__, __LINE__,
		  "(warning) close: %d", con->fd);

	if (r->conf.log_state_handling) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "connection closed for fd %d", con->fd);
	}
	con->fd = -1;

	connection_del(srv, con);
}

static void connection_read_for_eos_plain(connection * const con) {
	/* we have to do the linger_on_close stuff regardless
	 * of r->keep_alive; even non-keepalive sockets
	 * may still have unread data, and closing before reading
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
		con->close_timeout_ts = log_epoch_secs - (HTTP_LINGER_TIMEOUT+1);
}

static void connection_read_for_eos_ssl(connection * const con) {
	if (con->network_read(con, con->read_queue, MAX_READ_LIMIT) < 0)
		con->close_timeout_ts = log_epoch_secs - (HTTP_LINGER_TIMEOUT+1);
	chunkqueue_reset(con->read_queue);
}

static void connection_read_for_eos(connection * const con) {
	!con->is_ssl_sock
	  ? connection_read_for_eos_plain(con)
	  : connection_read_for_eos_ssl(con);
}

static void connection_handle_close_state(connection *con) {
	connection_read_for_eos(con);

	if (log_epoch_secs - con->close_timeout_ts > HTTP_LINGER_TIMEOUT) {
		connection_close(con);
	}
}

static void connection_handle_shutdown(connection *con) {
	plugins_call_handle_connection_shut_wr(con);

	connection_reset(con);
	++con->srv->con_closed;

	/* close the connection */
	if (con->fd >= 0
	    && (con->is_ssl_sock || 0 == shutdown(con->fd, SHUT_WR))) {
		con->close_timeout_ts = log_epoch_secs;

		request_st * const r = &con->request;
		connection_set_state(r, CON_STATE_CLOSE);
		if (r->conf.log_state_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "shutdown for fd %d", con->fd);
		}
	} else {
		connection_close(con);
	}
}

__attribute_cold__
static void connection_fdwaitqueue_append(connection *con) {
    connection_list_append(&con->srv->fdwaitqueue, con);
}

static void connection_handle_response_end_state(request_st * const r, connection * const con) {
	/* call request_done hook if http_status set (e.g. to log request) */
	/* (even if error, connection dropped, as long as http_status is set) */
	if (r->http_status) plugins_call_handle_request_done(r);

	if (r->state != CON_STATE_ERROR) ++con->srv->con_written;

	if (r->reqbody_length != r->reqbody_queue->bytes_in
	    || r->state == CON_STATE_ERROR) {
		/* request body is present and has not been read completely */
		r->keep_alive = 0;
	}

        if (r->keep_alive) {
		connection_reset(con);
#if 0
		r->start_ts = con->read_idle_ts = log_epoch_secs;
#endif
		connection_set_state(r, CON_STATE_REQUEST_START);
	} else {
		connection_handle_shutdown(con);
	}
}

__attribute_cold__
static void connection_handle_errdoc_init(request_st * const r) {
	/* modules that produce headers required with error response should
	 * typically also produce an error document.  Make an exception for
	 * mod_auth WWW-Authenticate response header. */
	buffer *www_auth = NULL;
	if (401 == r->http_status) {
		const buffer *vb = http_header_response_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"));
		if (NULL != vb) www_auth = buffer_init_buffer(vb);
	}

	buffer_reset(&r->physical.path);
	r->resp_htags = 0;
	array_reset_data_strings(&r->resp_headers);
	http_response_body_clear(r, 0);

	if (NULL != www_auth) {
		http_header_response_set(r, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(www_auth));
		buffer_free(www_auth);
	}
}

__attribute_cold__
static void connection_handle_errdoc(request_st * const r) {
    if (NULL == r->handler_module
        ? r->error_handler_saved_status >= 65535
        : (!r->conf.error_intercept||r->error_handler_saved_status))
        return;

    connection_handle_errdoc_init(r);
    r->resp_body_finished = 1;

    /* try to send static errorfile */
    if (!buffer_string_is_empty(r->conf.errorfile_prefix)) {
        buffer_copy_buffer(&r->physical.path, r->conf.errorfile_prefix);
        buffer_append_int(&r->physical.path, r->http_status);
        buffer_append_string_len(&r->physical.path, CONST_STR_LEN(".html"));
        if (0 == http_chunk_append_file(r, &r->physical.path)) {
            stat_cache_entry *sce = stat_cache_get_entry(&r->physical.path);
            const buffer *content_type = (NULL != sce)
              ? stat_cache_content_type_get(sce, r)
              : NULL;
            if (content_type)
                http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
                                         CONST_STR_LEN("Content-Type"),
                                         CONST_BUF_LEN(content_type));
            return;
        }
    }

    /* build default error-page */
    buffer_reset(&r->physical.path);
    buffer * const b = r->tmp_buf;
    buffer_copy_string_len(b, CONST_STR_LEN(
      "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
      "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
      "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
      " <head>\n"
      "  <title>"));
    http_status_append(b, r->http_status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</title>\n"
      " </head>\n"
      " <body>\n"
      "  <h1>"));
    http_status_append(b, r->http_status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</h1>\n"
      " </body>\n"
      "</html>\n"));
    (void)http_chunk_append_mem(r, CONST_BUF_LEN(b));

    http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
                             CONST_STR_LEN("Content-Type"),
                             CONST_STR_LEN("text/html"));
}

static int connection_handle_write_prepare(request_st * const r) {
	if (NULL == r->handler_module) {
		/* static files */
		switch(r->http_method) {
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
			if ((!r->http_status || r->http_status == 200)
			    && !buffer_string_is_empty(&r->uri.path)
			    && r->uri.path.ptr[0] != '*') {
				http_response_body_clear(r, 0);
				http_header_response_append(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Allow"), CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));
				r->http_status = 200;
				r->resp_body_finished = 1;

			}
			break;
		default:
			if (0 == r->http_status) {
				r->http_status = 501;
			}
			break;
		}
	}

	if (r->http_status == 0) {
		r->http_status = 403;
	}

	switch(r->http_status) {
	case 204: /* class: header only */
	case 205:
	case 304:
		/* disable chunked encoding again as we have no body */
		http_response_body_clear(r, 1);
		r->resp_body_finished = 1;
		break;
	default: /* class: header + body */
		/* only custom body for 4xx and 5xx */
		if (r->http_status >= 400 && r->http_status < 600)
			connection_handle_errdoc(r);
		break;
	}

	/* Allow filter plugins to change response headers before they are written. */
	switch(plugins_call_handle_response_start(r)) {
	case HANDLER_GO_ON:
	case HANDLER_FINISHED:
		break;
	default:
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "response_start plugin failed");
		return -1;
	}

	if (r->resp_body_finished) {
		/* we have all the content and chunked encoding is not used, set a content-length */

		if (!(r->resp_htags & (HTTP_HEADER_CONTENT_LENGTH|HTTP_HEADER_TRANSFER_ENCODING))) {
			off_t qlen = chunkqueue_length(r->write_queue);

			/**
			 * The Content-Length header only can be sent if we have content:
			 * - HEAD doesn't have a content-body (but have a content-length)
			 * - 1xx, 204 and 304 don't have a content-body (RFC 2616 Section 4.3)
			 *
			 * Otherwise generate a Content-Length header as chunked encoding is not 
			 * available
			 */
			if ((r->http_status >= 100 && r->http_status < 200) ||
			    r->http_status == 204 ||
			    r->http_status == 304) {
				/* no Content-Body, no Content-Length */
				http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
			} else if (qlen > 0 || r->http_method != HTTP_METHOD_HEAD) {
				/* qlen = 0 is important for Redirects (301, ...) as they MAY have
				 * a content. Browsers are waiting for a Content otherwise
				 */
				buffer * const tb = r->tmp_buf;
				buffer_clear(tb);
				buffer_append_int(tb, qlen);
				http_header_response_set(r, HTTP_HEADER_CONTENT_LENGTH,
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

		if (!(r->resp_htags & (HTTP_HEADER_CONTENT_LENGTH|HTTP_HEADER_TRANSFER_ENCODING|HTTP_HEADER_UPGRADE))) {
			if (r->http_method == HTTP_METHOD_CONNECT
			    && r->http_status == 200) {
				/*(no transfer-encoding if successful CONNECT)*/
			} else if (r->http_version == HTTP_VERSION_1_1) {
				off_t qlen = chunkqueue_length(r->write_queue);
				r->resp_send_chunked = 1;
				if (qlen) {
					/* create initial Transfer-Encoding: chunked segment */
					buffer * const b = chunkqueue_prepend_buffer_open(r->write_queue);
					buffer_append_uint_hex(b, (uintmax_t)qlen);
					buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
					chunkqueue_prepend_buffer_commit(r->write_queue);
					chunkqueue_append_mem(r->write_queue, CONST_STR_LEN("\r\n"));
				}
				http_header_response_append(r, HTTP_HEADER_TRANSFER_ENCODING, CONST_STR_LEN("Transfer-Encoding"), CONST_STR_LEN("chunked"));
			} else {
				r->keep_alive = 0;
			}
		}
	}

	if (r->http_method == HTTP_METHOD_HEAD) {
		/**
		 * a HEAD request has the same as a GET 
		 * without the content
		 */
		http_response_body_clear(r, 1);
		r->resp_body_finished = 1;
	}

	http_response_write_header(r);

	return 0;
}

static void connection_handle_write(connection *con) {
	int rc = connection_write_chunkqueue(con, con->write_queue, MAX_WRITE_LIMIT);
	request_st * const r = &con->request;
	switch (rc) {
	case 0:
		if (r->resp_body_finished) {
			connection_set_state(r, CON_STATE_RESPONSE_END);
		}
		break;
	case -1: /* error on our side */
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "connection closed: write failed on fd %d", con->fd);
		connection_set_state(r, CON_STATE_ERROR);
		break;
	case -2: /* remote close */
		connection_set_state(r, CON_STATE_ERROR);
		break;
	case 1:
		con->is_writable = 0;

		/* not finished yet -> WRITE */
		break;
	}
}

static void connection_handle_write_state(request_st * const r, connection * const con) {
    do {
        /* only try to write if we have something in the queue */
        if (!chunkqueue_is_empty(con->write_queue)) {
            if (con->is_writable) {
                connection_handle_write(con);
                if (r->state != CON_STATE_WRITE) break;
            }
        } else if (r->resp_body_finished) {
            connection_set_state(r, CON_STATE_RESPONSE_END);
            break;
        }

        if (r->handler_module && !r->resp_body_finished) {
            const plugin * const p = r->handler_module;
            int rc = p->handle_subrequest(r, p->data);
            switch(rc) {
            case HANDLER_WAIT_FOR_EVENT:
            case HANDLER_FINISHED:
            case HANDLER_GO_ON:
                break;
            case HANDLER_WAIT_FOR_FD:
                connection_fdwaitqueue_append(con);
                break;
            case HANDLER_COMEBACK:
            default:
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "unexpected subrequest handler ret-value: %d %d",
                  con->fd, rc);
                /* fall through */
            case HANDLER_ERROR:
                connection_set_state(r, CON_STATE_ERROR);
                break;
            }
        }
    } while (r->state == CON_STATE_WRITE
             && (!chunkqueue_is_empty(con->write_queue)
                 ? con->is_writable
                 : r->resp_body_finished));
}


__attribute_cold__
static connection *connection_init(server *srv) {
	connection * const con = calloc(1, sizeof(*con));
	force_assert(NULL != con);

	con->fd = 0;
	con->ndx = -1;
	con->bytes_written = 0;
	con->bytes_read = 0;

	con->dst_addr_buf = buffer_init();
	con->srv  = srv;
	con->plugin_slots = srv->plugin_slots;
	con->config_data_base = srv->config_data_base;

	request_st * const r = &con->request;

	con->write_queue = r->write_queue = chunkqueue_init();
	con->read_queue = r->read_queue = chunkqueue_init();

	/* init plugin specific connection structures */

	r->resp_header_len = 0;
	r->loops_per_request = 0;
	r->con = con;
	r->tmp_buf = srv->tmp_buf;

	r->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));
	force_assert(NULL != r->plugin_ctx);

	r->cond_cache = calloc(srv->config_context->used, sizeof(cond_cache_t));
	force_assert(NULL != r->cond_cache);

      #ifdef HAVE_PCRE_H
	if (srv->config_context->used > 1) {/*save 128b per con if no conditions)*/
		r->cond_match =
		  calloc(srv->config_context->used, sizeof(cond_match_t));
		force_assert(NULL != r->cond_match);
	}
      #endif

	r->reqbody_queue = chunkqueue_init();

	config_reset_config(r);

	return con;
}

void connections_free(server *srv) {
	connections * const conns = &srv->conns;
	for (uint32_t i = 0; i < conns->size; ++i) {
		connection *con = conns->ptr[i];
		request_st * const r = &con->request;

		connection_reset(con);

		chunkqueue_free(r->reqbody_queue);
		chunkqueue_free(r->write_queue);
		chunkqueue_free(r->read_queue);
		array_free_data(&r->rqst_headers);
		array_free_data(&r->resp_headers);
		array_free_data(&r->env);

		free(r->target.ptr);
		free(r->target_orig.ptr);

		free(r->uri.scheme.ptr);
		free(r->uri.authority.ptr);
		free(r->uri.path.ptr);
		free(r->uri.path_raw.ptr);
		free(r->uri.query.ptr);

		free(r->physical.doc_root.ptr);
		free(r->physical.path.ptr);
		free(r->physical.basedir.ptr);
		free(r->physical.etag.ptr);
		free(r->physical.rel_path.ptr);

		free(r->pathinfo.ptr);
		free(r->server_name_buf.ptr);

		free(r->plugin_ctx);
		free(r->cond_cache);
		free(r->cond_match);

		buffer_free(con->dst_addr_buf);

		free(con);
	}

	free(conns->ptr);
	conns->ptr = NULL;
}


static int connection_reset(connection *con) {
	request_st * const r = &con->request;
	plugins_call_connection_reset(r);

	connection_response_reset(r);
	con->is_readable = 1;

	con->bytes_written = 0;
	con->bytes_written_cur_second = 0;
	con->bytes_read = 0;

	r->resp_header_len = 0;
	r->loops_per_request = 0;

	r->http_method = HTTP_METHOD_UNSET;
	r->http_version = HTTP_VERSION_UNSET;

	/*con->proto_default_port = 80;*//*set to default in connection_accepted()*/

	r->http_host = NULL;
	r->reqbody_length = 0;
	r->te_chunked = 0;
	r->rqst_htags = 0;

	buffer_clear(&r->uri.scheme);

	if (r->rqst_header_len <= BUFFER_MAX_REUSE_SIZE) {
		r->rqst_headers.used = 0;
		/* (Note: total header size not recalculated on HANDLER_COMEBACK
		 *  even if other request headers changed during processing)
		 * (While this might delay release of larger buffers, it is not
		 *  expected to be the general case.  For those systems where it
		 *  is a typical case, the larger buffers are likely to be reused) */
		buffer_clear(&r->target);
		buffer_clear(&r->pathinfo);
		buffer_clear(&r->uri.path_raw);
		/*buffer_clear(&r->target_orig);*/  /* reset later; used by mod_status*/
		/*buffer_clear(&r->uri.path);*/     /* reset later; used by mod_status*/
		/*buffer_clear(&r->uri.query);*/    /* reset later; used by mod_status*/
		/*buffer_clear(&r->uri.authority);*//* reset later; used by mod_status*/
		/*buffer_clear(&r->server_name_buf);*//* reset when used */
	}
	else {
		buffer_reset(&r->target);
		buffer_reset(&r->pathinfo);
		buffer_reset(&r->uri.path_raw);
		/*buffer_reset(&r->target_orig);*/  /* reset later; used by mod_status*/
		/*buffer_reset(&r->uri.path);*/     /* reset later; used by mod_status*/
		/*buffer_reset(&r->uri.query);*/    /* reset later; used by mod_status*/
		/*buffer_clear(&r->uri.authority);*//* reset later; used by mod_status*/
		/*buffer_clear(&r->server_name_buf);*//* reset when used */
		array_reset_data_strings(&r->rqst_headers);
	}
	r->rqst_header_len = 0;
	if (0 != r->env.used)
		array_reset_data_strings(&r->env);

	chunkqueue_reset(r->reqbody_queue);

	/* The cond_cache gets reset in response.c */
	/* config_cond_cache_reset(r); */

	r->async_callback = 0;
	r->error_handler_saved_status = 0;
	/*r->error_handler_saved_method = HTTP_METHOD_UNSET;*/
	/*(error_handler_saved_method value is not valid unless error_handler_saved_status is set)*/

	config_reset_config(r);

	return 0;
}

__attribute_noinline__
static void connection_discard_blank_line(request_st * const r, const char * const s, unsigned short * const hoff)  {
    if ((s[0] == '\r' && s[1] == '\n')
        || (s[0] == '\n'
            && !(r->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT))) {
        hoff[2] += hoff[1];
        memmove(hoff+1, hoff+2, (--hoff[0] - 1) * sizeof(unsigned short));
    }
}

static chunk * connection_read_header_more(connection *con, chunkqueue *cq, chunk *c, const size_t olen) {
    if ((NULL == c || NULL == c->next) && con->is_readable) {
        con->read_idle_ts = log_epoch_secs;
        if (0 != con->network_read(con, cq, MAX_READ_LIMIT)) {
            request_st * const r = &con->request;
            connection_set_state(r, CON_STATE_ERROR);
        }
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
static int connection_handle_read_state(connection * const con)  {
    chunkqueue * const cq = con->read_queue;
    chunk *c = cq->first;
    uint32_t clen = 0;
    uint32_t header_len = 0;
    request_st * const r = &con->request;
    int keepalive_request_start = 0;
    int pipelined_request_start = 0;
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */

    if (con->request_count > 1 && 0 == con->bytes_read) {
        keepalive_request_start = 1;
        if (NULL != c) { /* !chunkqueue_is_empty(cq)) */
            pipelined_request_start = 1;
            /* partial header of next request has already been read,
             * so optimistically check for more data received on
             * socket while processing the previous request */
            con->is_readable = 1;
            /*(if partially read next request and unable to read() any bytes,
             * then will unnecessarily scan again before subsequent read())*/
        }
    }

    do {
        if (NULL == c) continue;
        clen = buffer_string_length(c->mem) - c->offset;
        if (0 == clen) continue;
        if (c->offset > USHRT_MAX) /*(highly unlikely)*/
            chunkqueue_compact_mem(cq, clen);

        hoff[0] = 1;                         /* number of lines */
        hoff[1] = (unsigned short)c->offset; /* base offset for all lines */
        /*hoff[2] = ...;*/                   /* offset from base for 2nd line */

        header_len =
          connection_read_header_hoff(c->mem->ptr + c->offset, clen, hoff);

        /* casting to (unsigned short) might truncate, and the hoff[]
         * addition might overflow, but max_request_field_size is USHRT_MAX,
         * so failure will be detected below */
        const uint32_t max_request_field_size=r->conf.max_request_field_size;
        if ((header_len ? header_len : clen) > max_request_field_size
            || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1) {
            log_error(r->conf.errh, __FILE__, __LINE__, "%s",
                      "oversized request-header -> sending Status 431");
            r->http_status = 431; /* Request Header Fields Too Large */
            r->keep_alive = 0;
            return 1;
        }

        if (0 != header_len) break;
    } while ((c = connection_read_header_more(con, cq, c, clen)));

    if (keepalive_request_start) {
        if (0 != con->bytes_read) {
            /* update r->start_ts timestamp when first byte of
             * next request is received on a keep-alive connection */
            r->start_ts = log_epoch_secs;
            if (r->conf.high_precision_timestamps)
                log_clock_gettime_realtime(&r->start_hp);
        }
        if (pipelined_request_start && c) con->read_idle_ts = log_epoch_secs;
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
            connection_discard_blank_line(r, hdrs, hoff);

        /* clear buffers which may have been kept for reporting on keep-alive,
         * (e.g. mod_status) */
        buffer_clear(&r->uri.authority);
        buffer_reset(&r->uri.path);
        buffer_reset(&r->uri.query);
        buffer_reset(&r->target_orig);
    }

    if (r->conf.log_request_header) {
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "fd: %d request-len: %d\n%.*s", con->fd, (int)header_len,
                  (int)header_len, hdrs);
    }

    r->http_status = http_request_parse(r, hdrs, hoff, con->proto_default_port);
    if (0 != r->http_status) {
        r->keep_alive = 0;
        r->reqbody_length = 0;

        if (r->conf.log_request_header_on_error) {
            /*(http_request_parse() modifies hdrs only to
             * undo line-wrapping in-place using spaces)*/
            log_error(r->conf.errh, __FILE__, __LINE__, "request-header:\n%.*s",
                      (int)header_len, hdrs);
        }
    }

    r->rqst_header_len = header_len;
    chunkqueue_mark_written(cq, header_len);
    connection_set_state(r, CON_STATE_REQUEST_END);
    return 1;
}

static handler_t connection_handle_fdevent(void *context, int revents) {
	connection *con = context;

	joblist_append(con);

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

	request_st * const r = &con->request;

	if (r->state == CON_STATE_READ) {
		connection_handle_read_state(con);
	}

	if (r->state == CON_STATE_WRITE &&
	    !chunkqueue_is_empty(con->write_queue) &&
	    con->is_writable) {
		connection_handle_write(con);
	}

	if (r->state == CON_STATE_CLOSE) {
		/* flush the read buffers */
		connection_read_for_eos(con);
	}


	/* attempt (above) to read data in kernel socket buffers
	 * prior to handling FDEVENT_HUP and FDEVENT_ERR */

	if ((revents & ~(FDEVENT_IN | FDEVENT_OUT)) && r->state != CON_STATE_ERROR) {
		if (r->state == CON_STATE_CLOSE) {
			con->close_timeout_ts = log_epoch_secs - (HTTP_LINGER_TIMEOUT+1);
		} else if (revents & FDEVENT_HUP) {
			connection_set_state(r, CON_STATE_ERROR);
		} else if (revents & FDEVENT_RDHUP) {
			int events = fdevent_fdnode_interest(con->fdn);
			events &= ~(FDEVENT_IN|FDEVENT_RDHUP);
			r->conf.stream_request_body &= ~(FDEVENT_STREAM_REQUEST_BUFMIN|FDEVENT_STREAM_REQUEST_POLLIN);
			r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLRDHUP;
			con->is_readable = 1; /*(can read 0 for end-of-stream)*/
			if (chunkqueue_is_empty(con->read_queue)) r->keep_alive = 0;
			if (r->reqbody_length < -1) { /*(transparent proxy mode; no more data to read)*/
				r->reqbody_length = r->reqbody_queue->bytes_in;
			}
			if (sock_addr_get_family(&con->dst_addr) == AF_UNIX) {
				/* future: will getpeername() on AF_UNIX properly check if still connected? */
				fdevent_fdnode_event_set(con->srv->ev, con->fdn, events);
			} else if (fdevent_is_tcp_half_closed(con->fd)) {
				/* Success of fdevent_is_tcp_half_closed() after FDEVENT_RDHUP indicates TCP FIN received,
				 * but does not distinguish between client shutdown(fd, SHUT_WR) and client close(fd).
				 * Remove FDEVENT_RDHUP so that we do not spin on the ready event.
				 * However, a later TCP RST will not be detected until next write to socket.
				 * future: might getpeername() to check for TCP RST on half-closed sockets
				 * (without FDEVENT_RDHUP interest) when checking for write timeouts
				 * once a second in server.c, though getpeername() on Windows might not indicate this */
				r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;
				fdevent_fdnode_event_set(con->srv->ev, con->fdn, events);
			} else {
				/* Failure of fdevent_is_tcp_half_closed() indicates TCP RST
				 * (or unable to tell (unsupported OS), though should not
				 * be setting FDEVENT_RDHUP in that case) */
				connection_set_state(r, CON_STATE_ERROR);
			}
		} else if (revents & FDEVENT_ERR) { /* error, connection reset */
			connection_set_state(r, CON_STATE_ERROR);
		} else {
			log_error(r->conf.errh, __FILE__, __LINE__,
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


__attribute_cold__
static int connection_read_cq_err(connection *con) {
    request_st * const r = &con->request;
  #if defined(__WIN32)
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
        log_error(r->conf.errh, __FILE__, __LINE__,
          "connection closed - recv failed: %d", lastError);
        break;
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
        log_perror(r->conf.errh, __FILE__, __LINE__,
          "connection closed - read failed");
        break;
    }
  #endif /* __WIN32 */

    connection_set_state(r, CON_STATE_ERROR);
    return -1;
}


/* 0: everything ok, -1: error, -2: con closed */
static int connection_read_cq(connection *con, chunkqueue *cq, off_t max_bytes) {
    ssize_t len;
    size_t mem_len = 0;

    do {
        /* obtain chunk memory into which to read
         * fill previous chunk if it has a reasonable amount of space available
         * (use mem_len=0 to obtain large buffer at least half of chunk_buf_sz)
         */
        chunk *ckpt = cq->last;
        char * const mem = chunkqueue_get_memory(cq, &mem_len);
        if (mem_len > (size_t)max_bytes) mem_len = (size_t)max_bytes;

      #if defined(__WIN32)
        len = recv(con->fd, mem, mem_len, 0);
      #else
        len = read(con->fd, mem, mem_len);
      #endif

        chunkqueue_use_memory(cq, ckpt, len > 0 ? len : 0);

        if (len != (ssize_t)mem_len) {
            /* we got less then expected, wait for the next fd-event */
            con->is_readable = 0;

            if (len > 0) {
                con->bytes_read += len;
                return 0;
            }
            else if (0 == len) /* other end close connection -> KEEP-ALIVE */
                return -2;     /* (pipelining) */
            else
                return connection_read_cq_err(con);
        }

        con->bytes_read += len;
        max_bytes -= len;

        int frd;
        mem_len = (0 == fdevent_ioctl_fionread(con->fd, S_IFSOCK, &frd))
          ? (frd < max_bytes) ? (size_t)frd : (size_t)max_bytes
          : 0;
    } while (max_bytes);
    return 0;
}


static int connection_write_cq(connection *con, chunkqueue *cq, off_t max_bytes) {
    request_st * const r = &con->request;
    return con->srv->network_backend_write(con->fd,cq,max_bytes,r->conf.errh);
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

		request_st * const r = &con->request;
		connection_set_state(r, CON_STATE_REQUEST_START);

		con->connection_start = log_epoch_secs;
		con->dst_addr = *cnt_addr;
		buffer_copy_string(con->dst_addr_buf, inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
		con->srv_socket = srv_socket;
		con->is_ssl_sock = srv_socket->is_ssl;
		con->proto_default_port = 80; /* "http" */

		config_cond_cache_reset(r);
		r->conditional_is_valid |= (1 << COMP_SERVER_SOCKET)
		                        |  (1 << COMP_HTTP_REMOTE_IP);

		if (HANDLER_GO_ON != plugins_call_handle_connection_accept(con)) {
			connection_reset(con);
			connection_close(con);
			return NULL;
		}
		if (r->http_status < 0) connection_set_state(r, CON_STATE_WRITE);
		return con;
}


static int connection_handle_request(request_st * const r) {
			int rc = http_response_prepare(r);
			switch (rc) {
			case HANDLER_WAIT_FOR_EVENT:
				if (!r->resp_body_finished && (!r->resp_body_started || 0 == r->conf.stream_response_body)) {
					break; /* come back here */
				}
				/* response headers received from backend; fall through to start response */
				/* fall through */
			case HANDLER_FINISHED:
				if (r->http_status == 0) r->http_status = 200;
				if (r->error_handler_saved_status > 0) {
					r->http_method = r->error_handler_saved_method;
				}
				if (NULL == r->handler_module || r->conf.error_intercept) {
					if (r->error_handler_saved_status) {
						const int subreq_status = r->http_status;
						if (r->error_handler_saved_status > 0) {
							r->http_status = r->error_handler_saved_status;
						} else if (r->http_status == 404 || r->http_status == 403) {
							/* error-handler-404 is a 404 */
							r->http_status = -r->error_handler_saved_status;
						} else {
							/* error-handler-404 is back and has generated content */
							/* if Status: was set, take it otherwise use 200 */
						}
						if (200 <= subreq_status && subreq_status <= 299) {
							/*(flag value to indicate that error handler succeeded)
							 *(for (NULL == r->handler_module))*/
							r->error_handler_saved_status = 65535; /* >= 1000 */
						}
					} else if (r->http_status >= 400) {
						const buffer *error_handler = NULL;
						if (!buffer_string_is_empty(r->conf.error_handler)) {
							error_handler = r->conf.error_handler;
						} else if ((r->http_status == 404 || r->http_status == 403)
							   && !buffer_string_is_empty(r->conf.error_handler_404)) {
							error_handler = r->conf.error_handler_404;
						}

						if (error_handler) {
							/* call error-handler */

							/* set REDIRECT_STATUS to save current HTTP status code
							 * for access by dynamic handlers
							 * https://redmine.lighttpd.net/issues/1828 */
							buffer * const tb = r->tmp_buf;
							buffer_clear(tb);
							buffer_append_int(tb, r->http_status);
							http_header_env_set(r, CONST_STR_LEN("REDIRECT_STATUS"), CONST_BUF_LEN(tb));

							if (error_handler == r->conf.error_handler) {
								plugins_call_connection_reset(r);

								if (r->reqbody_length) {
									if (r->reqbody_length != r->reqbody_queue->bytes_in) {
										r->keep_alive = 0;
									}
									r->reqbody_length = 0;
									chunkqueue_reset(r->reqbody_queue);
								}

								r->con->is_writable = 1;
								r->resp_body_finished = 0;
								r->resp_body_started = 0;

								r->error_handler_saved_status = r->http_status;
								r->error_handler_saved_method = r->http_method;

								r->http_method = HTTP_METHOD_GET;
							} else { /*(preserve behavior for server.error-handler-404)*/
								r->error_handler_saved_status = -r->http_status; /*(negative to flag old behavior)*/
							}

							if (r->http_version == HTTP_VERSION_UNSET) r->http_version = HTTP_VERSION_1_0;

							buffer_copy_buffer(&r->target, error_handler);
							connection_handle_errdoc_init(r);
							r->http_status = 0; /*(after connection_handle_errdoc_init())*/

							return 1;
						}
					}
				}

				/* we have something to send, go on */
				connection_set_state(r, CON_STATE_RESPONSE_START);
				break;
			case HANDLER_WAIT_FOR_FD:
				connection_fdwaitqueue_append(r->con);
				break;
			case HANDLER_COMEBACK:
				if (NULL == r->handler_module && buffer_is_empty(&r->physical.path)) {
					config_reset_config(r);
				}
				return 1;
			case HANDLER_ERROR:
				/* something went wrong */
				connection_set_state(r, CON_STATE_ERROR);
				break;
			default:
				connection_set_state(r, CON_STATE_ERROR);
				log_error(r->conf.errh, __FILE__, __LINE__, "unknown ret-value: %d %d", r->con->fd, rc);
				break;
			}

			return 0;
}


int connection_state_machine(connection *con) {
	request_st * const r = &con->request;
	request_state_t ostate;
	int rc;
	const int log_state_handling = r->conf.log_state_handling;

	if (log_state_handling) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "state at enter %d %s", con->fd, connection_get_state(r->state));
	}

	do {
		if (log_state_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "state for fd %d %s", con->fd, connection_get_state(r->state));
		}

		switch ((ostate = r->state)) {
		case CON_STATE_REQUEST_START: /* transient */
			r->start_ts = con->read_idle_ts = log_epoch_secs;
			if (r->conf.high_precision_timestamps)
				log_clock_gettime_realtime(&r->start_hp);

			con->request_count++;
			r->loops_per_request = 0;

			connection_set_state(r, CON_STATE_READ);
			/* fall through */
		case CON_STATE_READ:
			if (!connection_handle_read_state(con)) break;
			/*if (r->state != CON_STATE_REQUEST_END) break;*/
			/* fall through */
		case CON_STATE_REQUEST_END: /* transient */
			ostate = (0 == r->reqbody_length)
			  ? CON_STATE_HANDLE_REQUEST
			  : CON_STATE_READ_POST;
			connection_set_state(r, ostate);
			/* fall through */
		case CON_STATE_READ_POST:
		case CON_STATE_HANDLE_REQUEST:
			if (connection_handle_request(r)) {
				/* redo loop; will not match r->state */
				ostate = CON_STATE_CONNECT;
				break;
			}

			if (r->state == CON_STATE_HANDLE_REQUEST
			    && ostate == CON_STATE_READ_POST) {
				ostate = CON_STATE_HANDLE_REQUEST;
			}

			if (r->state != CON_STATE_RESPONSE_START) break;
			/* fall through */
		case CON_STATE_RESPONSE_START: /* transient */
			if (-1 == connection_handle_write_prepare(r)) {
				connection_set_state(r, CON_STATE_ERROR);
				break;
			}
			connection_set_state(r, CON_STATE_WRITE);
			/* fall through */
		case CON_STATE_WRITE:
			connection_handle_write_state(r, con);
			if (r->state != CON_STATE_RESPONSE_END) break;
			/* fall through */
		case CON_STATE_RESPONSE_END: /* transient */
		case CON_STATE_ERROR:        /* transient */
			connection_handle_response_end_state(r, con);
			break;
		case CON_STATE_CLOSE:
			connection_handle_close_state(con);
			break;
		case CON_STATE_CONNECT:
			break;
		default:
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "unknown state: %d %d", con->fd, r->state);
			break;
		}
	} while (ostate != (request_state_t)r->state);

	if (log_state_handling) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "state at exit: %d %s", con->fd, connection_get_state(r->state));
	}

	rc = 0;
	switch(r->state) {
	case CON_STATE_READ:
		rc = FDEVENT_IN | FDEVENT_RDHUP;
		break;
	case CON_STATE_WRITE:
		/* request write-fdevent only if we really need it
		 * - if we have data to write
		 * - if the socket is not writable yet
		 */
		if (!chunkqueue_is_empty(con->write_queue) &&
		    (con->is_writable == 0) &&
		    (con->traffic_limit_reached == 0)) {
			rc |= FDEVENT_OUT;
		}
		/* fall through */
	case CON_STATE_READ_POST:
		if (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN) {
			rc |= FDEVENT_IN | FDEVENT_RDHUP;
		}
		break;
	case CON_STATE_CLOSE:
		rc = FDEVENT_IN;
		break;
	default:
		break;
	}
	if (con->fd >= 0) {
		const int events = fdevent_fdnode_interest(con->fdn);
		if (con->is_readable < 0) {
			con->is_readable = 0;
			rc |= FDEVENT_IN;
		}
		if (con->is_writable < 0) {
			con->is_writable = 0;
			rc |= FDEVENT_OUT;
		}
		if (events & FDEVENT_RDHUP) {
			rc |= FDEVENT_RDHUP;
		}
		if (rc != events) {
			/* update timestamps when enabling interest in events */
			if ((rc & FDEVENT_IN) && !(events & FDEVENT_IN)) {
				con->read_idle_ts = log_epoch_secs;
			}
			if ((rc & FDEVENT_OUT) && !(events & FDEVENT_OUT)) {
				con->write_request_ts = log_epoch_secs;
			}
			fdevent_fdnode_event_set(con->srv->ev, con->fdn, rc);
		}
	}

	return 0;
}

static void connection_check_timeout (connection * const con, const time_t cur_ts) {
    const int waitevents = fdevent_fdnode_interest(con->fdn);
    int changed = 0;
    int t_diff;

    request_st * const r = &con->request;
    if (r->state == CON_STATE_CLOSE) {
        if (cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT) {
            changed = 1;
        }
    } else if (waitevents & FDEVENT_IN) {
        if (con->request_count == 1 || r->state != CON_STATE_READ) {
            /* e.g. CON_STATE_READ_POST || CON_STATE_WRITE */
            if (cur_ts - con->read_idle_ts > r->conf.max_read_idle) {
                /* time - out */
                if (r->conf.log_request_handling) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                              "connection closed - read timeout: %d", con->fd);
                }

                connection_set_state(r, CON_STATE_ERROR);
                changed = 1;
            }
        } else {
            if (cur_ts - con->read_idle_ts > con->keep_alive_idle) {
                /* time - out */
                if (r->conf.log_request_handling) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                              "connection closed - keep-alive timeout: %d",
                              con->fd);
                }

                connection_set_state(r, CON_STATE_ERROR);
                changed = 1;
            }
        }
    }

    /* max_write_idle timeout currently functions as backend timeout,
     * too, after response has been started.
     * future: have separate backend timeout, and then change this
     * to check for write interest before checking for timeout */
    /*if (waitevents & FDEVENT_OUT)*/
    if ((r->state == CON_STATE_WRITE) &&
        (con->write_request_ts != 0)) {
      #if 0
        if (cur_ts - con->write_request_ts > 60) {
            log_error(r->conf.errh, __FILE__, __LINE__,
                      "connection closed - pre-write-request-timeout: %d %d",
                      con->fd, cur_ts - con->write_request_ts);
        }
      #endif

        if (cur_ts - con->write_request_ts > r->conf.max_write_idle) {
            /* time - out */
            if (r->conf.log_timeouts) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "NOTE: a request from %.*s for %.*s timed out after writing "
                  "%zd bytes. We waited %d seconds.  If this is a problem, "
                  "increase server.max-write-idle",
                  BUFFER_INTLEN_PTR(con->dst_addr_buf),
                  BUFFER_INTLEN_PTR(&r->target),
                  con->bytes_written, (int)r->conf.max_write_idle);
            }
            connection_set_state(r, CON_STATE_ERROR);
            changed = 1;
        }
    }

    if (0 == (t_diff = cur_ts - con->connection_start)) t_diff = 1;

    if (con->traffic_limit_reached &&
        (r->conf.bytes_per_second == 0 ||
         con->bytes_written < (off_t)r->conf.bytes_per_second * t_diff)) {
        /* enable connection again */
        con->traffic_limit_reached = 0;

        changed = 1;
    }

    con->bytes_written_cur_second = 0;

    if (changed) {
        connection_state_machine(con);
    }
}

void connection_periodic_maint (server * const srv, const time_t cur_ts) {
    /* check all connections for timeouts */
    connections * const conns = &srv->conns;
    for (size_t ndx = 0; ndx < conns->used; ++ndx) {
        connection_check_timeout(conns->ptr[ndx], cur_ts);
    }
}

void connection_graceful_shutdown_maint (server *srv) {
    connections * const conns = &srv->conns;
    for (size_t ndx = 0; ndx < conns->used; ++ndx) {
        connection * const con = conns->ptr[ndx];
        int changed = 0;

        request_st * const r = &con->request;
        if (r->state == CON_STATE_CLOSE) {
            /* reduce remaining linger timeout to be
             * (from zero) *up to* one more second, but no more */
            if (HTTP_LINGER_TIMEOUT > 1)
                con->close_timeout_ts -= (HTTP_LINGER_TIMEOUT - 1);
            if (log_epoch_secs - con->close_timeout_ts > HTTP_LINGER_TIMEOUT)
                changed = 1;
        }
        else if (r->state == CON_STATE_READ && con->request_count > 1
                 && chunkqueue_is_empty(con->read_queue)) {
            /* close connections in keep-alive waiting for next request */
            connection_set_state(r, CON_STATE_ERROR);
            changed = 1;
        }

        r->keep_alive = 0;            /* disable keep-alive */

        r->conf.bytes_per_second = 0;         /* disable rate limit */
        r->conf.global_bytes_per_second = 0;  /* disable rate limit */
        if (con->traffic_limit_reached) {
            con->traffic_limit_reached = 0;
            changed = 1;
        }

        if (changed) {
            connection_state_machine(con);
        }
    }
}
