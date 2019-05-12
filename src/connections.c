#include "first.h"

#include "base.h"
#include "buffer.h"
#include "burl.h"       /* HTTP_PARSEOPT_HEADER_STRICT */
#include "log.h"
#include "connections.h"
#include "fdevent.h"
#include "http_header.h"

#include "configfile.h"
#include "request.h"
#include "response.h"
#include "network.h"
#include "http_chunk.h"
#include "stat_cache.h"
#include "joblist.h"

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

typedef struct {
	        PLUGIN_DATA;
} plugin_data;

__attribute_cold__
static connection *connection_init(server *srv);

static int connection_reset(server *srv, connection *con);


static connection *connections_get_new_connection(server *srv) {
	connections *conns = srv->conns;
	size_t i;

	if (conns->size == conns->used) {
		conns->size += srv->max_conns >= 128 ? 128 : srv->max_conns > 16 ? 16 : srv->max_conns;
		conns->ptr = realloc(conns->ptr, sizeof(*conns->ptr) * conns->size);
		force_assert(NULL != conns->ptr);

		for (i = conns->used; i < conns->size; i++) {
			conns->ptr[i] = connection_init(srv);
			connection_reset(srv, conns->ptr[i]);
		}
	}

	conns->ptr[conns->used]->ndx = conns->used;
	return conns->ptr[conns->used++];
}

static int connection_del(server *srv, connection *con) {
	size_t i;
	connections *conns = srv->conns;
	connection *temp;

	if (con == NULL) return -1;

	if (-1 == con->ndx) return -1;

	buffer_clear(con->uri.authority);
	buffer_reset(con->uri.path);
	buffer_reset(con->uri.query);
	buffer_reset(con->request.orig_uri);

	i = con->ndx;

	/* not last element */

	if (i != conns->used - 1) {
		temp = conns->ptr[i];
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

static int connection_close(server *srv, connection *con) {
	if (con->fd < 0) con->fd = -con->fd;

	plugins_call_handle_connection_close(srv, con);

	con->request_count = 0;
	chunkqueue_reset(con->read_queue);

	fdevent_fdnode_event_del(srv->ev, con->fdn);
	fdevent_unregister(srv->ev, con->fd);
	con->fdn = NULL;
#ifdef __WIN32
	if (closesocket(con->fd)) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"(warning) close:", con->fd, strerror(errno));
	}
#else
	if (close(con->fd)) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"(warning) close:", con->fd, strerror(errno));
	}
#endif
	else {
		srv->cur_fds--;
	}

	if (srv->srvconf.log_state_handling) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"connection closed for fd", con->fd);
	}
	con->fd = -1;
	con->is_ssl_sock = 0;

	/* plugins should have cleaned themselves up */
	for (size_t i = 0; i < srv->plugins.used; ++i) {
		plugin *p = ((plugin **)(srv->plugins.ptr))[i];
		plugin_data *pd = p->data;
		if (!pd || NULL == con->plugin_ctx[pd->id]) continue;
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"missing cleanup in", p->name);
		con->plugin_ctx[pd->id] = NULL;
	}

	connection_del(srv, con);
	connection_set_state(srv, con, CON_STATE_CONNECT);

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
	if (con->network_read(srv, con, con->read_queue, MAX_READ_LIMIT) < 0)
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
	plugins_call_handle_connection_shut_wr(srv, con);

	srv->con_closed++;
	connection_reset(srv, con);

	/* close the connection */
	if (con->fd >= 0
	    && (con->is_ssl_sock || 0 == shutdown(con->fd, SHUT_WR))) {
		con->close_timeout_ts = srv->cur_ts;
		connection_set_state(srv, con, CON_STATE_CLOSE);

		if (srv->srvconf.log_state_handling) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"shutdown for fd", con->fd);
		}
	} else {
		connection_close(srv, con);
	}
}

static void connection_handle_response_end_state(server *srv, connection *con) {
        /* log the request */
        /* (even if error, connection dropped, still write to access log if http_status) */
	if (con->http_status) {
		plugins_call_handle_request_done(srv, con);
	}

	if (con->state != CON_STATE_ERROR) srv->con_written++;

	if (con->request.content_length != con->request_content_queue->bytes_in
	    || con->state == CON_STATE_ERROR) {
		/* request body is present and has not been read completely */
		con->keep_alive = 0;
	}

        if (con->keep_alive) {
		connection_reset(srv, con);
#if 0
		con->request_start = srv->cur_ts;
		con->read_idle_ts = srv->cur_ts;
#endif
		connection_set_state(srv, con, CON_STATE_REQUEST_START);
	} else {
		connection_handle_shutdown(srv, con);
	}
}

static void connection_handle_errdoc_init(connection *con) {
	/* modules that produce headers required with error response should
	 * typically also produce an error document.  Make an exception for
	 * mod_auth WWW-Authenticate response header. */
	buffer *www_auth = NULL;
	if (401 == con->http_status) {
		buffer *vb = http_header_response_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"));
		if (NULL != vb) www_auth = buffer_init_buffer(vb);
	}

	buffer_reset(con->physical.path);
	con->response.htags = 0;
	array_reset_data_strings(con->response.headers);
	http_response_body_clear(con, 0);

	if (NULL != www_auth) {
		http_header_response_set(con, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(www_auth));
		buffer_free(www_auth);
	}
}

static int connection_handle_write_prepare(server *srv, connection *con) {
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
		if (con->http_status < 400 || con->http_status >= 600) break;

		if (con->mode != DIRECT && (!con->conf.error_intercept || con->error_handler_saved_status)) break;
		if (con->mode == DIRECT && con->error_handler_saved_status >= 65535) break;

		con->file_finished = 0;

		connection_handle_errdoc_init(con);

		/* try to send static errorfile */
		if (!buffer_string_is_empty(con->conf.errorfile_prefix)) {
			stat_cache_entry *sce = NULL;

			buffer_copy_buffer(con->physical.path, con->conf.errorfile_prefix);
			buffer_append_int(con->physical.path, con->http_status);
			buffer_append_string_len(con->physical.path, CONST_STR_LEN(".html"));

			if (0 == http_chunk_append_file(srv, con, con->physical.path)) {
				con->file_finished = 1;
				if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
					stat_cache_content_type_get(srv, con, con->physical.path, sce);
					http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(sce->content_type));
				}
			}
		}

		if (!con->file_finished) {
			buffer *b = srv->tmp_buf;

			buffer_reset(con->physical.path);

			con->file_finished = 1;

			/* build default error-page */
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

			buffer_append_string_len(b, CONST_STR_LEN("</h1>\n"
					     " </body>\n"
					     "</html>\n"
					     ));

			(void)http_chunk_append_mem(srv, con, CONST_BUF_LEN(b));

			http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
		}
		break;
	}

	/* Allow filter plugins to change response headers before they are written. */
	switch(plugins_call_handle_response_start(srv, con)) {
	case HANDLER_GO_ON:
	case HANDLER_FINISHED:
		break;
	default:
		log_error_write(srv, __FILE__, __LINE__, "s", "response_start plugin failed");
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
				buffer_copy_int(srv->tmp_buf, qlen);
				http_header_response_set(con, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"), CONST_BUF_LEN(srv->tmp_buf));
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

	http_response_write_header(srv, con);

	return 0;
}

static void connection_handle_write(server *srv, connection *con) {
	switch(connection_write_chunkqueue(srv, con, con->write_queue, MAX_WRITE_LIMIT)) {
	case 0:
		con->write_request_ts = srv->cur_ts;
		if (con->file_finished) {
			connection_set_state(srv, con, CON_STATE_RESPONSE_END);
		}
		break;
	case -1: /* error on our side */
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"connection closed: write failed on fd", con->fd);
		connection_set_state(srv, con, CON_STATE_ERROR);
		break;
	case -2: /* remote close */
		connection_set_state(srv, con, CON_STATE_ERROR);
		break;
	case 1:
		con->write_request_ts = srv->cur_ts;
		con->is_writable = 0;

		/* not finished yet -> WRITE */
		break;
	}
}

static void connection_handle_write_state(server *srv, connection *con) {
    do {
        /* only try to write if we have something in the queue */
        if (!chunkqueue_is_empty(con->write_queue)) {
            if (con->is_writable) {
                connection_handle_write(srv, con);
                if (con->state != CON_STATE_WRITE) break;
            }
        } else if (con->file_finished) {
            connection_set_state(srv, con, CON_STATE_RESPONSE_END);
            break;
        }

        if (con->mode != DIRECT && !con->file_finished) {
            int r = plugins_call_handle_subrequest(srv, con);
            switch(r) {
            case HANDLER_WAIT_FOR_EVENT:
            case HANDLER_FINISHED:
            case HANDLER_GO_ON:
                break;
            case HANDLER_WAIT_FOR_FD:
                srv->want_fds++;
                fdwaitqueue_append(srv, con);
                break;
            case HANDLER_COMEBACK:
            default:
                log_error_write(srv, __FILE__, __LINE__, "sdd",
                                "unexpected subrequest handler ret-value:",
                                con->fd, r);
                /* fall through */
            case HANDLER_ERROR:
                connection_set_state(srv, con, CON_STATE_ERROR);
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

	UNUSED(srv);

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

	CLEAN(server_name);
	CLEAN(proto);
	CLEAN(dst_addr_buf);

#undef CLEAN
	con->write_queue = chunkqueue_init();
	con->read_queue = chunkqueue_init();
	con->request_content_queue = chunkqueue_init();

	con->request.headers      = array_init();
	con->response.headers     = array_init();
	con->environment     = array_init();

	/* init plugin specific connection structures */

	con->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));
	force_assert(NULL != con->plugin_ctx);

	con->cond_cache = calloc(srv->config_context->used, sizeof(cond_cache_t));
	force_assert(NULL != con->cond_cache);
	config_setup_connection(srv, con);

	return con;
}

void connections_free(server *srv) {
	connections *conns = srv->conns;
	size_t i;

	if (NULL == conns) return;

	for (i = 0; i < conns->size; i++) {
		connection *con = conns->ptr[i];

		connection_reset(srv, con);

		chunkqueue_free(con->write_queue);
		chunkqueue_free(con->read_queue);
		chunkqueue_free(con->request_content_queue);
		array_free(con->request.headers);
		array_free(con->response.headers);
		array_free(con->environment);

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

		CLEAN(server_name);
		CLEAN(proto);
		CLEAN(dst_addr_buf);
#undef CLEAN
		free(con->plugin_ctx);
		free(con->cond_cache);

		free(con);
	}

	free(conns->ptr);
	free(conns);
	srv->conns = NULL;
}


static int connection_reset(server *srv, connection *con) {
	plugins_call_connection_reset(srv, con);

	connection_response_reset(srv, con);
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
	buffer_clear(con->server_name);

	con->request.http_host = NULL;
	con->request.content_length = 0;
	con->request.te_chunked = 0;
	con->request.htags = 0;

	array_reset_data_strings(con->request.headers);
	array_reset_data_strings(con->environment);

	chunkqueue_reset(con->request_content_queue);

	/* The cond_cache gets reset in response.c */
	/* config_cond_cache_reset(srv, con); */

	con->header_len = 0;
	con->async_callback = 0;
	con->error_handler_saved_status = 0;
	/*con->error_handler_saved_method = HTTP_METHOD_UNSET;*/
	/*(error_handler_saved_method value is not valid unless error_handler_saved_status is set)*/

	config_setup_connection(srv, con);

	return 0;
}

static void connection_read_header(server *srv, connection *con)  {
    chunkqueue * const cq = con->read_queue;
    chunk *c;
    size_t hlen = 0;
    int le = 0;
    buffer *save = NULL;

    for (c = cq->first; c; c = c->next) {
        size_t clen = buffer_string_length(c->mem) - c->offset;
        const char * const b = c->mem->ptr + c->offset;
        const char *n = b;
        if (0 == clen) continue;
        if (le) { /*(line end sequence cross chunk boundary)*/
            if (n[0] == '\r')   ++n;
            if (n[0] == '\n') { ++n; hlen += n - b; break; }
            if (n[0] == '\0') { hlen += n - b; continue; }
            le = 0;
        }
        for (const char * const end = b+clen; (n = memchr(n,'\n',end-n)); ++n) {
            if (n[1] == '\r')   ++n;
            if (n[1] == '\n') { hlen += n - b + 2; break; }
            if (n[1] == '\0') { n = NULL; le = 1; break; }
        }
        if (n) break;
        hlen += clen;
    }

    if (hlen > srv->srvconf.max_request_field_size) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "oversized request-header -> sending Status 431");
        con->http_status = 431; /* Request Header Fields Too Large */
        con->keep_alive = 0;
        connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
    }

    if (NULL == c) return; /* incomplete request headers */

    con->header_len = hlen;

    buffer_clear(con->request.request);

    for (c = cq->first; c; c = c->next) {
        size_t len = buffer_string_length(c->mem) - c->offset;
        if (len > hlen) len = hlen;
        buffer_append_string_len(con->request.request,
                                 c->mem->ptr + c->offset, len);
        if (0 == (hlen -= len)) break;
    }

    chunkqueue_mark_written(cq, con->header_len);

    /* skip past \r\n or \n after previous POST request when keep-alive */
    if (con->request_count > 1) {
        char * const s = con->request.request->ptr;
      #ifdef __COVERITY__
        if (buffer_string_length(con->request.request) < 2) {
            return;
        }
      #endif
        if (s[0] == '\r' && s[1] == '\n') {
            size_t len = buffer_string_length(con->request.request);
            memmove(s, s+2, len-2);
            buffer_string_set_length(con->request.request, len-2);
        }
        else if (s[0] == '\n') {
            if (!(con->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT)) {
                size_t len = buffer_string_length(con->request.request);
                memmove(s, s+1, len-1);
                buffer_string_set_length(con->request.request, len-1);
            }
        }
    }

    if (con->conf.log_request_header) {
        log_error_write(srv, __FILE__, __LINE__, "sdsdSb",
          "fd:", con->fd,
          "request-len:", buffer_string_length(con->request.request),
          "\n", con->request.request);
    }

    buffer_clear(con->uri.authority);
    buffer_reset(con->uri.path);
    buffer_reset(con->uri.query);
    buffer_reset(con->request.orig_uri);

    if (srv->srvconf.log_request_header_on_error) {
        /* copy request only if we may need to log it upon error */
        save = buffer_init_buffer(con->request.request);
    }

    con->http_status = http_request_parse(srv, con, con->request.request);
    if (0 != con->http_status) {
        con->keep_alive = 0;
        con->request.content_length = 0;

        if (srv->srvconf.log_request_header_on_error) {
            log_error_write(srv, __FILE__, __LINE__, "Sb",
                            "request-header:\n", save);
        }
    }

    if (NULL != save) buffer_free(save);
    buffer_reset(con->request.request);

    connection_set_state(srv, con, CON_STATE_REQUEST_END);
}

/**
 * handle request header read
 *
 * we get called by the state-engine and by the fdevent-handler
 */
static int connection_handle_read_state(server *srv, connection *con)  {
	int is_closed = 0; /* the connection got closed, if we don't have a complete header, -> error */

	if (con->request_count > 1 && 0 == con->bytes_read) {

		/* update request_start timestamp when first byte of
		 * next request is received on a keep-alive connection */
		con->request_start = srv->cur_ts;
		if (con->conf.high_precision_timestamps)
			log_clock_gettime_realtime(&con->request_start_hp);

		if (!chunkqueue_is_empty(con->read_queue)) {
			/*(if partially read next request and unable to read() any bytes below,
			 * then will unnecessarily scan again here before subsequent read())*/
			connection_read_header(srv, con);
			if (con->state != CON_STATE_READ) {
				con->read_idle_ts = srv->cur_ts;
				return 0;
			}
		}
	}

	if (con->is_readable) {
		con->read_idle_ts = srv->cur_ts;

		switch (con->network_read(srv, con, con->read_queue, MAX_READ_LIMIT)) {
		case -1:
			connection_set_state(srv, con, CON_STATE_ERROR);
			return -1;
		case -2:
			is_closed = 1;
			break;
		default:
			break;
		}
	}

	connection_read_header(srv, con);

	if (con->state == CON_STATE_READ && is_closed) {
		/* the connection got closed and we didn't got enough data to leave CON_STATE_READ;
		 * the only way is to leave here */
		connection_set_state(srv, con, CON_STATE_ERROR);
	}

	return 0;
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
		connection_handle_write(srv, con);
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
			connection_set_state(srv, con, CON_STATE_ERROR);
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
				connection_set_state(srv, con, CON_STATE_ERROR);
			}
		} else if (revents & FDEVENT_ERR) { /* error, connection reset */
			connection_set_state(srv, con, CON_STATE_ERROR);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"connection closed: poll() -> ???", revents);
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

	if (srv->conns->used >= srv->max_conns) {
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
			log_error_write(srv, __FILE__, __LINE__, "ssd", "accept failed:", strerror(errno), errno);
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
static int connection_read_cq(server *srv, connection *con, chunkqueue *cq, off_t max_bytes) {
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
				log_error_write(srv, __FILE__, __LINE__, "sd", "connection closed - recv failed: ", lastError);
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
			log_error_write(srv, __FILE__, __LINE__, "ssd", "connection closed - read failed: ", strerror(errno), errno);
			break;
		}
#endif /* __WIN32 */

		connection_set_state(srv, con, CON_STATE_ERROR);

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


static int connection_write_cq(server *srv, connection *con, chunkqueue *cq, off_t max_bytes) {
	return srv->network_backend_write(srv, con->fd, cq, max_bytes);
}


connection *connection_accepted(server *srv, server_socket *srv_socket, sock_addr *cnt_addr, int cnt) {
		connection *con;

		srv->cur_fds++;

		/* ok, we have the connection, register it */
#if 0
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"appected()", cnt);
#endif
		srv->con_opened++;

		con = connections_get_new_connection(srv);
		con->errh = srv->errh;

		con->fd = cnt;
		con->fdn = fdevent_register(srv->ev, con->fd, connection_handle_fdevent, con);
		con->network_read = connection_read_cq;
		con->network_write = connection_write_cq;

		connection_set_state(srv, con, CON_STATE_REQUEST_START);

		con->connection_start = srv->cur_ts;
		con->dst_addr = *cnt_addr;
		buffer_copy_string(con->dst_addr_buf, inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
		con->srv_socket = srv_socket;
		con->is_ssl_sock = srv_socket->is_ssl;

		config_cond_cache_reset(srv, con);
		con->conditional_is_valid[COMP_SERVER_SOCKET] = 1;
		con->conditional_is_valid[COMP_HTTP_REMOTE_IP] = 1;

		buffer_copy_string_len(con->proto, CONST_STR_LEN("http"));
		if (HANDLER_GO_ON != plugins_call_handle_connection_accept(srv, con)) {
			connection_reset(srv, con);
			connection_close(srv, con);
			return NULL;
		}
		if (con->http_status < 0) connection_set_state(srv, con, CON_STATE_WRITE);
		return con;
}


static int connection_handle_request(server *srv, connection *con) {
			int r = http_response_prepare(srv, con);
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
						buffer *error_handler = NULL;
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
							buffer_copy_int(srv->tmp_buf, con->http_status);
							http_header_env_set(con, CONST_STR_LEN("REDIRECT_STATUS"), CONST_BUF_LEN(srv->tmp_buf));

							if (error_handler == con->conf.error_handler) {
								plugins_call_connection_reset(srv, con);

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
				connection_set_state(srv, con, CON_STATE_RESPONSE_START);
				break;
			case HANDLER_WAIT_FOR_FD:
				srv->want_fds++;

				fdwaitqueue_append(srv, con);

				break;
			case HANDLER_COMEBACK:
				return 1;
			case HANDLER_ERROR:
				/* something went wrong */
				connection_set_state(srv, con, CON_STATE_ERROR);
				break;
			default:
				log_error_write(srv, __FILE__, __LINE__, "sdd", "unknown ret-value: ", con->fd, r);
				break;
			}

			return 0;
}


int connection_state_machine(server *srv, connection *con) {
	connection_state_t ostate;
	int r;
	const int log_state_handling = srv->srvconf.log_state_handling;

	if (log_state_handling) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"state at enter",
				con->fd,
				connection_get_state(con->state));
	}

	do {
		if (log_state_handling) {
			log_error_write(srv, __FILE__, __LINE__, "sds",
					"state for fd", con->fd, connection_get_state(con->state));
		}

		switch ((ostate = con->state)) {
		case CON_STATE_REQUEST_START: /* transient */
			con->request_start = srv->cur_ts;
			con->read_idle_ts = srv->cur_ts;
			if (con->conf.high_precision_timestamps)
				log_clock_gettime_realtime(&con->request_start_hp);

			con->request_count++;
			con->loops_per_request = 0;

			connection_set_state(srv, con, CON_STATE_READ);
			/* fall through */
		case CON_STATE_READ:
			connection_handle_read_state(srv, con);
			if (con->state != CON_STATE_REQUEST_END) break;
			/* fall through */
		case CON_STATE_REQUEST_END: /* transient */
			ostate = (0 == con->request.content_length)
			  ? CON_STATE_HANDLE_REQUEST
			  : CON_STATE_READ_POST;
			connection_set_state(srv, con, ostate);
			/* fall through */
		case CON_STATE_READ_POST:
		case CON_STATE_HANDLE_REQUEST:
			if (connection_handle_request(srv, con)) {
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
			if (-1 == connection_handle_write_prepare(srv, con)) {
				connection_set_state(srv, con, CON_STATE_ERROR);
				break;
			}
			connection_set_state(srv, con, CON_STATE_WRITE);
			/* fall through */
		case CON_STATE_WRITE:
			connection_handle_write_state(srv, con);
			if (con->state != CON_STATE_RESPONSE_END) break;
			/* fall through */
		case CON_STATE_RESPONSE_END: /* transient */
		case CON_STATE_ERROR:        /* transient */
			connection_handle_response_end_state(srv, con);
			break;
		case CON_STATE_CLOSE:
			connection_handle_close_state(srv, con);
			break;
		case CON_STATE_CONNECT:
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sdd",
					"unknown state:", con->fd, con->state);
			break;
		}
	} while (ostate != con->state);

	if (log_state_handling) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"state at exit:",
				con->fd,
				connection_get_state(con->state));
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
