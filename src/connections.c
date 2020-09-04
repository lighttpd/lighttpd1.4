#include "first.h"

#include "base.h"
#include "buffer.h"
#include "burl.h"       /* HTTP_PARSEOPT_HEADER_STRICT */
#include "chunk.h"
#include "log.h"
#include "connections.h"
#include "fdevent.h"
#include "h2.h"
#include "http_header.h"

#include "reqpool.h"
#include "request.h"
#include "response.h"
#include "network.h"
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
static void connection_set_state_error(request_st * const r, const request_state_t state) {
    connection_set_state(r, state);
}

__attribute_cold__
static connection *connection_init(server *srv);

static void connection_reset(connection *con);


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

static void connection_close(connection *con) {
	if (con->fd < 0) con->fd = -con->fd;

	plugins_call_handle_connection_close(con);

	server * const srv = con->srv;
	request_st * const r = &con->request;
	request_reset_ex(r); /*(r->conf.* is still valid below)*/
	connection_set_state(r, CON_STATE_CONNECT);

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
	if (r->http_version > HTTP_VERSION_1_1) {
		h2_retire_con(r, con);
		r->keep_alive = 0;
		/* set a status so that mod_accesslog, mod_rrdtool hooks are called
		 * in plugins_call_handle_request_done() (XXX: or set to 0 to omit) */
		r->http_status = 100; /* XXX: what if con->state == CON_STATE_ERROR? */
	}

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
		request_reset(r);
		config_reset_config(r);
		con->is_readable = 1; /* potentially trigger optimistic read */
		/*(accounting used by mod_accesslog for HTTP/1.0 and HTTP/1.1)*/
		r->bytes_read_ckpt = con->bytes_read;
		r->bytes_written_ckpt = con->bytes_written;
#if 0
		r->start_ts = con->read_idle_ts = log_epoch_secs;
#endif
		connection_set_state(r, CON_STATE_REQUEST_START);
	} else {
		connection_handle_shutdown(con);
	}
}

static off_t
connection_write_throttle (connection * const con, off_t max_bytes)
{
    request_st * const r = &con->request;
    if (r->conf.global_bytes_per_second) {
        off_t limit = (off_t)r->conf.global_bytes_per_second
                    - *(r->conf.global_bytes_per_second_cnt_ptr);
        if (limit <= 0) {
            /* we reached the global traffic limit */
            con->traffic_limit_reached = 1;
            return 0;
        }
        else if (max_bytes > limit)
            max_bytes = limit;
    }

    if (r->conf.bytes_per_second) {
        off_t limit = (off_t)r->conf.bytes_per_second
                    - con->bytes_written_cur_second;
        if (limit <= 0) {
            /* we reached the traffic limit */
            con->traffic_limit_reached = 1;
            return 0;
        }
        else if (max_bytes > limit)
            max_bytes = limit;
    }

    return max_bytes;
}


static int
connection_write_chunkqueue (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    con->write_request_ts = log_epoch_secs;

    max_bytes = connection_write_throttle(con, max_bytes);
    if (0 == max_bytes) return 1;

    off_t written = cq->bytes_out;
    int ret;

  #ifdef TCP_CORK
    /* Linux: put a cork into socket as we want to combine write() calls
     * but only if we really have multiple chunks including non-MEM_CHUNK,
     * and only if TCP socket
     */
    int corked = 0;
    if (cq->first && cq->first->next) {
        const int sa_family = sock_addr_get_family(&con->srv_socket->addr);
        if (sa_family == AF_INET || sa_family == AF_INET6) {
            chunk *c = cq->first;
            while (c->type == MEM_CHUNK && NULL != (c = c->next)) ;
            if (NULL != c) {
                corked = 1;
                (void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK,
                                 &corked, sizeof(corked));
            }
        }
    }
  #endif

    ret = con->network_write(con, cq, max_bytes);
    if (ret >= 0) {
        ret = chunkqueue_is_empty(cq) ? 0 : 1;
    }

  #ifdef TCP_CORK
    if (corked) {
        corked = 0;
        (void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK,
                         &corked, sizeof(corked));
    }
  #endif

    written = cq->bytes_out - written;
    con->bytes_written += written;
    con->bytes_written_cur_second += written;
    request_st * const r = &con->request;
    if (r->conf.global_bytes_per_second_cnt_ptr)
        *(r->conf.global_bytes_per_second_cnt_ptr) += written;

    return ret;
}


static int
connection_write_100_continue (request_st * const r, connection * const con)
{
    /* Make best effort to send all or none of "HTTP/1.1 100 Continue" */
    /* (Note: also choosing not to update con->write_request_ts
     *  which differs from connection_write_chunkqueue()) */
    static const char http_100_continue[] = "HTTP/1.1 100 Continue\r\n\r\n";

    if (con->traffic_limit_reached)
        return 1; /* success; skip sending if throttled */

    chunkqueue * const cq = r->write_queue;
    off_t written = cq->bytes_out;

    chunkqueue_append_mem(cq,http_100_continue,sizeof(http_100_continue)-1);
    int rc = con->network_write(con, cq, sizeof(http_100_continue)-1);

    written = cq->bytes_out - written;
    con->bytes_written += written;
    con->bytes_written_cur_second += written;
    if (r->conf.global_bytes_per_second_cnt_ptr)
        *(r->conf.global_bytes_per_second_cnt_ptr) += written;

    if (rc < 0) {
        connection_set_state_error(r, CON_STATE_ERROR);
        return 0; /* error */
    }

    if (0 == written) {
        /* skip sending 100 Continue if send would block */
        chunkqueue_mark_written(cq, sizeof(http_100_continue)-1);
        con->is_writable = 0;
    }
    /* else partial write (unlikely), which can cause corrupt
     * response if response is later cleared, e.g. sending errdoc.
     * However, situation of partial write can occur here only on
     * keep-alive request where client has sent pipelined request,
     * and more than 0 chars were written, but fewer than 25 chars */

    return 1; /* success; sent all or none of "HTTP/1.1 100 Continue" */
}


static void connection_handle_write(request_st * const r, connection * const con) {
	int rc = connection_write_chunkqueue(con, con->write_queue, MAX_WRITE_LIMIT);
	switch (rc) {
	case 0:
		if (r->resp_body_finished) {
			connection_set_state(r, CON_STATE_RESPONSE_END);
		}
		break;
	case -1: /* error on our side */
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "connection closed: write failed on fd %d", con->fd);
		connection_set_state_error(r, CON_STATE_ERROR);
		break;
	case -2: /* remote close */
		connection_set_state_error(r, CON_STATE_ERROR);
		break;
	case 1:
		/* do not spin trying to send HTTP/2 server Connection Preface
		 * while waiting for TLS negotiation to complete */
		if (con->write_queue->bytes_out)
			con->is_writable = 0;

		/* not finished yet -> WRITE */
		break;
	}
}

static void connection_handle_write_state(request_st * const r, connection * const con) {
    do {
        /* only try to write if we have something in the queue */
        if (!chunkqueue_is_empty(r->write_queue)) {
            if (r->http_version <= HTTP_VERSION_1_1 && con->is_writable) {
                /*(r->write_queue == con->write_queue)*//*(not HTTP/2 stream)*/
                connection_handle_write(r, con);
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
                /* (In addition to waiting for dispatch from fdwaitqueue,
                 *  HTTP/2 connections may retry more frequently after any
                 *  activity occurs on connection or on other streams) */
                connection_fdwaitqueue_append(con);
                break;
            case HANDLER_COMEBACK:
            default:
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "unexpected subrequest handler ret-value: %d %d",
                  con->fd, rc);
                /* fall through */
            case HANDLER_ERROR:
                connection_set_state_error(r, CON_STATE_ERROR);
                break;
            }
        }
    } while (r->state == CON_STATE_WRITE
             && r->http_version <= HTTP_VERSION_1_1
             && (!chunkqueue_is_empty(r->write_queue)
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
	request_init_data(r, con, srv);
	config_reset_config(r);
	con->write_queue = r->write_queue;
	con->read_queue = r->read_queue;

	/* init plugin-specific per-connection structures */
	con->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));
	force_assert(NULL != con->plugin_ctx);

	return con;
}


void connections_free(server *srv) {
	connections * const conns = &srv->conns;
	for (uint32_t i = 0; i < conns->size; ++i) {
		connection *con = conns->ptr[i];
		request_st * const r = &con->request;

		connection_reset(con);
		if (con->write_queue != r->write_queue)
			chunkqueue_free(con->write_queue);
		if (con->read_queue != r->read_queue)
			chunkqueue_free(con->read_queue);
		request_free_data(r);

		free(con->plugin_ctx);
		buffer_free(con->dst_addr_buf);

		free(con);
	}

	free(conns->ptr);
	conns->ptr = NULL;
}


static void connection_reset(connection *con) {
	request_st * const r = &con->request;
	request_reset(r);
	config_reset_config(r);
	r->bytes_read_ckpt = 0;
	r->bytes_written_ckpt = 0;
	con->is_readable = 1;

	con->bytes_written = 0;
	con->bytes_written_cur_second = 0;
	con->bytes_read = 0;
}


__attribute_cold__
static chunk *
connection_discard_blank_line (chunkqueue * const cq, uint32_t header_len)
{
    /*(separate func only to be able to mark with compiler hint as cold)*/
    chunkqueue_mark_written(cq, header_len);
    return cq->first; /* refresh c after chunkqueue_mark_written() */
}


static chunk * connection_read_header_more(connection *con, chunkqueue *cq, chunk *c, const size_t olen) {
    /*(should not be reached by HTTP/2 streams)*/
    /*if (r->http_version == HTTP_VERSION_2) return NULL;*/
    /*(However, new connections over TLS may become HTTP/2 connections via ALPN
     * and return from this routine with r->http_version == HTTP_VERSION_2) */

    if ((NULL == c || NULL == c->next) && con->is_readable) {
        con->read_idle_ts = log_epoch_secs;
        if (0 != con->network_read(con, cq, MAX_READ_LIMIT)) {
            request_st * const r = &con->request;
            connection_set_state_error(r, CON_STATE_ERROR);
        }
        /* check if switched to HTTP/2 (ALPN "h2" during TLS negotiation) */
        request_st * const r = &con->request;
        if (r->http_version == HTTP_VERSION_2) return NULL;
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


static void
connection_transition_h2 (request_st * const h2r, connection * const con)
{
    buffer_copy_string_len(&h2r->target,      CONST_STR_LEN("*"));
    buffer_copy_string_len(&h2r->target_orig, CONST_STR_LEN("*"));
    buffer_copy_string_len(&h2r->uri.path,    CONST_STR_LEN("*"));
    h2r->http_method = HTTP_METHOD_PRI;
    h2r->reqbody_length = -1; /*(unnecessary for h2r?)*/
    h2r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;

    /* (h2r->state == CON_STATE_READ) for transition by ALPN
     *   or starting cleartext HTTP/2 with Prior Knowledge
     *   (e.g. via HTTP Alternative Services)
     * (h2r->state == CON_STATE_RESPONSE_END) for Upgrade: h2c */

    if (h2r->state != CON_STATE_ERROR)
        connection_set_state(h2r, CON_STATE_WRITE);

  #if 0 /* ... if it turns out we need a separate fdevent handler for HTTP/2 */
    con->fdn->handler = connection_handle_fdevent_h2;
  #endif

    if (NULL == con->h2) /*(not yet transitioned to HTTP/2; not Upgrade: h2c)*/
        h2_init_con(h2r, con, NULL);
}


/**
 * handle request header read
 *
 * we get called by the state-engine and by the fdevent-handler
 */
__attribute_noinline__
static int connection_handle_read_state(connection * const con)  {
    /*(should not be reached by HTTP/2 streams)*/
    chunkqueue * const cq = con->read_queue;
    chunk *c = cq->first;
    uint32_t clen = 0;
    uint32_t header_len = 0;
    request_st * const r = &con->request;
    uint8_t keepalive_request_start = 0;
    uint8_t pipelined_request_start = 0;
    uint8_t discard_blank = 0;
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */

    if (con->request_count > 1) {
        discard_blank = 1;
        if (con->bytes_read == r->bytes_read_ckpt) {
            keepalive_request_start = 1;
            if (NULL != c) { /* !chunkqueue_is_empty(cq)) */
                pipelined_request_start = 1;
                /* partial header of next request has already been read,
                 * so optimistically check for more data received on
                 * socket while processing the previous request */
                con->is_readable = 1;
                /*(if partially read next request and unable to read any bytes,
                 * then will unnecessarily scan again before subsequent read)*/
            }
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

        header_len = http_header_parse_hoff(c->mem->ptr + c->offset,clen,hoff);

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
            connection_set_state(r, CON_STATE_REQUEST_END);
            return 1;
        }

        if (0 != header_len) {
            if (hoff[0] > 1) break; /* common case; request headers complete */

            if (discard_blank) { /* skip one blank line e.g. following POST */
                if (header_len == clen) continue;
                const int ch = c->mem->ptr[c->offset+header_len];
                if (ch != '\r' && ch != '\n') {
                    /* discard prior blank line if next line is not blank */
                    discard_blank = 0;
                    clen = 0;/*(for connection_read_header_more() to return c)*/
                    c = connection_discard_blank_line(cq, header_len);/*cold*/
                    continue;
                } /*(else fall through to error out in next block)*/
            }
        }

        if (((unsigned char *)c->mem->ptr)[c->offset] < 32) {
            /* expecting ASCII method beginning with alpha char
             * or HTTP/2 pseudo-header beginning with ':' */
            /*(TLS handshake begins with SYN 0x16 (decimal 22))*/
            log_error(r->conf.errh, __FILE__, __LINE__, "%s",
                      "invalid request-line -> sending Status 400");
            r->http_status = 400; /* Bad Request */
            r->keep_alive = 0;
            connection_set_state(r, CON_STATE_REQUEST_END);
            return 1;
        }
    } while ((c = connection_read_header_more(con, cq, c, clen)));

    if (keepalive_request_start) {
        if (con->bytes_read > r->bytes_read_ckpt) {
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
        /* clear buffers which may have been kept for reporting on keep-alive,
         * (e.g. mod_status) */
        request_reset_ex(r);
    }
    /* RFC7540 3.5 HTTP/2 Connection Preface
     * "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
     * (Connection Preface MUST be exact match)
     * If ALT-SVC used to advertise HTTP/2, then client might start
     * http connection (not TLS) sending HTTP/2 connection preface.
     * (note: intentionally checking only on initial request) */
    else if (!con->is_ssl_sock && r->conf.h2proto
             && hoff[0] == 2 && hoff[2] == 16
             && hdrs[0]=='P' && hdrs[1]=='R' && hdrs[2]=='I' && hdrs[3]==' ') {
        r->http_version = HTTP_VERSION_2;
        return 0;
    }

    r->rqst_header_len = header_len;
    if (r->conf.log_request_header)
        log_error(r->conf.errh, __FILE__, __LINE__,
          "fd: %d request-len: %d\n%.*s", con->fd,
          (int)header_len, (int)header_len, hdrs);
    http_request_headers_process(r, hdrs, hoff, con->proto_default_port);
    chunkqueue_mark_written(cq, r->rqst_header_len);
    connection_set_state(r, CON_STATE_REQUEST_END);

    if (!con->is_ssl_sock && r->conf.h2proto && 0 == r->http_status
        && h2_check_con_upgrade_h2c(r)) {
        /*(Upgrade: h2c over cleartext does not have SNI; no COMP_HTTP_HOST)*/
        r->conditional_is_valid = (1 << COMP_SERVER_SOCKET)
                                | (1 << COMP_HTTP_REMOTE_IP);
        /*connection_handle_write(r, con);*//* defer write to network */
        return 0;
    }

    return 1;
}


static void connection_state_machine_h2 (request_st *r, connection *con);

static handler_t connection_handle_fdevent(void *context, int revents) {
	connection *con = context;

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

	if (r->http_version == HTTP_VERSION_2) {
		connection_state_machine_h2(r, con);
		if (-1 == con->fd) /*(con closed; CON_STATE_CONNECT)*/
			return HANDLER_FINISHED;
	}
	else {
		joblist_append(con);

		if (r->state == CON_STATE_READ) {
			if (!connection_handle_read_state(con)
			    && r->http_version == HTTP_VERSION_2)
				connection_transition_h2(r, con);
		}

		if (r->state == CON_STATE_WRITE &&
		    !chunkqueue_is_empty(con->write_queue) &&
		    con->is_writable) {
			connection_handle_write(r, con);
		}
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
			connection_set_state_error(r, CON_STATE_ERROR);
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
				connection_set_state_error(r, CON_STATE_ERROR);
			}
		} else if (revents & FDEVENT_ERR) { /* error, connection reset */
			connection_set_state_error(r, CON_STATE_ERROR);
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

    connection_set_state_error(r, CON_STATE_ERROR);
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


static handler_t connection_handle_read_post_state(request_st * const r);

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
		con->reqbody_read = connection_handle_read_post_state;

		request_st * const r = &con->request;
		connection_set_state(r, CON_STATE_REQUEST_START);

		con->connection_start = log_epoch_secs;
		con->dst_addr = *cnt_addr;
		buffer_copy_string(con->dst_addr_buf, inet_ntop_cache_get_ip(srv, &(con->dst_addr)));
		con->srv_socket = srv_socket;
		con->is_ssl_sock = srv_socket->is_ssl;
		con->proto_default_port = 80; /* "http" */

		config_cond_cache_reset(r);
		r->conditional_is_valid = (1 << COMP_SERVER_SOCKET)
		                        | (1 << COMP_HTTP_REMOTE_IP);

		if (HANDLER_GO_ON != plugins_call_handle_connection_accept(con)) {
			connection_reset(con);
			connection_close(con);
			return NULL;
		}
		if (r->http_status < 0) connection_set_state(r, CON_STATE_WRITE);
		return con;
}


__attribute_cold__
__attribute_noinline__
static const char *
connection_get_state (request_state_t state)
{
    switch (state) {
      case CON_STATE_CONNECT:        return "connect";
      case CON_STATE_READ:           return "read";
      case CON_STATE_READ_POST:      return "readpost";
      case CON_STATE_WRITE:          return "write";
      case CON_STATE_CLOSE:          return "close";
      case CON_STATE_ERROR:          return "error";
      case CON_STATE_HANDLE_REQUEST: return "handle-req";
      case CON_STATE_REQUEST_START:  return "req-start";
      case CON_STATE_REQUEST_END:    return "req-end";
      case CON_STATE_RESPONSE_START: return "resp-start";
      case CON_STATE_RESPONSE_END:   return "resp-end";
      default:                       return "(unknown)";
    }
}


static void
connection_state_machine_loop (request_st * const r, connection * const con)
{
	request_state_t ostate;
	do {
		if (r->conf.log_state_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "state for fd %d %s", con->fd, connection_get_state(r->state));
		}

		switch ((ostate = r->state)) {
		case CON_STATE_REQUEST_START: /* transient */
			/*(should not be reached by HTTP/2 streams)*/
			r->start_ts = con->read_idle_ts = log_epoch_secs;
			if (r->conf.high_precision_timestamps)
				log_clock_gettime_realtime(&r->start_hp);

			con->request_count++;
			r->loops_per_request = 0;

			connection_set_state(r, CON_STATE_READ);
			/* fall through */
		case CON_STATE_READ:
			/*(should not be reached by HTTP/2 streams)*/
			if (!connection_handle_read_state(con)) {
				if (r->http_version == HTTP_VERSION_2) {
					connection_transition_h2(r, con);
					connection_state_machine_h2(r, con);
					return;
				}
				break;
			}
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
			switch (http_response_handler(r)) {
			  case HANDLER_GO_ON:/*CON_STATE_RESPONSE_START occurred;transient*/
			  case HANDLER_FINISHED:
				break;
			  case HANDLER_WAIT_FOR_EVENT:
				return;
			  case HANDLER_COMEBACK:
				/* redo loop; will not match r->state */
				ostate = CON_STATE_CONNECT;
				continue;
			  case HANDLER_WAIT_FOR_FD:
		                connection_fdwaitqueue_append(con);
				return;
			  /*case HANDLER_ERROR:*/
			  default:
				connection_set_state_error(r, CON_STATE_ERROR);
				continue;
			}
			/* fall through */
		/*case CON_STATE_RESPONSE_START:*//*occurred;transient*/
			if (r->http_version > HTTP_VERSION_1_1)
				h2_send_headers(r, con);
			else
				http_response_write_header(r);
			connection_set_state(r, CON_STATE_WRITE);
			/* fall through */
		case CON_STATE_WRITE:
			connection_handle_write_state(r, con);
			if (r->state != CON_STATE_RESPONSE_END) break;
			/* fall through */
		case CON_STATE_RESPONSE_END: /* transient */
		case CON_STATE_ERROR:        /* transient */
			if (r->http_version > HTTP_VERSION_1_1 && r != &con->request)
				return;
			connection_handle_response_end_state(r, con);
			break;
		case CON_STATE_CLOSE:
			/*(should not be reached by HTTP/2 streams)*/
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
}


static void
connection_set_fdevent_interest (request_st * const r, connection * const con)
{
    if (con->fd < 0) return;

    int n = 0;
    switch(r->state) {
      case CON_STATE_READ:
        n = FDEVENT_IN | FDEVENT_RDHUP;
        break;
      case CON_STATE_WRITE:
        if (!chunkqueue_is_empty(con->write_queue)
            && 0 == con->is_writable && 0 == con->traffic_limit_reached)
            n |= FDEVENT_OUT;
        __attribute_fallthrough__
      case CON_STATE_READ_POST:
        if (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN)
            n |= FDEVENT_IN;
        if (!(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLRDHUP))
            n |= FDEVENT_RDHUP;
        break;
      case CON_STATE_CLOSE:
        n = FDEVENT_IN;
        break;
      case CON_STATE_CONNECT:
        return;
      default:
        break;
    }

    const int events = fdevent_fdnode_interest(con->fdn);
    if (con->is_readable < 0) {
        con->is_readable = 0;
        n |= FDEVENT_IN;
    }
    if (con->is_writable < 0) {
        con->is_writable = 0;
        n |= FDEVENT_OUT;
    }
    if (events & FDEVENT_RDHUP)
        n |= FDEVENT_RDHUP;

    if (n == events) return;

    /* update timestamps when enabling interest in events */
    if ((n & FDEVENT_IN) && !(events & FDEVENT_IN))
        con->read_idle_ts = log_epoch_secs;
    if ((n & FDEVENT_OUT) && !(events & FDEVENT_OUT))
        con->write_request_ts = log_epoch_secs;
    fdevent_fdnode_event_set(con->srv->ev, con->fdn, n);
}


static void
connection_state_machine_h2 (request_st * const h2r, connection * const con)
{
    h2con * const h2c = con->h2;

    if (h2c->sent_goaway <= 0
        && (chunkqueue_is_empty(con->read_queue) || h2_parse_frames(con))
        && con->is_readable) {
        chunkqueue * const cq = con->read_queue;
        const off_t mark = cq->bytes_in;
        if (0 == con->network_read(con, cq, MAX_READ_LIMIT)) {
            if (mark < cq->bytes_in)
                h2_parse_frames(con);
        }
        else {
            /* network error; do not send GOAWAY, but pretend that we did */
            h2c->sent_goaway = H2_E_CONNECT_ERROR; /*any error (not NO_ERROR)*/
            connection_set_state_error(h2r, CON_STATE_ERROR);
        }
    }

    /* process requests on HTTP/2 streams */
    int resched = 0;
    if (h2c->sent_goaway <= 0 && h2c->rused) {
        /* coarse check for write throttling
         * (connection.kbytes-per-second, server.kbytes-per-second)
         * obtain an approximate limit, not refreshed per request_st,
         * even though we are not calculating response HEADERS frames
         * or frame overhead here */
        off_t max_bytes = con->is_writable
          ? connection_write_throttle(con, MAX_WRITE_LIMIT)
          : 0;
        const off_t fsize = (off_t)h2c->s_max_frame_size;

        /* XXX: to avoid buffer bloat due to staging too much data in
         * con->write_queue, consider setting limit on how much is staged
         * for sending on con->write_queue: adjusting max_bytes down */

        /* XXX: TODO: process requests in stream priority order */
        for (uint32_t i = 0; i < h2c->rused; ++i) {
            request_st * const r = h2c->r[i];
            /* future: might track read/write interest per request
             * to avoid iterating through all active requests */

            /* XXX: h2.c manages r->h2state, but does not modify r->state
             *      (might revisit later and allow h2.c to modify both) */
            if (r->state < CON_STATE_REQUEST_END
                && (r->h2state == H2_STATE_OPEN
                    || r->h2state == H2_STATE_HALF_CLOSED_REMOTE))
                connection_set_state(r, CON_STATE_REQUEST_END);
            else if (r->h2state == H2_STATE_CLOSED
                     && r->state != CON_STATE_ERROR)
                    connection_set_state(r, CON_STATE_ERROR);

          #if 0 /*(done in connection_state_machine(), but w/o stream id)*/
            const int log_state_handling = r->conf.log_state_handling;
            if (log_state_handling)
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "state at enter %d %d %s", con->fd, r->h2id,
                  connection_get_state(r->state));
          #endif

            connection_state_machine_loop(r, con);

            if (r->resp_header_len && !chunkqueue_is_empty(r->write_queue)
                && (r->resp_body_finished || r->conf.stream_response_body)) {

                chunkqueue * const cq = r->write_queue;
                off_t avail = cq->bytes_in - cq->bytes_out;
                if (avail > max_bytes)    avail = max_bytes;
                if (avail > fsize)        avail = fsize;
                if (avail > r->h2_swin)   avail = r->h2_swin;
                if (avail > h2r->h2_swin) avail = h2r->h2_swin;

                if (avail > 0) {
                    max_bytes -= avail;
                    h2_send_cqdata(r, con, cq, (uint32_t)avail);
                }

                if (r->resp_body_finished && chunkqueue_is_empty(cq)) {
                    connection_set_state(r, CON_STATE_RESPONSE_END);
                    if (r->conf.log_state_handling)
                        connection_state_machine_loop(r, con);
                }
                else if (avail) /*(do not spin if swin empty window)*/
                    resched |= (!chunkqueue_is_empty(cq));
            }

          #if 0 /*(done in connection_state_machine(), but w/o stream id)*/
            /* XXX: TODO: r is invalid if retired; not properly handled here */
            if (log_state_handling)
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "state at exit %d %d %s", con->fd, r->h2id,
                  connection_get_state(r->state));
          #endif

            if (r->state==CON_STATE_RESPONSE_END || r->state==CON_STATE_ERROR) {
                /*(trigger reschedule of con if frames pending)*/
                if (h2c->rused == sizeof(h2c->r)/sizeof(*h2c->r)
                    && !chunkqueue_is_empty(con->read_queue))
                    resched |= 1;
                h2_send_end_stream(r, con);
                h2_retire_stream(r, con);/*r invalidated;removed from h2c->r[]*/
                --i;/* adjust loop i; h2c->rused was modified to retire r */
            }
        }
    }

    if (h2c->sent_goaway > 0 && h2c->rused) {
        /* retire streams if an error has occurred
         * note: this is not done to other streams in the loop above
         * (besides the current stream in the loop) due to the specific
         * implementation above, where doing so would mess up the iterator */
        for (uint32_t i = 0; i < h2c->rused; ++i) {
            request_st * const r = h2c->r[i];
            /*assert(r->h2state == H2_STATE_CLOSED);*/
            h2_retire_stream(r, con);/*r invalidated;removed from h2c->r[]*/
            --i;/* adjust loop i; h2c->rused was modified to retire r */
        }
        /* XXX: ? should we discard con->write_queue
         *        and change h2r->state to CON_STATE_RESPONSE_END ? */
    }

    if (h2r->state == CON_STATE_WRITE) {
        /* write HTTP/2 frames to socket */
        if (!chunkqueue_is_empty(con->write_queue) && con->is_writable)
            connection_handle_write(h2r, con);

        if (chunkqueue_is_empty(con->write_queue)
            && 0 == h2c->rused && h2c->sent_goaway)
            connection_set_state(h2r, CON_STATE_RESPONSE_END);
    }

    if (h2r->state == CON_STATE_WRITE) {
        if (resched && !con->traffic_limit_reached)
            joblist_append(con);

        if (h2_want_read(con))
            h2r->conf.stream_request_body |=  FDEVENT_STREAM_REQUEST_POLLIN;
        else
            h2r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
    }
    else /* e.g. CON_STATE_RESPONSE_END or CON_STATE_ERROR */
        connection_state_machine_loop(h2r, con);

    connection_set_fdevent_interest(h2r, con);
}


static void
connection_state_machine_h1 (request_st * const r, connection * const con)
{
	const int log_state_handling = r->conf.log_state_handling;
	if (log_state_handling) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "state at enter %d %s", con->fd, connection_get_state(r->state));
	}

	connection_state_machine_loop(r, con);

	if (log_state_handling) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "state at exit: %d %s", con->fd, connection_get_state(r->state));
	}

	connection_set_fdevent_interest(r, con);
}


void
connection_state_machine (connection * const con)
{
    request_st * const r = &con->request;
    if (r->http_version == HTTP_VERSION_2)
        connection_state_machine_h2(r, con);
    else /* if (r->http_version <= HTTP_VERSION_1_1) */
        connection_state_machine_h1(r, con);
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
    }
    else if (con->h2 && r->state == CON_STATE_WRITE) {
        h2con * const h2c = con->h2;
        if (h2c->rused) {
            for (uint32_t i = 0; i < h2c->rused; ++i) {
                request_st * const rr = h2c->r[i];
                if (rr->state == CON_STATE_ERROR) { /*(should not happen)*/
                    changed = 1;
                    continue;
                }
                if (rr->reqbody_length != rr->reqbody_queue->bytes_in) {
                    /* XXX: should timeout apply if not trying to read on h2con?
                     * (still applying timeout to catch stuck connections) */
                    /* XXX: con->read_idle_ts is not per-request, so timeout
                     * will not occur if other read activity occurs on h2con
                     * (future: might keep separate timestamp per-request) */
                    if (cur_ts - con->read_idle_ts > rr->conf.max_read_idle) {
                        /* time - out */
                        if (rr->conf.log_request_handling) {
                            log_error(rr->conf.errh, __FILE__, __LINE__,
                              "request aborted - read timeout: %d", con->fd);
                        }
                        connection_set_state_error(r, CON_STATE_ERROR);
                        changed = 1;
                    }
                }

                if (rr->state != CON_STATE_READ_POST
                    && con->write_request_ts != 0) {
                    /* XXX: con->write_request_ts is not per-request, so timeout
                     * will not occur if other write activity occurs on h2con
                     * (future: might keep separate timestamp per-request) */
                    if (cur_ts - con->write_request_ts
                        > r->conf.max_write_idle) {
                        /*(see comment further down about max_write_idle)*/
                        /* time - out */
                        if (r->conf.log_timeouts) {
                            log_error(r->conf.errh, __FILE__, __LINE__,
                              "NOTE: a request from %.*s for %.*s timed out "
                              "after writing %lld bytes. We waited %d seconds. "
                              "If this is a problem, increase "
                              "server.max-write-idle",
                              BUFFER_INTLEN_PTR(con->dst_addr_buf),
                              BUFFER_INTLEN_PTR(&r->target),
                              (long long)r->write_queue->bytes_out,
                              (int)r->conf.max_write_idle);
                        }
                        connection_set_state_error(r, CON_STATE_ERROR);
                        changed = 1;
                    }
                }
            }
        }
        else {
            if (cur_ts - con->read_idle_ts > con->keep_alive_idle) {
                /* time - out */
                if (r->conf.log_request_handling) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                              "connection closed - keep-alive timeout: %d",
                              con->fd);
                }
                connection_set_state(r, CON_STATE_RESPONSE_END);
                changed = 1;
            }
        }
    }
    else if (waitevents & FDEVENT_IN) {
        if (con->request_count == 1 || r->state != CON_STATE_READ) {
            /* e.g. CON_STATE_READ_POST || CON_STATE_WRITE */
            if (cur_ts - con->read_idle_ts > r->conf.max_read_idle) {
                /* time - out */
                if (r->conf.log_request_handling) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                              "connection closed - read timeout: %d", con->fd);
                }

                connection_set_state_error(r, CON_STATE_ERROR);
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

                connection_set_state_error(r, CON_STATE_ERROR);
                changed = 1;
            }
        }
    }

    /* max_write_idle timeout currently functions as backend timeout,
     * too, after response has been started.
     * future: have separate backend timeout, and then change this
     * to check for write interest before checking for timeout */
    /*if (waitevents & FDEVENT_OUT)*/
    if (r->http_version <= HTTP_VERSION_1_1
        && r->state == CON_STATE_WRITE && con->write_request_ts != 0) {
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
                  "%lld bytes. We waited %d seconds.  If this is a problem, "
                  "increase server.max-write-idle",
                  BUFFER_INTLEN_PTR(con->dst_addr_buf),
                  BUFFER_INTLEN_PTR(&r->target),
                  (long long)con->bytes_written, (int)r->conf.max_write_idle);
            }
            connection_set_state_error(r, CON_STATE_ERROR);
            changed = 1;
        }
    }

    /* lighttpd HTTP/2 limitation: rate limit config r->conf.bytes_per_second
     * (currently) taken only from top-level config (socket), with host if SNI
     * used, but not any other config conditions, e.g. not per-file-type */

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
        else if (con->h2 && r->state == CON_STATE_WRITE) {
            h2_send_goaway(con, H2_E_NO_ERROR);
            if (0 == con->h2->rused && chunkqueue_is_empty(con->write_queue)) {
                connection_set_state(r, CON_STATE_RESPONSE_END);
                changed = 1;
            }
        }
        else if (r->state == CON_STATE_READ && con->request_count > 1
                 && chunkqueue_is_empty(con->read_queue)) {
            /* close connections in keep-alive waiting for next request */
            connection_set_state_error(r, CON_STATE_ERROR);
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


static int
connection_handle_read_post_cq_compact (chunkqueue * const cq)
{
    /* combine first mem chunk with next non-empty mem chunk
     * (loop if next chunk is empty) */
    chunk *c;
    while (NULL != (c = cq->first) && NULL != c->next) {
        buffer *mem = c->next->mem;
        off_t offset = c->next->offset;
        size_t blen = buffer_string_length(mem) - (size_t)offset;
        force_assert(c->type == MEM_CHUNK);
        force_assert(c->next->type == MEM_CHUNK);
        buffer_append_string_len(c->mem, mem->ptr+offset, blen);
        c->next->offset = c->offset;
        c->next->mem = c->mem;
        c->mem = mem;
        c->offset = offset + (off_t)blen;
        chunkqueue_remove_finished_chunks(cq);
        if (0 != blen) return 1;
    }
    return 0;
}


static int
connection_handle_read_post_chunked_crlf (chunkqueue * const cq)
{
    /* caller might check chunkqueue_length(cq) >= 2 before calling here
     * to limit return value to either 1 for good or -1 for error */
    chunk *c;
    buffer *b;
    char *p;
    size_t len;

    /* caller must have called chunkqueue_remove_finished_chunks(cq), so if
     * chunkqueue is not empty, it contains chunk with at least one char */
    if (chunkqueue_is_empty(cq)) return 0;

    c = cq->first;
    b = c->mem;
    p = b->ptr+c->offset;
    if (p[0] != '\r') return -1; /* error */
    if (p[1] == '\n') return 1;
    len = buffer_string_length(b) - (size_t)c->offset;
    if (1 != len) return -1; /* error */

    while (NULL != (c = c->next)) {
        b = c->mem;
        len = buffer_string_length(b) - (size_t)c->offset;
        if (0 == len) continue;
        p = b->ptr+c->offset;
        return (p[0] == '\n') ? 1 : -1; /* error if not '\n' */
    }
    return 0;
}


static handler_t
connection_handle_read_post_chunked (request_st * const r, chunkqueue * const cq, chunkqueue * const dst_cq)
{
    /* r->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)r->conf.max_request_size << 10;
    off_t te_chunked = r->te_chunked;
    do {
        off_t len = cq->bytes_in - cq->bytes_out;

        while (0 == te_chunked) {
            char *p;
            chunk *c = cq->first;
            if (NULL == c) break;
            force_assert(c->type == MEM_CHUNK);
            p = strchr(c->mem->ptr+c->offset, '\n');
            if (NULL != p) { /* found HTTP chunked header line */
                off_t hsz = p + 1 - (c->mem->ptr+c->offset);
                unsigned char *s = (unsigned char *)c->mem->ptr+c->offset;
                for (unsigned char u;(u=(unsigned char)hex2int(*s))!=0xFF;++s) {
                    if (te_chunked > (off_t)(1uLL<<(8*sizeof(off_t)-5))-1) {
                        log_error(r->conf.errh, __FILE__, __LINE__,
                          "chunked data size too large -> 400");
                        /* 400 Bad Request */
                        return http_response_reqbody_read_error(r, 400);
                    }
                    te_chunked <<= 4;
                    te_chunked |= u;
                }
                if (s == (unsigned char *)c->mem->ptr+c->offset) { /*(no hex)*/
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked header invalid chars -> 400");
                    /* 400 Bad Request */
                    return http_response_reqbody_read_error(r, 400);
                }
                while (*s == ' ' || *s == '\t') ++s;
                if (*s != '\r' && *s != ';') {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked header invalid chars -> 400");
                    /* 400 Bad Request */
                    return http_response_reqbody_read_error(r, 400);
                }

                if (hsz >= 1024) {
                    /* prevent theoretical integer overflow
                     * casting to (size_t) and adding 2 (for "\r\n") */
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked header line too long -> 400");
                    /* 400 Bad Request */
                    return http_response_reqbody_read_error(r, 400);
                }

                if (0 == te_chunked) {
                    /* do not consume final chunked header until
                     * (optional) trailers received along with
                     * request-ending blank line "\r\n" */
                    if (p[0] == '\r' && p[1] == '\n') {
                        /*(common case with no trailers; final \r\n received)*/
                        hsz += 2;
                    }
                    else {
                        /* trailers or final CRLF crosses into next cq chunk */
                        hsz -= 2;
                        do {
                            c = cq->first;
                            p = strstr(c->mem->ptr+c->offset+hsz, "\r\n\r\n");
                        } while (NULL == p
                                 && connection_handle_read_post_cq_compact(cq));
                        if (NULL == p) {
                            /*(effectively doubles max request field size
                             * potentially received by backend, if in the future
                             * these trailers are added to request headers)*/
                            if ((off_t)buffer_string_length(c->mem) - c->offset
                                < (off_t)r->conf.max_request_field_size) {
                                break;
                            }
                            else {
                                /* ignore excessively long trailers;
                                 * disable keep-alive on connection */
                                r->keep_alive = 0;
                                p = c->mem->ptr + buffer_string_length(c->mem)
                                  - 4;
                            }
                        }
                        hsz = p + 4 - (c->mem->ptr+c->offset);
                        /* trailers currently ignored, but could be processed
                         * here if 0 == r->conf.stream_request_body, taking
                         * care to reject any fields forbidden in trailers,
                         * making trailers available to CGI and other backends*/
                    }
                    chunkqueue_mark_written(cq, (size_t)hsz);
                    r->reqbody_length = dst_cq->bytes_in;
                    break; /* done reading HTTP chunked request body */
                }

                /* consume HTTP chunked header */
                chunkqueue_mark_written(cq, (size_t)hsz);
                len = cq->bytes_in - cq->bytes_out;

                if (0 !=max_request_size
                    && (max_request_size < te_chunked
                     || max_request_size - te_chunked < dst_cq->bytes_in)) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "request-size too long: %lld -> 413",
                      (long long)(dst_cq->bytes_in + te_chunked));
                    /* 413 Payload Too Large */
                    return http_response_reqbody_read_error(r, 413);
                }

                te_chunked += 2; /*(for trailing "\r\n" after chunked data)*/

                break; /* read HTTP chunked header */
            }

            /*(likely better ways to handle chunked header crossing chunkqueue
             * chunks, but this situation is not expected to occur frequently)*/
            if ((off_t)buffer_string_length(c->mem) - c->offset >= 1024) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "chunked header line too long -> 400");
                /* 400 Bad Request */
                return http_response_reqbody_read_error(r, 400);
            }
            else if (!connection_handle_read_post_cq_compact(cq)) {
                break;
            }
        }
        if (0 == te_chunked) break;

        if (te_chunked > 2) {
            if (len > te_chunked-2) len = te_chunked-2;
            if (dst_cq->bytes_in + te_chunked <= 64*1024) {
                /* avoid buffering request bodies <= 64k on disk */
                chunkqueue_steal(dst_cq, cq, len);
            }
            else if (0 != chunkqueue_steal_with_tempfiles(dst_cq, cq, len,
                                                          r->conf.errh)) {
                /* 500 Internal Server Error */
                return http_response_reqbody_read_error(r, 500);
            }
            te_chunked -= len;
            len = cq->bytes_in - cq->bytes_out;
        }

        if (len < te_chunked) break;

        if (2 == te_chunked) {
            if (-1 == connection_handle_read_post_chunked_crlf(cq)) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "chunked data missing end CRLF -> 400");
                /* 400 Bad Request */
                return http_response_reqbody_read_error(r, 400);
            }
            chunkqueue_mark_written(cq, 2);/*consume \r\n at end of chunk data*/
            te_chunked -= 2;
        }

    } while (!chunkqueue_is_empty(cq));

    r->te_chunked = te_chunked;
    return HANDLER_GO_ON;
}


static handler_t
connection_handle_read_body_unknown (request_st * const r, chunkqueue * const cq, chunkqueue * const dst_cq)
{
    /* r->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)r->conf.max_request_size << 10;
    chunkqueue_append_chunkqueue(dst_cq, cq);
    if (0 != max_request_size && dst_cq->bytes_in > max_request_size) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "request-size too long: %lld -> 413", (long long)dst_cq->bytes_in);
        /* 413 Payload Too Large */
        return http_response_reqbody_read_error(r, 413);
    }
    return HANDLER_GO_ON;
}


static handler_t
connection_handle_read_post_state (request_st * const r)
{
    connection * const con = r->con;
    chunkqueue * const cq = r->read_queue;
    chunkqueue * const dst_cq = r->reqbody_queue;

    int is_closed = 0;

    if (r->http_version > HTTP_VERSION_1_1) {
        /*(H2_STATE_HALF_CLOSED_REMOTE or H2_STATE_CLOSED)*/
        if (r->h2state >= H2_STATE_HALF_CLOSED_REMOTE)
            is_closed = 1;
    }
    else if (con->is_readable) {
        con->read_idle_ts = log_epoch_secs;

        switch(con->network_read(con, cq, MAX_READ_LIMIT)) {
        case -1:
            connection_set_state_error(r, CON_STATE_ERROR);
            return HANDLER_ERROR;
        case -2:
            is_closed = 1;
            break;
        default:
            break;
        }
    }

    chunkqueue_remove_finished_chunks(cq);

    /* Check for Expect: 100-continue in request headers
     * if no request body received yet */
    if (chunkqueue_is_empty(cq) && 0 == dst_cq->bytes_in
        && r->http_version != HTTP_VERSION_1_0
        && chunkqueue_is_empty(r->write_queue) && con->is_writable) {
        const buffer *vb =
          http_header_request_get(r, HTTP_HEADER_EXPECT,
                                  CONST_STR_LEN("Expect"));
        if (NULL != vb
            && buffer_eq_icase_slen(vb, CONST_STR_LEN("100-continue"))) {
            http_header_request_unset(r, HTTP_HEADER_EXPECT,
                                      CONST_STR_LEN("Expect"));
            if (r->http_version > HTTP_VERSION_1_1)
                h2_send_100_continue(r, con);
            else if (!connection_write_100_continue(r, con))
                return HANDLER_ERROR;
        }
    }

    if (r->http_version > HTTP_VERSION_1_1) {
        /* h2_recv_data() places frame payload directly into r->reqbody_queue */
    }
    else if (r->reqbody_length < 0) {
        /*(-1: Transfer-Encoding: chunked, -2: unspecified length)*/
        handler_t rc = (-1 == r->reqbody_length)
                     ? connection_handle_read_post_chunked(r, cq, dst_cq)
                     : connection_handle_read_body_unknown(r, cq, dst_cq);
        if (HANDLER_GO_ON != rc) return rc;
    }
    else {
        off_t len = (off_t)r->reqbody_length - dst_cq->bytes_in;
        if (r->reqbody_length <= 64*1024) {
            /* don't buffer request bodies <= 64k on disk */
            chunkqueue_steal(dst_cq, cq, len);
        }
        else if (0 !=
                 chunkqueue_steal_with_tempfiles(dst_cq,cq,len,r->conf.errh)) {
            /* writing to temp file failed */ /* Internal Server Error */
            return http_response_reqbody_read_error(r, 500);
        }
    }

    chunkqueue_remove_finished_chunks(cq);

    if (dst_cq->bytes_in == (off_t)r->reqbody_length) {
        /* Content is ready */
        r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
        if (r->state == CON_STATE_READ_POST) {
            connection_set_state(r, CON_STATE_HANDLE_REQUEST);
        }
        return HANDLER_GO_ON;
    }
    else if (is_closed) {
      #if 0
        return http_response_reqbody_read_error(r, 400); /* Bad Request */
      #endif
        return HANDLER_ERROR;
    }
    else {
        r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
        return (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
          ? HANDLER_GO_ON
          : HANDLER_WAIT_FOR_EVENT;
    }
}
