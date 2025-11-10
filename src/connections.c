#include "first.h"

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "log.h"
#include "connections.h"
#include "fdevent.h"
#include "h1.h"
#include "http_header.h"

#include "reqpool.h"
#include "request.h"
#include "response.h"

#include "plugin.h"
#include "plugins.h"

#include "sock_addr_cache.h"

#include <sys/stat.h>
#include "sys-unistd.h" /* <unistd.h> */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "sys-socket.h"

/* keep in sync with h1.c */
#define HTTP_LINGER_TIMEOUT 5

#define connection_set_state(r,state)       request_set_state((r),(state))
#define connection_set_state_error(r,state) request_set_state_error((r),(state))


__attribute_cold__
__attribute_returns_nonnull__
static connection *connection_init(server *srv);

__attribute_noinline__
static void connection_reset(connection *con);

static connection *connections_get_new_connection(server *srv) {
    connection *con;
    --srv->lim_conns;
    if (srv->conns_pool) {
        con = srv->conns_pool;
        srv->conns_pool = con->next;
    }
    else {
        con = connection_init(srv);
        connection_reset(con);
    }
    /*con->prev = NULL;*//*(already set)*/
    if ((con->next = srv->conns))
        con->next->prev = con;
    return (srv->conns = con);
}

static void connection_del(server *srv, connection *con) {
    if (con->next)
        con->next->prev = con->prev;
    if (con->prev)
        con->prev->next = con->next;
    else
        srv->conns = con->next;
    con->prev = NULL;
    con->next = srv->conns_pool;
    srv->conns_pool = con;
    ++srv->lim_conns;
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
	con->traffic_limit_reached = 0;
	con->revents_err = 0;

	fdevent_fdnode_event_del(srv->ev, con->fdn);
	fdevent_unregister(srv->ev, con->fdn);
	con->fdn = NULL;
	if (0 != fdio_close_socket(con->fd))
		log_serror(r->conf.errh, __FILE__, __LINE__,
		  "(warning) close: %d", con->fd);
	con->fd = -1;

	--srv->cur_fds;
	connection_del(srv, con);
}

static void connection_read_for_eos_plain(connection * const con) {
	/* we have to do the linger_on_close stuff regardless
	 * of r->keep_alive; even non-keepalive sockets
	 * may still have unread data, and closing before reading
	 * it will make the client not see all our output.
	 */
	ssize_t len;
	const int type = sock_addr_get_family(&con->dst_addr);
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
		con->close_timeout_ts = log_monotonic_secs - (HTTP_LINGER_TIMEOUT+1);
}

static void connection_read_for_eos_ssl(connection * const con) {
	if (con->network_read(con, con->read_queue, MAX_READ_LIMIT) < 0)
		con->close_timeout_ts = log_monotonic_secs - (HTTP_LINGER_TIMEOUT+1);
	chunkqueue_reset(con->read_queue);
}

static void connection_read_for_eos(connection * const con) {
	!con->is_ssl_sock
	  ? connection_read_for_eos_plain(con)
	  : connection_read_for_eos_ssl(con);
}

static void connection_handle_close_state(connection *con) {
	connection_read_for_eos(con);

	if (log_monotonic_secs - con->close_timeout_ts > HTTP_LINGER_TIMEOUT) {
		connection_close(con);
	}
}

static void connection_handle_shutdown(connection *con) {
	plugins_call_handle_connection_shut_wr(con);

	connection_reset(con);

	/* close the connection */
	if (con->fd >= 0
	    && (con->is_ssl_sock || 0 == shutdown(con->fd, SHUT_WR))) {
		con->close_timeout_ts = log_monotonic_secs;
		request_st * const r = &con->request;
		connection_set_state(r, CON_STATE_CLOSE);
	} else {
		connection_close(con);
	}
}


static void
connection_handle_request_start_state (request_st * const r, connection * const con)
{
    /*connection_set_state(r, CON_STATE_REQUEST_START);*/
    ++con->request_count;
    con->read_idle_ts = log_monotonic_secs;
    r->start_hp.tv_sec = log_epoch_secs;
    r->loops_per_request = 0;
    if (r->conf.high_precision_timestamps)
        log_clock_gettime_realtime(&r->start_hp);
}


static void connection_handle_response_end_state(request_st * const r, connection * const con) {
	if (r->http_version > HTTP_VERSION_1_1) {
		r->keep_alive = 0;
		/* set a status so that mod_accesslog, mod_rrdtool hooks are called
		 * in plugins_call_handle_request_done() (XXX: or set to 0 to omit) */
		r->http_status = 100; /* XXX: what if con->state == CON_STATE_ERROR? */
		/*if (r->http_status)*/
			plugins_call_handle_request_done(r);
		connection_handle_shutdown(con);
		return;
	}

	/* call request_done hook if http_status set (e.g. to log request) */
	/* (even if error, connection dropped, as long as http_status is set) */
	if (r->http_status) plugins_call_handle_request_done(r);

	if (r->reqbody_length != r->reqbody_queue.bytes_in
	    || r->state == CON_STATE_ERROR) {
		/* request body may not have been read completely */
		r->keep_alive = 0;
		/* clean up failed partial write of 1xx intermediate responses*/
		if (&r->write_queue != con->write_queue) { /*(for HTTP/1.1)*/
			chunkqueue_free(con->write_queue);
			con->write_queue = &r->write_queue;
		}
	}

        if (r->keep_alive > 0) {
		request_reset(r);
		con->is_readable = 1; /* potentially trigger optimistic read */
		/*(accounting used by mod_accesslog for HTTP/1.0 and HTTP/1.1)*/
		/*(overloaded to detect next bytes recv'd on keep-alive con)*/
		r->x.h1.bytes_read_ckpt = r->read_queue.bytes_in;
		r->x.h1.bytes_written_ckpt = r->write_queue.bytes_out;
#if 0
		r->start_hp.tv_sec = log_epoch_secs;
		con->read_idle_ts = log_monotonic_secs;
#endif
		connection_set_state(r, CON_STATE_REQUEST_START);
	} else {
		connection_handle_shutdown(con);
	}
}


__attribute_pure__
static off_t
connection_write_throttle (const connection * const con, off_t max_bytes)
{
    /*assert(max_bytes > 0);*/
    const request_config * const restrict rconf = &con->request.conf;
    if (__builtin_expect(
          (0 == (rconf->global_bytes_per_second | rconf->bytes_per_second)), 1))
        return max_bytes;

    if (rconf->global_bytes_per_second) {
        off_t limit = (off_t)rconf->global_bytes_per_second
                    - *(rconf->global_bytes_per_second_cnt_ptr);
        if (max_bytes > limit)
            max_bytes = limit;
    }

    if (rconf->bytes_per_second) {
        off_t limit = (off_t)rconf->bytes_per_second
                    - con->bytes_written_cur_second;
        if (max_bytes > limit)
            max_bytes = limit;
    }

    return max_bytes > 0 ? max_bytes : 0; /*(0 == reached traffic limit)*/
}


static int
connection_write_chunkqueue (connection * const con, chunkqueue * const restrict cq, off_t max_bytes)
{
    /*assert(!chunkqueue_is_empty(cq));*//* checked by callers */

    con->write_request_ts = log_monotonic_secs;

    max_bytes = connection_write_throttle(con, max_bytes);
    if (__builtin_expect( (0 == max_bytes), 0))
        return (con->traffic_limit_reached = 1);

    off_t written = cq->bytes_out;
    int ret;

  #ifdef TCP_CORK
    int corked = 0;
  #endif

    /* walk chunkqueue up to first FILE_CHUNK (if present)
     * This may incur memory load misses for pointer chasing, but effectively
     * preloads part of the chunkqueue, something which used to be a side effect
     * of a previous (less efficient) version of chunkqueue_length() which
     * walked the entire chunkqueue (on each and every call).  The loads here
     * make a measurable difference in performance in underlying call to
     * con->network_write() */
    if (cq->first->next && cq->first->type == MEM_CHUNK) {
        const chunk *c = cq->first;
        do { c = c->next; } while (c && c->type == MEM_CHUNK);
      #ifdef TCP_CORK
        /* Linux: put a cork into socket as we want to combine write() calls
         * but only if we really have multiple chunks including non-MEM_CHUNK
         * (or if multiple chunks and TLS), and only if TCP socket */
        /* (max_bytes may have been reduced by connection_write_throttle(),
         *  but not bothering to check; might result in some extra corking) */
        if (NULL != c || (con->is_ssl_sock && chunkqueue_length(cq) > 16384)) {
            const int sa_family = sock_addr_get_family(&con->srv_socket->addr);
            if (sa_family == AF_INET || sa_family == AF_INET6) {
                corked = 1;
                (void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK,
                                 &corked, sizeof(corked));
            }
        }
      #endif
    }

    ret = con->network_write(con, cq, max_bytes);

  #ifdef TCP_CORK
    if (corked) {
        corked = 0;
        (void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK,
                         &corked, sizeof(corked));
    }
  #endif

    written = cq->bytes_out - written;
    con->bytes_written_cur_second += written;
    request_st * const r = &con->request;
    if (r->conf.global_bytes_per_second_cnt_ptr)
        *(r->conf.global_bytes_per_second_cnt_ptr) += written;

    /* return 1 for caller to set con->is_writable = 0 when cq not empty *and*
     * bytes have been sent from cq in order to not spin trying to send HTTP/2
     * server Connection Preface while waiting for TLS negotiation to complete*/
    return (ret >= 0) ? !chunkqueue_is_empty(cq) && cq->bytes_out : ret;
}


__attribute_noinline__
static int connection_handle_write(request_st * const r, connection * const con) {
	/*assert(!chunkqueue_is_empty(cq));*//* checked by callers */

	if (con->is_writable <= 0) return CON_STATE_WRITE;
	int rc = connection_write_chunkqueue(con, con->write_queue, MAX_WRITE_LIMIT);
	switch (rc) {
	case 0:
		break;
	case -1: /* local error */
	case -2: /* remote close */
		connection_set_state_error(r, CON_STATE_ERROR);
		return CON_STATE_ERROR;
	case 1:
		con->is_writable = 0;
		break;
	}

	return CON_STATE_WRITE; /*(state did not change)*/
}

static int connection_handle_write_state(request_st * const r, connection * const con) {
    int loop_once = 0;
    do {
        /* only try to write if we have something in the queue */
        if (!chunkqueue_is_empty(&r->write_queue)) {
            int rc = connection_handle_write(r, con);
            if (rc != CON_STATE_WRITE) return rc;
        }
        else if (r->resp_body_finished) {
            connection_set_state(r, CON_STATE_RESPONSE_END);
            return CON_STATE_RESPONSE_END;
        }

        if (r->handler_module && !r->resp_body_finished) {
            const plugin * const p = r->handler_module;
            if (p->handle_subrequest(r, p->data) > HANDLER_WAIT_FOR_EVENT) {
                connection_set_state_error(r, CON_STATE_ERROR);
                return CON_STATE_ERROR;
            }
        }

    } while (!chunkqueue_is_empty(&r->write_queue)
             ? con->is_writable > 0 && 0 == con->traffic_limit_reached
               && 1 == ++loop_once
             : r->resp_body_finished);

    /* yield to handle other connections or else TLS on a slow, embedded device
     * might loop here and monopolize resources */
    if (2 == loop_once)
        joblist_append(con);

    return CON_STATE_WRITE;
}


__attribute_cold__
__attribute_returns_nonnull__
static connection *connection_init(server *srv) {
	connection * const con = ck_calloc(1, sizeof(*con));

	con->srv = srv;
	con->plugin_slots = srv->plugin_slots;
	con->config_data_base = srv->config_data_base;

	request_st * const r = &con->request;
	request_init_data(r, con, srv);
	con->write_queue = &r->write_queue;
	con->read_queue = &r->read_queue;

	/* init plugin-specific per-connection structures */
	con->plugin_ctx = ck_calloc(srv->plugins.used + 1, sizeof(void *));

	return con;
}


static void connection_free(connection * const con) {
    request_st * const r = &con->request;

    connection_reset(con);
    if (con->write_queue != &r->write_queue)
        chunkqueue_free(con->write_queue);
    if (con->read_queue != &r->read_queue)
        chunkqueue_free(con->read_queue);
    request_free_data(r);

    free(con->plugin_ctx);
    free(con->dst_addr_buf.ptr);
    free(con);
}

void connections_pool_clear(server * const srv) {
    connection *con, *next = srv->conns_pool;
    srv->conns_pool = NULL;
    while ((con = next)) {
        next = con->next;
        if (!con->jqnext) /*(jqnext or sentinel; NULL if not in job queue)*/
            connection_free(con);
        else {
            /*(leave con in srv->conns_pool if con still in job queue
             * rather than excess work to remove from singly-linked job queue
             * for rare, but possible, condition; reverses list of remainders)*/
            con->next = srv->conns_pool;
            srv->conns_pool = con;
        }
    }
}

void connections_free(server *srv) {
    connection *con;
    while ((con = srv->conns_pool)) {
        srv->conns_pool = con->next;
        connection_free(con);
    }
    while ((con = srv->conns)) {
        srv->conns = con->next;
        connection_free(con);
    }
}


static void connection_reset(connection *con) {
	request_st * const r = &con->request;
	request_reset(r);
	con->is_readable = 1;
	con->bytes_written_cur_second = 0;
	con->fn = NULL;
}


__attribute_cold__
static void
connection_transition_h2 (request_st * const h2r, connection * const con)
{
    buffer_copy_string_len(&h2r->target,      CONST_STR_LEN("*"));
    buffer_copy_string_len(&h2r->target_orig, CONST_STR_LEN("*"));
    buffer_copy_string_len(&h2r->uri.path,    CONST_STR_LEN("*"));
    h2r->http_method = HTTP_METHOD_PRI;
    /*(setting all bits might break existing lighttpd.conf,
     * which e.g. might make assumptions in configs for "OPTIONS *",
     * so probably better to leave other conditions unset)*/
    /*h2r->conditional_is_valid = ~0u;*/
    h2r->conditional_is_valid |= (1 << COMP_HTTP_REQUEST_METHOD);
    h2r->reqbody_length = -1; /*(unnecessary for h2r?)*/
    h2r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;

    /* (h2r->state == CON_STATE_READ) for transition by ALPN
     *   or starting cleartext HTTP/2 with Prior Knowledge
     *   (e.g. via HTTP Alternative Services)
     * (h2r->state == CON_STATE_WRITE) for Upgrade: h2c */

    if (h2r->state == CON_STATE_ERROR) /*(CON_STATE_ERROR unexpected here)*/
        return;

    connection_set_state(h2r, CON_STATE_WRITE);

  #if 0 /* ... if it turns out we need a separate fdevent handler for HTTP/2 */
    con->fdn->handler = connection_handle_fdevent_h2;
  #endif

    /* r->conf.h2proto must be checked prior to setting r->http_version to
     * HTTP_VERSION_2, so if we get here, http_dispatch[HTTP_VERSION_2] inited*/
    if (NULL == con->hx) /*(not yet transitioned to HTTP/2; not Upgrade: h2c)*/
        http_dispatch[HTTP_VERSION_2].upgrade_h2(h2r, con);
}


static handler_t connection_handle_fdevent(void * const context, const int revents) {
    connection * restrict con = context;
    const int is_ssl_sock = con->is_ssl_sock;

    joblist_append(con);

    if (revents & ~(FDEVENT_IN | FDEVENT_OUT))
        con->revents_err |= (revents & ~(FDEVENT_IN | FDEVENT_OUT));

    if (revents & (FDEVENT_IN | FDEVENT_OUT)) {
        if (is_ssl_sock) /*(ssl may read and write for both reads and writes)*/
            con->is_readable = con->is_writable = 1;
        else {
            if (revents & FDEVENT_IN)
                con->is_readable = 1;
            if (revents & FDEVENT_OUT)
                con->is_writable = 1;
        }
    }

    return HANDLER_FINISHED;
}


__attribute_cold__
static int connection_read_cq_err(connection *con) {
    request_st * const r = &con->request;
  #ifdef _WIN32
    switch (WSAGetLastError()) {
      case WSAEWOULDBLOCK:
        return 0;
      case WSAEINTR:
        /* we have been interrupted before we could read */
        con->is_readable = 1;
        return 0;
      case WSAECONNRESET:
        /* suppress logging for this error, expected for keep-alive */
        break;
    default:
        log_serror(r->conf.errh, __FILE__, __LINE__,
          "connection closed - recv failed");
        break;
    }
  #else
    switch (errno) {
    case EAGAIN:
   #ifdef EWOULDBLOCK
   #if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
   #endif
   #endif
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
  #endif

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

      #ifdef _WIN32
        len = recv(con->fd, mem, mem_len, 0);
      #else
        len = read(con->fd, mem, mem_len);
      #endif

        chunkqueue_use_memory(cq, ckpt, len > 0 ? len : 0);

        if (len != (ssize_t)mem_len) {
            /* we got less than expected, wait for the next fd-event */
            con->is_readable = 0;
            return len > 0 ? 0 : 0 == len ? -2 : connection_read_cq_err(con);
        }

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


connection *connection_accepted(server *srv, const server_socket *srv_socket, sock_addr *cnt_addr, int cnt) {
		connection *con;

		srv->cur_fds++;

		con = connections_get_new_connection(srv);

		con->fd = cnt;
		con->fdn = fdevent_register(srv->ev, con->fd, connection_handle_fdevent, con);
		con->network_read = connection_read_cq;
		con->network_write = connection_write_cq;
		con->reqbody_read = h1_reqbody_read;

		request_st * const r = &con->request;
		connection_set_state(r, CON_STATE_REQUEST_START);

		con->connection_start = log_monotonic_secs;
		con->dst_addr = *cnt_addr;
		sock_addr_cache_inet_ntop_copy_buffer(&con->dst_addr_buf,
		                                      &con->dst_addr);
		con->srv_socket = srv_socket;
		/* recv() immediately after accept() fails (on default Linux for TCP);
		 * so skip optimistic read.  (might revisit with HTTP/3 UDP) */
		/*con->is_readable = 1;*/
		con->is_writable = 1;
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


static void
connection_state_machine_loop (request_st * const r, connection * const con)
{
	request_state_t ostate;
	do {
		switch ((ostate = r->state)) {
		case CON_STATE_REQUEST_START: /* transient */
			/*(should not be reached by HTTP/2 streams)*/
			connection_handle_request_start_state(r, con);
			connection_set_state(r, CON_STATE_READ);
			__attribute_fallthrough__
		case CON_STATE_READ:
			/*(should not be reached by HTTP/2 streams)*/
			if (!h1_recv_headers(r, con)) {
				if (r->http_version == HTTP_VERSION_2) {
					connection_transition_h2(r, con);
					connection_state_machine(con);
					ostate = CON_STATE_WRITE;
					continue; /*(end loop if CON_STATE_WRITE)*/
				}
				break;
			}
			/*connection_set_state(r, CON_STATE_REQUEST_END);*/
			/*__attribute_fallthrough__*/
		/*case CON_STATE_REQUEST_END:*//* transient */
			connection_set_state(r,
			  (0 == r->reqbody_length)
			  ? CON_STATE_HANDLE_REQUEST
			  : CON_STATE_READ_POST);
			__attribute_fallthrough__
		case CON_STATE_READ_POST:
		case CON_STATE_HANDLE_REQUEST:
			switch (http_response_handler(r)) {
			  case HANDLER_GO_ON:/*CON_STATE_RESPONSE_START occurred;transient*/
			  case HANDLER_FINISHED:
				break;
			  case HANDLER_WAIT_FOR_EVENT:
				return;
			  /*case HANDLER_COMEBACK:*//*(not expected)*/
			  /*case HANDLER_ERROR:*/
			  default:
				connection_set_state_error(r, CON_STATE_ERROR);
				continue;
			}
			/*__attribute_fallthrough__*/
		/*case CON_STATE_RESPONSE_START:*//*occurred;transient*/
			h1_send_headers(r);
			connection_set_state(r, CON_STATE_WRITE);
			__attribute_fallthrough__
		case CON_STATE_WRITE:
			if (connection_handle_write_state(r, con) == CON_STATE_WRITE)
				return;
			__attribute_fallthrough__
		case CON_STATE_RESPONSE_END: /* transient */
		case CON_STATE_ERROR:        /* transient */
			connection_handle_response_end_state(r, con);
			if (r->state == CON_STATE_REQUEST_START) {
				joblist_append(con);
				return;
			}
			/*(make sure ostate will not match r->state)*/
			ostate = CON_STATE_RESPONSE_END;/* != r->state */
			break;
		case CON_STATE_CLOSE:
			/*(should not be reached by HTTP/2 streams)*/
			connection_handle_close_state(con);
			return;
		case CON_STATE_CONNECT:
			return;
		default:/*(should not happen)*/
			return;
		}
	} while (ostate != r->state);
}


__attribute_cold__
static void
connection_revents_err (request_st * const r, connection * const con)
{
    /* defer handling FDEVENT_HUP and FDEVENT_ERR to here in order to
     * first attempt (in callers) to read data in kernel socket buffers */
    /*assert(con->revents_err & ~(FDEVENT_IN | FDEVENT_OUT));*/
    const int revents = (int)con->revents_err;
    con->revents_err = 0;

    if (r->state == CON_STATE_CLOSE)
        con->close_timeout_ts = log_monotonic_secs - (HTTP_LINGER_TIMEOUT+1);
    else if (revents & FDEVENT_HUP)
        connection_set_state_error(r, CON_STATE_ERROR);
    else if (revents & FDEVENT_RDHUP) {
        int events = fdevent_fdnode_interest(con->fdn);
        events &= ~(FDEVENT_IN|FDEVENT_RDHUP);
        r->conf.stream_request_body &=
          ~(FDEVENT_STREAM_REQUEST_BUFMIN|FDEVENT_STREAM_REQUEST_POLLIN);
        r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLRDHUP;
        con->is_readable = 1; /*(can read 0 for end-of-stream)*/
        if (chunkqueue_is_empty(con->read_queue)) r->keep_alive = 0;
        if (r->reqbody_length < -1)/*(transparent proxy mode; no more rd data)*/
            r->reqbody_length = r->reqbody_queue.bytes_in;
        if (sock_addr_get_family(&con->dst_addr) == AF_UNIX) {
            /* future: will getpeername() on AF_UNIX check if still connected?*/
            fdevent_fdnode_event_set(con->srv->ev, con->fdn, events);
        }
        else if (fdevent_is_tcp_half_closed(con->fd)) {
            /* Success of fdevent_is_tcp_half_closed() after FDEVENT_RDHUP
             * indicates TCP FIN received, but does not distinguish between
             * client shutdown(fd, SHUT_WR) and client close(fd).  Remove
             * FDEVENT_RDHUP so that we do not spin on ready event.  However,
             * a later TCP RST will not be detected until next write to socket.
             * future: might getpeername() to check for TCP RST on half-closed
             * sockets (without FDEVENT_RDHUP interest) when checking for write
             * timeouts once a second in server.c, though getpeername() on
             * Windows might not indicate this */
            r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;
            fdevent_fdnode_event_set(con->srv->ev, con->fdn, events);
        }
        else {
            /* Failure of fdevent_is_tcp_half_closed() indicates TCP RST
             * (or unable to tell (unsupported OS), though should not
             * be setting FDEVENT_RDHUP in that case) */
            connection_set_state_error(r, CON_STATE_ERROR);
        }
    }
    else if (revents & FDEVENT_ERR)  /* error, connection reset */
        connection_set_state_error(r, CON_STATE_ERROR);
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
          "connection closed: poll() -> ??? %d", revents);
}


static void
connection_set_fdevent_interest (request_st * const r, connection * const con)
{
    if (con->fd < 0) return;

    if (con->revents_err && r->state != CON_STATE_ERROR) {
        connection_revents_err(r, con); /* resets con->revents_err = 0 */
        connection_state_machine(con);
        return;
        /* connection_state_machine() will end up calling back into
         * connection_set_fdevent_interest(), but with 0 == con->revents_err */
    }

    int n = 0;
    switch(r->state) {
      case CON_STATE_READ:
        n = FDEVENT_IN;
        if (!(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLRDHUP))
            n |= FDEVENT_RDHUP;
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
        con->read_idle_ts = log_monotonic_secs;
    if ((n & FDEVENT_OUT) && !(events & FDEVENT_OUT))
        con->write_request_ts = log_monotonic_secs;
    fdevent_fdnode_event_set(con->srv->ev, con->fdn, n);
}


void
connection_state_machine (connection * const con)
{
    int rc = !con->fn || con->fn->process_streams(con, http_response_handler,
                                                       connection_handle_write);
    if (rc)
        connection_state_machine_loop(&con->request, con);
    connection_set_fdevent_interest(&con->request, con);
}


static void
connection_check_timeout (connection * const con, const unix_time64_t cur_ts)
{
    int changed = (con->fn && con->fn->check_timeout)
      ? con->fn->check_timeout(con, cur_ts)
      : h1_check_timeout(con, cur_ts);
      /*http_dispatch[HTTP_VERSION_1_1].check_timeout(con, cur_ts)*//*(future)*/

    con->bytes_written_cur_second = 0;

    /* lighttpd HTTP/2 limitation: rate limit config r->conf.bytes_per_second
     * (currently) taken only from top-level config (socket), with host if SNI
     * used, but not any other config conditions, e.g. not per-file-type */

    if (__builtin_expect( (con->traffic_limit_reached != 0), 0)) {
        const request_st * const r = &con->request;
        const int t_diff = cur_ts - con->connection_start;
        if (r->conf.bytes_per_second == 0
            || con->write_queue->bytes_out
                 < (off_t)r->conf.bytes_per_second * (t_diff ? t_diff : 1)) {
            /* enable connection write again */
            con->traffic_limit_reached = 0;
            changed = 1;
        }
    }

    if (changed) {
        connection_state_machine(con);
    }
}


void
connection_periodic_maint (server * const srv, const unix_time64_t cur_ts)
{
    /* check all connections for timeouts */
    for (connection *con = srv->conns, *tc; con; con = tc) {
        tc = con->next;
        connection_check_timeout(con, cur_ts);
    }
}


void
connection_graceful_shutdown_maint (server * const srv)
{
    const int graceful_expire =
      (srv->graceful_expire_ts && srv->graceful_expire_ts < log_monotonic_secs);
    for (connection *con = srv->conns, *tc; con; con = tc) {
        tc = con->next;
        int changed = 0;

        request_st * const r = &con->request;
        if (r->state == CON_STATE_CLOSE) {
            /* reduce remaining linger timeout to be
             * (from zero) *up to* one more second, but no more */
            if (HTTP_LINGER_TIMEOUT > 1)
                con->close_timeout_ts -= (HTTP_LINGER_TIMEOUT - 1);
            con->close_timeout_ts -= (graceful_expire << 1); /*(-2 if expired)*/
            if (log_monotonic_secs - con->close_timeout_ts > HTTP_LINGER_TIMEOUT)
                changed = 1;
        }
        else if (con->fn) {
            if (con->fn->goaway_graceful(con))
                changed = 1;
        }
        else if (r->state == CON_STATE_READ && con->request_count > 1
                 && chunkqueue_is_empty(con->read_queue)) {
            /* close connections in keep-alive waiting for next request */
            connection_set_state_error(r, CON_STATE_ERROR);
            changed = 1;
        }
        else if (r->reqbody_length == -2
                 && !(r->conf.stream_request_body
                      & FDEVENT_STREAM_REQUEST_TCP_FIN)) {
            /* For requests in transparent proxy mode, trigger behavior as if
             * TCP FIN received from client, as tunnels (e.g. websockets) are
             * otherwise opaque */
            r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;
            changed = 1;
        }

        if (graceful_expire && r->state != CON_STATE_CLOSE) {
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
