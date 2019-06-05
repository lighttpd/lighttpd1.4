#include "first.h"

#include "sys-socket.h"
#include "base.h"
#include "connections.h"
#include "fdevent.h"
#include "http_header.h"
#include "log.h"
#include "response.h"

#include <errno.h>
#include <string.h>

const char *connection_get_state(connection_state_t state) {
	switch (state) {
	case CON_STATE_CONNECT: return "connect";
	case CON_STATE_READ: return "read";
	case CON_STATE_READ_POST: return "readpost";
	case CON_STATE_WRITE: return "write";
	case CON_STATE_CLOSE: return "close";
	case CON_STATE_ERROR: return "error";
	case CON_STATE_HANDLE_REQUEST: return "handle-req";
	case CON_STATE_REQUEST_START: return "req-start";
	case CON_STATE_REQUEST_END: return "req-end";
	case CON_STATE_RESPONSE_START: return "resp-start";
	case CON_STATE_RESPONSE_END: return "resp-end";
	default: return "(unknown)";
	}
}

const char *connection_get_short_state(connection_state_t state) {
	switch (state) {
	case CON_STATE_CONNECT: return ".";
	case CON_STATE_READ: return "r";
	case CON_STATE_READ_POST: return "R";
	case CON_STATE_WRITE: return "W";
	case CON_STATE_CLOSE: return "C";
	case CON_STATE_ERROR: return "E";
	case CON_STATE_HANDLE_REQUEST: return "h";
	case CON_STATE_REQUEST_START: return "q";
	case CON_STATE_REQUEST_END: return "Q";
	case CON_STATE_RESPONSE_START: return "s";
	case CON_STATE_RESPONSE_END: return "S";
	default: return "x";
	}
}

int connection_set_state(server *srv, connection *con, connection_state_t state) {
	UNUSED(srv);

	con->state = state;

	return 0;
}

static int connection_handle_read_post_cq_compact(chunkqueue *cq) {
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

static int connection_handle_read_post_chunked_crlf(chunkqueue *cq) {
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

handler_t connection_handle_read_post_error(server *srv, connection *con, int http_status) {
    UNUSED(srv);

    con->keep_alive = 0;

    /*(do not change status if response headers already set and possibly sent)*/
    if (0 != con->bytes_header) return HANDLER_ERROR;

    http_response_body_clear(con, 0);
    con->http_status = http_status;
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

static handler_t connection_handle_read_post_chunked(server *srv, connection *con, chunkqueue *cq, chunkqueue *dst_cq) {

    /* con->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)con->conf.max_request_size << 10;
    off_t te_chunked = con->request.te_chunked;
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
                        log_error_write(srv, __FILE__, __LINE__, "s",
                                        "chunked data size too large -> 400");
                        /* 400 Bad Request */
                        return connection_handle_read_post_error(srv, con, 400);
                    }
                    te_chunked <<= 4;
                    te_chunked |= u;
                }
                while (*s == ' ' || *s == '\t') ++s;
                if (*s != '\r' && *s != ';') {
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "chunked header invalid chars -> 400");
                    /* 400 Bad Request */
                    return connection_handle_read_post_error(srv, con, 400);
                }

                if (hsz >= 1024) {
                    /* prevent theoretical integer overflow
                     * casting to (size_t) and adding 2 (for "\r\n") */
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "chunked header line too long -> 400");
                    /* 400 Bad Request */
                    return connection_handle_read_post_error(srv, con, 400);
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
                                < srv->srvconf.max_request_field_size) {
                                break;
                            }
                            else {
                                /* ignore excessively long trailers;
                                 * disable keep-alive on connection */
                                con->keep_alive = 0;
                                p = c->mem->ptr + buffer_string_length(c->mem) - 4;
                            }
                        }
                        hsz = p + 4 - (c->mem->ptr+c->offset);
                        /* trailers currently ignored, but could be processed
                         * here if 0 == con->conf.stream_request_body, taking
                         * care to reject any fields forbidden in trailers,
                         * making trailers available to CGI and other backends*/
                    }
                    chunkqueue_mark_written(cq, (size_t)hsz);
                    con->request.content_length = dst_cq->bytes_in;
                    break; /* done reading HTTP chunked request body */
                }

                /* consume HTTP chunked header */
                chunkqueue_mark_written(cq, (size_t)hsz);
                len = cq->bytes_in - cq->bytes_out;

                if (0 !=max_request_size
                    && (max_request_size < te_chunked
                     || max_request_size - te_chunked < dst_cq->bytes_in)) {
                    log_error_write(srv, __FILE__, __LINE__, "sos",
                                    "request-size too long:",
                                    dst_cq->bytes_in + te_chunked, "-> 413");
                    /* 413 Payload Too Large */
                    return connection_handle_read_post_error(srv, con, 413);
                }

                te_chunked += 2; /*(for trailing "\r\n" after chunked data)*/

                break; /* read HTTP chunked header */
            }

            /*(likely better ways to handle chunked header crossing chunkqueue
             * chunks, but this situation is not expected to occur frequently)*/
            if ((off_t)buffer_string_length(c->mem) - c->offset >= 1024) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "chunked header line too long -> 400");
                /* 400 Bad Request */
                return connection_handle_read_post_error(srv, con, 400);
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
            else if (0 != chunkqueue_steal_with_tempfiles(srv,dst_cq,cq,len)) {
                /* 500 Internal Server Error */
                return connection_handle_read_post_error(srv, con, 500);
            }
            te_chunked -= len;
            len = cq->bytes_in - cq->bytes_out;
        }

        if (len < te_chunked) break;

        if (2 == te_chunked) {
            if (-1 == connection_handle_read_post_chunked_crlf(cq)) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "chunked data missing end CRLF -> 400");
                /* 400 Bad Request */
                return connection_handle_read_post_error(srv, con, 400);
            }
            chunkqueue_mark_written(cq, 2);/*consume \r\n at end of chunk data*/
            te_chunked -= 2;
        }

    } while (!chunkqueue_is_empty(cq));

    con->request.te_chunked = te_chunked;
    return HANDLER_GO_ON;
}

static handler_t connection_handle_read_body_unknown(server *srv, connection *con, chunkqueue *cq, chunkqueue *dst_cq) {
    /* con->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)con->conf.max_request_size << 10;
    chunkqueue_append_chunkqueue(dst_cq, cq);
    if (0 != max_request_size && dst_cq->bytes_in > max_request_size) {
        log_error_write(srv, __FILE__, __LINE__, "sos",
                        "request-size too long:", dst_cq->bytes_in, "-> 413");
        /* 413 Payload Too Large */
        return connection_handle_read_post_error(srv, con, 413);
    }
    return HANDLER_GO_ON;
}

static off_t connection_write_throttle(server *srv, connection *con, off_t max_bytes) {
	UNUSED(srv);
	if (con->conf.global_kbytes_per_second) {
		off_t limit = con->conf.global_kbytes_per_second * 1024 - *(con->conf.global_bytes_per_second_cnt_ptr);
		if (limit <= 0) {
			/* we reached the global traffic limit */
			con->traffic_limit_reached = 1;

			return 0;
		} else {
			if (max_bytes > limit) max_bytes = limit;
		}
	}

	if (con->conf.kbytes_per_second) {
		off_t limit = con->conf.kbytes_per_second * 1024 - con->bytes_written_cur_second;
		if (limit <= 0) {
			/* we reached the traffic limit */
			con->traffic_limit_reached = 1;

			return 0;
		} else {
			if (max_bytes > limit) max_bytes = limit;
		}
	}

	return max_bytes;
}

int connection_write_chunkqueue(server *srv, connection *con, chunkqueue *cq, off_t max_bytes) {
	int ret = -1;
	off_t written = 0;
      #ifdef TCP_CORK
	int corked = 0;
      #endif

	max_bytes = connection_write_throttle(srv, con, max_bytes);
	if (0 == max_bytes) return 1;

	written = cq->bytes_out;

      #ifdef TCP_CORK
	/* Linux: put a cork into socket as we want to combine write() calls
	 * but only if we really have multiple chunks including non-MEM_CHUNK,
	 * and only if TCP socket
	 */
	if (cq->first && cq->first->next) {
		const int sa_family = sock_addr_get_family(&con->srv_socket->addr);
		if (sa_family == AF_INET || sa_family == AF_INET6) {
			chunk *c = cq->first;
			while (c->type == MEM_CHUNK && NULL != (c = c->next)) ;
			if (NULL != c) {
				corked = 1;
				(void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
			}
		}
	}
      #endif

	ret = con->network_write(srv, con, cq, max_bytes);
	if (ret >= 0) {
		ret = chunkqueue_is_empty(cq) ? 0 : 1;
	}

      #ifdef TCP_CORK
	if (corked) {
		corked = 0;
		(void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
	}
      #endif

	written = cq->bytes_out - written;
	con->bytes_written += written;
	con->bytes_written_cur_second += written;
	*(con->conf.global_bytes_per_second_cnt_ptr) += written;

	return ret;
}

static int connection_write_100_continue(server *srv, connection *con) {
	/* Make best effort to send all or none of "HTTP/1.1 100 Continue" */
	/* (Note: also choosing not to update con->write_request_ts
	 *  which differs from connections.c:connection_handle_write()) */
	static const char http_100_continue[] = "HTTP/1.1 100 Continue\r\n\r\n";
	chunkqueue *cq;
	off_t written;
	int rc;

	off_t max_bytes =
	  connection_write_throttle(srv, con, sizeof(http_100_continue)-1);
	if (max_bytes < (off_t)sizeof(http_100_continue)-1) {
		return 1; /* success; skip sending if throttled to partial */
	}

	cq = con->write_queue;
	written = cq->bytes_out;

	chunkqueue_append_mem(cq,http_100_continue,sizeof(http_100_continue)-1);
	rc = con->network_write(srv, con, cq, sizeof(http_100_continue)-1);

	written = cq->bytes_out - written;
	con->bytes_written += written;
	con->bytes_written_cur_second += written;
	*(con->conf.global_bytes_per_second_cnt_ptr) += written;

	if (rc < 0) {
		connection_set_state(srv, con, CON_STATE_ERROR);
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

handler_t connection_handle_read_post_state(server *srv, connection *con) {
	chunkqueue *cq = con->read_queue;
	chunkqueue *dst_cq = con->request_content_queue;

	int is_closed = 0;

	if (con->is_readable) {
		con->read_idle_ts = srv->cur_ts;

		switch(con->network_read(srv, con, con->read_queue, MAX_READ_LIMIT)) {
		case -1:
			connection_set_state(srv, con, CON_STATE_ERROR);
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
	    && con->request.http_version != HTTP_VERSION_1_0
	    && chunkqueue_is_empty(con->write_queue) && con->is_writable) {
		buffer *vb = http_header_request_get(con, HTTP_HEADER_EXPECT, CONST_STR_LEN("Expect"));
		if (NULL != vb && buffer_eq_icase_slen(vb, CONST_STR_LEN("100-continue"))) {
			http_header_request_unset(con, HTTP_HEADER_EXPECT, CONST_STR_LEN("Expect"));
			if (!connection_write_100_continue(srv, con)) {
				return HANDLER_ERROR;
			}
		}
	}

	if (con->request.content_length < 0) {
		/*(-1: Transfer-Encoding: chunked, -2: unspecified length)*/
		handler_t rc = (-1 == con->request.content_length)
                  ? connection_handle_read_post_chunked(srv, con, cq, dst_cq)
                  : connection_handle_read_body_unknown(srv, con, cq, dst_cq);
		if (HANDLER_GO_ON != rc) return rc;
	}
	else if (con->request.content_length <= 64*1024) {
		/* don't buffer request bodies <= 64k on disk */
		chunkqueue_steal(dst_cq, cq, (off_t)con->request.content_length - dst_cq->bytes_in);
	}
	else if (0 != chunkqueue_steal_with_tempfiles(srv, dst_cq, cq, (off_t)con->request.content_length - dst_cq->bytes_in)) {
		/* writing to temp file failed */
		return connection_handle_read_post_error(srv, con, 500); /* Internal Server Error */
	}

	chunkqueue_remove_finished_chunks(cq);

	if (dst_cq->bytes_in == (off_t)con->request.content_length) {
		/* Content is ready */
		con->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
		if (con->state == CON_STATE_READ_POST) {
			connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
		}
		return HANDLER_GO_ON;
	} else if (is_closed) {
	      #if 0
		return connection_handle_read_post_error(srv, con, 400); /* Bad Request */
	      #endif
		return HANDLER_ERROR;
	} else {
		con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
		return (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
		  ? HANDLER_GO_ON
		  : HANDLER_WAIT_FOR_EVENT;
	}
}

void connection_response_reset(server *srv, connection *con) {
	UNUSED(srv);

	con->mode = DIRECT;
	con->http_status = 0;
	con->is_writable = 1;
	con->file_finished = 0;
	con->file_started = 0;
	if (con->physical.path) { /*(skip for mod_fastcgi authorizer)*/
		buffer_clear(con->physical.doc_root);
		buffer_reset(con->physical.path);
		buffer_clear(con->physical.basedir);
		buffer_reset(con->physical.rel_path);
		buffer_clear(con->physical.etag);
	}
	con->response.htags = 0;
	array_reset_data_strings(con->response.headers);
	http_response_body_clear(con, 0);
}
