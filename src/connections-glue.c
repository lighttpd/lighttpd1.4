#include "first.h"

#include "sys-socket.h"
#include "base.h"
#include "connections.h"
#include "fdevent.h"
#include "http_header.h"
#include "log.h"
#include "response.h"
#include "settings.h"   /* MAX_READ_LIMIT */

#include <stdlib.h>
#include <string.h>

const char *connection_get_state(request_state_t state) {
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

const char *connection_get_short_state(request_state_t state) {
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

__attribute_cold__
static void connection_list_resize(connections *conns) {
    conns->size += 16;
    conns->ptr   = realloc(conns->ptr, sizeof(*conns->ptr) * conns->size);
    force_assert(NULL != conns->ptr);
}

void connection_list_append(connections *conns, connection *con) {
    if (conns->used == conns->size) connection_list_resize(conns);
    conns->ptr[conns->used++] = con;
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

handler_t connection_handle_read_post_error(request_st * const r, int http_status) {
    r->keep_alive = 0;

    /*(do not change status if response headers already set and possibly sent)*/
    if (0 != r->resp_header_len) return HANDLER_ERROR;

    http_response_body_clear(r, 0);
    r->http_status = http_status;
    r->handler_module = NULL;
    return HANDLER_FINISHED;
}

static handler_t connection_handle_read_post_chunked(request_st * const r, chunkqueue * const cq, chunkqueue * const dst_cq) {

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
                        return connection_handle_read_post_error(r, 400);
                    }
                    te_chunked <<= 4;
                    te_chunked |= u;
                }
                while (*s == ' ' || *s == '\t') ++s;
                if (*s != '\r' && *s != ';') {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked header invalid chars -> 400");
                    /* 400 Bad Request */
                    return connection_handle_read_post_error(r, 400);
                }

                if (hsz >= 1024) {
                    /* prevent theoretical integer overflow
                     * casting to (size_t) and adding 2 (for "\r\n") */
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked header line too long -> 400");
                    /* 400 Bad Request */
                    return connection_handle_read_post_error(r, 400);
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
                                p = c->mem->ptr + buffer_string_length(c->mem) - 4;
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
                    return connection_handle_read_post_error(r, 413);
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
                return connection_handle_read_post_error(r, 400);
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
                return connection_handle_read_post_error(r, 500);
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
                return connection_handle_read_post_error(r, 400);
            }
            chunkqueue_mark_written(cq, 2);/*consume \r\n at end of chunk data*/
            te_chunked -= 2;
        }

    } while (!chunkqueue_is_empty(cq));

    r->te_chunked = te_chunked;
    return HANDLER_GO_ON;
}

static handler_t connection_handle_read_body_unknown(request_st * const r, chunkqueue * const cq, chunkqueue * const dst_cq) {
    /* r->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)r->conf.max_request_size << 10;
    chunkqueue_append_chunkqueue(dst_cq, cq);
    if (0 != max_request_size && dst_cq->bytes_in > max_request_size) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "request-size too long: %lld -> 413", (long long)dst_cq->bytes_in);
        /* 413 Payload Too Large */
        return connection_handle_read_post_error(r, 413);
    }
    return HANDLER_GO_ON;
}

static off_t connection_write_throttle(connection * const con, off_t max_bytes) {
	request_st * const r = &con->request;
	if (r->conf.global_bytes_per_second) {
		off_t limit = (off_t)r->conf.global_bytes_per_second - *(r->conf.global_bytes_per_second_cnt_ptr);
		if (limit <= 0) {
			/* we reached the global traffic limit */
			r->con->traffic_limit_reached = 1;

			return 0;
		} else {
			if (max_bytes > limit) max_bytes = limit;
		}
	}

	if (r->conf.bytes_per_second) {
		off_t limit = (off_t)r->conf.bytes_per_second - con->bytes_written_cur_second;
		if (limit <= 0) {
			/* we reached the traffic limit */
			r->con->traffic_limit_reached = 1;

			return 0;
		} else {
			if (max_bytes > limit) max_bytes = limit;
		}
	}

	return max_bytes;
}

int connection_write_chunkqueue(connection *con, chunkqueue *cq, off_t max_bytes) {
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
				(void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
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
		(void)setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
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

static int connection_write_100_continue(request_st * const r, connection * const con) {
	/* Make best effort to send all or none of "HTTP/1.1 100 Continue" */
	/* (Note: also choosing not to update con->write_request_ts
	 *  which differs from connection_write_chunkqueue()) */
	static const char http_100_continue[] = "HTTP/1.1 100 Continue\r\n\r\n";

	off_t max_bytes =
	  connection_write_throttle(con, sizeof(http_100_continue)-1);
	if (max_bytes < (off_t)sizeof(http_100_continue)-1) {
		return 1; /* success; skip sending if throttled to partial */
	}

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
		r->state = CON_STATE_ERROR;
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

handler_t connection_handle_read_post_state(request_st * const r) {
	connection * const con = r->con;
	chunkqueue * const cq = r->read_queue;
	chunkqueue * const dst_cq = r->reqbody_queue;

	int is_closed = 0;

	if (con->is_readable) {
		con->read_idle_ts = log_epoch_secs;

		switch(con->network_read(con, cq, MAX_READ_LIMIT)) {
		case -1:
			r->state = CON_STATE_ERROR;
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
		const buffer *vb = http_header_request_get(r, HTTP_HEADER_EXPECT, CONST_STR_LEN("Expect"));
		if (NULL != vb && buffer_eq_icase_slen(vb, CONST_STR_LEN("100-continue"))) {
			http_header_request_unset(r, HTTP_HEADER_EXPECT, CONST_STR_LEN("Expect"));
			if (!connection_write_100_continue(r, con)) {
				return HANDLER_ERROR;
			}
		}
	}

	if (r->reqbody_length < 0) {
		/*(-1: Transfer-Encoding: chunked, -2: unspecified length)*/
		handler_t rc = (-1 == r->reqbody_length)
                  ? connection_handle_read_post_chunked(r, cq, dst_cq)
                  : connection_handle_read_body_unknown(r, cq, dst_cq);
		if (HANDLER_GO_ON != rc) return rc;
	}
	else if (r->reqbody_length <= 64*1024) {
		/* don't buffer request bodies <= 64k on disk */
		chunkqueue_steal(dst_cq, cq, (off_t)r->reqbody_length - dst_cq->bytes_in);
	}
	else if (0 != chunkqueue_steal_with_tempfiles(dst_cq, cq, (off_t)r->reqbody_length - dst_cq->bytes_in, r->conf.errh)) {
		/* writing to temp file failed */
		return connection_handle_read_post_error(r, 500); /* Internal Server Error */
	}

	chunkqueue_remove_finished_chunks(cq);

	if (dst_cq->bytes_in == (off_t)r->reqbody_length) {
		/* Content is ready */
		r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
		if (r->state == CON_STATE_READ_POST) {
			r->state = CON_STATE_HANDLE_REQUEST;
		}
		return HANDLER_GO_ON;
	} else if (is_closed) {
	      #if 0
		return connection_handle_read_post_error(r, 400); /* Bad Request */
	      #endif
		return HANDLER_ERROR;
	} else {
		r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
		return (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
		  ? HANDLER_GO_ON
		  : HANDLER_WAIT_FOR_EVENT;
	}
}

void connection_response_reset(request_st * const r) {
	r->http_status = 0;
	r->con->is_writable = 1;
	r->resp_body_finished = 0;
	r->resp_body_started = 0;
	r->handler_module = NULL;
	if (r->physical.path.ptr) { /*(skip for mod_fastcgi authorizer)*/
		buffer_clear(&r->physical.doc_root);
		buffer_clear(&r->physical.basedir);
		buffer_clear(&r->physical.etag);
		buffer_reset(&r->physical.path);
		buffer_reset(&r->physical.rel_path);
	}
	r->resp_htags = 0;
	array_reset_data_strings(&r->resp_headers);
	http_response_body_clear(r, 0);
}
