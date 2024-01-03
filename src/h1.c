/*
 * h1 - HTTP/1.x protocol layer
 *
 * Copyright(c) 2023 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"
#include "h1.h"

#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"    /* FDEVENT_STREAM_REQUEST_BUFMIN */
#include "http_date.h"
#include "http_header.h"
#include "log.h"
#include "reqpool.h"    /* request_reset_ex() */
#include "request.h"
#include "response.h"   /* http_response_reqbody_read_error() */


static int
h1_send_1xx_info (request_st * const r, connection * const con)
{
    /* (Note: prior 1xx intermediate responses may be present in cq) */
    /* (Note: also choosing not to update con->write_request_ts
     *  which differs from connection_write_chunkqueue()) */
    chunkqueue * const cq = con->write_queue;
    off_t written = cq->bytes_out;

    int rc = con->network_write(con, cq, MAX_WRITE_LIMIT);

    written = cq->bytes_out - written;
    con->bytes_written_cur_second += written;
    if (r->conf.global_bytes_per_second_cnt_ptr)
        *(r->conf.global_bytes_per_second_cnt_ptr) += written;

    if (rc < 0) {
        request_set_state_error(r, CON_STATE_ERROR);
        return 0; /* error */
    }

    if (!chunkqueue_is_empty(cq)) { /* partial write (unlikely) */
        con->is_writable = 0;
        if (cq == &r->write_queue) {
            /* save partial write of 1xx in separate chunkqueue
             * Note: sending of remainder of 1xx might be delayed
             * until next set of response headers are sent */
            con->write_queue = chunkqueue_init(NULL);
            /* (copy bytes for accounting purposes in event of failure) */
            con->write_queue->bytes_in = cq->bytes_out; /*(yes, bytes_out)*/
            con->write_queue->bytes_out = cq->bytes_out;
            chunkqueue_append_chunkqueue(con->write_queue, cq);
        }
    }

  #if 0
    /* XXX: accounting inconsistency
     * 1xx is not currently included in r->resp_header_len,
     * so mod_accesslog reporting of %b or %B (FORMAT_BYTES_OUT_NO_HEADER)
     * reports all bytes out minus len of final response headers,
     * but including 1xx intermediate responses.  If 1xx intermediate
     * responses were included in r->resp_header_len, then there are a
     * few places in the code which must be adjusted to use r->resp_header_done
     * instead of (0 == r->resp_header_len) as flag that final response was set
     * (Doing the following would "discard" the 1xx len from bytes_out)
     */
    r->write_queue.bytes_in = r->write_queue.bytes_out = 0;
  #endif

    return 1; /* success */
}


__attribute_cold__
int
h1_send_1xx (request_st * const r, connection * const con)
{
    /* Make best effort to send HTTP/1.1 1xx intermediate */
    /* (Note: if other modules set response headers *before* the
     *  handle_response_start hook, and the backends subsequently sends 1xx,
     *  then the response headers are sent here with 1xx and might be cleared
     *  by caller (http_response_parse_headers() and http_response_check_1xx()),
     *  instead of being sent with the final response.
     *  (e.g. mod_magnet setting response headers, then backend sending 103)) */

    chunkqueue * const cq = con->write_queue; /*(bypass r->write_queue)*/

    buffer * const b = chunkqueue_append_buffer_open(cq);
    buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.1 "));
    http_status_append(b, r->http_status);
    for (uint32_t i = 0; i < r->resp_headers.used; ++i) {
        const data_string * const ds = (data_string *)r->resp_headers.data[i];
        const uint32_t klen = buffer_clen(&ds->key);
        const uint32_t vlen = buffer_clen(&ds->value);
        if (0 == klen || 0 == vlen) continue;
        buffer_append_str2(b, CONST_STR_LEN("\r\n"), ds->key.ptr, klen);
        buffer_append_str2(b, CONST_STR_LEN(": "), ds->value.ptr, vlen);
    }
    buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));
    chunkqueue_append_buffer_commit(cq);

    if (con->traffic_limit_reached)
        return 1; /* success; send later if throttled */

    return h1_send_1xx_info(r, con);
}


static int
h1_send_100_continue (request_st * const r, connection * const con)
{
    /* Make best effort to send "HTTP/1.1 100 Continue" */
    static const char http_100_continue[] = "HTTP/1.1 100 Continue\r\n\r\n";

    if (con->traffic_limit_reached)
        return 1; /* success; skip sending if throttled */

    chunkqueue * const cq = con->write_queue; /*(bypass r->write_queue)*/
    chunkqueue_append_mem(cq, http_100_continue, sizeof(http_100_continue)-1);
    return h1_send_1xx_info(r, con);
}


__attribute_cold__
static void
h1_send_headers_partial_1xx (request_st * const r, buffer * const b)
{
    /* take data in con->write_queue and move into b
     * (to be sent prior to final response headers in r->write_queue) */
    connection * const con = r->con;
    /*assert(&r->write_queue != con->write_queue);*/
    chunkqueue * const cq = con->write_queue;
    con->write_queue = &r->write_queue;

    /*assert(0 == buffer_clen(b));*//*expect empty buffer from caller*/
    uint32_t len = (uint32_t)chunkqueue_length(cq);
    /*(expecting MEM_CHUNK(s), so not expecting error reading files)*/
    if (chunkqueue_read_data(cq, buffer_string_prepare_append(b, len),
                             len, r->conf.errh) < 0)
        len = 0;
    buffer_truncate(b, len);/*expect initial empty buffer from caller*/
    chunkqueue_free(cq);
}


void
h1_send_headers (request_st * const r)
{
    /* disable keep-alive if requested */

    r->con->keep_alive_idle = r->conf.max_keep_alive_idle;
    if (__builtin_expect( (0 == r->conf.max_keep_alive_idle), 0)
        || r->con->request_count > r->conf.max_keep_alive_requests) {
        r->keep_alive = 0;
    }
    else if (0 != r->reqbody_length
             && r->reqbody_length != r->reqbody_queue.bytes_in
             && (NULL == r->handler_module
                 || 0 == (r->conf.stream_request_body
                          & (FDEVENT_STREAM_REQUEST
                             | FDEVENT_STREAM_REQUEST_BUFMIN)))) {
        r->keep_alive = 0;
    }

    if (light_btst(r->resp_htags, HTTP_HEADER_UPGRADE)
        && r->http_version == HTTP_VERSION_1_1) {
        http_header_response_set(r, HTTP_HEADER_CONNECTION,
                                 CONST_STR_LEN("Connection"),
                                 CONST_STR_LEN("upgrade"));
    }
    else if (r->keep_alive <= 0) {
        if (r->keep_alive < 0)
            http_response_delay(r->con);
        http_header_response_set(r, HTTP_HEADER_CONNECTION,
                                 CONST_STR_LEN("Connection"),
                                 CONST_STR_LEN("close"));
    }
    else if (r->http_version == HTTP_VERSION_1_0) {/*(&& r->keep_alive > 0)*/
        http_header_response_set(r, HTTP_HEADER_CONNECTION,
                                 CONST_STR_LEN("Connection"),
                                 CONST_STR_LEN("keep-alive"));
    }

    if (304 == r->http_status
        && light_btst(r->resp_htags, HTTP_HEADER_CONTENT_ENCODING)) {
        http_header_response_unset(r, HTTP_HEADER_CONTENT_ENCODING,
                                   CONST_STR_LEN("Content-Encoding"));
    }

    chunkqueue * const cq = &r->write_queue;
    buffer * const b = chunkqueue_prepend_buffer_open(cq);

    if (cq != r->con->write_queue)
        h1_send_headers_partial_1xx(r, b);

    buffer_append_string_len(b,
                             (r->http_version == HTTP_VERSION_1_1)
                               ? "HTTP/1.1 "
                               : "HTTP/1.0 ",
                             sizeof("HTTP/1.1 ")-1);
    http_status_append(b, r->http_status);

    /* add all headers */
    for (size_t i = 0, used = r->resp_headers.used; i < used; ++i) {
        const data_string * const ds = (data_string *)r->resp_headers.data[i];
        const uint32_t klen = buffer_clen(&ds->key);
        const uint32_t vlen = buffer_clen(&ds->value);
        if (__builtin_expect( (0 == klen), 0)) continue;
        if (__builtin_expect( (0 == vlen), 0)) continue;
        if ((ds->key.ptr[0] & 0xdf) == 'X' && http_response_omit_header(r, ds))
            continue;
        char * restrict s = buffer_extend(b, klen+vlen+4);
        s[0] = '\r';
        s[1] = '\n';
        memcpy(s+2, ds->key.ptr, klen);
        s += 2+klen;
        s[0] = ':';
        s[1] = ' ';
        memcpy(s+2, ds->value.ptr, vlen);
    }

    if (!light_btst(r->resp_htags, HTTP_HEADER_DATE)) {
        /* HTTP/1.1 and later requires a Date: header */
        /* "\r\nDate: " 8-chars + 30-chars "%a, %d %b %Y %T GMT" + '\0' */
        static unix_time64_t tlast = 0;
        static char tstr[40] = "\r\nDate: ";

        /* cache the generated timestamp */
        const unix_time64_t cur_ts = log_epoch_secs;
        if (__builtin_expect ( (tlast != cur_ts), 0))
            http_date_time_to_str(tstr+8, sizeof(tstr)-8, (tlast = cur_ts));

        buffer_append_string_len(b, tstr, 37);
    }

    if (!light_btst(r->resp_htags, HTTP_HEADER_SERVER) && r->conf.server_tag)
        buffer_append_str2(b, CONST_STR_LEN("\r\nServer: "),
                              BUF_PTR_LEN(r->conf.server_tag));

    buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));
    r->resp_header_len = buffer_clen(b);

    if (r->conf.log_response_header)
        log_debug_multiline(r->conf.errh, __FILE__, __LINE__,
                            BUF_PTR_LEN(b), "fd:%d resp: ", r->con->fd);

    chunkqueue_prepend_buffer_commit(cq);

    /*(optimization to use fewer syscalls to send a small response)*/
    off_t cqlen;
    if (r->resp_body_finished
        && light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)
        && (cqlen = chunkqueue_length(cq) - r->resp_header_len) > 0
        && cqlen < 16384)
        chunkqueue_small_resp_optim(cq);
}


__attribute_cold__
static chunk *
h1_discard_blank_line (chunkqueue * const cq, uint32_t header_len)
{
    /*(separate func only to be able to mark with compiler hint as cold)*/
    chunkqueue_mark_written(cq, header_len);
    return cq->first; /* refresh c after chunkqueue_mark_written() */
}


static chunk *
h1_recv_headers_more (connection * const con, chunkqueue * const cq, chunk *c, const size_t olen)
{
    /*(should not be reached by HTTP/2 streams)*/
    /*if (r->http_version == HTTP_VERSION_2) return NULL;*/
    /*(However, new connections over TLS may become HTTP/2 connections via ALPN
     * and return from this routine with r->http_version == HTTP_VERSION_2) */

    if ((NULL == c || NULL == c->next) && con->is_readable > 0) {
        con->read_idle_ts = log_monotonic_secs;
        if (0 != con->network_read(con, cq, MAX_READ_LIMIT)) {
            request_st * const r = &con->request;
            request_set_state_error(r, CON_STATE_ERROR);
        }
        /* check if switched to HTTP/2 (ALPN "h2" during TLS negotiation) */
        request_st * const r = &con->request;
        if (r->http_version == HTTP_VERSION_2) return NULL;
    }

    if (cq->first != cq->last && 0 != olen) {
        const size_t clen = chunkqueue_length(cq);
        size_t block = (olen + (16384-1)) & ~(16384-1);
        block += (block - olen > 1024 ? 0 : 16384);
        chunkqueue_compact_mem(cq, block > clen ? clen : block);
    }

    /* detect if data is added to chunk */
    c = cq->first;
    return (c && (size_t)c->offset + olen < buffer_clen(c->mem))
      ? c
      : NULL;
}


#include "plugin_config.h" /* COMP_SERVER_SOCKET COMP_HTTP_REMOTE_IP */

__attribute_cold__
static int
h1_check_upgrade (request_st * const r, connection * const con)
{
    buffer *upgrade = http_header_request_get(r, HTTP_HEADER_UPGRADE,
                                              CONST_STR_LEN("Upgrade"));
  #ifdef __COVERITY__
    if (NULL == upgrade) return 0; /*(checked by caller)*/
  #endif

    buffer * const http_connection =
      http_header_request_get(r, HTTP_HEADER_CONNECTION,
                              CONST_STR_LEN("Connection"));
    if (NULL == http_connection) {
        http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                                  CONST_STR_LEN("Upgrade"));
        return 0;
    }

    if (r->http_version == HTTP_VERSION_1_1) {
        /* Upgrade: websocket (not handled here)
         * (potentially handled by modules elsewhere) */

        if (!http_header_str_contains_token(BUF_PTR_LEN(upgrade),
                                            CONST_STR_LEN("h2c")))
            return 0; /*(preserve Connection and Upgrade as-is)*/

        /* Upgrade: h2c
         * RFC7540 3.2 Starting HTTP/2 for "http" URIs */

        if (http_header_str_contains_token(BUF_PTR_LEN(http_connection),
                                           CONST_STR_LEN("HTTP2-Settings"))) {
            if (http_dispatch[HTTP_VERSION_2].upgrade_h2c)
                http_dispatch[HTTP_VERSION_2].upgrade_h2c(r, con);
        } /*else ignore Upgrade: h2c; HTTP2-Settings required for Upgrade: h2c*/
        /*(remove "HTTP2-Settings", even if not listed in "Connection")*/
        http_header_request_unset(r, HTTP_HEADER_HTTP2_SETTINGS,
                                  CONST_STR_LEN("HTTP2-Settings"));
        http_header_remove_token(http_connection,
                                 CONST_STR_LEN("HTTP2-Settings"));
    } /*(else invalid with HTTP/1.0; remove Connection and Upgrade)*/

    http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                              CONST_STR_LEN("Upgrade"));
    http_header_remove_token(http_connection, CONST_STR_LEN("Upgrade"));

    if (r->http_version != HTTP_VERSION_2)
        return 0;

    /*(Upgrade: h2c over cleartext does not have SNI; no COMP_HTTP_HOST)*/
    r->conditional_is_valid = (1 << COMP_SERVER_SOCKET)
                            | (1 << COMP_HTTP_REMOTE_IP);
    /*connection_handle_write(r, con);*//* defer write to network */
    return 1;
}


int
h1_recv_headers (request_st * const r, connection * const con)
{
    chunkqueue * const cq = con->read_queue;
    chunk *c = cq->first;
    uint32_t clen = 0;
    uint32_t header_len = 0;
    uint8_t keepalive_request_start = 0;
    uint8_t pipelined_request_start = 0;
    uint8_t discard_blank = 0;
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */

    if (con->request_count > 1) {
        discard_blank = 1;
        if (cq->bytes_in == r->x.h1.bytes_read_ckpt) {
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
        clen = buffer_clen(c->mem) - c->offset;
        if (0 == clen) continue;
        if (__builtin_expect( (c->offset > USHRT_MAX), 0)) /*(highly unlikely)*/
            chunkqueue_compact_mem_offset(cq);

        hoff[0] = 1;                         /* number of lines */
        hoff[1] = (unsigned short)c->offset; /* base offset for all lines */
        /*hoff[2] = ...;*/                   /* offset from base for 2nd line */

        header_len = http_header_parse_hoff(c->mem->ptr + c->offset,clen,hoff);

        /* casting to (unsigned short) might truncate, and the hoff[]
         * addition might overflow, but max_request_field_size is USHRT_MAX,
         * so failure will be detected below */
        const uint32_t max_request_field_size = r->conf.max_request_field_size;
        if ((header_len ? header_len : clen) > max_request_field_size
            || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1) {
            log_error(r->conf.errh, __FILE__, __LINE__, "%s",
                      "oversized request-header -> sending Status 431");
            r->http_status = 431; /* Request Header Fields Too Large */
            r->keep_alive = 0;
            return 1;
        }

        if (__builtin_expect( (0 != header_len), 1)) {
            if (__builtin_expect( (hoff[0] > 1), 1))
                break; /* common case; request headers complete */

            if (discard_blank) { /* skip one blank line e.g. following POST */
                if (header_len == clen) continue;
                const int ch = c->mem->ptr[c->offset+header_len];
                if (ch != '\r' && ch != '\n') {
                    /* discard prior blank line if next line is not blank */
                    discard_blank = 0;
                    clen = 0;/*(for h1_recv_headers_more() to return c)*/
                    c = h1_discard_blank_line(cq, header_len);/*cold*/
                    continue;
                } /*(else fall through to error out in next block)*/
            }
        }

        if (((unsigned char *)c->mem->ptr)[c->offset] < 32) {
            /* expecting ASCII method beginning with alpha char
             * or HTTP/2 pseudo-header beginning with ':' */
            /*(TLS handshake begins with SYN 0x16 (decimal 22))*/
            log_error(r->conf.errh, __FILE__, __LINE__, "%s (%s)",
                      c->mem->ptr[c->offset] == 0x16
                      ? "unexpected TLS ClientHello on clear port"
                      : "invalid request-line -> sending Status 400",
                      con->dst_addr_buf.ptr);
            r->http_status = 400; /* Bad Request */
            r->keep_alive = 0;
            return 1;
        }
    } while ((c = h1_recv_headers_more(con, cq, c, clen)));

    if (keepalive_request_start) {
        if (cq->bytes_in > r->x.h1.bytes_read_ckpt) {
            /* update r->start_hp.tv_sec timestamp when first byte of
             * next request is received on a keep-alive connection */
            r->start_hp.tv_sec = log_epoch_secs;
            if (r->conf.high_precision_timestamps)
                log_clock_gettime_realtime(&r->start_hp);
        }
        if (pipelined_request_start && c)
            con->read_idle_ts = log_monotonic_secs;
    }

    if (NULL == c) return 0; /* incomplete request headers */

  #ifdef __COVERITY__
    if (buffer_clen(c->mem) < hoff[1]) {
        return 1;
    }
  #endif

    char * const hdrs = c->mem->ptr + hoff[1];

    if (con->request_count > 1) {
        /* adjust r->x.h1.bytes_read_ckpt for http_request_stats_bytes_in()
         * (headers_len is still in cq; marked written, bytes_out incr below) */
        r->x.h1.bytes_read_ckpt = cq->bytes_out;
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
        log_debug_multiline(r->conf.errh, __FILE__, __LINE__,
                            hdrs, header_len, "fd:%d rqst: ", con->fd);
    http_request_headers_process(r, hdrs, hoff, con->proto_default_port);
    chunkqueue_mark_written(cq, r->rqst_header_len);

    if (light_btst(r->rqst_htags, HTTP_HEADER_UPGRADE)
        && 0 == r->http_status
        && h1_check_upgrade(r, con))
        return 0;

    return 1;
}


__attribute_cold__
static int
h1_check_expect_100 (request_st * const r, connection * const con)
{
    if (con->is_writable <= 0)
        return 1;

    const buffer * const vb =
      http_header_request_get(r, HTTP_HEADER_EXPECT,
                              CONST_STR_LEN("Expect"));
    if (NULL == vb)
        return 1;

    /* (always unset Expect header so that check is not repeated for request */
    int rc = buffer_eq_icase_slen(vb, CONST_STR_LEN("100-continue"));
    http_header_request_unset(r, HTTP_HEADER_EXPECT,
                              CONST_STR_LEN("Expect"));
    if (!rc
        || 0 != r->reqbody_queue.bytes_in
        || !chunkqueue_is_empty(&r->read_queue)
        || !chunkqueue_is_empty(&r->write_queue)
        || r->http_version == HTTP_VERSION_1_0)
        return 1;

    /* send 100 Continue only if no request body data received yet
     * and response has not yet started (checked above) */
    return h1_send_100_continue(r, con);
}


static int
h1_cq_compact (chunkqueue * const cq)
{
    /* combine first mem chunk with next non-empty mem chunk
     * (loop if next chunk is empty) */
    chunk *c = cq->first;
    if (NULL == c) return 0;
    const uint32_t mlen = buffer_clen(c->mem) - (size_t)c->offset;
    while ((c = c->next)) {
        const uint32_t blen = buffer_clen(c->mem) - (size_t)c->offset;
        if (0 == blen) continue;
        chunkqueue_compact_mem(cq, mlen + blen);
        return 1;
    }
    return 0;
}


__attribute_pure__
static int
h1_chunked_crlf (chunkqueue * const cq)
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
    len = buffer_clen(b) - (size_t)c->offset;
    if (1 != len) return -1; /* error */

    while (NULL != (c = c->next)) {
        b = c->mem;
        len = buffer_clen(b) - (size_t)c->offset;
        if (0 == len) continue;
        p = b->ptr+c->offset;
        return (p[0] == '\n') ? 1 : -1; /* error if not '\n' */
    }
    return 0;
}


static handler_t
h1_chunked (request_st * const r, chunkqueue * const cq, chunkqueue * const dst_cq)
{
    /* r->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)r->conf.max_request_size << 10;
    off_t te_chunked = r->x.h1.te_chunked;
    do {
        off_t len = chunkqueue_length(cq);

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
                    if (te_chunked > (off_t)(1uLL<<(8*sizeof(off_t)-5))-1-2) {
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
                        } while (NULL == p && h1_cq_compact(cq));
                        if (NULL == p) {
                            /*(effectively doubles max request field size
                             * potentially received by backend, if in the future
                             * these trailers are added to request headers)*/
                            if ((off_t)buffer_clen(c->mem) - c->offset
                                < (off_t)r->conf.max_request_field_size) {
                                break;
                            }
                            else {
                                /* ignore excessively long trailers;
                                 * disable keep-alive on connection */
                                r->keep_alive = 0;
                                p = c->mem->ptr + buffer_clen(c->mem)
                                  - 4;
                            }
                        }
                        hsz = p + 4 - (c->mem->ptr+c->offset);
                        /* trailers currently ignored, but could be processed
                         * here if 0 == (r->conf.stream_request_body &
                         *               & (FDEVENT_STREAM_REQUEST
                         *                 |FDEVENT_STREAM_REQUEST_BUFMIN))
                         * taking care to reject fields forbidden in trailers,
                         * making trailers available to CGI and other backends*/
                    }
                    chunkqueue_mark_written(cq, (size_t)hsz);
                    r->reqbody_length = dst_cq->bytes_in;
                    break; /* done reading HTTP chunked request body */
                }

                /* consume HTTP chunked header */
                chunkqueue_mark_written(cq, (size_t)hsz);
                len = chunkqueue_length(cq);

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
            if ((off_t)buffer_clen(c->mem) - c->offset >= 1024) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "chunked header line too long -> 400");
                /* 400 Bad Request */
                return http_response_reqbody_read_error(r, 400);
            }
            else if (!h1_cq_compact(cq)) {
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
            len = chunkqueue_length(cq);
        }

        if (len < te_chunked) break;

        if (2 == te_chunked) {
            if (-1 == h1_chunked_crlf(cq)) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "chunked data missing end CRLF -> 400");
                /* 400 Bad Request */
                return http_response_reqbody_read_error(r, 400);
            }
            chunkqueue_mark_written(cq, 2);/*consume \r\n at end of chunk data*/
            te_chunked -= 2;
        }

    } while (!chunkqueue_is_empty(cq));

    r->x.h1.te_chunked = te_chunked;
    return HANDLER_GO_ON;
}


static handler_t
h1_read_body_unknown (request_st * const r, chunkqueue * const cq, chunkqueue * const dst_cq)
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


handler_t
h1_reqbody_read (request_st * const r)
{
    connection * const con = r->con;
    chunkqueue * const cq = &r->read_queue;
    chunkqueue * const dst_cq = &r->reqbody_queue;

    int is_closed = 0;

    if (con->is_readable > 0) {
        con->read_idle_ts = log_monotonic_secs;
        const off_t max_per_read =
          !(r->conf.stream_request_body /*(if not streaming request body)*/
            & (FDEVENT_STREAM_REQUEST|FDEVENT_STREAM_REQUEST_BUFMIN))
            ? MAX_READ_LIMIT
            : (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN)
              ? 16384  /* FDEVENT_STREAM_REQUEST_BUFMIN */
              : 65536; /* FDEVENT_STREAM_REQUEST */
        switch(con->network_read(con, cq, max_per_read)) {
        case -1:
            request_set_state_error(r, CON_STATE_ERROR);
            return HANDLER_ERROR;
        case -2:
            is_closed = 1;
            break;
        default:
            break;
        }

        chunkqueue_remove_finished_chunks(cq);
    }

    /* Check for Expect: 100-continue in request headers */
    if (light_btst(r->rqst_htags, HTTP_HEADER_EXPECT)
        && !h1_check_expect_100(r, con))
        return HANDLER_ERROR;

    if (r->reqbody_length < 0) {
        /*(-1: Transfer-Encoding: chunked, -2: unspecified length)*/
        handler_t rc = (-1 == r->reqbody_length)
                     ? h1_chunked(r, cq, dst_cq)
                     : h1_read_body_unknown(r, cq, dst_cq);
        if (HANDLER_GO_ON != rc) return rc;
        chunkqueue_remove_finished_chunks(cq);
    }
    else {
        off_t len = (off_t)r->reqbody_length - dst_cq->bytes_in;
        if (r->reqbody_length <= 64*1024) {
            /* don't buffer request bodies <= 64k on disk */
            chunkqueue_steal(dst_cq, cq, len);
        }
        else if (chunkqueue_length(dst_cq) + len <= 64*1024
                 && (!dst_cq->first || dst_cq->first->type == MEM_CHUNK)) {
            /* avoid tempfiles when streaming request body to fast backend */
            chunkqueue_steal(dst_cq, cq, len);
        }
        else if (0 !=
                 chunkqueue_steal_with_tempfiles(dst_cq,cq,len,r->conf.errh)) {
            /* writing to temp file failed */ /* Internal Server Error */
            return http_response_reqbody_read_error(r, 500);
        }
        chunkqueue_remove_finished_chunks(cq);
    }

    if (dst_cq->bytes_in == (off_t)r->reqbody_length) {
        /* Content is ready */
        r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
        if (r->state == CON_STATE_READ_POST) {
            request_set_state(r, CON_STATE_HANDLE_REQUEST);
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


/* keep in sync with connections.c */
#define HTTP_LINGER_TIMEOUT 5

int
h1_check_timeout (connection * const con, const unix_time64_t cur_ts)
{
    request_st * const r = &con->request;
    const int waitevents = fdevent_fdnode_interest(con->fdn);
    int changed = 0;

    if (r->state == CON_STATE_CLOSE) {
        if (cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT)
            changed = 1;
    }
    else if (waitevents & FDEVENT_IN) {
        /* keep-alive or else expect CON_STATE_READ_POST || CON_STATE_WRITE */
        int keep_alive = con->request_count != 1 && r->state == CON_STATE_READ;
        int idle_timeout = keep_alive
          ? con->keep_alive_idle
          : (int)r->conf.max_read_idle;
        if (cur_ts - con->read_idle_ts > idle_timeout) {
            if (r->conf.log_timeouts)
                log_debug(r->conf.errh, __FILE__, __LINE__,
                  "connection closed - %s timeout: %d",
                  keep_alive ? "keep-alive" : "read", con->fd);
            request_set_state_error(r, CON_STATE_ERROR);
            changed = 1;
        }
    }

    /* max_write_idle timeout currently functions as backend timeout,
     * too, after response has been started.
     * Although backend timeouts now exist, there is no default for timeouts
     * to backends, so were this client timeout now to be changed to check
     * for write interest to the client, then timeout would not occur if the
     * backend hung and there was no backend read timeout set.  Therefore,
     * max_write_idle timeout remains timeout for both reading from backend
     * and writing to client, though this check here is only for HTTP/1.1.
     * In the future, if there were a quick way to detect that a backend
     * read timeout was in effect, then this timeout could check for write
     * interest to client.  (not a priority) */
    /*if (waitevents & FDEVENT_OUT)*/
    if (r->http_version <= HTTP_VERSION_1_1 /*(func reused by h2, h3)*/
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
                log_debug(r->conf.errh, __FILE__, __LINE__,
                  "NOTE: a request from %s for %.*s timed out after writing "
                  "%lld bytes. We waited %d seconds. If this is a problem, "
                  "increase server.max-write-idle",
                  r->dst_addr_buf->ptr,
                  BUFFER_INTLEN_PTR(&r->target),
                  (long long)con->write_queue->bytes_out,
                  (int)r->conf.max_write_idle);
            }
            request_set_state_error(r, CON_STATE_ERROR);
            changed = 1;
        }
    }

    return changed;
}
