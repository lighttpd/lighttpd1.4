/*
 * h2 - HTTP/2 protocol layer
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"
#include "h2.h"

#ifndef _WIN32
#include <arpa/inet.h>  /* htonl() */
#else
#include <winsock2.h>   /* htonl() */
#endif
#include <stdint.h>     /* INT32_MAX INT32_MIN */
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"    /* FDEVENT_STREAM_REQUEST_BUFMIN */
#include "http_date.h"
#include "http_header.h"
#include "http_status.h"
#include "log.h"
#include "request.h"
#include "response.h"   /* http_dispatch[] http_response_omit_header() */


/* lowercased field-names
 * (32-byte record (power-2) and single block of memory for memory locality) */
static const char http_header_lc[][32] = {
  [HTTP_HEADER_OTHER]                     = ""
 ,[HTTP_HEADER_ACCEPT]                    = "accept"
 ,[HTTP_HEADER_ACCEPT_ENCODING]           = "accept-encoding"
 ,[HTTP_HEADER_ACCEPT_LANGUAGE]           = "accept-language"
 ,[HTTP_HEADER_ACCEPT_RANGES]             = "accept-ranges"
 ,[HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]="access-control-allow-origin"
 ,[HTTP_HEADER_AGE]                       = "age"
 ,[HTTP_HEADER_ALLOW]                     = "allow"
 ,[HTTP_HEADER_ALT_SVC]                   = "alt-svc"
 ,[HTTP_HEADER_ALT_USED]                  = "alt-used"
 ,[HTTP_HEADER_AUTHORIZATION]             = "authorization"
 ,[HTTP_HEADER_CACHE_CONTROL]             = "cache-control"
 ,[HTTP_HEADER_CONNECTION]                = "connection"
 ,[HTTP_HEADER_CONTENT_ENCODING]          = "content-encoding"
 ,[HTTP_HEADER_CONTENT_LENGTH]            = "content-length"
 ,[HTTP_HEADER_CONTENT_LOCATION]          = "content-location"
 ,[HTTP_HEADER_CONTENT_RANGE]             = "content-range"
 ,[HTTP_HEADER_CONTENT_SECURITY_POLICY]   = "content-security-policy"
 ,[HTTP_HEADER_CONTENT_TYPE]              = "content-type"
 ,[HTTP_HEADER_COOKIE]                    = "cookie"
 ,[HTTP_HEADER_DATE]                      = "date"
 ,[HTTP_HEADER_DNT]                       = "dnt"
 ,[HTTP_HEADER_ETAG]                      = "etag"
 ,[HTTP_HEADER_EXPECT]                    = "expect"
 ,[HTTP_HEADER_EXPIRES]                   = "expires"
 ,[HTTP_HEADER_FORWARDED]                 = "forwarded"
 ,[HTTP_HEADER_HOST]                      = "host"
 ,[HTTP_HEADER_HTTP2_SETTINGS]            = "http2-settings"
 ,[HTTP_HEADER_IF_MATCH]                  = "if-match"
 ,[HTTP_HEADER_IF_MODIFIED_SINCE]         = "if-modified-since"
 ,[HTTP_HEADER_IF_NONE_MATCH]             = "if-none-match"
 ,[HTTP_HEADER_IF_RANGE]                  = "if-range"
 ,[HTTP_HEADER_IF_UNMODIFIED_SINCE]       = "if-unmodified-since"
 ,[HTTP_HEADER_INCREMENTAL]               = "incremental"
 ,[HTTP_HEADER_LAST_MODIFIED]             = "last-modified"
 ,[HTTP_HEADER_LINK]                      = "link"
 ,[HTTP_HEADER_LOCATION]                  = "location"
 ,[HTTP_HEADER_ONION_LOCATION]            = "onion-location"
 ,[HTTP_HEADER_P3P]                       = "p3p"
 ,[HTTP_HEADER_PRAGMA]                    = "pragma"
 ,[HTTP_HEADER_PRIORITY]                  = "priority"
 ,[HTTP_HEADER_RANGE]                     = "range"
 ,[HTTP_HEADER_REFERER]                   = "referer"
 ,[HTTP_HEADER_REFERRER_POLICY]           = "referrer-policy"
 ,[HTTP_HEADER_SERVER]                    = "server"
 ,[HTTP_HEADER_SET_COOKIE]                = "set-cookie"
 ,[HTTP_HEADER_STATUS]                    = "status"
 ,[HTTP_HEADER_STRICT_TRANSPORT_SECURITY] = "strict-transport-security"
 ,[HTTP_HEADER_TE]                        = "te"
 ,[HTTP_HEADER_TRANSFER_ENCODING]         = "transfer-encoding"
 ,[HTTP_HEADER_UPGRADE]                   = "upgrade"
 ,[HTTP_HEADER_UPGRADE_INSECURE_REQUESTS] = "upgrade-insecure-requests"
 ,[HTTP_HEADER_USER_AGENT]                = "user-agent"
 ,[HTTP_HEADER_VARY]                      = "vary"
 ,[HTTP_HEADER_WWW_AUTHENTICATE]          = "www-authenticate"
 ,[HTTP_HEADER_X_CONTENT_TYPE_OPTIONS]    = "x-content-type-options"
 ,[HTTP_HEADER_X_FORWARDED_FOR]           = "x-forwarded-for"
 ,[HTTP_HEADER_X_FORWARDED_PROTO]         = "x-forwarded-proto"
 ,[HTTP_HEADER_X_FRAME_OPTIONS]           = "x-frame-options"
 ,[HTTP_HEADER_X_XSS_PROTECTION]          = "x-xss-protection"
};


/* future optimization: could conceivably store static XXH32() hash values for
 * field-name (e.g. for benefit of entries marked LSHPACK_HDR_UNKNOWN) to
 * incrementally reduce cost of calculating hash values for field-name on each
 * request where those headers are used.  Might also store single element
 * static caches for "date:" value (updated each time static buffer is updated)
 * and for "server:" value (often global to server), keyed on r->conf.server_tag
 * pointer addr.  HTTP_HEADER_STATUS could be overloaded for ":status", since
 * lighttpd should not send "Status:" response header (should not happen) */

static const uint8_t http_header_lshpack_idx[] = {
  [HTTP_HEADER_OTHER]                     = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_ACCEPT_ENCODING]           = LSHPACK_HDR_ACCEPT_ENCODING
 ,[HTTP_HEADER_AUTHORIZATION]             = LSHPACK_HDR_AUTHORIZATION
 ,[HTTP_HEADER_CACHE_CONTROL]             = LSHPACK_HDR_CACHE_CONTROL
 ,[HTTP_HEADER_CONNECTION]                = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_CONTENT_ENCODING]          = LSHPACK_HDR_CONTENT_ENCODING
 ,[HTTP_HEADER_CONTENT_LENGTH]            = LSHPACK_HDR_CONTENT_LENGTH
 ,[HTTP_HEADER_CONTENT_LOCATION]          = LSHPACK_HDR_CONTENT_LOCATION
 ,[HTTP_HEADER_CONTENT_TYPE]              = LSHPACK_HDR_CONTENT_TYPE
 ,[HTTP_HEADER_COOKIE]                    = LSHPACK_HDR_COOKIE
 ,[HTTP_HEADER_DATE]                      = LSHPACK_HDR_DATE
 ,[HTTP_HEADER_ETAG]                      = LSHPACK_HDR_ETAG
 ,[HTTP_HEADER_EXPECT]                    = LSHPACK_HDR_EXPECT
 ,[HTTP_HEADER_FORWARDED]                 = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_HOST]                      = LSHPACK_HDR_HOST
 ,[HTTP_HEADER_IF_MODIFIED_SINCE]         = LSHPACK_HDR_IF_MODIFIED_SINCE
 ,[HTTP_HEADER_IF_NONE_MATCH]             = LSHPACK_HDR_IF_NONE_MATCH
 ,[HTTP_HEADER_LAST_MODIFIED]             = LSHPACK_HDR_LAST_MODIFIED
 ,[HTTP_HEADER_LOCATION]                  = LSHPACK_HDR_LOCATION
 ,[HTTP_HEADER_RANGE]                     = LSHPACK_HDR_RANGE
 ,[HTTP_HEADER_SERVER]                    = LSHPACK_HDR_SERVER
 ,[HTTP_HEADER_SET_COOKIE]                = LSHPACK_HDR_SET_COOKIE
 ,[HTTP_HEADER_STATUS]                    = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_TRANSFER_ENCODING]         = LSHPACK_HDR_TRANSFER_ENCODING
 ,[HTTP_HEADER_UPGRADE]                   = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_USER_AGENT]                = LSHPACK_HDR_USER_AGENT
 ,[HTTP_HEADER_VARY]                      = LSHPACK_HDR_VARY
 ,[HTTP_HEADER_X_FORWARDED_FOR]           = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_X_FORWARDED_PROTO]         = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_HTTP2_SETTINGS]            = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_ACCEPT]                    = LSHPACK_HDR_ACCEPT
 ,[HTTP_HEADER_ACCEPT_LANGUAGE]           = LSHPACK_HDR_ACCEPT_LANGUAGE
 ,[HTTP_HEADER_ACCEPT_RANGES]             = LSHPACK_HDR_ACCEPT_RANGES
 ,[HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]=LSHPACK_HDR_ACCESS_CONTROL_ALLOW_ORIGIN
 ,[HTTP_HEADER_AGE]                       = LSHPACK_HDR_AGE
 ,[HTTP_HEADER_ALLOW]                     = LSHPACK_HDR_ALLOW
 ,[HTTP_HEADER_ALT_SVC]                   = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_ALT_USED]                  = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_CONTENT_RANGE]             = LSHPACK_HDR_CONTENT_RANGE
 ,[HTTP_HEADER_CONTENT_SECURITY_POLICY]   = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_DNT]                       = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_EXPIRES]                   = LSHPACK_HDR_EXPIRES
 ,[HTTP_HEADER_IF_MATCH]                  = LSHPACK_HDR_IF_MATCH
 ,[HTTP_HEADER_IF_RANGE]                  = LSHPACK_HDR_IF_RANGE
 ,[HTTP_HEADER_IF_UNMODIFIED_SINCE]       = LSHPACK_HDR_IF_UNMODIFIED_SINCE
 ,[HTTP_HEADER_LINK]                      = LSHPACK_HDR_LINK
 ,[HTTP_HEADER_ONION_LOCATION]            = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_P3P]                       = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_PRAGMA]                    = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_PRIORITY]                  = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_REFERER]                   = LSHPACK_HDR_REFERER
 ,[HTTP_HEADER_REFERRER_POLICY]           = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_STRICT_TRANSPORT_SECURITY] = LSHPACK_HDR_STRICT_TRANSPORT_SECURITY
 ,[HTTP_HEADER_TE]                        = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_UPGRADE_INSECURE_REQUESTS] = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_WWW_AUTHENTICATE]          = LSHPACK_HDR_WWW_AUTHENTICATE
 ,[HTTP_HEADER_X_CONTENT_TYPE_OPTIONS]    = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_X_FRAME_OPTIONS]           = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_X_XSS_PROTECTION]          = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_INCREMENTAL]               = LSHPACK_HDR_UNKNOWN
};


/* Note: must be kept in sync with ls-hpack/lshpack.h:lshpack_static_hdr_idx[]*/
static const int8_t lshpack_idx_http_header[] = {
  [LSHPACK_HDR_UNKNOWN]                   = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_AUTHORITY]                 = HTTP_HEADER_H2_AUTHORITY
 ,[LSHPACK_HDR_METHOD_GET]                = HTTP_HEADER_H2_METHOD
 ,[LSHPACK_HDR_METHOD_POST]               = HTTP_HEADER_H2_METHOD
 ,[LSHPACK_HDR_PATH]                      = HTTP_HEADER_H2_PATH
 ,[LSHPACK_HDR_PATH_INDEX_HTML]           = HTTP_HEADER_H2_PATH
 ,[LSHPACK_HDR_SCHEME_HTTP]               = HTTP_HEADER_H2_SCHEME
 ,[LSHPACK_HDR_SCHEME_HTTPS]              = HTTP_HEADER_H2_SCHEME
 ,[LSHPACK_HDR_STATUS_200]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_STATUS_204]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_STATUS_206]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_STATUS_304]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_STATUS_400]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_STATUS_404]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_STATUS_500]                = HTTP_HEADER_H2_UNKNOWN
 ,[LSHPACK_HDR_ACCEPT_CHARSET]            = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_ACCEPT_ENCODING]           = HTTP_HEADER_ACCEPT_ENCODING
 ,[LSHPACK_HDR_ACCEPT_LANGUAGE]           = HTTP_HEADER_ACCEPT_LANGUAGE
 ,[LSHPACK_HDR_ACCEPT_RANGES]             = HTTP_HEADER_ACCEPT_RANGES
 ,[LSHPACK_HDR_ACCEPT]                    = HTTP_HEADER_ACCEPT
 ,[LSHPACK_HDR_ACCESS_CONTROL_ALLOW_ORIGIN]=HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN
 ,[LSHPACK_HDR_AGE]                       = HTTP_HEADER_AGE
 ,[LSHPACK_HDR_ALLOW]                     = HTTP_HEADER_ALLOW
 ,[LSHPACK_HDR_AUTHORIZATION]             = HTTP_HEADER_AUTHORIZATION
 ,[LSHPACK_HDR_CACHE_CONTROL]             = HTTP_HEADER_CACHE_CONTROL
 ,[LSHPACK_HDR_CONTENT_DISPOSITION]       = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_CONTENT_ENCODING]          = HTTP_HEADER_CONTENT_ENCODING
 ,[LSHPACK_HDR_CONTENT_LANGUAGE]          = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_CONTENT_LENGTH]            = HTTP_HEADER_CONTENT_LENGTH
 ,[LSHPACK_HDR_CONTENT_LOCATION]          = HTTP_HEADER_CONTENT_LOCATION
 ,[LSHPACK_HDR_CONTENT_RANGE]             = HTTP_HEADER_CONTENT_RANGE
 ,[LSHPACK_HDR_CONTENT_TYPE]              = HTTP_HEADER_CONTENT_TYPE
 ,[LSHPACK_HDR_COOKIE]                    = HTTP_HEADER_COOKIE
 ,[LSHPACK_HDR_DATE]                      = HTTP_HEADER_DATE
 ,[LSHPACK_HDR_ETAG]                      = HTTP_HEADER_ETAG
 ,[LSHPACK_HDR_EXPECT]                    = HTTP_HEADER_EXPECT
 ,[LSHPACK_HDR_EXPIRES]                   = HTTP_HEADER_EXPIRES
 ,[LSHPACK_HDR_FROM]                      = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_HOST]                      = HTTP_HEADER_HOST
 ,[LSHPACK_HDR_IF_MATCH]                  = HTTP_HEADER_IF_MATCH
 ,[LSHPACK_HDR_IF_MODIFIED_SINCE]         = HTTP_HEADER_IF_MODIFIED_SINCE
 ,[LSHPACK_HDR_IF_NONE_MATCH]             = HTTP_HEADER_IF_NONE_MATCH
 ,[LSHPACK_HDR_IF_RANGE]                  = HTTP_HEADER_IF_RANGE
 ,[LSHPACK_HDR_IF_UNMODIFIED_SINCE]       = HTTP_HEADER_IF_UNMODIFIED_SINCE
 ,[LSHPACK_HDR_LAST_MODIFIED]             = HTTP_HEADER_LAST_MODIFIED
 ,[LSHPACK_HDR_LINK]                      = HTTP_HEADER_LINK
 ,[LSHPACK_HDR_LOCATION]                  = HTTP_HEADER_LOCATION
 ,[LSHPACK_HDR_MAX_FORWARDS]              = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_PROXY_AUTHENTICATE]        = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_PROXY_AUTHORIZATION]       = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_RANGE]                     = HTTP_HEADER_RANGE
 ,[LSHPACK_HDR_REFERER]                   = HTTP_HEADER_REFERER
 ,[LSHPACK_HDR_REFRESH]                   = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_RETRY_AFTER]               = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_SERVER]                    = HTTP_HEADER_SERVER
 ,[LSHPACK_HDR_SET_COOKIE]                = HTTP_HEADER_SET_COOKIE
 ,[LSHPACK_HDR_STRICT_TRANSPORT_SECURITY] = HTTP_HEADER_STRICT_TRANSPORT_SECURITY
 ,[LSHPACK_HDR_TRANSFER_ENCODING]         = HTTP_HEADER_TRANSFER_ENCODING
 ,[LSHPACK_HDR_USER_AGENT]                = HTTP_HEADER_USER_AGENT
 ,[LSHPACK_HDR_VARY]                      = HTTP_HEADER_VARY
 ,[LSHPACK_HDR_VIA]                       = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_WWW_AUTHENTICATE]          = HTTP_HEADER_WWW_AUTHENTICATE
};


__attribute_returns_nonnull__
static request_st * h2_init_stream (request_st * const h2r, connection * const con);


__attribute_pure__
static inline uint32_t
h2_u32 (const uint8_t * const s)
{
    return ((uint32_t)s[0] << 24)
         | ((uint32_t)s[1] << 16)
         | ((uint32_t)s[2] <<  8)
         |  (uint32_t)s[3];
}


__attribute_pure__
static inline uint32_t
h2_u31 (const uint8_t * const s)
{
    return h2_u32(s) & ~0x80000000u;
}


__attribute_pure__
static inline uint32_t
h2_u24 (const uint8_t * const s)
{
  #if 1
    /* XXX: optimization is valid only for how this is used in h2.c
     * where we have checked that frame header received is at least
     * 9 chars, and where s containing frame length (3-bytes) is
     * followed by at least 1 additional char. */
    return h2_u32(s) >> 8;
  #else
    return ((uint32_t)s[0] << 16)
         | ((uint32_t)s[1] <<  8)
         |  (uint32_t)s[2];
  #endif
}


__attribute_pure__
static inline uint16_t
h2_u16 (const uint8_t * const s)
{
    return ((uint16_t)s[0] << 8)
         |  (uint16_t)s[1];
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_pure__
static request_st *
h2_get_stream_req (const h2con * const h2c, const uint32_t h2id)
{
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const r = h2c->r[i];
        if (r->x.h2.id == h2id) return r;
    }
    return NULL;
}


static void
h2_send_settings_ack (connection * const con)
{
    static const uint8_t settings_ack[] = {
      /* SETTINGS w/ ACK */
      0x00, 0x00, 0x00        /* frame length */
     ,H2_FTYPE_SETTINGS       /* frame type */
     ,H2_FLAG_ACK             /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier */
    };

    chunkqueue_append_mem(con->write_queue,
                          (const char *)settings_ack, sizeof(settings_ack));
}


__attribute_cold__
static void
h2_send_rst_stream_id (uint32_t h2id, connection * const con, const request_h2error_t e)
{
    union {
      uint8_t c[16];
      uint32_t u[4];          /*(alignment)*/
    } rst_stream = { {        /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* RST_STREAM */
     ,0x00, 0x00, 0x04        /* frame length */
     ,H2_FTYPE_RST_STREAM     /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier (fill in below) */
     ,0x00, 0x00, 0x00, 0x00  /* error code;       (fill in below) */
    } };

    rst_stream.u[2] = htonl(h2id);
    rst_stream.u[3] = htonl(e);
    chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align padding)*/
                          (const char *)rst_stream.c+3, sizeof(rst_stream)-3);
}


__attribute_cold__
static void
h2_send_rst_stream_state (request_st * const r, h2con * const h2c)
{
    if (r->x.h2.state != H2_STATE_HALF_CLOSED_REMOTE
        && r->x.h2.state != H2_STATE_CLOSED) {
        /* set timestamp for comparison; not tracking individual stream ids */
        h2c->half_closed_ts = log_monotonic_secs;
    }
    r->state = CON_STATE_ERROR;
    r->x.h2.state = H2_STATE_CLOSED;
}


__attribute_cold__
static void
h2_send_goaway_e (connection * const con, const request_h2error_t e);


__attribute_cold__
static void
h2_send_rst_stream (request_st * const r, connection * const con, const request_h2error_t e)
{
    /*(set r->x.h2.state=H2_STATE_CLOSED)*/
    h2_send_rst_stream_state(r, (h2con *)con->hx);
    h2_send_rst_stream_id(r->x.h2.id, con, e);

    /* attempt to detect HTTP/2 MadeYouReset DoS attack VU#767506 CVE-2025-8671
     * heuristic to detect excessive err sent by client to cause reset by server
     * Ignore H2_E_NO_ERROR and H2_E_INTERNAL_ERROR.
     *   Were H2_E_INTERNAL_ERROR to be included, there might be false positives
     *   (not attacks) in the count.  Ignoring H2_E_INTERNAL_ERROR here does not
     *   count *response* headers too long, but that is not a client error.
     * Ignore H2_E_REFUSED_STREAM, which is counted separately, elsewhere,
     *   but not listed in conditional below since H2_E_REFUSED_STREAM is sent
     *   directly via h2_send_rst_stream_id(), not h2_send_rst_stream()
     * Include all other errors, though some are more prevalent than others:
     *   H2_E_PROTOCOL_ERROR, H2_E_FLOW_CONTROL_ERROR, H2_E_STREAM_CLOSED,
     *   H2_E_FRAME_SIZE_ERROR, H2_E_COMPRESSION_ERROR, ...
     * Many such errors are sent with GOAWAY, so not as relevant to count here.
     * If r->x.h2.state is not H2_STATE_CLOSED, include H2_E_STREAM_CLOSED here.
     *
     * Errors for unrecognized (not currently active) stream id are not counted
     * here, but also do not affect potentially in-progress streams which are
     * consuming resources in lighttpd and/or backends, e.g. if request headers
     * are not yet complete, a backend to handle request has not been started.
     *
     * Similar to h2_recv_rst_stream() for HTTP/2 Rapid Reset attack,
     * send GOAWAY with H2_E_NO_ERROR if count exceeds the policy limit since if
     * peer is triggering server to send RST_STREAM, the peer is misbehaving,
     * whether or not it is multiplexing requests from different clients, but a
     * naive peer multiplexing requests from different clients could result in
     * more reset (failed) streams of valid streams if one client could trigger
     * too many resets sent by server on a single multiplexed connection, and
     * server resets all streams and sends GOAWAY w/ error (not H2_E_NO_ERROR).
     * log watchers such as fail2ban could watch for error log trace indicating
     * detection of this attack, and could respond accordingly, across multiple
     * servers.  In lighttpd, a client could trigger server-sent reset stream w/
     * e.g. mismatch between received data and Content-Length, when provided.
     */
    if (e != H2_E_NO_ERROR && e != H2_E_INTERNAL_ERROR) {
        /* simulate receiving TCP FIN from client to trigger imminent shutdown()
         * on socket connection to backend, indicating request terminated.
         * Note: mod_cgi must be configured for this to have any effect,
         *   e.g. cgi.limits += ("tcp-fin-propagate" => "SIGTERM")
         * Regardless of whether or not this optimization is performed,
         * lighttpd will schedule close() on backend socket (or CGI pipe)
         * and will close() backend socket (or kill CGI) upon next poll cycle */
        /*r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;*/
        if (r->handler_module)
            joblist_append(con);  /*(cause short poll for next poll cycle)*/

        /* increment h2c->n_send_rst_stream_err and check for policy violation
         *
         * time step interval currently 2 secs: (log_monotonic_secs >> 1)
         * store time bits in upper nibble of h2c->n_send_rst_stream_err
         *   (32-second time slice: ((log_monotonic_secs >> 1) & 0xF))
         * time_bits are only 4 bits, so repeated time_bits could cause false
         *   positive and not decay the counter, but well-behaved peers should
         *   not trigger *any* RST_STREAM, so tripping the policy sooner is ok.
         *   (rather than potentially missing policy violation (false negative))
         * decay counter (divide by 2 (>> 1)) when time step interval changes
         *   (any time interval change; not shifting by (cur_bits - time_bits))
         * counter is 4 bits, so max is 15 (0xF) unless bit masks are adjusted
         *
         * XXX: server triggered to send RST_STREAM w/ error is unexpected
         *      A stricter implementation might send GOAWAY H2_E_NO_ERROR
         *      upon first occurrence.
         */
        h2con * const h2c = (h2con *)con->hx;
        uint8_t cur_bits = (log_monotonic_secs >> 1) & 0xF;
        uint8_t time_bits = h2c->n_send_rst_stream_err >> 4;
        if (cur_bits != time_bits)
            h2c->n_send_rst_stream_err =
              (cur_bits << 4) | ((h2c->n_send_rst_stream_err & 0xF) >> 1);
        if (!h2c->sent_goaway && (++h2c->n_send_rst_stream_err & 0xF) > 4) {
            log_error(NULL, __FILE__, __LINE__,
              "h2: %s triggered too many RST_STREAM too quickly (xaddr:%s)",
              con->request.dst_addr_buf->ptr, r->dst_addr_buf->ptr);
            h2_send_goaway_e(con, H2_E_NO_ERROR);
            /* h2_send_goaway_e w/ H2_E_PROTOCOL_ERROR or H2_E_ENHANCE_YOUR_CALM
             * would cause other request streams to be reset (and would have to
             * check h2c->send_goaway <= 0 above instead of !h2c->sent_goaway)*/
        }
    }
}


__attribute_cold__
__attribute_noinline__
static void
h2_send_rst_stream_closed (request_st * const r, connection * const con)
{
    if (r->x.h2.state == H2_STATE_CLOSED) /*already closed; rst_stream_id only*/
        h2_send_rst_stream_id(r->x.h2.id, con, H2_E_STREAM_CLOSED);
    else /*(r->x.h2.state == H2_STATE_HALF_CLOSED_REMOTE)*/
        h2_send_rst_stream(r, con, H2_E_STREAM_CLOSED);
}


__attribute_cold__
static void
h2_send_goaway_rst_stream (connection * const con)
{
    h2con * const h2c = (h2con *)con->hx;
    const int sent_goaway = h2c->sent_goaway;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const r = h2c->r[i];
        if (r->x.h2.state == H2_STATE_CLOSED) continue;
        h2_send_rst_stream_state(r, h2c);/*(set r->x.h2.state=H2_STATE_CLOSED)*/
        /*(XXX: might consider always sending RST_STREAM)*/
        if (sent_goaway)
            h2_send_rst_stream_id(r->x.h2.id, con, H2_E_PROTOCOL_ERROR);
    }
}


static void
h2_send_goaway (connection * const con, const request_h2error_t e)
{
    /* future: RFC 7540 Section 6.8 notes that server initiating graceful
     * connection shutdown SHOULD send GOAWAY with stream id 2^31-1 and a
     * NO_ERROR code, and later send another GOAWAY with an updated last
     * stream identifier.  (This is not done here, but doing so would be
     * friendlier to clients that send streaming requests which the client
     * is unable to retry.) */

    if (e != H2_E_NO_ERROR)
        h2_send_goaway_rst_stream(con);
    /*XXX: else should send RST_STREAM w/ CANCEL for any active PUSH_PROMISE */

    h2con * const h2c = (h2con *)con->hx;
    if (h2c->sent_goaway && (h2c->sent_goaway > 0 || e == H2_E_NO_ERROR))
        return;
    h2c->sent_goaway = (e == H2_E_NO_ERROR) ? -1 : (int32_t)e;

    union {
      uint8_t c[20];
      uint32_t u[5];          /*(alignment)*/
    } goaway = { {            /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* GOAWAY */
     ,0x00, 0x00, 0x08        /* frame length */
     ,H2_FTYPE_GOAWAY         /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier */
     ,0x00, 0x00, 0x00, 0x00  /* last-stream-id (fill in below) */
     ,0x00, 0x00, 0x00, 0x00  /* error code     (fill in below) */
                              /* additional debug data (*); (optional)
                               * adjust frame length if any additional
                               * debug data is sent */
    } };

    goaway.u[3] = htonl(h2c->h2_cid); /* last-stream-id */
    goaway.u[4] = htonl(e);
    chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align padding)*/
                          (const char *)goaway.c+3, sizeof(goaway)-3);
}


__attribute_cold__
static void
h2_send_goaway_e (connection * const con, const request_h2error_t e)
{
    h2_send_goaway(con, e);
}


__attribute_cold__
static int
h2_send_refused_stream (uint32_t h2id, connection * const con)
{
    h2con * const h2c = (h2con *)con->hx;

    /* avoid sending REFUSED_STREAM if an existing stream is ready to be
     * cleaned up, better handling edge case where stream concurrency limit
     * has been reached and client sends RST_STREAM followed by HEADERS to
     * cancel an existing stream and create a new, different stream.
     * Note: this handles HTTP/2 rapid reset attack (CVE-2023-44487)
     * slightly better than prior behavior by avoiding the minor overhead
     * of responding with RST_STREAM REFUSED_STREAM */
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        const request_st * const r = h2c->r[i];
        if (r->state > CON_STATE_WRITE)
            /* (CON_STATE_RESPONSE_END or CON_STATE_ERROR)
             * request will be cleaned up shortly, releasing a slot;
             * defer processing frame rather than sending REFUSED_STREAM */
            return -1;
    }

    if (h2c->sent_settings) { /*(see h2_recv_settings() comments)*/
        /* client connected and immediately sent flurry of request streams
         * (h2c->sent_settings is non-zero if sent SETTINGS frame to
         *  client and have not yet received SETTINGS ACK from client)
         * lighttpd sends SETTINGS_MAX_CONCURRENT_STREAMS <limit> with
         * server Connection Preface, so a well-behaved client will
         * adjust after it sends its initial requests.
         *   (e.g. h2load -n 100 -m 100 sends 100 requests upon connect)
         */

        /* Send GOAWAY if too many requests (> 100) sent prior to SETTINGS ackn
         *   (and if we reach here checking to refuse excess stream).
         * (lighttpd currently sends SETTINGS once, following server preface) */
        if (h2id > 200) {
            log_error(NULL, __FILE__, __LINE__,
              "h2: %s too many refused requests before SETTINGS ackn",
              con->request.dst_addr_buf->ptr);
            h2_send_goaway_e(con, H2_E_ENHANCE_YOUR_CALM);
            return 0;
        }

        /*
         * Check if active streams have pending request body.  If all active
         * streams have pending request body, then must refuse new stream as
         * progress might be blocked if active streams all wait for DATA. */
        for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
            const request_st * const r = h2c->r[i];
            if (r->reqbody_length == r->reqbody_queue.bytes_in) {
                /* check that stream response will not be blocked waiting
                 * for stream WINDOW_UPDATE or connection WINDOW_UPDATE */
                request_st * const h2r = &con->request;
                if (r->x.h2.swin <= 0 || h2r->x.h2.swin <= 0) continue;

                /* no pending request body; at least this request may proceed,
                 * though others waiting for request body may block until new
                 * request streams become active if new request streams precede
                 * DATA frames for active streams
                 *
                 * alternative to sending refused stream:
                 * stop processing frames and defer processing this HEADERS
                 * frame until num active streams drops below limit. */
                return -1;
            }
        }
        /* overload h2c->half_closed_ts to discard DATA (in h2_recv_data())
         * from refused streams while waiting for SETTINGS ackn from client
         * (instead of additional h2 con init time check in h2_recv_data())
         * (though h2c->half_closed_ts is not unset when SETTINGS ackn received)
         * (fuzzy discard; imprecise; see further comments in h2_recv_data()) */
        h2c->half_closed_ts = h2c->sent_settings;
    }

    /* too many active streams; refuse new stream */
    h2c->h2_cid = h2id;
    h2_send_rst_stream_id(h2id, con, H2_E_REFUSED_STREAM);

    /* mitigate request floods pipelining streams in excess of concurrency limit
     *
     * excess streams opened after SETTINGS_MAX_CONCURRENT_STREAMS 8 sent may
     * indicate an attack, or may indicate an impatient and ill-behaved client
     * (SETTINGS_MAX_CONCURRENT_STREAMS >= 100 recommended by RFC 9113)
     * If client sends more than 100 requests before sending SETTINGS ackn,
     * then lighttpd treats that as excessive (above).  It could be accidental,
     * but could be malicious since an attacker might intentionally omit sending
     * SETTINGS ackn.  Note: SETTINGS_MAX_CONCURRENT_STREAMS is not currently
     * sent by lighttpd after SETTINGS following HTTP/2 server preface, so this
     * stream concurrency limit does not change after connection initiation.
     * Here, either SETTINGS ackn has been received, and still too many requests
     * (more than concurrenty limit of 8) *or* fall through from above if active
     *  requests might block/timeout waiting for later frames).  Well-behaved
     * clients should not fall afoul of server SETTINGS_MAX_CONCURRENT_STREAMS*/
    if (++h2c->n_refused_stream > 16) {
        log_error(NULL, __FILE__, __LINE__,
          "h2: %s too many refused requests",
          con->request.dst_addr_buf->ptr);
        h2_send_goaway_e(con, H2_E_NO_ERROR);
        /*(return 0 if sending H2_E_ENHANCE_YOUR_CALM instead)*/
    }

    return 1;
}


static int
h2_recv_goaway (connection * const con, const uint8_t * const s, uint32_t len)
{
    /*(s must be entire GOAWAY frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_GOAWAY);*/
    if (len < 8) {          /*(GOAWAY frame length must be >= 8)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return 0;
    }
    if (0 != h2_u31(s+5)) { /*(GOAWAY stream id must be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }
    const uint32_t e = h2_u32(s+13);
  #if 0
    /* XXX: debug: could log error code sent by peer */
  #endif
  #if 0
    /* XXX: debug: could log additional debug info (if any) sent by peer */
    if (len > 8) {
    }
  #endif
  #if 0
    /* XXX: could validate/use Last-Stream-ID sent by peer */
    const uint32_t last_id = h2_u31(s+9);
  #endif

    /* send PROTOCOL_ERROR back to peer if peer sent an error code
     * (i.e. not NO_ERROR) in order to terminate connection more quickly */
    h2_send_goaway(con, e==H2_E_NO_ERROR ? H2_E_NO_ERROR : H2_E_PROTOCOL_ERROR);
    h2con * const h2c = (h2con *)con->hx;
    if (0 == h2c->rused) return 0;
    return 1;
}


static void
h2_recv_rst_stream (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire RST_STREAM frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_RST_STREAM);*/
    if (4 != len) {                  /*(RST_STREAM frame length must be 4)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }
    const uint32_t id = h2_u31(s+5);
    if (0 == id) {                   /*(RST_STREAM id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    h2con * const h2c = (h2con *)con->hx;
    request_st * const r = h2_get_stream_req(h2c, id);
    if (r) {
        if (r->x.h2.state == H2_STATE_IDLE) {
            /*(RST_STREAM must not be for stream in "idle" state)*/
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return;
        }
        /* XXX: ? add debug trace including error code from RST_STREAM ? */
        r->state = CON_STATE_ERROR;
        r->x.h2.state = H2_STATE_CLOSED;
        if (r->handler_module)
            joblist_append(con);  /*(cause short poll for next poll cycle)*/

        /* attempt to detect HTTP/2 rapid reset attack (CVE-2023-44487)
         * Send GOAWAY if 17 or more requests in recent batch of up to 32
         * requests have been cancelled by client sending RST_STREAM.
         * Note: this can legitimately occur, but is less likely for RST_STREAM
         * in < 2 secs in which request was sent, repeated 16 more times within
         * the next 32 requests, w/ SETTINGS_MAX_CONCURRENT_STREAMS only 8.
         * Still, send GOAWAY NO_ERROR instead of sending ENHANCE_YOUR_CALM. */
        if (!h2c->sent_goaway && r->start_hp.tv_sec+2 > log_epoch_secs) {
            if ((++h2c->n_recv_rst_stream & 0xf) == 0)
                h2c->n_recv_rst_stream |= 0xf;
            uint8_t n_recv_rst_stream =
              (h2c->n_recv_rst_stream >> 4) + (h2c->n_recv_rst_stream & 0xf);
            if (n_recv_rst_stream > 16) {
                log_error(NULL, __FILE__, __LINE__,
                  "h2: %s sent too many RST_STREAM too quickly (xaddr:%s)",
                  con->request.dst_addr_buf->ptr, r->dst_addr_buf->ptr);
                h2_send_goaway_e(con, H2_E_NO_ERROR);
            }
        }

        return;
    }
    /* unknown/inactive stream id
     * XXX: how should we handle RST_STREAM for unknown/inactive stream id?
     * (stream id may have been closed recently and server forgot about it,
     *  but client (peer) sent RST_STREAM prior to receiving stream end from
     *  server)*/
  #if 0
    if (h2c->sent_goaway && h2c->h2_cid < id) return;
    h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
  #else
    if (h2c->h2_cid < id) {
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
  #endif
}


static void
h2_recv_ping (connection * const con, uint8_t * const s, const uint32_t len)
{
  #if 0
    union {
      uint8_t c[20];
      uint32_t u[5];          /*(alignment)*/
    } ping = { {              /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* PING */
     ,0x00, 0x00, 0x08        /* frame length */
     ,H2_FTYPE_PING           /* frame type */
     ,H2_FLAG_ACK             /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier */
     ,0x00, 0x00, 0x00, 0x00  /* opaque            (fill in below) */
     ,0x00, 0x00, 0x00, 0x00
    } };
  #endif

    /*(s must be entire PING frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_PING);*/
    if (8 != len) {                  /*(PING frame length must be 8)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }
    s[5] &= ~0x80; /* reserved bit must be ignored */
    if (0 != h2_u31(s+5)) { /*(PING stream id must be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    if (s[4] & H2_FLAG_ACK) /*(ignore; unexpected if we did not send PING)*/
        return;
    /* reflect PING back to peer with frame flag ACK */
    /* (9 byte frame header plus 8 byte PING payload = 17 bytes)*/
    s[4] = H2_FLAG_ACK;
    chunkqueue_append_mem(con->write_queue, (const char *)s, 17);
}


static void
h2_apply_priority_update (h2con * const h2c, const request_st * const r, const uint32_t rpos)
{
    const request_st ** const rr = (const request_st **)h2c->r;
    uint32_t npos = rpos;
    while (npos
           && (rr[npos-1]->x.h2.prio > r->x.h2.prio
               || (rr[npos-1]->x.h2.prio == r->x.h2.prio
                   && rr[npos-1]->x.h2.id > r->x.h2.id)))
        --npos;
    if (rpos - npos) {
        memmove(rr+npos+1, rr+npos, (rpos - npos)*sizeof(request_st *));
    }
    else {
        while (npos+1 < h2c->rused
               && (rr[npos+1]->x.h2.prio < r->x.h2.prio
                   || (rr[npos+1]->x.h2.prio == r->x.h2.prio
                       && rr[npos+1]->x.h2.id < r->x.h2.id)))
            ++npos;
        if (npos - rpos == 0)
            return; /*(no movement)*/
        memmove(rr+rpos, rr+rpos+1, (npos - rpos)*sizeof(request_st *));
    }
    rr[npos] = r;
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_pure__
static uint8_t
h2_parse_priority_update (const char * const prio, const uint32_t len)
{
    /* parse priority string (structured field values: dictionary)
     * (resets urgency (u) and incremental (i) to defaults if len == 0)
     * (upon parse error, cease parsing and use defaults for remaining items) */
    int urg = 3, incr = 0;
    for (uint32_t i = 0; i < len; ++i) {
        if (prio[i] == ' ' || prio[i] == '\t' || prio[i] == ',') continue;
        if (prio[i] == 'u') { /* value: 0 - 7 */
            if (i+2 < len && prio[i+1] == '=') {
                if ((uint32_t)(prio[i+2] - '0') < 8)
                    urg = prio[i+2] - '0';
                else
                    break; /* cease parsing if invalid syntax */
                i += 2;
            }
            else
                break; /* cease parsing if invalid syntax */
        }
        if (prio[i] == 'i') { /* value: 0 or 1 (boolean) */
            if (i+3 < len && prio[i+1] == '=' && prio[i+2] == '?') {
                if ((uint32_t)(prio[i+3] - '0') <= 1) /* 0 or 1 */
                    incr = prio[i+3] - '0';
                else
                    break; /* cease parsing if invalid syntax */
                i += 3;
            }
            else if (i+1 == len
                     || prio[i+1]==' ' || prio[i+1]=='\t' || prio[i+1]==',')
                incr = 1;
            else
                break; /* cease parsing if invalid syntax */
        }
        do { ++i; } while (i < len && prio[i] != ','); /*advance to next token*/
    }
    /* combine priority 'urgency' value and invert 'incremental' boolean
     * for easy (ascending) sorting by urgency and then incremental before
     * non-incremental */
    return (uint8_t)(urg << 1 | !incr);
}


static void
h2_recv_priority_update (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire PRIORITY_UPDATE frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_PRIORITY_UPDATE);*/
    if (len < 4) {                   /*(PRIORITY_UPDATE frame len must be >=4)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }
    const uint32_t id = h2_u31(s+5);
    if (0 != id) {                   /*(PRIORITY_UPDATE id must be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    const uint32_t prid = h2_u31(s+9);
    if (0 == prid) {                 /*(prioritized stream id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    h2con * const h2c = (h2con *)con->hx;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const r = h2c->r[i];
        if (r->x.h2.id != prid) continue;
        uint8_t prio = h2_parse_priority_update((char *)s+13, len-4);
        if (r->x.h2.prio != prio) {
            r->x.h2.prio = prio;
            h2_apply_priority_update(h2c, r, i);
        }
        return;
    }
  #if 0
    /*(note: not checking if prid applies to PUSH_PROMISE ids; unused in h2.c)*/
    if (h2c->sent_goaway)
        return;
    if (h2c->h2_cid < prid) {
        /* TODO: parse out urgency and incremental values,
         *       and then save for prid of future stream
         *       (see h2_recv_headers() for where to check and apply)
         * (ignore for now; probably more worthwhile to do in HTTP/3;
         *  in HTTP/2, client might sent PRIORITY_UPDATE before HEADERS,
         *  but that is not handled here, and is not expected since the
         *  Priority request header can be used instead.) */
        return;
    }
  #endif
    /*(choosing to ignore frames for unmatched prid)*/
}


__attribute_cold__
__attribute_noinline__
static void
h2_recv_priority (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire PRIORITY frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_PRIORITY);*/
    if (5 != len) {                  /*(PRIORITY frame length must be 5)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }
    const uint32_t id = h2_u31(s+5);
    if (0 == id) {                   /*(PRIORITY id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    const uint32_t prio = h2_u31(s+9);
  #if 0
    uint32_t exclusive_dependency = (s[9] & 0x80) ? 1 : 0;
    /*(ignore dependency prid and exclusive_dependency,
     * and attempt to scale PRIORITY weight (weight+1 default is 16)
     * to PRIORITY_UPDATE (default urgency 3) (see h2_init_stream()))*/
    uint8_t weight = s[13] >> 2;
    weight = ((weight < 8 ? weight : 7) << 1) | !0;
  #endif
    h2con * const h2c = (h2con *)con->hx;
    request_st * const r = h2_get_stream_req(h2c, id);
    if (r) {
        /* XXX: TODO: update priority info */
        if (prio == id) {
            h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
            return;
        }
      #if 0
        else if (r->x.h2.prio != weight) {
            r->x.h2.prio = weight;
            h2_apply_priority_update(h2c, r, i);
        }
      #endif
        return;
    }
    /* XXX: TODO: update priority info for unknown/inactive stream */
    /*if (h2c->sent_goaway && h2c->h2_cid < id) return;*/
    if (prio == id) {
        h2_send_rst_stream_id(id, con, H2_E_PROTOCOL_ERROR);
        return;
    }
}


static void
h2_recv_window_update (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire WINDOW_UPDATE frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_WINDOW_UPDATE);*/
    if (4 != len) {                  /*(WINDOW_UPDATE frame length must be 4)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }
    const uint32_t id = h2_u31(s+5);
    const int32_t v = (int32_t)h2_u31(s+9);
    request_st *r = NULL;
    if (0 == id)
        r = &con->request;
    else {
        h2con * const h2c = (h2con *)con->hx;
        r = h2_get_stream_req(h2c, id);
        /* peer should not send WINDOW_UPDATE for an inactive stream,
         * but RFC 7540 does not explicitly call this out.  On the other hand,
         * since there may be a temporary mismatch in stream state between
         * peers, ignore window update if stream id is unknown/inactive.
         * Also, it is not an error if GOAWAY sent and h2c->h2_cid < id */
        if (NULL == r) {
            if (h2c->h2_cid < id && 0 == h2c->sent_goaway)
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
          #ifdef H2SPEC
            /*(needed for h2spec if testing with response < 16k+1 over TLS
             * or response <= socket send buffer size over cleartext, due to
             * completing response too quickly for the test frame sequence) */
            if (v == 0)        /* h2spec: 6.9-2   (after we retired id 1) */
                h2_send_rst_stream_id(id, con, H2_E_PROTOCOL_ERROR);
            if (v == INT32_MAX)/* h2spec: 6.9.1-3 (after we retired id 1) */
                h2_send_rst_stream_id(id, con, H2_E_FLOW_CONTROL_ERROR);
          #endif
            return;
        }
        /* MUST NOT be treated as error if stream is in closed state; ignore */
        if (r->x.h2.state == H2_STATE_CLOSED
            || r->x.h2.state == H2_STATE_HALF_CLOSED_LOCAL) return;
    }
    if (0 == v || r->x.h2.swin > INT32_MAX - v) {
        request_h2error_t e = (0 == v)
          ? H2_E_PROTOCOL_ERROR
          : H2_E_FLOW_CONTROL_ERROR;
        if (0 == id)
            h2_send_goaway_e(con, e);
        else
            h2_send_rst_stream(r, con, e);
        return;
    }
    r->x.h2.swin += v;
}


static void
h2_send_window_update (connection * const con, uint32_t h2id, const uint32_t len)
{
    if (0 == len) return;
    union {
      uint8_t c[16];
      uint32_t u[4];          /*(alignment)*/
    } window_upd = { {        /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* WINDOW_UPDATE */
     ,0x00, 0x00, 0x04        /* frame length */
     ,H2_FTYPE_WINDOW_UPDATE  /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier      (fill in below) */
     ,0x00, 0x00, 0x00, 0x00  /* window update increase (fill in below) */
    } };

    window_upd.u[2] = htonl(h2id);
    window_upd.u[3] = htonl(len);
    chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align padding)*/
                          (const char *)window_upd.c+3, sizeof(window_upd)-3);
}


__attribute_noinline__
static void
h2_send_window_update_unit (connection * const con, request_st * const r, const uint32_t len)
{
    r->x.h2.rwin_fudge -= (int16_t)len;
    if (r->x.h2.rwin_fudge < 0) {
        r->x.h2.rwin_fudge += 16384;
        h2_send_window_update(con, r->x.h2.id, 16384); /*(r->x.h2.rwin)*/
    }
}


static void
h2_parse_frame_settings (connection * const con, const uint8_t *s, uint32_t len)
{
    /*(s and len must be SETTINGS frame payload)*/
    /*(caller must validate frame len, frame type == 0x04, frame id == 0)*/
    h2con * const h2c = (h2con *)con->hx;
    for (; len >= 6; len -= 6, s += 6) {
        uint32_t v = h2_u32(s+2);
        switch (h2_u16(s)) {
          case H2_SETTINGS_HEADER_TABLE_SIZE:
            /* encoder may use any table size <= value sent by peer */
            /* For simple compliance with RFC and constrained memory use,
             * choose to not increase table size beyond the default 4096,
             * but allow smaller sizes to be set and then reset up to 4096,
             * e.g. set to 0 to evict all dynamic table entries,
             * and then set to 4096 to restore dynamic table use */
            if (v > 4096) v = 4096;
            if (v == h2c->s_header_table_size) break;
            h2c->s_header_table_size = v;
            lshpack_enc_set_max_capacity(&h2c->encoder, v);
            break;
          case H2_SETTINGS_ENABLE_PUSH:
            if ((v|1) != 1) { /*(v == 0 || v == 1)*/
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
                return;
            }
            h2c->s_enable_push = v;
            break;
          case H2_SETTINGS_MAX_CONCURRENT_STREAMS:
            h2c->s_max_concurrent_streams = v;
            break;
          case H2_SETTINGS_INITIAL_WINDOW_SIZE:
            if (v > INT32_MAX) { /*(2^31 - 1)*/
                h2_send_goaway_e(con, H2_E_FLOW_CONTROL_ERROR);
                return;
            }
            else if (h2c->rused) { /*(update existing streams)*/
                /*(underflow is ok; unsigned integer math)*/
                /*(h2c->s_initial_window_size is >= 0)*/
                int32_t diff =
                  (int32_t)((uint32_t)v - (uint32_t)h2c->s_initial_window_size);
                for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
                    request_st * const r = h2c->r[i];
                    const int32_t swin = r->x.h2.swin;
                    if (r->x.h2.state == H2_STATE_HALF_CLOSED_LOCAL
                        || r->x.h2.state == H2_STATE_CLOSED) continue;
                    if (diff >= 0
                        ? swin > INT32_MAX - diff
                        : swin < INT32_MIN - diff) {
                        h2_send_rst_stream(r, con, H2_E_FLOW_CONTROL_ERROR);
                        continue;
                    }
                    r->x.h2.swin += diff;
                }
            }
            h2c->s_initial_window_size = (int32_t)v;
            break;
          case H2_SETTINGS_MAX_FRAME_SIZE:
            if (v < 16384 || v > 16777215) { /*[(2^14),(2^24-1)]*/
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
                return;
            }
            h2c->s_max_frame_size = v;
            break;
          case H2_SETTINGS_MAX_HEADER_LIST_SIZE:
            h2c->s_max_header_list_size = v;
            break;
          default:
            break;
        }
    }

    if (len) {
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }

    /* caller must send SETTINGS frame with ACK flag,
     * if appropriate, and if h2c->sent_goaway is not set
     * (Do not send ACK for Upgrade: h2c and HTTP2-Settings header) */
}


static void
h2_recv_settings (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire SETTINGS frame, len must be the frame length field)*/
    /*assert(s[3] == H2_FTYPE_SETTINGS);*/
    if (0 != h2_u31(s+5)) {/*(SETTINGS stream id must be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }

    h2con * const h2c = (h2con *)con->hx;
    if (!(s[4] & H2_FLAG_ACK)) {
        h2_parse_frame_settings(con, s+9, len);
        if (h2c->sent_goaway <= 0)
            h2_send_settings_ack(con);
    }
    else {
        /* lighttpd currently sends SETTINGS in server preface, and not again,
         * so this does not have to handle another SETTINGS frame being sent
         * before receiving an ACK from prior SETTINGS frame.  (If it does,
         * then we will need some sort of counter.) */
        if (0 != len)
            h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        else if (h2c->sent_settings)
            h2c->sent_settings = 0;
        else /* SETTINGS with ACK for SETTINGS frame we did not send */
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
    }
}


static int
h2_recv_end_data (request_st * const r, connection * const con, const uint32_t alen)
{
    chunkqueue * const reqbody_queue = &r->reqbody_queue;
    r->x.h2.state = (r->x.h2.state == H2_STATE_OPEN)
      ? H2_STATE_HALF_CLOSED_REMOTE
      : H2_STATE_CLOSED;
    if (r->reqbody_length == -1)
        r->reqbody_length = reqbody_queue->bytes_in + (off_t)alen;
    else if (r->reqbody_length != reqbody_queue->bytes_in + (off_t)alen) {
        if (0 == reqbody_queue->bytes_out) {
            h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
            return 0;
        } /* else let reqbody streaming consumer handle truncated reqbody */
    }

    return 1;
}


static int
h2_recv_data (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire DATA frame, len must be the frame length field)*/
    /*assert(s[3] == H2_FTYPE_DATA);*/

    /* future: consider string refs rather than copying DATA from chunkqueue
     * or try to consume entire chunk, or to split chunks with less copying */

    h2con * const h2c = (h2con *)con->hx;
    const uint32_t id = h2_u31(s+5);
    if (0 == id || h2c->h2_cid < id) { /*(RST_STREAM id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }

    uint32_t alen = len; /* actual data len, minus padding */
    uint32_t pad = 0;
    if (s[4] & H2_FLAG_PADDED) {
        pad = s[9]; /*(reads '\0' after string if 0 == len)*/
        if (pad >= len) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        alen -= (1 + pad);
    }

    request_st * const h2r = &con->request;
    if (h2r->x.h2.rwin <= 0 && 0 != alen) { /*(always proceed if 0 == alen)*/
        /*(h2_process_streams() must ensure con is rescheduled,
         * when backends consume data if con->read_queue is not empty,
         * whether or not con->fd has data to read from the network)*/
        /*(leave frame in cq to be re-read later)*/
        return 0;
    }
    /*(allow h2r->x.h2.rwin to dip below 0 so that entire frame is processed)*/
    /*(not worried about underflow while
     * SETTINGS_MAX_FRAME_SIZE is small (e.g. 16k or 32k) and
     * SETTINGS_MAX_CONCURRENT_STREAMS is small (h2c->r[8]))*/
    /*h2r->x.h2.rwin -= (int32_t)len;*//*update connection recv window (below)*/

    request_st * const r = h2_get_stream_req(h2c, id);
    chunkqueue * const cq = con->read_queue;
    if (NULL == r) {
        /* simplistic heuristic to discard additional DATA from recently-closed
         * streams (or half-closed (local)), where recently-closed here is
         * within 2-3 seconds of any (other) stream being half-closed (local)
         * or reset before that (other) stream received END_STREAM from peer.
         * (e.g. clients might fire off POST request followed by DATA,
         *  and a response might be sent before processing DATA frames)
         * (id <= h2c->h2_cid) already checked above, else H2_E_PROTOCOL_ERROR
         * If the above conditions do not hold, then send GOAWAY to attempt to
         * reduce the chance of becoming an infinite data sink for misbehaving
         * clients, though remaining streams are still handled before the
         * connection is closed. */
        chunkqueue_mark_written(cq, 9+len);
        if (h2c->half_closed_ts + 2 >= log_monotonic_secs) {
            h2_send_window_update_unit(con, h2r, len); /*(h2r->x.h2.rwin)*/
            return 1;
        }
        else {
            if (!h2c->sent_goaway && 0 != alen)
                h2_send_goaway_e(con, H2_E_NO_ERROR);
            return 0;
        }
    }

    if (r->x.h2.state == H2_STATE_CLOSED
        || r->x.h2.state == H2_STATE_HALF_CLOSED_REMOTE) {
        h2_send_rst_stream_closed(r, con); /* H2_E_STREAM_CLOSED */
        chunkqueue_mark_written(cq, 9+len);
        h2_send_window_update_unit(con, h2r, len); /*(h2r->x.h2.rwin)*/
        return 1;
    }

    if (r->x.h2.rwin <= 0 && 0 != alen) {/*(always proceed if 0==alen)*/
        /* note: r->x.h2.rwin is not adjusted (below) if max_request_size exceeded
         *       in order to read and discard h2_rwin amount of data (below) */
        if (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN) {
            /*(h2_process_streams() must ensure con is rescheduled,
             * when backends consume data if con->read_queue is not empty,
             * whether or not con->fd has data to read from the network)*/
            /*(leave frame in cq to be re-read later)*/
            return 0;
        }
    }
    /*(allow r->x.h2.rwin to dip below 0 so that entire frame is processed)*/
    /*(underflow will not occur (with reasonable SETTINGS_MAX_FRAME_SIZE used)
     * since windows updated elsewhere and data is streamed to temp files if
     * not FDEVENT_STREAM_REQUEST_BUFMIN)*/
    /*r->x.h2.rwin -= (int32_t)len;*/
    /*h2_send_window_update_unit(con,r,len);*//*(r->x.h2.rwin)*//*(see below)*/

    /* avoid sending small WINDOW_UPDATE frames
     * Pre-emptively increase window size up to 16k (default max frame size)
     * and then defer small window updates until the excess is utilized. */
    h2_send_window_update_unit(con, h2r, len); /*(h2r->x.h2.rwin)*/

    chunkqueue * const dst = &r->reqbody_queue;

    if (r->reqbody_length >= 0 && r->reqbody_length < dst->bytes_in + alen) {
        /* data exceeds Content-Length specified (client mistake) */
      #if 0 /* truncate */
        alen = r->reqbody_length - dst->bytes_in;
        /*(END_STREAM may follow in 0-length DATA frame or HEADERS (trailers))*/
      #else /* reject */
        h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
        chunkqueue_mark_written(cq, 9+len);
        return 1;
      #endif
    }

    /*(accounting for mod_accesslog and mod_rrdtool)*/
    chunkqueue * const rq = &r->read_queue;
    rq->bytes_in  += (off_t)alen;
    rq->bytes_out += (off_t)alen;

    uint32_t wupd = 0;
    if (s[4] & H2_FLAG_END_STREAM) {
        if (!h2_recv_end_data(r, con, alen)) {
            chunkqueue_mark_written(cq, 9+len);
            return 1;
        }
        /*(accept data if H2_FLAG_END_STREAM was just received,
         * regardless of r->conf.max_request_size setting)*/
    }
    else if (0 == r->conf.max_request_size)
        wupd = len;
    else {
        /* r->conf.max_request_size is in kBytes */
        const off_t max_request_size = (off_t)r->conf.max_request_size << 10;
        off_t n = max_request_size - dst->bytes_in - (off_t)alen;
        int32_t rwin = r->x.h2.rwin - (int32_t)len;
        if (rwin < 0) rwin = 0;
        if (__builtin_expect( (n >= 0), 1)) /*(force wupd below w/ +16384)*/
            wupd=n>=rwin ? (n-=rwin)>(int32_t)len ? len : (uint32_t)n+16384 : 0;
        else if (-n > 65536 || 0 == r->http_status) {
            if (!http_status_is_set(r)) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "request-size too long: %lld -> 413",
                  (long long) (dst->bytes_in + (off_t)alen));
                http_status_set_err(r, 413); /* Payload Too Large */
            }
            else { /* if (-n > 65536) */
                /* tolerate up to 64k additional data before resetting stream
                 * (in excess to window updates sent to client)
                 * (attempt to sink data in kernel buffers so 413 can be sent)*/
                h2_send_rst_stream_id(id, con, H2_E_STREAM_CLOSED);
            }
            chunkqueue_mark_written(cq, 9+len);
            return 1;
        }
    }
    /* r->x.h2.rwin is intentionally unmodified here so that some data in excess
     * of max_request_size received and discarded.  If r->x.h2.rwin use changes
     * in future and might reach 0, then also need to make sure that we do not
     * spin re-processing con while waiting for backend to consume request body.
     * stream rwin is always updated, potentially more than max_request_size so
     * that too much data is detected, instead of waiting for read timeout. */
    /*r->x.h2.rwin -= (int32_t)len;*/
    /*r->x.h2.rwin += (int32_t)wupd;*/
    /* avoid sending small WINDOW_UPDATE frames
     * Pre-emptively increase window size up to 16k (default max frame size)
     * and then defer small window updates until the excess is utilized.
     * This aims to reduce degenerative behavior from clients sending an
     * increasing number of tiny DATA frames. */
    /*(note: r->x.h2.rwin is not adjusted with r->x.h2.rwin_fudge factor)*/
    h2_send_window_update_unit(con, r, wupd);

    chunkqueue_mark_written(cq, 9 + ((s[4] & H2_FLAG_PADDED) ? 1 : 0));

  #if 0
    if (pad) {
        /* XXX: future optimization: if data is at end of chunk, then adjust
         * size of chunk by reducing c->mem->used to avoid copying chunk
         * when it is split (below) since the split would be due to padding
         * (also adjust cq->bytes_out)*/
        /*(might quickly check 9+len == cqlen if cqlen passed in as param)*/
        /*(then check if cq->last contains all of padding, or leave alone)*/
        /*(if handled here, then set pad = 0 here)*/
    }
  #endif

    /*(similar decision logic to that in http_chunk_uses_tempfile())*/
    const chunk * const c = dst->last;
    if ((c && c->type == FILE_CHUNK && c->file.is_temp)
        || chunkqueue_length(dst) + alen > 65536) {
        log_error_st * const errh = r->conf.errh;
        if (0 != chunkqueue_steal_with_tempfiles(dst, cq, (off_t)alen, errh)) {
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            return 0;
        }
    }
    else
        chunkqueue_steal(dst, cq, (off_t)alen);

    if (pad)
        chunkqueue_mark_written(cq, pad);
    return 1;
}


__attribute_cold__
__attribute_noinline__
static void h2_recv_expect_100 (request_st * const r);

static handler_t
h2_recv_reqbody (request_st * const r)
{
    /* h2 r->con->reqbody_read() */

    /* Check for Expect: 100-continue in request headers */
    if (light_btst(r->rqst_htags, HTTP_HEADER_EXPECT))
        h2_recv_expect_100(r);

    /* h2_recv_data() places frame payload directly into r->reqbody_queue */

    if (r->reqbody_queue.bytes_in == (off_t)r->reqbody_length) {
        /*r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;*/
        if (r->state == CON_STATE_READ_POST) /* content is ready */
            request_set_state(r, CON_STATE_HANDLE_REQUEST);
        return HANDLER_GO_ON;
    }
    else if (r->x.h2.state >= H2_STATE_HALF_CLOSED_REMOTE) {
        /*(H2_STATE_HALF_CLOSED_REMOTE or H2_STATE_CLOSED)*/
        return HANDLER_ERROR;
    }
    else {
        /*r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;*/
        return (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
          ? HANDLER_GO_ON
          : HANDLER_WAIT_FOR_EVENT;
    }
}


__attribute_cold__
static uint32_t
h2_frame_cq_compact (chunkqueue * const cq, uint32_t len)
{
    /*(marked cold since most frames not expect to cross chunk boundary)*/

    /* caller must guarantee that chunks in chunkqueue are all MEM_CHUNK */
    /* caller should check (chunkqueue_length(cq) >= len) before calling,
     * or should check that returned value >= len */

    chunkqueue_compact_mem(cq, len);
    return buffer_clen(cq->first->mem) - (uint32_t)cq->first->offset;
}


__attribute_cold__
__attribute_noinline__
static uint32_t
h2_recv_continuation (uint32_t n, uint32_t clen, const off_t cqlen, chunkqueue * const cq, connection * const con)
{
    chunk *c = cq->first;
    uint8_t *s = (uint8_t *)(c->mem->ptr + c->offset);
    uint32_t m = n;
    uint32_t flags;
    h2con * const h2c = (h2con *)con->hx;
    const uint32_t fsize = h2c->s_max_frame_size;
    const uint32_t id = h2_u31(s+5);
    int nloops = 0;
    do {
        if (cqlen < n+9) return n+9; /* incomplete frame; go on */
        if (clen < n+9) {
            clen = h2_frame_cq_compact(cq, n+9);
            c = cq->first; /*(reload after h2_frame_cq_compact())*/
            s = (uint8_t *)(c->mem->ptr + c->offset);
        }
        if (s[n+3] != H2_FTYPE_CONTINUATION) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        flags = s[n+4];
        const uint32_t flen = h2_u24(s+n);
        if (id != h2_u32(s+n+5)) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        if (flen > fsize) {
            h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
            return 0;
        }
        n += 9+flen;
        if (n >= 65536) { /*(very oversized for hpack)*/
            h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
            return 0;
        }
        if (clen < n) {
            clen = h2_frame_cq_compact(cq, n);
            if (clen < n) return n; /* incomplete frame; go on */
            c = cq->first; /*(reload after h2_frame_cq_compact())*/
            s = (uint8_t *)(c->mem->ptr + c->offset);
        }

        /* Detect VU#421644 (even though lighttpd already imposes limits)
         * HTTP/2 CONTINUATION frames can be utilized for DoS attacks
         *
         * MAX_READ_LIMIT is currently 256k (from kernel socket buffers)
         * and much larger than 64k limit which lighttpd imposes on raw request
         * HEADERS + CONTINUATION(s) above, and much larger than 64k upper limit
         * which lighttpd imposes on HPACK-decoded request headers.  Since
         * kernel socket buffers are generally not less than 32k, expect to
         * complete reading CONTINUATION(s) in 3 recv()s or less if DoS attacker
         * is quickly sending CONTINUATION frames.  Instead of keeping a count
         * of small CONTINUATION frames, simply set a limit on the max number of
         * CONTINUATION frames to process consecutively in this batch.
         *
         * Warn once if >= 32 CONTINUATION frames processed in this batch. */
        if (++nloops == 32) {
            log_error(NULL, __FILE__, __LINE__,
              "h2: %s quickly sent excessive number of CONTINUATION frames",
              con->request.dst_addr_buf->ptr);
            h2_send_goaway_e(con, H2_E_NO_ERROR);
        }
      #if 0
        if (nloops > 32) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
      #endif
      #if 0 /*(too specific;excessive empty frames handled in above heuristic)*/
        /* possible CONTINUATION attack if 0 frame length and not END_HEADERS */
        if (__builtin_expect( (0==flen), 0) && !(flags & H2_FLAG_END_HEADERS)) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
      #endif
    } while (!(flags & H2_FLAG_END_HEADERS));

    /* If some CONTINUATION frames were concatenated to earlier frames while
     * processing above, but END_HEADERS were not received, then the next time
     * data was read, initial frame size might exceed SETTINGS_MAX_FRAME_SIZE.
     * (This describes the current lighttpd implementation in h2_parse_frames())
     * While a flag could be set and checked to avoid this, such situations of
     * large HEADERS (and CONTINUATION) across multiple network reads is
     * expected to be rare.  Reparse and concatenate below.
     *
     * Aside: why would the authors of RFC 7540 go through the trouble of
     * creating a CONTINUATION frame that must be special-cased when use of
     * CONTINUATION is so restricted e.g. no other intervening frames and
     * that HEADERS and PUSH_PROMISE HPACK must be parsed as a single block?
     * IMHO, it would have been simpler to avoid CONTINUATION entirely, and have
     * a special-case for HEADERS and PUSH_PROMISE to be allowed to exceed
     * SETTINGS_MAX_FRAME_SIZE with implementations providing a different limit.
     * While intermediates would not know such a limit of origin servers,
     * there could have been a reasonable default set with a different SETTINGS
     * parameter aimed just at HEADERS and PUSH_PROMISE.  The parameter
     * SETTINGS_MAX_HEADER_LIST_SIZE could even have been (re)used, had it been
     * given a reasonable initial value instead of "unlimited", since HPACK
     * encoded headers are smaller than the HPACK decoded headers to which the
     * limit SETTINGS_MAX_HEADER_LIST_SIZE applies. */

    n = m; /* reset n to beginning of first CONTINUATION frame */

    /* Eliminate padding from first frame (HEADERS or PUSH_PROMISE) if PADDED */
    if (s[4] & H2_FLAG_PADDED) {
        const uint32_t plen = s[9];
        /* validate padding */
        const uint32_t flen = h2_u24(s);
        if (flen < 1 + plen + ((s[n+4] & H2_FLAG_PRIORITY) ? 5 : 0)) {
            /* Padding that exceeds the size remaining for the header block
             * fragment MUST be treated as a PROTOCOL_ERROR. */
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        /* set padding to 0 since we will overwrite padding in merge below */
        /* (alternatively, could memmove() 9 bytes of frame header over the
         *  pad length octet, remove PADDED flag, add 1 to c->offset,
         *  add 1 to s, subtract 1 from clen and subtract 1 from cqlen,
         *  subtract 1 from n, add 1 to cq->bytes_out) */
        s[9] = 0;
        /* set offset to beginning of padding at end of first frame */
        m -= plen;
        /* XXX: layer violation; adjusts chunk.c internal accounting */
        cq->bytes_out += plen;
    }

  #ifdef __COVERITY__
    /* Coverity does not notice that values used in s are checked.
     * Although silencing here, would prefer not to do so since doing so
     * disables Coverity from reporting questionable modifications which
     * might be made to the code in the future. */
    __coverity_tainted_data_sink__(s);
  #endif

    do {
        const uint32_t flen = h2_u24(s+n);
      #ifdef __COVERITY__ /*flen values were checked in do {} while loop above*/
        if (clen < n+9+flen) {
            h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
            return 0;
        }
      #endif
        flags = s[n+4];
        memmove(s+m, s+n+9, flen);
        m += flen;
        n += 9+flen;
        /* XXX: layer violation; adjusts chunk.c internal accounting */
        cq->bytes_out += 9;
    } while (!(flags & H2_FLAG_END_HEADERS));
    /* overwrite frame size */
    m -= 9; /*(temporarily remove frame header from len)*/
    s[0] = (m >> 16) & 0xFF;
    s[1] = (m >>  8) & 0xFF;
    s[2] = (m      ) & 0xFF;
    m += 9;
    /* adjust chunk c->mem */
    if (n < clen) { /*(additional frames after CONTINUATION)*/
        memmove(s+m, s+n, clen-n);
        n = m + (clen-n);
    }
    else
        n = m;
    buffer_truncate(c->mem, n + (uint32_t)c->offset);

    return m;
}


__attribute_cold__
static request_st *
h2_recv_trailers_r (connection * const con, h2con * const h2c, const uint32_t id, const uint32_t flags)
{
    /* rant: RFC 7230 HTTP/1.1 trailer-part would have been much simpler
     * to support in RFC 7540 HTTP/2 as a distinct frame type rather than
     * HEADERS.  As trailers are not known at the time the request is made,
     * reuse of such trailers is limited and so a theoretical TRAILERS frame
     * could have been implemented without HPACK encoding, and would have
     * been more straightforward to implement than overloading and having to
     * handle multiple cases for HEADERS.  TRAILERS support could then also
     * be optional, like in HTTP/1.1 */
    request_st * const r = h2_get_stream_req(h2c, id);
    if (NULL == r) {
        /* Note: sending GOAWAY here might be too strict.  With the introduction
         * of h2_discard_headers(), the GOAWAY can now safely be commented out
         * if this causes any issue with legitimate use in the field due to
         * lighttpd responding to a stream, closing and forgetting about the
         * stream, and then receiving trailers from the client for the stream.*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return NULL;
    }
    if (r->x.h2.state != H2_STATE_OPEN
        && r->x.h2.state != H2_STATE_HALF_CLOSED_LOCAL) {
        h2_send_rst_stream_closed(r, con); /* H2_E_STREAM_CLOSED */
        return NULL;
    }
    /* RFC 7540 is not explicit in restricting HEADERS (trailers) following
     * (optional) DATA frames, but in following HTTP/1.1, we limit to single
     * (optional) HEADERS (+ CONTINUATIONs) after (optional) DATA frame(s)
     * and require that the HEADERS frame set END_STREAM flag. */
    if (!(flags & H2_FLAG_END_STREAM)) {
        h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
        return NULL;
    }

    return h2_recv_end_data(r, con, 0) ? r : NULL;
}


__attribute_cold__
static void
h2_discard_headers_frame (struct lshpack_dec * const restrict decoder, const unsigned char **psrc, const unsigned char * const restrict endp, const request_st * const restrict r)
{
    /* HPACK decode and discard; stripped down from h2_parse_headers_frame().
     * If HEADERS frame is received, HEADERS frame must be HPACK-decoded to
     * maintain HPACK decoder state consistency for the connection, unless
     * GOAWAY has been sent and no new streams will be opened.  Even then,
     * if GOAWAY was sent with H2_E_NO_ERROR, there is still chance that
     * trailers sent later on active streams will fail to be decoded unless
     * all HEADERS frames are HPACK-decoded in the order received. */

    /*(h2_init_con() resized h2r->tmp_buf to 64k; shared with r->tmp_buf)*/
    buffer * const tb = r->tmp_buf;
    char * const tbptr = tb->ptr;
    const lsxpack_strlen_t tbsz = (tb->size <= LSXPACK_MAX_STRLEN)
      ? tb->size
      : LSXPACK_MAX_STRLEN;

    lsxpack_header_t lsx;
    while (*psrc < endp) {
        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = tbptr;
        lsx.val_len = tbsz;
        if (lshpack_dec_decode(decoder, psrc, endp, &lsx) != LSHPACK_OK)
            break; /* HPACK decode failed; should probably send GOAWAY? */
    }
}


static void h2_retire_stream (request_st *r, connection * const con);


static void
h2_parse_headers_frame (struct lshpack_dec * const restrict decoder, const unsigned char **psrc, const unsigned char * const endp, request_st * const restrict r, const int trailers)
{
    http_header_parse_ctx hpctx;
    hpctx.hlen     = 0;
    hpctx.pseudo   = !trailers;
    hpctx.scheme   = 0;
    hpctx.trailers = trailers;
    hpctx.log_request_header = r->conf.log_request_header;
    hpctx.max_request_field_size = r->conf.max_request_field_size;
    hpctx.http_parseopts = r->conf.http_parseopts;
    int rc = LSHPACK_OK;
    /*buffer_clear(&r->target);*//*(initial state)*/

    /*(h2_init_con() resized h2r->tmp_buf to 64k; shared with r->tmp_buf)*/
    buffer * const tb = r->tmp_buf;
    force_assert(tb->size >= 65536);/*(sanity check; remove in future)*/
    char * const tbptr = tb->ptr;
    const lsxpack_strlen_t tbsz = (tb->size <= LSXPACK_MAX_STRLEN)
      ? tb->size
      : LSXPACK_MAX_STRLEN;

    lsxpack_header_t lsx;
    while (*psrc < endp) {
        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = tbptr;
        lsx.val_len = tbsz;
        rc = lshpack_dec_decode(decoder, psrc, endp, &lsx);
        if (0 == lsx.name_len)
            rc = LSHPACK_ERR_BAD_DATA;
        if (__builtin_expect( (rc == LSHPACK_OK), 1)) {
            hpctx.k = lsx.buf+lsx.name_offset;
            hpctx.v = lsx.buf+lsx.val_offset;
            hpctx.klen = lsx.name_len;
            hpctx.vlen = lsx.val_len;
            /*assert(lsx.hpack_index < sizeof(lshpack_idx_http_header));*/
            hpctx.id = lshpack_idx_http_header[lsx.hpack_index];

            if (hpctx.log_request_header)
                log_debug(r->conf.errh, __FILE__, __LINE__,
                  "fd:%d id:%u rqst: %.*s: %.*s", r->con->fd, r->x.h2.id,
                  (int)hpctx.klen, hpctx.k, (int)hpctx.vlen, hpctx.v);

            const int http_status = http_request_parse_header(r, &hpctx);
            if (__builtin_expect( (0 != http_status), 0)) {
                if (r->http_status == 0) /*might be set if processing trailers*/
                    r->http_status = http_status;
                /* Note: hpctx.hlen is not adjusted for rest of headers, nor
                 * debug printing of headers if hpctx.log_request_header */
                h2_discard_headers_frame(decoder, psrc, endp, r);
                break;
            }
        }
      #if 0 /*(see catch-all below)*/
        /* Send GOAWAY (further below) (decoder state not maintained on error)
         * (see comments above why decoder state must be maintained) */
        /* XXX: future: could try to send :status 431 here
         * and reset other active streams in H2_STATE_OPEN */
        else if (rc == LSHPACK_ERR_MORE_BUF) {
            /* XXX: TODO if (r->conf.log_request_header_on_error) */
            r->http_status = 431; /* Request Header Fields Too Large */
            /*(try to avoid reading/buffering more data for this request)*/
            r->x.h2.rwin = 0; /*(out-of-sync with peer, but is error case)*/
            /*r->x.h2.state = H2_STATE_HALF_CLOSED_REMOTE*/
            /* psrc was not advanced if LSHPACK_ERR_MORE_BUF;
             * processing must stop (since not retrying w/ larger buf)*/
            break;
        }
      #endif
        else { /* LSHPACK_ERR_BAD_DATA */
            /* GOAWAY with H2_E_PROTOCOL_ERROR is not specific enough
             * to tell peer to not retry request, so send RST_STREAM
             * (slightly more specific, but not by much) before GOAWAY*/
            /* LSHPACK_ERR_MORE_BUF is treated as an attack, send GOAWAY
             * (h2r->tmp_buf was resized to 64k in h2_init_con()) */
            request_h2error_t err = H2_E_COMPRESSION_ERROR;
            if (rc != LSHPACK_ERR_BAD_DATA) {
                /* LSHPACK_ERR_TOO_LARGE, LSHPACK_ERR_MORE_BUF */
                err = H2_E_PROTOCOL_ERROR;
              #if 0
                /* redundant: h2_send_goaway_e() sends RST_STREAM with
                 * H2_E_PROTOCOL_ERROR if GOAWAY not already sent.
                 * (If GOAWAY were sent with higher id, we would want
                 *  to send RST_STREAM here, but that is not the case) */
                h2_send_rst_stream(r, r->con, err);
              #endif
            }
            if (!hpctx.trailers) {
                h2con * const h2c = (h2con *)r->con->hx;
                if (!h2c->sent_goaway)
                    h2c->h2_cid = r->x.h2.id;
                h2_send_goaway_e(r->con, err);
                return;
            }
            h2_send_goaway_e(r->con, err);
            break;
        }
    }

    hpctx.hlen += 2;
    /* note: trailer field length is added here, too, and should be if merging
     * trailers into request headers.  If not, might increase buffer size optim
     * for preparing env for backends (though probably merging if not sent yet).
     * Also affects mod_magnet accessor lighty.r.req_item["req_header_len"] */
    r->rqst_header_len += hpctx.hlen;
    /*(accounting for mod_accesslog and mod_rrdtool)*/
    chunkqueue * const rq = &r->read_queue;
    rq->bytes_in  += (off_t)hpctx.hlen;
    rq->bytes_out += (off_t)hpctx.hlen;

    if (hpctx.trailers)
        return;

    if (hpctx.pseudo && 0 == r->http_status)
        r->http_status =
          http_request_validate_pseudohdrs(r, hpctx.scheme,
                                           hpctx.http_parseopts);

  #ifdef H2SPEC
    /* RFC 7540 Section 8. HTTP Message Exchanges
     * 8.1.2.6. Malformed Requests and Responses
     * RFC 9113 Section 8. Expressing HTTP Semantics in HTTP/2
     * 8.1.1. Malformed Messages
     *   For malformed requests, a server MAY send an HTTP
     *   response prior to closing or resetting the stream.
     * However, h2spec expects stream PROTOCOL_ERROR.
     * (This is unfortunate, since we would rather send
     *  400 Bad Request which tells client *do not* retry
     *  the bad request without modification)
     * https://github.com/summerwind/h2spec/issues/120
     * https://github.com/summerwind/h2spec/issues/121
     * https://github.com/summerwind/h2spec/issues/122
     */
    if (__builtin_expect( (400 == r->http_status), 0))
        h2_send_rst_stream(r, r->con, H2_E_PROTOCOL_ERROR);
  #endif

    http_request_headers_process_h2(r, r->con->proto_default_port);
}


__attribute_cold__
static int
h2_discard_headers (struct lshpack_dec * const restrict decoder, const unsigned char **psrc, const unsigned char * const restrict endp, const request_st * const restrict r, h2con * const h2c)
{
    /* If GOAWAY was sent with an error, return quickly without decoding;
     * choose *to not keep* HPACK decoder state in sync, since
     * h2_send_rst_stream_state() set r->state = CON_STATE_ERROR and
     * r->x.h2.state = H2_STATE_CLOSED for previously active streams. */
    if (h2c->sent_goaway > 0) return 0;

    /* Send error if too many discarded HEADERS frames.
     * (similar to h2_send_refused_stream())
     * Note: this could legitimately be triggered by a client sending trailers
     * after lighttpd has responded to and closed a stream, so no longer tracked
     * by lighttpd, but that is not expected to be a common scenario.  (Also, if
     * this were permitted without limit, it could be abused to bypass limit.)*/
    if (++h2c->n_discarded_headers > 32) {
        connection * const con = r->con;
        log_error(NULL, __FILE__, __LINE__,
          "h2: %s too many discarded requests",
          con->request.dst_addr_buf->ptr);
        h2_send_goaway_e(con, H2_E_ENHANCE_YOUR_CALM);
    }

    h2_discard_headers_frame(decoder, psrc, endp, r);

    /* return 1 to continue processing HTTP/2 frames
     * Note: if returning 0 to defer processing additional frames and
     * yield to other connections, must also joblist_append(con) unless
     * all h2c->r slots are full and next frame is HEADERS (which could
     * be passed in as a flag depending on the calling location) */
    return 1;
}


__attribute_noinline__
static int
h2_recv_headers (connection * const con, uint8_t * const s, uint32_t flen)
{
  #ifdef __COVERITY__
    /* Coverity does not notice that values used in s are checked.
     * Although silencing here, would prefer not to do so since doing so
     * disables Coverity from reporting questionable modifications which
     * might be made to the code in the future. */
    __coverity_tainted_data_sink__(s);
  #endif
    h2con * const h2c = (h2con *)con->hx;
    const uint32_t id = h2_u31(s+5);
  #if 0 /*(included in (!(id & 1)) below)*/
    if (0 == id) { /* HEADERS, PUSH_PROMISE stream id must != 0 */
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }
  #endif
    if (!(id & 1)) { /* stream id from client must be odd */
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }

    const unsigned char *psrc = s + 9;
    uint32_t alen = flen;
    if (s[4] & H2_FLAG_PADDED) {
        ++psrc;
        const uint32_t pad = s[9]; /*(reads '\0' after string if 0 == alen)*/
        if (alen < 1 + pad) {
            /* Padding that exceeds the size remaining for the header block
             * fragment MUST be treated as a PROTOCOL_ERROR. */
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        alen -= (1 + pad); /*(alen is adjusted for PRIORITY below)*/
    }
    if (s[4] & H2_FLAG_PRIORITY) {
        if (alen < 5) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        if (((/*prio = */h2_u32(psrc)) == id) & (id > h2c->h2_cid)) {
            /*(ignore dep if HEADERS frame is trailers (id <= h2c->h2_cid)*/
            /* https://www.rfc-editor.org/rfc/rfc7540#section-5.3.1
             * A stream cannot depend on itself.  An endpoint MUST treat this
             * as a stream error (Section 5.4.2) of type PROTOCOL_ERROR.*/
            h2_send_rst_stream_id(id, con, H2_E_PROTOCOL_ERROR);
            /* PRIORITY is deprecated in RFC9113.  As this mistake is now more
             * likely an attack, follow with goaway error since HEADERS frame
             * is not HPACK decoded here to maintain HPACK decoder state. */
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
      #if 0
        uint32_t exclusive_dependency = (psrc[0] & 0x80) ? 1 : 0;
        /*(ignore dependency prid and exclusive_dependency,
         * and attempt to scale PRIORITY weight (weight+1 default is 16)
         * to PRIORITY_UPDATE (default urgency 3) (see h2_init_stream()))*/
        uint8_t weight = psrc[4] >> 2;
        r->x.h2.prio = ((weight < 8 ? weight : 7) << 1) | !0;
      #endif
        psrc += 5;
        alen -= 5;
    }

    if (id <= h2c->h2_cid) { /* (trailers; cold code path) */
        request_st * const r = h2_recv_trailers_r(con, h2c, id, s[4]);
        if (NULL == r)
            return h2_discard_headers(&h2c->decoder, &psrc, psrc+alen,
                                      &con->request, h2c);
        h2_parse_headers_frame(&h2c->decoder,&psrc,psrc+alen,r,1);/*(trailers)*/
        return 1;
    }

    /* Note: MUST process HPACK decode even if already sent GOAWAY.
     * This is necessary since there may be active streams not in
     * H2_STATE_HALF_CLOSED_REMOTE, e.g. H2_STATE_OPEN, still possibly
     * receiving DATA and, more relevantly, still might receive HEADERS
     * frame with trailers, for which the decoder state may be required. */

    if (h2c->sent_goaway)
        return h2_discard_headers(&h2c->decoder, &psrc, psrc+alen,
                                  &con->request, h2c);

  #if 0 /*(handled in h2_parse_frames() as a connection error)*/
    if (s[3] == H2_FTYPE_PUSH_PROMISE) {
        /* discard the request if PUSH_PROMISE, since not expected, as this code
         * is running as a server, not as a client. */
        /* note: h2_parse_headers_frame() sets h2c->h2_cid on HPACK decode error
         * and would need to be changed for code to be shared by PUSH_PROMISE */
        /* rant: PUSH_PROMISE could have been a flag on HEADERS frame
         *       instead of an independent frame type */
        h2c->h2_sid = id;
        return h2_discard_headers(&h2c->decoder, &psrc, psrc+alen,
                                  &con->request, h2c);
    }
  #endif

    /* new stream */

        if (h2c->rused == sizeof(h2c->r)/sizeof(*h2c->r))
            return h2_send_refused_stream(id, con) == -1
              ? -1
              : h2_discard_headers(&h2c->decoder, &psrc, psrc+alen,
                                   &con->request, h2c);

        request_st * const h2r = &con->request;
        request_st * const r = h2_init_stream(h2r, con);
        r->x.h2.id = id;
        if (s[4] & H2_FLAG_END_STREAM) {
            r->x.h2.state = H2_STATE_HALF_CLOSED_REMOTE;
            r->state = CON_STATE_HANDLE_REQUEST;
            r->reqbody_length = 0;
        }
        else {
            r->x.h2.state = H2_STATE_OPEN;
            r->state = CON_STATE_READ_POST;
            r->reqbody_length = -1;
        }
        /* Note: timestamps here are updated only after receipt of entire header
         * (HEADERS frame might have been sent in multiple packets
         *  and CONTINUATION frames may have been sent in multiple packets)
         * (affects high precision timestamp, if enabled)
         * (large sets of headers are not typical, and even when they do
         *  occur, they will typically be sent within the same second)
         * (future: might keep high precision timestamp in h2con when first
         *  packet of HEADERS or PUSH_PROMISE is received, and clear that
         *  timestamp when frame + CONTINUATION(s) are complete (so that
         *  re-read of initial frame does not overwrite the timestamp))
         */
        r->start_hp.tv_sec = log_epoch_secs;
        if (r->conf.high_precision_timestamps)
            log_clock_gettime_realtime(&r->start_hp);

    h2_parse_headers_frame(&h2c->decoder, &psrc, psrc+alen, r, 0); /*(headers)*/

    if (!h2c->sent_goaway) {
        h2c->h2_cid = id;

        /* counter to detect HTTP/2 rapid reset attack (CVE-2023-44487)
         * HTTP/2 client ids are odds, so use mask 0x1f
         * in order to reset lower counter every 16 requests */
        if ((id & 0x1f) == 0x1) h2c->n_recv_rst_stream <<= 4;

        /*(lighttpd.conf config conditions not yet applied to request,
         * but do not increase window size if BUFMIN set in global config)*/
        if (r->reqbody_length /*(see h2_init_con() for session window)*/
            && !(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN))
            h2_send_window_update(con, id, 131072); /*(add 128k)*/

        if (light_btst(r->rqst_htags, HTTP_HEADER_PRIORITY)) {
            const buffer * const prio =
              http_header_request_get(r, HTTP_HEADER_PRIORITY,
                                      CONST_STR_LEN("priority"));
            r->x.h2.prio = h2_parse_priority_update(BUF_PTR_LEN(prio));
        }
        else {
          #if 0
            /* TODO: might check to match saved prid if PRIORITY_UPDATE frame
             * received prior to HEADERS, and apply urgency, incremental vals */
            if (0)
                r->x.h2.prio = x;
            else
          #endif
            {   /*(quick peek at raw (non-normalized) r->target)*/
                /*(bump .js and .css to urgency 2; see h2_init_stream())*/
                const uint32_t len = buffer_clen(&r->target);
                const char * const p = r->target.ptr+len-4;
                if (len>=4 && (0==memcmp(p+1,".js",3)||0==memcmp(p,".css",4))) {
                    r->x.h2.prio = (2 << 1) | !0; /*(urgency=2, incremental=0)*/
                    http_header_response_set(r, HTTP_HEADER_PRIORITY,
                                             CONST_STR_LEN("priority"),
                                             CONST_STR_LEN("u=2"));
                }
            }
        }
        if (h2c->rused-1) /*(true if more than one active stream)*/
            h2_apply_priority_update(h2c, r, h2c->rused-1);
    }
    else {
        /* Had to process HPACK to keep HPACK tables sync'd with peer
         * but now discard the request */
        r->http_status = 0;
        h2_retire_stream(r, con);
    }

    return 1;
}


static int
h2_parse_frames (connection * const con)
{
    /* read and process HTTP/2 frames from socket */
    h2con * const h2c = (h2con *)con->hx;
    chunkqueue * const cq = con->read_queue;
    /* initial max frame size is the minimum: 16k
     * (lighttpd does not currently increase max frame size)
     * (lighttpd does not currently decrease max frame size)
     * (XXX: If SETTINGS_MAX_FRAME_SIZE were increased and then decreased,
     *       should accept the larger frame size until SETTINGS is ACK'd) */
    const uint32_t fsize = h2c->s_max_frame_size;
    for (off_t cqlen; (cqlen = chunkqueue_length(cq)) >= 9; ) {

        /* defer parsing additional frames if large output queue pending write*/
        if (__builtin_expect( (chunkqueue_length(con->write_queue) > 65536), 0))
            return 0;

        chunk *c = cq->first;
        /*assert(c->type == MEM_CHUNK);*/
        /* copy data if frame header crosses chunk boundary
         * future: be more efficient than blind full chunk copy */
        uint32_t clen = buffer_clen(c->mem) - c->offset;
        if (clen < 9) {
            clen = h2_frame_cq_compact(cq, 9);
            c = cq->first; /*(reload after h2_frame_cq_compact())*/
        }
        uint8_t *s = (uint8_t *)(c->mem->ptr + c->offset);
        uint32_t flen = h2_u24(s);
        if (flen > fsize) {
            h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
            return 0;
        }
        if (cqlen < 9+flen) return 1; /* incomplete frame; go on */

        /*(handle PUSH_PROMISE as connection error further below)*/
        /*if (s[3] == H2_FTYPE_HEADERS || s[3] == H2_FTYPE_PUSH_PROMISE)*/

        if (s[3] == H2_FTYPE_HEADERS) {
            if (clen < 9+flen) {
                clen = h2_frame_cq_compact(cq, 9+flen);
                c = cq->first; /*(reload after h2_frame_cq_compact())*/
                s = (uint8_t *)(c->mem->ptr + c->offset);
            }

            if (!(s[4] & H2_FLAG_END_HEADERS)) {
                /* collect CONTINUATION frames (cold code path) */
                /* note: h2_recv_continuation() return value is overloaded
                 * and the resulting clen is 9+flen of *concatenated* frames */
                clen = h2_recv_continuation(9+flen, clen, cqlen, cq, con);
                if (0 == clen)    return 0;
                if (cqlen < clen) return 1; /* incomplete frames; go on */
                c = cq->first; /*(reload after h2_recv_continuation())*/
                s = (uint8_t *)(c->mem->ptr + c->offset);
                /* frame size was also updated and might (legitimately)
                 * exceed SETTINGS_MAX_FRAME_SIZE, so do not test fsize again */
                flen = h2_u24(s);
                /* recalculate after CONTINUATION removed */
                /*cqlen = chunkqueue_length(cq);*/
            }

          #ifdef __COVERITY__
            /* Coverity does not notice that values used in s are checked.
             * Although silencing here, would prefer not to do so since doing so
             * disables Coverity from reporting questionable modifications which
             * might be made to the code in the future. */
            __coverity_tainted_data_sink__(s);
          #endif

            int rc = h2_recv_headers(con, s, flen);
            if (rc >= 0)
                chunkqueue_mark_written(cq, 9+flen);
            if (rc <= 0)
                return 0;
            con->read_idle_ts = log_monotonic_secs;
        }
        else if (s[3] == H2_FTYPE_DATA) {
            /* future: might try to stream data for incomplete frames,
             * but that would require keeping additional state for partially
             * read frames, including cleaning up if errors occur.
             * Since well-behaved clients do not intentionally send partial
             * frames, and try to resend if socket buffers are full, this is
             * probably not a big concern in practice. */
            con->read_idle_ts = log_monotonic_secs;
            /*(h2_recv_data() must consume frame from cq or else return 0)*/
            if (!h2_recv_data(con, s, flen))
                return 0;
        }
        else {
            /* frame types below are expected to be small
             * most frame types below have fixed (small) size
             *   4 bytes - WINDOW_UPDATE
             *   5 bytes - PRIORITY
             *   8 bytes - PING
             *   4 bytes - RST_STREAM
             * some are variable size
             *     SETTINGS (6 * #settings; 6 defined in RFC 7540 Section 6.5)
             *     GOAWAY   (8 + optional additional debug data (variable))
             * XXX: might add sanity check for a max flen here,
             *      before waiting to read partial frame
             *      (fsize limit is still enforced above for all frames)
             */
            if (clen < 9+flen) {
                clen = h2_frame_cq_compact(cq, 9+flen); UNUSED(clen);
                c = cq->first; /*(reload after h2_frame_cq_compact())*/
                s = (uint8_t *)(c->mem->ptr + c->offset);
            }
            switch (s[3]) { /* frame type */
              case H2_FTYPE_WINDOW_UPDATE:
                h2_recv_window_update(con, s, flen);
                break;
              case H2_FTYPE_PRIORITY_UPDATE:
                h2_recv_priority_update(con, s, flen);
                break;
              case H2_FTYPE_SETTINGS:
                h2_recv_settings(con, s, flen);
                break;
              case H2_FTYPE_PING:
                h2_recv_ping(con, s, flen);
                break;
              case H2_FTYPE_RST_STREAM:
                h2_recv_rst_stream(con, s, flen);
                break;
              case H2_FTYPE_GOAWAY:
                if (!h2_recv_goaway(con, s, flen)) return 0;
                break;
              case H2_FTYPE_PRIORITY:
                h2_recv_priority(con, s, flen);
                break;
              case H2_FTYPE_PUSH_PROMISE: /*not expected from client*/
              case H2_FTYPE_CONTINUATION: /*handled with HEADERS*/
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
                return 0;
              default: /* ignore unknown frame types */
                break;
            }
            chunkqueue_mark_written(cq, 9+flen);
        }

        if (h2c->sent_goaway > 0) return 0;
    }

    return 1;
}


static int
h2_want_read (connection * const con)
{
    chunkqueue * const cq = con->read_queue;
    if (chunkqueue_is_empty(cq)) return 1;

    /* check for partial frame */
    const off_t cqlen = chunkqueue_length(cq);
    if (cqlen < 9) return 1;
    chunk *c = cq->first;
    uint32_t clen = buffer_clen(c->mem) - c->offset;
    if (clen < 9) {
        clen = h2_frame_cq_compact(cq, 9);
        c = cq->first; /*(reload after h2_frame_cq_compact())*/
    }
    uint8_t *s = (uint8_t *)(c->mem->ptr + c->offset);
    uint32_t flen = h2_u24(s);
    if (clen < 9+flen) return 1;

    /* check if not HEADERS, or if HEADERS has END_HEADERS flag */
    if (s[3] != H2_FTYPE_HEADERS || (s[4] & H2_FLAG_END_HEADERS))
        return 0;

    /* check for partial CONTINUATION frames */
    for (uint32_t n = 9+flen; cqlen >= n+9; n += 9+flen) {
        if (clen < n+9) {
            clen = h2_frame_cq_compact(cq, n+9);
            c = cq->first; /*(reload after h2_frame_cq_compact())*/
            s = (uint8_t *)(c->mem->ptr + c->offset);
        }
        flen = h2_u24(s+n);
        if (cqlen < n+9+flen) return 1; /* incomplete frame; go on */
        if (s[4] & H2_FLAG_END_HEADERS) return 0;
    }

    return 1;
}


static int
h2_recv_client_connection_preface (connection * const con)
{
    /* check if the client Connection Preface (24 bytes) has been received
     * (initial SETTINGS frame should immediately follow, but is not checked) */
    chunkqueue * const cq = con->read_queue;
    if (chunkqueue_length(cq) < 24) {
        chunk * const c = cq->first;
        if (c && buffer_clen(c->mem) - c->offset >= 4) {
            const char * const s = c->mem->ptr + c->offset;
            if (s[0]!='P'||s[1]!='R'||s[2]!='I'||s[3]!=' ') {
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
                return 1; /* error; done receiving connection preface */
            }
        }
        return 0; /*(not ready yet)*/
    }

    static const char h2preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    chunk *c = cq->first;
    const uint32_t clen = buffer_clen(c->mem) - c->offset;
    if (clen < 24) h2_frame_cq_compact(cq, 24);
    c = cq->first; /*(reload after h2_frame_cq_compact())*/
    const uint8_t * const s = (uint8_t *)(c->mem->ptr + c->offset);
    if (0 == memcmp(s, h2preface, 24)) /* sizeof(h2preface)-1) */
        chunkqueue_mark_written(cq, 24);
    else
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
    return 1; /* done receiving connection preface (even if error occurred) */
}


__attribute_cold__
static int
h2_read_client_connection_preface (struct connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    /* temporary con->network_read() filter until connection preface received */

    /*(alternatively, func ptr could be saved in an element in (h2con *))*/
    void ** const hctx = con->plugin_ctx+0; /*(0 idx used for h2)*/
    int(* const network_read)(struct connection *, chunkqueue *, off_t) =
      (int(*)(struct connection *, chunkqueue *, off_t))(uintptr_t)(*hctx);
    if (max_bytes < 24) max_bytes = 24; /*(should not happen)*/
    int rc = (network_read)(con, cq, max_bytes);
    if (NULL == con->hx) return rc; /*(unexpected; already cleaned up)*/
    if (-1 != rc && h2_recv_client_connection_preface(con)) {
        con->network_read = network_read;
        *hctx = NULL;
        /*(intentionally update timestamp only after reading preface complete)*/
        con->read_idle_ts = log_monotonic_secs;
    }
    return rc;
}


#define connection_set_state(r,state)       request_set_state((r),(state))
#define connection_set_state_error(r,state) request_set_state_error((r),(state))


__attribute_cold__
static int
h2_send_goaway_graceful (connection * const con)
{
    request_st * const h2r = &con->request;
    int changed = 0;
    if (h2r->state == CON_STATE_WRITE) {
        h2con * const h2c = (h2con *)con->hx;
        if (!h2c->sent_goaway) {
            h2_send_goaway(con, H2_E_NO_ERROR);
            changed = 1;
        }
      #if 0
        /* XXX: (disabled for now)
         * well-behaved clients should close websocket streams after GOAWAY
         * (might enable this if that turns out not to be the case) */

        /* For streams in transparent proxy mode, trigger behavior as if
         * TCP FIN received from client, as tunnels (e.g. websockets) are
         * otherwise opaque */
        for (uint32_t i = 0; i < h2c->rused; ++i) {
            request_st * const r = h2c->r[i];
            if (r->reqbody_length != -2)
                continue;
            if (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_TCP_FIN)
                continue;
            r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;
            changed = 1;
        }
      #endif
    }
    return changed;
}


static void
h2_init_con (request_st * const restrict h2r, connection * const restrict con)
{
    h2con * const h2c = ck_calloc(1, sizeof(h2con));
    con->hx = (hxcon *)h2c;
    con->fn = &http_dispatch[HTTP_VERSION_2];
    con->reqbody_read = h2_recv_reqbody;
    con->read_idle_ts = log_monotonic_secs;
    con->keep_alive_idle = h2r->conf.max_keep_alive_idle;

    h2r->x.h2.rwin = 262144;              /* h2 connection recv window (256k)*/
    h2r->x.h2.swin = 65535;               /* h2 connection send window */
    h2r->x.h2.rwin_fudge = 0;
    /* settings sent from peer */         /* initial values */
    h2c->s_header_table_size     = 4096;  /* SETTINGS_HEADER_TABLE_SIZE      */
    h2c->s_enable_push           = 1;     /* SETTINGS_ENABLE_PUSH            */
    h2c->s_max_concurrent_streams= ~0u;   /* SETTINGS_MAX_CONCURRENT_STREAMS */
    h2c->s_initial_window_size   = 65536; /* SETTINGS_INITIAL_WINDOW_SIZE    */
    h2c->s_max_frame_size        = 16384; /* SETTINGS_MAX_FRAME_SIZE         */
    h2c->s_max_header_list_size  = ~0u;   /* SETTINGS_MAX_HEADER_LIST_SIZE   */
    h2c->sent_settings           = log_monotonic_secs;/*(send SETTINGS below)*/
    /* avoid incorrect protocol handling when monotonic clock starts at zero */
    if (!h2c->sent_settings) h2c->sent_settings = 1;/*(boolean and timestamp)*/

    lshpack_dec_init(&h2c->decoder);
    lshpack_enc_init(&h2c->encoder);
    lshpack_enc_use_hist(&h2c->encoder, 1);

    static const uint8_t h2settings[] = { /*(big-endian numbers)*/
      /* SETTINGS */
      0x00, 0x00, 0x1e        /* frame length */ /* 5 * (6 bytes per setting) */
     ,H2_FTYPE_SETTINGS       /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier */
     ,0x00, H2_SETTINGS_MAX_CONCURRENT_STREAMS
     ,0x00, 0x00, 0x00, 0x08  /* 8 */
     #if 0  /* ? explicitly disable dynamic table ? (and adjust frame length) */
            /* If this is sent, must wait until peer sends SETTINGS with ACK
             * before disabling dynamic table in HPACK decoder */
            /*(before calling lshpack_dec_set_max_capacity(&h2c->decoder, 0))*/
     ,0x00, H2_SETTINGS_HEADER_TABLE_SIZE
     ,0x00, 0x00, 0x00, 0x00  /* 0 */
     #endif
     #if 0  /* ? explicitly disable push ?       (and adjust frame length) */
     ,0x00, H2_SETTINGS_ENABLE_PUSH
     ,0x00, 0x00, 0x00, 0x00  /* 0 */
     #endif
     ,0x00, H2_SETTINGS_INITIAL_WINDOW_SIZE /*(must match in h2_init_stream())*/
     ,0x00, 0x01, 0x00, 0x00  /* 65536 *//*multiple of SETTINGS_MAX_FRAME_SIZE*/
     #if 0  /* ? increase from default (16384) ? (and adjust frame length) */
     ,0x00, H2_SETTINGS_MAX_FRAME_SIZE
     ,0x00, 0x00, 0x80, 0x00  /* 32768 */
     #endif
     ,0x00, H2_SETTINGS_MAX_HEADER_LIST_SIZE
     ,0x00, 0x00, 0xFF, 0xFF  /* 65535 */
     ,0x00, H2_SETTINGS_ENABLE_CONNECT_PROTOCOL
     ,0x00, 0x00, 0x00, 0x01  /* 1 */
     ,0x00, H2_SETTINGS_NO_RFC7540_PRIORITIES
     ,0x00, 0x00, 0x00, 0x01  /* 1 */

      /* WINDOW_UPDATE */
     ,0x00, 0x00, 0x04        /* frame length */
     ,H2_FTYPE_WINDOW_UPDATE  /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier */
     ,0x00, 0x03, 0x00, 0x01  /* 196609 *//*(increase connection rwin to 256k)*/
    };

    chunkqueue_append_mem(con->write_queue,
                          (const char *)h2settings, sizeof(h2settings));

    if (!h2_recv_client_connection_preface(con)) {
        /*(alternatively, func ptr could be saved in an element in (h2con *))*/
        con->plugin_ctx[0] = (void *)(uintptr_t)con->network_read;
        con->network_read = h2_read_client_connection_preface;
        /* note: no steps taken to reset con->network_read() on error
         * as con->network_read() is always set in connection_accepted() */
    }

    buffer_string_prepare_copy(h2r->tmp_buf, 65535);
}


static void
h2_send_hpack (request_st * const r, connection * const con, const char *data, uint32_t dlen, const uint32_t flags)
{
    union {
      uint8_t c[12];
      uint32_t u[3];          /*(alignment)*/
    } headers = { {           /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* HEADERS */
     ,0x00, 0x00, 0x00        /* frame length      (fill in below) */
     ,H2_FTYPE_HEADERS        /* frame type */
     ,(uint8_t)flags          /* frame flags (e.g. END_STREAM for trailers) */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier (fill in below) */
    } };

    headers.u[2] = htonl(r->x.h2.id);

    if (flags & H2_FLAG_END_STREAM) {
        /* step r->x.h2.state
         *   H2_STATE_OPEN -> H2_STATE_HALF_CLOSED_LOCAL
         * or
         *   H2_STATE_HALF_CLOSED_REMOTE -> H2_STATE_CLOSED */
      #if 1
        ++r->x.h2.state;
      #else
        r->x.h2.state = (r->x.h2.state == H2_STATE_HALF_CLOSED_REMOTE)
          ? H2_STATE_CLOSED
          : H2_STATE_HALF_CLOSED_LOCAL;
      #endif
    }

    /* similar to h2_send_data(), but unlike DATA frames there is a HEADERS
     * frame potentially followed by CONTINUATION frame(s) here, and the final
     * HEADERS or CONTINUATION frame here has END_HEADERS flag set.
     * For trailers, END_STREAM flag is set on HEADERS frame. */

    /*(approximate space needed for frames (header + payload)
     * with slight over-estimate of 16 bytes per frame header (> 9)
     * and minimum SETTING_MAX_FRAME_SIZE of 16k (could be larger)
     * (dlen >> 14)+1 is num 16k frames needed, multiplied by 16 bytes
     *  per frame can be appoximated with (dlen>>10) + 9)*/
    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, dlen + (dlen>>10) + 9);
    char * restrict ptr = b->ptr;
    h2con * const h2c = (h2con *)con->hx;
    const uint32_t fsize = h2c->s_max_frame_size;
    do {
        const uint32_t len = dlen < fsize ? dlen : fsize;
        headers.c[3] = (len >> 16) & 0xFF; /*(off +3 to skip over align pad)*/
        headers.c[4] = (len >>  8) & 0xFF;
        headers.c[5] = (len      ) & 0xFF;
        if (len == dlen)
            headers.c[7] |= H2_FLAG_END_HEADERS;
      #if 0
        chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align pad)*/
                              (const char *)headers.c+3, sizeof(headers)-3);
        chunkqueue_append_mem(con->write_queue, data, len);
      #else
        memcpy(ptr, headers.c+3, sizeof(headers)-3);
        memcpy(ptr+sizeof(headers)-3, data, len);
        ptr  += len + sizeof(headers)-3;
      #endif
        data += len;
        dlen -= len;
        /*(include H2_FLAG_END_STREAM in HEADERS frame, not CONTINUATION)*/
        headers.c[6] = H2_FTYPE_CONTINUATION; /*(if additional frames needed)*/
        headers.c[7] = 0x00; /*(off +3 to skip over align pad)*/
    } while (dlen);
    buffer_truncate(b, (uint32_t)(ptr - b->ptr));
    chunkqueue_append_buffer_commit(con->write_queue);
}


__attribute_cold__
__attribute_noinline__
static void
h2_log_response_header_lsx(request_st * const r, const lsxpack_header_t * const lsx)
{
    log_debug(r->conf.errh, __FILE__, __LINE__,
      "fd:%d id:%u resp: %.*s: %.*s", r->con->fd, r->x.h2.id,
      (int)lsx->name_len, lsx->buf + lsx->name_offset,
      (int)lsx->val_len,  lsx->buf + lsx->val_offset);
}


__attribute_cold__
static void
h2_log_response_header(request_st * const r, const int len, const char * const hdr)
{
    log_debug(r->conf.errh, __FILE__, __LINE__,
      "fd:%d id:%u resp: %.*s", r->con->fd, r->x.h2.id, len, hdr);
}


static void
h2_send_headers (request_st * const r, connection * const con)
{
    /*(set keep_alive_idle; out-of-place and non-event for most configs,
     * but small attempt to (maybe) preserve behavior for specific configs)*/
    con->keep_alive_idle = r->conf.max_keep_alive_idle;

    /* specialized version of http_response_write_header(); send headers
     * directly to HPACK encoder, rather than double-buffering in chunkqueue */

    if (304 == r->http_status
        && light_btst(r->resp_htags, HTTP_HEADER_CONTENT_ENCODING))
        http_header_response_unset(r, HTTP_HEADER_CONTENT_ENCODING,
                                   CONST_STR_LEN("Content-Encoding"));

    /*(h2_init_con() resized h2r->tmp_buf to 64k; shared with r->tmp_buf)*/
    buffer * const tb = r->tmp_buf;
    force_assert(tb->size >= 65536);/*(sanity check; remove in future)*/
    unsigned char *dst = (unsigned char *)tb->ptr;
    unsigned char * const dst_end = (unsigned char *)tb->ptr + tb->size;

    h2con * const h2c = (h2con *)con->hx;
    struct lshpack_enc * const encoder = &h2c->encoder;
    lsxpack_header_t lsx;
    uint32_t alen = 7+3+4; /* ":status: xxx\r\n" */
    const int log_response_header = r->conf.log_response_header;
    const int resp_header_repeated = r->resp_header_repeated;

    /*char status[] = ":status: 200";*/
    char status[12] = {':','s','t','a','t','u','s',':',' ','2','0','0'};

    memset(&lsx, 0, sizeof(lsxpack_header_t));
    lsx.buf = status;
    lsx.name_offset = 0;
    lsx.name_len = 7;
    lsx.val_offset = 9;
    lsx.val_len = 3;
    lsx.flags = LSXPACK_HPACK_VAL_MATCHED;
    if (__builtin_expect( (200 == r->http_status), 1)) {
        lsx.hpack_index = LSHPACK_HDR_STATUS_200;
    }
    else {
        int x = r->http_status; /*(expect status < 1000; should be [100-599])*/
        switch (x) {
          /*case 200: lsx.hpack_index = LSHPACK_HDR_STATUS_200; break;*/
          case 204: lsx.hpack_index = LSHPACK_HDR_STATUS_204; break;
          case 206: lsx.hpack_index = LSHPACK_HDR_STATUS_206; break;
          case 304: lsx.hpack_index = LSHPACK_HDR_STATUS_304; break;
          case 400: lsx.hpack_index = LSHPACK_HDR_STATUS_400; break;
          case 404: lsx.hpack_index = LSHPACK_HDR_STATUS_404; break;
          case 500: lsx.hpack_index = LSHPACK_HDR_STATUS_500; break;
          default:
            lsx.flags = 0;
            break;
        }
        int nx;
        status[11] += (x - (nx = x/10) * 10); /* (x % 10) */
        x = nx;
        status[10] += (x - (nx = x/10) * 10); /* (x / 10 % 10) */
        status[9]   = '0' + nx;               /* (x / 100) */
    }

    dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
    if (dst == (unsigned char *)tb->ptr) {
        h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
        return;
    }

    if (log_response_header)
        h2_log_response_header(r, 12, status);

    /* add all headers */
    data_string * const * const restrict hdata =
      (data_string * const *)r->resp_headers.data;
    for (uint32_t i = 0, used = r->resp_headers.used; i < used; ++i) {
        data_string * const ds = hdata[i];
        const uint32_t klen = buffer_clen(&ds->key);
        const uint32_t vlen = buffer_clen(&ds->value);
        if (__builtin_expect( (0 == klen), 0)) continue;
        if (__builtin_expect( (0 == vlen), 0)) continue;
        alen += klen + vlen + 4;

        if (alen > LSXPACK_MAX_STRLEN) {
            /* ls-hpack default limit (UINT16_MAX) is per-line, due to field
             * sizes of lsx.name_offset,lsx.name_len,lsx.val_offset,lsx.val_len
             * However, similar to elsewhere, limit total size of expanded
             * headers to (very generous) 64k - 1.  Peers might allow less. */
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            return;
        }

        /* HTTP/2 requires lowercase keys
         * ls-hpack requires key and value be in same buffer
         * Since keys are typically short, append (and lowercase) key onto
         * end of value buffer, following '\0' after end of value, and
         * without modifying ds->value.used or overwriting '\0' */
        char * const v =
          __builtin_expect( (buffer_string_space(&ds->value) >= klen), 1)
          ? ds->value.ptr+vlen+1 /*perf: inline check before call*/
          : buffer_string_prepare_append(&ds->value, klen)+1;
        if (__builtin_expect( (ds->ext != HTTP_HEADER_OTHER), 1)) {
            memcpy(v, http_header_lc[ds->ext], klen);
        }
        else {
            const char * const restrict k = ds->key.ptr;
            if ((k[0] & 0xdf) == 'X' && http_response_omit_header(r, ds)) {
                alen -= klen + vlen + 4;
                continue;
            }
            for (uint32_t j = 0; j < klen; ++j)
                v[j] = !light_isupper(k[j]) ? k[j] : (k[j] | 0x20);
        }

        uint32_t voff = 0;
        const char *n;
        lsx.buf = ds->value.ptr;
        do {
            n = !resp_header_repeated
              ? NULL
              : memchr(lsx.buf+voff, '\n', vlen - voff);

            memset(&lsx, 0, sizeof(lsxpack_header_t));
            lsx.hpack_index = http_header_lshpack_idx[ds->ext];
            lsx.buf = ds->value.ptr;
            lsx.name_offset = vlen+1;
            lsx.name_len = klen;
            lsx.val_offset = voff;
            if (NULL == n)
                lsx.val_len = vlen - voff;
            else {
                /* multiple headers (same field-name) separated by "\r\n"
                 * and then "field-name: " (see http_header_response_insert())*/
                voff = (uint32_t)(n + 1 - lsx.buf);
                lsx.val_len = voff - 2 - lsx.val_offset; /*(-2 for "\r\n")*/
                voff += klen + 2;
            }

            if (log_response_header)
                h2_log_response_header_lsx(r, &lsx);

            unsigned char * const dst_in = dst;
            dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
            if (dst == dst_in) {
                h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
                return;
            }
        } while (n);
    }

    if (!light_btst(r->resp_htags, HTTP_HEADER_DATE)) {
        /* HTTP/1.1 and later requires a Date: header */
        /* "date: " 6-chars + 30-chars for "%a, %d %b %Y %T GMT" + '\0' */
        static unix_time64_t tlast = 0;
        static char tstr[36] = "date: ";

        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = tstr;
        lsx.name_offset = 0;
        lsx.name_len = 4;
        lsx.val_offset = 6;
        lsx.val_len = 29;
        lsx.hpack_index = LSHPACK_HDR_DATE;

        /* cache the generated timestamp */
        const unix_time64_t cur_ts = log_epoch_secs;
        if (__builtin_expect ( (tlast != cur_ts), 0))
            http_date_time_to_str(tstr+6, sizeof(tstr)-6, (tlast = cur_ts));

        alen += 35+2;

        if (log_response_header)
            h2_log_response_header(r, 35, tstr);

        unsigned char * const dst_in = dst;
        dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
        if (dst == dst_in) {
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            return;
        }
    }

    if (!light_btst(r->resp_htags, HTTP_HEADER_SERVER) && r->conf.server_tag) {
        /*("server" is appended after '\0' in r->conf.server_tag at startup)*/
        const uint32_t vlen = buffer_clen(r->conf.server_tag);

        alen += 6+vlen+4;

        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = r->conf.server_tag->ptr;
        lsx.name_offset = vlen+1;
        lsx.name_len = 6;
        lsx.val_offset = 0;
        lsx.val_len = vlen;
        lsx.hpack_index = LSHPACK_HDR_SERVER;

        if (log_response_header)
            h2_log_response_header_lsx(r, &lsx);

        unsigned char * const dst_in = dst;
        dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
        if (dst == dst_in) {
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            return;
        }
    }

    alen += 2; /* "virtual" blank line ("\r\n") ending headers */
    r->resp_header_len = alen;
    /*(accounting for mod_accesslog and mod_rrdtool)*/
    chunkqueue * const wq = &r->write_queue;
    wq->bytes_in  += (off_t)alen;
    wq->bytes_out += (off_t)alen;

    const uint32_t dlen = (uint32_t)((char *)dst - tb->ptr);
    const uint32_t flags =
     #if 1
      (r->resp_body_finished && chunkqueue_is_empty(&r->write_queue))
     #else /*(see src/response.c:http_response_merge_trailers())*/
      (r->resp_body_finished && chunkqueue_is_empty(&r->write_queue)
       && (!r->gw_dechunk || buffer_is_unset(&r->gw_dechunk->b)))
     #endif
        ? H2_FLAG_END_STREAM
        : 0;
    h2_send_hpack(r, con, tb->ptr, dlen, flags);
}


__attribute_cold__
__attribute_noinline__
static void
h2_send_headers_hoff (request_st * const r, connection * const con, const char *hdrs, const unsigned short hoff[8192], uint32_t flags);

__attribute_cold__
__attribute_noinline__
static void
h2_send_headers_block (request_st * const r, connection * const con, char *hdrs, const uint32_t hlen, uint32_t flags)
{
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */
    hoff[0] = 1;                         /* number of lines */
    hoff[1] = 0;                         /* base offset for all lines */
    /*hoff[2] = ...;*/                   /* offset from base for 2nd line */
    uint32_t rc = http_header_parse_hoff(hdrs, hlen, hoff);
    if (rc != hlen || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1
        || 1 == hoff[0]) { /*(initial blank line (should not happen))*/
        /* error if headers incomplete or too many header fields */
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "oversized response-header");
      #if 0 /*(recursive call might add additional 16k stack use)*/
        h2_send_headers_block(r, con, CONST_STR_LEN(":status: 502\r\n\r\n"), flags);
        return;
      #else
        hoff[0] = 1;
        hoff[1] = 0;
        hdrs = ":status: 502\r\n\r\n";
       #if 0
        if (http_header_parse_hoff(CONST_STR_LEN(":status: 502\r\n\r\n"),hoff)){
            /*(ignore for coverity; static string is successfully parsed)*/
        }
       #else
        hoff[2] = 14;
        hoff[3] = 16;
       #endif
      #endif
    }
    h2_send_headers_hoff(r, con, hdrs, hoff, flags);
}

__attribute_cold__
__attribute_noinline__
static void
h2_send_headers_hoff (request_st * const r, connection * const con, const char *hdrs, const unsigned short hoff[8192], uint32_t flags)
{
    /*(h2_init_con() resized h2r->tmp_buf to 64k; shared with r->tmp_buf)*/
    buffer * const tb = r->tmp_buf;
    force_assert(tb->size >= 65536);/*(sanity check; remove in future)*/
    unsigned char *dst = (unsigned char *)tb->ptr;
    unsigned char * const dst_end = (unsigned char *)tb->ptr + tb->size;

    h2con * const h2c = (h2con *)con->hx;
    struct lshpack_enc * const encoder = &h2c->encoder;
    lsxpack_header_t lsx;

    int i = 1;
    if (hdrs[0] == ':') {
        i = 2;
        /* expect first line to contain ":status: ..." if pseudo-header,
         * and expecting single pseudo-header for headers, zero for trailers */
        /*assert(0 == memcmp(hdrs, ":status: ", sizeof(":status: ")-1));*/
        memset(&lsx, 0, sizeof(lsxpack_header_t));
        *(const char **)&lsx.buf = hdrs;
        lsx.name_offset = 0;
        lsx.name_len = sizeof(":status")-1;
        lsx.val_offset = lsx.name_len + 2;
        lsx.val_len = 3;
        dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
        if (dst == (unsigned char *)tb->ptr) {
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            return;
        }
    }

    /*(note: not expecting any other pseudo-headers)*/

    /* note: expects field-names are lowercased (http_response_write_header())*/

    for (; i < hoff[0]; ++i) {
        const char *k = hdrs + hoff[i]; /*hdrs + ((i > 1) ? hoff[i] : 0);*/
        const char *end = hdrs + hoff[i+1];
        const char *v = memchr(k, ':', end-k);
        /* XXX: DOES NOT handle line wrapping (which is deprecated by RFCs)
         * (not expecting line wrapping; not produced internally by lighttpd,
         *  though possible from backends or with custom lua code)*/
        if (NULL == v || k == v) continue;
        uint32_t klen = v - k;
        if (0 == klen) continue;
        do { ++v; } while (*v == ' ' || *v == '\t'); /*(expect single ' ')*/
      #ifdef __COVERITY__
        /*(k has at least .:\n by now, so end[-2] valid)*/
        force_assert(end >= k + 2);
      #endif
        if (end[-2] != '\r') /*(header line must end "\r\n")*/
            continue;
        end -= 2;
        uint32_t vlen = end - v;
        if (0 == vlen) continue;
        memset(&lsx, 0, sizeof(lsxpack_header_t));
        *(const char **)&lsx.buf = hdrs;
        lsx.name_offset = k - hdrs;
        lsx.name_len = klen;
        lsx.val_offset = v - hdrs;
        lsx.val_len = vlen;
        unsigned char * const dst_in = dst;
        dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
        if (dst == dst_in) {
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            return;
        }
    }
    uint32_t dlen = (uint32_t)((char *)dst - tb->ptr);
    h2_send_hpack(r, con, tb->ptr, dlen, flags);
}


static void
h2_send_1xx_block (request_st * const r, connection * const con, char * const hdrs, const uint32_t hlen)
{
    h2_send_headers_block(r, con, hdrs, hlen, 0);
}


static int
h2_send_1xx (request_st * const r, connection * const con)
{
    buffer * const b = chunk_buffer_acquire();

    buffer_copy_string_len(b, CONST_STR_LEN(":status: "));
    buffer_append_int(b, r->http_status);
    for (uint32_t i = 0; i < r->resp_headers.used; ++i) {
        const data_string * const ds = (data_string *)r->resp_headers.data[i];
        const uint32_t klen = buffer_clen(&ds->key);
        const uint32_t vlen = buffer_clen(&ds->value);
        if (0 == klen || 0 == vlen) continue;
        /* HTTP/2 requires lowercase keys */
        const char *k;
        if (__builtin_expect( (ds->ext != HTTP_HEADER_OTHER), 1))
            k = http_header_lc[ds->ext];
        else {
            buffer_copy_string_len_lc(r->tmp_buf, ds->key.ptr, klen);
            k = r->tmp_buf->ptr;
        }
        buffer_append_str2(b, CONST_STR_LEN("\r\n"), k, klen);
        buffer_append_str2(b, CONST_STR_LEN(": "), ds->value.ptr, vlen);
        /*(line folding should have been unfolded
         * before being adding to r->resp_headers)*/
    }
    buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

    if (buffer_clen(b) <= UINT16_MAX)
        h2_send_1xx_block(r, con, BUF_PTR_LEN(b));
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
          "intermediate response headers too large for %s", r->uri.path.ptr);

    chunk_buffer_release(b);
    return 1; /* for http_response_send_1xx */
}


static void
h2_send_100_continue (request_st * const r, connection * const con)
{
    /* 100 Continue is small and will always fit in SETTING_MAX_FRAME_SIZE;
     * i.e. there will not be any CONTINUATION frames here */

    /* XXX: need to update hpack dynamic table,
     * or else could hard-code header block fragment
     * { 0x48, 0x03, 0x31, 0x30, 0x30 }
     */

    /* short header block, so reuse shared code used for trailers
     * rather than adding something specific for ls-hpack here */

  #if 0
    h2_send_1xx_block(r, con, CONST_STR_LEN(":status: 100\r\n\r\n"));
  #else
    const unsigned short hoff[8192] = { 1, 0, 14, 16 };
    const char * const hdrs = ":status: 100\r\n\r\n";
    h2_send_headers_hoff(r, con, hdrs, hoff, 0);
  #endif
}


__attribute_cold__
__attribute_noinline__
static void
h2_recv_expect_100 (request_st * const r)
{
    const buffer * const vb =
      http_header_request_get(r, HTTP_HEADER_EXPECT,
                              CONST_STR_LEN("Expect"));

    /* send 100 Continue only if no request body data received yet
     * and response has not yet started */
    if (vb && buffer_eq_icase_slen(vb, CONST_STR_LEN("100-continue"))
        && 0 == r->reqbody_queue.bytes_in
        && chunkqueue_is_empty(&r->write_queue))
        h2_send_100_continue(r, r->con);

    /* (always unset Expect header so that check is not repeated for request */
    http_header_request_unset(r, HTTP_HEADER_EXPECT,
                              CONST_STR_LEN("Expect"));
}


static void
h2_send_end_stream_data (request_st * const r, connection * const con);

__attribute_cold__
__attribute_noinline__
static void
h2_send_end_stream_trailers (request_st * const r, connection * const con, char * const trailers, const uint32_t tlen)
{
    /*(trailers are merged into response headers if trailers are received before
     * sending response headers to client.  However, if streaming response, then
     * trailers might need handling here)*/

    /* parse and lowercase field-names in trailers */
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */
    hoff[0] = 1;                         /* number of lines */
    hoff[1] = 0;                         /* base offset for all lines */
    /*hoff[2] = ...;*/                   /* offset from base for 2nd line */
    /*(unfolding occurs in http_request_trailers_check()
     * called from http_chunk_decode_append_trailers())*/
    uint32_t rc = http_header_parse_hoff(trailers, tlen, hoff);
    if (rc != tlen || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1
        || 1 == hoff[0]) { /*(initial blank line)*/
        /* skip trailers if incomplete, too many fields, or too long (> 64k-1)*/
        h2_send_end_stream_data(r, con);
        return;
    }

    for (int i = 1; i < hoff[0]; ++i) {
        char *k = trailers + hoff[i]; /*trailers + ((i > 1) ? hoff[i] : 0);*/
      #if 0
        /*(checked in http_request_trailers_check())*/
        if (*k == ':') {
            /*(pseudo-header should not appear in trailers)*/
            h2_send_end_stream_data(r, con);
            return;
        }
      #endif
        const char * const colon = memchr(k, ':', trailers+hoff[i+1]-k);
        /*(checked in http_request_trailers_check())*/
        /*if (NULL == colon) continue;*/
        do {
            if (light_isupper(*k)) *k |= 0x20;
        } while (++k != colon);
    }

    h2_send_headers_hoff(r, con, trailers, hoff, H2_FLAG_END_STREAM);
}


#if 0 /*(replaced by h2_send_headers())*/
void
h2_send_cqheaders (request_st * const r, connection * const con)
{
    /*(assumes HTTP/1.1 response headers have been prepended as first chunk)
     *(future: if r->write_queue is bypassed for headers, adjust
     * r->write_queue bytes counts (bytes_in, bytes_out) with header len)*/
    /* note: expects field-names are lowercased (http_response_write_header())*/
    chunk * const c = r->write_queue.first;
    const uint32_t len = buffer_clen(c->mem) - (uint32_t)c->offset;
    uint32_t flags = (r->resp_body_finished && NULL == c->next)
      ? H2_FLAG_END_STREAM
      : 0;
    /* XXX: add field validation if this code is ever enabled */
    h2_send_headers_block(r, con, c->mem->ptr + c->offset, len, flags);
    chunkqueue_mark_written(&r->write_queue, len);
}
#endif


#if 0

uint32_t
h2_send_data (request_st * const r, connection * const con, const char *data, uint32_t dlen)
{
    /* Note: dlen should be <= MAX_WRITE_LIMIT in order to share resources */

    union {
      uint8_t c[12];
      uint32_t u[3];          /*(alignment)*/
    } dataframe = { {         /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* DATA */
     ,0x00, 0x00, 0x00        /* frame length      (fill in below) */
     ,H2_FTYPE_DATA           /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier (fill in below) */
    } };

    dataframe.u[2] = htonl(r->x.h2.id);

    /* XXX: does not provide an optimization to send final set of data with
     *      END_STREAM flag; see h2_send_end_stream_data() to end stream */

    /* adjust stream and connection windows */
    /*assert(dlen <= INT32_MAX);*//* dlen should be <= MAX_WRITE_LIMIT */
    request_st * const h2r = &con->request;
    if (r->x.h2.swin   < 0) return 0;
    if (h2r->x.h2.swin < 0) return 0;
    if ((int32_t)dlen > r->x.h2.swin)   dlen = (uint32_t)r->x.h2.swin;
    if ((int32_t)dlen > h2r->x.h2.swin) dlen = (uint32_t)h2r->x.h2.swin;
    if (0 == dlen) return 0;
    r->x.h2.swin   -= (int32_t)dlen;
    h2r->x.h2.swin -= (int32_t)dlen;

    /* XXX: future: should have an interface which processes chunkqueue
     * and takes string refs to mmap FILE_CHUNK to avoid extra copying
     * since the result is likely to be consumed by TLS modules */

    /*(approximate space needed for frames (header + payload)
     * with slight over-estimate of 16 bytes per frame header (> 9)
     * and minimum SETTING_MAX_FRAME_SIZE of 16k (could be larger)
     * (dlen >> 14)+1 is num 16k frames needed, multiplied by 16 bytes
     *  per frame can be appoximated with (dlen>>10) + 9)*/
    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, dlen + (dlen>>10) + 9);
    char * restrict ptr = b->ptr;
    h2con * const h2c = (h2con *)con->hx;
    const uint32_t fsize = h2c->s_max_frame_size;
    uint32_t sent = 0;
    do {
        const uint32_t len = dlen < fsize ? dlen : fsize;
        dataframe.c[3] = (len >> 16) & 0xFF; /*(off +3 to skip over align pad)*/
        dataframe.c[4] = (len >>  8) & 0xFF;
        dataframe.c[5] = (len      ) & 0xFF;
      #if 0
        chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align pad)*/
                              (const char *)dataframe.c+3, sizeof(dataframe)-3);
        chunkqueue_append_mem(con->write_queue, data, len);
      #else
        memcpy(ptr, dataframe.c+3, sizeof(dataframe)-3);
        memcpy(ptr+sizeof(dataframe)-3, data, len);
        ptr  += len + sizeof(dataframe)-3;
      #endif
        data += len;
        sent += len;
        dlen -= len;
    } while (dlen);
    buffer_truncate(b, (uint32_t)(ptr - b->ptr));
    chunkqueue_append_buffer_commit(con->write_queue);
    return sent;
}

#endif


static uint32_t
h2_send_cqdata (request_st * const r, connection * const con, chunkqueue * const cq, uint32_t dlen)
{
    /* Note: dlen should be <= MAX_WRITE_LIMIT in order to share resources */

    union {
      uint8_t c[12];
      uint32_t u[3];          /*(alignment)*/
    } dataframe = { {         /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* DATA */
     ,0x00, 0x00, 0x00        /* frame length      (fill in below) */
     ,H2_FTYPE_DATA           /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier (fill in below) */
    } };

    dataframe.u[2] = htonl(r->x.h2.id);

    /* XXX: does not provide an optimization to send final set of data with
     *      END_STREAM flag; see h2_send_end_stream_data() to end stream */
    /*      (and would also have to add check for trailers before END_STREAM) */

    /* adjust stream and connection windows */
    /*assert(dlen <= INT32_MAX);*//* dlen should be <= MAX_WRITE_LIMIT */
    request_st * const h2r = &con->request;
    if (r->x.h2.swin   < 0) return 0;
    if (h2r->x.h2.swin < 0) return 0;
    if ((int32_t)dlen > r->x.h2.swin)   dlen = (uint32_t)r->x.h2.swin;
    if ((int32_t)dlen > h2r->x.h2.swin) dlen = (uint32_t)h2r->x.h2.swin;
    const off_t cqlen = chunkqueue_length(cq);
    if ((int32_t)dlen > cqlen) dlen = (uint32_t)cqlen;
  #ifndef H2SPEC
    /*(note: must temporarily disable next line when running h2spec since
     * some h2spec tests expect 1-byte DATA frame, not a deferred response)*/
    else if (dlen < 2048 && cqlen >= 2048) return 0;
  #endif
    if (0 == dlen) return 0;

    /* XXX: future: should have an interface which processes chunkqueue
     * and takes string refs to mmap FILE_CHUNK to avoid extra copying
     * since the result is likely to be consumed by TLS modules */

    h2con * const h2c = (h2con *)con->hx;
    const uint32_t fsize = h2c->s_max_frame_size;
    uint32_t sent = 0;
    do {
        if (cq->first->type == FILE_CHUNK) {
            /* combine frame header and data into single mem chunk buffer
             * and adjust to fit efficiently into power-2 sized buffer
             * (default and minimum HTTP/2 SETTINGS_MAX_FRAME_SIZE is 16k)
             * (default send buffer size in lighttpd TLS modules is 16k)
             * (read into memory since likely needed for HTTP/2 over TLS,
             *  and to avoid many small calls to dup(), sendfile(), close())
             * (reading here into single chunk buffer is likely more efficient
             *  than reference counting file chunks split and duplicated by
             *  chunkqueue_steal() into 16k chunks, and alternating with 8k
             *  chunk buffers containing 9 byte HTTP/2 header frame) */
            uint32_t len = dlen < fsize ? dlen : fsize-9;
            uint32_t blen = len;
            buffer * const b =         /*(sizeof(dataframe)-3 == 9)*/
              chunkqueue_append_buffer_open_sz(con->write_queue, 9+len);
            char *data = b->ptr+9;     /*(note: not including +1 to _open_sz)*/

            if (0 == chunkqueue_peek_data(cq, &data, &len, r->conf.errh, 1)) {
                if (__builtin_expect( (0 == len), 0)) {
                    if (!cq->first->file.busy)
                        chunkqueue_remove_finished_chunks(cq);
                    /*(remove empty last chunk)*/
                    chunkqueue_remove_empty_chunks(con->write_queue);
                    break; /* yield bandwidth for other ready streams */
                }
                dlen -= len;
                sent += len;
                dataframe.c[3] = (len >> 16) & 0xFF; /*(+3 to skip align pad)*/
                dataframe.c[4] = (len >>  8) & 0xFF;
                dataframe.c[5] = (len      ) & 0xFF;
                memcpy(b->ptr,(const char *)dataframe.c+3, sizeof(dataframe)-3);
                if (b->ptr+9 != data)
                    memcpy(b->ptr+9, data, len);
                buffer_commit(b, 9+len);
                chunkqueue_append_buffer_commit(con->write_queue);
                chunkqueue_mark_written(cq, len);
                if (blen != len)
                    break; /* yield bandwidth for other ready streams */
                continue;
            }

            /*(else remove empty last chunk and fall through to below)*/
            chunkqueue_remove_empty_chunks(con->write_queue);
        }

        const uint32_t len = dlen < fsize ? dlen : fsize;
        dlen -= len;
        sent += len;
        dataframe.c[3] = (len >> 16) & 0xFF; /*(off +3 to skip over align pad)*/
        dataframe.c[4] = (len >>  8) & 0xFF;
        dataframe.c[5] = (len      ) & 0xFF;
        chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align pad)*/
                              (const char *)dataframe.c+3, sizeof(dataframe)-3);
        chunkqueue_steal(con->write_queue, cq, (off_t)len);
    } while (dlen);
    r->x.h2.swin   -= (int32_t)sent;
    h2r->x.h2.swin -= (int32_t)sent;
    return sent;
}


__attribute_noinline__
static void
h2_send_end_stream_data (request_st * const r, connection * const con)
{
  if (r->x.h2.state != H2_STATE_HALF_CLOSED_LOCAL) {
    union {
      uint8_t c[12];
      uint32_t u[3];          /*(alignment)*/
    } dataframe = { {         /*(big-endian numbers)*/
      0x00, 0x00, 0x00        /* padding for alignment; do not send */
      /* DATA */
     ,0x00, 0x00, 0x00        /* frame length */
     ,H2_FTYPE_DATA           /* frame type */
     ,H2_FLAG_END_STREAM      /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier (fill in below) */
    } };

    dataframe.u[2] = htonl(r->x.h2.id);
    /*(ignore window updates when sending 0-length DATA frame with END_STREAM)*/
    chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align pad)*/
                          (const char *)dataframe.c+3, sizeof(dataframe)-3);
  }

    if (r->x.h2.state != H2_STATE_HALF_CLOSED_REMOTE) {
        /* set timestamp for comparison; not tracking individual stream ids */
        h2con * const h2c = (h2con *)con->hx;
        h2c->half_closed_ts = log_monotonic_secs;
      #ifndef H2SPEC
        /* indicate to peer that no more DATA should be sent from peer */
        /*(note: must temporarily disable next line when running h2spec since
         * some h2spec tests do not expect multiple RST_STREAM frames)*/
        h2_send_rst_stream_id(r->x.h2.id, con, H2_E_NO_ERROR);
      #endif
    }
    r->x.h2.state = H2_STATE_CLOSED;
}


static void
h2_send_end_stream (request_st * const r, connection * const con)
{
    if (r->x.h2.state == H2_STATE_CLOSED) return;
    if (r->state != CON_STATE_ERROR && r->resp_body_finished) {
        /* CON_STATE_RESPONSE_END */
        buffer *b;
        char *t;
        if (r->http_status != 204 && r->http_status != 304
            && r->gw_dechunk && r->gw_dechunk->done
            && !buffer_is_unset(&r->gw_dechunk->b)
               /* step over initial "0\r\n" */
            && (t = strchr((b = &r->gw_dechunk->b)->ptr, '\n'))) {
            ++t;
            h2_send_end_stream_trailers(r, con, t, buffer_clen(b)
                                                   - (uint32_t)(t - b->ptr));
        }
        else
            h2_send_end_stream_data(r, con);
    }
    else { /* CON_STATE_ERROR */
        h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
    }
}


/*
 * (XXX: might move below to separate file)
 */
#include "base64.h"
#include "chunk.h"
#include "plugins.h"
#include "plugin_config.h"
#include "reqpool.h"


__attribute_returns_nonnull__
static request_st *
h2_init_stream (request_st * const h2r, connection * const con)
{
    h2con * const h2c = (h2con *)con->hx;
    ++con->request_count;
    force_assert(h2c->rused < sizeof(h2c->r)/sizeof(*h2c->r));
    /* initialize stream as subrequest (request_st *) */
    request_st * const r = request_acquire(con);
    /* XXX: TODO: assign default priority, etc.
     *      Perhaps store stream id and priority in separate table */
    h2c->r[h2c->rused++] = r;
    r->x.h2.rwin = 65536; /* must keep in sync with h2_init_con() */
    r->x.h2.swin = h2c->s_initial_window_size;
    r->x.h2.rwin_fudge = 0;
    /* combine priority 'urgency' value and invert 'incremental' boolean
     * for easy (ascending) sorting by urgency and then incremental before
     * non-incremental */
    r->x.h2.prio = (3 << 1) | !0; /*(default urgency=3, incremental=0)*/
    r->http_version = HTTP_VERSION_2;

    /* copy config state from h2r */
    server * const srv = con->srv;
    const uint32_t used = srv->config_context->used;
    r->conditional_is_valid = h2r->conditional_is_valid;
    memcpy(r->cond_cache, h2r->cond_cache, used * sizeof(cond_cache_t));
  #ifdef HAVE_PCRE
    if (srv->config_captures)
        memcpy(r->cond_match, h2r->cond_match,
               srv->config_captures * sizeof(cond_match_t *));
  #endif
    /*(see request_config_reset() and request_reset_ex())*/
    r->server_name = h2r->server_name;
    memcpy(&r->conf, &h2r->conf, sizeof(request_config));

    /* stream id must be assigned by caller */
    return r;
}


static void
h2_release_stream (request_st * const r, connection * const con)
{
    if (r->http_status) {
        /* (see comment in connection_handle_response_end_state()) */
        plugins_call_handle_request_done(r);

      #if 0
        /* (fuzzy accounting for mod_accesslog, mod_rrdtool to avoid
         *  double counting, but HTTP/2 framing and HPACK-encoded headers in
         *  con->read_queue and con->write_queue are not equivalent to the
         *  HPACK-decoded headers and request and response bodies in stream
         *  r->read_queue and r->write_queue) */
        /* DISABLED since mismatches invalidate the relationship between
         * con->bytes_in and con->bytes_out */
        con->read_queue->bytes_in   -= r->read_queue.bytes_in;
        con->write_queue->bytes_out -= r->write_queue.bytes_out;
      #else
        UNUSED(con);
      #endif
    }

    request_release(r);
}


static void
h2_retire_stream (request_st *r, connection * const con)
{
    if (r == NULL) return; /*(should not happen)*/
    h2con * const h2c = (h2con *)con->hx;
    request_st ** const ar = h2c->r;
    uint32_t i = 0, rused = h2c->rused;
    while (i < rused && ar[i] != r) ++i;
    if (i != rused) {
        /* swap with last element; might need to revisit if ordered by priority */
        /*if (i != --rused) ar[i] = ar[rused];*/
        /* shift elements; currently choosing to preserve order requested */
        if (i != --rused) memmove(ar+i, ar+i+1, (rused-i)*sizeof(*ar));
        h2c->r[(h2c->rused = rused)] = NULL;
        h2_release_stream(r, con);
    }
    /*else ... should not happen*/
}


static void
h2_retire_con (request_st * const h2r, connection * const con)
{
    h2con * const h2c = (h2con *)con->hx;

    if (h2r->state != CON_STATE_ERROR) { /*(CON_STATE_RESPONSE_END)*/
        h2_send_goaway(con, H2_E_NO_ERROR);
        for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
            /*(unexpected if CON_STATE_RESPONSE_END)*/
            request_st * const r = h2c->r[i];
            h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
            h2_release_stream(r, con);
        }
        if (!chunkqueue_is_empty(con->write_queue)) {
            /* similar to connection_handle_write() but without error checks,
             * without MAX_WRITE_LIMIT, and without connection throttling */
            /*h2r->conf.bytes_per_second = 0;*/         /* disable rate limit */
            /*h2r->conf.global_bytes_per_second = 0;*/  /* disable rate limit */
            /*con->traffic_limit_reached = 0;*/
            chunkqueue * const cq = con->write_queue;
            const off_t len = chunkqueue_length(cq);
            off_t written = cq->bytes_out;
            con->network_write(con, cq, len);
            /*(optional accounting)*/
            written = cq->bytes_out - written;
            con->bytes_written_cur_second += written;
            if (h2r->conf.global_bytes_per_second_cnt_ptr)
                *(h2r->conf.global_bytes_per_second_cnt_ptr) += written;
        }
    }
    else { /* CON_STATE_ERROR */
        for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
            request_st * const r = h2c->r[i];
            h2_release_stream(r, con);
        }
        /* XXX: perhaps attempt to send GOAWAY?  Not when CON_STATE_ERROR */
    }

    con->hx = NULL;

    /*(use HTTP/1.x dispatch table for connection shutdown and close)*/
    con->fn = NULL;

    /* future: might keep a pool of reusable (h2con *) */
    lshpack_enc_cleanup(&h2c->encoder);
    lshpack_dec_cleanup(&h2c->decoder);
    free(h2c);
}


__attribute_cold__
__attribute_nonnull__()
static void
h2_upgrade_h2c (request_st * const h2r, connection * const con)
{
    /* Upgrade: h2c
     * RFC7540 3.2 Starting HTTP/2 for "http" URIs */

    buffer * const http2_settings =
      http_header_request_get(h2r, HTTP_HEADER_HTTP2_SETTINGS,
                              CONST_STR_LEN("HTTP2-Settings"));

    /* ignore Upgrade: h2c if request body present since we do not
     * (currently) handle request body before transition to h2c */
    /* RFC7540 3.2 Requests that contain a payload body MUST be sent
     * in their entirety before the client can send HTTP/2 frames. */

    if (NULL != http2_settings
        && 0 == h2r->reqbody_length
        && h2r->conf.h2proto > 1 /*(must be enabled with server.h2c feature)*/
        && !con->is_ssl_sock)    /*(disallow h2c over TLS socket)*/
        h2r->http_version = HTTP_VERSION_2;
    else
        return;

    /* HTTP/1.1 101 Switching Protocols
     * Connection: Upgrade
     * Upgrade: h2c
     */
  #if 1
    static const char switch_proto[] = "HTTP/1.1 101 Switching Protocols\r\n"
                                       "Connection: Upgrade\r\n"
                                       "Upgrade: h2c\r\n\r\n";
    chunkqueue_append_mem(&h2r->write_queue,
                          CONST_STR_LEN(switch_proto));
    h2r->resp_header_len = sizeof(switch_proto)-1;
  #else
    h2r->http_status = 101;
    http_header_response_set(h2r, HTTP_HEADER_UPGRADE, CONST_STR_LEN("Upgrade"),
                                                       CONST_STR_LEN("h2c"));
    http_response_write_header(h2r);
    http_response_reset(h2r);
    h2r->http_status = 0;
  #endif

    h2_init_con(h2r, con);
    if (((h2con *)con->hx)->sent_goaway) return;

    ((h2con *)con->hx)->h2_cid = 1; /* stream id 1 is assigned to h2c upgrade */

    buffer * const tb = h2r->tmp_buf;
    buffer_clear(tb);
    if (buffer_append_base64_decode(tb,BUF_PTR_LEN(http2_settings),BASE64_URL))
        h2_parse_frame_settings(con, (uint8_t *)BUF_PTR_LEN(tb));
    else {
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }

    /* copy request state from &con->request to subrequest r
     * XXX: would be nice if there were a cleaner way to do this
     * (This is fragile and must be kept in-sync with request_st in request.h)*/

    request_st * const r = h2_init_stream(h2r, con);
    /*(undo double-count; already incremented in CON_STATE_REQUEST_START)*/
    --con->request_count;
    r->state = CON_STATE_HANDLE_REQUEST; /* require 0 == r->reqbody_length */
    r->http_status = 0;
    r->http_method = h2r->http_method;
    r->x.h2.state = H2_STATE_HALF_CLOSED_REMOTE;
    r->x.h2.id = 1;
    r->rqst_htags = h2r->rqst_htags;
    h2r->rqst_htags = 0;
    r->rqst_header_len = h2r->rqst_header_len;
    h2r->rqst_header_len = 0;
    r->rqst_headers = h2r->rqst_headers;        /* copy struct */
    memset(&h2r->rqst_headers, 0, sizeof(array));
    r->uri = h2r->uri;                          /* copy struct */
  #if 0
    r->physical = h2r->physical;                /* copy struct */
    r->env = h2r->env;                          /* copy struct */
  #endif
    memset(&h2r->rqst_headers, 0, sizeof(array));
    memset(&h2r->uri, 0, sizeof(request_uri));
  #if 0
    memset(&h2r->physical, 0, sizeof(physical));
    memset(&h2r->env, 0, sizeof(array));
  #endif
  #if 0 /* expect empty request body */
    r->reqbody_length = h2r->reqbody_length; /* currently always 0 */
    r->x.h1.te_chunked = h2r->x.h1.te_chunked;/*must be 0 before r->x.h2 above*/
    r->resp_body_scratchpad = h2r->resp_body_scratchpad; /*(not started yet)*/
    swap(&r->reqbody_queue,&h2r->reqbody_queue);/*currently always empty queue*/
  #endif
    r->http_host = h2r->http_host;
    h2r->http_host = NULL;
  #if 0
    r->server_name = h2r->server_name;
    h2r->server_name = &h2r->uri.authority;     /*(is not null)*/
  #endif
    r->target = h2r->target;                    /* copy struct */
    r->target_orig = h2r->target_orig;          /* copy struct */
  #if 0
    r->pathinfo = h2r->pathinfo;                /* copy struct */
    r->server_name_buf = h2r->server_name_buf;  /* copy struct */
  #endif
    memset(&h2r->target, 0, sizeof(buffer));
    memset(&h2r->target_orig, 0, sizeof(buffer));
  #if 0
    memset(&h2r->pathinfo, 0, sizeof(buffer));
    memset(&h2r->server_name_buf, 0, sizeof(buffer));
  #endif
  #if 0
    /* skip copying response structures, other state not yet modified in h2r */
    /* r write_queue and read_queue are intentionally separate from h2r */
    /* r->gw_dechunk must be NULL for HTTP/2 */
    /* bytes_written_ckpt and bytes_read_ckpt are for HTTP/1.1 */
    /* error handlers have not yet been set */
  #endif
  #if 0
    r->loops_per_request = h2r->loops_per_request;
  #endif
    r->keep_alive = h2r->keep_alive;
    r->tmp_buf = h2r->tmp_buf;                /* shared; same as srv->tmp_buf */
    r->start_hp = h2r->start_hp;                /* copy struct */

    http_header_request_unset(r, HTTP_HEADER_HTTP2_SETTINGS,
                              CONST_STR_LEN("HTTP2-Settings"));
    http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                              CONST_STR_LEN("Upgrade"));
    buffer * const http_connection =
      http_header_request_get(r, HTTP_HEADER_CONNECTION,
                              CONST_STR_LEN("Connection"));
    http_header_remove_token(http_connection, CONST_STR_LEN("HTTP2-Settings"));
    http_header_remove_token(http_connection, CONST_STR_LEN("Upgrade"));

    /* Note: HTTP/1.1 101 Switching Protocols is not immediately written to
     * the network here.  As this is called from cleartext Upgrade: h2c,
     * we choose to delay sending the status until the beginning of the response
     * to the HTTP/1.1 request which included Upgrade: h2c */
}


__attribute_cold__
__attribute_noinline__
static void
h2_send_goaway_delayed (connection * const con)
{
    request_st * const h2r = &con->request;
    if (h2r->keep_alive >= 0) {
        if (config_feature_bool(con->srv, "auth.http-goaway-invalid-creds", 1)){
            h2r->keep_alive = -1;
            h2_send_goaway(con, H2_E_NO_ERROR);
        }
        http_response_delay(con);
    }
    else /*(abort connection upon second request to close h2 connection)*/
        h2_send_goaway(con, H2_E_ENHANCE_YOUR_CALM);
}


#include "plugin.h"     /* const plugin * const p = r->handler_module; */

static int
h2_process_streams (connection * const con,
                    handler_t(*http_response_loop)(request_st *),
                    int(*connection_handle_write)(request_st *, connection *))
{
    h2con * const h2c = (h2con *)con->hx;

    if (h2c->sent_goaway <= 0
        && (chunkqueue_is_empty(con->read_queue) || h2_parse_frames(con))
        && con->is_readable > 0) {
        chunkqueue * const cq = con->read_queue;
        const off_t mark = cq->bytes_in;
        if (0 == con->network_read(con, cq, MAX_READ_LIMIT)) {
            if (mark < cq->bytes_in)
                h2_parse_frames(con);
        }
        else {
            /* network error; do not send GOAWAY, but pretend that we did */
            h2c->sent_goaway = H2_E_CONNECT_ERROR; /*any error (not NO_ERROR)*/
            request_st * const h2r = &con->request;
            request_set_state_error(h2r, CON_STATE_ERROR); /*connection error*/
        }
    }

    /* process requests on HTTP/2 streams */
    int resched = 0;
    if (h2c->sent_goaway <= 0 && h2c->rused) {
      #if 0
        /* coarse check for write throttling
         * (connection.kbytes-per-second, server.kbytes-per-second)
         * obtain an approximate limit, not refreshed per request_st,
         * even though we are not calculating response HEADERS frames
         * or frame overhead here */
        off_t max_bytes = con->is_writable > 0
          ? connection_write_throttle(con, MAX_WRITE_LIMIT)
          : 0;
      #else
        /*(throttle further when writing to network, defer 'precise' throttle)*/
        off_t max_bytes = con->is_writable > 0 && !con->traffic_limit_reached
          ? MAX_WRITE_LIMIT
          : 0;
      #endif
        const off_t cqlen = chunkqueue_length(con->write_queue);
        if (cqlen > 8192 && max_bytes > 65536) max_bytes = 65536;
        max_bytes -= cqlen;
        if (max_bytes < 0) max_bytes = 0;

        /* XXX: to avoid buffer bloat due to staging too much data in
         * con->write_queue, consider setting limit on how much is staged
         * for sending on con->write_queue: adjusting max_bytes down */

        for (uint32_t i = 0; i < h2c->rused; ++i) {
            request_st * const r = h2c->r[i];
            /* future: might track read/write interest per request
             * to avoid iterating through all active requests */
            /* specialized connection_state_machine_loop() for h2 streams */
            switch (r->state) {
              case CON_STATE_READ_POST:
              case CON_STATE_HANDLE_REQUEST:
                {
                    const handler_t rc = http_response_loop(r);
                    if (rc >= HANDLER_WAIT_FOR_EVENT) {
                        if (rc > HANDLER_WAIT_FOR_EVENT) {
                            /*HANDLER_ERROR or HANDLER_COMEBACK (not expected)*/
                            request_set_state_error(r, CON_STATE_ERROR);
                            break;
                        }
                        continue; /* HANDLER_WAIT_FOR_EVENT */
                    }
                    /* HANDLER_GO_ON or HANDLER_FINISHED */
                }
                /*__attribute_fallthrough__*/
              /*case CON_STATE_RESPONSE_START:*//*occurred;transient*/
                h2_send_headers(r, con);
                request_set_state(r, CON_STATE_WRITE);
                __attribute_fallthrough__
              case CON_STATE_WRITE:
                /* specialized connection_handle_write_state() */

                if (r->handler_module && !r->resp_body_finished) {
                    const plugin * const p = r->handler_module;
                    if (p->handle_subrequest(r, p->data)
                        > HANDLER_WAIT_FOR_EVENT) {
                      /*case HANDLER_COMEBACK:*//*error after send resp hdrs*/
                      /*case HANDLER_ERROR:*/
                        request_set_state_error(r, CON_STATE_ERROR);
                        break;
                    }
                }

                if (!chunkqueue_is_empty(&r->write_queue)
                    && max_bytes
                    && (r->resp_body_finished
                        || (r->conf.stream_response_body
                            & (FDEVENT_STREAM_RESPONSE
                              |FDEVENT_STREAM_RESPONSE_BUFMIN)))) {
                    /*(subtract 9 byte HTTP/2 frame overhead from each 16k DATA
                     * frame for more efficient sending of large files)*/
                    /*(use smaller max per stream if marked 'incremental' (w/ 0)
                     * to give more streams a chance to send in parallel)*/
                    uint32_t dlen = (r->x.h2.prio & 1) ? 32768-18 : 8192;
                    if (dlen > (uint32_t)max_bytes) dlen = (uint32_t)max_bytes;
                    dlen = h2_send_cqdata(r, con, &r->write_queue, dlen);
                    max_bytes -= (off_t)dlen;
                    if (!chunkqueue_is_empty(&r->write_queue)) {
                        /*(do not resched (spin) if swin empty window)*/
                        if (dlen || r->write_queue.first->file.busy)
                            resched |= r->write_queue.first->file.busy ? 4 : 1;
                        continue;
                    }
                }
                if (!chunkqueue_is_empty(&r->write_queue)
                    || !r->resp_body_finished)
                    continue;

                request_set_state(r, CON_STATE_RESPONSE_END);
                break;
              default:
                break;
            }

            {/*(r->state==CON_STATE_RESPONSE_END || r->state==CON_STATE_ERROR)*/
                /*(trigger reschedule of con if frames pending)*/
                if (h2c->rused == sizeof(h2c->r)/sizeof(*h2c->r)
                    && !chunkqueue_is_empty(con->read_queue))
                    resched |= 2;
                h2_send_end_stream(r, con);
                const int alive = r->keep_alive;
                h2_retire_stream(r, con);/*r invalidated;removed from h2c->r[]*/
                --i;/* adjust loop i; h2c->rused was modified to retire r */
                /*(special-case: allow *stream* to set r->keep_alive = -1 to
                 * trigger goaway on h2 connection, e.g. after mod_auth failure
                 * in attempt to mitigate brute force attacks by forcing a
                 * reconnect and (somewhat) slowing down retries)*/
                if (alive < 0)
                    h2_send_goaway_delayed(con);
            }
        }

        if (0 == max_bytes) resched |= 0x100;
    }

    if (h2c->sent_goaway > 0 && h2c->rused) {
        /* retire streams if an error has occurred
         * note: this is not done to other streams in the loop above
         * (besides the current stream in the loop) due to the specific
         * implementation above, where doing so would mess up the iterator */
        #if 0
        for (uint32_t i = 0; i < h2c->rused; ++i) {
            request_st * const r = h2c->r[i];
            /*assert(r->x.h2.state == H2_STATE_CLOSED);*/
            h2_retire_stream(r, con);/*r invalidated;removed from h2c->r[]*/
            --i;/* adjust loop i; h2c->rused was modified to retire r */
        }
        #else
        do { h2_retire_stream(h2c->r[0], con); } while (h2c->rused);
        #endif
        /* XXX: ? should we discard con->write_queue
         *        and change h2r->state to CON_STATE_RESPONSE_END ? */
    }

    request_st * const h2r = &con->request;
    if (h2r->state == CON_STATE_WRITE) {
        /* write HTTP/2 frames to socket */
        if (!chunkqueue_is_empty(con->write_queue)) {
            connection_handle_write(h2r, con);
            /* check if might need to resched to process more frames
             * (could be more precise duplicating parts of h2_want_read(),
             *  though prefer to check here when write_queue has been emptied)
             * need to resched if still CON_STATE_WRITE, write_queue empty,
             * full frame pending, and frame is not HEADERS or h2c->r not full,
             * which might happen if parsing frames was deferred if write_queue
             * grew too large generating HTTP/2 replies to various frame types.
             * Also reschedule if max_bytes write allocation was fully used
             * (indicating that there is more data from request streams ready)*/
            if (chunkqueue_is_empty(con->write_queue)) {
                if (!chunkqueue_is_empty(con->read_queue))
                    resched |= 2;
                if (resched & 0x100)
                    resched |= 1;
            }
        }

        if (chunkqueue_is_empty(con->write_queue)
            && 0 == h2c->rused && h2c->sent_goaway)
            connection_set_state(h2r, CON_STATE_RESPONSE_END);
    }

    if (h2r->state == CON_STATE_WRITE) {
        /* (resched & 1) more data is available to write, if still able to write
         * (resched & 2) resched to read deferred frames from con->read_queue
         * (resched & 4) at least one request is waiting for disk I/O
         * (resched & 0x100) (intermediate flag handled above) */
        /*(con->is_writable set to 0 if !chunkqueue_is_empty(con->write_queue)
         * after trying to write in connection_handle_write() above)*/
        if (((resched & (1|4))
             && con->is_writable > 0 && !con->traffic_limit_reached)
            || (resched & 2))
            joblist_append(con);

        if (h2_want_read(con))
            h2r->conf.stream_request_body |=  FDEVENT_STREAM_REQUEST_POLLIN;
        else
            h2r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
        return 0;
    }
    else { /* e.g. CON_STATE_RESPONSE_END or CON_STATE_ERROR */
        h2_retire_con(h2r, con);
        return 1;
    }
}


static int
h2_check_timeout (connection * const con, const unix_time64_t cur_ts)
{
    h2con * const h2c = (h2con *)con->hx;
    request_st * const r = &con->request;
    int changed = (r->state != CON_STATE_WRITE); /*(e.g. CON_STATE_ERROR)*/

    if (!changed) {
        if (h2c->rused) {
            for (uint32_t i = 0; i < h2c->rused; ++i) {
                request_st * const rr = h2c->r[i];
                if (rr->state == CON_STATE_ERROR) { /*(should not happen)*/
                    changed = 1;
                    continue;
                }
                if (rr->reqbody_length != rr->reqbody_queue.bytes_in) {
                    /* XXX: should timeout apply if not trying to read on h2con?
                     * (still applying timeout to catch stuck connections) */
                    /* XXX: con->read_idle_ts is not per-request, so timeout
                     * will not occur if other read activity occurs on h2con
                     * (future: might keep separate timestamp per-request) */
                    if (cur_ts - con->read_idle_ts > rr->conf.max_read_idle) {
                        /* time - out */
                        if (rr->conf.log_timeouts) {
                            log_debug(rr->conf.errh, __FILE__, __LINE__,
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
                            log_debug(r->conf.errh, __FILE__, __LINE__,
                              "NOTE: a request from %s for %.*s timed out "
                              "after writing %lld bytes. We waited %d seconds. "
                              "If this is a problem, increase "
                              "server.max-write-idle",
                              r->dst_addr_buf->ptr,
                              BUFFER_INTLEN_PTR(&r->target),
                              (long long)r->write_queue.bytes_out,
                              (int)r->conf.max_write_idle);
                        }
                        connection_set_state_error(r, CON_STATE_ERROR);
                        changed = 1;
                    }
                }
            }
        }
        else {
            if (cur_ts - con->read_idle_ts
                 > (unix_time64_t)con->keep_alive_idle) {
                /* time - out */
                if (r->conf.log_timeouts) {
                    log_debug(r->conf.errh, __FILE__, __LINE__,
                              "connection closed - keep-alive timeout: %d",
                              con->fd);
                }
                connection_set_state(r, CON_STATE_RESPONSE_END);
                changed = 1;
            }
        }
        /* process changes before optimistic read of additional HTTP/2 frames */
        if (changed)
            con->is_readable = 0;
    }

    return changed;
}


const struct http_dispatch h2_dispatch_table = {
  .process_streams   = h2_process_streams
 ,.upgrade_h2        = h2_init_con
 ,.upgrade_h2c       = h2_upgrade_h2c
 ,.send_1xx          = h2_send_1xx
 ,.check_timeout     = h2_check_timeout
 ,.goaway_graceful   = h2_send_goaway_graceful
};


#include "plugin.h"

typedef struct {
    PLUGIN_DATA;
} plugin_data;

INIT_FUNC(mod_h2_init) {
    http_dispatch[HTTP_VERSION_2] = h2_dispatch_table; /* copy struct */
    return ck_calloc(1, sizeof(plugin_data));
}


__attribute_cold__
__declspec_dllexport__
int mod_h2_plugin_init (plugin *p);
int mod_h2_plugin_init (plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "h2";
    p->init        = mod_h2_init;
    return 0;
}
