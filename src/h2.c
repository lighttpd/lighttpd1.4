/*
 * h2 - HTTP/2 protocol layer
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"
#include "h2.h"

#include <arpa/inet.h>  /* htonl() */
#include <stdint.h>     /* INT32_MAX INT32_MIN */
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"    /* FDEVENT_STREAM_REQUEST_BUFMIN */
#include "http_date.h"
#include "http_header.h"
#include "log.h"
#include "request.h"
#include "response.h"   /* http_response_omit_header() */


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
 ,[HTTP_HEADER_EXPECT_CT]                 = "expect-ct"
 ,[HTTP_HEADER_EXPIRES]                   = "expires"
 ,[HTTP_HEADER_FORWARDED]                 = "forwarded"
 ,[HTTP_HEADER_HOST]                      = "host"
 ,[HTTP_HEADER_HTTP2_SETTINGS]            = "http2-settings"
 ,[HTTP_HEADER_IF_MATCH]                  = "if-match"
 ,[HTTP_HEADER_IF_MODIFIED_SINCE]         = "if-modified-since"
 ,[HTTP_HEADER_IF_NONE_MATCH]             = "if-none-match"
 ,[HTTP_HEADER_IF_RANGE]                  = "if-range"
 ,[HTTP_HEADER_IF_UNMODIFIED_SINCE]       = "if-unmodified-since"
 ,[HTTP_HEADER_LAST_MODIFIED]             = "last-modified"
 ,[HTTP_HEADER_LINK]                      = "link"
 ,[HTTP_HEADER_LOCATION]                  = "location"
 ,[HTTP_HEADER_ONION_LOCATION]            = "onion-location"
 ,[HTTP_HEADER_P3P]                       = "p3p"
 ,[HTTP_HEADER_PRAGMA]                    = "pragma"
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
 ,[HTTP_HEADER_EXPECT_CT]                 = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_EXPIRES]                   = LSHPACK_HDR_EXPIRES
 ,[HTTP_HEADER_IF_MATCH]                  = LSHPACK_HDR_IF_MATCH
 ,[HTTP_HEADER_IF_RANGE]                  = LSHPACK_HDR_IF_RANGE
 ,[HTTP_HEADER_IF_UNMODIFIED_SINCE]       = LSHPACK_HDR_IF_UNMODIFIED_SINCE
 ,[HTTP_HEADER_LINK]                      = LSHPACK_HDR_LINK
 ,[HTTP_HEADER_ONION_LOCATION]            = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_P3P]                       = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_PRAGMA]                    = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_REFERER]                   = LSHPACK_HDR_REFERER
 ,[HTTP_HEADER_REFERRER_POLICY]           = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_STRICT_TRANSPORT_SECURITY] = LSHPACK_HDR_STRICT_TRANSPORT_SECURITY
 ,[HTTP_HEADER_TE]                        = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_UPGRADE_INSECURE_REQUESTS] = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_WWW_AUTHENTICATE]          = LSHPACK_HDR_WWW_AUTHENTICATE
 ,[HTTP_HEADER_X_CONTENT_TYPE_OPTIONS]    = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_X_FRAME_OPTIONS]           = LSHPACK_HDR_UNKNOWN
 ,[HTTP_HEADER_X_XSS_PROTECTION]          = LSHPACK_HDR_UNKNOWN
};


/* Note: must be kept in sync with ls-hpack/lshpack.h:lshpack_static_hdr_idx[]*/
static const uint8_t lshpack_idx_http_header[] = {
  [LSHPACK_HDR_UNKNOWN]                   = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_AUTHORITY]                 = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_METHOD_GET]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_METHOD_POST]               = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_PATH]                      = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_PATH_INDEX_HTML]           = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_SCHEME_HTTP]               = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_SCHEME_HTTPS]              = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_200]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_204]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_206]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_304]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_400]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_404]                = HTTP_HEADER_OTHER
 ,[LSHPACK_HDR_STATUS_500]                = HTTP_HEADER_OTHER
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


static request_st * h2_init_stream (request_st * const h2r, connection * const con);


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
h2_send_rst_stream (request_st * const r, connection * const con, const request_h2error_t e)
{
    r->state = CON_STATE_ERROR;
    r->h2state = H2_STATE_CLOSED;
    h2_send_rst_stream_id(r->h2id, con, e);
}


__attribute_cold__
static void
h2_send_goaway_rst_stream (connection * const con)
{
    h2con * const h2c = con->h2;
    const int sent_goaway = h2c->sent_goaway;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const r = h2c->r[i];
        if (r->h2state == H2_STATE_CLOSED) continue;
        /*(XXX: might consider always sending RST_STREAM)*/
        if (!sent_goaway) {
            r->state = CON_STATE_ERROR;
            r->h2state = H2_STATE_CLOSED;
        }
        else /*(also sets r->h2state = H2_STATE_CLOSED)*/
            h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
    }
}


void
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

    h2con * const h2c = con->h2;
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


static int
h2_recv_goaway (connection * const con, const uint8_t * const s, uint32_t len)
{
    /*(s must be entire GOAWAY frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_GOAWAY);*/
    UNUSED(len);
    if ((s[5] & ~0x80) | s[6] | s[7] | s[8]) { /*(GOAWAY stream id must be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }
    const uint32_t e = (s[13]<< 24) | (s[14]<< 16) | (s[15]<< 8) | s[16];
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
    const uint32_t last_id = (s[9] << 24) | (s[10]<< 16) | (s[11]<< 8) | s[12];
  #endif

    /* send PROTOCOL_ERROR back to peer if peer sent an error code
     * (i.e. not NO_ERROR) in order to terminate connection more quickly */
    h2_send_goaway(con, e==H2_E_NO_ERROR ? H2_E_NO_ERROR : H2_E_PROTOCOL_ERROR);
    h2con * const h2c = con->h2;
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
    const uint32_t id =
      ((s[5] << 24) | (s[6] << 16) | (s[7] << 8) | s[8]) & ~0x80000000u;
    if (0 == id) {                   /*(RST_STREAM id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    h2con * const h2c = con->h2;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const r = h2c->r[i];
        if (r->h2id != id) continue;
        if (r->h2state == H2_STATE_IDLE) {
            /*(RST_STREAM must not be for stream in "idle" state)*/
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return;
        }
        /* XXX: ? add debug trace including error code from RST_STREAM ? */
        r->state = CON_STATE_ERROR;
        r->h2state = H2_STATE_CLOSED;
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
    if (s[5] | s[6] | s[7] | s[8]) { /*(PING stream id must be 0)*/
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
h2_recv_priority (connection * const con, const uint8_t * const s, const uint32_t len)
{
    /*(s must be entire PRIORITY frame and len the frame length field)*/
    /*assert(s[3] == H2_FTYPE_PRIORITY);*/
    if (5 != len) {                  /*(PRIORITY frame length must be 5)*/
        h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
        return;
    }
    const uint32_t id =
      ((s[5] << 24) | (s[6] << 16) | (s[7] << 8) | s[8]) & ~0x80000000u;
    if (0 == id) {                   /*(PRIORITY id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }
    const uint32_t prio =
      ((s[9] << 24) | (s[10] << 16) | (s[11] << 8) | s[12]) & ~0x80000000u;
  #if 0
    uint32_t exclusive_dependency = (s[9] & 0x80) ? 1 : 0;
    uint32_t weight = s[13];
  #endif
    h2con * const h2c = con->h2;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const r = h2c->r[i];
        if (r->h2id != id) continue;
        /* XXX: TODO: update priority info */
        if (prio == id) {
            h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
            return;
        }
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
    const uint32_t id =
      ((s[5] << 24) | (s[6] << 16) | (s[7] << 8) | s[8]) & ~0x80000000u;
    const int32_t v =
      (int32_t)(((s[9] << 24)|(s[10] << 16)|(s[11] << 8)|s[12]) & ~0x80000000);
    request_st *r = NULL;
    if (0 == id)
        r = &con->request;
    else {
        h2con * const h2c = con->h2;
        for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
            request_st * const rr = h2c->r[i];
            if (rr->h2id != id) continue;
            r = rr;
            break;
        }
        /* peer should not send WINDOW_UPDATE for an inactive stream,
         * but RFC 7540 does not explicitly call this out.  On the other hand,
         * since there may be a temporary mismatch in stream state between
         * peers, ignore window update if stream id is unknown/inactive.
         * Also, it is not an error if GOAWAY sent and h2c->h2_cid < id */
        if (NULL == r) {
            if (h2c->h2_cid < id && 0 == h2c->sent_goaway)
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
          #if 0
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
        if (r->h2state == H2_STATE_CLOSED
            || r->h2state == H2_STATE_HALF_CLOSED_LOCAL) return;
    }
    if (0 == v || r->h2_swin > INT32_MAX - v) {
        request_h2error_t e = (0 == v)
          ? H2_E_PROTOCOL_ERROR
          : H2_E_FLOW_CONTROL_ERROR;
        if (0 == id)
            h2_send_goaway_e(con, e);
        else
            h2_send_rst_stream(r, con, e);
        return;
    }
    r->h2_swin += v;
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


static void
h2_parse_frame_settings (connection * const con, const uint8_t *s, uint32_t len)
{
    /*(s and len must be SETTINGS frame payload)*/
    /*(caller must validate frame len, frame type == 0x04, frame id == 0)*/
    h2con * const h2c = con->h2;
    for (; len >= 6; len -= 6, s += 6) {
        uint32_t v = (s[2] << 24) | (s[3] << 16) | (s[4] << 8) | s[5];
        switch (((s[0] << 8) | s[1])) {
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
                    const int32_t swin = r->h2_swin;
                    if (r->h2state == H2_STATE_HALF_CLOSED_LOCAL
                        || r->h2state == H2_STATE_CLOSED) continue;
                    if (diff >= 0
                        ? swin > INT32_MAX - diff
                        : swin < INT32_MIN - diff) {
                        h2_send_rst_stream(r, con, H2_E_FLOW_CONTROL_ERROR);
                        continue;
                    }
                    r->h2_swin += diff;
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
    if ((s[5] & ~0x80) | s[6] | s[7] | s[8]) {/*(SETTINGS stream id must be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return;
    }

    h2con * const h2c = con->h2;
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
    r->h2state = (r->h2state == H2_STATE_OPEN)
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

    h2con * const h2c = con->h2;
    const uint32_t id =
      ((s[5] << 24) | (s[6] << 16) | (s[7] << 8) | s[8]) & ~0x80000000u;
    if (0 == id || h2c->h2_cid < id) { /*(RST_STREAM id must not be 0)*/
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }

    uint32_t alen = len; /* actual data len, minus padding */
    uint32_t pad = 0;
    if (s[4] & H2_FLAG_PADDED) {
        pad = s[9];
        if (pad >= len) {
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        alen -= (1 + pad);
    }

    request_st * const h2r = &con->request;
    if (h2r->h2_rwin <= 0 && 0 != alen) { /*(always proceed if 0 == alen)*/
        /*(connection_state_machine_h2() must ensure con is rescheduled,
         * when backends consume data if con->read_queue is not empty,
         * whether or not con->fd has data to read from the network)*/
        /*(leave frame in cq to be re-read later)*/
        return 0;
    }
    /*(allow h2r->h2_rwin to dip below 0 so that entire frame is processed)*/
    /*(not worried about underflow while
     * SETTINGS_MAX_FRAME_SIZE is small (e.g. 16k or 32k) and
     * SETTINGS_MAX_CONCURRENT_STREAMS is small (h2c->r[8]))*/
    /*h2r->h2_rwin -= (int32_t)len;*//* update connection recv window (below) */

    request_st *r = NULL;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const rr = h2c->r[i];
        if (rr->h2id != id) continue;
        r = rr;
        break;
    }
    chunkqueue * const cq = con->read_queue;
    if (NULL == r) {
        /* XXX: TODO: might need to keep a list of recently retired streams
         * for a few seconds so that if we send RST_STREAM, then we ignore
         * further DATA and do not send connection error, though recv windows
         * still must be updated. */
        if (h2c->h2_cid < id || (!h2c->sent_goaway && 0 != alen))
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        chunkqueue_mark_written(cq, 9+len);
        return 0;
    }

    if (r->h2state == H2_STATE_CLOSED
        || r->h2state == H2_STATE_HALF_CLOSED_REMOTE) {
        h2_send_rst_stream_id(id, con, H2_E_STREAM_CLOSED);
        chunkqueue_mark_written(cq, 9+len);
        h2_send_window_update(con, 0, len); /*(h2r->h2_rwin)*/
        return 1;
    }

    if (r->h2_rwin <= 0 && 0 != alen) {/*(always proceed if 0==alen)*/
        if (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN) {
            /*(connection_state_machine_h2() must ensure con is rescheduled,
             * when backends consume data if con->read_queue is not empty,
             * whether or not con->fd has data to read from the network)*/
            /*(leave frame in cq to be re-read later)*/
            return 0;
        }
    }
    /*(allow h2r->h2_rwin to dip below 0 so that entire frame is processed)*/
    /*(undeflow will not occur (with reasonable SETTINGS_MAX_FRAME_SIZE used)
     * since windows updated elsewhere and data is streamed to temp files if
     * not FDEVENT_STREAM_REQUEST_BUFMIN)*/
    /*r->h2_rwin -= (int32_t)len;*/
    h2_send_window_update(con, r->h2id, len); /*(r->h2_rwin)*/
    h2_send_window_update(con, 0, len);       /*(h2r->h2_rwin)*/

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

    /* r->conf.max_request_size is in kBytes */
    const off_t max_request_size = (off_t)r->conf.max_request_size << 10;
    if (0 != max_request_size
        && dst->bytes_in + (off_t)alen > max_request_size) {
        if (0 == r->http_status) {
            r->http_status = 413; /* Payload Too Large */
            log_error(r->conf.errh, __FILE__, __LINE__,
              "request-size too long: %lld -> 413",
              (long long) (dst->bytes_in + (off_t)alen));
        }
        chunkqueue_mark_written(cq, 9+len);
        return 1;
    }

    if ((s[4] & H2_FLAG_END_STREAM) && !h2_recv_end_data(r, con, alen)) {
        chunkqueue_mark_written(cq, 9+len);
        return 1;
    }

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
static uint32_t
h2_frame_cq_compact (chunkqueue * const cq, uint32_t len)
{
    /*(marked cold since most frames not expect to cross chunk boundary)*/

    /* caller must guarantee that chunks in chunkqueue are all MEM_CHUNK */
    /* caller should check (chunkqueue_length(cq) >= len) before calling,
     * or should check that returned value >= len */

    chunkqueue_compact_mem(cq, len);
    return buffer_string_length(cq->first->mem) - (uint32_t)cq->first->offset;
}


__attribute_cold__
static uint32_t
h2_recv_continuation (uint32_t n, uint32_t clen, const off_t cqlen, chunkqueue * const cq, connection * const con)
{
    chunk *c = cq->first;
    uint8_t *s = (uint8_t *)(c->mem->ptr + c->offset);
    uint32_t m = n;
    uint32_t flags;
    h2con * const h2c = con->h2;
    const uint32_t fsize = h2c->s_max_frame_size;
    const uint32_t id =
      ((s[5] << 24) | (s[6] << 16) | (s[7] << 8) | s[8]) & ~0x80000000u;
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
        const uint32_t flen = (s[n+0]<<16)|(s[n+1]<<8)|s[n+2];
        if (id != (uint32_t)((s[n+5]<<24)|(s[n+6]<<16)|(s[n+7]<<8)|s[n+8])) {
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
        const uint32_t flen = (s[0]<<16)|(s[1]<<8)|s[2];
        if (flen < 1 + plen + ((s[n+4] & H2_FLAG_PRIORITY) ? 5 : 0)) {
            /* Padding that exceeds the size remaining for the header block
             * fragment MUST be treated as a PROTOCOL_ERROR. */
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            return 0;
        }
        /* set padding to 0 since we will overwrite padding in merge below */
        /* (alternatively, could memmove() 9 bytes of frame header over the
         *  pad length octet, remove PADDED flag, add 1 to c->offset,
         *  add 1 to s, subtract 1 from clen and substract 1 from cqlen,
         *  substract 1 from n, add 1 to cq->bytes_out) */
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
        const uint32_t flen = (s[n+0]<<16)|(s[n+1]<<8)|s[n+2];
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
    buffer_string_set_length(c->mem, n + (uint32_t)c->offset);

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
    request_st *r = NULL;
    for (uint32_t i = 0, rused = h2c->rused; i < rused; ++i) {
        request_st * const rr = h2c->r[i];
        if (rr->h2id != id) continue;
        r = rr;
        break;
    }
    if (NULL == r) {
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return NULL;
    }
    if (r->h2state != H2_STATE_OPEN
        && r->h2state != H2_STATE_HALF_CLOSED_LOCAL) {
        h2_send_rst_stream(r, con, H2_E_STREAM_CLOSED);
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


static void
h2_parse_headers_frame (request_st * const restrict r, const unsigned char *psrc, const uint32_t plen, const int trailers)
{
    h2con * const h2c = r->con->h2;
    struct lshpack_dec * const restrict decoder = &h2c->decoder;
    const unsigned char * const endp = psrc + plen;
    http_header_parse_ctx hpctx;
    hpctx.hlen     = 0;
    hpctx.pseudo   = 1;
    hpctx.scheme   = 0;
    hpctx.trailers = trailers;
    hpctx.max_request_field_size = r->conf.max_request_field_size;
    hpctx.http_parseopts = r->conf.http_parseopts;
    const int log_request_header = r->conf.log_request_header;
    int rc = LSHPACK_OK;
    /*buffer_clear(&r->target);*//*(initial state)*/

    /*(h2_init_con() resized h2r->tmp_buf to 64k; shared with r->tmp_buf)*/
    buffer * const tb = r->tmp_buf;
    force_assert(tb->size >= 65536);/*(sanity check; remove in future)*/
    const lsxpack_strlen_t tbsz = (tb->size <= LSXPACK_MAX_STRLEN)
      ? tb->size
      : LSXPACK_MAX_STRLEN;

    /* note: #define LSHPACK_DEC_HTTP1X_OUTPUT 1 (default) configures
     * decoder to produce output in format: "field-name: value\r\n"
     * future: modify build system to define value to 0 in lshpack.h
     * against which lighttpd builds (or define value in build systems)
     * Then adjust code below to not use the HTTP/1.x compatibility,
     * as it is less efficient to copy into HTTP/1.1 request and reparse
     * than it is to directly parse each decoded header line. */
    lsxpack_header_t lsx;
    while (psrc < endp) {
        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = tb->ptr;
        lsx.val_len = tbsz;
        rc = lshpack_dec_decode(decoder, &psrc, endp, &lsx);
        if (0 == lsx.name_len)
            rc = LSHPACK_ERR_BAD_DATA;
        if (rc == LSHPACK_OK) {
            hpctx.k = lsx.buf+lsx.name_offset;
            hpctx.v = lsx.buf+lsx.val_offset;
            hpctx.klen = lsx.name_len;
            hpctx.vlen = lsx.val_len;
            /*assert(lsx.hpack_index < sizeof(lshpack_idx_http_header));*/
            hpctx.id = lshpack_idx_http_header[lsx.hpack_index];

            if (log_request_header)
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "fd:%d id:%u rqst: %.*s: %.*s", r->con->fd, r->h2id,
                  (int)hpctx.klen, hpctx.k, (int)hpctx.vlen, hpctx.v);

          #if 0
            /* might not be worth special-casing pseudo headers here and
             * repeating the code in http_request_parse_header() to avoid
             * memcmp() for pseudo headers (request.c does not know ls-hpack)*/
            if (hpctx.pseudo && lsx.hpack_index
                && lsx.hpack_index < LSHPACK_HDR_STATUS_200 && !trailers) {
                /* lsx.hpack_index:
                 *   LSHPACK_HDR_AUTHORITY
                 *   LSHPACK_HDR_METHOD_GET
                 *   LSHPACK_HDR_METHOD_POST
                 *   LSHPACK_HDR_PATH
                 *   LSHPACK_HDR_PATH_INDEX_HTML
                 *   LSHPACK_HDR_SCHEME_HTTP
                 *   LSHPACK_HDR_SCHEME_HTTPS
                 */
            }
          #endif

            r->http_status = http_request_parse_header(r, &hpctx);
            if (0 != r->http_status)
                break;
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
            r->h2_rwin = 0; /*(out-of-sync with peer, but is error case)*/
            /*r->h2state = H2_STATE_HALF_CLOSED_REMOTE*/
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
                h2_send_rst_stream(r, r->con, err);
            }
            if (!h2c->sent_goaway && !trailers)
                h2c->h2_cid = r->h2id;
            h2_send_goaway_e(r->con, err);
            if (!trailers) {
                h2_retire_stream(r, r->con);
                return;
            }
            else {
                r->state = CON_STATE_ERROR;
                r->h2state = H2_STATE_CLOSED;
            }
            break;
        }
    }

    hpctx.hlen += 2;
    r->rqst_header_len += hpctx.hlen;
    /*(accounting for mod_accesslog and mod_rrdtool)*/
    chunkqueue * const rq = &r->read_queue;
    rq->bytes_in  += (off_t)hpctx.hlen;
    rq->bytes_out += (off_t)hpctx.hlen;

    if (0 == r->http_status && LSHPACK_OK == rc) {
        if (hpctx.pseudo)
            r->http_status =
              http_request_validate_pseudohdrs(r, hpctx.scheme,
                                               hpctx.http_parseopts);
        if (0 == r->http_status)
            http_request_headers_process_h2(r, r->con->proto_default_port);
    }
}


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
    request_st *r = NULL;
    h2con * const h2c = con->h2;
    const uint32_t id =
      ((s[5] << 24) | (s[6] << 16) | (s[7] << 8) | s[8]) & ~0x80000000u;
    if (0 == id) { /* HEADERS, PUSH_PROMISE stream id must != 0 */
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }
    if (!(id & 1)) { /* stream id from client must be odd */
        h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
        return 0;
    }

    request_st * const h2r = &con->request;
    int trailers = 0;

    if (id > h2c->h2_cid) {
        if (h2c->rused == sizeof(h2c->r)/sizeof(*h2c->r)) {
            if (0 == h2c->sent_settings) { /*(see h2_recv_settings() comments)*/
                /* too many active streams; refuse new stream */
                h2c->h2_cid = id;
                h2_send_rst_stream_id(id, con, H2_E_REFUSED_STREAM);
                return 1;
            }
            else {
                /* alternative: stop processing frames and defer processing this
                 * HEADERS frame until num active streams drops below limit.
                 * lighttpd sends SETTINGS_MAX_CONCURRENT_STREAMS <limit> with
                 * server Connection Preface, so a well-behaved client will
                 * adjust after it sends its initial requests.
                 * (e.g. h2load -n 100 -m 100 sends 100 requests upon connect)*/
                return -1;
            }
        }
        /* Note: MUST process HPACK decode even if already sent GOAWAY.
         * This is necessary since there may be active streams not in
         * H2_STATE_HALF_CLOSED_REMOTE, e.g. H2_STATE_OPEN, still possibly
         * receiving DATA and, more relevantly, still might receive HEADERS
         * frame with trailers, for which the decoder state is required.
         * XXX: future might try to reduce other processing done if sent
         *      GOAWAY, e.g. might avoid allocating (request_st *r) */
        r = h2_init_stream(h2r, con);
        r->h2id = id;
        r->h2state = (s[4] & H2_FLAG_END_STREAM)
          ? H2_STATE_HALF_CLOSED_REMOTE
          : H2_STATE_OPEN;
        r->state = CON_STATE_REQUEST_END;
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
    }
    else {
        r = h2_recv_trailers_r(con, h2c, id, s[4]); /* (cold code path) */
        if (NULL == r)
            return (h2c->sent_goaway > 0) ? 0 : 1;
        trailers = 1;
    }

    const unsigned char *psrc = s + 9;
    uint32_t alen = flen;
    if (s[4] & H2_FLAG_PADDED) {
        ++psrc;
        const uint32_t pad = s[9];
        if (flen < 1 + pad + ((s[4] & H2_FLAG_PRIORITY) ? 5 : 0)) {
            /* Padding that exceeds the size remaining for the header block
             * fragment MUST be treated as a PROTOCOL_ERROR. */
            h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
            if (!trailers)
                h2_retire_stream(r, con);
            else {
                r->state = CON_STATE_ERROR;
                r->h2state = H2_STATE_CLOSED;
            }
            return 0;
        }
        alen -= (1 + pad); /*(alen is adjusted for PRIORITY below)*/
    }
    if (s[4] & H2_FLAG_PRIORITY) {
        /* XXX: TODO: handle PRIORITY (prio fields start at *psrc) */
        const uint32_t prio =
          ((psrc[0]<<24)|(psrc[1]<<16)|(psrc[2]<<8)|psrc[3]) & ~0x80000000u;
        if (prio == id) {
            h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
            if (!trailers)
                h2_retire_stream(r, con);
            return 1;
        }
      #if 0
        uint32_t exclusive_dependency = (psrc[0] & 0x80) ? 1 : 0;
        uint32_t weight = psrc[4];
      #endif
        psrc += 5;
        alen -= 5;
    }

    h2_parse_headers_frame(r, psrc, alen, trailers);

  #if 0 /*(handled in h2_parse_frames() as a connection error)*/
    /* not handled here:
     * r is invalid if h2_parse_headers_frame() HPACK decode error */
    if (s[3] == H2_FTYPE_PUSH_PROMISE && !trailers) {
        /* Had to process HPACK to keep HPACK tables sync'd with peer but now
         * discard the request if PUSH_PROMISE, since not expected, as this code
         * is running as a server, not as a client.
         * XXX: future might try to reduce other processing done if
         * discarding, e.g. might avoid allocating (request_st *r) */
        /* rant: PUSH_PROMISE could have been a flag on HEADERS frame
         *       instead of an independent frame type */
        r->http_status = 0;
        h2_retire_stream(r, con);
    }
  #endif

    if (!h2c->sent_goaway) {
        h2c->h2_cid = id;
        if (!light_btst(r->rqst_htags, HTTP_HEADER_CONTENT_LENGTH))
            r->reqbody_length = (s[4] & H2_FLAG_END_STREAM) ? 0 : -1;
      #if 0
        else if (r->reqbody_length > 0 && (s[4] & H2_FLAG_END_STREAM)) {
            /*(handled in connection_handle_read_post_state())*/
            /* XXX: TODO if (r->conf.log_request_header_on_error) */
            r->http_status = 400; /* Bad Request */
        }
      #endif

        /* RFC 7540 Section 8. HTTP Message Exchanges
         * 8.1.2.6. Malformed Requests and Responses
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
      #if 0
        if (400 == r->http_status && !trailers) {
            h2_send_rst_stream(r, con, H2_E_PROTOCOL_ERROR);
            h2_retire_stream(r, con);
        }
      #endif
    }
    else if (h2c->h2_cid < id) {
        /* Had to process HPACK to keep HPACK tables sync'd with peer
         * but now discard the request if id is after id sent in GOAWAY.
         * XXX: future might try to reduce other processing done if
         * discarding, e.g. might avoid allocating (request_st *r) */
        r->http_status = 0;
        h2_retire_stream(r, con);
    }

    return 1;
}


int
h2_parse_frames (connection * const con)
{
    /* read and process HTTP/2 frames from socket */
    h2con * const h2c = con->h2;
    chunkqueue * const cq = con->read_queue;
    /* initial max frame size is the minimum: 16k
     * (lighttpd does not currently increase max frame size)
     * (lighttpd does not currently decrease max frame size)
     * (XXX: If SETTINGS_MAX_FRAME_SIZE were increased and then decreased,
     *       should accept the larger frame size until SETTINGS is ACK'd) */
    const uint32_t fsize = h2c->s_max_frame_size;
    for (off_t cqlen = chunkqueue_length(cq); cqlen >= 9; ) {
        chunk *c = cq->first;
        /*assert(c->type == MEM_CHUNK);*/
        /* copy data if frame header crosses chunk boundary
         * future: be more efficient than blind full chunk copy */
        uint32_t clen = buffer_string_length(c->mem) - c->offset;
        if (clen < 9) {
            clen = h2_frame_cq_compact(cq, 9);
            c = cq->first; /*(reload after h2_frame_cq_compact())*/
        }
        uint8_t *s = (uint8_t *)(c->mem->ptr + c->offset);
        uint32_t flen = (s[0] << 16) | (s[1] << 8) | s[2];
        if (flen > fsize) {
            h2_send_goaway_e(con, H2_E_FRAME_SIZE_ERROR);
            return 0;
        }

        /*(handle PUSH_PROMISE as connection error further below)*/
        /*if (s[3] == H2_FTYPE_HEADERS || s[3] == H2_FTYPE_PUSH_PROMISE)*/

        if (s[3] == H2_FTYPE_HEADERS) {
            if (cqlen < 9+flen) return 1; /* incomplete frame; go on */
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
                flen = (s[0]<<16)|(s[1]<<8)|s[2];
                /* recalculate after CONTINUATION removed */
                cqlen = chunkqueue_length(cq);
            }

          #ifdef __COVERITY__
            /* Coverity does not notice that values used in s are checked.
             * Although silencing here, would prefer not to do so since doing so
             * disables Coverity from reporting questionable modifications which
             * might be made to the code in the future. */
            __coverity_tainted_data_sink__(s);
          #endif

            int rc = h2_recv_headers(con, s, flen);
            cqlen -= (9+flen);
            if (rc >= 0)
                chunkqueue_mark_written(cq, 9+flen);
            if (rc <= 0)
                return 0;
            con->read_idle_ts = log_epoch_secs;
        }
        else if (s[3] == H2_FTYPE_DATA) {
            /* future: might try to stream data for incomplete frames,
             * but that would require keeping additional state for partially
             * read frames, including cleaning up if errors occur.
             * Since well-behaved clients do not intentionally send partial
             * frames, and try to resend if socket buffers are full, this is
             * probably not a big concern in practice. */
            if (cqlen < 9+flen) return 1; /* incomplete frame; go on */
            con->read_idle_ts = log_epoch_secs;
            /*(h2_recv_data() must consume frame from cq or else return 0)*/
            if (!h2_recv_data(con, s, flen))
                return 0;
            cqlen -= (9+flen);
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
            if (cqlen < 9+flen) return 1; /* incomplete frame; go on */
            if (clen < 9+flen) {
                clen = h2_frame_cq_compact(cq, 9+flen); UNUSED(clen);
                c = cq->first; /*(reload after h2_frame_cq_compact())*/
                s = (uint8_t *)(c->mem->ptr + c->offset);
            }
            switch (s[3]) { /* frame type */
              case H2_FTYPE_WINDOW_UPDATE:
                h2_recv_window_update(con, s, flen);
                break;
              case H2_FTYPE_PRIORITY:
                h2_recv_priority(con, s, flen);
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
              case H2_FTYPE_PUSH_PROMISE: /*not expected from client*/
              case H2_FTYPE_CONTINUATION: /*handled with HEADERS*/
                h2_send_goaway_e(con, H2_E_PROTOCOL_ERROR);
                return 0;
              default: /* ignore unknown frame types */
                break;
            }
            cqlen -= (9+flen);
            chunkqueue_mark_written(cq, 9+flen);
        }

        if (h2c->sent_goaway > 0) return 0;
    }

    return 1;
}


int
h2_want_read (connection * const con)
{
    chunkqueue * const cq = con->read_queue;
    if (chunkqueue_is_empty(cq)) return 1;

    /* check for partial frame */
    const off_t cqlen = chunkqueue_length(cq);
    if (cqlen < 9) return 1;
    chunk *c = cq->first;
    uint32_t clen = buffer_string_length(c->mem) - c->offset;
    if (clen < 9) {
        clen = h2_frame_cq_compact(cq, 9);
        c = cq->first; /*(reload after h2_frame_cq_compact())*/
    }
    uint8_t *s = (uint8_t *)(c->mem->ptr + c->offset);
    uint32_t flen = (s[0] << 16) | (s[1] << 8) | s[2];
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
        flen = (s[n+0] << 16) | (s[n+1] << 8) | s[n+2];
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
        if (c && buffer_string_length(c->mem) - c->offset >= 4) {
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
    const uint32_t clen = buffer_string_length(c->mem) - c->offset;
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
    if (NULL == con->h2) return rc; /*(unexpected; already cleaned up)*/
    if (-1 != rc && h2_recv_client_connection_preface(con)) {
        con->network_read = network_read;
        *hctx = NULL;
        /*(intentionally update timestamp only after reading preface complete)*/
        con->read_idle_ts = log_epoch_secs;
    }
    return rc;
}


void
h2_init_con (request_st * const restrict h2r, connection * const restrict con, const buffer * const restrict http2_settings)
{
    h2con * const h2c = calloc(1, sizeof(h2con));
    force_assert(h2c);
    con->h2 = h2c;
    con->read_idle_ts = log_epoch_secs;
    con->keep_alive_idle = h2r->conf.max_keep_alive_idle;

    h2r->h2_rwin = 65535;                 /* h2 connection recv window */
    h2r->h2_swin = 65535;                 /* h2 connection send window */
    /* settings sent from peer */         /* initial values */
    h2c->s_header_table_size     = 4096;  /* SETTINGS_HEADER_TABLE_SIZE      */
    h2c->s_enable_push           = 1;     /* SETTINGS_ENABLE_PUSH            */
    h2c->s_max_concurrent_streams= ~0u;   /* SETTINGS_MAX_CONCURRENT_STREAMS */
    h2c->s_initial_window_size   = 65535; /* SETTINGS_INITIAL_WINDOW_SIZE    */
    h2c->s_max_frame_size        = 16384; /* SETTINGS_MAX_FRAME_SIZE         */
    h2c->s_max_header_list_size  = ~0u;   /* SETTINGS_MAX_HEADER_LIST_SIZE   */
    h2c->sent_settings           = log_epoch_secs; /*(send SETTINGS below)*/

    lshpack_dec_init(&h2c->decoder);
    lshpack_enc_init(&h2c->encoder);
    lshpack_enc_use_hist(&h2c->encoder, 1);

    if (http2_settings) /*(if Upgrade: h2c)*/
        h2_parse_frame_settings(con, (uint8_t *)CONST_BUF_LEN(http2_settings));

    static const uint8_t h2settings[] = { /*(big-endian numbers)*/
      /* SETTINGS */
      0x00, 0x00, 0x0c        /* frame length */ /* 6 * 2 for two settings */
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
     #if 0  /* ? increase from default (65535) ? (and adjust frame length) */
     ,0x00, H2_SETTINGS_INITIAL_WINDOW_SIZE
     ,0x00, 0x02, 0x00, 0x00  /* 131072 */
     #endif
     #if 0  /* ? increase from default (16384) ? (and adjust frame length) */
     ,0x00, H2_SETTINGS_MAX_FRAME_SIZE
     ,0x00, 0x00, 0x80, 0x00  /* 32768 */
     #endif
     ,0x00, H2_SETTINGS_MAX_HEADER_LIST_SIZE
     ,0x00, 0x00, 0xFF, 0xFF  /* 65535 */

     #if 0
      /* WINDOW_UPDATE */
     ,0x00, 0x00, 0x04        /* frame length */
     ,H2_FTYPE_WINDOW_UPDATE  /* frame type */
     ,0x00                    /* frame flags */
     ,0x00, 0x00, 0x00, 0x00  /* stream identifier */
     ,0x00, 0x01, 0x00, 0x01  /* 65537 */ /* increase connection rwin to 128k */
     #endif
    };

    /*h2r->h2_rwin += 65537;*//*(enable if WINDOWS_UPDATE is sent above)*/
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

    headers.u[2] = htonl(r->h2id);

    /* similar to h2_send_data(), but unlike DATA frames there is a HEADERS
     * frame potentially followed by CONTINUATION frame(s) here, and the final
     * HEADERS or CONTINUATION frame here has END_HEADERS flag set.
     * For trailers, END_STREAM flag is set on HEADERS frame. */

    /*(approximate space needed for frames (header + payload)
     * with slight over-estimate of 16 bytes per frame header (> 9)
     * and minimum SETTING_MAX_FRAME_SIZE of 16k (could be larger)
     * (dlen >> 14)+1 is num 16k frames needed, multipled by 16 bytes
     *  per frame can be appoximated with (dlen>>10) + 9)*/
    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, dlen + (dlen>>10) + 9);
    char * restrict ptr = b->ptr;
    h2con * const h2c = con->h2;
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
    buffer_string_set_length(b, (uint32_t)(ptr - b->ptr));
    chunkqueue_append_buffer_commit(con->write_queue);
}


__attribute_cold__
static void
h2_log_response_header_lsx(request_st * const r, const lsxpack_header_t * const lsx)
{
    log_error(r->conf.errh, __FILE__, __LINE__,
      "fd:%d id:%u resp: %.*s: %.*s", r->con->fd, r->h2id,
      (int)lsx->name_len, lsx->buf + lsx->name_offset,
      (int)lsx->val_len,  lsx->buf + lsx->val_offset);
}


__attribute_cold__
static void
h2_log_response_header(request_st * const r, const int len, const char * const hdr)
{
    log_error(r->conf.errh, __FILE__, __LINE__,
      "fd:%d id:%u resp: %.*s", r->con->fd, r->h2id, len, hdr);
}


void
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

    h2con * const h2c = con->h2;
    struct lshpack_enc * const encoder = &h2c->encoder;
    lsxpack_header_t lsx;
    uint32_t alen = 7+3+4; /* ":status: xxx\r\n" */
    const int log_response_header = r->conf.log_response_header;
    const int resp_header_repeated = r->resp_header_repeated;

    char status[12] = ":status: ";
    int x = r->http_status; /*(expect status < 1000; should be [100-599])*/
    status[11] = (x % 10) + '0';
    status[10] = (x / 10 % 10) + '0';
    status[9]  = (x / 100) + '0';

    if (log_response_header)
        h2_log_response_header(r, 12, status);

    memset(&lsx, 0, sizeof(lsxpack_header_t));
    lsx.buf = status;
    lsx.name_offset = 0;
    lsx.name_len = 7;
    lsx.val_offset = 9;
    lsx.val_len = 3;
    switch (r->http_status) {
      case 200: lsx.hpack_index = LSHPACK_HDR_STATUS_200; break;
      case 204: lsx.hpack_index = LSHPACK_HDR_STATUS_204; break;
      case 206: lsx.hpack_index = LSHPACK_HDR_STATUS_206; break;
      case 304: lsx.hpack_index = LSHPACK_HDR_STATUS_304; break;
      case 400: lsx.hpack_index = LSHPACK_HDR_STATUS_400; break;
      case 404: lsx.hpack_index = LSHPACK_HDR_STATUS_404; break;
      case 500: lsx.hpack_index = LSHPACK_HDR_STATUS_500; break;
      default:
        break;
    }
    dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
    if (dst == (unsigned char *)tb->ptr) {
        h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
        return;
    }

    /* add all headers */
    for (uint32_t i = 0, used = r->resp_headers.used; i < used; ++i) {
        data_string * const restrict ds =(data_string *)r->resp_headers.data[i];
        const uint32_t klen = buffer_string_length(&ds->key);
        const uint32_t vlen = buffer_string_length(&ds->value);
        const char * const restrict k = ds->key.ptr;
        if (0 == vlen || 0 == klen) continue;
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
         * end of value buffer */
        char * const v = buffer_string_prepare_append(&ds->value, klen);
        if (ds->ext != HTTP_HEADER_OTHER) {
            memcpy(v, http_header_lc[ds->ext], klen);
        }
        else {
            if ((k[0] & 0xdf) == 'X' && http_response_omit_header(r, ds)) {
                alen -= klen + vlen + 4;
                continue;
            }
            for (uint32_t j = 0; j < klen; ++j)
                v[j] = !light_isupper(k[j]) ? k[j] : (k[j] | 0x20);
        }
        /*buffer_commit(&ds->value, klen);*//*(not necessary; truncated below)*/

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
            lsx.name_offset = vlen;
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
                buffer_string_set_length(&ds->value, vlen); /*(restore prior value)*/
                h2_send_rst_stream(r, con, H2_E_INTERNAL_ERROR);
                return;
            }
        } while (n);
        buffer_string_set_length(&ds->value, vlen); /*(restore prior value)*/
    }

    if (!light_btst(r->resp_htags, HTTP_HEADER_DATE)) {
        /* HTTP/1.1 and later requires a Date: header */
        /* "date: " 6-chars + 30-chars for "%a, %d %b %Y %H:%M:%S GMT" + '\0' */
        static time_t tlast = 0;
        static char tstr[36] = "date: ";

        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = tstr;
        lsx.name_offset = 0;
        lsx.name_len = 4;
        lsx.val_offset = 6;
        lsx.val_len = 29;
        lsx.hpack_index = LSHPACK_HDR_DATE;

        /* cache the generated timestamp */
        const time_t cur_ts = log_epoch_secs;
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

    if (!light_btst(r->resp_htags, HTTP_HEADER_SERVER)
        && !buffer_string_is_empty(r->conf.server_tag)) {
        buffer * const b = chunk_buffer_acquire();
        const uint32_t vlen = buffer_string_length(r->conf.server_tag);
        buffer_copy_string_len(b, CONST_STR_LEN("server: "));
        buffer_append_string_len(b, CONST_BUF_LEN(r->conf.server_tag));

        alen += 6+vlen+4;

        if (log_response_header)
            h2_log_response_header(r, (int)6+vlen+2, b->ptr);

        memset(&lsx, 0, sizeof(lsxpack_header_t));
        lsx.buf = b->ptr;
        lsx.name_offset = 0;
        lsx.name_len = 6;
        lsx.val_offset = 8;
        lsx.val_len = vlen;
        lsx.hpack_index = LSHPACK_HDR_SERVER;
        unsigned char * const dst_in = dst;
        dst = lshpack_enc_encode(encoder, dst, dst_end, &lsx);
        chunk_buffer_release(b);
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
      (r->resp_body_finished && chunkqueue_is_empty(&r->write_queue))
        ? H2_FLAG_END_STREAM
        : 0;
    h2_send_hpack(r, con, tb->ptr, dlen, flags);
}


__attribute_cold__
__attribute_noinline__
static void
h2_send_headers_block (request_st * const r, connection * const con, const char * const hdrs, const uint32_t hlen, uint32_t flags)
{
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */
    hoff[0] = 1;                         /* number of lines */
    hoff[1] = 0;                         /* base offset for all lines */
    /*hoff[2] = ...;*/                   /* offset from base for 2nd line */
    uint32_t rc = http_header_parse_hoff(hdrs, hlen, hoff);
    if (0 == rc || rc > USHRT_MAX || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1
        || 1 == hoff[0]) { /*(initial blank line (should not happen))*/
        /* error if headers incomplete or too many header fields */
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "oversized response-header");
        hoff[0] = 1;
        hoff[1] = 0;
        http_header_parse_hoff(CONST_STR_LEN(":status: 500\r\n\r\n"), hoff);
    }

    /*(h2_init_con() resized h2r->tmp_buf to 64k; shared with r->tmp_buf)*/
    buffer * const tb = r->tmp_buf;
    force_assert(tb->size >= 65536);/*(sanity check; remove in future)*/
    unsigned char *dst = (unsigned char *)tb->ptr;
    unsigned char * const dst_end = (unsigned char *)tb->ptr + tb->size;

    h2con * const h2c = con->h2;
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
        const char *k = hdrs + ((i > 1) ? hoff[i] : 0);
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
h2_send_1xx_block (request_st * const r, connection * const con, const char * const hdrs, const uint32_t hlen)
{
    h2_send_headers_block(r, con, hdrs, hlen, 0);
}


int
h2_send_1xx (request_st * const r, connection * const con)
{
    buffer * const b = chunk_buffer_acquire();

    buffer_copy_string_len(b, CONST_STR_LEN(":status: "));
    buffer_append_int(b, r->http_status);
    for (uint32_t i = 0; i < r->resp_headers.used; ++i) {
        const data_string * const ds = (data_string *)r->resp_headers.data[i];

        if (buffer_string_is_empty(&ds->value)) continue;
        if (buffer_string_is_empty(&ds->key)) continue;

        buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
        buffer_append_string_buffer(b, &ds->key);
        buffer_append_string_len(b, CONST_STR_LEN(": "));
        buffer_append_string_buffer(b, &ds->value);
    }
    buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

    h2_send_1xx_block(r, con, CONST_BUF_LEN(b));

    chunk_buffer_release(b);
    return 1; /* for http_response_send_1xx_cb */
}


void
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

    h2_send_1xx_block(r, con, CONST_STR_LEN(":status: 100\r\n\r\n"));
}


static void
h2_send_end_stream_data (request_st * const r, connection * const con);

__attribute_cold__
__attribute_noinline__
static void
h2_send_end_stream_trailers (request_st * const r, connection * const con, const buffer * const trailers)
{
    /*(trailers are merged into response headers if trailers are received before
     * sending response headers to client.  However, if streaming response, then
     * trailers might need handling here)*/

    /* parse and lowercase field-names in trailers */
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */
    hoff[0] = 1;                         /* number of lines */
    hoff[1] = 0;                         /* base offset for all lines */
    /*hoff[2] = ...;*/                   /* offset from base for 2nd line */
    uint32_t rc = http_header_parse_hoff(CONST_BUF_LEN(trailers), hoff);
    if (0 == rc || rc > USHRT_MAX || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1
        || 1 == hoff[0]) { /*(initial blank line)*/
        /* skip trailers if incomplete, too many fields, or too long (> 64k-1)*/
        h2_send_end_stream_data(r, con);
        return;
    }

    char * const ptr = trailers->ptr;
    for (int i = 1; i < hoff[0]; ++i) {
        char *k = ptr + ((i > 1) ? hoff[i] : 0);
        if (*k == ':') {
            /*(pseudo-header should not appear in trailers)*/
            h2_send_end_stream_data(r, con);
            return;
        }
        const char * const colon = memchr(k, ':', ptr+hoff[i+1]-k);
        if (NULL == colon) continue;
        do {
            if (light_isupper(*k)) *k |= 0x20;
        } while (++k != colon);
    }

    h2_send_headers_block(r, con, CONST_BUF_LEN(trailers), H2_FLAG_END_STREAM);
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
    const uint32_t len = buffer_string_length(c->mem) - (uint32_t)c->offset;
    uint32_t flags = (r->resp_body_finished && NULL == c->next)
      ? H2_FLAG_END_STREAM
      : 0;
    h2_send_headers_block(r, con, c->mem->ptr + c->offset, len, flags);
    chunkqueue_mark_written(&r->write_queue, len);
}
#endif


#if 0

void
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

    dataframe.u[2] = htonl(r->h2id);

    /* XXX: does not provide an optimization to send final set of data with
     *      END_STREAM flag; see h2_send_end_stream_data() to end stream */

    /* adjust stream and connection windows */
    /*assert(dlen <= INT32_MAX);*//* dlen should be <= MAX_WRITE_LIMIT */
    request_st * const h2r = &con->request;
    if (r->h2_swin   < 0) return;
    if (h2r->h2_swin < 0) return;
    if ((int32_t)dlen > r->h2_swin)   dlen = (uint32_t)r->h2_swin;
    if ((int32_t)dlen > h2r->h2_swin) dlen = (uint32_t)h2r->h2_swin;
    if (0 == dlen) return;
    r->h2_swin   -= (int32_t)dlen;
    h2r->h2_swin -= (int32_t)dlen;

    /* XXX: future: should have an interface which processes chunkqueue
     * and takes string refs to mmap FILE_CHUNK to avoid extra copying
     * since the result is likely to be consumed by TLS modules */

    /*(approximate space needed for frames (header + payload)
     * with slight over-estimate of 16 bytes per frame header (> 9)
     * and minimum SETTING_MAX_FRAME_SIZE of 16k (could be larger)
     * (dlen >> 14)+1 is num 16k frames needed, multipled by 16 bytes
     *  per frame can be appoximated with (dlen>>10) + 9)*/
    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, dlen + (dlen>>10) + 9);
    char * restrict ptr = b->ptr;
    h2con * const h2c = con->h2;
    const uint32_t fsize = h2c->s_max_frame_size;
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
        dlen -= len;
    } while (dlen);
    buffer_string_set_length(b, (uint32_t)(ptr - b->ptr));
    chunkqueue_append_buffer_commit(con->write_queue);
}

#endif


void
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

    dataframe.u[2] = htonl(r->h2id);

    /* XXX: does not provide an optimization to send final set of data with
     *      END_STREAM flag; see h2_send_end_stream_data() to end stream */

    /* adjust stream and connection windows */
    /*assert(dlen <= INT32_MAX);*//* dlen should be <= MAX_WRITE_LIMIT */
    request_st * const h2r = &con->request;
    if (r->h2_swin   < 0) return;
    if (h2r->h2_swin < 0) return;
    if ((int32_t)dlen > r->h2_swin)   dlen = (uint32_t)r->h2_swin;
    if ((int32_t)dlen > h2r->h2_swin) dlen = (uint32_t)h2r->h2_swin;
    if (0 == dlen) return;
    r->h2_swin   -= (int32_t)dlen;
    h2r->h2_swin -= (int32_t)dlen;

    /* XXX: future: should have an interface which processes chunkqueue
     * and takes string refs to mmap FILE_CHUNK to avoid extra copying
     * since the result is likely to be consumed by TLS modules */

    h2con * const h2c = con->h2;
    const uint32_t fsize = h2c->s_max_frame_size;
    do {
        const uint32_t len = dlen < fsize ? dlen : fsize;
        dataframe.c[3] = (len >> 16) & 0xFF; /*(off +3 to skip over align pad)*/
        dataframe.c[4] = (len >>  8) & 0xFF;
        dataframe.c[5] = (len      ) & 0xFF;
        chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align pad)*/
                              (const char *)dataframe.c+3, sizeof(dataframe)-3);
        chunkqueue_steal(con->write_queue, cq, (off_t)dlen);
        dlen -= len;
    } while (dlen);
}


static void
h2_send_end_stream_data (request_st * const r, connection * const con)
{
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

    dataframe.u[2] = htonl(r->h2id);
    r->h2state = H2_STATE_CLOSED;
    /*(ignore window updates when sending 0-length DATA frame with END_STREAM)*/
    chunkqueue_append_mem(con->write_queue,  /*(+3 to skip over align pad)*/
                          (const char *)dataframe.c+3, sizeof(dataframe)-3);
}


void
h2_send_end_stream (request_st * const r, connection * const con)
{
    if (r->state != CON_STATE_ERROR && r->resp_body_finished) {
        /* CON_STATE_RESPONSE_END */
        if (r->gw_dechunk && r->gw_dechunk->done
            && !buffer_is_empty(&r->gw_dechunk->b))
            h2_send_end_stream_trailers(r, con, &r->gw_dechunk->b);
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
#include "plugin.h"
#include "plugin_config.h"
#include "reqpool.h"


static request_st *
h2_init_stream (request_st * const h2r, connection * const con)
{
    h2con * const h2c = con->h2;
    ++con->request_count;
    force_assert(h2c->rused < sizeof(h2c->r)/sizeof(*h2c->r));
    /* initialize stream as subrequest (request_st *) */
    request_st * const r = request_acquire(con);
    /* XXX: TODO: assign default priority, etc.
     *      Perhaps store stream id and priority in separate table */
    h2c->r[h2c->rused++] = r;
    r->h2_rwin = h2c->s_initial_window_size;
    r->h2_swin = h2c->s_initial_window_size;
    r->http_version = HTTP_VERSION_2;

    /* copy config state from h2r */
    server * const srv = con->srv;
    const uint32_t used = srv->config_context->used;
    r->conditional_is_valid = h2r->conditional_is_valid;
    memcpy(r->cond_cache, h2r->cond_cache, used * sizeof(cond_cache_t));
  #ifdef HAVE_PCRE_H
    if (used > 1) /*(save 128b per con if no conditions)*/
        memcpy(r->cond_match, h2r->cond_match, used * sizeof(cond_match_t));
  #endif
    /*(see config_reset_config())*/
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


void
h2_retire_stream (request_st *r, connection * const con)
{
    if (r == NULL) return; /*(should not happen)*/
    h2con * const h2c = con->h2;
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


void
h2_retire_con (request_st * const h2r, connection * const con)
{
    h2con * const h2c = con->h2;
    if (NULL == h2c) return;

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
            con->bytes_written += written;
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

    con->h2 = NULL;

    /* future: might keep a pool of reusable (h2con *) */
    lshpack_enc_cleanup(&h2c->encoder);
    lshpack_dec_cleanup(&h2c->decoder);
    free(h2c);
}


static void
h2_con_upgrade_h2c (request_st * const h2r, const buffer * const http2_settings)
{
    /* status: (h2r->state == CON_STATE_REQUEST_END) for Upgrade: h2c */

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

    connection * const con = h2r->con;
    h2_init_con(h2r, con, http2_settings);
    if (con->h2->sent_goaway) return;

    con->h2->h2_cid = 1; /* stream id 1 is assigned to h2c upgrade */

    /* copy request state from &con->request to subrequest r
     * XXX: would be nice if there were a cleaner way to do this
     * (This is fragile and must be kept in-sync with request_st in request.h)*/

    request_st * const r = h2_init_stream(h2r, con);
    /*(undo double-count; already incremented in CON_STATE_REQUEST_START)*/
    --con->request_count;
    r->state = h2r->state; /* CON_STATE_REQUEST_END */
    r->http_status = 0;
    r->http_method = h2r->http_method;
    r->h2state = H2_STATE_HALF_CLOSED_REMOTE;
    r->h2id = 1;
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
    r->te_chunked = h2r->te_chunked;         /* must be 0 */
    r->resp_body_scratchpad = h2r->resp_body_scratchpad; /*(not started yet)*/
    swap(&r->reqbody_queue,&h2r->reqbody_queue);/*currently always empty queue*/
  #endif
    r->http_host = h2r->http_host;
    h2r->http_host = NULL;
  #if 0
    r->server_name = h2r->server_name;
    h2r->server_name = NULL;
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
    r->async_callback = h2r->async_callback;
  #endif
    r->keep_alive = h2r->keep_alive;
    r->tmp_buf = h2r->tmp_buf;                /* shared; same as srv->tmp_buf */
    r->start_hp = h2r->start_hp;                /* copy struct */

    /* Note: HTTP/1.1 101 Switching Protocols is not immediately written to
     * the network here.  As this is called from cleartext Upgrade: h2c,
     * we choose to delay sending the status until the beginning of the response
     * to the HTTP/1.1 request which included Upgrade: h2c */
}


int
h2_check_con_upgrade_h2c (request_st * const r)
{
    /* RFC7540 3.2 Starting HTTP/2 for "http" URIs */

    buffer *http_connection, *http2_settings;
    buffer *upgrade = http_header_request_get(r, HTTP_HEADER_UPGRADE,
                                              CONST_STR_LEN("Upgrade"));
    if (NULL == upgrade) return 0;
    http_connection = http_header_request_get(r, HTTP_HEADER_CONNECTION,
                                              CONST_STR_LEN("Connection"));
    if (NULL == http_connection) {
        http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                                  CONST_STR_LEN("Upgrade"));
        return 0;
    }
    if (r->http_version != HTTP_VERSION_1_1) {
        http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                                  CONST_STR_LEN("Upgrade"));
        http_header_remove_token(http_connection, CONST_STR_LEN("Upgrade"));
        return 0;
    }

    if (!http_header_str_contains_token(CONST_BUF_LEN(upgrade),
                                        CONST_STR_LEN("h2c")))
        return 0;

    http2_settings = http_header_request_get(r, HTTP_HEADER_HTTP2_SETTINGS,
                                             CONST_STR_LEN("HTTP2-Settings"));
    if (NULL != http2_settings) {
        if (0 == r->reqbody_length) {
            buffer * const b = r->tmp_buf;
            buffer_clear(b);
            if (r->conf.h2proto > 1/*(must be enabled with server.h2c feature)*/
                &&
                http_header_str_contains_token(CONST_BUF_LEN(http_connection),
                                               CONST_STR_LEN("HTTP2-Settings"))
                && buffer_append_base64_decode(b, CONST_BUF_LEN(http2_settings),
                                               BASE64_URL)) {
                h2_con_upgrade_h2c(r, b);
                r->http_version = HTTP_VERSION_2;
            } /* else ignore if invalid base64 */
        }
        else {
            /* ignore Upgrade: h2c if request body present since we do not
             * (currently) handle request body before transition to h2c */
            /* RFC7540 3.2 Requests that contain a payload body MUST be sent
             * in their entirety before the client can send HTTP/2 frames. */
        }
        http_header_request_unset(r, HTTP_HEADER_HTTP2_SETTINGS,
                                  CONST_STR_LEN("HTTP2-Settings"));
        http_header_remove_token(http_connection, CONST_STR_LEN("HTTP2-Settings"));
    } /* else ignore Upgrade: h2c; HTTP2-Settings required for Upgrade: h2c */
    http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                              CONST_STR_LEN("Upgrade"));
    http_header_remove_token(http_connection, CONST_STR_LEN("Upgrade"));
    return (r->http_version == HTTP_VERSION_2);
}
