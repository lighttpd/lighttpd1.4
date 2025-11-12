/*
 * request - HTTP request processing
 *
 * Fully-rewritten from original
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "request.h"
#include "burl.h"
#include "fdevent.h"  /* FDEVENT_STREAM_REQUEST FDEVENT_STREAM_REQUEST_BUFMIN */
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "sock_addr.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


__attribute_cold__
__attribute_noinline__
void
http_request_state_append (buffer * const b, request_state_t state)
{
    static const struct sn { const char *s; uint32_t n; } states[] = {
      { CONST_STR_LEN("connect") }
     ,{ CONST_STR_LEN("req-start") }
     ,{ CONST_STR_LEN("read") }
     ,{ CONST_STR_LEN("req-end") }
     ,{ CONST_STR_LEN("readpost") }
     ,{ CONST_STR_LEN("handle-req") }
     ,{ CONST_STR_LEN("resp-start") }
     ,{ CONST_STR_LEN("write") }
     ,{ CONST_STR_LEN("resp-end") }
     ,{ CONST_STR_LEN("error") }
     ,{ CONST_STR_LEN("close") }
     ,{ CONST_STR_LEN("(unknown)") }
    };
    const struct sn * const p =
      states +((uint32_t)state <= CON_STATE_CLOSE ? state : CON_STATE_CLOSE+1);
    buffer_append_string_len(b, p->s, p->n);
}

__attribute_cold__
__attribute_noinline__
__attribute_pure__
const char *
http_request_state_short (request_state_t state)
{
    /*((char *) returned, but caller must use only one char)*/
    static const char sstates[] = ".qrQRhsWSECx";
    return
      sstates+((uint32_t)state <= CON_STATE_CLOSE ? state : CON_STATE_CLOSE+1);
}


__attribute_noinline__
__attribute_nonnull__()
__attribute_pure__
static const char * http_request_check_uri_strict (const uint8_t * const restrict s, const uint_fast32_t len) {
    for (uint_fast32_t i = 0; i < len; ++i) {
        if (__builtin_expect( (s[i] <= 32),  0))
            return (const char *)s+i;
        if (__builtin_expect( ((s[i] & 0x7f) == 0x7f), 0)) /* 127 or 255 */
            return (const char *)s+i;
    }
    return NULL;
}

__attribute_nonnull__()
__attribute_pure__
static const char * http_request_check_line_strict (const char * const restrict s, const uint_fast32_t len) {
    for (uint_fast32_t i = 0; i < len; ++i) {
        if (__builtin_expect( (((const uint8_t *)s)[i]<32), 0) && s[i] != '\t')
            return s+i;
        if (__builtin_expect( (s[i] == 127), 0))
            return s+i;
    }
    return NULL;
}

__attribute_nonnull__()
__attribute_pure__
static const char * http_request_check_line_minimal (const char * const restrict s, const uint_fast32_t len) {
    for (uint_fast32_t i = 0; i < len; ++i) {
        if (__builtin_expect( (s[i] == '\0'), 0)) return s+i;
        if (__builtin_expect( (s[i] == '\r'), 0)) return s+i;
        if (__builtin_expect( (s[i] == '\n'), 0)) return s+i;
    }
    return NULL;
}

__attribute_nonnull__()
__attribute_pure__
const char * http_request_field_check_value (const char * const restrict v, const uint32_t vlen, const unsigned int http_header_strict) {
    return (http_header_strict)
      ? http_request_check_line_strict(v, vlen)
      : http_request_check_line_minimal(v, vlen);
}

static int request_check_hostname(buffer * const host) {
    /*
     *       hostport      = host [ ":" port ]
     *       host          = hostname | IPv4address | IPv6address
     *       hostname      = *( domainlabel "." ) toplabel [ "." ]
     *       domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
     *       toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
     *       IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
     *       IPv6address   = "[" ... "]"
     *       port          = *digit
     */

    const char *h = host->ptr;

    if (*h != '[') {
        uint32_t len = buffer_clen(host);
        const char * const colon = memchr(h, ':', len);
        uint32_t hlen = colon ? (uint32_t)(colon - h) : len;

        /* if hostname ends in ".", strip it */
        if (__builtin_expect( (0 == hlen), 0)) return -1;
        if (__builtin_expect( (h[hlen-1] == '.'), 0)) {
            /* shift port info one left */
            if (--hlen == 0) return -1;
            --len;
            if (NULL != colon)
                memmove(host->ptr+hlen, colon, len - hlen);
            buffer_truncate(host, len);
        }

        int label_len = 0;
        int allnumeric = 1;
        int numeric = 1;
        int level = 0;
        for (uint32_t i = 0; i < hlen; ++i) {
            const int ch = h[i];
            ++label_len;
            if (light_isdigit(ch))
                continue;
            else if ((light_isalpha(ch) || (ch == '-' && i != 0)))
                numeric = 0;
            else if (ch == '.' && 1 != label_len && '-' != h[i+1]) {
                allnumeric &= numeric;
                numeric = 1;
                label_len = 0;
                ++level;
            }
            else
                return -1;
        }
        /* (if last segment numeric, then IPv4 and must have 4 numeric parts) */
        if (0 == label_len || (numeric && (level != 3 || !allnumeric)))
            return -1;

        h += hlen;
    }
    else {  /* IPv6 address */
        /* check the address inside [...]; note: not fully validating */
        /* (note: not allowing scoped literals, e.g. %eth0 suffix) */
        ++h; /* step past '[' */
        int cnt = 0;
        while (light_isxdigit(*h) || *h == '.' || (*h == ':' && ++cnt < 8)) ++h;
        /*(invalid char, too many ':', missing ']', or empty "[]")*/
        if (*h != ']' || h - host->ptr == 1) return -1;
        ++h; /* step past ']' */
    }

    /* check numerical port, if present */
    if (*h == ':') {
        if (__builtin_expect( (h[1] == '\0'), 0)) /*(remove trailing colon)*/
            buffer_truncate(host, h - host->ptr);
        do { ++h; } while (light_isdigit(*h));
    }

    return (*h == '\0') ? 0 : -1;
}

int http_request_host_normalize(buffer * const b, const int scheme_port) {
    /*
     * check for and canonicalize numeric IP address and portnum (optional)
     * (IP address may be followed by ":portnum" (optional))
     * - IPv6: "[...]"
     * - IPv4: "x.x.x.x"
     * - IPv4: 12345678   (32-bit decimal number)
     * - IPv4: 012345678  (32-bit octal number)
     * - IPv4: 0x12345678 (32-bit hex number)
     *
     * allow any chars (except ':' and '\0' and stray '[' or ']')
     *   (other code may check chars more strictly or more pedantically)
     * ':'  delimits (optional) port at end of string
     * "[]" wraps IPv6 address literal
     * '\0' should have been rejected earlier were it present
     *
     * any chars includes, but is not limited to:
     * - allow '-' any where, even at beginning of word
     *     (security caution: might be confused for cmd flag if passed to shell)
     * - allow all-digit TLDs
     *     (might be mistaken for IPv4 addr by inet_aton()
     *      unless non-digits appear in subdomain)
     */

    /* Note: not using getaddrinfo() since it does not support "[]" around IPv6
     * and is not as lenient as inet_aton() and inet_addr() for IPv4 strings.
     * Not using inet_pton() (when available) on IPv4 for similar reasons. */

    const char * const p = b->ptr;
    const size_t blen = buffer_clen(b);
    long port = 0;

    if (*p != '[') {
        char * const colon = (char *)memchr(p, ':', blen);
        if (colon) {
            if (*p == ':') return -1; /*(empty host then port, or naked IPv6)*/
            if (colon[1] != '\0') {
                char *e;
                port = strtol(colon+1, &e, 0); /*(allow decimal, octal, hex)*/
                if (0 < port && port <= (long)USHRT_MAX && *e == '\0') {
                    /* valid port */
                } else {
                    return -1;
                }
            } /*(else ignore stray colon at string end)*/
            buffer_truncate(b, (size_t)(colon - p)); /*(remove port str)*/
        }

        if (light_isdigit(*p)) do {
            /* (IPv4 address literal or domain starting w/ digit (e.g. 3com))*/
            /* (check one-element cache of normalized IPv4 address string) */
            static struct { char s[INET_ADDRSTRLEN]; size_t n; } laddr;
            size_t n = colon ? (size_t)(colon - p) : blen;
            sock_addr addr;
            if (n == laddr.n && 0 == memcmp(p, laddr.s, n)) break;
            if (1 == sock_addr_inet_pton(&addr, p, AF_INET, 0)) {
                sock_addr_inet_ntop_copy_buffer(b, &addr);
                n = buffer_clen(b);
                if (n < sizeof(laddr.s)) memcpy(laddr.s, b->ptr, (laddr.n = n));
            }
        } while (0);
    } else do { /* IPv6 addr */
      #if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)

        /* (check one-element cache of normalized IPv4 address string) */
        static struct { char s[INET6_ADDRSTRLEN]; size_t n; } laddr;
        sock_addr addr;
        char *bracket = b->ptr+blen-1;
        char *percent = strchr(b->ptr+1, '%');
        size_t len;
        int rc;
        char buf[INET6_ADDRSTRLEN+16]; /*(+16 for potential %interface name)*/
        if (blen <= 2) return -1; /*(invalid "[]")*/
        if (*bracket != ']') {
            bracket = (char *)memchr(b->ptr+1, ']', blen-1);
            if (NULL == bracket || bracket[1] != ':'  || bracket - b->ptr == 1){
               return -1;
            }
            if (bracket[2] != '\0') { /*(ignore stray colon at string end)*/
                char *e;
                port = strtol(bracket+2, &e, 0); /*(allow decimal, octal, hex)*/
                if (0 < port && port <= (long)USHRT_MAX && *e == '\0') {
                    /* valid port */
                } else {
                    return -1;
                }
            }
        }

        len = (size_t)((percent ? percent : bracket) - (b->ptr+1));
        if (laddr.n == len && 0 == memcmp(laddr.s, b->ptr+1, len)) {
            /* truncate after ']' and re-add normalized port, if needed */
            buffer_truncate(b, (size_t)(bracket - b->ptr + 1));
            break;
        }

        *bracket = '\0';/*(terminate IPv6 string)*/
        if (percent) *percent = '\0'; /*(remove %interface from address)*/
        rc = sock_addr_inet_pton(&addr, b->ptr+1, AF_INET6, 0);
        if (percent) *percent = '%'; /*(restore %interface)*/
        *bracket = ']'; /*(restore bracket)*/
        if (1 != rc) return -1;

        sock_addr_inet_ntop(&addr, buf, sizeof(buf));
        len = strlen(buf);
        if (percent) {
            if (percent > bracket) return -1;
            if (len + (size_t)(bracket - percent) >= sizeof(buf)) return -1;
            if (len < sizeof(laddr.s)) memcpy(laddr.s, buf, (laddr.n = len));
            memcpy(buf+len, percent, (size_t)(bracket - percent));
            len += (size_t)(bracket - percent);
        }
        buffer_truncate(b, 1); /* truncate after '[' */
        buffer_append_str2(b, buf, len, CONST_STR_LEN("]"));

      #else

        return -1;

      #endif
    } while (0);

    if (0 != port && port != scheme_port) {
        buffer_append_char(b, ':');
        buffer_append_int(b, (int)port);
    }

    return 0;
}

int http_request_host_policy (buffer * const b, const unsigned int http_parseopts, const int scheme_port) {
    /* caller should lowercase, as is done in http_request_header_set_Host(),
     * for consistency in case the value is used prior to calling policy func */
    /*buffer_to_lower(b);*/
    return (((http_parseopts & HTTP_PARSEOPT_HOST_STRICT)
               ? 0 != request_check_hostname(b)
               : NULL != http_request_check_line_minimal(BUF_PTR_LEN(b)))
            || ((http_parseopts & HTTP_PARSEOPT_HOST_NORMALIZE)
                && 0 != http_request_host_normalize(b, scheme_port)));
}

__attribute_cold__
__attribute_noinline__
static int http_request_header_line_invalid(request_st * const restrict r, const int status, const char * const restrict msg) {
    if (r->conf.log_request_header_on_error) {
        if (msg) log_debug(r->conf.errh, __FILE__, __LINE__, "%s", msg);
    }
    return status;
}

__attribute_cold__
__attribute_noinline__
static int http_request_header_char_invalid(request_st * const restrict r, const char ch, const char * const restrict msg) {
    if (r->conf.log_request_header_on_error) {
        if ((unsigned char)ch > 32 && ch != 127) {
            log_debug(r->conf.errh, __FILE__, __LINE__, "%s ('%c')", msg, ch);
        }
        else {
            log_debug(r->conf.errh, __FILE__, __LINE__, "%s (0x%x)", msg, ch);
        }
    }
    return 400;
}


__attribute_noinline__
static void http_request_header_set_Host(request_st * const restrict r, const char * const h, size_t hlen)
{
    r->http_host = http_header_request_set_ptr(r, HTTP_HEADER_HOST,
                                               CONST_STR_LEN("Host"));
    buffer_copy_string_len_lc(r->http_host, h, hlen);
}


int64_t
li_restricted_strtoint64 (const char *v, const uint32_t vlen, const char ** const err)
{
    /* base 10 strtoll() parsing exactly vlen chars and requiring digits 0-9 */
    /* rejects negative numbers and considers values > INT64_MAX an error */
    /* note: errno is not set; detect error if *err != v+vlen upon return */
    /*(caller must check 0 == vlen if that is to be an error for caller)*/
    int64_t rv = 0;
    uint32_t i;
    for (i = 0; i < vlen; ++i) {
        const uint8_t c = ((uint8_t *)v)[i] - '0'; /*(unsigned; underflow ok)*/
        if (c > 9) break;
        if (rv > INT64_MAX/10) break;
        rv *= 10;
        if (rv > INT64_MAX - c) break;
        rv += c;
    }
    *err = v+i;
    return rv;
}


__attribute_cold__
static int http_request_parse_duplicate(request_st * const restrict r, const enum http_header_e id, const char * const restrict k, const size_t klen, const char * const restrict v, const size_t vlen) {
    /* Proxies sometimes send dup headers
     * if they are the same we ignore the second
     * if not, we raise an error */
    const buffer * const vb = http_header_request_get(r, id, k, klen);
    if (vb && buffer_eq_icase_slen(vb, v, vlen))
        return 0; /* ignore header; matches existing header */

    const char *errmsg;
    switch (id) {
      case HTTP_HEADER_HOST:
        errmsg = "duplicate Host header -> 400";
        break;
      case HTTP_HEADER_CONTENT_TYPE:
        errmsg = "duplicate Content-Type header -> 400";
        break;
      case HTTP_HEADER_IF_MODIFIED_SINCE:
        errmsg = "duplicate If-Modified-Since header -> 400";
        break;
      case HTTP_HEADER_HTTP2_SETTINGS:
        errmsg = "duplicate HTTP2-Settings header -> 400";
        break;
      default:
        errmsg = "duplicate header -> 400";
        break;
      case HTTP_HEADER_IF_NONE_MATCH:
        /* if dup, only the first one will survive */
        return 0; /* ignore header */
    }
    return http_request_header_line_invalid(r, 400, errmsg);
}


/* add header to list of headers
 * certain headers are also parsed
 * might drop a header if deemed unnecessary/broken
 *
 * returns 0 on success, HTTP status on error
 */
static int http_request_parse_single_header(request_st * const restrict r, const enum http_header_e id, const char * const restrict k, const size_t klen, const char * const restrict v, const size_t vlen) {
    /*
     * Note: k might not be '\0'-terminated
     * Note: v is not '\0'-terminated
     *   With lighttpd HTTP/1.1 parser, v ends with whitespace
     *     (one of '\r' '\n' ' ' '\t')
     *   With lighttpd HTTP/2 parser, v should not be accessed beyond vlen
     *     (care must be taken to avoid libc funcs which expect z-strings)
     */
    /*assert(vlen);*//*(caller must not call this func with 0 klen or 0 vlen)*/

    switch (id) {
      /*case HTTP_HEADER_OTHER:*/
      default:
        break;
      case HTTP_HEADER_HOST:
        if (!light_btst(r->rqst_htags, HTTP_HEADER_HOST)) {
            if (vlen >= 1024) { /*(expecting < 256)*/
                return http_request_header_line_invalid(r, 400, "uri-authority too long -> 400");
            }
            /*(http_request_header_append() plus sets r->http_host)*/
            http_request_header_set_Host(r, v, vlen);
            return 0;
        }
        else if (NULL != r->http_host
                 && __builtin_expect( buffer_eq_slen(r->http_host,v,vlen), 1)) {
            /* ignore all Host: headers if match authority in request line */
            /* (expect Host to match case in :authority of HTTP/2 request) */
            return 0; /* ignore header */
        }
        /* else parse duplicate for match or error */
        __attribute_fallthrough__
      case HTTP_HEADER_IF_MODIFIED_SINCE:
      case HTTP_HEADER_IF_NONE_MATCH:
      case HTTP_HEADER_CONTENT_TYPE:
      case HTTP_HEADER_HTTP2_SETTINGS:
        if (light_btst(r->rqst_htags, id))
            return http_request_parse_duplicate(r, id, k, klen, v, vlen);
        break;
      case HTTP_HEADER_CONNECTION:
        if (HTTP_VERSION_1_1 < r->http_version)
            return http_request_header_line_invalid(r, 400,
              "invalid Connection header with HTTP/2 or later -> 400");
        /* "Connection: close" is common case if header is present */
        if ((vlen == 5 && buffer_eq_icase_ssn(v, CONST_STR_LEN("close")))
            || http_header_str_contains_token(v,vlen,CONST_STR_LEN("close"))) {
            r->keep_alive = 0;
            break;
        }
        if (http_header_str_contains_token(v,vlen,CONST_STR_LEN("keep-alive"))){
            r->keep_alive = 1;
            break;
        }
        break;
      case HTTP_HEADER_CONTENT_LENGTH:
        if (!light_btst(r->rqst_htags, HTTP_HEADER_CONTENT_LENGTH)) {
            /*(trailing whitespace was removed from vlen)*/
            /*(not using strtoll() since v might not be z-string)*/
            const char *err;
            off_t clen = (off_t)li_restricted_strtoint64(v, vlen, &err);
            if (err == v+vlen) {
                /* (set only if not set to -1 by Transfer-Encoding: chunked) */
                if (r->http_version > HTTP_VERSION_1_1 || 0==r->reqbody_length)
                    r->reqbody_length = clen;
            }
            else {
                return http_request_header_line_invalid(r, 400, "invalid Content-Length header -> 400");
            }
        }
        else {
            return http_request_header_line_invalid(r, 400, "duplicate Content-Length header -> 400");
        }
        break;
      case HTTP_HEADER_TRANSFER_ENCODING:
        if (HTTP_VERSION_1_1 != r->http_version) {
            /* RFC9112 HTTP/1.1 Section 6.1. Transfer-Encoding
             * https://httpwg.org/specs/rfc9112.html#rfc.section.6.1.p.16
             * A server or client that receives an HTTP/1.0 message containing a
             * Transfer-Encoding header field MUST treat the message as if the
             * framing is faulty, even if a Content-Length is present, and close
             * the connection after processing the message. */
            r->keep_alive = 0;
            return http_request_header_line_invalid(r, 400,
              HTTP_VERSION_1_0 == r->http_version
                ? "HTTP/1.0 with Transfer-Encoding (bad HTTP/1.0 proxy?) -> 400"
                : "HTTP/2 with Transfer-Encoding is invalid -> 400");
        }

        if (!buffer_eq_icase_ss(v, vlen, CONST_STR_LEN("chunked"))) {
            /* Transfer-Encoding might contain additional encodings,
             * which are not currently supported by lighttpd */
            return http_request_header_line_invalid(r, 501, NULL); /* Not Implemented */
        }
        r->reqbody_length = -1;

        /* Transfer-Encoding is a hop-by-hop header,
         * which must not be blindly forwarded to backends */
        return 0; /* skip header */
    }

    http_header_request_append(r, id, k, klen, v, vlen);
    return 0;
}


__attribute_cold__
__attribute_noinline__
static int http_request_parse_single_trailer(request_st * const restrict r, const enum http_header_e id, const char * const restrict k, const size_t klen, const char * const restrict v, const size_t vlen) {
    /* (for HTTP/2) */

    if (0 == (r->conf.stream_request_body
              & (FDEVENT_STREAM_REQUEST | FDEVENT_STREAM_REQUEST_BUFMIN))) {
        /* (HTTP/2 version of src/h1.c:h1_chunked_trailers()) */
        /* RFC9110 https://www.rfc-editor.org/rfc/rfc9110.html
         * Section B.2. "Changes from RFC 7230" encourages implementations
         * to avoid merging trailers into headers if the implementation
         * does not have full knowledge of each field permitting merge and
         * defining how to merge.  ... In other words, merging to headers is
         * discouraged.  This code might move in that direction in the future,
         * though de-chunking (and either merging or dropping trailers) is
         * necessary for non-HTTP backends (e.g. FastCGI, SCGI, AJP13, etc which
         * do not support trailers in their protocols).
         * RFC9110 mentions only a few fields explicitly allowed in trailers:
         * ETag, Authentication-Info, Proxy-Authentication-Info, Accept-Ranges
         */
        http_trailer_parse_ctx tpctx;
        tpctx.k    = k;
        tpctx.v    = v;
        tpctx.klen = klen;
        tpctx.vlen = vlen;
        tpctx.max_request_field_size = r->conf.max_request_field_size;
        tpctx.hlen = 0;
        tpctx.http_header_strict =
          (r->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);
        tpctx.id = id;
        tpctx.trailer = http_header_request_get(r, HTTP_HEADER_OTHER,
                                                CONST_STR_LEN("Trailer"));
        int rc = http_request_trailer_check(r, &tpctx);
        if (0 != rc)
            return rc;
        /* note: Trailer header (if set) is left set as info for backends.
         * To remove Trailer, would have to check for trailer merging into
         * headers after all trailers processed */
        if (http_request_trailer_check_whitelist(k, klen))
            http_header_request_append(r, id, k, klen, v, vlen);
    }
    else {
        /* trailers currently ignored if streaming request,
         * but (future) could be set aside here if handler is mod_proxy
         * and mod_proxy is sending chunked request to backend */
      #if 0 /*(similar to http_header_env_append() but adds lines, not tokens)*/
        buffer * const vb =
          array_get_buf_ptr(&r->env, CONST_STR_LEN("_L_TRAILERS"));
        buffer_append_str2(vb, k, klen, CONST_STR_LEN(": "));
        buffer_append_str2(vb, v, vlen, CONST_STR_LEN("\r\n"));
      #endif
    }

    return 0;
}


__attribute_cold__
__attribute_noinline__
static const char * http_request_parse_reqline_uri(request_st * const restrict r, const char * const restrict uri, const size_t len, const unsigned int http_parseopts) {
    const char *nuri;
    if ((len > 7 && buffer_eq_icase_ssn(uri, "http://", 7)
        && NULL != (nuri = memchr(uri + 7, '/', len-7)))
       ||
       (len > 8 && buffer_eq_icase_ssn(uri, "https://", 8)
        && NULL != (nuri = memchr(uri + 8, '/', len-8)))) {
        const char * const host = uri + (uri[4] == ':' ? 7 : 8);
        const size_t hostlen = nuri - host;
        if (0 == hostlen || hostlen >= 1024) { /*(expecting < 256)*/
            http_request_header_line_invalid(r, 400, "uri-authority empty or too long -> 400");
            return NULL;
        }
        /* Insert as "Host" header */
        http_request_header_set_Host(r, host, hostlen);
        return nuri;
    } else if (!(http_parseopts & HTTP_PARSEOPT_HEADER_STRICT) /*(!http_header_strict)*/
           || (HTTP_METHOD_CONNECT == r->http_method && (uri[0] == ':' || light_isdigit(uri[0])))
           || (HTTP_METHOD_OPTIONS == r->http_method && uri[0] == '*' && 1 == len)) {
        /* (permitted) */
        return uri;
    } else {
        http_request_header_line_invalid(r, 400, "request-URI parse error -> 400");
        return NULL;
    }
}


__attribute_cold__
__attribute_nonnull__()
__attribute_pure__
static const char * http_request_field_check_name_h2(const char * const restrict k, const int_fast32_t klen, const unsigned int http_header_strict);


int
http_request_validate_pseudohdrs (request_st * const restrict r, const int scheme, const unsigned int http_parseopts)
{
    /* :method is required to indicate method
     * CONNECT method must have :method and :authority
     *   unless RFC8441 CONNECT extension, which must follow 'other' (below)
     * All other methods must have at least :method :scheme :path */

    if (HTTP_METHOD_UNSET == r->http_method)
        return http_request_header_line_invalid(r, 400,
          "missing pseudo-header method -> 400");

    /* ignore :protocol unless :method is CONNECT
     * (:protocol may have been received prior to :method, so check here) */
    if (HTTP_METHOD_CONNECT != r->http_method)
        r->h2_connect_ext = 0;

    if (__builtin_expect( (HTTP_METHOD_CONNECT != r->http_method), 1)
        || __builtin_expect( (r->h2_connect_ext != 0), 0)) {

        if (!scheme)
            return http_request_header_line_invalid(r, 400,
              "missing pseudo-header scheme -> 400");

        if (buffer_is_blank(&r->target))
            return http_request_header_line_invalid(r, 400,
              "missing pseudo-header path -> 400");

        const char * const uri = r->target.ptr;
        if (*uri != '/') { /* (common case: (*uri == '/')) */
            if (uri[0] != '*' || uri[1] != '\0'
                || HTTP_METHOD_OPTIONS != r->http_method)
                return http_request_header_line_invalid(r, 400,
                  "invalid pseudo-header path -> 400");
        }
    }
    else { /* HTTP_METHOD_CONNECT */
        if (NULL == r->http_host)
            return http_request_header_line_invalid(r, 400,
              "missing pseudo-header authority -> 400");
        if (!buffer_is_blank(&r->target) || scheme)
            return http_request_header_line_invalid(r, 400,
              "invalid pseudo-header with CONNECT -> 400");
        /* note: this copy occurs prior to http_request_host_policy()
         * so any consumer handling CONNECT should normalize r->target
         * as appropriate */
        buffer_copy_buffer(&r->target, r->http_host);
    }
    buffer_copy_buffer(&r->target_orig, &r->target);

    /* r->http_host, if set, is checked with http_request_host_policy()
     * in http_request_parse() */

    /* copied and modified from end of http_request_parse_reqline() */

    /* check uri for invalid characters */
    const uint32_t len = buffer_clen(&r->target);/*(http_header_strict)*/
    const char * const x = (http_parseopts & HTTP_PARSEOPT_HEADER_STRICT)
      ? (http_parseopts & HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT)
          ? NULL /* URI will be checked in http_request_parse_target() */
          : http_request_check_uri_strict((const uint8_t *)r->target.ptr, len)
      : http_request_check_line_minimal(r->target.ptr, len);
    return (NULL == x)
      ? 0
      : http_request_header_char_invalid(r, *x,
          "invalid character in URI -> 400");
}


int
http_request_parse_header (request_st * const restrict r, http_header_parse_ctx * const restrict hpctx)
{
    /* Note: k and v might not be '\0' terminated strings;
     * care must be taken to avoid libc funcs which expect z-strings */
    const char * const restrict k = hpctx->k;
    const char * restrict v = hpctx->v;
    const uint32_t klen = hpctx->klen;
    uint32_t vlen = hpctx->vlen;

    if (0 == klen)
        return http_request_header_line_invalid(r, 400,
          "invalid header key -> 400");

    if ((hpctx->hlen += klen + vlen + 4) > hpctx->max_request_field_size) {
        /*(configurable with server.max-request-field-size; default 8k)*/
      #if 1 /* emit to error log for people sending large headers */
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "oversized request header -> 431");
        return 431; /* Request Header Fields Too Large */
      #else
        /* 431 Request Header Fields Too Large */
        return http_request_header_line_invalid(r, 431,
          "oversized request header -> 431");
      #endif
    }

    {
        if (*k == ':') {
            /* HTTP/2 request pseudo-header fields */
            if (!hpctx->pseudo) /*(pseudo header after non-pseudo header)*/
                return http_request_header_line_invalid(r, 400,
                  "invalid pseudo-header -> 400");
            if (0 == vlen)
                return http_request_header_line_invalid(r, 400,
                  "invalid header value -> 400");

            /* (note: relies on implementation details using ls-hpack in h2.c)
             * (hpctx->id mapped from lsxpack_header_t hpack_index, which only
             *  matches key, not also value, if lsxpack_header_t flags does not
             *  have LSXPACK_HPACK_VAL_MATCHED set, so HTTP_HEADER_H2_METHOD
             *  below indicates any method, not only "GET") */
            if (__builtin_expect( (hpctx->id == HTTP_HEADER_H2_UNKNOWN), 0)) {
                switch (klen-1) {
                  case 4:
                    if (0 == memcmp(k+1, "path", 4))
                        hpctx->id = HTTP_HEADER_H2_PATH;
                    break;
                  case 6:
                    if (0 == memcmp(k+1, "method", 6))
                        hpctx->id = HTTP_HEADER_H2_METHOD;
                    else if (0 == memcmp(k+1, "scheme", 6))
                        hpctx->id = HTTP_HEADER_H2_SCHEME;
                    break;
                  case 8:
                    if (0 == memcmp(k+1, "protocol", 8))
                        hpctx->id = HTTP_HEADER_H2_PROTOCOL;
                    break;
                  case 9:
                    if (0 == memcmp(k+1, "authority", 9))
                        hpctx->id = HTTP_HEADER_H2_AUTHORITY;
                    break;
                  default:
                    break;
                }
                if (hpctx->id >= HTTP_HEADER_H2_UNKNOWN)
                    return http_request_header_line_invalid(r, 400,
                      "invalid pseudo-header -> 400");
            }

            switch (hpctx->id) {
              case HTTP_HEADER_H2_AUTHORITY:
                if (__builtin_expect( (r->http_host != NULL), 0))
                    break;
                if (vlen >= 1024) /*(expecting < 256)*/
                    return http_request_header_line_invalid(r, 400,
                      "invalid pseudo-header authority too long -> 400");
                /* insert as "Host" header */
                http_request_header_set_Host(r, v, vlen);
                return 0;
              case HTTP_HEADER_H2_METHOD:
                if (__builtin_expect( (HTTP_METHOD_UNSET != r->http_method), 0))
                    break;
                r->http_method = http_method_key_get(v, vlen);
                if (HTTP_METHOD_UNSET >= r->http_method)
                    return http_request_header_line_invalid(r, 501,
                      "unknown http-method -> 501");
                return 0;
              case HTTP_HEADER_H2_PATH:
                if (__builtin_expect( (!buffer_is_blank(&r->target)), 0))
                    break;
                buffer_copy_string_len(&r->target, v, vlen);
                return 0;
              case HTTP_HEADER_H2_SCHEME:
                if (__builtin_expect( (hpctx->scheme), 0))
                    break;
                hpctx->scheme = 1; /*(marked present, but otherwise ignored)*/
                return 0;
               #if 0
                switch (vlen) {/*(validated, but then ignored)*/
                  case 5: /* "https" */
                    if (v[4]!='s') break;
                    __attribute_fallthrough__
                  case 4: /* "http" */
                    if (v[0]=='h' && v[1]=='t' && v[2]=='t' && v[3]=='p') {
                        hpctx->scheme = 1;
                        return 0;
                    }
                    break;
                  default:
                    break;
                }
                return http_request_header_line_invalid(r, 400,
                  "unknown pseudo-header scheme -> 400");
               #endif
              case HTTP_HEADER_H2_PROTOCOL:
                /* support only ":protocol: websocket" for now */
                if (vlen != 9 || 0 != memcmp(v, "websocket", 9))
                    return http_request_header_line_invalid(r, 405,
                      "unhandled :protocol value -> 405");
                /*(future: might be enum of recognized :protocol: ext values)*/
                r->h2_connect_ext = 1;
                return 0;
              default:
                return http_request_header_line_invalid(r, 400,
                  "invalid pseudo-header -> 400");
            }
            return http_request_header_line_invalid(r, 400,
              "repeated pseudo-header -> 400");
        }
        else { /*(non-pseudo headers)*/
            if (hpctx->pseudo) { /*(transition to non-pseudo headers)*/
                hpctx->pseudo = 0;
                int status =
                  http_request_validate_pseudohdrs(r, hpctx->scheme,
                                                   hpctx->http_parseopts);
                if (0 != status) return status;
            }
            if (0 == vlen)
                return 0;

            const unsigned int http_header_strict =
              (hpctx->http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);

            const char * const x =
              http_request_field_check_value(v, vlen, http_header_strict);
            if (x)
                return http_request_header_char_invalid(r, *x,
                  "invalid character in header -> 400");

            /* remove leading and trailing whitespace (strict RFC conformance)*/
            if (__builtin_expect( (*v <= 0x20), 0)) {
                while ((*v == ' ' || *v == '\t') && (++v, --vlen)) ;
                if (0 == vlen)
                    return 0;
            }
            if (__builtin_expect( (v[vlen-1] <= 0x20), 0)) {
                while (v[vlen-1] == ' ' || v[vlen-1] == '\t') --vlen;
            }

            if (__builtin_expect( (hpctx->id == HTTP_HEADER_H2_UNKNOWN), 0)) {
                hpctx->id = http_header_hkey_get_lc(k, klen);
            }

            if (hpctx->id == HTTP_HEADER_OTHER) {
                const char * const xx =
                  http_request_field_check_name_h2(k, (int)klen,
                                                   http_header_strict);
                if (xx)
                    return http_request_header_char_invalid(r, *xx,
                      "invalid character in header key -> 400");
            }

            const enum http_header_e id = (enum http_header_e)hpctx->id;

            if (__builtin_expect( (id == HTTP_HEADER_TE), 0)
                && !buffer_eq_icase_ss(v, vlen, CONST_STR_LEN("trailers")))
                return http_request_header_line_invalid(r, 400,
                  "invalid TE header value with HTTP/2 -> 400");

            return !hpctx->trailers
              ? http_request_parse_single_header(r, id, k, klen, v, vlen)
              : http_request_parse_single_trailer(r, id, k, klen, v, vlen);
        }
    }

  #if 0 /* (old comments from when this block handled 'if (hpctx->trailers)') */
    else { /*(trailers)*/
        if (*k == ':')
            return http_request_header_line_invalid(r, 400,
              "invalid pseudo-header in trailers -> 400");
        /* ignore trailers (after required HPACK decoding) if streaming
         * request body to backend since headers have already been sent
         * to backend via Common Gateway Interface (CGI) (CGI, FastCGI,
         * SCGI, etc) or HTTP/1.1 (proxy) (mod_proxy does not currently
         * support using HTTP/2 to connect to backends) */
      #if 0 /* (if needed, save flag in hpctx instead of fdevent.h dependency)*/
        if (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
            return 0;
      #endif
        /* Note: do not unconditionally merge into headers since if
         * headers had already been sent to backend, then mod_accesslog
         * logging of request headers might be inaccurate.
         * Many simple backends do not support HTTP/1.1 requests sending
         * Transfer-Encoding: chunked, and even those that do might not
         * handle trailers.  Some backends do not even support HTTP/1.1.
         * For all these reasons, ignore trailers if streaming request
         * body to backend.  Revisit in future if adding support for
         * connecting to backends using HTTP/2 (with explicit config
         * option to force connecting to backends using HTTP/2) */

        /* XXX: TODO: request trailers not handled if streaming reqbody
         * XXX: must ensure that trailers are not disallowed field-names
         */

      #if 0
        if (0 == vlen)
            return 0;
      #endif

        return 0;
    }
  #endif
}


static int http_request_parse_reqline(request_st * const restrict r, const char * const restrict ptr, const unsigned short * const restrict hoff, const unsigned int http_parseopts) {
    size_t len = hoff[2];

    /* parse the first line of the request
     * <method> <uri> <protocol>\r\n
     * */
    if (len < 13) /* minimum len with (!http_header_strict): "x x HTTP/1.0\n" */
        return http_request_header_line_invalid(r, 400, "invalid request line (too short) -> 400");
    if (ptr[len-2] == '\r')
        len-=2;
    else if (!(http_parseopts & HTTP_PARSEOPT_HEADER_STRICT)) /*(!http_header_strict)*/
        len-=1;
    else
        return http_request_header_line_invalid(r, 400, "missing CR before LF in header -> 400");

    /*
     * RFC7230:
     *   HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
     *   HTTP-name     = %x48.54.54.50 ; "HTTP", case-sensitive
     */

    /* protocol is expected to be " HTTP/1.1" or " HTTP/1.0" at end of line */
    union proto_un {
      char c[8];
      uint64_t u;
    };
    static const union proto_un http_1_1 = {{'H','T','T','P','/','1','.','1'}};
    static const union proto_un http_1_0 = {{'H','T','T','P','/','1','.','0'}};
    const char *p = ptr + len - 8;
    union proto_un proto8;
    proto8.c[0]=p[0]; proto8.c[1]=p[1]; proto8.c[2]=p[2]; proto8.c[3]=p[3];
    proto8.c[4]=p[4]; proto8.c[5]=p[5]; proto8.c[6]=p[6]; proto8.c[7]=p[7];
    if (p[-1] == ' ' && http_1_1.u == proto8.u) {
        r->http_version = HTTP_VERSION_1_1;
        r->keep_alive = 1; /* keep-alive default: HTTP/1.1 -> true */
    }
    else if (p[-1] == ' ' && http_1_0.u == proto8.u) {
        r->http_version = HTTP_VERSION_1_0;
        r->keep_alive = 0; /* keep-alive default: HTTP/1.0 -> false */
    }
  #if 0 /*(pedantic: "HTTP/???")*/
    else if (p[-1] == ' ' && (http_1_0.u >> 24) == (proto8.u >> 24))
        return http_request_header_line_invalid(r, 505, "unknown HTTP version -> 505");
  #endif
    else
        return http_request_header_line_invalid(r, 400, "unknown protocol -> 400");
    if (p[-2] == ' ')
        return http_request_header_line_invalid(r, 400, "invalid request line (separators) -> 400");

    /* method is expected to be a short string in the general case */
    size_t i = 0;
    while (ptr[i] != ' ') ++i;
    /*(space must exist if protocol was parsed successfully)*/

    r->http_method = http_method_key_get(ptr, i);
    if (HTTP_METHOD_UNSET >= r->http_method)
        return http_request_header_line_invalid(r, 501, "unknown http-method -> 501");

    const char *uri = ptr + i + 1;

    if (uri == p)
        return http_request_header_line_invalid(r, 400, "no uri specified -> 400");
    len = (size_t)(p - uri - 1);

    if (*uri != '/') { /* (common case: (*uri == '/')) */
        uri = http_request_parse_reqline_uri(r, uri, len, http_parseopts);
        if (NULL == uri) return 400;
        len = (size_t)(p - uri - 1);
    }

    if (0 == len)
        return http_request_header_line_invalid(r, 400, "no uri specified -> 400");

    /* check uri for invalid characters */     /* http_header_strict */
    const char * const x = (http_parseopts & HTTP_PARSEOPT_HEADER_STRICT)
      ? (http_parseopts & HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT)
          ? NULL /* URI will be checked in http_request_parse_target() */
          : http_request_check_uri_strict((const uint8_t *)uri, len)
      : memchr(ptr, '\0', hoff[hoff[0]]);/* check entire headers set for '\0' */
    if (x)
        return http_request_header_char_invalid(r, *x, "invalid character in URI -> 400");

    buffer_copy_string_len(&r->target, uri, len);
    buffer_copy_string_len(&r->target_orig, uri, len);
    return 0;
}

int http_request_parse_target(request_st * const r, int scheme_port) {
    /* URI is parsed into components at start of request and may
     * also be re-parsed upon HANDLER_COMEBACK during the request
     * r->target is expected to be a "/url-part?query-part"
     *   (and *not* a fully-qualified URI starting https://...)
     * r->uri.authority is expected to be parsed elsewhere into r->http_host
     */

    /**
     * prepare strings
     *
     * - uri.path
     * - uri.query
     *
     */

    /**
     * Name according to RFC 2396
     *
     * - scheme
     * - authority
     * - path
     * - query
     *
     * (scheme)://(authority)(path)?(query)#fragment
     *
     */

    /* take initial scheme value from connection-level state
     * (request r->uri.scheme can be overwritten for later,
     *  for example by mod_extforward or mod_magnet) */
    buffer_copy_string_len(&r->uri.scheme, "https", scheme_port == 443 ? 5 : 4);

    buffer * const target = &r->target;
    if ((r->http_method == HTTP_METHOD_CONNECT && !r->h2_connect_ext)
        || (r->http_method == HTTP_METHOD_OPTIONS
            && target->ptr[0] == '*'
            && target->ptr[1] == '\0')) {
        /* CONNECT ... (or) OPTIONS * ... */
        buffer_copy_buffer(&r->uri.path, target);
        buffer_clear(&r->uri.query);
        return 0;
    }

    char *qstr;
    if (r->conf.http_parseopts & HTTP_PARSEOPT_URL_NORMALIZE) {
        /*uint32_t len = buffer_clen(target);*/
        int qs = burl_normalize(target, r->tmp_buf, r->conf.http_parseopts);
        if (-2 == qs)
            return http_request_header_line_invalid(r, 400,
              "invalid character in URI -> 400"); /* Bad Request */
        qstr = (-1 == qs) ? NULL : target->ptr+qs;
      #if 0  /* future: might enable here, or below for all requests */
        /* (Note: total header size not recalculated on HANDLER_COMEBACK
         *  even if other request headers changed during processing)
         * (If (0 != r->loops_per_request), then the generated
         *  request is too large.  Should a different error be returned?) */
        r->rqst_header_len -= len;
        len = buffer_clen(target);
        r->rqst_header_len += len;
        if (len > MAX_HTTP_REQUEST_URI) {
            return 414; /* 414 URI Too Long */
        }
        if (r->rqst_header_len > MAX_HTTP_REQUEST_HEADER) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "request header fields too large: %u -> 431",
              r->rqst_header_len);
            return 431; /* Request Header Fields Too Large */
        }
      #endif
    }
    else {
        size_t rlen = buffer_clen(target);
        qstr = memchr(target->ptr, '#', rlen);/* discard fragment */
        if (qstr) {
            rlen = (size_t)(qstr - target->ptr);
            buffer_truncate(target, rlen);
        }
        qstr = memchr(target->ptr, '?', rlen);
    }

    /** extract query string from target */
    const char * const pstr = target->ptr;
    const uint32_t rlen = buffer_clen(target);
    uint32_t plen;
    if (NULL != qstr) {
        plen = (uint32_t)(qstr - pstr);
        buffer_copy_string_len(&r->uri.query, qstr + 1, rlen - plen - 1);
    }
    else {
        plen = rlen;
        buffer_clear(&r->uri.query);
    }
    buffer_copy_string_len(&r->uri.path, pstr, plen);

    /* decode url to path
     *
     * - decode url-encodings  (e.g. %20 -> ' ')
     * - remove path-modifiers (e.g. /../)
     */

    buffer_urldecode_path(&r->uri.path);
    buffer_path_simplify(&r->uri.path);
    if (r->uri.path.ptr[0] != '/')
        return http_request_header_line_invalid(r, 400,
          "uri-path does not begin with '/' -> 400"); /* Bad Request */

    return 0;
}

__attribute_cold__
__attribute_pure__
static const char * http_request_parse_header_other(const char * const restrict k, const int klen, const unsigned int http_header_strict) {
    for (int i = 0; i < klen; ++i) {
        if (light_isalpha(k[i]) || k[i] == '-') continue; /*(common cases)*/
        /**
         * 1*<any CHAR except CTLs or separators>
         * CTLs == 0-31 + 127, CHAR = 7-bit ascii (0..127)
         *
         */
        switch(k[i]) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ':':
        case ';':
        case '\\':
        case '\"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
            return k+i;
        default:
            if (http_header_strict ? (k[i] < 32 || ((unsigned char *)k)[i] >= 127) : k[i] == '\0')
                return k+i;
            break; /* ok */
        }
    }
    return NULL;
}

__attribute_nonnull__()
__attribute_pure__
const char * http_request_field_check_name(const char * const restrict k, const int klen, const unsigned int http_header_strict) {
    for (int i = 0; i < klen; ++i) {
        if (light_isalpha(k[i]) || k[i] == '-') continue; /*(common cases)*/
        return http_request_parse_header_other(k+i, klen-i, http_header_strict);
    }
    return NULL;
}

__attribute_cold__
__attribute_nonnull__()
__attribute_pure__
static const char * http_request_field_check_name_h2(const char * const restrict k, const int_fast32_t klen, const unsigned int http_header_strict) {
    int_fast32_t i = 0;
    while ((light_islower(k[i]) || k[i] == '-') && ++i < klen) ;/*common cases*/
    if (__builtin_expect( (i != klen), 0)) {
        const char * const x =
          http_request_parse_header_other(k+i, klen-i, http_header_strict);
        if (x)
            return x;
        do {
            if (light_isupper(k[i])) return k+i;
        } while (++i < klen);
    }
    return NULL;
}

static int http_request_parse_headers(request_st * const restrict r, char * const restrict ptr, const unsigned short * const restrict hoff, const unsigned int http_parseopts) {
    const unsigned int http_header_strict = (http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);

    for (int i = 2; i < hoff[0]; ++i) {
        const char *k = ptr + hoff[i];
        /* one past last line hoff[hoff[0]] is to final "\r\n" */
        char *end = ptr + hoff[i+1];

        const char *colon = memchr(k, ':', end - k);
        if (NULL == colon)
            return http_request_header_line_invalid(r, 400, "invalid header missing ':' -> 400");

        const char *v = colon + 1;

        /* RFC7230 Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing
         * 3.2.4.  Field Parsing
         * [...]
         * No whitespace is allowed between the header field-name and colon.  In
         * the past, differences in the handling of such whitespace have led to
         * security vulnerabilities in request routing and response handling.  A
         * server MUST reject any received request message that contains
         * whitespace between a header field-name and colon with a response code
         * of 400 (Bad Request).  A proxy MUST remove any such whitespace from a
         * response message before forwarding the message downstream.
         */
        /* (line k[-1] is always preceded by a '\n',
         *  including first header after request-line,
         *  so no need to check colon != k) */
        if (colon[-1] == ' ' || colon[-1] == '\t') {
            if (http_header_strict) {
                return http_request_header_line_invalid(r, 400, "invalid whitespace between field-name and colon -> 400");
            }
            else {
                /* remove trailing whitespace from key(if !http_header_strict)*/
                do { --colon; } while (colon[-1] == ' ' || colon[-1] == '\t');
            }
        }

        const int klen = (int)(colon - k);
        if (0 == klen)
            return http_request_header_line_invalid(r, 400, "invalid header key -> 400");
        const enum http_header_e id = http_header_hkey_get(k, klen);

        if (id == HTTP_HEADER_OTHER) {
            const char * const x =
              http_request_field_check_name(k, klen, http_header_strict);
            if (x)
                return http_request_header_char_invalid(r, *x,
                  "invalid character in header key -> 400");
        }

        /* remove leading whitespace from value */
        while (*v == ' ' || *v == '\t') ++v;

      #ifdef __COVERITY__
        /*(buf holding k has non-zero request-line, so end[-2] valid)*/
        force_assert(end >= k + 2);
      #endif
        if (end[-2] == '\r')
            --end;
        else if (http_header_strict)
            return http_request_header_line_invalid(r, 400, "missing CR before LF in header -> 400");
        /* remove trailing whitespace from value (+ remove '\r\n') */
        /* (line k[-1] is always preceded by a '\n',
         *  including first header after request-line,
         *  so no need to check (end != k)) */
        do { --end; } while (end[-1] == ' ' || end[-1] == '\t');

        const int vlen = (int)(end - v);
        if (__builtin_expect( (vlen <= 0), 0)) {
            if (id == HTTP_HEADER_CONTENT_LENGTH)
                return http_request_header_line_invalid(r, 400, "invalid Content-Length header -> 400");
            continue; /* ignore empty header */
        }

        if (http_header_strict) {
            const char * const x = http_request_check_line_strict(v, vlen);
            if (x)
                return http_request_header_char_invalid(r, *x,
                  "invalid character in header -> 400");
        } /* else URI already checked in http_request_parse_reqline() for any '\0' */

        int status = http_request_parse_single_header(r, id, k, (size_t)klen, v, (size_t)vlen);
        if (0 != status) return status;
    }

    /* check that headers end with CRLF blank line ("\r\n" is 2 chars) */
    if (http_header_strict && hoff[hoff[0]+1] - hoff[hoff[0]] != 2)
        return http_request_header_line_invalid(r, 400, "missing CR before LF to end header block -> 400");

    return 0;
}


static int
http_request_parse (request_st * const restrict r, const int scheme_port)
{
    int status = http_request_parse_target(r, scheme_port);
    if (0 != status) return status;

    /* post-processing */
    const unsigned int http_parseopts = r->conf.http_parseopts;

    /* check hostname field if it is set */
    /*(r->http_host might not be set until after parsing request headers)*/
    if (__builtin_expect( (r->http_host != NULL), 1)) {
        if (0 != http_request_host_policy(r->http_host,
                                          http_parseopts, scheme_port))
            return http_request_header_line_invalid(r, 400, "Invalid Hostname -> 400");
        buffer_copy_buffer(&r->uri.authority, r->http_host);
    }
    else {
        buffer_copy_string_len(&r->uri.authority, CONST_STR_LEN(""));
        if (r->http_version >= HTTP_VERSION_1_1)
            return http_request_header_line_invalid(r, 400, "HTTP/1.1 but Host missing -> 400");
    }

    if (HTTP_VERSION_1_1 != r->http_version
        && (r->rqst_htags
            & (light_bshift(HTTP_HEADER_UPGRADE)
              |light_bshift(HTTP_HEADER_HTTP2_SETTINGS)))) {
        return http_request_header_line_invalid(r, 400, "invalid hop-by-hop header w/o HTTP/1.1 -> 400");
    }

    if (0 == r->reqbody_length) {
        /* POST generally expects Content-Length (or Transfer-Encoding)
         * (-1 == r->reqbody_length when Transfer-Encoding: chunked)*/
        if (HTTP_METHOD_POST == r->http_method
            && r->http_version <= HTTP_VERSION_1_1
            && !light_btst(r->rqst_htags, HTTP_HEADER_CONTENT_LENGTH)) {
            return http_request_header_line_invalid(r, 411, "POST-request, but content-length missing -> 411");
        }
    }
    else {
        /* (-1 == r->reqbody_length when Transfer-Encoding: chunked)*/
        if (-1 == r->reqbody_length
            && light_btst(r->rqst_htags, HTTP_HEADER_CONTENT_LENGTH)) {
            /* RFC9112 HTTP/1.1 Section 6.1. Transfer-Encoding
             * https://httpwg.org/specs/rfc9112.html#rfc.section.6.1.p.15
             * A server MAY reject a request that contains both Content-Length
             * and Transfer-Encoding or process such a request in accordance
             * with the Transfer-Encoding alone. Regardless, the server MUST
             * close the connection after responding to such a request to
             * avoid the potential attacks. */
            r->keep_alive = 0;
            /* RFC7230 Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing
             * 3.3.3.  Message Body Length
             * [...]
             * If a message is received with both a Transfer-Encoding and a
             * Content-Length header field, the Transfer-Encoding overrides the
             * Content-Length.  Such a message might indicate an attempt to
             * perform request smuggling (Section 9.5) or response splitting
             * (Section 9.4) and ought to be handled as an error.  A sender MUST
             * remove the received Content-Length field prior to forwarding such
             * a message downstream.
             */
            const unsigned int http_header_strict =
              (http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);
            if (http_header_strict) {
                return http_request_header_line_invalid(r, 400, "invalid Transfer-Encoding + Content-Length -> 400");
            }
            else {
                /* ignore Content-Length */
                http_header_request_unset(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
            }
        }
        if (http_method_get_or_head(r->http_method)
            && !(http_parseopts & HTTP_PARSEOPT_METHOD_GET_BODY)) {
            return http_request_header_line_invalid(r, 400, "GET/HEAD with content-length -> 400");
        }
    }

    return 0;
}


static int
http_request_parse_hoff (request_st * const restrict r, char * const restrict hdrs, const unsigned short * const restrict hoff, const int scheme_port)
{
    /*
     * Request: "^(GET|POST|HEAD|...) ([^ ]+(\\?[^ ]+|)) (HTTP/1\\.[01])$"
     * Header : "^([-a-zA-Z]+): (.+)$"
     * End    : "^$"
     */

    int status;
    const unsigned int http_parseopts = r->conf.http_parseopts;

    status = http_request_parse_reqline(r, hdrs, hoff, http_parseopts);
    if (0 != status) return status;

    status = http_request_parse_headers(r, hdrs, hoff, http_parseopts);
    if (0 != status) return status;

    return http_request_parse(r, scheme_port);
}


static void
http_request_headers_fin (request_st * const restrict r)
{
    if (0 == r->http_status) {
      #if 0
        r->conditional_is_valid = (1 << COMP_SERVER_SOCKET)
                                | (1 << COMP_HTTP_SCHEME)
                                | (1 << COMP_HTTP_HOST)
                                | (1 << COMP_HTTP_REMOTE_IP)
                                | (1 << COMP_HTTP_REQUEST_METHOD)
                                | (1 << COMP_HTTP_URL)
                                | (1 << COMP_HTTP_QUERY_STRING)
                                | (1 << COMP_HTTP_REQUEST_HEADER);
      #else
        /* all config conditions are valid after parsing header
         * (set all bits; remove dependency on plugin_config.h) */
        r->conditional_is_valid = ~0u;
      #endif
    }
    else {
        r->keep_alive = 0;
        r->reqbody_length = 0;
    }
}


void
http_request_headers_process (request_st * const restrict r, char * const restrict hdrs, const unsigned short * const restrict hoff, const int scheme_port)
{
    r->http_status = http_request_parse_hoff(r, hdrs, hoff, scheme_port);

    http_request_headers_fin(r);

    if (__builtin_expect( (0 != r->http_status), 0)) {
        if (r->conf.log_request_header_on_error) {
            /*(http_request_parse_headers() modifies hdrs only to
             * undo line-wrapping in-place using spaces)*/
            log_debug_multiline(r->conf.errh, __FILE__, __LINE__,
                                hdrs, r->rqst_header_len, "rqst: ");
        }
    }
}


void
http_request_headers_process_h2 (request_st * const restrict r, const int scheme_port)
{
    if (0 == r->http_status)
        r->http_status = http_request_parse(r, scheme_port);

    http_request_headers_fin(r);

    /* limited; headers not collected into a single buf for HTTP/2 */
    if (__builtin_expect( (0 != r->http_status), 0)) {
        if (r->conf.log_request_header_on_error) {
            log_debug(r->conf.errh, __FILE__, __LINE__,
              "request-header:\n:authority: %s\n:method: %s\n:path: %s",
              r->http_host ? r->http_host->ptr : "",
              http_method_buf(r->http_method)->ptr,
              !buffer_is_blank(&r->target) ? r->target.ptr : "");
        }
    }

  #if 0 /*(redundant; Upgrade rejected in http_request_parse() if present)*/
    /* ignore Upgrade if using HTTP/2 */
    if (light_btst(r->rqst_htags, HTTP_HEADER_UPGRADE))
        http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                                  CONST_STR_LEN("upgrade"));
  #endif
    /* XXX: should filter out other hop-by-hop connection headers, too */
}


static buffer *trailer_whitelist;


__attribute_cold__
void
http_request_trailer_set_whitelist (buffer *b)
{
    if (buffer_string_is_empty(b))
        b = NULL;
    else if (b->ptr[buffer_clen(b)-1] != ',')
        buffer_append_char(b, ','); /*see http_request_trailer_check_whitelist*/
    trailer_whitelist = b;
}


__attribute_cold__
__attribute_pure__
int
http_request_trailer_check_whitelist (const char *k, const uint32_t klen)
{
    if (!trailer_whitelist) return 0;
    const char *s = trailer_whitelist->ptr;
    for (const char *comma; (comma = strchr(s, ',')); s = comma+1) {
        uint32_t n = (uint32_t)(comma - s);
        if (n == klen && buffer_eq_icase_ssn(k, s, n))
            return 1;
    }
    return 0;
}


__attribute_cold__
int
http_request_trailer_check (request_st * const restrict r, http_trailer_parse_ctx * const restrict tpctx)
{
    if (tpctx->trailer  /*(?should strict policy require "Trailer" header?)*/
        && !http_header_str_contains_token(BUF_PTR_LEN(tpctx->trailer),
                                           tpctx->k, tpctx->klen))
        return http_request_header_line_invalid(r, 400,
          "trailer not listed in Trailer header");

    tpctx->hlen += tpctx->klen + tpctx->vlen + 4;
    if (tpctx->hlen > tpctx->max_request_field_size) {
        /* 431 Request Header Fields Too Large */
        return http_request_header_line_invalid(r, 431,
          "oversized trailers -> 431");
    }

    const enum http_header_e id = tpctx->id =
      http_header_hkey_get(tpctx->k, tpctx->klen);
    if (__builtin_expect( (id != HTTP_HEADER_OTHER), 1)) {
        /*(recognizing label name establishes label name
         * does not contain bad whitespace or CTL chars)*/
        /* explicitly reject certain field names disallowed in trailers
         * (XXX: list can be expanded further)
         * https://datatracker.ietf.org/doc/html/rfc7230#section-4.1.2
         * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Trailer
         * ? Are Connection or Proxy-Connection permitted in trailers?
         *   Choosing to reject Connection,Proxy-Connection in trailers.
         * Choosing to reject Forwarded,Upgrade,WWW-Authenticate in trailers
         */
        if (light_bshift(id)
            & (light_bshift(HTTP_HEADER_AUTHORIZATION)
              |light_bshift(HTTP_HEADER_AGE)
              |light_bshift(HTTP_HEADER_CACHE_CONTROL)
              |light_bshift(HTTP_HEADER_CONNECTION)
              |light_bshift(HTTP_HEADER_CONTENT_ENCODING)
              |light_bshift(HTTP_HEADER_CONTENT_LENGTH)
              |light_bshift(HTTP_HEADER_CONTENT_RANGE)
              |light_bshift(HTTP_HEADER_CONTENT_TYPE)
              |light_bshift(HTTP_HEADER_DATE)
              |light_bshift(HTTP_HEADER_EXPECT)
              |light_bshift(HTTP_HEADER_EXPIRES)
              |light_bshift(HTTP_HEADER_FORWARDED)
              |light_bshift(HTTP_HEADER_HOST)
              |light_bshift(HTTP_HEADER_IF_MATCH)
              |light_bshift(HTTP_HEADER_IF_MODIFIED_SINCE)
              |light_bshift(HTTP_HEADER_IF_NONE_MATCH)
              |light_bshift(HTTP_HEADER_IF_RANGE)
              |light_bshift(HTTP_HEADER_IF_UNMODIFIED_SINCE)
              |light_bshift(HTTP_HEADER_LOCATION)
              |light_bshift(HTTP_HEADER_PRAGMA)
              |light_bshift(HTTP_HEADER_RANGE)
              |light_bshift(HTTP_HEADER_SET_COOKIE)
              |light_bshift(HTTP_HEADER_TE)
              |light_bshift(HTTP_HEADER_TRANSFER_ENCODING)
              |light_bshift(HTTP_HEADER_UPGRADE)
              |light_bshift(HTTP_HEADER_USER_AGENT)
              |light_bshift(HTTP_HEADER_VARY)
              |light_bshift(HTTP_HEADER_WWW_AUTHENTICATE)))
            return http_request_header_line_invalid(r, 400,
              "forbidden trailer");
    }
    else { /* (id == HTTP_HEADER_OTHER) */
        const char * const x =
          http_request_field_check_name(tpctx->k, (int)tpctx->klen,
                                        tpctx->http_header_strict);
        if (x)
            return http_request_header_char_invalid(r, *x,
              "invalid character in header key -> 400");
        /* explicitly reject certain field names disallows in trailers
         * (XXX: list can be expanded further)
         * (If list gets too long, consider whitelisting common trailers,
         *  e.g. "Server-Timing")
         * https://datatracker.ietf.org/doc/html/rfc7230#section-4.1.2
         * https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Trailer
         */
        if ((tpctx->klen == 16
             && buffer_eq_icase_ssn(tpctx->k,CONST_STR_LEN("Proxy-Connection")))
            || (tpctx->klen == 12
                && buffer_eq_icase_ssn(tpctx->k, CONST_STR_LEN("Max-Forwards")))
            || (tpctx->klen == 7
                && buffer_eq_icase_ssn(tpctx->k, CONST_STR_LEN("Trailer"))))
            return http_request_header_line_invalid(r, 400,
              "forbidden trailer");
    }

    const char * const x =
      http_request_field_check_value(tpctx->v, tpctx->vlen,
                                     tpctx->http_header_strict);
    if (x)
        return http_request_header_char_invalid(r, *x,
          "invalid character in trailer");

    return 0;
}


__attribute_cold__
__attribute_noinline__
int
http_request_trailers_check (request_st * const restrict r, char *t, uint32_t tlen, const buffer * const trailer)
{
    /* (This function can be used on request trailers and response trailers) */
    /* future: might move this function to h1.c */
    /* Note: this function operates on (const char *) and either validates
     * or rejects the input; the input is not modified.  Any policy failure
     * results in rejection.  Policy is strict; trailers are less-frequently
     * used, and so potential impact of strictness should be more limited. */
    unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */
    hoff[0] = 1;                         /* number of lines */
    hoff[1] = 0;                         /* base offset for all lines */
    /*hoff[2] = ...;*/                   /* offset from base for 2nd line */
    uint32_t rc = http_header_parse_hoff(t, tlen, hoff);
    if (rc != tlen || hoff[0] >= sizeof(hoff)/sizeof(hoff[0])-1)
        return http_request_header_line_invalid(r, 400,
          "invalid trailers; incomplete or too many fields -> 400");
    if (1 == hoff[0]) /*(initial blank line (no trailers))*/
        return 0;

    http_trailer_parse_ctx tpctx;
    tpctx.hlen = 0;
    tpctx.id = HTTP_HEADER_OTHER;
    tpctx.trailer = trailer;
    tpctx.http_header_strict =
      (r->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);
    tpctx.max_request_field_size = r->conf.max_request_field_size;

    for (int i = 1; i < hoff[0]; ++i) {
        const char *k = t + hoff[i]; /*t + ((i > 1) ? hoff[i] : 0);*/
        const char *end = t + hoff[i+1];
        const char *v = memchr(k, ':', end-k);
        if (NULL == v)
            return http_request_header_line_invalid(r, 400,
              "invalid trailer missing ':'");
        uint32_t klen = (uint32_t)(v - k);
        if (0 == klen)
            return http_request_header_line_invalid(r, 400,
              "invalid trailer key");
        do { ++v; } while (*v == ' ' || *v == '\t'); /*(expect single ' ')*/
      #ifdef __COVERITY__
        /*(k has at least .:\n by now, so end[-2] valid)*/
        force_assert(end >= k + 2);
      #endif
        end -= 2;
        if (end[0] != '\r') /*(header line must end "\r\n")*/
            return http_request_header_line_invalid(r, 400,
              "missing CR before LF in trailer");
        uint32_t vlen = (uint32_t)(end - v);
        /* A blank value is technically allowed by RFCs, but I choose to reject;
         * omit from sending trailer field with blank value; the omission could
         * be treated as such by the recipient.  If this is removed, then
         * merging into headers should check for blank value and avoid adding
         * comma separator followed by a blank field */
        if (0 == vlen) return 400;

        tpctx.k    = k;
        tpctx.v    = v;
        tpctx.klen = klen;
        tpctx.vlen = vlen;
        if (0 != http_request_trailer_check(r, &tpctx))
            return 400;
    }

    return 0;
}
