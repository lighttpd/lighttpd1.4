/*
 * http_header - HTTP header manipulation interfaces
 *
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <string.h>
#include "sys-strings.h"

#include "http_header.h"
#include "array.h"
#include "buffer.h"
#include "request.h"


typedef struct keyvlenvalue {
    const  int16_t key;
    const uint16_t vlen;
    const char value[28];
} keyvlenvalue;

/* Note: must be sorted by length */
/* Note: must be kept in sync with http_header.h enum http_header_e */
/* Note: must be kept in sync http_headers[] and http_headers_off[] */
/* Note: must be kept in sync h2.c:http_header_lc[] */
/* Note: must be kept in sync h2.c:http_header_lshpack_idx[] */
/* Note: must be kept in sync h2.c:lshpack_idx_http_header[] */
/* http_headers_off lists first offset at which string of specific len occur */
static const int8_t http_headers_off[] = {
  -1, -1,  0,  1,  4,  9, 11, 17, 21, 26, 28, -1, 31, 32,
  38, 41, 46, 50, -1, 53, -1, -1, 54, 55, -1, 56, -1, 58
};
static const keyvlenvalue http_headers[] = {
  { HTTP_HEADER_TE,                          CONST_LEN_STR("te") }
 ,{ HTTP_HEADER_AGE,                         CONST_LEN_STR("age") }
 ,{ HTTP_HEADER_DNT,                         CONST_LEN_STR("dnt") }
 ,{ HTTP_HEADER_P3P,                         CONST_LEN_STR("p3p") }
 ,{ HTTP_HEADER_HOST,                        CONST_LEN_STR("host") }
 ,{ HTTP_HEADER_DATE,                        CONST_LEN_STR("date") }
 ,{ HTTP_HEADER_ETAG,                        CONST_LEN_STR("etag") }
 ,{ HTTP_HEADER_VARY,                        CONST_LEN_STR("vary") }
 ,{ HTTP_HEADER_LINK,                        CONST_LEN_STR("link") }
 ,{ HTTP_HEADER_ALLOW,                       CONST_LEN_STR("allow") }
 ,{ HTTP_HEADER_RANGE,                       CONST_LEN_STR("range") }
 ,{ HTTP_HEADER_COOKIE,                      CONST_LEN_STR("cookie") }
 ,{ HTTP_HEADER_ACCEPT,                      CONST_LEN_STR("accept") }
 ,{ HTTP_HEADER_STATUS,                      CONST_LEN_STR("status") }
 ,{ HTTP_HEADER_SERVER,                      CONST_LEN_STR("server") }
 ,{ HTTP_HEADER_EXPECT,                      CONST_LEN_STR("expect") }
 ,{ HTTP_HEADER_PRAGMA,                      CONST_LEN_STR("pragma") }
 ,{ HTTP_HEADER_UPGRADE,                     CONST_LEN_STR("upgrade") }
 ,{ HTTP_HEADER_REFERER,                     CONST_LEN_STR("referer") }
 ,{ HTTP_HEADER_EXPIRES,                     CONST_LEN_STR("expires") }
 ,{ HTTP_HEADER_ALT_SVC,                     CONST_LEN_STR("alt-svc") }
 ,{ HTTP_HEADER_LOCATION,                    CONST_LEN_STR("location") }
 ,{ HTTP_HEADER_PRIORITY,                    CONST_LEN_STR("priority") }
 ,{ HTTP_HEADER_IF_MATCH,                    CONST_LEN_STR("if-match") }
 ,{ HTTP_HEADER_IF_RANGE,                    CONST_LEN_STR("if-range") }
 ,{ HTTP_HEADER_ALT_USED,                    CONST_LEN_STR("alt-used") }
 ,{ HTTP_HEADER_FORWARDED,                   CONST_LEN_STR("forwarded") }
 ,{ HTTP_HEADER_EXPECT_CT,                   CONST_LEN_STR("expect-ct") }
 ,{ HTTP_HEADER_CONNECTION,                  CONST_LEN_STR("connection") }
 ,{ HTTP_HEADER_SET_COOKIE,                  CONST_LEN_STR("set-cookie") }
 ,{ HTTP_HEADER_USER_AGENT,                  CONST_LEN_STR("user-agent") }
 ,{ HTTP_HEADER_CONTENT_TYPE,                CONST_LEN_STR("content-type") }
 ,{ HTTP_HEADER_LAST_MODIFIED,               CONST_LEN_STR("last-modified") }
 ,{ HTTP_HEADER_AUTHORIZATION,               CONST_LEN_STR("authorization") }
 ,{ HTTP_HEADER_IF_NONE_MATCH,               CONST_LEN_STR("if-none-match") }
 ,{ HTTP_HEADER_CACHE_CONTROL,               CONST_LEN_STR("cache-control") }
 ,{ HTTP_HEADER_ACCEPT_RANGES,               CONST_LEN_STR("accept-ranges") }
 ,{ HTTP_HEADER_CONTENT_RANGE,               CONST_LEN_STR("content-range") }
 ,{ HTTP_HEADER_CONTENT_LENGTH,              CONST_LEN_STR("content-length") }
 ,{ HTTP_HEADER_HTTP2_SETTINGS,              CONST_LEN_STR("http2-settings") }
 ,{ HTTP_HEADER_ONION_LOCATION,              CONST_LEN_STR("onion-location") }
 ,{ HTTP_HEADER_ACCEPT_ENCODING,             CONST_LEN_STR("accept-encoding") }
 ,{ HTTP_HEADER_ACCEPT_LANGUAGE,             CONST_LEN_STR("accept-language") }
 ,{ HTTP_HEADER_REFERRER_POLICY,             CONST_LEN_STR("referrer-policy") }
 ,{ HTTP_HEADER_X_FORWARDED_FOR,             CONST_LEN_STR("x-forwarded-for") }
 ,{ HTTP_HEADER_X_FRAME_OPTIONS,             CONST_LEN_STR("x-frame-options") }
 ,{ HTTP_HEADER_WWW_AUTHENTICATE,            CONST_LEN_STR("www-authenticate") }
 ,{ HTTP_HEADER_CONTENT_ENCODING,            CONST_LEN_STR("content-encoding") }
 ,{ HTTP_HEADER_CONTENT_LOCATION,            CONST_LEN_STR("content-location") }
 ,{ HTTP_HEADER_X_XSS_PROTECTION,            CONST_LEN_STR("x-xss-protection") }
 ,{ HTTP_HEADER_IF_MODIFIED_SINCE,           CONST_LEN_STR("if-modified-since") }
 ,{ HTTP_HEADER_TRANSFER_ENCODING,           CONST_LEN_STR("transfer-encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_PROTO,           CONST_LEN_STR("x-forwarded-proto") }
 ,{ HTTP_HEADER_IF_UNMODIFIED_SINCE,         CONST_LEN_STR("if-unmodified-since") }
 ,{ HTTP_HEADER_X_CONTENT_TYPE_OPTIONS,      CONST_LEN_STR("x-content-type-options") }
 ,{ HTTP_HEADER_CONTENT_SECURITY_POLICY,     CONST_LEN_STR("content-security-policy") }
 ,{ HTTP_HEADER_STRICT_TRANSPORT_SECURITY,   CONST_LEN_STR("strict-transport-security") }
 ,{ HTTP_HEADER_UPGRADE_INSECURE_REQUESTS,   CONST_LEN_STR("upgrade-insecure-requests") }
 ,{ HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, CONST_LEN_STR("access-control-allow-origin") }
 ,{ HTTP_HEADER_OTHER, 0, "" }
};

enum http_header_e http_header_hkey_get(const char * const s, const size_t slen) {
    if (__builtin_expect( (slen < sizeof(http_headers_off)), 1)) {
        const int i = http_headers_off[slen];
        /*(lowercase first char as all recognized headers start w/ alpha char)*/
        const int c = s[0] | 0x20;
        const struct keyvlenvalue * restrict kv = http_headers + i;
        if (__builtin_expect( (i != -1), 1)) {
            do {
                if (__builtin_expect( (c != kv->value[0]), 1))
                    continue;
                if (buffer_eq_icase_ssn(s+1, kv->value+1, slen-1))
                    return (enum http_header_e)kv->key;
            } while (slen == (++kv)->vlen);
        }
    }
    return HTTP_HEADER_OTHER;
}

enum http_header_e http_header_hkey_get_lc(const char * const s, const size_t slen) {
    /* XXX: might not provide much real performance over http_header_hkey_get()
     *      (since the first-char comparison optimization was added)
     *      (and since well-known h2 headers are already mapped to hkey) */
    if (__builtin_expect( (slen < sizeof(http_headers_off)), 1)) {
        const int i = http_headers_off[slen];
        const int c = s[0];
        const struct keyvlenvalue * restrict kv = http_headers + i;
        if (__builtin_expect( (i != -1), 1)) {
            do {
                if (__builtin_expect( (c != kv->value[0]), 1))
                    continue;
                if (0 == memcmp(s+1, kv->value+1, slen-1))
                    return (enum http_header_e)kv->key;
            } while (slen == (++kv)->vlen);
        }
    }
    return HTTP_HEADER_OTHER;
}


int http_header_str_to_code (const char * const s)
{
    /*(more strict than strtol(); exactly 3 digits followed by SP/TAB/NIL)*/
    return (light_isdigit(s[0]) && light_isdigit(s[1]) && light_isdigit(s[2])
            && (s[3] == '\0' || s[3] == ' ' || s[3] == '\t'))
      ? (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2]-'0')
      : -1;
}

int http_header_str_contains_token (const char * const s, const uint32_t slen, const char * const m, const uint32_t mlen)
{
    /*if (slen < mlen) return 0;*//*(possible optimizations for caller)*/
    /*if (slen == mlen && buffer_eq_icase_ssn(s, m, mlen)) return 1;*/
    /*(note: does not handle quoted-string)*/
    uint32_t i = 0;
    do {
        while (i < slen &&  (s[i]==' ' || s[i]=='\t' || s[i]==',')) ++i;
        if (slen - i < mlen) return 0;
        if (buffer_eq_icase_ssn(s+i, m, mlen)) {
            i += mlen;
            if (i == slen || s[i]==' ' || s[i]=='\t' || s[i]==',' || s[i]==';')
                return 1;
        }
        while (i < slen &&   s[i]!=',') ++i;
    } while (i < slen);
    return 0;
}


int http_header_remove_token (buffer * const b, const char * const m, const uint32_t mlen)
{
    /*(remove all instance of token from string)*/
    /*(note: does not handle quoted-string)*/
    int rc = 0;
    for (char *s = b->ptr; s; ) {
        while (*s == ' ' || *s == '\t' || *s == ',') ++s;
        if (0 == strncasecmp(s, m, mlen)) {
            s += mlen;
            if (*s=='\0' || *s==' ' || *s=='\t' || *s==',' || *s==';') {
                memset(s-mlen, ' ', mlen);
                while (*s != '\0' && *s != ',') ++s;
                rc = 1;
                if (*s == ',') {
                    *s++ = ' ';
                    continue;
                }
                else {
                    for (s -= mlen; *s != ',' && s != b->ptr; --s) ;
                    buffer_truncate(b, (size_t)(s - b->ptr));
                    break;
                }
            }
        }
        s = strchr(s, ',');
    }
    return rc;
}


static inline void http_header_token_append(buffer * const vb, const char * const v, const uint32_t vlen) {
    if (!buffer_is_blank(vb))
        buffer_append_string_len(vb, CONST_STR_LEN(", "));
    buffer_append_string_len(vb, v, vlen);
}

__attribute_cold__
static inline void http_header_token_append_cookie(buffer * const vb, const char * const v, const uint32_t vlen) {
    /* Cookie request header must be special-cased to use ';' separator
     * instead of ',' to combine multiple headers (if present) */
    if (!buffer_is_blank(vb))
        buffer_append_string_len(vb, CONST_STR_LEN("; "));
    buffer_append_string_len(vb, v, vlen);
}

__attribute_pure__
static inline buffer * http_header_generic_get_ifnotempty(const array * const a, const enum http_header_e id, const char * const k, const uint32_t klen) {
    data_string * const ds =
      (data_string *)array_get_element_klen_ext(a, id, k, klen);
    return ds && !buffer_is_blank(&ds->value) ? &ds->value : NULL;
}

static inline void http_header_set_key_value(array * const a, enum http_header_e id, const char * const k, const size_t klen, const char * const v, const size_t vlen) {
    buffer_copy_string_len(array_get_buf_ptr_ext(a, id, k, klen), v, vlen);
}


buffer * http_header_response_get(const request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    return light_btst(r->resp_htags, id)
      ? http_header_generic_get_ifnotempty(&r->resp_headers, id, k, klen)
      : NULL;
}

buffer * http_header_response_set_ptr(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    /* note: caller must not leave buffer empty
     * or must call http_header_response_unset() */
    light_bset(r->resp_htags, id);
    buffer * const vb = array_get_buf_ptr_ext(&r->resp_headers, id, k, klen);
    buffer_clear(vb);
    return vb;
}

void http_header_response_unset(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    if (light_btst(r->resp_htags, id)) {
        /* (do not clear bit for HTTP_HEADER_OTHER,
         *  as there might be addtl "other" headers) */
        if (id > HTTP_HEADER_OTHER) light_bclr(r->resp_htags, id);
        http_header_set_key_value(&r->resp_headers,id,k,klen,CONST_STR_LEN(""));
    }
}

void http_header_response_set(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     * (do not clear bit for HTTP_HEADER_OTHER if 0 == vlen,
     *  as there might be addtl "other" headers) */
    (vlen)
      ? light_bset(r->resp_htags, id)
      : (id > HTTP_HEADER_OTHER ? light_bclr(r->resp_htags, id) : 0);
    http_header_set_key_value(&r->resp_headers, id, k, klen, v, vlen);
}

void http_header_response_append(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    light_bset(r->resp_htags, id);
    buffer * const vb = array_get_buf_ptr_ext(&r->resp_headers, id, k, klen);
    http_header_token_append(vb, v, vlen);
}

__attribute_cold__
static void http_header_response_insert_addtl(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, buffer * const vb, uint32_t vlen) {
    UNUSED(id);
    char *h = buffer_string_prepare_append(vb, 2 + klen + vlen + 2);
    buffer_append_str3(vb, CONST_STR_LEN("\r\n"), k, klen, CONST_STR_LEN(": "));
    if (r->http_version >= HTTP_VERSION_2) {
        r->resp_header_repeated = 1;
        h += 2;
        for (uint32_t i = 0; i < klen; ++i) {
            if (light_isupper(h[i])) h[i] |= 0x20;
        }
    }
}

void http_header_response_insert(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    light_bset(r->resp_htags, id);
    buffer * const vb = array_get_buf_ptr_ext(&r->resp_headers, id, k, klen);
    if (!buffer_is_blank(vb)) /*append repeated field-name on new line*/
        http_header_response_insert_addtl(r, id, k, klen, vb, vlen);
    buffer_append_string_len(vb, v, vlen);
}


buffer * http_header_request_get(const request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    return light_btst(r->rqst_htags, id)
      ? http_header_generic_get_ifnotempty(&r->rqst_headers, id, k, klen)
      : NULL;
}

buffer * http_header_request_set_ptr(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    /* note: caller must not leave buffer empty
     * or must call http_header_request_unset() */
    light_bset(r->rqst_htags, id);
    buffer * const vb = array_get_buf_ptr_ext(&r->rqst_headers, id, k, klen);
    buffer_clear(vb);
    return vb;
}

void http_header_request_unset(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    if (light_btst(r->rqst_htags, id)) {
        /* (do not clear bit for HTTP_HEADER_OTHER,
         *  as there might be addtl "other" headers) */
        if (id > HTTP_HEADER_OTHER) light_bclr(r->rqst_htags, id);
        http_header_set_key_value(&r->rqst_headers,id,k,klen,CONST_STR_LEN(""));
    }
}

void http_header_request_set(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     * (do not clear bit for HTTP_HEADER_OTHER if 0 == vlen,
     *  as there might be addtl "other" headers) */
    (vlen)
      ? light_bset(r->rqst_htags, id)
      : (id > HTTP_HEADER_OTHER ? light_bclr(r->rqst_htags, id) : 0);
    http_header_set_key_value(&r->rqst_headers, id, k, klen, v, vlen);
}

void http_header_request_append(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    light_bset(r->rqst_htags, id);
    buffer * const vb = array_get_buf_ptr_ext(&r->rqst_headers, id, k, klen);
    if (id != HTTP_HEADER_COOKIE)
        http_header_token_append(vb, v, vlen);
    else
        http_header_token_append_cookie(vb, v, vlen);
}


buffer * http_header_env_get(const request_st * const r, const char *k, uint32_t klen) {
    /* similar to http_header_generic_get_ifnotempty() but without id */
    data_string * const ds =
      (data_string *)array_get_element_klen(&r->env, k, klen);
    return ds && !buffer_is_blank(&ds->value) ? &ds->value : NULL;
}

buffer * http_header_env_set_ptr(request_st *r, const char *k, uint32_t klen) {
    buffer * const vb = array_get_buf_ptr(&r->env, k, klen);
    buffer_clear(vb);
    return vb;
}

void http_header_env_set(request_st * const r, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    array_set_key_value(&r->env, k, klen, v, vlen);
}

void http_header_env_append(request_st * const r, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /*if (0 == vlen) return;*//* skip check; permit env var w/ blank value */
    buffer * const vb = array_get_buf_ptr(&r->env, k, klen);
    http_header_token_append(vb, v, vlen);
}


uint32_t
http_header_parse_hoff (const char *n, const uint32_t clen, unsigned short hoff[8192])
{
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
