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
#include "base.h"
#include "array.h"
#include "buffer.h"


typedef struct keyvlenvalue {
    const int key;
    const uint32_t vlen;
    const char value[24];
} keyvlenvalue;

/* Note: must be sorted by length */
/* Note: must be kept in sync with http_header.h enum http_header_e */
/* Note: must be kept in sync http_headers[] and http_headers_off[] */
/* http_headers_off lists first offset at which string of specific len occur */
int8_t http_headers_off[] = {
  -1, -1, -1, -1, 0, 4, 5, 9, 10, 11, 12, -1, 15, 16, 20, 22, 24, 26
};
static const keyvlenvalue http_headers[] = {
  { HTTP_HEADER_HOST,                 CONST_LEN_STR("host") }
 ,{ HTTP_HEADER_DATE,                 CONST_LEN_STR("date") }
 ,{ HTTP_HEADER_ETAG,                 CONST_LEN_STR("etag") }
 ,{ HTTP_HEADER_VARY,                 CONST_LEN_STR("vary") }
 ,{ HTTP_HEADER_RANGE,                CONST_LEN_STR("range") }
 ,{ HTTP_HEADER_COOKIE,               CONST_LEN_STR("cookie") }
 ,{ HTTP_HEADER_EXPECT,               CONST_LEN_STR("expect") }
 ,{ HTTP_HEADER_STATUS,               CONST_LEN_STR("status") }
 ,{ HTTP_HEADER_SERVER,               CONST_LEN_STR("server") }
 ,{ HTTP_HEADER_UPGRADE,              CONST_LEN_STR("upgrade") }
 ,{ HTTP_HEADER_LOCATION,             CONST_LEN_STR("location") }
 ,{ HTTP_HEADER_FORWARDED,            CONST_LEN_STR("forwarded") }
 ,{ HTTP_HEADER_CONNECTION,           CONST_LEN_STR("connection") }
 ,{ HTTP_HEADER_SET_COOKIE,           CONST_LEN_STR("set-cookie") }
 ,{ HTTP_HEADER_USER_AGENT,           CONST_LEN_STR("user-agent") }
 ,{ HTTP_HEADER_CONTENT_TYPE,         CONST_LEN_STR("content-type") }
 ,{ HTTP_HEADER_LAST_MODIFIED,        CONST_LEN_STR("last-modified") }
 ,{ HTTP_HEADER_AUTHORIZATION,        CONST_LEN_STR("authorization") }
 ,{ HTTP_HEADER_IF_NONE_MATCH,        CONST_LEN_STR("if-none-match") }
 ,{ HTTP_HEADER_CACHE_CONTROL,        CONST_LEN_STR("cache-control") }
 ,{ HTTP_HEADER_CONTENT_LENGTH,       CONST_LEN_STR("content-length") }
 ,{ HTTP_HEADER_HTTP2_SETTINGS,       CONST_LEN_STR("http2-settings") }
 ,{ HTTP_HEADER_ACCEPT_ENCODING,      CONST_LEN_STR("accept-encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_FOR,      CONST_LEN_STR("x-forwarded-for") }
 ,{ HTTP_HEADER_CONTENT_ENCODING,     CONST_LEN_STR("content-encoding") }
 ,{ HTTP_HEADER_CONTENT_LOCATION,     CONST_LEN_STR("content-location") }
 ,{ HTTP_HEADER_IF_MODIFIED_SINCE,    CONST_LEN_STR("if-modified-since") }
 ,{ HTTP_HEADER_TRANSFER_ENCODING,    CONST_LEN_STR("transfer-encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_PROTO,    CONST_LEN_STR("x-forwarded-proto") }
 ,{ HTTP_HEADER_OTHER, 0, "" }
};

enum http_header_e http_header_hkey_get(const char * const s, const uint32_t slen) {
    const struct keyvlenvalue * const kv = http_headers;
    int i = slen < sizeof(http_headers_off) ? http_headers_off[slen] : -1;
    if (i < 0) return HTTP_HEADER_OTHER;
    do {
        if (buffer_eq_icase_ssn(s, kv[i].value, slen))
            return (enum http_header_e)kv[i].key;
    } while (slen == kv[++i].vlen);
    return HTTP_HEADER_OTHER;
}

enum http_header_e http_header_hkey_get_lc(const char * const s, const uint32_t slen) {
    const struct keyvlenvalue * const kv = http_headers;
    int i = slen < sizeof(http_headers_off) ? http_headers_off[slen] : -1;
    if (i < 0) return HTTP_HEADER_OTHER;
    do {
        if (0 == memcmp(s, kv[i].value, slen))
            return (enum http_header_e)kv[i].key;
    } while (slen == kv[++i].vlen);
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
                    buffer_string_set_length(b, (size_t)(s - b->ptr));
                    break;
                }
            }
        }
        s = strchr(s, ',');
    }
    return rc;
}


static inline void http_header_token_append(buffer * const vb, const char * const v, const uint32_t vlen) {
    if (!buffer_string_is_empty(vb))
        buffer_append_string_len(vb, CONST_STR_LEN(", "));
    buffer_append_string_len(vb, v, vlen);
}

__attribute_cold__
static inline void http_header_token_append_cookie(buffer * const vb, const char * const v, const uint32_t vlen) {
    /* Cookie request header must be special-cased to use ';' separator
     * instead of ',' to combine multiple headers (if present) */
    if (!buffer_string_is_empty(vb))
        buffer_append_string_len(vb, CONST_STR_LEN("; "));
    buffer_append_string_len(vb, v, vlen);
}

__attribute_pure__
static inline buffer * http_header_generic_get_ifnotempty(const array * const a, const char * const k, const uint32_t klen) {
    data_string * const ds =
      (data_string *)array_get_element_klen(a, k, klen);
    return ds && !buffer_string_is_empty(&ds->value) ? &ds->value : NULL;
}


buffer * http_header_response_get(const request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    return (id <= HTTP_HEADER_OTHER || light_btst(r->resp_htags, id))
      ? http_header_generic_get_ifnotempty(&r->resp_headers, k, klen)
      : NULL;
}

void http_header_response_unset(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    if (id <= HTTP_HEADER_OTHER || light_btst(r->resp_htags, id)) {
        if (id > HTTP_HEADER_OTHER) light_bclr(r->resp_htags, id);
        array_set_key_value(&r->resp_headers, k, klen, CONST_STR_LEN(""));
    }
}

void http_header_response_set(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     */
    if (id > HTTP_HEADER_OTHER)
        (vlen) ? light_bset(r->resp_htags, id) : light_bclr(r->resp_htags, id);
    array_set_key_value(&r->resp_headers, k, klen, v, vlen);
}

void http_header_response_append(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    if (id > HTTP_HEADER_OTHER) light_bset(r->resp_htags, id);
    buffer * const vb = array_get_buf_ptr(&r->resp_headers, k, klen);
    http_header_token_append(vb, v, vlen);
}

void http_header_response_insert(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    if (id > HTTP_HEADER_OTHER) light_bset(r->resp_htags, id);
    buffer * const vb = array_get_buf_ptr(&r->resp_headers, k, klen);
    if (!buffer_string_is_empty(vb)) { /* append value */
        buffer_append_string_len(vb, CONST_STR_LEN("\r\n"));
        if (r->http_version >= HTTP_VERSION_2) {
            r->resp_header_repeated = 1;
            char * const h = buffer_string_prepare_append(vb, klen + vlen + 2);
            for (uint32_t i = 0; i < klen; ++i)
                h[i] = !light_isupper(k[i]) ? k[i] : (k[i] | 0x20);
            buffer_commit(vb, klen);
        }
        else
            buffer_append_string_len(vb, k, klen);
        buffer_append_string_len(vb, CONST_STR_LEN(": "));
    }
    buffer_append_string_len(vb, v, vlen);
}


buffer * http_header_request_get(const request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    return (id <= HTTP_HEADER_OTHER || light_btst(r->rqst_htags, id))
      ? http_header_generic_get_ifnotempty(&r->rqst_headers, k, klen)
      : NULL;
}

void http_header_request_unset(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    if (id <= HTTP_HEADER_OTHER || light_btst(r->rqst_htags, id)) {
        if (id > HTTP_HEADER_OTHER) light_bclr(r->rqst_htags, id);
        array_set_key_value(&r->rqst_headers, k, klen, CONST_STR_LEN(""));
    }
}

void http_header_request_set(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     */
    if (id > HTTP_HEADER_OTHER)
        (vlen) ? light_bset(r->rqst_htags, id) : light_bclr(r->rqst_htags, id);
    array_set_key_value(&r->rqst_headers, k, klen, v, vlen);
}

void http_header_request_append(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    if (id > HTTP_HEADER_OTHER) light_bset(r->rqst_htags, id);
    buffer * const vb = array_get_buf_ptr(&r->rqst_headers, k, klen);
    if (id != HTTP_HEADER_COOKIE)
        http_header_token_append(vb, v, vlen);
    else
        http_header_token_append_cookie(vb, v, vlen);
}


buffer * http_header_env_get(const request_st * const r, const char *k, uint32_t klen) {
    return http_header_generic_get_ifnotempty(&r->env, k, klen);
}

void http_header_env_set(request_st * const r, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    array_set_key_value(&r->env, k, klen, v, vlen);
}

void http_header_env_append(request_st * const r, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /*if (0 == vlen) return;*//* skip check; permit env var w/ blank value */
    buffer * const vb = array_get_buf_ptr(&r->env, k, klen);
    if (0 == vlen) return;
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
