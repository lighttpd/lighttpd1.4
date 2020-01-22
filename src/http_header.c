#include "first.h"

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
  -1, -1, -1, -1, 0, 4, 5, 9, 10, 11, 12, -1, 15, 16, 20, 21, 23, 25
};
static const keyvlenvalue http_headers[] = {
  { HTTP_HEADER_HOST,                 CONST_LEN_STR("Host") }
 ,{ HTTP_HEADER_DATE,                 CONST_LEN_STR("Date") }
 ,{ HTTP_HEADER_ETAG,                 CONST_LEN_STR("ETag") }
 ,{ HTTP_HEADER_VARY,                 CONST_LEN_STR("Vary") }
 ,{ HTTP_HEADER_RANGE,                CONST_LEN_STR("Range") }
 ,{ HTTP_HEADER_COOKIE,               CONST_LEN_STR("Cookie") }
 ,{ HTTP_HEADER_EXPECT,               CONST_LEN_STR("Expect") }
 ,{ HTTP_HEADER_STATUS,               CONST_LEN_STR("Status") }
 ,{ HTTP_HEADER_SERVER,               CONST_LEN_STR("Server") }
 ,{ HTTP_HEADER_UPGRADE,              CONST_LEN_STR("Upgrade") }
 ,{ HTTP_HEADER_LOCATION,             CONST_LEN_STR("Location") }
 ,{ HTTP_HEADER_FORWARDED,            CONST_LEN_STR("Forwarded") }
 ,{ HTTP_HEADER_CONNECTION,           CONST_LEN_STR("Connection") }
 ,{ HTTP_HEADER_SET_COOKIE,           CONST_LEN_STR("Set-Cookie") }
 ,{ HTTP_HEADER_USER_AGENT,           CONST_LEN_STR("User-Agent") }
 ,{ HTTP_HEADER_CONTENT_TYPE,         CONST_LEN_STR("Content-Type") }
 ,{ HTTP_HEADER_LAST_MODIFIED,        CONST_LEN_STR("Last-Modified") }
 ,{ HTTP_HEADER_AUTHORIZATION,        CONST_LEN_STR("Authorization") }
 ,{ HTTP_HEADER_IF_NONE_MATCH,        CONST_LEN_STR("If-None-Match") }
 ,{ HTTP_HEADER_CACHE_CONTROL,        CONST_LEN_STR("Cache-Control") }
 ,{ HTTP_HEADER_CONTENT_LENGTH,       CONST_LEN_STR("Content-Length") }
 ,{ HTTP_HEADER_ACCEPT_ENCODING,      CONST_LEN_STR("Accept-Encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_FOR,      CONST_LEN_STR("X-Forwarded-For") }
 ,{ HTTP_HEADER_CONTENT_ENCODING,     CONST_LEN_STR("Content-Encoding") }
 ,{ HTTP_HEADER_CONTENT_LOCATION,     CONST_LEN_STR("Content-Location") }
 ,{ HTTP_HEADER_IF_MODIFIED_SINCE,    CONST_LEN_STR("If-Modified-Since") }
 ,{ HTTP_HEADER_TRANSFER_ENCODING,    CONST_LEN_STR("Transfer-Encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_PROTO,    CONST_LEN_STR("X-Forwarded-Proto") }
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


int http_header_str_contains_token (const char * const s, const uint32_t slen, const char * const m, const uint32_t mlen)
{
    /*if (slen < mlen) return 0;*//*(possible optimizations for caller)*/
    /*if (slen == mlen && buffer_eq_icase_ssn(s, m, mlen)) return 1;*/
    uint32_t i = 0;
    do {
        while (i < slen &&  (s[i]==' ' || s[i]=='\t' || s[i]==',')) ++i;
        if (i == slen) return 0;
        if (buffer_eq_icase_ssn(s+i, m, mlen)) {
            i += mlen;
            if (i == slen || s[i]==' ' || s[i]=='\t' || s[i]==',' || s[i]==';')
                return 1;
        }
        while (i < slen &&   s[i]!=',') ++i;
    } while (i < slen);
    return 0;
}


static inline void http_header_token_append(buffer * const vb, const char * const v, const uint32_t vlen) {
    if (!buffer_string_is_empty(vb))
        buffer_append_string_len(vb, CONST_STR_LEN(", "));
    buffer_append_string_len(vb, v, vlen);
}

__attribute_pure__
static inline buffer * http_header_generic_get_ifnotempty(const array * const a, const char * const k, const uint32_t klen) {
    data_string * const ds =
      (data_string *)array_get_element_klen(a, k, klen);
    return ds && !buffer_string_is_empty(&ds->value) ? &ds->value : NULL;
}


buffer * http_header_response_get(const request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    return (id <= HTTP_HEADER_OTHER || (r->resp_htags & id))
      ? http_header_generic_get_ifnotempty(&r->resp_headers, k, klen)
      : NULL;
}

void http_header_response_unset(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    if (id <= HTTP_HEADER_OTHER || (r->resp_htags & id)) {
        if (id > HTTP_HEADER_OTHER) r->resp_htags &= ~id;
        array_set_key_value(&r->resp_headers, k, klen, CONST_STR_LEN(""));
    }
}

void http_header_response_set(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     */
    if (id > HTTP_HEADER_OTHER)
        (vlen) ? (r->resp_htags |= id) : (r->resp_htags &= ~id);
    array_set_key_value(&r->resp_headers, k, klen, v, vlen);
}

void http_header_response_append(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    if (id > HTTP_HEADER_OTHER) r->resp_htags |= id;
    buffer * const vb = array_get_buf_ptr(&r->resp_headers, k, klen);
    http_header_token_append(vb, v, vlen);
}

void http_header_response_insert(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    if (id > HTTP_HEADER_OTHER) r->resp_htags |= id;
    buffer * const vb = array_get_buf_ptr(&r->resp_headers, k, klen);
    if (!buffer_string_is_empty(vb)) { /* append value */
        buffer_append_string_len(vb, CONST_STR_LEN("\r\n"));
        buffer_append_string_len(vb, k, klen);
        buffer_append_string_len(vb, CONST_STR_LEN(": "));
    }
    buffer_append_string_len(vb, v, vlen);
}


buffer * http_header_request_get(const request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    return (id <= HTTP_HEADER_OTHER || (r->rqst_htags & id))
      ? http_header_generic_get_ifnotempty(&r->rqst_headers, k, klen)
      : NULL;
}

void http_header_request_unset(request_st * const r, enum http_header_e id, const char *k, uint32_t klen) {
    if (id <= HTTP_HEADER_OTHER || (r->rqst_htags & id)) {
        if (id > HTTP_HEADER_OTHER) r->rqst_htags &= ~id;
        array_set_key_value(&r->rqst_headers, k, klen, CONST_STR_LEN(""));
    }
}

void http_header_request_set(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     */
    if (id > HTTP_HEADER_OTHER)
        (vlen) ? (r->rqst_htags |= id) : (r->rqst_htags &= ~id);
    array_set_key_value(&r->rqst_headers, k, klen, v, vlen);
}

void http_header_request_append(request_st * const r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen) {
    if (0 == vlen) return;
    if (id > HTTP_HEADER_OTHER) r->rqst_htags |= id;
    buffer * const vb = array_get_buf_ptr(&r->rqst_headers, k, klen);
    http_header_token_append(vb, v, vlen);
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
