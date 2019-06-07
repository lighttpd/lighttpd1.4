#include "first.h"

#include "http_header.h"
#include "base.h"
#include "array.h"
#include "buffer.h"


typedef struct keyvlenvalue {
    const int key;
    const unsigned int vlen;
    const char * const value;
} keyvlenvalue;

/* Note: must be sorted by length */
/* Note: must be kept in sync with http_header.h enum http_header_e */
#define CONST_LEN_STR(x) (unsigned int)(sizeof(x)-1), (x)
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
 ,{ HTTP_HEADER_OTHER, 0, NULL }
};

enum http_header_e http_header_hkey_get(const char *s, size_t slen) {
    const struct keyvlenvalue * const kv = http_headers;
    for (int i = 0; kv[i].vlen && slen >= kv[i].vlen; ++i) {
        if (slen == kv[i].vlen
            && buffer_eq_icase_ssn(s, kv[i].value, slen))
            return (enum http_header_e)kv[i].key;
    }
    return HTTP_HEADER_OTHER;
}


buffer * http_header_response_get(connection *con, enum http_header_e id, const char *k, size_t klen) {
    data_string * const ds =
      (id <= HTTP_HEADER_OTHER || (con->response.htags & id))
      ? (data_string *)array_get_element_klen(con->response.headers, k, klen)
      : NULL;
    return ds && !buffer_string_is_empty(ds->value) ? ds->value : NULL;
}

void http_header_response_unset(connection *con, enum http_header_e id, const char *k, size_t klen) {
    if (id <= HTTP_HEADER_OTHER || (con->response.htags & id)) {
        if (id > HTTP_HEADER_OTHER) con->response.htags &= ~id;
        array_set_key_value(con->response.headers, k, klen, CONST_STR_LEN(""));
    }
}

void http_header_response_set(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     */
    if (id > HTTP_HEADER_OTHER)
        (vlen) ? (con->response.htags |= id) : (con->response.htags &= ~id);
    array_set_key_value(con->response.headers, k, klen, v, vlen);
}

void http_header_response_append(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen) {
    if (vlen) {
        data_string *ds= (id <= HTTP_HEADER_OTHER || (con->response.htags & id))
          ? (data_string *)array_get_element_klen(con->response.headers,k,klen)
          : NULL;
        if (id > HTTP_HEADER_OTHER) con->response.htags |= id;
        if (NULL == ds) {
            array_insert_key_value(con->response.headers, k, klen, v, vlen);
        }
        else { /* append value */
            buffer *vb = ds->value;
            if (!buffer_string_is_empty(vb))
                buffer_append_string_len(vb, CONST_STR_LEN(", "));
            buffer_append_string_len(vb, v, vlen);
        }
    }
}

void http_header_response_insert(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen) {
    if (vlen) {
        data_string *ds= (id <= HTTP_HEADER_OTHER || (con->response.htags & id))
          ? (data_string *)array_get_element_klen(con->response.headers,k,klen)
          : NULL;
        if (id > HTTP_HEADER_OTHER) con->response.htags |= id;
        if (NULL == ds) {
            array_insert_key_value(con->response.headers, k, klen, v, vlen);
        }
        else { /* append value */
            buffer *vb = ds->value;
            if (!buffer_string_is_empty(vb)) {
                buffer_append_string_len(vb, CONST_STR_LEN("\r\n"));
                buffer_append_string_len(vb, k, klen);
                buffer_append_string_len(vb, CONST_STR_LEN(": "));
            }
            buffer_append_string_len(vb, v, vlen);
        }
    }
}


buffer * http_header_request_get(connection *con, enum http_header_e id, const char *k, size_t klen) {
    data_string * const ds =
      (id <= HTTP_HEADER_OTHER || (con->request.htags & id))
      ? (data_string *)array_get_element_klen(con->request.headers, k, klen)
      : NULL;
    return ds && !buffer_string_is_empty(ds->value) ? ds->value : NULL;
}

void http_header_request_unset(connection *con, enum http_header_e id, const char *k, size_t klen) {
    if (id <= HTTP_HEADER_OTHER || (con->request.htags & id)) {
        if (id > HTTP_HEADER_OTHER) con->request.htags &= ~id;
        array_set_key_value(con->request.headers, k, klen, CONST_STR_LEN(""));
    }
}

void http_header_request_set(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen) {
    /* set value, including setting blank value if 0 == vlen
     * (note: if 0 == vlen, header is still inserted with blank value,
     *  which is used to indicate a "removed" header)
     */
    if (id > HTTP_HEADER_OTHER)
        (vlen) ? (con->request.htags |= id) : (con->request.htags &= ~id);
    array_set_key_value(con->request.headers, k, klen, v, vlen);
}

void http_header_request_append(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen) {
    if (vlen) {
        data_string *ds = (id <= HTTP_HEADER_OTHER || (con->request.htags & id))
          ? (data_string *)array_get_element_klen(con->request.headers, k, klen)
          : NULL;
        if (id > HTTP_HEADER_OTHER) con->request.htags |= id;
        if (NULL == ds) {
            array_insert_key_value(con->request.headers, k, klen, v, vlen);
        }
        else { /* append value */
            buffer *vb = ds->value;
            if (!buffer_string_is_empty(vb))
                buffer_append_string_len(vb, CONST_STR_LEN(", "));
            buffer_append_string_len(vb, v, vlen);
        }
    }
}


buffer * http_header_env_get(connection *con, const char *k, size_t klen) {
    data_string * const ds =
      (data_string *)array_get_element_klen(con->environment, k, klen);
    return ds && !buffer_string_is_empty(ds->value) ? ds->value : NULL;
}

void http_header_env_set(connection *con, const char *k, size_t klen, const char *v, size_t vlen) {
    array_set_key_value(con->environment, k, klen, v, vlen);
}

void http_header_env_append(connection *con, const char *k, size_t klen, const char *v, size_t vlen) {
    /*if (vlen)*/ /* skip check; permit env var w/ blank value to be appended */
    {
        buffer * const vb = http_header_env_get(con, k, klen);
        if (NULL == vb) {
            array_insert_key_value(con->environment, k, klen, v, vlen);
        }
        else if (vlen) { /* append value */
            buffer_append_string_len(vb, CONST_STR_LEN(", "));
            buffer_append_string_len(vb, v, vlen);
        }
    }
}
