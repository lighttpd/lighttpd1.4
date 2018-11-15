#include "first.h"

#include "http_header.h"
#include "base.h"
#include "array.h"
#include "buffer.h"


typedef struct keyvlenvalue {
    const int key;
    const char * const value;
    const size_t vlen;
} keyvlenvalue;

/* Note: must be sorted by length */
/* Note: must be kept in sync with http_header.h enum http_header_e */
static const keyvlenvalue http_headers[] = {
  { HTTP_HEADER_HOST,                 CONST_STR_LEN("Host") }
 ,{ HTTP_HEADER_DATE,                 CONST_STR_LEN("Date") }
 ,{ HTTP_HEADER_ETAG,                 CONST_STR_LEN("ETag") }
 ,{ HTTP_HEADER_VARY,                 CONST_STR_LEN("Vary") }
 ,{ HTTP_HEADER_RANGE,                CONST_STR_LEN("Range") }
 ,{ HTTP_HEADER_COOKIE,               CONST_STR_LEN("Cookie") }
 ,{ HTTP_HEADER_EXPECT,               CONST_STR_LEN("Expect") }
 ,{ HTTP_HEADER_STATUS,               CONST_STR_LEN("Status") }
 ,{ HTTP_HEADER_SERVER,               CONST_STR_LEN("Server") }
 ,{ HTTP_HEADER_UPGRADE,              CONST_STR_LEN("Upgrade") }
 ,{ HTTP_HEADER_LOCATION,             CONST_STR_LEN("Location") }
 ,{ HTTP_HEADER_FORWARDED,            CONST_STR_LEN("Forwarded") }
 ,{ HTTP_HEADER_CONNECTION,           CONST_STR_LEN("Connection") }
 ,{ HTTP_HEADER_SET_COOKIE,           CONST_STR_LEN("Set-Cookie") }
 ,{ HTTP_HEADER_CONTENT_TYPE,         CONST_STR_LEN("Content-Type") }
 ,{ HTTP_HEADER_LAST_MODIFIED,        CONST_STR_LEN("Last-Modified") }
 ,{ HTTP_HEADER_AUTHORIZATION,        CONST_STR_LEN("Authorization") }
 ,{ HTTP_HEADER_IF_NONE_MATCH,        CONST_STR_LEN("If-None-Match") }
 ,{ HTTP_HEADER_CACHE_CONTROL,        CONST_STR_LEN("Cache-Control") }
 ,{ HTTP_HEADER_CONTENT_LENGTH,       CONST_STR_LEN("Content-Length") }
 ,{ HTTP_HEADER_ACCEPT_ENCODING,      CONST_STR_LEN("Accept-Encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_FOR,      CONST_STR_LEN("X-Forwarded-For") }
 ,{ HTTP_HEADER_CONTENT_ENCODING,     CONST_STR_LEN("Content-Encoding") }
 ,{ HTTP_HEADER_CONTENT_LOCATION,     CONST_STR_LEN("Content-Location") }
 ,{ HTTP_HEADER_IF_MODIFIED_SINCE,    CONST_STR_LEN("If-Modified-Since") }
 ,{ HTTP_HEADER_TRANSFER_ENCODING,    CONST_STR_LEN("Transfer-Encoding") }
 ,{ HTTP_HEADER_X_FORWARDED_PROTO,    CONST_STR_LEN("X-Forwarded-Proto") }
 ,{ HTTP_HEADER_OTHER, NULL, 0 }
};

enum http_header_e http_header_hkey_get(const char *s, size_t slen) {
    const struct keyvlenvalue * const kv = http_headers;
    for (int i = 0; kv[i].vlen && slen >= kv[i].vlen; ++i) {
        if (slen == kv[i].vlen
            && 0 == buffer_caseless_compare(s, slen, kv[i].value, kv[i].vlen))
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
