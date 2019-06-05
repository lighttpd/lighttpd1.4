#ifndef INCLUDED_HTTP_HEADER_H
#define INCLUDED_HTTP_HEADER_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

/* Note: must be kept in sync with http_header.c http_headers[] */
/* Note: when adding new items, must replace OTHER in existing code for item */
enum http_header_e {
  HTTP_HEADER_UNSPECIFIED       = -1
 ,HTTP_HEADER_OTHER             = 0x00000000
 ,HTTP_HEADER_ACCEPT_ENCODING   = 0x00000001
 ,HTTP_HEADER_AUTHORIZATION     = 0x00000002
 ,HTTP_HEADER_CACHE_CONTROL     = 0x00000004
 ,HTTP_HEADER_CONNECTION        = 0x00000008
 ,HTTP_HEADER_CONTENT_ENCODING  = 0x00000010
 ,HTTP_HEADER_CONTENT_LENGTH    = 0x00000020
 ,HTTP_HEADER_CONTENT_LOCATION  = 0x00000040
 ,HTTP_HEADER_CONTENT_TYPE      = 0x00000080
 ,HTTP_HEADER_COOKIE            = 0x00000100
 ,HTTP_HEADER_DATE              = 0x00000200
 ,HTTP_HEADER_ETAG              = 0x00000400
 ,HTTP_HEADER_EXPECT            = 0x00000800
 ,HTTP_HEADER_FORWARDED         = 0x00001000
 ,HTTP_HEADER_HOST              = 0x00002000
 ,HTTP_HEADER_IF_MODIFIED_SINCE = 0x00004000
 ,HTTP_HEADER_IF_NONE_MATCH     = 0x00008000
 ,HTTP_HEADER_LAST_MODIFIED     = 0x00010000
 ,HTTP_HEADER_LOCATION          = 0x00020000
 ,HTTP_HEADER_RANGE             = 0x00040000
 ,HTTP_HEADER_SERVER            = 0x00080000
 ,HTTP_HEADER_SET_COOKIE        = 0x00100000
 ,HTTP_HEADER_STATUS            = 0x00200000
 ,HTTP_HEADER_TRANSFER_ENCODING = 0x00400000
 ,HTTP_HEADER_UPGRADE           = 0x00800000
 ,HTTP_HEADER_VARY              = 0x01000000
 ,HTTP_HEADER_X_FORWARDED_FOR   = 0x02000000
 ,HTTP_HEADER_X_FORWARDED_PROTO = 0x04000000
};

__attribute_pure__
enum http_header_e http_header_hkey_get(const char *s, size_t slen);

buffer * http_header_response_get(connection *con, enum http_header_e id, const char *k, size_t klen);
void http_header_response_unset(connection *con, enum http_header_e id, const char *k, size_t klen);
void http_header_response_set(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen);
void http_header_response_append(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen);
void http_header_response_insert(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen);

buffer * http_header_request_get(connection *con, enum http_header_e id, const char *k, size_t klen);
void http_header_request_unset(connection *con, enum http_header_e id, const char *k, size_t klen);
void http_header_request_set(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen);
void http_header_request_append(connection *con, enum http_header_e id, const char *k, size_t klen, const char *v, size_t vlen);

buffer * http_header_env_get(connection *con, const char *k, size_t klen);
void http_header_env_set(connection *con, const char *k, size_t klen, const char *v, size_t vlen);
void http_header_env_append(connection *con, const char *k, size_t klen, const char *v, size_t vlen);

#endif
