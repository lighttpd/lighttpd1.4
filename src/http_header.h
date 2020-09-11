#ifndef INCLUDED_HTTP_HEADER_H
#define INCLUDED_HTTP_HEADER_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

/* Note: must be kept in sync with http_header.c http_headers[] */
/* Note: when adding new items, must replace OTHER in existing code for item */
enum http_header_e {
  HTTP_HEADER_UNSPECIFIED       = -1
 ,HTTP_HEADER_OTHER             =  0
 ,HTTP_HEADER_ACCEPT_ENCODING
 ,HTTP_HEADER_AUTHORIZATION
 ,HTTP_HEADER_CACHE_CONTROL
 ,HTTP_HEADER_CONNECTION
 ,HTTP_HEADER_CONTENT_ENCODING
 ,HTTP_HEADER_CONTENT_LENGTH
 ,HTTP_HEADER_CONTENT_LOCATION
 ,HTTP_HEADER_CONTENT_TYPE
 ,HTTP_HEADER_COOKIE
 ,HTTP_HEADER_DATE
 ,HTTP_HEADER_ETAG
 ,HTTP_HEADER_EXPECT
 ,HTTP_HEADER_FORWARDED
 ,HTTP_HEADER_HOST
 ,HTTP_HEADER_IF_MODIFIED_SINCE
 ,HTTP_HEADER_IF_NONE_MATCH
 ,HTTP_HEADER_LAST_MODIFIED
 ,HTTP_HEADER_LOCATION
 ,HTTP_HEADER_RANGE
 ,HTTP_HEADER_SERVER
 ,HTTP_HEADER_SET_COOKIE
 ,HTTP_HEADER_STATUS
 ,HTTP_HEADER_TRANSFER_ENCODING
 ,HTTP_HEADER_UPGRADE
 ,HTTP_HEADER_USER_AGENT
 ,HTTP_HEADER_VARY
 ,HTTP_HEADER_X_FORWARDED_FOR
 ,HTTP_HEADER_X_FORWARDED_PROTO
 ,HTTP_HEADER_HTTP2_SETTINGS
};

__attribute_pure__
enum http_header_e http_header_hkey_get(const char *s, uint32_t slen);

__attribute_pure__
int http_header_str_to_code (const char * const s);

__attribute_pure__
int http_header_str_contains_token (const char *s, uint32_t slen, const char *m, uint32_t mlen);

int http_header_remove_token (buffer * const b, const char * const m, const uint32_t mlen);

__attribute_pure__
buffer * http_header_response_get(const request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_response_unset(request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_response_set(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_response_append(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_response_insert(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);

__attribute_pure__
buffer * http_header_request_get(const request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_request_unset(request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_request_set(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_request_append(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);

__attribute_pure__
buffer * http_header_env_get(const request_st *r, const char *k, uint32_t klen);
void http_header_env_set(request_st *r, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_env_append(request_st *r, const char *k, uint32_t klen, const char *v, uint32_t vlen);

__attribute_hot__
uint32_t http_header_parse_hoff (const char *n, const uint32_t clen, unsigned short hoff[8192]);

#endif
