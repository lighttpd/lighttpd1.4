#ifndef INCLUDED_HTTP_HEADER_H
#define INCLUDED_HTTP_HEADER_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

/* HTTP header enum for select HTTP field-names
 * reference:
 *   https://www.iana.org/assignments/message-headers/message-headers.xml
 *   https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
 */
/* Note: must be kept in sync with http_header.c http_headers[] */
/* Note: must be kept in sync h2.c:http_header_lc[] */
/* Note: must be kept in sync h2.c:http_header_lshpack_idx[] */
/* Note: must be kept in sync h2.c:lshpack_idx_http_header[] */
/* Note: when adding new items, must replace OTHER in existing code for item */
/* Note: current implementation has limit of 64 htags
 *       Use of htags is an optimization for quick existence checks in lighttpd.
 *       (In the future, these values may also be used to map to HPACK indices.)
 *       However, listing all possible headers here is highly discouraged,
 *       as extending the bitmap greater than 64-bits may make quick bitmasks
 *       check more expensive, and the cost for looking up unmarked headers
 *       (HTTP_HEADER_OTHER) is not substantially more.  In the future, this
 *       list may be revisitied and reviewed, and less frequent headers removed
 *       or replaced.
 */
enum http_header_h2_e { /* pseudo-headers */
  HTTP_HEADER_H2_UNKNOWN         = -1
 ,HTTP_HEADER_H2_AUTHORITY       = -2
 ,HTTP_HEADER_H2_METHOD_GET      = -3
 ,HTTP_HEADER_H2_METHOD_POST     = -4
 ,HTTP_HEADER_H2_PATH            = -5
 ,HTTP_HEADER_H2_PATH_INDEX_HTML = -6
 ,HTTP_HEADER_H2_SCHEME_HTTP     = -7
 ,HTTP_HEADER_H2_SCHEME_HTTPS    = -8
};
enum http_header_e {
  HTTP_HEADER_OTHER = 0
 ,HTTP_HEADER_ACCEPT
 ,HTTP_HEADER_ACCEPT_ENCODING
 ,HTTP_HEADER_ACCEPT_LANGUAGE
 ,HTTP_HEADER_ACCEPT_RANGES
 ,HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN
 ,HTTP_HEADER_AGE
 ,HTTP_HEADER_ALLOW
 ,HTTP_HEADER_ALT_SVC
 ,HTTP_HEADER_ALT_USED
 ,HTTP_HEADER_AUTHORIZATION
 ,HTTP_HEADER_CACHE_CONTROL
 ,HTTP_HEADER_CONNECTION
 ,HTTP_HEADER_CONTENT_ENCODING
 ,HTTP_HEADER_CONTENT_LENGTH
 ,HTTP_HEADER_CONTENT_LOCATION
 ,HTTP_HEADER_CONTENT_RANGE
 ,HTTP_HEADER_CONTENT_SECURITY_POLICY
 ,HTTP_HEADER_CONTENT_TYPE
 ,HTTP_HEADER_COOKIE
 ,HTTP_HEADER_DATE
 ,HTTP_HEADER_DNT
 ,HTTP_HEADER_ETAG
 ,HTTP_HEADER_EXPECT
 ,HTTP_HEADER_EXPECT_CT
 ,HTTP_HEADER_EXPIRES
 ,HTTP_HEADER_FORWARDED
 ,HTTP_HEADER_HOST
 ,HTTP_HEADER_HTTP2_SETTINGS
 ,HTTP_HEADER_IF_MATCH
 ,HTTP_HEADER_IF_MODIFIED_SINCE
 ,HTTP_HEADER_IF_NONE_MATCH
 ,HTTP_HEADER_IF_RANGE
 ,HTTP_HEADER_IF_UNMODIFIED_SINCE
 ,HTTP_HEADER_LAST_MODIFIED
 ,HTTP_HEADER_LINK
 ,HTTP_HEADER_LOCATION
 ,HTTP_HEADER_ONION_LOCATION
 ,HTTP_HEADER_P3P
 ,HTTP_HEADER_PRAGMA
 ,HTTP_HEADER_RANGE
 ,HTTP_HEADER_REFERER
 ,HTTP_HEADER_REFERRER_POLICY
 ,HTTP_HEADER_SERVER
 ,HTTP_HEADER_SET_COOKIE
 ,HTTP_HEADER_STATUS
 ,HTTP_HEADER_STRICT_TRANSPORT_SECURITY
 ,HTTP_HEADER_TE
 ,HTTP_HEADER_TRANSFER_ENCODING
 ,HTTP_HEADER_UPGRADE
 ,HTTP_HEADER_UPGRADE_INSECURE_REQUESTS
 ,HTTP_HEADER_USER_AGENT
 ,HTTP_HEADER_VARY
 ,HTTP_HEADER_WWW_AUTHENTICATE
 ,HTTP_HEADER_X_CONTENT_TYPE_OPTIONS
 ,HTTP_HEADER_X_FORWARDED_FOR
 ,HTTP_HEADER_X_FORWARDED_PROTO
 ,HTTP_HEADER_X_FRAME_OPTIONS
 ,HTTP_HEADER_X_XSS_PROTECTION
};

__attribute_pure__
enum http_header_e http_header_hkey_get(const char *s, size_t slen);
__attribute_pure__
enum http_header_e http_header_hkey_get_lc(const char *s, size_t slen);

__attribute_pure__
int http_header_str_to_code (const char * const s);

__attribute_pure__
int http_header_str_contains_token (const char *s, uint32_t slen, const char *m, uint32_t mlen);

int http_header_remove_token (buffer * const b, const char * const m, const uint32_t mlen);

__attribute_pure__
buffer * http_header_response_get(const request_st *r, enum http_header_e id, const char *k, uint32_t klen);
__attribute_returns_nonnull__
buffer * http_header_response_set_ptr(request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_response_unset(request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_response_set(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_response_append(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_response_insert(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);

__attribute_pure__
buffer * http_header_request_get(const request_st *r, enum http_header_e id, const char *k, uint32_t klen);
__attribute_returns_nonnull__
buffer * http_header_request_set_ptr(request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_request_unset(request_st *r, enum http_header_e id, const char *k, uint32_t klen);
void http_header_request_set(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_request_append(request_st *r, enum http_header_e id, const char *k, uint32_t klen, const char *v, uint32_t vlen);

__attribute_pure__
buffer * http_header_env_get(const request_st *r, const char *k, uint32_t klen);
__attribute_returns_nonnull__
buffer * http_header_env_set_ptr(request_st *r, const char *k, uint32_t klen);
void http_header_env_set(request_st *r, const char *k, uint32_t klen, const char *v, uint32_t vlen);
void http_header_env_append(request_st *r, const char *k, uint32_t klen, const char *v, uint32_t vlen);

__attribute_hot__
uint32_t http_header_parse_hoff (const char *n, const uint32_t clen, unsigned short hoff[8192]);

#endif
