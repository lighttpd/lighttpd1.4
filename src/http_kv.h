#ifndef INCLUDED_HTTP_KV_H
#define INCLUDED_HTTP_KV_H
#include "first.h"

#include "buffer.h"

/* sources:
 * - [RFC2616], Section 9
 *   (or http://tools.ietf.org/html/draft-ietf-httpbis-p2-semantics-22)
 * - http://tools.ietf.org/html/draft-ietf-httpbis-method-registrations-11, Appendix A
 *
 * http://tools.ietf.org/html/draft-ietf-httpbis-p2-semantics-22, Section 8.1 defines
 * a new registry (not available yet):
 *   http://www.iana.org/assignments/http-methods
 */

typedef enum {
	HTTP_METHOD_PRI = -2,          /* [RFC7540], Section 3.5 */
	HTTP_METHOD_UNSET = -1,
	HTTP_METHOD_GET,               /* [RFC2616], Section 9.3 */
	HTTP_METHOD_HEAD,              /* [RFC2616], Section 9.4 */
	HTTP_METHOD_QUERY,             /* [RFCxxxx], Section 2 */
	HTTP_METHOD_POST,              /* [RFC2616], Section 9.5 */
	HTTP_METHOD_PUT,               /* [RFC2616], Section 9.6 */
	HTTP_METHOD_DELETE,            /* [RFC2616], Section 9.7 */
	HTTP_METHOD_CONNECT,           /* [RFC2616], Section 9.9 */
	HTTP_METHOD_OPTIONS,           /* [RFC2616], Section 9.2 */
	HTTP_METHOD_TRACE,             /* [RFC2616], Section 9.8 */
	HTTP_METHOD_ACL,               /* [RFC3744], Section 8.1 */
	HTTP_METHOD_BASELINE_CONTROL,  /* [RFC3253], Section 12.6 */
	HTTP_METHOD_BIND,              /* [RFC5842], Section 4 */
	HTTP_METHOD_CHECKIN,           /* [RFC3253], Section 4.4 and [RFC3253], Section 9.4 */
	HTTP_METHOD_CHECKOUT,          /* [RFC3253], Section 4.3 and [RFC3253], Section 8.8 */
	HTTP_METHOD_COPY,              /* [RFC4918], Section 9.8 */
	HTTP_METHOD_LABEL,             /* [RFC3253], Section 8.2 */
	HTTP_METHOD_LINK,              /* [RFC2068], Section 19.6.1.2 */
	HTTP_METHOD_LOCK,              /* [RFC4918], Section 9.10 */
	HTTP_METHOD_MERGE,             /* [RFC3253], Section 11.2 */
	HTTP_METHOD_MKACTIVITY,        /* [RFC3253], Section 13.5 */
	HTTP_METHOD_MKCALENDAR,        /* [RFC4791], Section 5.3.1 */
	HTTP_METHOD_MKCOL,             /* [RFC4918], Section 9.3 */
	HTTP_METHOD_MKREDIRECTREF,     /* [RFC4437], Section 6 */
	HTTP_METHOD_MKWORKSPACE,       /* [RFC3253], Section 6.3 */
	HTTP_METHOD_MOVE,              /* [RFC4918], Section 9.9 */
	HTTP_METHOD_ORDERPATCH,        /* [RFC3648], Section 7 */
	HTTP_METHOD_PATCH,             /* [RFC5789], Section 2 */
	HTTP_METHOD_PROPFIND,          /* [RFC4918], Section 9.1 */
	HTTP_METHOD_PROPPATCH,         /* [RFC4918], Section 9.2 */
	HTTP_METHOD_REBIND,            /* [RFC5842], Section 6 */
	HTTP_METHOD_REPORT,            /* [RFC3253], Section 3.6 */
	HTTP_METHOD_SEARCH,            /* [RFC5323], Section 2 */
	HTTP_METHOD_UNBIND,            /* [RFC5842], Section 5 */
	HTTP_METHOD_UNCHECKOUT,        /* [RFC3253], Section 4.5 */
	HTTP_METHOD_UNLINK,            /* [RFC2068], Section 19.6.1.3 */
	HTTP_METHOD_UNLOCK,            /* [RFC4918], Section 9.11 */
	HTTP_METHOD_UPDATE,            /* [RFC3253], Section 7.1 */
	HTTP_METHOD_UPDATEREDIRECTREF, /* [RFC4437], Section 7 */
	HTTP_METHOD_VERSION_CONTROL    /* [RFC3253], Section 3.5 */
} http_method_t;

typedef enum {
    HTTP_VERSION_UNSET = -1
   ,HTTP_VERSION_1_0
   ,HTTP_VERSION_1_1
   ,HTTP_VERSION_2
   ,HTTP_VERSION_3
} http_version_t;

__attribute_pure__
__attribute_returns_nonnull__
const buffer *http_version_buf (http_version_t i);

__attribute_pure__
__attribute_returns_nonnull__
const buffer *http_method_buf (http_method_t i);

__attribute_nonnull__()
__attribute_pure__
http_method_t http_method_key_get (const char *s, size_t slen);

__attribute_nonnull__()
void http_status_append (buffer *b, int status);

#define http_method_get_or_head(method)         ((method) <= HTTP_METHOD_HEAD)
#define http_method_get_head_query(method)      ((method) <= HTTP_METHOD_QUERY)
#define http_method_get_head_query_post(method) ((method) <= HTTP_METHOD_POST)

__attribute_nonnull__()
static inline void http_version_append (buffer * const b, const http_version_t version);
static inline void http_version_append (buffer * const b, const http_version_t version)
{
    buffer_append_buffer(b, http_version_buf(version));
}

__attribute_nonnull__()
static inline void http_method_append (buffer * const b, const http_method_t method);
static inline void http_method_append (buffer * const b, const http_method_t method)
{
    buffer_append_buffer(b, http_method_buf(method));
}


#endif
