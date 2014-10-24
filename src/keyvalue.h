#ifndef _KEY_VALUE_H_
#define _KEY_VALUE_H_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_PCRE_H
# include <pcre.h>
#endif

struct server;

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
	HTTP_METHOD_UNSET = -1,
	HTTP_METHOD_GET,               /* [RFC2616], Section 9.3 */
	HTTP_METHOD_HEAD,              /* [RFC2616], Section 9.4 */
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

typedef enum { HTTP_VERSION_UNSET = -1, HTTP_VERSION_1_0, HTTP_VERSION_1_1 } http_version_t;
/*It can save some storage space*/
typedef enum {
	HTTP_VERSIONS	= 0,
	HTTP_METHODS		= 0,
	HTTP_STATUS		= 100,
	HTTP_STATUS_BODY= 400
} keyvalue_t;

/*remove the old keyvalue's definition, instead, We used typedef char* keyvalue;*/
typedef char* keyvalue;

#if 0
typedef struct {
	int key;

	char *value;
} keyvalue;
#endif

typedef struct {
	char *key;

	char *value;
} s_keyvalue;

typedef struct {
#ifdef HAVE_PCRE_H
	pcre *key;
	pcre_extra *key_extra;
#endif

	buffer *value;
} pcre_keyvalue;

typedef enum { HTTP_AUTH_BASIC, HTTP_AUTH_DIGEST } httpauth_type;

typedef struct {
	char *key;

	char *realm;
	httpauth_type type;
} httpauth_keyvalue;

#define KVB(x) \
typedef struct {\
	x **kv; \
	size_t used;\
	size_t size;\
} x ## _buffer

KVB(keyvalue);
KVB(s_keyvalue);
KVB(httpauth_keyvalue);
KVB(pcre_keyvalue);

void set_http_status(keyvalue *kv, int key, const char *value);

/*init http_status, It will be invocating in the function of server_init()*/
#define INIT_HTTP_STATUS()	\
		set_http_status(http_status, 100, "Continue");	\
		set_http_status(http_status, 101, "Switching Protocols");	\
		set_http_status(http_status, 200, "OK");	\
		set_http_status(http_status, 201, "Created");	\
		set_http_status(http_status, 202, "Accepted");	\
		set_http_status(http_status, 203, "Non-Authoritative Information");	\
		set_http_status(http_status, 204, "No Content");	\
		set_http_status(http_status, 205, "Reset Content");	\
		set_http_status(http_status, 206, "Partial Content");	\
		set_http_status(http_status, 207, "Multi-status");	\
		set_http_status(http_status, 300, "Multiple Choices");	\
		set_http_status(http_status, 301, "Moved Permanently");	\
		set_http_status(http_status, 302, "Found");	\
		set_http_status(http_status, 303, "See Other");	\
		set_http_status(http_status, 304, "Not Modified");	\
		set_http_status(http_status, 305, "Use Proxy");	\
		set_http_status(http_status, 306, "(Unused)");	\
		set_http_status(http_status, 307, "Temporary Redirect");	\
		set_http_status(http_status, 400, "Bad Request");	\
		set_http_status(http_status, 401, "Unauthorized");	\
		set_http_status(http_status, 402, "Payment Required");	\
		set_http_status(http_status, 403, "Forbidden");	\
		set_http_status(http_status, 404, "Not Found");	\
		set_http_status(http_status, 405, "Method Not Allowed");	\
		set_http_status(http_status, 406, "Not Acceptable");	\
		set_http_status(http_status, 407, "Proxy Authentication Required");	\
		set_http_status(http_status, 408, "Request Timeout");	\
		set_http_status(http_status, 409, "Conflict");	\
		set_http_status(http_status, 410, "Gone");	\
		set_http_status(http_status, 411, "Length Required");	\
		set_http_status(http_status, 412, "Precondition Failed");	\
		set_http_status(http_status, 413, "Request Entity Too Large");	\
		set_http_status(http_status, 414, "Request-URI Too Long");	\
		set_http_status(http_status, 415, "Unsupported Media Type");	\
		set_http_status(http_status, 416, "Requested Range Not Satisfiable");	\
		set_http_status(http_status, 417, "Expectation Failed");	\
		set_http_status(http_status, 422, "Unprocessable Entity");	\
		set_http_status(http_status, 423, "Locked");	\
		set_http_status(http_status, 424, "Failed Dependency");	\
		set_http_status(http_status, 426, "Upgrade Required");	\
		set_http_status(http_status, 500, "Internal Server Error");	\
		set_http_status(http_status, 501, "Not Implemented");	\
		set_http_status(http_status, 502, "Bad Gateway");	\
		set_http_status(http_status, 503, "Service Not Available");	\
		set_http_status(http_status, 504, "Gateway Timeout");	\
		set_http_status(http_status, 505, "HTTP Version Not Supported");	\
		set_http_status(http_status, 507, "Insufficient Storage");	\
		set_http_status(http_status, -1, NULL);	\


const char *get_http_status_name(int i);
const char *get_http_version_name(int i);
const char *get_http_method_name(http_method_t i);
const char *get_http_status_body_name(int i);
int get_http_version_key(const char *s);
http_method_t get_http_method_key(const char *s);

const char *keyvalue_get_value_by_keyvalue_t(keyvalue *kv, int k, keyvalue_t kt);
int keyvalue_get_key_by_keyvalue_t(keyvalue *kv, const char *s, keyvalue_t kt);
#if 0
const char *keyvalue_get_value(keyvalue *kv, int k);
int keyvalue_get_key(keyvalue *kv, const char *s);
#endif
/*Since we never used the keyvalue_buffer, So we remove all of them directly.Centerly,It's might not good*/
#if 0
keyvalue_buffer *keyvalue_buffer_init(void);
int keyvalue_buffer_append(keyvalue_buffer *kvb, int k, const char *value);
void keyvalue_buffer_free(keyvalue_buffer *kvb);
#endif
s_keyvalue_buffer *s_keyvalue_buffer_init(void);
int s_keyvalue_buffer_append(s_keyvalue_buffer *kvb, const char *key, const char *value);
void s_keyvalue_buffer_free(s_keyvalue_buffer *kvb);

httpauth_keyvalue_buffer *httpauth_keyvalue_buffer_init(void);
int httpauth_keyvalue_buffer_append(httpauth_keyvalue_buffer *kvb, const char *key, const char *realm, httpauth_type type);
void httpauth_keyvalue_buffer_free(httpauth_keyvalue_buffer *kvb);

pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void);
int pcre_keyvalue_buffer_append(struct server *srv, pcre_keyvalue_buffer *kvb, const char *key, const char *value);
void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb);

#endif
