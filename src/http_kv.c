#include "first.h"

#include "http_kv.h"
#include "buffer.h"

#include <string.h>

#define CONST_LEN_STR(x) (unsigned int)sizeof(x)-1, (x)

typedef struct {
	int key;
	unsigned int vlen;
	const char *value;
} keyvalue;

static const keyvalue http_versions[] = {
	{ HTTP_VERSION_1_1, CONST_LEN_STR("HTTP/1.1") },
	{ HTTP_VERSION_1_0, CONST_LEN_STR("HTTP/1.0") },
	{ HTTP_VERSION_UNSET, 0, NULL }
};

static const keyvalue http_methods[] = {
	{ HTTP_METHOD_GET,                 CONST_LEN_STR("GET") },
	{ HTTP_METHOD_HEAD,                CONST_LEN_STR("HEAD") },
	{ HTTP_METHOD_POST,                CONST_LEN_STR("POST") },
	{ HTTP_METHOD_PUT,                 CONST_LEN_STR("PUT") },
	{ HTTP_METHOD_DELETE,              CONST_LEN_STR("DELETE") },
	{ HTTP_METHOD_CONNECT,             CONST_LEN_STR("CONNECT") },
	{ HTTP_METHOD_OPTIONS,             CONST_LEN_STR("OPTIONS") },
	{ HTTP_METHOD_TRACE,               CONST_LEN_STR("TRACE") },
	{ HTTP_METHOD_ACL,                 CONST_LEN_STR("ACL") },
	{ HTTP_METHOD_BASELINE_CONTROL,    CONST_LEN_STR("BASELINE-CONTROL") },
	{ HTTP_METHOD_BIND,                CONST_LEN_STR("BIND") },
	{ HTTP_METHOD_CHECKIN,             CONST_LEN_STR("CHECKIN") },
	{ HTTP_METHOD_CHECKOUT,            CONST_LEN_STR("CHECKOUT") },
	{ HTTP_METHOD_COPY,                CONST_LEN_STR("COPY") },
	{ HTTP_METHOD_LABEL,               CONST_LEN_STR("LABEL") },
	{ HTTP_METHOD_LINK,                CONST_LEN_STR("LINK") },
	{ HTTP_METHOD_LOCK,                CONST_LEN_STR("LOCK") },
	{ HTTP_METHOD_MERGE,               CONST_LEN_STR("MERGE") },
	{ HTTP_METHOD_MKACTIVITY,          CONST_LEN_STR("MKACTIVITY") },
	{ HTTP_METHOD_MKCALENDAR,          CONST_LEN_STR("MKCALENDAR") },
	{ HTTP_METHOD_MKCOL,               CONST_LEN_STR("MKCOL") },
	{ HTTP_METHOD_MKREDIRECTREF,       CONST_LEN_STR("MKREDIRECTREF") },
	{ HTTP_METHOD_MKWORKSPACE,         CONST_LEN_STR("MKWORKSPACE") },
	{ HTTP_METHOD_MOVE,                CONST_LEN_STR("MOVE") },
	{ HTTP_METHOD_ORDERPATCH,          CONST_LEN_STR("ORDERPATCH") },
	{ HTTP_METHOD_PATCH,               CONST_LEN_STR("PATCH") },
	{ HTTP_METHOD_PROPFIND,            CONST_LEN_STR("PROPFIND") },
	{ HTTP_METHOD_PROPPATCH,           CONST_LEN_STR("PROPPATCH") },
	{ HTTP_METHOD_REBIND,              CONST_LEN_STR("REBIND") },
	{ HTTP_METHOD_REPORT,              CONST_LEN_STR("REPORT") },
	{ HTTP_METHOD_SEARCH,              CONST_LEN_STR("SEARCH") },
	{ HTTP_METHOD_UNBIND,              CONST_LEN_STR("UNBIND") },
	{ HTTP_METHOD_UNCHECKOUT,          CONST_LEN_STR("UNCHECKOUT") },
	{ HTTP_METHOD_UNLINK,              CONST_LEN_STR("UNLINK") },
	{ HTTP_METHOD_UNLOCK,              CONST_LEN_STR("UNLOCK") },
	{ HTTP_METHOD_UPDATE,              CONST_LEN_STR("UPDATE") },
	{ HTTP_METHOD_UPDATEREDIRECTREF,   CONST_LEN_STR("UPDATEREDIRECTREF") },
	{ HTTP_METHOD_VERSION_CONTROL,     CONST_LEN_STR("VERSION-CONTROL") },

	{ HTTP_METHOD_UNSET, 0, NULL }
};

static const keyvalue http_status[] = {
	{ 100, CONST_LEN_STR("100 Continue") },
	{ 101, CONST_LEN_STR("101 Switching Protocols") },
	{ 102, CONST_LEN_STR("102 Processing") }, /* WebDAV */
	{ 200, CONST_LEN_STR("200 OK") },
	{ 201, CONST_LEN_STR("201 Created") },
	{ 202, CONST_LEN_STR("202 Accepted") },
	{ 203, CONST_LEN_STR("203 Non-Authoritative Information") },
	{ 204, CONST_LEN_STR("204 No Content") },
	{ 205, CONST_LEN_STR("205 Reset Content") },
	{ 206, CONST_LEN_STR("206 Partial Content") },
	{ 207, CONST_LEN_STR("207 Multi-status") }, /* WebDAV */
	{ 300, CONST_LEN_STR("300 Multiple Choices") },
	{ 301, CONST_LEN_STR("301 Moved Permanently") },
	{ 302, CONST_LEN_STR("302 Found") },
	{ 303, CONST_LEN_STR("303 See Other") },
	{ 304, CONST_LEN_STR("304 Not Modified") },
	{ 305, CONST_LEN_STR("305 Use Proxy") },
	{ 306, CONST_LEN_STR("306 (Unused)") },
	{ 307, CONST_LEN_STR("307 Temporary Redirect") },
	{ 308, CONST_LEN_STR("308 Permanent Redirect") },
	{ 400, CONST_LEN_STR("400 Bad Request") },
	{ 401, CONST_LEN_STR("401 Unauthorized") },
	{ 402, CONST_LEN_STR("402 Payment Required") },
	{ 403, CONST_LEN_STR("403 Forbidden") },
	{ 404, CONST_LEN_STR("404 Not Found") },
	{ 405, CONST_LEN_STR("405 Method Not Allowed") },
	{ 406, CONST_LEN_STR("406 Not Acceptable") },
	{ 407, CONST_LEN_STR("407 Proxy Authentication Required") },
	{ 408, CONST_LEN_STR("408 Request Timeout") },
	{ 409, CONST_LEN_STR("409 Conflict") },
	{ 410, CONST_LEN_STR("410 Gone") },
	{ 411, CONST_LEN_STR("411 Length Required") },
	{ 412, CONST_LEN_STR("412 Precondition Failed") },
	{ 413, CONST_LEN_STR("413 Request Entity Too Large") },
	{ 414, CONST_LEN_STR("414 Request-URI Too Long") },
	{ 415, CONST_LEN_STR("415 Unsupported Media Type") },
	{ 416, CONST_LEN_STR("416 Requested Range Not Satisfiable") },
	{ 417, CONST_LEN_STR("417 Expectation Failed") },
	{ 422, CONST_LEN_STR("422 Unprocessable Entity") }, /* WebDAV */
	{ 423, CONST_LEN_STR("423 Locked") }, /* WebDAV */
	{ 424, CONST_LEN_STR("424 Failed Dependency") }, /* WebDAV */
	{ 426, CONST_LEN_STR("426 Upgrade Required") }, /* TLS */
	{ 500, CONST_LEN_STR("500 Internal Server Error") },
	{ 501, CONST_LEN_STR("501 Not Implemented") },
	{ 502, CONST_LEN_STR("502 Bad Gateway") },
	{ 503, CONST_LEN_STR("503 Service Not Available") },
	{ 504, CONST_LEN_STR("504 Gateway Timeout") },
	{ 505, CONST_LEN_STR("505 HTTP Version Not Supported") },
	{ 507, CONST_LEN_STR("507 Insufficient Storage") }, /* WebDAV */

	{ -1, 0, NULL }
};


static const char *keyvalue_get_value(const keyvalue *kv, int k) {
	int i;
	for (i = 0; kv[i].value; i++) {
		if (kv[i].key == k) return kv[i].value;
	}
	return NULL;
}

static int keyvalue_get_key(const keyvalue *kv, const char *s, unsigned int slen) {
	for (int i = 0; kv[i].vlen; ++i) {
		if (kv[i].vlen == slen && 0 == memcmp(kv[i].value, s, slen))
			return kv[i].key;
	}
	return -1;
}


const char *get_http_version_name(int i) {
	return keyvalue_get_value(http_versions, i);
}

const char *get_http_status_name(int i) {
	return keyvalue_get_value(http_status, i);
}

const char *get_http_method_name(http_method_t i) {
	return keyvalue_get_value(http_methods, i);
}

int get_http_version_key(const char *s, size_t slen) {
    return keyvalue_get_key(http_versions, s, (unsigned int)slen);
}

http_method_t get_http_method_key(const char *s, size_t slen) {
    return (http_method_t)keyvalue_get_key(http_methods, s, (unsigned int)slen);
}


void http_status_append(buffer * const b, const int status) {
    const keyvalue * const kv = http_status;
    int i;
    for (i = 0; kv[i].key != status && kv[i].vlen; ++i) ;
    if (kv[i].vlen) {
        buffer_append_string_len(b, kv[i].value, kv[i].vlen);
    }
    else {
        buffer_append_int(b, status);
        buffer_append_string_len(b, CONST_STR_LEN(" "));
    }
}

void http_method_append(buffer * const b, const http_method_t method) {
    const keyvalue * const kv = http_methods;
    int i;
    for (i = 0; kv[i].key != method && kv[i].vlen; ++i) ;
    if (kv[i].vlen) {
        buffer_append_string_len(b, kv[i].value, kv[i].vlen);
    }
}
