#include "first.h"

#include "http_kv.h"
#include "buffer.h"

#include <string.h>

typedef struct {
	int key;
	const char *value;
	size_t vlen;
} keyvalue;

static const keyvalue http_versions[] = {
	{ HTTP_VERSION_1_1, CONST_STR_LEN("HTTP/1.1") },
	{ HTTP_VERSION_1_0, CONST_STR_LEN("HTTP/1.0") },
	{ HTTP_VERSION_UNSET, NULL, 0 }
};

static const keyvalue http_methods[] = {
	{ HTTP_METHOD_GET,                 CONST_STR_LEN("GET") },
	{ HTTP_METHOD_HEAD,                CONST_STR_LEN("HEAD") },
	{ HTTP_METHOD_POST,                CONST_STR_LEN("POST") },
	{ HTTP_METHOD_PUT,                 CONST_STR_LEN("PUT") },
	{ HTTP_METHOD_DELETE,              CONST_STR_LEN("DELETE") },
	{ HTTP_METHOD_CONNECT,             CONST_STR_LEN("CONNECT") },
	{ HTTP_METHOD_OPTIONS,             CONST_STR_LEN("OPTIONS") },
	{ HTTP_METHOD_TRACE,               CONST_STR_LEN("TRACE") },
	{ HTTP_METHOD_ACL,                 CONST_STR_LEN("ACL") },
	{ HTTP_METHOD_BASELINE_CONTROL,    CONST_STR_LEN("BASELINE-CONTROL") },
	{ HTTP_METHOD_BIND,                CONST_STR_LEN("BIND") },
	{ HTTP_METHOD_CHECKIN,             CONST_STR_LEN("CHECKIN") },
	{ HTTP_METHOD_CHECKOUT,            CONST_STR_LEN("CHECKOUT") },
	{ HTTP_METHOD_COPY,                CONST_STR_LEN("COPY") },
	{ HTTP_METHOD_LABEL,               CONST_STR_LEN("LABEL") },
	{ HTTP_METHOD_LINK,                CONST_STR_LEN("LINK") },
	{ HTTP_METHOD_LOCK,                CONST_STR_LEN("LOCK") },
	{ HTTP_METHOD_MERGE,               CONST_STR_LEN("MERGE") },
	{ HTTP_METHOD_MKACTIVITY,          CONST_STR_LEN("MKACTIVITY") },
	{ HTTP_METHOD_MKCALENDAR,          CONST_STR_LEN("MKCALENDAR") },
	{ HTTP_METHOD_MKCOL,               CONST_STR_LEN("MKCOL") },
	{ HTTP_METHOD_MKREDIRECTREF,       CONST_STR_LEN("MKREDIRECTREF") },
	{ HTTP_METHOD_MKWORKSPACE,         CONST_STR_LEN("MKWORKSPACE") },
	{ HTTP_METHOD_MOVE,                CONST_STR_LEN("MOVE") },
	{ HTTP_METHOD_ORDERPATCH,          CONST_STR_LEN("ORDERPATCH") },
	{ HTTP_METHOD_PATCH,               CONST_STR_LEN("PATCH") },
	{ HTTP_METHOD_PROPFIND,            CONST_STR_LEN("PROPFIND") },
	{ HTTP_METHOD_PROPPATCH,           CONST_STR_LEN("PROPPATCH") },
	{ HTTP_METHOD_REBIND,              CONST_STR_LEN("REBIND") },
	{ HTTP_METHOD_REPORT,              CONST_STR_LEN("REPORT") },
	{ HTTP_METHOD_SEARCH,              CONST_STR_LEN("SEARCH") },
	{ HTTP_METHOD_UNBIND,              CONST_STR_LEN("UNBIND") },
	{ HTTP_METHOD_UNCHECKOUT,          CONST_STR_LEN("UNCHECKOUT") },
	{ HTTP_METHOD_UNLINK,              CONST_STR_LEN("UNLINK") },
	{ HTTP_METHOD_UNLOCK,              CONST_STR_LEN("UNLOCK") },
	{ HTTP_METHOD_UPDATE,              CONST_STR_LEN("UPDATE") },
	{ HTTP_METHOD_UPDATEREDIRECTREF,   CONST_STR_LEN("UPDATEREDIRECTREF") },
	{ HTTP_METHOD_VERSION_CONTROL,     CONST_STR_LEN("VERSION-CONTROL") },

	{ HTTP_METHOD_UNSET, NULL, 0 }
};

static const keyvalue http_status[] = {
	{ 100, CONST_STR_LEN("100 Continue") },
	{ 101, CONST_STR_LEN("101 Switching Protocols") },
	{ 102, CONST_STR_LEN("102 Processing") }, /* WebDAV */
	{ 200, CONST_STR_LEN("200 OK") },
	{ 201, CONST_STR_LEN("201 Created") },
	{ 202, CONST_STR_LEN("202 Accepted") },
	{ 203, CONST_STR_LEN("203 Non-Authoritative Information") },
	{ 204, CONST_STR_LEN("204 No Content") },
	{ 205, CONST_STR_LEN("205 Reset Content") },
	{ 206, CONST_STR_LEN("206 Partial Content") },
	{ 207, CONST_STR_LEN("207 Multi-status") }, /* WebDAV */
	{ 300, CONST_STR_LEN("300 Multiple Choices") },
	{ 301, CONST_STR_LEN("301 Moved Permanently") },
	{ 302, CONST_STR_LEN("302 Found") },
	{ 303, CONST_STR_LEN("303 See Other") },
	{ 304, CONST_STR_LEN("304 Not Modified") },
	{ 305, CONST_STR_LEN("305 Use Proxy") },
	{ 306, CONST_STR_LEN("306 (Unused)") },
	{ 307, CONST_STR_LEN("307 Temporary Redirect") },
	{ 308, CONST_STR_LEN("308 Permanent Redirect") },
	{ 400, CONST_STR_LEN("400 Bad Request") },
	{ 401, CONST_STR_LEN("401 Unauthorized") },
	{ 402, CONST_STR_LEN("402 Payment Required") },
	{ 403, CONST_STR_LEN("403 Forbidden") },
	{ 404, CONST_STR_LEN("404 Not Found") },
	{ 405, CONST_STR_LEN("405 Method Not Allowed") },
	{ 406, CONST_STR_LEN("406 Not Acceptable") },
	{ 407, CONST_STR_LEN("407 Proxy Authentication Required") },
	{ 408, CONST_STR_LEN("408 Request Timeout") },
	{ 409, CONST_STR_LEN("409 Conflict") },
	{ 410, CONST_STR_LEN("410 Gone") },
	{ 411, CONST_STR_LEN("411 Length Required") },
	{ 412, CONST_STR_LEN("412 Precondition Failed") },
	{ 413, CONST_STR_LEN("413 Request Entity Too Large") },
	{ 414, CONST_STR_LEN("414 Request-URI Too Long") },
	{ 415, CONST_STR_LEN("415 Unsupported Media Type") },
	{ 416, CONST_STR_LEN("416 Requested Range Not Satisfiable") },
	{ 417, CONST_STR_LEN("417 Expectation Failed") },
	{ 422, CONST_STR_LEN("422 Unprocessable Entity") }, /* WebDAV */
	{ 423, CONST_STR_LEN("423 Locked") }, /* WebDAV */
	{ 424, CONST_STR_LEN("424 Failed Dependency") }, /* WebDAV */
	{ 426, CONST_STR_LEN("426 Upgrade Required") }, /* TLS */
	{ 500, CONST_STR_LEN("500 Internal Server Error") },
	{ 501, CONST_STR_LEN("501 Not Implemented") },
	{ 502, CONST_STR_LEN("502 Bad Gateway") },
	{ 503, CONST_STR_LEN("503 Service Not Available") },
	{ 504, CONST_STR_LEN("504 Gateway Timeout") },
	{ 505, CONST_STR_LEN("505 HTTP Version Not Supported") },
	{ 507, CONST_STR_LEN("507 Insufficient Storage") }, /* WebDAV */

	{ -1, NULL, 0 }
};


static const char *keyvalue_get_value(const keyvalue *kv, int k) {
	int i;
	for (i = 0; kv[i].value; i++) {
		if (kv[i].key == k) return kv[i].value;
	}
	return NULL;
}

static int keyvalue_get_key(const keyvalue *kv, const char *s) {
	int i;
	for (i = 0; kv[i].value; i++) {
		if (0 == strcmp(kv[i].value, s)) return kv[i].key;
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

int get_http_version_key(const char *s) {
	return keyvalue_get_key(http_versions, s);
}

http_method_t get_http_method_key(const char *s) {
	return (http_method_t)keyvalue_get_key(http_methods, s);
}


void http_status_append(buffer * const b, const int status) {
    const keyvalue * const kv = http_status;
    int i;
    for (i = 0; kv[i].key != status && kv[i].value; ++i) ;
    if (kv[i].value) {
        buffer_append_string_len(b, kv[i].value, kv[i].vlen);
    }
    else {
        buffer_append_int(b, status);
        buffer_append_string_len(b, CONST_STR_LEN(" "));
    }
}
