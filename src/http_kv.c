#include "first.h"

#include "http_kv.h"

#include <string.h>

typedef struct {
	int key;
	const char *value;
} keyvalue;

static const keyvalue http_versions[] = {
	{ HTTP_VERSION_1_1, "HTTP/1.1" },
	{ HTTP_VERSION_1_0, "HTTP/1.0" },
	{ HTTP_VERSION_UNSET, NULL }
};

static const keyvalue http_methods[] = {
	{ HTTP_METHOD_GET, "GET" },
	{ HTTP_METHOD_HEAD, "HEAD" },
	{ HTTP_METHOD_POST, "POST" },
	{ HTTP_METHOD_PUT, "PUT" },
	{ HTTP_METHOD_DELETE, "DELETE" },
	{ HTTP_METHOD_CONNECT, "CONNECT" },
	{ HTTP_METHOD_OPTIONS, "OPTIONS" },
	{ HTTP_METHOD_TRACE, "TRACE" },
	{ HTTP_METHOD_ACL, "ACL" },
	{ HTTP_METHOD_BASELINE_CONTROL, "BASELINE-CONTROL" },
	{ HTTP_METHOD_BIND, "BIND" },
	{ HTTP_METHOD_CHECKIN, "CHECKIN" },
	{ HTTP_METHOD_CHECKOUT, "CHECKOUT" },
	{ HTTP_METHOD_COPY, "COPY" },
	{ HTTP_METHOD_LABEL, "LABEL" },
	{ HTTP_METHOD_LINK, "LINK" },
	{ HTTP_METHOD_LOCK, "LOCK" },
	{ HTTP_METHOD_MERGE, "MERGE" },
	{ HTTP_METHOD_MKACTIVITY, "MKACTIVITY" },
	{ HTTP_METHOD_MKCALENDAR, "MKCALENDAR" },
	{ HTTP_METHOD_MKCOL, "MKCOL" },
	{ HTTP_METHOD_MKREDIRECTREF, "MKREDIRECTREF" },
	{ HTTP_METHOD_MKWORKSPACE, "MKWORKSPACE" },
	{ HTTP_METHOD_MOVE, "MOVE" },
	{ HTTP_METHOD_ORDERPATCH, "ORDERPATCH" },
	{ HTTP_METHOD_PATCH, "PATCH" },
	{ HTTP_METHOD_PROPFIND, "PROPFIND" },
	{ HTTP_METHOD_PROPPATCH, "PROPPATCH" },
	{ HTTP_METHOD_REBIND, "REBIND" },
	{ HTTP_METHOD_REPORT, "REPORT" },
	{ HTTP_METHOD_SEARCH, "SEARCH" },
	{ HTTP_METHOD_UNBIND, "UNBIND" },
	{ HTTP_METHOD_UNCHECKOUT, "UNCHECKOUT" },
	{ HTTP_METHOD_UNLINK, "UNLINK" },
	{ HTTP_METHOD_UNLOCK, "UNLOCK" },
	{ HTTP_METHOD_UPDATE, "UPDATE" },
	{ HTTP_METHOD_UPDATEREDIRECTREF, "UPDATEREDIRECTREF" },
	{ HTTP_METHOD_VERSION_CONTROL, "VERSION-CONTROL" },

	{ HTTP_METHOD_UNSET, NULL }
};

static const keyvalue http_status[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 102, "Processing" }, /* WebDAV */
	{ 200, "OK" },
	{ 201, "Created" },
	{ 202, "Accepted" },
	{ 203, "Non-Authoritative Information" },
	{ 204, "No Content" },
	{ 205, "Reset Content" },
	{ 206, "Partial Content" },
	{ 207, "Multi-status" }, /* WebDAV */
	{ 300, "Multiple Choices" },
	{ 301, "Moved Permanently" },
	{ 302, "Found" },
	{ 303, "See Other" },
	{ 304, "Not Modified" },
	{ 305, "Use Proxy" },
	{ 306, "(Unused)" },
	{ 307, "Temporary Redirect" },
	{ 308, "Permanent Redirect" },
	{ 400, "Bad Request" },
	{ 401, "Unauthorized" },
	{ 402, "Payment Required" },
	{ 403, "Forbidden" },
	{ 404, "Not Found" },
	{ 405, "Method Not Allowed" },
	{ 406, "Not Acceptable" },
	{ 407, "Proxy Authentication Required" },
	{ 408, "Request Timeout" },
	{ 409, "Conflict" },
	{ 410, "Gone" },
	{ 411, "Length Required" },
	{ 412, "Precondition Failed" },
	{ 413, "Request Entity Too Large" },
	{ 414, "Request-URI Too Long" },
	{ 415, "Unsupported Media Type" },
	{ 416, "Requested Range Not Satisfiable" },
	{ 417, "Expectation Failed" },
	{ 422, "Unprocessable Entity" }, /* WebDAV */
	{ 423, "Locked" }, /* WebDAV */
	{ 424, "Failed Dependency" }, /* WebDAV */
	{ 426, "Upgrade Required" }, /* TLS */
	{ 500, "Internal Server Error" },
	{ 501, "Not Implemented" },
	{ 502, "Bad Gateway" },
	{ 503, "Service Not Available" },
	{ 504, "Gateway Timeout" },
	{ 505, "HTTP Version Not Supported" },
	{ 507, "Insufficient Storage" }, /* WebDAV */

	{ -1, NULL }
};

static const keyvalue http_status_body[] = {
	{ 400, "400.html" },
	{ 401, "401.html" },
	{ 403, "403.html" },
	{ 404, "404.html" },
	{ 411, "411.html" },
	{ 416, "416.html" },
	{ 500, "500.html" },
	{ 501, "501.html" },
	{ 503, "503.html" },
	{ 505, "505.html" },

	{ -1, NULL }
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

const char *get_http_status_body_name(int i) {
	return keyvalue_get_value(http_status_body, i);
}

int get_http_version_key(const char *s) {
	return keyvalue_get_key(http_versions, s);
}

http_method_t get_http_method_key(const char *s) {
	return (http_method_t)keyvalue_get_key(http_methods, s);
}
