/*
 * http_kv - HTTP version, method, status key-value string mapping
 *
 * Fully-rewritten from original
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_kv.h"
#include "buffer.h"

#include <string.h>

typedef struct {
	int key;
	unsigned int vlen;
	const char *value;
} keyvalue;

static const keyvalue http_versions[] = {
	{ HTTP_VERSION_2,   CONST_LEN_STR("HTTP/2.0") }, /* SERVER_PROTOCOL */
	{ HTTP_VERSION_1_1, CONST_LEN_STR("HTTP/1.1") },
	{ HTTP_VERSION_1_0, CONST_LEN_STR("HTTP/1.0") },
	{ HTTP_VERSION_UNSET, 0, NULL }
};

static const buffer http_methods[] = {
	{ CONST_STR_LEN("GET")+1, 0 },
	{ CONST_STR_LEN("HEAD")+1, 0 },
	{ CONST_STR_LEN("POST")+1, 0 },
	{ CONST_STR_LEN("PUT")+1, 0 },
	{ CONST_STR_LEN("DELETE")+1, 0 },
	{ CONST_STR_LEN("CONNECT")+1, 0 },
	{ CONST_STR_LEN("OPTIONS")+1, 0 },
	{ CONST_STR_LEN("TRACE")+1, 0 },
	{ CONST_STR_LEN("ACL")+1, 0 },
	{ CONST_STR_LEN("BASELINE-CONTROL")+1, 0 },
	{ CONST_STR_LEN("BIND")+1, 0 },
	{ CONST_STR_LEN("CHECKIN")+1, 0 },
	{ CONST_STR_LEN("CHECKOUT")+1, 0 },
	{ CONST_STR_LEN("COPY")+1, 0 },
	{ CONST_STR_LEN("LABEL")+1, 0 },
	{ CONST_STR_LEN("LINK")+1, 0 },
	{ CONST_STR_LEN("LOCK")+1, 0 },
	{ CONST_STR_LEN("MERGE")+1, 0 },
	{ CONST_STR_LEN("MKACTIVITY")+1, 0 },
	{ CONST_STR_LEN("MKCALENDAR")+1, 0 },
	{ CONST_STR_LEN("MKCOL")+1, 0 },
	{ CONST_STR_LEN("MKREDIRECTREF")+1, 0 },
	{ CONST_STR_LEN("MKWORKSPACE")+1, 0 },
	{ CONST_STR_LEN("MOVE")+1, 0 },
	{ CONST_STR_LEN("ORDERPATCH")+1, 0 },
	{ CONST_STR_LEN("PATCH")+1, 0 },
	{ CONST_STR_LEN("PROPFIND")+1, 0 },
	{ CONST_STR_LEN("PROPPATCH")+1, 0 },
	{ CONST_STR_LEN("REBIND")+1, 0 },
	{ CONST_STR_LEN("REPORT")+1, 0 },
	{ CONST_STR_LEN("SEARCH")+1, 0 },
	{ CONST_STR_LEN("UNBIND")+1, 0 },
	{ CONST_STR_LEN("UNCHECKOUT")+1, 0 },
	{ CONST_STR_LEN("UNLINK")+1, 0 },
	{ CONST_STR_LEN("UNLOCK")+1, 0 },
	{ CONST_STR_LEN("UPDATE")+1, 0 },
	{ CONST_STR_LEN("UPDATEREDIRECTREF")+1, 0 },
	{ CONST_STR_LEN("VERSION-CONTROL")+1, 0 },

	{ CONST_STR_LEN("PRI")+1, 0 },
	{ "", 0, 0 }
};

/* https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml */
static const keyvalue http_status[] = {
	{ 100, CONST_LEN_STR("100 Continue") },
	{ 101, CONST_LEN_STR("101 Switching Protocols") },
	{ 102, CONST_LEN_STR("102 Processing") }, /* WebDAV */
	{ 103, CONST_LEN_STR("103 Early Hints") },
	{ 200, CONST_LEN_STR("200 OK") },
	{ 201, CONST_LEN_STR("201 Created") },
	{ 202, CONST_LEN_STR("202 Accepted") },
	{ 203, CONST_LEN_STR("203 Non-Authoritative Information") },
	{ 204, CONST_LEN_STR("204 No Content") },
	{ 205, CONST_LEN_STR("205 Reset Content") },
	{ 206, CONST_LEN_STR("206 Partial Content") },
	{ 207, CONST_LEN_STR("207 Multi-status") }, /* WebDAV */
	{ 208, CONST_LEN_STR("208 Already Reported") },
	{ 226, CONST_LEN_STR("226 IM Used") },
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
	{ 413, CONST_LEN_STR("413 Payload Too Large") },
	{ 414, CONST_LEN_STR("414 URI Too Long") },
	{ 415, CONST_LEN_STR("415 Unsupported Media Type") },
	{ 416, CONST_LEN_STR("416 Range Not Satisfiable") },
	{ 417, CONST_LEN_STR("417 Expectation Failed") },
	{ 421, CONST_LEN_STR("421 Misdirected Request") }, /* RFC 7540 */
	{ 422, CONST_LEN_STR("422 Unprocessable Entity") }, /* WebDAV */
	{ 423, CONST_LEN_STR("423 Locked") }, /* WebDAV */
	{ 424, CONST_LEN_STR("424 Failed Dependency") }, /* WebDAV */
	{ 426, CONST_LEN_STR("426 Upgrade Required") }, /* TLS */
	{ 428, CONST_LEN_STR("428 Precondition Required") },
	{ 429, CONST_LEN_STR("429 Too Many Requests") },
	{ 431, CONST_LEN_STR("431 Request Header Fields Too Large") },
	{ 451, CONST_LEN_STR("451 Unavailable For Legal Reasons") },
	{ 500, CONST_LEN_STR("500 Internal Server Error") },
	{ 501, CONST_LEN_STR("501 Not Implemented") },
	{ 502, CONST_LEN_STR("502 Bad Gateway") },
	{ 503, CONST_LEN_STR("503 Service Unavailable") },
	{ 504, CONST_LEN_STR("504 Gateway Timeout") },
	{ 505, CONST_LEN_STR("505 HTTP Version Not Supported") },
	{ 506, CONST_LEN_STR("506 Variant Also Negotiates") },
	{ 507, CONST_LEN_STR("507 Insufficient Storage") }, /* WebDAV */
	{ 508, CONST_LEN_STR("508 Loop Detected") },
	{ 510, CONST_LEN_STR("510 Not Extended") },
	{ 511, CONST_LEN_STR("511 Network Authentication Required") },

	{ -1, 0, NULL }
};


const buffer *http_method_buf (http_method_t i)
{
    return ((unsigned int)i < sizeof(http_methods)/sizeof(*http_methods)-2)
      ? http_methods+i
      : http_methods+i+sizeof(http_methods)/sizeof(*http_methods);
        /* HTTP_METHOD_PRI is -2, HTTP_METHOD_UNSET is -1 */
}


__attribute_noinline__
__attribute_pure__
static const keyvalue * keyvalue_from_key (const keyvalue *kv, const int k)
{
    /*(expects sentinel to have key == -1 and value == NULL)*/
    while (kv->key != k && kv->key != -1) ++kv;
    return kv;
}


#if 0 /*(unused)*/
__attribute_pure__
static int keyvalue_get_key(const keyvalue *kv, const char * const s, const unsigned int slen)
{
    /*(expects sentinel to have key == -1 and vlen == 0)*/
    while (kv->vlen && (kv->vlen != slen || 0 != memcmp(kv->value, s, slen)))
        ++kv;
    return kv->key;
}
#endif


const char *get_http_version_name(int i) {
    return keyvalue_from_key(http_versions, i)->value;
}

#if 0 /*(unused)*/
const char *get_http_status_name(int i) {
    return keyvalue_from_key(http_status, i)->value;
}
#endif

#if 0 /*(unused)*/
int get_http_version_key(const char *s, size_t slen) {
    return keyvalue_get_key(http_versions, s, (unsigned int)slen);
}
#endif

http_method_t get_http_method_key(const char *s, const size_t slen) {
    if (slen == 3 && s[0] == 'G' && s[1] == 'E' && s[2] == 'T')
        return HTTP_METHOD_GET;
    const buffer *kv = http_methods+1; /*(step over http_methods[0] ("GET"))*/
    while (kv->used && (kv->used-1 != slen || 0 != memcmp(kv->ptr, s, slen)))
        ++kv;
    const uint_fast32_t i = kv - http_methods;
    /*(not done: could overload kv->size and store enum in kv->size)*/
    return (i < sizeof(http_methods)/sizeof(*http_methods)-2)
      ? (http_method_t)i
      : i == sizeof(http_methods)/sizeof(*http_methods)-2
        ? HTTP_METHOD_PRI
        : HTTP_METHOD_UNSET;
}


void http_status_append(buffer * const b, const int status) {
    if (200 == status) { /*(short-circuit common case)*/
        buffer_append_string_len(b, CONST_STR_LEN("200 OK"));
        return;
    }

    const keyvalue * const kv = keyvalue_from_key(http_status, status);
    if (__builtin_expect( (0 != kv->vlen), 1))
        buffer_append_string_len(b, kv->value, kv->vlen);
    else {
        buffer_append_int(b, status);
        buffer_append_string_len(b, CONST_STR_LEN(" "));
    }
}

void http_version_append(buffer * const b, const http_version_t version) {
    const keyvalue * const kv = keyvalue_from_key(http_versions, version);
    if (__builtin_expect( (0 != kv->vlen), 1))
        buffer_append_string_len(b, kv->value, kv->vlen);
}
