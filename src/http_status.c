/*
 * http_status - HTTP status methods
 *
 * Copyright(c) 2018,2025 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_status.h"
#include "request.h"


typedef struct {
	int key;
	unsigned int vlen;
	const char *value;
} http_status_kv;

/* https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml */
static const http_status_kv http_status_list[] = {
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
	{ 425, CONST_LEN_STR("425 Too Early") },
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


__attribute_pure__
static const http_status_kv *
http_status_keyvalue_from_key (const http_status_kv *kv, const int k)
{
    /*(expects sentinel to have key == -1 and value == NULL)*/
    while (kv->key != k && kv->key != -1) ++kv;
    return kv;
}


void
http_status_append (buffer * const b, const int http_status)
{
    if (200 == http_status) { /*(short-circuit common case)*/
        buffer_append_string_len(b, CONST_STR_LEN("200 OK"));
        return;
    }

    const http_status_kv * const kv =
      http_status_keyvalue_from_key(http_status_list, http_status);
    if (__builtin_expect( (0 != kv->vlen), 1))
        buffer_append_string_len(b, kv->value, kv->vlen);
    else {
        buffer_append_int(b, http_status);
        buffer_append_char(b, ' ');
    }
}


__attribute_cold__
__attribute_noinline__
handler_t
http_status_set_err (request_st * const r, int http_status)
{
    /*(intended to set http status error code and unset handler
     * so that internal error doc used (if !r->resp_body_finished).
     * Callers should ensure/know that response headers have not been sent and
     * response body has not been started (unless r->resp_body_finished set))*/
    r->handler_module = NULL;
    r->http_status = http_status;
    return HANDLER_FINISHED;
}


__attribute_cold__
handler_t
http_status_set_err_fin (request_st * const r, int http_status)
{
    /*(intended to set http status error code and mark response finished)*/
    r->resp_body_finished = 1; /*(skip sending error doc if body not set)*/
    return http_status_set_err(r, http_status);
}


__attribute_cold__
handler_t
http_status_set_err_close (request_st * const r, int http_status)
{
    /*(intended to set http status error code and close connection if HTTP/1.x;
     * e.g. disable keep-alive to prevent processing further requests after
     * failure to process request headers on HTTP/1.x connection, or failure
     * to read entire request body)*/
    if (r->keep_alive > 0) r->keep_alive = 0; /*(preserve value if -1)*/
    return http_status_set_err_fin(r, http_status);
}
