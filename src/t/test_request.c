#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "request.c"
#include "fdlog.h"

static void test_request_reset(request_st * const r)
{
    r->http_method = HTTP_METHOD_UNSET;
    r->http_version = HTTP_VERSION_UNSET;
    r->http_host = NULL;
    r->rqst_htags = 0;
    r->reqbody_length = 0;
    buffer_clear(&r->target_orig);
    buffer_clear(&r->target);
    array_reset_data_strings(&r->rqst_headers);
}

static void run_http_request_parse(request_st * const r, int line, int status, const char *desc, const char *req, size_t reqlen)
{
    unsigned short hloffsets[32];
    char hdrs[1024];
    test_request_reset(r);
    assert(reqlen < sizeof(hdrs));
    memcpy(hdrs, req, reqlen);
    hloffsets[0] = 1;
    hloffsets[1] = 0;
    hloffsets[2] = 0;
    for (const char *n=req, *end=req+reqlen; (n=memchr(n,'\n',end-n)); ++n) {
        if (++hloffsets[0] >= sizeof(hloffsets)/sizeof(*hloffsets)) break;
        hloffsets[hloffsets[0]] = n - req + 1;
    }
    --hloffsets[0]; /*(ignore final blank line "\r\n" ending headers)*/
    const int proto_default_port = 80;
    int http_status =
      http_request_parse_hoff(r, hdrs, hloffsets, proto_default_port);
    if (http_status != status) {
        fprintf(stderr,
                "%s.%d: %s() failed: expected '%d', got '%d' for test %s\n",
                __FILE__, line, "http_request_parse_hoff", status, http_status,
                desc);
        fflush(stderr);
        abort();
    }
}

static void test_request_http_request_parse(request_st * const r)
{
    buffer *b;

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: space",
      CONST_STR_LEN(" \r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: space, char",
      CONST_STR_LEN(" a\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: dot",
      CONST_STR_LEN(".\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: single char",
      CONST_STR_LEN("a\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: char, space",
      CONST_STR_LEN("a \r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method only",
      CONST_STR_LEN("GET\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space",
      CONST_STR_LEN("GET \r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space space",
      CONST_STR_LEN("GET  \r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space proto",
      CONST_STR_LEN("GET HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space space proto",
      CONST_STR_LEN("GET  HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space space space proto",
      CONST_STR_LEN("GET   HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method slash proto, no spaces",
      CONST_STR_LEN("GET/HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space slash proto",
      CONST_STR_LEN("GET /HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid request-line: method space space slash proto",
      CONST_STR_LEN("GET  /HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 501,
      "invalid request-line: method slash space proto",
      CONST_STR_LEN("GET/ HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 501,
      "invalid request-line: method slash space space proto",
      CONST_STR_LEN("GET/  HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "hostname",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("www.example.org")));

    run_http_request_parse(r, __LINE__, 0,
      "IPv4 address",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: 127.0.0.1\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("127.0.0.1")));

    run_http_request_parse(r, __LINE__, 0,
      "IPv6 address",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("[::1]")));

    run_http_request_parse(r, __LINE__, 0,
      "hostname + port",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org:80\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("www.example.org")));

    run_http_request_parse(r, __LINE__, 0,
      "IPv4 address + port",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: 127.0.0.1:80\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("127.0.0.1")));

    run_http_request_parse(r, __LINE__, 0,
      "IPv6 address + port",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]:80\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("[::1]")));

    run_http_request_parse(r, __LINE__, 400,
      "directory traversal",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: ../123.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "leading and trailing dot",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .jsdh.sfdg.sdfg.\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "trailing dot is ok",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh.sfdg.sdfg.\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("jsdh.sfdg.sdfg")));

    run_http_request_parse(r, __LINE__, 400,
      "leading dot",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .jsdh.sfdg.sdfg\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "two dots",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh..sfdg.sdfg\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "broken port-number",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh.sfdg.sdfg:asd\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "negative port-number",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh.sfdg.sdfg:-1\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "port given but host missing",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: :80\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "port and host are broken",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .jsdh.sfdg.:sdfg.\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "allowed characters in host-name",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: a.b-c.d123\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("a.b-c.d123")));

    run_http_request_parse(r, __LINE__, 400,
      "leading dash",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: -a.c\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "dot only",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "broken IPv4 address - non-digit",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: a192.168.2.10:1234\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "broken IPv4 address - too short",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: 192.168.2:1234\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "IPv6 address + SQL injection",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]' UNION SELECT '/\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "IPv6 address + path traversal",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]/../../../\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "negative Content-Length",
      CONST_STR_LEN("POST /12345.txt HTTP/1.0\r\n"
                    "Content-Length: -2\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 411,
      "Content-Length is empty",
      CONST_STR_LEN("POST /12345.txt HTTP/1.0\r\n"
                    "Host: 123.example.org\r\n"
                    "Content-Length:\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "Host missing",
      CONST_STR_LEN("GET / HTTP/1.1\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "empty request-URI",
      CONST_STR_LEN("GET  HTTP/1.0\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "URL-decode request-URI",
      CONST_STR_LEN("GET /index%2ehtml HTTP/1.0\r\n"
                    "\r\n"));
    assert(buffer_eq_slen(&r->uri.path, CONST_STR_LEN("/index.html")));

    run_http_request_parse(r, __LINE__, 0,
      "#1232 - duplicate headers with line-wrapping",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Location: foo\r\n"
                    "Location: foobar\r\n"
                    "  baz\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_LOCATION,
                                   CONST_STR_LEN("Location"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("foo, foobar    baz")));

    run_http_request_parse(r, __LINE__, 0,
      "#1232 - duplicate headers with line-wrapping - test 2",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Location: \r\n"
                    "Location: foobar\r\n"
                    "  baz\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_LOCATION,
                                   CONST_STR_LEN("Location"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("foobar    baz")));

    run_http_request_parse(r, __LINE__, 0,
      "#1232 - duplicate headers with line-wrapping - test 3",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "A: \r\n"
                    "Location: foobar\r\n"
                    "  baz\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_LOCATION,
                                   CONST_STR_LEN("Location"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("foobar    baz")));

    run_http_request_parse(r, __LINE__, 400,
      "missing protocol",
      CONST_STR_LEN("GET /\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 505,
      "zeros in protocol version",
      CONST_STR_LEN("GET / HTTP/01.01\r\n"
                    "Host: foo\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 505,
      "missing major version",
      CONST_STR_LEN("GET / HTTP/.01\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 505,
      "missing minor version",
      CONST_STR_LEN("GET / HTTP/01.\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 505,
      "strings as version",
      CONST_STR_LEN("GET / HTTP/a.b\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "missing protocol + unknown method",
      CONST_STR_LEN("BC /\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "missing protocol + unknown method + missing URI",
      CONST_STR_LEN("ABC\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 501,
      "unknown method",
      CONST_STR_LEN("ABC / HTTP/1.0\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 505,
      "unknown protocol",
      CONST_STR_LEN("GET / HTTP/1.3\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "absolute URI",
      CONST_STR_LEN("GET http://www.example.org/ HTTP/1.0\r\n"
                    "\r\n"));
    assert(r->http_host && buffer_eq_slen(r->http_host, CONST_STR_LEN("www.example.org")));
    assert(buffer_eq_slen(&r->target, CONST_STR_LEN("/")));

    run_http_request_parse(r, __LINE__, 400,
      "whitespace after key",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC : foo\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "whitespace within key",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC a: foo\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "no whitespace",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC:foo\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("ABC"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("foo")));

    run_http_request_parse(r, __LINE__, 0,
      "line-folding",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC:foo\r\n"
                    "  bc\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("ABC"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("foo    bc")));

    run_http_request_parse(r, __LINE__, 411,
      "POST request, no Content-Length",
      CONST_STR_LEN("POST / HTTP/1.0\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "Duplicate Host headers, Bug #25",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "Host: 123.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "Duplicate Content-Length headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Content-Length: 5\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "Duplicate Content-Type headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Content-Type: 5\r\n"
                    "Content-Type: 4\r\n"
                    "\r\n"));

    /* (not actually testing Range here anymore; parsing deferred until use) */

    run_http_request_parse(r, __LINE__, 0,
      "Duplicate Range headers (get appended)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=5-6\r\n"
                    "Range: bytes=5-9\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "Duplicate Range headers with invalid range (a)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=0\r\n"
                    "Range: bytes=5-9\r\n"
                    "\r\n"));
    run_http_request_parse(r, __LINE__, 0,
      "Duplicate Range headers with invalid range (b)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=5-9\r\n"
                    "Range: bytes=0\r\n"
                    "\r\n"));
    run_http_request_parse(r, __LINE__, 0,
      "Duplicate Range headers with invalid range (c)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: 0\r\n"
                    "Range: bytes=5-9\r\n"
                    "\r\n"));
    run_http_request_parse(r, __LINE__, 0,
      "Duplicate Range headers with invalid range (d)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=5-9\r\n"
                    "Range: 0\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "Duplicate If-None-Match headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "If-None-Match: 5\r\n"
                    "If-None-Match: 4\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "Duplicate If-Modified-Since headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "If-Modified-Since: 5\r\n"
                    "If-Modified-Since: 4\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 400,
      "GET with Content-Length",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"
                    "1234"));

    run_http_request_parse(r, __LINE__, 400,
      "HEAD with Content-Length",
      CONST_STR_LEN("HEAD / HTTP/1.0\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"
                    "1234"));

    run_http_request_parse(r, __LINE__, 400,
      "invalid chars in Header values (bug #1286)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "If-Modified-Since: \0\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "absolute-uri in request-line (without Host)",
      CONST_STR_LEN("GET http://zzz.example.org/ HTTP/1.1\r\n"
                    "Connection: close\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_HOST, CONST_STR_LEN("Host"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("zzz.example.org")));

    run_http_request_parse(r, __LINE__, 0,
      "absolute-uri in request-line (with Host match)",
      CONST_STR_LEN("GET http://zzz.example.org/ HTTP/1.1\r\n"
                    "Host: zzz.example.org\r\n"
                    "Connection: close\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_HOST, CONST_STR_LEN("Host"));
    assert(b && buffer_eq_slen(b, CONST_STR_LEN("zzz.example.org")));

    run_http_request_parse(r, __LINE__, 400,
      "absolute-uri in request-line (with Host mismatch)",
      CONST_STR_LEN("GET http://zzz.example.org/ HTTP/1.1\r\n"
                    "Host: aaa.example.org\r\n"
                    "Connection: close\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "ignore duplicated If-Modified-Since if matching",
      CONST_STR_LEN("GET / HTTP/1.1\r\n"
                    "Host: zzz.example.org\r\n"
                    "If-Modified-Since: Sun, 01 Jan 2036 00:00:02 GMT\r\n"
                    "If-Modified-Since: Sun, 01 Jan 2036 00:00:02 GMT\r\n"
                    "Connection: close\r\n"
                    "\r\n"));
    b = http_header_request_get(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                                CONST_STR_LEN("If-Modified-Since"));
    assert(b && buffer_eq_slen(b,
                               CONST_STR_LEN("Sun, 01 Jan 2036 00:00:02 GMT")));

    run_http_request_parse(r, __LINE__, 400,
      "reject duplicated If-Modified-Since if not matching",
      CONST_STR_LEN("GET / HTTP/1.1\r\n"
                    "Host: zzz.example.org\r\n"
                    "If-Modified-Since: Sun, 01 Jan 2036 00:00:02 GMT\r\n"
                    "If-Modified-Since: Sun, 01 Jan 2036 00:00:03 GMT\r\n"
                    "Connection: close\r\n"
                    "\r\n"));

    run_http_request_parse(r, __LINE__, 0,
      "large headers", /*(copied from tests/request.t)*/
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Hsgfsdjf: asdfhdf\r\n"
                    "hdhd: shdfhfdasd\r\n"
                    "hfhr: jfghsdfg\r\n"
                    "jfuuehdmn: sfdgjfdg\r\n"
                    "jvcbzufdg: sgfdfg\r\n"
                    "hrnvcnd: jfjdfg\r\n"
                    "jfusfdngmd: gfjgfdusdfg\r\n"
                    "nfj: jgfdjdfg\r\n"
                    "jfue: jfdfdg\r\n"
                    "\r\n"));

    /* (quick check that none of above tests were left in a state
     *  which resulted in subsequent tests returning 400 for other
     *  reasons) */
    run_http_request_parse(r, __LINE__, 0,
      "valid",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));
}

#include "base.h"
#include "burl.h"
#include "log.h"

void test_request (void);
void test_request (void)
{
    request_st r;

    memset(&r, 0, sizeof(request_st));
    r.conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
    r.conf.errh->fd          = -1; /* (disable) */
    r.conf.allow_http11      = 1;
    r.conf.http_parseopts    = HTTP_PARSEOPT_HEADER_STRICT
                             | HTTP_PARSEOPT_HOST_STRICT
                             | HTTP_PARSEOPT_HOST_NORMALIZE;

    test_request_http_request_parse(&r);

    free(r.target_orig.ptr);
    free(r.target.ptr);
    array_free_data(&r.rqst_headers);

    fdlog_free(r.conf.errh);
}
