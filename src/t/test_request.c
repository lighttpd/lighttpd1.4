#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "request.h"
#include "base.h"
#include "burl.h"
#include "log.h"

static void test_request_connection_reset(connection *con)
{
    con->request.http_method = HTTP_METHOD_UNSET;
    con->request.http_version = HTTP_VERSION_UNSET;
    con->request.http_host = NULL;
    con->request.htags = 0;
    con->request.content_length = 0;
    con->header_len = 0;
    con->http_status = 0;
    buffer_reset(con->proto);
    buffer_reset(con->request.request);
    buffer_reset(con->request.orig_uri);
    buffer_reset(con->request.uri);
    array_reset(con->request.headers);
}

static void run_http_request_parse(server *srv, connection *con, int line, int status, const char *desc, const char *req, size_t reqlen)
{
    int http_status;
    test_request_connection_reset(con);
    buffer_copy_string_len(con->request.request, req, reqlen);
    http_status = http_request_parse(srv, con, con->request.request);
    if (http_status != status) {
        fprintf(stderr,
                "%s.%d: %s() failed: expected '%d', got '%d' for test %s\n",
                __FILE__, line, "http_request_parse", status, http_status,
                desc);
        fflush(stderr);
        abort();
    }
}

static void test_request_http_request_parse(server *srv, connection *con)
{
    data_string *ds;

    run_http_request_parse(srv, con, __LINE__, 0,
      "hostname",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("www.example.org")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "IPv4 address",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: 127.0.0.1\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("127.0.0.1")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "IPv6 address",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("[::1]")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "hostname + port",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org:80\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("www.example.org")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "IPv4 address + port",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: 127.0.0.1:80\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("127.0.0.1")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "IPv6 address + port",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]:80\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("[::1]")));

    run_http_request_parse(srv, con, __LINE__, 400,
      "directory traversal",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: ../123.org\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "leading and trailing dot",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .jsdh.sfdg.sdfg.\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "trailing dot is ok",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh.sfdg.sdfg.\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("jsdh.sfdg.sdfg")));

    run_http_request_parse(srv, con, __LINE__, 400,
      "leading dot",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .jsdh.sfdg.sdfg\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "two dots",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh..sfdg.sdfg\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "broken port-number",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh.sfdg.sdfg:asd\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "negative port-number",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: jsdh.sfdg.sdfg:-1\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "port given but host missing",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: :80\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "port and host are broken",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .jsdh.sfdg.:sdfg.\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "allowed characters in host-name",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: a.b-c.d123\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("a.b-c.d123")));

    run_http_request_parse(srv, con, __LINE__, 400,
      "leading dash",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: -a.c\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "dot only",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: .\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "broken IPv4 address - non-digit",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: a192.168.2.10:1234\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "broken IPv4 address - too short",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: 192.168.2:1234\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "IPv6 address + SQL injection",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]' UNION SELECT '/\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "IPv6 address + path traversal",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: [::1]/../../../\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "negative Content-Length",
      CONST_STR_LEN("POST /12345.txt HTTP/1.0\r\n"
                    "Content-Length: -2\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 411,
      "Content-Length is empty",
      CONST_STR_LEN("POST /12345.txt HTTP/1.0\r\n"
                    "Host: 123.example.org\r\n"
                    "Content-Length:\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "Host missing",
      CONST_STR_LEN("GET / HTTP/1.1\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "empty request-URI",
      CONST_STR_LEN("GET  HTTP/1.0\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "#1232 - duplicate headers with line-wrapping",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Location: foo\r\n"
                    "Location: foobar\r\n"
                    "  baz\r\n"
                    "\r\n"));
    ds = (data_string *)
      array_get_element_klen(con->request.headers, CONST_STR_LEN("Location"));
    assert(ds
           && buffer_is_equal_string(ds->value,
                                     CONST_STR_LEN("foo, foobar    baz")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "#1232 - duplicate headers with line-wrapping - test 2",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Location: \r\n"
                    "Location: foobar\r\n"
                    "  baz\r\n"
                    "\r\n"));
    ds = (data_string *)
      array_get_element_klen(con->request.headers, CONST_STR_LEN("Location"));
    assert(ds
           && buffer_is_equal_string(ds->value, CONST_STR_LEN("foobar    baz")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "#1232 - duplicate headers with line-wrapping - test 3",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "A: \r\n"
                    "Location: foobar\r\n"
                    "  baz\r\n"
                    "\r\n"));
    ds = (data_string *)
      array_get_element_klen(con->request.headers, CONST_STR_LEN("Location"));
    assert(ds
           && buffer_is_equal_string(ds->value, CONST_STR_LEN("foobar    baz")));

    run_http_request_parse(srv, con, __LINE__, 400,
      "missing protocol",
      CONST_STR_LEN("GET /\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 505,
      "zeros in protocol version",
      CONST_STR_LEN("GET / HTTP/01.01\r\n"
                    "Host: foo\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 505,
      "missing major version",
      CONST_STR_LEN("GET / HTTP/.01\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 505,
      "missing minor version",
      CONST_STR_LEN("GET / HTTP/01.\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 505,
      "strings as version",
      CONST_STR_LEN("GET / HTTP/a.b\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "missing protocol + unknown method",
      CONST_STR_LEN("BC /\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "missing protocol + unknown method + missing URI",
      CONST_STR_LEN("ABC\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 501,
      "unknown method",
      CONST_STR_LEN("ABC / HTTP/1.0\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 505,
      "unknown protocol",
      CONST_STR_LEN("GET / HTTP/1.3\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "absolute URI",
      CONST_STR_LEN("GET http://www.example.org/ HTTP/1.0\r\n"
                    "\r\n"));
    assert(buffer_is_equal_string(con->request.http_host,
                                  CONST_STR_LEN("www.example.org")));
    assert(buffer_is_equal_string(con->request.uri,
                                  CONST_STR_LEN("/")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "whitespace after key",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC : foo\r\n"
                    "\r\n"));
    ds = (data_string *)
      array_get_element_klen(con->request.headers, CONST_STR_LEN("ABC"));
    assert(ds && buffer_is_equal_string(ds->value, CONST_STR_LEN("foo")));

    run_http_request_parse(srv, con, __LINE__, 400,
      "whitespace within key",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC a: foo\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "no whitespace",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC:foo\r\n"
                    "\r\n"));
    ds = (data_string *)
      array_get_element_klen(con->request.headers, CONST_STR_LEN("ABC"));
    assert(ds && buffer_is_equal_string(ds->value, CONST_STR_LEN("foo")));

    run_http_request_parse(srv, con, __LINE__, 0,
      "line-folding",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "ABC:foo\r\n"
                    "  bc\r\n"
                    "\r\n"));
    ds = (data_string *)
      array_get_element_klen(con->request.headers, CONST_STR_LEN("ABC"));
    assert(ds && buffer_is_equal_string(ds->value, CONST_STR_LEN("foo    bc")));

    run_http_request_parse(srv, con, __LINE__, 411,
      "POST request, no Content-Length",
      CONST_STR_LEN("POST / HTTP/1.0\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "Duplicate Host headers, Bug #25",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "Host: 123.example.org\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "Duplicate Content-Length headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Content-Length: 5\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "Duplicate Content-Type headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Content-Type: 5\r\n"
                    "Content-Type: 4\r\n"
                    "\r\n"));

    /* (not actually testing Range here anymore; parsing deferred until use) */

    run_http_request_parse(srv, con, __LINE__, 0,
      "Duplicate Range headers (get appended)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=5-6\r\n"
                    "Range: bytes=5-9\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "Duplicate Range headers with invalid range (a)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=0\r\n"
                    "Range: bytes=5-9\r\n"
                    "\r\n"));
    run_http_request_parse(srv, con, __LINE__, 0,
      "Duplicate Range headers with invalid range (b)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=5-9\r\n"
                    "Range: bytes=0\r\n"
                    "\r\n"));
    run_http_request_parse(srv, con, __LINE__, 0,
      "Duplicate Range headers with invalid range (c)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: 0\r\n"
                    "Range: bytes=5-9\r\n"
                    "\r\n"));
    run_http_request_parse(srv, con, __LINE__, 0,
      "Duplicate Range headers with invalid range (d)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Range: bytes=5-9\r\n"
                    "Range: 0\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 0,
      "Duplicate If-None-Match headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "If-None-Match: 5\r\n"
                    "If-None-Match: 4\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "Duplicate If-Modified-Since headers",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "If-Modified-Since: 5\r\n"
                    "If-Modified-Since: 4\r\n"
                    "\r\n"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "GET with Content-Length",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"
                    "1234"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "HEAD with Content-Length",
      CONST_STR_LEN("HEAD / HTTP/1.0\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"
                    "1234"));

    run_http_request_parse(srv, con, __LINE__, 400,
      "invalid chars in Header values (bug #1286)",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "If-Modified-Since: \0\r\n"
                    "\r\n"));

    /* (quick check that none of above tests were left in a state
     *  which resulted in subsequent tests returning 400 for other
     *  reasons) */
    run_http_request_parse(srv, con, __LINE__, 0,
      "valid",
      CONST_STR_LEN("GET / HTTP/1.0\r\n"
                    "Host: www.example.org\r\n"
                    "\r\n"));
}

int main (void)
{
    server srv;
    connection con;

    memset(&srv, 0, sizeof(server));
    srv.errh = log_error_st_init(&srv.cur_ts, &srv.last_generated_debug_ts);
    srv.errh->errorlog_fd = -1; /* (disable) */
    srv.split_vals = array_init();

    memset(&con, 0, sizeof(connection));
    con.proto                = buffer_init();
    con.request.request      = buffer_init();
    con.request.orig_uri     = buffer_init();
    con.request.uri          = buffer_init();
    con.request.headers      = array_init();
    con.conf.allow_http11   = 1;
    con.conf.http_parseopts = HTTP_PARSEOPT_HEADER_STRICT
                            | HTTP_PARSEOPT_HOST_STRICT
                            | HTTP_PARSEOPT_HOST_NORMALIZE;

    test_request_http_request_parse(&srv, &con);

    buffer_free(con.proto);
    buffer_free(con.request.request);
    buffer_free(con.request.orig_uri);
    buffer_free(con.request.uri);
    array_free(con.request.headers);

    array_free(srv.split_vals);
    log_error_st_free(srv.errh);

    return 0;
}
