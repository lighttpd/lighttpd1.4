/*
 * http_cgi - Common Gateway Interface (CGI) interfaces (RFC 3875)
 *
 * Copyright(c) 2016-2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_cgi.h"

#include "sys-socket.h"
#include <string.h>

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "log.h"
#include "http_header.h"
#include "sock_addr.h"

handler_t
http_cgi_local_redir (request_st * const r)
{
    /* [RFC3875] The Common Gateway Interface (CGI) Version 1.1
     * [RFC3875] 6.2.2 Local Redirect Response
     *
     *    The CGI script can return a URI path and query-string
     *    ('local-pathquery') for a local resource in a Location header field.
     *    This indicates to the server that it should reprocess the request
     *    using the path specified.
     *
     *      local-redir-response = local-Location NL
     *
     *    The script MUST NOT return any other header fields or a message-body,
     *    and the server MUST generate the response that it would have produced
     *    in response to a request containing the URL
     *
     *      scheme "://" server-name ":" server-port local-pathquery
     *
     * (While not required by the RFC, do not send local-redir back to same URL
     *  since CGI should have handled it internally if it really wanted to do
     *  that internally)
     */

    size_t ulen = buffer_clen(&r->uri.path);
    const buffer *vb = http_header_response_get(r, HTTP_HEADER_LOCATION,
                                                CONST_STR_LEN("Location"));
    if (NULL != vb
        && vb->ptr[0] == '/'
        && (0 != strncmp(vb->ptr, r->uri.path.ptr, ulen)
            || (   vb->ptr[ulen] != '\0'
                && vb->ptr[ulen] != '/'
                && vb->ptr[ulen] != '?'))
        && 1 == r->resp_headers.used /*"Location"; no "Status" or NPH response*/
        && r->http_status >= 300 && r->http_status < 400) {
        if (++r->loops_per_request > 5) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "too many internal loops while processing request: %s",
              r->target_orig.ptr);
            r->http_status = 500; /* Internal Server Error */
            r->resp_body_started = 0;
            r->handler_module = NULL;
            return HANDLER_FINISHED;
        }

        buffer_copy_buffer(&r->target, vb);
        buffer_clear(&r->pathinfo);

        if (r->reqbody_length) {
            if (r->reqbody_length != r->reqbody_queue.bytes_in)
                r->keep_alive = 0;
            r->reqbody_length = 0;
            chunkqueue_reset(&r->reqbody_queue);
        }

        if (r->http_status != 307 && r->http_status != 308) {
            /* Note: request body (if any) sent to initial dynamic handler
             * and is not available to the internal redirect */
            r->http_method = HTTP_METHOD_GET;
        }

        /*(caller must reset request as follows)*/
        /*http_response_reset(r);*/ /*(sets r->http_status = 0)*/
        /*r->con->srv->plugins_request_reset(r);*/

        return HANDLER_COMEBACK;
    }

    return HANDLER_GO_ON;
}


static void
http_cgi_encode_varname (buffer * const b, const char * const restrict s, const size_t len, const int is_http_header)
{
    char * const restrict p = buffer_string_prepare_copy(b, len + 5);
    size_t i, j = 0;

    if (is_http_header) {
      #if 0 /*(special-cased in caller that sets is_http_header)*/
        if (len == 12 && buffer_eq_icase_ssn(s, "Content-Type", 12)) {
            buffer_copy_string_len(b, CONST_STR_LEN("CONTENT_TYPE"));
            return;
        }
      #endif
        memcpy(p, "HTTP_", 5);
        j = 5; /* "HTTP_" */
    }

    for (i = 0; i < len; ++i) {/* uppercase alpha, pass numeric, map rest '_' */
        const unsigned char c = s[i];
        p[j++] = light_isalpha(c) ? c & ~0x20 : light_isdigit(c) ? c : '_';
    }
    buffer_truncate(b, j);
}


int
http_cgi_headers (request_st * const r, http_cgi_opts * const opts, http_cgi_header_append_cb cb, void *vdata)
{
    /* CGI-SPEC 6.1.2, FastCGI spec 6.3 and SCGI spec */

    /* note: string ptrs passed to cb() func must not be NULL */

    int rc = 0;
    uint32_t len;
    buffer * const tb = r->tmp_buf;
    const char *s;
    size_t n;
    char buf[INET6_ADDRSTRLEN + 1]; /*(also larger than LI_ITOSTRING_LENGTH)*/

    /* (CONTENT_LENGTH must be first for SCGI) */
    if (!opts->authorizer)
        rc |= cb(vdata, CONST_STR_LEN("CONTENT_LENGTH"),
                 buf, li_itostrn(buf,sizeof(buf),r->reqbody_length));

    n = buffer_clen(&r->uri.query);
    rc |= cb(vdata, CONST_STR_LEN("QUERY_STRING"),
                    n ? r->uri.query.ptr : "", n);

    s = r->target_orig.ptr;
    n = buffer_clen(&r->target_orig);
    len = opts->strip_request_uri ? buffer_clen(opts->strip_request_uri) : 0;
    if (len) {
        /* e.g. /app1/index/list
         *      stripping /app1 or /app1/ should lead to /index/list
         *      (trailing slash removed from strip_request_uri at config time)*/
        if (n < len || 0 != memcmp(s, opts->strip_request_uri->ptr, len)
            || s[len] != '/')
            len = 0;
    }
    rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"), s+len, n-len);

    if (!buffer_is_equal(&r->target, &r->target_orig))
        rc |= cb(vdata, CONST_STR_LEN("REDIRECT_URI"),
                        BUF_PTR_LEN(&r->target));

    /* set REDIRECT_STATUS for php compiled with --force-redirect
     * (if REDIRECT_STATUS has not already been set by error handler) */
    if (0 == r->error_handler_saved_status)
        rc |= cb(vdata, CONST_STR_LEN("REDIRECT_STATUS"),
                        CONST_STR_LEN("200"));

    /*
     * SCRIPT_NAME, PATH_INFO and PATH_TRANSLATED according to
     * http://cgi-spec.golux.com/draft-coar-cgi-v11-03-clean.html
     * (6.1.14, 6.1.6, 6.1.7)
     */
    if (!opts->authorizer) {
        rc |= cb(vdata, CONST_STR_LEN("SCRIPT_NAME"),
                        BUF_PTR_LEN(&r->uri.path));
        if (!buffer_is_blank(&r->pathinfo)) {
            rc |= cb(vdata, CONST_STR_LEN("PATH_INFO"),
                            BUF_PTR_LEN(&r->pathinfo));
            /* PATH_TRANSLATED is only defined if PATH_INFO is set
             * Note: not implemented: re-url-encode '?' '=' ';' for
             * (RFC 3875 4.1.6) */
            const buffer * const bd = (opts->docroot)
              ? opts->docroot
              : &r->physical.basedir;
            buffer_copy_path_len2(tb, BUF_PTR_LEN(bd),
                                      BUF_PTR_LEN(&r->pathinfo));
            rc |= cb(vdata, CONST_STR_LEN("PATH_TRANSLATED"),
                            BUF_PTR_LEN(tb));
        }
    }

   /*
    * SCRIPT_FILENAME and DOCUMENT_ROOT for php
    * The PHP manual http://www.php.net/manual/en/reserved.variables.php
    * treatment of PATH_TRANSLATED is different from the one of CGI specs.
    * (see php.ini cgi.fix_pathinfo = 1 config parameter)
    */

    if (opts->docroot) {
        /* alternate docroot, e.g. for remote FastCGI or SCGI server */
        buffer_copy_path_len2(tb, BUF_PTR_LEN(opts->docroot),
                                  BUF_PTR_LEN(&r->uri.path));
        rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                        BUF_PTR_LEN(tb));
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        BUF_PTR_LEN(opts->docroot));
    }
    else {
        if (opts->break_scriptfilename_for_php) {
            /* php.ini config cgi.fix_pathinfo = 1 need a broken SCRIPT_FILENAME
             * to find out what PATH_INFO is itself
             *
             * see src/sapi/cgi_main.c, init_request_info()
             */
            buffer_copy_path_len2(tb, BUF_PTR_LEN(&r->physical.path),
                                      BUF_PTR_LEN(&r->pathinfo));
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            BUF_PTR_LEN(tb));
        }
        else
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            BUF_PTR_LEN(&r->physical.path));
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        BUF_PTR_LEN(&r->physical.basedir));
    }

    if (!r->h2_connect_ext) {
        const buffer * const m = http_method_buf(r->http_method);
        rc |= cb(vdata, CONST_STR_LEN("REQUEST_METHOD"), BUF_PTR_LEN(m));

        const buffer * const v = http_version_buf(r->http_version);
        rc |= cb(vdata, CONST_STR_LEN("SERVER_PROTOCOL"), BUF_PTR_LEN(v));
    }
    else {
        /*(SERVER_PROTOCOL=HTTP/1.1 instead of HTTP/2.0)*/
        rc |= cb(vdata, CONST_STR_LEN("REQUEST_METHOD"),
                        CONST_STR_LEN("GET"));
        rc |= cb(vdata, CONST_STR_LEN("SERVER_PROTOCOL"),
                        CONST_STR_LEN("HTTP/1.1"));
        /* https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
         * 7. The request MUST include a header field with the name
         *    |Sec-WebSocket-Key|.  The value of this header field MUST be a
         *    nonce consisting of a randomly selected 16-byte value that has
         *    been base64-encoded (see Section 4 of [RFC4648]).  The nonce
         *    MUST be selected randomly for each connection.
         * Note: Sec-WebSocket-Key is not used in RFC8441;
         *       include Sec-WebSocket-Key for HTTP/1.1 compatibility;
         *       !!not random!! base64-encoded "0000000000000000" */
        if (!http_header_request_get(r, HTTP_HEADER_OTHER,
                                     CONST_STR_LEN("Sec-WebSocket-Key")))
            rc |= cb(vdata, CONST_STR_LEN("HTTP_SEC_WEBSOCKET_KEY"),
                            CONST_STR_LEN("MDAwMDAwMDAwMDAwMDAwMA=="));
        /*(Upgrade and Connection should not exist for HTTP/2 request)*/
        rc |= cb(vdata, CONST_STR_LEN("HTTP_UPGRADE"),
                        CONST_STR_LEN("websocket"));
        rc |= cb(vdata, CONST_STR_LEN("HTTP_CONNECTION"),
                        CONST_STR_LEN("upgrade"));
    }

    if (r->conf.server_tag) {
        s = r->conf.server_tag->ptr;
        n = buffer_clen(r->conf.server_tag);
    }
    else {
        s = "";
        n = 0;
    }
    rc |= cb(vdata, CONST_STR_LEN("SERVER_SOFTWARE"), s, n);

    rc |= cb(vdata, CONST_STR_LEN("GATEWAY_INTERFACE"),
                    CONST_STR_LEN("CGI/1.1"));

    rc |= cb(vdata, CONST_STR_LEN("REQUEST_SCHEME"),
                    BUF_PTR_LEN(&r->uri.scheme));

    if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https")))
        rc |= cb(vdata, CONST_STR_LEN("HTTPS"), CONST_STR_LEN("on"));

    const connection * const con = r->con;
    const server_socket * const srv_sock = con->srv_socket;
    const size_t tlen = buffer_clen(srv_sock->srv_token);
    n = srv_sock->srv_token_colon;
    if (n < tlen) { /*(n != tlen)*/
        s = srv_sock->srv_token->ptr+n+1;
        n = tlen - (n+1);
    }
    else {
        s = "0";
        n = 1;
    }
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PORT"), s, n);

    n = 0;
    switch (sock_addr_get_family(&srv_sock->addr)) {
      case AF_INET:
      case AF_INET6:
        if (sock_addr_is_addr_wildcard(&srv_sock->addr)) {
            sock_addr addrbuf;
            socklen_t addrlen = sizeof(addrbuf);
            if (0 == getsockname(con->fd,(struct sockaddr *)&addrbuf,&addrlen)){
                /* future: might add a one- or two- element cache
                 * or use sock_addr_cache_inet_ntop_copy_buffer() into tb */
                s = sock_addr_inet_ntop(&addrbuf, buf, sizeof(buf));
                if (s)
                    n = strlen(s);
                else
                    s = "";
            }
            else
                s = "";
        }
        else {
            s = srv_sock->srv_token->ptr;
            n = srv_sock->srv_token_colon;
        }
        break;
      default:
        s = "";
        break;
    }
    rc |= cb(vdata, CONST_STR_LEN("SERVER_ADDR"), s, n);

    n = buffer_clen(r->server_name);
    if (n) {
        s = r->server_name->ptr;
        if (s[0] == '[') {
            const char *colon = strstr(s, "]:");
            if (colon) n = (colon + 1) - s;
        }
        else {
            const char *colon = strchr(s, ':');
            if (colon) n = colon - s;
        }
    } /* else set to be same as SERVER_ADDR (above) */
    rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"), s, n);

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_ADDR"),
                    BUF_PTR_LEN(r->dst_addr_buf));

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_PORT"), buf,
             li_utostrn(buf, sizeof(buf), sock_addr_get_port(r->dst_addr)));

    for (n = 0; n < r->rqst_headers.used; n++) {
        data_string *ds = (data_string *)r->rqst_headers.data[n];
        if (!buffer_is_blank(&ds->value) && !buffer_is_unset(&ds->key)) {
            /* Security: Do not emit HTTP_PROXY in environment.
             * Some executables use HTTP_PROXY to configure
             * outgoing proxy.  See also https://httpoxy.org/ */
            if (ds->ext == HTTP_HEADER_OTHER
                && buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Proxy"))) {
                continue;
            }
            else if (ds->ext == HTTP_HEADER_CONTENT_TYPE)
                buffer_copy_string_len(tb, CONST_STR_LEN("CONTENT_TYPE"));
            else
                http_cgi_encode_varname(tb, BUF_PTR_LEN(&ds->key), 1);
            rc |= cb(vdata, BUF_PTR_LEN(tb),
                            BUF_PTR_LEN(&ds->value));
        }
    }

    con->srv->request_env(r);

    for (n = 0; n < r->env.used; n++) {
        data_string *ds = (data_string *)r->env.data[n];
        if (!buffer_is_unset(&ds->value) && !buffer_is_unset(&ds->key)) {
            http_cgi_encode_varname(tb, BUF_PTR_LEN(&ds->key), 0);
            rc |= cb(vdata, BUF_PTR_LEN(tb),
                            BUF_PTR_LEN(&ds->value));
        }
    }

    return rc;
}
