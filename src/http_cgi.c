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

    size_t ulen = buffer_string_length(&r->uri.path);
    const buffer *vb = http_header_response_get(r, HTTP_HEADER_LOCATION,
                                                CONST_STR_LEN("Location"));
    if (NULL != vb
        && vb->ptr[0] == '/'
        && (0 != strncmp(vb->ptr, r->uri.path.ptr, ulen)
            || (   vb->ptr[ulen] != '\0'
                && vb->ptr[ulen] != '/'
                && vb->ptr[ulen] != '?'))
        && !light_btst(r->resp_htags, HTTP_HEADER_STATUS)
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
        /*plugins_call_handle_request_reset(r);*/

        return HANDLER_COMEBACK;
    }

    return HANDLER_GO_ON;
}


int
http_cgi_headers (request_st * const r, http_cgi_opts * const opts, http_cgi_header_append_cb cb, void *vdata)
{
    /* CGI-SPEC 6.1.2, FastCGI spec 6.3 and SCGI spec */

    int rc = 0;
    const connection * const con = r->con;
    server_socket * const srv_sock = con->srv_socket;
    buffer * const tb = r->tmp_buf;
    const char *s;
    size_t n;
    char buf[LI_ITOSTRING_LENGTH];
    sock_addr *addr;
    sock_addr addrbuf;
    char b2[INET6_ADDRSTRLEN + 1];

    /* (CONTENT_LENGTH must be first for SCGI) */
    if (!opts->authorizer)
        rc |= cb(vdata, CONST_STR_LEN("CONTENT_LENGTH"),
                 buf, li_itostrn(buf,sizeof(buf),r->reqbody_length));

    if (!buffer_string_is_empty(&r->uri.query))
        rc |= cb(vdata, CONST_STR_LEN("QUERY_STRING"),
                        CONST_BUF_LEN(&r->uri.query));
    else
        rc |= cb(vdata, CONST_STR_LEN("QUERY_STRING"),
                        CONST_STR_LEN(""));

    if (!buffer_string_is_empty(opts->strip_request_uri)) {
        /**
         * /app1/index/list
         *
         * stripping /app1 or /app1/ should lead to
         *
         * /index/list
         *
         */
        size_t len = buffer_string_length(opts->strip_request_uri);
        if ('/' == opts->strip_request_uri->ptr[len-1])
            --len;

        if (buffer_string_length(&r->target_orig) >= len
            && 0 == memcmp(r->target_orig.ptr,
                           opts->strip_request_uri->ptr, len)
            && r->target_orig.ptr[len] == '/') {
            rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                            r->target_orig.ptr+len,
                            buffer_string_length(&r->target_orig)-len);
        }
        else
            rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                            CONST_BUF_LEN(&r->target_orig));
    }
    else
        rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                        CONST_BUF_LEN(&r->target_orig));

    if (!buffer_is_equal(&r->target, &r->target_orig))
        rc |= cb(vdata, CONST_STR_LEN("REDIRECT_URI"),
                        CONST_BUF_LEN(&r->target));

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
                        CONST_BUF_LEN(&r->uri.path));
        if (!buffer_string_is_empty(&r->pathinfo)) {
            rc |= cb(vdata, CONST_STR_LEN("PATH_INFO"),
                            CONST_BUF_LEN(&r->pathinfo));
            /* PATH_TRANSLATED is only defined if PATH_INFO is set
             * Note: not implemented: re-url-encode '?' '=' ';' for
             * (RFC 3875 4.1.6) */
            if (!buffer_string_is_empty(opts->docroot))
                buffer_copy_buffer(tb, opts->docroot);
            else
                buffer_copy_buffer(tb, &r->physical.basedir);
            buffer_append_path_len(tb, CONST_BUF_LEN(&r->pathinfo));
            rc |= cb(vdata, CONST_STR_LEN("PATH_TRANSLATED"),
                            CONST_BUF_LEN(tb));
        }
    }

   /*
    * SCRIPT_FILENAME and DOCUMENT_ROOT for php
    * The PHP manual http://www.php.net/manual/en/reserved.variables.php
    * treatment of PATH_TRANSLATED is different from the one of CGI specs.
    * (see php.ini cgi.fix_pathinfo = 1 config parameter)
    */

    if (!buffer_string_is_empty(opts->docroot)) {
        /* alternate docroot, e.g. for remote FastCGI or SCGI server */
        buffer_copy_buffer(tb, opts->docroot);
        buffer_append_path_len(tb, CONST_BUF_LEN(&r->uri.path));
        rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                        CONST_BUF_LEN(tb));
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        CONST_BUF_LEN(opts->docroot));
    }
    else {
        if (opts->break_scriptfilename_for_php) {
            /* php.ini config cgi.fix_pathinfo = 1 need a broken SCRIPT_FILENAME
             * to find out what PATH_INFO is itself
             *
             * see src/sapi/cgi_main.c, init_request_info()
             */
            buffer_copy_buffer(tb, &r->physical.path);
            buffer_append_path_len(tb, CONST_BUF_LEN(&r->pathinfo));
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            CONST_BUF_LEN(tb));
        }
        else
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            CONST_BUF_LEN(&r->physical.path));
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        CONST_BUF_LEN(&r->physical.basedir));
    }

    s = get_http_method_name(r->http_method);
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("REQUEST_METHOD"), s, strlen(s));

    s = get_http_version_name(r->http_version);
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PROTOCOL"), s, strlen(s));

    rc |= cb(vdata, CONST_STR_LEN("SERVER_SOFTWARE"),
                    CONST_BUF_LEN(r->conf.server_tag));

    rc |= cb(vdata, CONST_STR_LEN("GATEWAY_INTERFACE"),
                    CONST_STR_LEN("CGI/1.1"));

    rc |= cb(vdata, CONST_STR_LEN("REQUEST_SCHEME"),
                    CONST_BUF_LEN(&r->uri.scheme));

    if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https")))
        rc |= cb(vdata, CONST_STR_LEN("HTTPS"), CONST_STR_LEN("on"));

    addr = &srv_sock->addr;
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PORT"),
             buf, li_utostrn(buf,sizeof(buf),sock_addr_get_port(addr)));

    switch (sock_addr_get_family(addr)) {
    case AF_INET:
    case AF_INET6:
        if (sock_addr_is_addr_wildcard(addr)) {
            socklen_t addrlen = sizeof(addrbuf);
            if (0 == getsockname(con->fd,(struct sockaddr *)&addrbuf,&addrlen)){
                addr = &addrbuf;
            }
            else {
                s = "";
                break;
            }
        }
        s = sock_addr_inet_ntop(addr, b2, sizeof(b2)-1);
        if (NULL == s) s = "";
        break;
    default:
        s = "";
        break;
    }
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("SERVER_ADDR"), s, strlen(s));

    if (!buffer_string_is_empty(r->server_name)) {
        size_t len = buffer_string_length(r->server_name);

        if (r->server_name->ptr[0] == '[') {
            const char *colon = strstr(r->server_name->ptr, "]:");
            if (colon) len = (colon + 1) - r->server_name->ptr;
        }
        else {
            const char *colon = strchr(r->server_name->ptr, ':');
            if (colon) len = colon - r->server_name->ptr;
        }

        rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"),
                        r->server_name->ptr, len);
    }
    else /* set to be same as SERVER_ADDR (above) */
        rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"), s, strlen(s));

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_ADDR"),
                    CONST_BUF_LEN(con->dst_addr_buf));

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_PORT"), buf,
             li_utostrn(buf,sizeof(buf),sock_addr_get_port(&con->dst_addr)));

    for (n = 0; n < r->rqst_headers.used; n++) {
        data_string *ds = (data_string *)r->rqst_headers.data[n];
        if (!buffer_string_is_empty(&ds->value) && !buffer_is_empty(&ds->key)) {
            /* Security: Do not emit HTTP_PROXY in environment.
             * Some executables use HTTP_PROXY to configure
             * outgoing proxy.  See also https://httpoxy.org/ */
            if (ds->ext == HTTP_HEADER_OTHER
                && buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Proxy"))) {
                continue;
            }
            buffer_copy_string_encoded_cgi_varnames(tb,
                                                    CONST_BUF_LEN(&ds->key), 1);
            rc |= cb(vdata, CONST_BUF_LEN(tb),
                            CONST_BUF_LEN(&ds->value));
        }
    }

    con->srv->request_env(r);

    for (n = 0; n < r->env.used; n++) {
        data_string *ds = (data_string *)r->env.data[n];
        if (!buffer_is_empty(&ds->value) && !buffer_is_empty(&ds->key)) {
            buffer_copy_string_encoded_cgi_varnames(tb,
                                                    CONST_BUF_LEN(&ds->key), 0);
            rc |= cb(vdata, CONST_BUF_LEN(tb),
                            CONST_BUF_LEN(&ds->value));
        }
    }

    return rc;
}
