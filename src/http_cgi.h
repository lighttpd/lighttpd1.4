/*
 * http_cgi - Common Gateway Interface (CGI) interfaces (RFC 3875)
 *
 * Copyright(c) 2016-2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_HTTP_CGI_H
#define INCLUDED_HTTP_CGI_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

typedef struct http_cgi_opts_t {
  int authorizer;
  int break_scriptfilename_for_php;
  const buffer *docroot;
  const buffer *strip_request_uri;
} http_cgi_opts;

typedef int (*http_cgi_header_append_cb)(void *vdata, const char *k, size_t klen, const char *v, size_t vlen);

int http_cgi_headers (request_st *r, http_cgi_opts *opts, http_cgi_header_append_cb cb, void *vdata);

handler_t http_cgi_local_redir (request_st *r);

#endif
