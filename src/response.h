#ifndef _RESPONSE_H_
#define _RESPONSE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"

#include <time.h>

int http_response_parse(server *srv, connection *con);
int http_response_write_header(connection *con);

typedef struct http_cgi_opts_t {
  int authorizer;
  int break_scriptfilename_for_php;
  const buffer *docroot;
  const buffer *strip_request_uri;
} http_cgi_opts;

enum {
  BACKEND_UNSET = 0,
  BACKEND_PROXY,
  BACKEND_CGI,
  BACKEND_FASTCGI,
  BACKEND_SCGI
};

typedef struct http_response_opts_t {
  int fdfmt;
  int backend;
  int authorizer;
  unsigned short local_redir;
  unsigned short xsendfile_allow;
  const array *xsendfile_docroot;
  void *pdata;
  handler_t(*parse)(connection *, struct http_response_opts_t *, buffer *, size_t);
  handler_t(*headers)(connection *, struct http_response_opts_t *);
} http_response_opts;

typedef int (*http_cgi_header_append_cb)(void *vdata, const char *k, size_t klen, const char *v, size_t vlen);
int http_cgi_headers(connection *con, http_cgi_opts *opts, http_cgi_header_append_cb cb, void *vdata);

handler_t http_response_parse_headers(connection *con, http_response_opts *opts, buffer *hdrs);
handler_t http_response_read(connection *con, http_response_opts *opts, buffer *b, fdnode *fdn);
handler_t http_response_prepare(connection *con);
int http_response_redirect_to_directory(connection *con, int status);
int http_response_handle_cachable(connection *con, const buffer * mtime);
void http_response_body_clear(connection *con, int preserve_length);
void http_response_send_file (connection *con, buffer *path);
void http_response_backend_done (connection *con);
void http_response_backend_error (connection *con);
void http_response_upgrade_read_body_unknown(connection *con);

__attribute_cold__
void strftime_cache_reset(void);

const buffer * strftime_cache_get(time_t last_mod);
#endif
