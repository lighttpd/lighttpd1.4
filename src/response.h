#ifndef _RESPONSE_H_
#define _RESPONSE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"

#include <time.h>

int http_response_parse(server *srv, request_st *r);

typedef struct http_cgi_opts_t {
  int authorizer;
  int break_scriptfilename_for_php;
  const buffer *docroot;
  const buffer *strip_request_uri;
} http_cgi_opts;

enum {
  BACKEND_PROXY = 0
 ,BACKEND_CGI
 ,BACKEND_FASTCGI
 ,BACKEND_SCGI
 ,BACKEND_AJP13
};

typedef struct http_response_opts_t {
  int fdfmt;
  int backend;
  int authorizer;
  unsigned short local_redir;
  unsigned short xsendfile_allow;
  const array *xsendfile_docroot;
  void *pdata;
  handler_t(*parse)(request_st *, struct http_response_opts_t *, buffer *, size_t);
  handler_t(*headers)(request_st *, struct http_response_opts_t *);
} http_response_opts;

typedef int (*http_cgi_header_append_cb)(void *vdata, const char *k, size_t klen, const char *v, size_t vlen);
int http_cgi_headers(request_st *r, http_cgi_opts *opts, http_cgi_header_append_cb cb, void *vdata);

typedef int (*http_response_send_1xx_cb)(request_st *r, connection *con);
__attribute_cold__
void http_response_send_1xx_cb_set (http_response_send_1xx_cb fn, int vers);
int http_response_send_1xx (request_st *r);

handler_t http_response_parse_headers(request_st *r, http_response_opts *opts, buffer *hdrs);
handler_t http_response_read(request_st *r, http_response_opts *opts, buffer *b, fdnode *fdn);

__attribute_cold__
handler_t http_response_reqbody_read_error(request_st *r, int http_status);

int http_response_buffer_append_authority(request_st *r, buffer *o);
int http_response_redirect_to_directory(request_st *r, int status);
const buffer * http_response_set_last_modified(request_st *r, time_t lmtime);
int http_response_handle_cachable(request_st *r, const buffer *lmod, time_t lmtime);
void http_response_body_clear(request_st *r, int preserve_length);
void http_response_reset(request_st *r);
void http_response_send_file (request_st *r, buffer *path);
void http_response_backend_done (request_st *r);
void http_response_backend_error (request_st *r);
void http_response_upgrade_read_body_unknown(request_st *r);

__attribute_cold__
int http_response_omit_header(request_st *r, const data_string *ds);

void http_response_write_header(request_st *r);
handler_t http_response_handler(request_st *r);

__attribute_cold__
void strftime_cache_reset(void);

#endif
