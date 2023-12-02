#ifndef _RESPONSE_H_
#define _RESPONSE_H_
#include "first.h"

#include "sys-time.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"

struct stat_cache_entry;/* declaration */
struct chunkqueue;      /* declaration */

struct http_dispatch {
    int  (*process_streams)  (connection *,
                              handler_t(*http_response_handler)(request_st *),
                              int(*)(request_st *, connection *));
    void (*upgrade_h2)       (request_st *, connection *);
    void (*upgrade_h2c)      (request_st *, connection *);
    int  (*send_100_continue)(request_st *, connection *);
    int  (*send_1xx)         (request_st *, connection *);
    int  (*check_timeout)    (connection *, unix_time64_t);
    int  (*goaway_graceful)  (connection *);  /* graceful restart/shutdown */
};

/* http_dispatch is in http-header-glue.c to be defined in shared object */
__declspec_dllimport__
extern struct http_dispatch http_dispatch[4]; /*(index by http_version_t)*/

int http_response_parse(server *srv, request_st *r);

enum {
  BACKEND_PROXY = 0
 ,BACKEND_CGI
 ,BACKEND_FASTCGI
 ,BACKEND_SCGI
 ,BACKEND_AJP13
};

typedef struct http_response_opts_t {
  uint32_t max_per_read;
  int fdfmt;
  int backend;
  int authorizer; /* bool *//*(maybe overloaded w/ response streaming flags)*/
  uint8_t simple_accum; /* bool */
  uint8_t local_redir; /* 0,1,2 */
  uint8_t upgrade; /* 0,1,2 */
  uint8_t xsendfile_allow; /* bool */
  const array *xsendfile_docroot;
  void *pdata;
  handler_t(*parse)(request_st *, struct http_response_opts_t *, buffer *, size_t);
  handler_t(*headers)(request_st *, struct http_response_opts_t *);
} http_response_opts;

int http_response_send_1xx (request_st *r);

handler_t http_response_parse_headers(request_st *r, http_response_opts *opts, buffer *hdrs);
handler_t http_response_read(request_st *r, http_response_opts *opts, buffer *b, fdnode *fdn);

__attribute_cold__
handler_t http_response_reqbody_read_error(request_st *r, int http_status);

int http_response_buffer_append_authority(request_st *r, buffer *o);
int http_response_redirect_to_directory(request_st *r, int status);
const buffer * http_response_set_last_modified(request_st *r, unix_time64_t lmtime);
int http_response_handle_cachable(request_st *r, const buffer *lmod, unix_time64_t lmtime);
void http_response_body_clear(request_st *r, int preserve_length);
void http_response_reset(request_st *r);
void http_response_send_file (request_st *r, const buffer *path, struct stat_cache_entry *sce);
void http_response_backend_done (request_st *r);
void http_response_backend_error (request_st *r);
void http_response_upgrade_read_body_unknown(request_st *r);
int http_response_transfer_cqlen(request_st *r, struct chunkqueue *cq, size_t len);

__attribute_cold__
void http_response_delay(connection *con);

__attribute_cold__
int http_response_omit_header(request_st *r, const data_string *ds);

handler_t http_response_handler(request_st *r);

__attribute_cold__
void strftime_cache_reset(void);

#endif
