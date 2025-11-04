#ifndef INCLUDED_HTTP_STATUS_H
#define INCLUDED_HTTP_STATUS_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

__attribute_nonnull__()
void http_status_append (buffer *b, int http_status);

#define http_status_set_fin(r, code) ((r)->resp_body_finished = 1, \
                                      (r)->handler_module = NULL, \
                                      (r)->http_status = (code))
#define http_status_set(r, code)     ((r)->http_status = (code))
#define http_status_is_set(r)        ((r)->http_status != 0)
#define http_status_unset(r)         ((r)->http_status = 0)
#define http_status_get(r)           ((r)->http_status)

__attribute_cold__
handler_t http_status_set_err (request_st *r, int http_status);

__attribute_cold__
handler_t http_status_set_err_fin (request_st *r, int http_status);

__attribute_cold__
handler_t http_status_set_err_close (request_st *r, int http_status);

#endif
