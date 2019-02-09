#ifndef _REQUEST_H_
#define _REQUEST_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

int http_request_parse(server *srv, connection *con, buffer *hdrs);
int http_request_host_normalize(buffer *b, int scheme_port);
int http_request_host_policy(connection *con, buffer *b, const buffer *scheme);

#endif
