#ifndef _REQUEST_H_
#define _REQUEST_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

int http_request_parse(connection *con, char *hdrs, const unsigned short *hloffsets);
int http_request_host_normalize(buffer *b, int scheme_port);
int http_request_host_policy(buffer *b, const buffer *scheme, unsigned int http_parseopts);

#endif
