#ifndef _RESPONSE_H_
#define _RESPONSE_H_

#include "server.h"

int http_response_parse(server *srv, connection *con);
int http_response_write_basic_header(server *srv, connection *con);
int http_response_write_header(server *srv, connection *con, 
			       off_t file_size, 
			       time_t last_mod);

int response_header_insert(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen);
int response_header_overwrite(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen);

handler_t http_response_prepare(server *srv, connection *con);
int http_response_redirect_to_directory(server *srv, connection *con);

#endif
