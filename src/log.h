#ifndef _LOG_H_
#define _LOG_H_

#include "server.h"

#define WP() log_error_write(srv, __FILE__, __LINE__, "");

int log_error_open(server *srv);
int log_error_close(server *srv);
int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...);
int log_error_cycle(server *srv);
	
#endif
