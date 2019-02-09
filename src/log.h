#ifndef _LOG_H_
#define _LOG_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

struct timespec; /* declaration */
int log_clock_gettime_realtime (struct timespec *ts);

ssize_t write_all(int fd, const void* buf, size_t count);

__attribute_cold__
int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...);

__attribute_cold__
int log_error_write_multiline_buffer(server *srv, const char *filename, unsigned int line, buffer *multiline, const char *fmt, ...);

#endif
