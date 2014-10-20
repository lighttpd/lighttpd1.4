#ifndef _LOG_H_
#define _LOG_H_

#include "server.h"

/**
 * From whole sources of the lighttpd1.4, we can find that the second and third parameter in the
 * function log_error_write and log_error_multiline_buffer are __FILE__, __LINE__ respectively.
 * So we can define two macros: log_error_write_caf,log_error_write_multiline_buffer_caf instead
 * Apparently, They avoid a lot of repeated operations. Certainly, It is not only compatible, but also
 * convenient and fast for the future's use;
 * 	"convenient and fast"  logogram: caf
 * 	So I Use of 'caf' as a suffix of the macros.
 */
#define log_error_write_caf(srv, fmt, ...) \
	log_error_write(src, __FILE__, __LINE__, fmt, __VA_ARGS__);

#define log_error_write_multiline_buffer_caf(src, multiline, fmt, ...) \
	log_error_write_multiline_buffer(src, __FILE__, __LINE__, multiline, fmt, __VA_ARGS__);

/* Close fd and _try_ to get a /dev/null for it instead.
 * Returns 0 on success and -1 on failure (fd gets closed in all cases)
 */
int openDevNull(int fd);

int open_logfile_or_pipe(server *srv, const char* logfile);

int log_error_open(server *srv);
int log_error_close(server *srv);
int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...);
int log_error_write_multiline_buffer(server *srv, const char *filename, unsigned int line, buffer *multiline, const char *fmt, ...);
int log_error_cycle(server *srv);

#endif
