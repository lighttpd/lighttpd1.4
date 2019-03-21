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

struct log_error_st {
    enum { ERRORLOG_FILE, ERRORLOG_FD, ERRORLOG_SYSLOG, ERRORLOG_PIPE } errorlog_mode;
    int errorlog_fd;
    buffer *b;
    buffer *tb;
    time_t *cur_ts;
    time_t *last_ts;
};

__attribute_cold__
log_error_st * log_error_st_init (time_t *cur_ts_ptr, time_t *last_ts_ptr);

__attribute_cold__
void log_error_st_free (log_error_st *errh);

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_error(const log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_perror(const log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

#endif
