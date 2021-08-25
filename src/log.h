#ifndef _LOG_H_
#define _LOG_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

extern unix_time64_t log_epoch_secs;
extern unix_time64_t log_monotonic_secs;

#if defined(HAVE_CLOCK_GETTIME) && HAS_TIME_BITS64
#define log_clock_gettime(clockid,ts)  clock_gettime((clockid),(ts))
#define log_clock_gettime_realtime(ts) clock_gettime(CLOCK_REALTIME,(ts))
#else
int log_clock_gettime(int clockid, unix_timespec64_t *ts);
int log_clock_gettime_realtime (unix_timespec64_t *ts);
#endif

ssize_t write_all(int fd, const void* buf, size_t count);

struct log_error_st {
    enum { ERRORLOG_FILE, ERRORLOG_FD, ERRORLOG_SYSLOG, ERRORLOG_PIPE } errorlog_mode;
    int errorlog_fd;
    buffer b;
    const char *fn;
};

__attribute_cold__
__attribute_malloc__
__attribute_returns_nonnull__
log_error_st * log_error_st_init (void);

__attribute_cold__
void log_error_st_free (log_error_st *errh);

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_error(log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_perror(log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

__attribute_cold__
__attribute_format__((__printf__, 6, 7))
void log_error_multiline(log_error_st *errh, const char *filename, unsigned int line, const char * restrict multiline, const size_t len, const char *fmt, ...);

#endif
