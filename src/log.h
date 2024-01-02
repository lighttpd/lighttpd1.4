#ifndef _LOG_H_
#define _LOG_H_
#include "first.h"

#include "base_decls.h"

__declspec_dllimport__
extern unix_time64_t log_epoch_secs;
__declspec_dllimport__
extern unix_time64_t log_monotonic_secs;

#if defined(HAVE_CLOCK_GETTIME) && HAS_TIME_BITS64
#define log_clock_gettime(clockid,ts)  clock_gettime((clockid),(ts))
#define log_clock_gettime_realtime(ts) clock_gettime(CLOCK_REALTIME,(ts))
#else
int log_clock_gettime(int clockid, unix_timespec64_t *ts);
int log_clock_gettime_realtime (unix_timespec64_t *ts);
#endif

ssize_t write_all(int fd, const void* buf, size_t count);

__attribute_cold__
__attribute_format__((__printf__, 5, 0))
void
log_pri(log_error_st *errh, const char *filename, unsigned int line, int pri, const char *fmt, ...);

/* (include fmt in __VA_ARGS__ for portability) */
/* (__VA_OPT__(,) not supported on older compilers) */
#define log_emerg(errh, file, line, ...) \
        log_pri((errh),(file),(line),0,__VA_ARGS__)
#define log_alert(errh, file, line, ...) \
        log_pri((errh),(file),(line),1,__VA_ARGS__)
#define log_crit(errh, file, line, ...) \
        log_pri((errh),(file),(line),2,__VA_ARGS__)
#define log_err(errh, file, line, ...) \
        log_pri((errh),(file),(line),3,__VA_ARGS__)
#define log_warn(errh, file, line, ...) \
        log_pri((errh),(file),(line),4,__VA_ARGS__)
#define log_notice(errh, file, line, ...) \
        log_pri((errh),(file),(line),5,__VA_ARGS__)
#define log_info(errh, file, line, ...) \
        log_pri((errh),(file),(line),6,__VA_ARGS__)
#if 0 /*(widely used; smaller code size as func in log.c)*/
#define log_debug(errh, file, line, ...) \
        log_pri((errh),(file),(line),7,__VA_ARGS__)
#endif /* log_pdebug() for debug similar to log_perror() */
#define log_pdebug(errh, file, line, ...) \
        log_pri((errh),(file),(line),((1 << 8) | 7),__VA_ARGS__)

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_debug(log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_error(log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_perror(log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);

#ifdef _WIN32
__attribute_cold__
__attribute_format__((__printf__, 4, 5))
void log_serror(log_error_st *errh, const char *filename, unsigned int line, const char *fmt, ...);
#else
#define log_serror log_perror
#endif

__attribute_cold__
__attribute_format__((__printf__, 7, 8))
void log_pri_multiline(log_error_st *errh, const char *filename, unsigned int line, int pri, const char * restrict multiline, const size_t len, const char *fmt, ...);

/* (include fmt in __VA_ARGS__ for portability) */
/* (__VA_OPT__(,) not supported on older compilers) */
#define log_emerg_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),0,__VA_ARGS__)
#define log_alert_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),1,__VA_ARGS__)
#define log_crit_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),2,__VA_ARGS__)
#define log_err_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),3,__VA_ARGS__)
#define log_warn_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),4,__VA_ARGS__)
#define log_notice_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),5,__VA_ARGS__)
#define log_info_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),6,__VA_ARGS__)
#define log_debug_multiline(errh, file, line, ...) \
        log_pri_multiline((errh),(file),(line),7,__VA_ARGS__)

/*(backwards compat for historic log_error_multiline())*/
#define log_error_multiline log_err_multiline

__attribute_cold__
__attribute_returns_nonnull__
log_error_st * log_set_global_errh (log_error_st *errh, int ts_high_precision);

#endif
