/* _XOPEN_SOURCE >= 500 for vsnprintf() */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "first.h"

#include "log.h"

#include <sys/types.h>
#include "sys-time.h"
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf() */
#include <stdlib.h>     /* malloc() free() */
#include <unistd.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "ck.h"
#include "fdlog.h"

static fdlog_st log_stderrh = { FDLOG_FD, STDERR_FILENO, { NULL, 0, 0 }, NULL };
static fdlog_st *log_errh = &log_stderrh;
static unix_time64_t log_tlast = 0;

/* log_con_jqueue instance here to be defined in shared object (see base.h) */
connection *log_con_jqueue;

unix_time64_t log_epoch_secs = 0;
unix_time64_t log_monotonic_secs = 0;

#if !defined(HAVE_CLOCK_GETTIME) || !HAS_TIME_BITS64

int log_clock_gettime (const int clockid, unix_timespec64_t * const ts) {
  #ifdef HAVE_CLOCK_GETTIME
   #if HAS_TIME_BITS64
    return clock_gettime(clockid, ts);
   #else
    struct timespec ts32;
    int rc = clock_gettime(clockid, &ts32);
    if (0 == rc) {
        /*(treat negative 32-bit tv.tv_sec as unsigned)*/
        ts->tv_sec  = TIME64_CAST(ts32.tv_sec);
        ts->tv_nsec = ts32.tv_nsec;
    }
    return rc;
   #endif
  #else
    /* Mac OSX before 10.12 Sierra does not provide clock_gettime()
     * e.g. defined(__APPLE__) && defined(__MACH__)
     *      && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 101200 */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    UNUSED(clockid);
   #if HAS_TIME_BITS64
    ts->tv_sec = tv.tv_sec;
   #else /*(treat negative 32-bit tv.tv_sec as unsigned)*/
    ts->tv_sec = TIME64_CAST(tv.tv_sec);
   #endif
    ts->tv_nsec = tv.tv_usec * 1000;
    return 0;
  #endif
}

int log_clock_gettime_realtime (unix_timespec64_t *ts) {
  #ifdef HAVE_CLOCK_GETTIME
    return log_clock_gettime(CLOCK_REALTIME, ts);
  #else
    return log_clock_gettime(0, ts);
  #endif
}

#endif /* !defined(HAVE_CLOCK_GETTIME) || !HAS_TIME_BITS64 */


/* retry write on EINTR or when not all data was written */
ssize_t write_all(int fd, const void * const buf, size_t count) {
    ssize_t written = 0;
    ssize_t wr;

    do {
        wr = write(fd, (const char *)buf + written, count);
    } while (wr > 0 ? (written += wr, count -= wr) : wr < 0 && errno == EINTR);

    if (__builtin_expect( (0 == count), 1))
        return written;
    else {
        if (0 == wr) errno = EIO; /* really shouldn't happen... */
        return -1; /* fail - repeating probably won't help */
    }
}


__attribute_nonnull__()
static void
log_buffer_timestamp (buffer * const restrict b)
{
    if (-2 == log_tlast) { /* -2 is value to flag high-precision timestamp */
        unix_timespec64_t ts = { 0, 0 };
        log_clock_gettime_realtime(&ts);
      #if 0
        buffer_append_int(b, TIME64_CAST(ts.tv_sec));
      #else /*(closer to syslog time format RFC 3339)*/
        struct tm tm;
        buffer_append_strftime(b, "%F %T",
                               localtime64_r(&ts.tv_sec, &tm));
      #endif
        buffer_append_string_len(b, CONST_STR_LEN(".000000000: "));
        char n[LI_ITOSTRING_LENGTH];
        const size_t nlen =
          li_utostrn(n, sizeof(n), (unsigned long)ts.tv_nsec);
        memcpy(b->ptr+buffer_clen(b)-nlen-2, n, nlen);
    }
    else {
        /* cache the generated timestamp */
        static uint32_t tlen;
        static char tstr[24]; /* 20 "%F %T" incl '\0' +2 ": " */
        if (__builtin_expect( (log_tlast != log_epoch_secs), 0)) {
            struct tm tm;
            log_tlast = log_epoch_secs;
            tlen = (uint32_t)
                     strftime(tstr, sizeof(tstr), "%F %T",
                              localtime64_r(&log_tlast, &tm));
            tstr[  tlen] = ':';
            tstr[++tlen] = ' ';
            /*tstr[++tlen] = '\0';*//*(not necessary for our use)*/
                   ++tlen;
        }

        buffer_copy_string_len(b, tstr, tlen);
    }
}


__attribute_nonnull__()
static void
log_buffer_prefix (buffer * const restrict b,
                   const char * const restrict filename,
                   const unsigned int line)
{
    char lstr[LI_ITOSTRING_LENGTH];
    struct const_iovec iov[] = {
      { CONST_STR_LEN("(") }
     ,{ filename, strlen(filename) }
     ,{ CONST_STR_LEN(".") }
     ,{ lstr, li_itostrn(lstr, sizeof(lstr), line) }
     ,{ CONST_STR_LEN(") ") }
    };
    buffer_append_iovec(b, iov, sizeof(iov)/sizeof(*iov));
}


static void
log_buffer_append_encoded (buffer * const b,
                           const char * const s, const size_t n)
{
    size_t i;
    for (i = 0; i < n && ' ' <= s[i] && s[i] <= '~'; ++i) ;/*(ASCII isprint())*/
    if (i == n)
        buffer_append_string_len(b, s, n);  /* common case; nothing to encode */
    else
        buffer_append_string_c_escaped(b, s, n);
}


__attribute_format__((__printf__, 2, 0))
__attribute_nonnull__()
static void
log_buffer_vsprintf (buffer * const restrict b,
                     const char * const restrict fmt, va_list ap)
{
    /* NOTE: log_buffer_prefix() ensures 0 != b->used */
    /*assert(0 != b->used);*//*(only because code calcs below assume this)*/
    /*assert(0 != b->size);*//*(b has non-size after log_buffer_prefix())*/
    size_t blen = buffer_clen(b);
    size_t bsp  = buffer_string_space(b)+1;
    char *s = b->ptr + blen;
    size_t n;

    va_list aptry;
    va_copy(aptry, ap);
    n = (size_t)vsnprintf(s, bsp, fmt, aptry);
    va_end(aptry);

    if (n < bsp)
        buffer_truncate(b, blen+n); /*buffer_commit(b, n);*/
    else {
        s = buffer_extend(b, n);
        vsnprintf(s, n+1, fmt, ap);
    }

    size_t i;
    for (i = 0; i < n && ' ' <= s[i] && s[i] <= '~'; ++i) ;/*(ASCII isprint())*/
    if (i == n) return; /* common case; nothing to encode */

    /* need to encode log line
     * copy original line fragment, append encoded line to buffer, free copy */
    char * const src = (char *)malloc(n);
    memcpy(src, s, n); /*(note: not '\0'-terminated)*/
    buffer_truncate(b, blen);
    buffer_append_string_c_escaped(b, src, n);
    free(src);
}


__attribute_nonnull__()
static buffer *
log_buffer_prepare (const log_error_st * const errh,
                    const char * const restrict filename,
                    const unsigned int line)
{
    buffer * const restrict b = &log_errh->b; /*(use shared temp buffer)*/
    buffer_clear(b);
    if (errh->mode != FDLOG_SYSLOG) { /*(syslog() generates its own timestamp)*/
        if (-1 == errh->fd) return NULL;
        log_buffer_timestamp(b);
    }
    log_buffer_prefix(b, filename, line);
    return b;
}


__attribute_nonnull__()
static void
log_error_write (const log_error_st * const errh, buffer * const restrict b)
{
    if (errh->mode != FDLOG_SYSLOG) { /* FDLOG_FD FDLOG_FILE FDLOG_PIPE */
        buffer_append_string_len(b, CONST_STR_LEN("\n"));
        write_all(errh->fd, BUF_PTR_LEN(b));
    }
    else {
        syslog(LOG_ERR, "%s", b->ptr);
    }
}


__attribute_noinline__
static void
log_error_append_strerror (buffer * const b, const int errnum)
{
    char buf[1024];
    errno_t rc = ck_strerror_s(buf, sizeof(buf), errnum);
    if (0 == rc || rc == ERANGE)
        buffer_append_str2(b, CONST_STR_LEN(": "), buf, strlen(buf));
}


__attribute_format__((__printf__, 4, 0))
static void
log_error_va_list_impl (const log_error_st *errh,
                        const char * const restrict filename,
                        const unsigned int line,
                        const char * const restrict fmt, va_list ap,
                        const int perr)
{
    const int errnum = errno;

    if (NULL == errh) errh = log_errh;
    buffer * const restrict b = log_buffer_prepare(errh, filename, line);
    if (NULL == b) return; /*(errno not modified if errh->fd == -1)*/

    log_buffer_vsprintf(b, fmt, ap);
    if (perr)
        log_error_append_strerror(b, errnum);

    log_error_write(errh, b);

    buffer_clear(b);
    errno = errnum;
}


void
log_error(log_error_st * const errh,
          const char * const filename, const unsigned int line,
          const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_error_va_list_impl(errh, filename, line, fmt, ap, 0);
    va_end(ap);
}


void
log_perror (log_error_st * const errh,
            const char * const filename, const unsigned int line,
            const char * const fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_error_va_list_impl(errh, filename, line, fmt, ap, 1);
    va_end(ap);
}


void
log_error_multiline (log_error_st *errh,
                     const char * const restrict filename,
                     const unsigned int line,
                     const char * const restrict multiline,
                     const size_t len,
                     const char * const restrict fmt, ...)
{
    if (0 == len) return;

    const int errnum = errno;

    if (NULL == errh) errh = log_errh;
    buffer * const restrict b = log_buffer_prepare(errh, filename, line);
    if (NULL == b) return; /*(errno not modified if errh->fd == -1)*/

    va_list ap;
    va_start(ap, fmt);
    log_buffer_vsprintf(b, fmt, ap);
    va_end(ap);

    const uint32_t prefix_len = buffer_clen(b);
    const char * const end = multiline + len;
    for (const char *pos = multiline; pos < end; ++pos) {
        const char * const current_line = pos;
        pos = strchr(pos, '\n');
        if (!pos)
            pos = end;
        size_t n = (size_t)(pos - current_line);
        if (n && current_line[n-1] == '\r') --n; /*(skip "\r\n")*/
        buffer_truncate(b, prefix_len);
        log_buffer_append_encoded(b, current_line, n);
        log_error_write(errh, b);
    }

    buffer_clear(b);
    errno = errnum;
}


log_error_st *
log_set_global_errh (log_error_st * const errh, const int ts_high_precision)
{
    /* reset log_tlast
     * -1 for cached timestamp to not match log_epoch_secs
     *    (e.g. if realtime clock init at 0)
     * -2 for high precision timestamp */
    log_tlast = ts_high_precision ? -2 : -1;

    buffer_free_ptr(&log_stderrh.b);
    return (log_errh = errh ? errh : &log_stderrh);
}
