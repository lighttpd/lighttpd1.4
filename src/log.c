/* _XOPEN_SOURCE >= 500 for vsnprintf() */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "first.h"

#undef __declspec_dllimport__
#define __declspec_dllimport__  __declspec_dllexport__

#include "log.h"

#include <sys/types.h>
#include "sys-time.h"
#include "sys-unistd.h" /* <unistd.h> */
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf() */
#include <stdlib.h>     /* malloc() free() */

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "ck.h"
#include "fdlog.h"

static fdlog_st log_stderrh = { FDLOG_FD, STDERR_FILENO, { NULL, 0, 0 }, NULL };
static fdlog_st *log_errh = &log_stderrh;
static unix_time64_t tlast;
static uint32_t thp;
static uint32_t tlen;
static char tstr[24]; /* 20 "%F %T" incl '\0' +2 ": " */

/* log_con_jqueue instance here to be defined in shared object (see base.h) */
__declspec_dllexport__
connection *log_con_jqueue;

__declspec_dllexport__
unix_time64_t log_epoch_secs = 0;
__declspec_dllexport__
unix_time64_t log_monotonic_secs = 0;

#if !defined(HAVE_CLOCK_GETTIME) || !HAS_TIME_BITS64

#ifdef _MSC_VER
#include <windows.h>
#endif

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
  #elif defined(_MSC_VER)
    /* https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime */
    /* https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime */
    /* Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC). */
    UNUSED(clockid);
    union { FILETIME ft; ULARGE_INTEGER u; } n; /*(alignment)*/
    GetSystemTimeAsFileTime(&n.ft);
    n.u.QuadPart -= 116444736000000000uLL; /* FILETIME Jan 1 1970 00:00:00 */
    ts->tv_sec  = (unix_time64_t)(n.u.QuadPart / 10000000uL);
    ts->tv_nsec = (unix_time64_t)(n.u.QuadPart % 10000000uL * 100uL);
    return 0;
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


static void
log_buffer_tstr (const unix_time64_t t)
{
    /* cache the generated timestamp */
    struct tm tm;
    tlast = t;
   #ifdef __MINGW32__
    tlen = (uint32_t) strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S",
                               localtime64_r(&tlast, &tm));
   #else
    tlen = (uint32_t) strftime(tstr, sizeof(tstr), "%F %T",
                               localtime64_r(&tlast, &tm));
   #endif
}


__attribute_nonnull__()
static void
log_buffer_timestamp (buffer * const restrict b)
{
    if (thp) { /* high-precision timestamp */
        unix_timespec64_t ts = { 0, 0 };
        log_clock_gettime_realtime(&ts);
      #if 0
        buffer_append_int(b, TIME64_CAST(ts.tv_sec));
        buffer_append_string_len(b, CONST_STR_LEN(".000000000: "));
      #else /*(closer to syslog time format RFC 3339)*/
        if (__builtin_expect( (tlast != ts.tv_sec), 0))
            log_buffer_tstr(ts.tv_sec);
        buffer_append_str2(b, tstr, tlen, CONST_STR_LEN(".000000000: "));
      #endif
        char n[LI_ITOSTRING_LENGTH];
        const size_t nlen =
          li_utostrn(n, sizeof(n), (unsigned long)ts.tv_nsec);
        memcpy(b->ptr+buffer_clen(b)-nlen-2, n, nlen);
    }
    else {
        if (__builtin_expect( (tlast != log_epoch_secs), 0)) {
            log_buffer_tstr(log_epoch_secs);
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
    unsigned int n;

    va_list aptry;
    va_copy(aptry, ap);
    n = (unsigned int)vsnprintf(s, bsp, fmt, aptry);
    va_end(aptry);

    if ((int)n <= 0)
        return;
    if (n < bsp)
        buffer_truncate(b, blen+n); /*buffer_commit(b, n);*/
    else {
        s = buffer_extend(b, n);
        vsnprintf(s, n+1, fmt, ap);
    }

    unsigned int i;
    for (i = 0; i < n && ' ' <= s[i] && s[i] <= '~'; ++i) ;/*(ASCII isprint())*/
    if (i == n) return; /* common case; nothing to encode */

    /* need to encode log line
     * copy original line fragment, append encoded line to buffer, free copy */
    n -= i;
    char * const src = (char *)ck_malloc(n);
    memcpy(src, s+i, n); /*(note: not '\0'-terminated)*/
    buffer_truncate(b, blen+i);
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
log_error_write (const log_error_st * const errh, buffer * const restrict b, const int pri)
{
    if (errh->mode != FDLOG_SYSLOG) { /* FDLOG_FD FDLOG_FILE FDLOG_PIPE */
        buffer_append_char(b, '\n');
        write_all(errh->fd, BUF_PTR_LEN(b));
    }
    else {
      #ifdef HAVE_SYSLOG_H
       #ifndef LOG_PRI
       #define LOG_PRI(x) (x & 3)
       #endif
        syslog(LOG_PRI(pri), "%s", b->ptr);
      #else
        UNUSED(pri);
      #endif
    }
}


#ifdef _WIN32
#include <winsock2.h>   /* WSAGetLastError() */

__attribute_noinline__
static void
log_error_append_winerror (buffer * const b, DWORD dwMessageId)
{
    if (0 == dwMessageId) return; /* The operation completed successfully. */
    TCHAR lpMsgBuf[1024];
    lpMsgBuf[0] = '\0';
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, dwMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)lpMsgBuf, sizeof(lpMsgBuf)/sizeof(TCHAR), NULL);
    size_t len = strlen(lpMsgBuf);
    if (len && lpMsgBuf[len-1] == '\n') --len;
    if (len && lpMsgBuf[len-1] == '\r') --len;
    buffer_append_str2(b, CONST_STR_LEN(": "), lpMsgBuf, len);
}
#endif


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
log_va_list (const log_error_st *errh,
             const char * const restrict filename,
             const unsigned int line,
             const char * const restrict fmt, va_list ap,
             const int pri)
{
    const int errnum = errno;

    if (NULL == errh) errh = log_errh;
    buffer * const restrict b = log_buffer_prepare(errh, filename, line);
    if (NULL == b) return; /*(errno not modified if errh->fd == -1)*/

    log_buffer_vsprintf(b, fmt, ap);
  #ifdef _WIN32
    switch (pri >> 8) {
      case 0: default: break;
      case 1: log_error_append_winerror(b, GetLastError());
              if (errnum) log_error_append_strerror(b, errnum);
              break;
      case 2: log_error_append_winerror(b, WSAGetLastError());
              break;
    }
  #else
    if (pri >> 8)
        log_error_append_strerror(b, errnum);
  #endif

    log_error_write(errh, b, pri);

    buffer_clear(b);
    errno = errnum;
}


#ifndef LOG_ERR
#define LOG_ERR 3
#endif
#ifndef LOG_DEBUG
#define LOG_DEBUG 7
#endif


void
log_debug(log_error_st * const errh,
          const char * const filename, const unsigned int line,
          const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_va_list(errh, filename, line, fmt, ap, ((0 << 8) | LOG_DEBUG));
    va_end(ap);
}


void
log_error(log_error_st * const errh,
          const char * const filename, const unsigned int line,
          const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_va_list(errh, filename, line, fmt, ap, ((0 << 8) | LOG_ERR));
    va_end(ap);
}


void
log_perror (log_error_st * const errh,
            const char * const filename, const unsigned int line,
            const char * const fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_va_list(errh, filename, line, fmt, ap, ((1 << 8) | LOG_ERR));
    va_end(ap);
}


#ifdef _WIN32
void
log_serror (log_error_st * const errh,
            const char * const filename, const unsigned int line,
            const char * const fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_va_list(errh, filename, line, fmt, ap, ((2 << 8) | LOG_ERR));
    va_end(ap);
}
#endif


void
log_pri (log_error_st * const errh,
         const char * const filename, const unsigned int line,
         const int pri, const char *fmt, ...)
{
    /*(same as log_error() with extra 'pri' param for syslog())*/
    va_list ap;
    va_start(ap, fmt);           /*((0 << 8) | pri)*/
    log_va_list(errh, filename, line, fmt, ap, pri);
    va_end(ap);
}


void
log_pri_multiline (log_error_st *errh,
                   const char * const restrict filename,
                   const unsigned int line,
                   const int pri,
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
        log_error_write(errh, b, pri);
    }

    buffer_clear(b);
    errno = errnum;
}


log_error_st *
log_set_global_errh (log_error_st * const errh, const int ts_high_precision)
{
    /* reset tlast
     * -1 for cached timestamp to not match log_epoch_secs
     *    (e.g. if realtime clock init at 0)
     */
    tlast = -1;
    thp = ts_high_precision;

    buffer_free_ptr(&log_stderrh.b);
    return (log_errh = errh ? errh : &log_stderrh);
}
