/* _XOPEN_SOURCE >= 500 for vsnprintf() */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "first.h"

#include "ck.h"
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

unix_time64_t log_epoch_secs = 0;
unix_time64_t log_monotonic_secs = 0;

int log_clock_gettime_realtime (unix_timespec64_t *ts) {
  #ifdef HAVE_CLOCK_GETTIME
   #if HAS_TIME_BITS64
    return clock_gettime(CLOCK_REALTIME, ts);
   #else
    struct timespec ts32;
    int rc = clock_gettime(CLOCK_REALTIME, &ts32);
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
   #if HAS_TIME_BITS64
    ts->tv_sec = tv.tv_sec;
   #else /*(treat negative 32-bit tv.tv_sec as unsigned)*/
    ts->tv_sec = TIME64_CAST(tv.tv_sec);
   #endif
    ts->tv_nsec = tv.tv_usec * 1000;
    return 0;
  #endif
}

int log_clock_gettime_monotonic (unix_timespec64_t *ts) {
  #ifdef HAVE_CLOCK_GETTIME
   #if HAS_TIME_BITS64
    return clock_gettime(CLOCK_MONOTONIC, ts);
   #else
    struct timespec ts32;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts32);
    if (0 == rc) {
        /*(treat negative 32-bit tv.tv_sec as unsigned)*/
        /*(negative 32-bit should not happen on monotonic clock
         * unless system running continously for > 68 years)*/
        ts->tv_sec  = TIME64_CAST(ts32.tv_sec);
        ts->tv_nsec = ts32.tv_nsec;
    }
    return rc;
   #endif
  #else
    return log_clock_gettime_realtime(ts); /*(fallback)*/
  #endif
}

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

static int log_buffer_prepare(const log_error_st *errh, const char *filename, unsigned int line, buffer *b) {
	static unix_time64_t tlast;
	static uint32_t tlen;
	static char tstr[24]; /* 20 "%F %T" incl '\0' +3 ": (" */
	switch(errh->errorlog_mode) {
	case ERRORLOG_PIPE:
	case ERRORLOG_FILE:
	case ERRORLOG_FD:
		if (-1 == errh->errorlog_fd) return -1;
		/* cache the generated timestamp */
		if (__builtin_expect( (tlast != log_epoch_secs), 0)) {
			struct tm tm;
			tlast = log_epoch_secs;
			tlen = (uint32_t)
			  strftime(tstr, sizeof(tstr), "%F %T",
			           localtime64_r(&tlast, &tm));
			tstr[  tlen] = ':';
			tstr[++tlen] = ' ';
			tstr[++tlen] = '(';
			/*tstr[++tlen] = '\0';*//*(not necessary for our use)*/
		}

		buffer_copy_string_len(b, tstr, tlen);
		break;
	case ERRORLOG_SYSLOG:
		/* syslog is generating its own timestamps */
		buffer_copy_string_len(b, CONST_STR_LEN("("));
		break;
	}

	buffer_append_string(b, filename);
	buffer_append_string_len(b, CONST_STR_LEN("."));
	buffer_append_int(b, line);
	buffer_append_string_len(b, CONST_STR_LEN(") "));

	return 0;
}

static void log_write(const log_error_st *errh, buffer *b) {
	switch(errh->errorlog_mode) {
	case ERRORLOG_PIPE:
	case ERRORLOG_FILE:
	case ERRORLOG_FD:
		buffer_append_string_len(b, CONST_STR_LEN("\n"));
		write_all(errh->errorlog_fd, BUF_PTR_LEN(b));
		break;
	case ERRORLOG_SYSLOG:
		syslog(LOG_ERR, "%s", b->ptr);
		break;
	}
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
static void
log_buffer_vprintf (buffer * const b,
                    const char * const fmt, va_list ap)
{
    /* NOTE: log_buffer_prepare() ensures 0 != b->used */
    /*assert(0 != b->used);*//*(only because code calcs below assume this)*/
    /*assert(0 != b->size);*//*(errh->b should not have 0 size here)*/
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
log_error_va_list_impl (log_error_st * const errh,
                        const char * const filename,
                        const unsigned int line,
                        const char * const fmt, va_list ap,
                        const int perr)
{
    const int errnum = errno;
    buffer * const b = &errh->b;
    if (-1 == log_buffer_prepare(errh, filename, line, b)) return;
    log_buffer_vprintf(b, fmt, ap);
    if (perr)
        log_error_append_strerror(b, errnum);
    log_write(errh, b);
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
log_error_multiline_buffer (log_error_st * const restrict errh,
                            const char * const restrict filename,
                            const unsigned int line,
                            const buffer * const restrict multiline,
                            const char * const restrict fmt, ...)
{
    if (multiline->used < 2) return;

    const int errnum = errno;
    buffer * const b = &errh->b;
    if (-1 == log_buffer_prepare(errh, filename, line, b)) return;

    va_list ap;
    va_start(ap, fmt);
    log_buffer_vprintf(b, fmt, ap);
    va_end(ap);

    const size_t prefix_len = buffer_clen(b);
    const char * const end = multiline->ptr + multiline->used - 2;
    const char *pos = multiline->ptr-1, *current_line;
    do {
        pos = strchr(current_line = pos+1, '\n');
        if (!pos)
            pos = end;
        buffer_truncate(b, prefix_len);
        log_buffer_append_encoded(b, current_line, pos - current_line);
        log_write(errh, b);
    } while (pos < end);

    errno = errnum;
}


log_error_st *
log_error_st_init (void)
{
    log_error_st *errh = calloc(1, sizeof(log_error_st));
    force_assert(errh);
    errh->errorlog_fd = STDERR_FILENO;
    errh->errorlog_mode = ERRORLOG_FD;
    return errh;
}


void
log_error_st_free (log_error_st *errh)
{
    if (NULL == errh) return;
    free(errh->b.ptr);
    free(errh);
}
