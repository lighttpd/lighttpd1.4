/* _XOPEN_SOURCE >= 500 for vsnprintf() */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "first.h"

#include "log.h"

#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf() */
#include <stdlib.h>     /* malloc() free() */
#include <unistd.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifndef HAVE_CLOCK_GETTIME
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>  /* gettimeofday() */
#endif
#endif

time_t log_epoch_secs = 0;

int log_clock_gettime_realtime (struct timespec *ts) {
      #ifdef HAVE_CLOCK_GETTIME
	return clock_gettime(CLOCK_REALTIME, ts);
      #else
	/* Mac OSX does not provide clock_gettime()
	 * e.g. defined(__APPLE__) && defined(__MACH__) */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	ts->tv_sec  = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;
	return 0;
      #endif
}

/* retry write on EINTR or when not all data was written */
ssize_t write_all(int fd, const void * const buf, size_t count) {
    ssize_t written = 0;

    for (ssize_t wr; count > 0; count -= wr, written += wr) {
        wr = write(fd, (const char *)buf + written, count);
        if (wr > 0) continue;

        if (wr < 0 && errno == EINTR) { wr = 0; continue; } /* try again */
        if (0 == wr) errno = EIO; /* really shouldn't happen... */
        return -1; /* fail - repeating probably won't help */
    }

    return written;
}

static int log_buffer_prepare(const log_error_st *errh, const char *filename, unsigned int line, buffer *b) {
	static time_t tlast;
	static char tstr[20]; /* 20-chars needed for "%Y-%m-%d %H:%M:%S" */
	static size_t tlen;
	switch(errh->errorlog_mode) {
	case ERRORLOG_PIPE:
	case ERRORLOG_FILE:
	case ERRORLOG_FD:
		if (-1 == errh->errorlog_fd) return -1;
		/* cache the generated timestamp */
		if (tlast != log_epoch_secs) {
			tlast = log_epoch_secs;
			tlen = strftime(tstr, sizeof(tstr),
			                "%Y-%m-%d %H:%M:%S", localtime(&tlast));
		}

		buffer_copy_string_len(b, tstr, tlen);
		buffer_append_string_len(b, CONST_STR_LEN(": ("));
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
		write_all(errh->errorlog_fd, CONST_BUF_LEN(b));
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


static void
log_buffer_vprintf (buffer * const b,
                    const char * const fmt, va_list ap)
{
    /* NOTE: log_buffer_prepare() ensures 0 != b->used */
    /*assert(0 != b->used);*//*(only because code calcs below assume this)*/
    /*assert(0 != b->size);*//*(errh->b should not have 0 size here)*/
    size_t blen = buffer_string_length(b);
    size_t bsp  = buffer_string_space(b)+1;
    char *s = b->ptr + blen;
    size_t n;

    va_list aptry;
    va_copy(aptry, ap);
    n = (size_t)vsnprintf(s, bsp, fmt, aptry);
    va_end(aptry);

    if (n >= bsp) {
        buffer_string_prepare_append(b, n); /*(must re-read s after realloc)*/
        vsnprintf((s = b->ptr + blen), buffer_string_space(b)+1, fmt, ap);
    }

    size_t i;
    for (i = 0; i < n && ' ' <= s[i] && s[i] <= '~'; ++i) ;/*(ASCII isprint())*/
    if (i == n) {
        buffer_string_set_length(b, blen + n);
        return; /* common case; nothing to encode */
    }

    /* need to encode log line
     * copy original line fragment, append encoded line to buffer, free copy */
    char * const src = (char *)malloc(n);
    memcpy(src, s, n); /*(note: not '\0'-terminated)*/
    buffer_append_string_c_escaped(b, src, n);
    free(src);
}


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
    if (perr) {
        buffer_append_string_len(b, CONST_STR_LEN(": "));
        buffer_append_string(b, strerror(errnum));
    }
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

    const size_t prefix_len = buffer_string_length(b);
    const char * const end = multiline->ptr + multiline->used - 2;
    const char *pos = multiline->ptr-1, *current_line;
    do {
        pos = strchr(current_line = pos+1, '\n');
        if (!pos)
            pos = end;
        buffer_string_set_length(b, prefix_len); /* truncate to prefix */
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
