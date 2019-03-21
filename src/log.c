/* _XOPEN_SOURCE >= 500 for vsnprintf() */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "first.h"

#include "base.h"
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
ssize_t write_all(int fd, const void* buf, size_t count) {
	ssize_t written = 0;

	while (count > 0) {
		ssize_t r = write(fd, buf, count);
		if (r < 0) {
			switch (errno) {
			case EINTR:
				/* try again */
				break;
			default:
				/* fail - repeating probably won't help */
				return -1;
			}
		} else if (0 == r) {
			/* really shouldn't happen... */
			errno = EIO;
			return -1;
		} else {
			force_assert(r <= (ssize_t) count);
			written += r;
			buf = r + (char const*) buf;
			count -= r;
		}
	}

	return written;
}

/* lowercase: append space, uppercase: don't */
static void log_buffer_append_printf(buffer *out, const char *fmt, va_list ap) {
	for(; *fmt; fmt++) {
		int d;
		char *s;
		buffer *b;
		off_t o;

		switch(*fmt) {
		case 'S':           /* string */
		case 's':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string_c_escaped(out, s, (NULL != s) ? strlen(s) : 0);
			break;
		case 'B':           /* buffer */
		case 'b':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_c_escaped(out, CONST_BUF_LEN(b));
			break;
		case 'D':           /* int */
		case 'd':           /* int */
			d = va_arg(ap, int);
			buffer_append_int(out, d);
			break;
		case 'O':           /* off_t */
		case 'o':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_int(out, o);
			break;
		case 'X':           /* int (hex) */
		case 'x':           /* int (hex) */
			d = va_arg(ap, int);
			buffer_append_string_len(out, CONST_STR_LEN("0x"));
			buffer_append_uint_hex(out, d);
			break;
		case '(':
		case ')':
		case '<':
		case '>':
		case ',':
		case ' ':
			buffer_append_string_len(out, fmt, 1);
			break;
		}

		if (*fmt >= 'a') { /* 's' 'b' 'd' 'o' 'x' */
			buffer_append_string_len(out, CONST_STR_LEN(" "));
		}
	}
}

static int log_buffer_prepare(const log_error_st *errh, const char *filename, unsigned int line, buffer *b) {
	switch(errh->errorlog_mode) {
	case ERRORLOG_PIPE:
	case ERRORLOG_FILE:
	case ERRORLOG_FD:
		if (-1 == errh->errorlog_fd) return -1;
		/* cache the generated timestamp */
		if (*errh->last_ts != *errh->cur_ts) {
			*errh->last_ts = *errh->cur_ts;
			buffer_clear(errh->tb);
			buffer_append_strftime(errh->tb, "%Y-%m-%d %H:%M:%S", localtime(errh->cur_ts));
		}

		buffer_copy_buffer(b, errh->tb);
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

int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...) {
	const log_error_st *errh = srv->errh;
	buffer *b = errh->b;
	if (-1 == log_buffer_prepare(errh, filename, line, b)) return 0;

	va_list ap;
	va_start(ap, fmt);
	log_buffer_append_printf(b, fmt, ap);
	va_end(ap);

	log_write(errh, b);

	return 0;
}

int log_error_write_multiline_buffer(server *srv, const char *filename, unsigned int line, buffer *multiline, const char *fmt, ...) {
	const log_error_st *errh = srv->errh;
	buffer *b = errh->b;
	va_list ap;
	size_t prefix_len;
	char *pos, *end, *current_line;

	if (buffer_string_is_empty(multiline)) return 0;

	if (-1 == log_buffer_prepare(errh, filename, line, b)) return 0;

	va_start(ap, fmt);
	log_buffer_append_printf(b, fmt, ap);
	va_end(ap);

	prefix_len = buffer_string_length(b);

	current_line = pos = multiline->ptr;
	end = multiline->ptr + buffer_string_length(multiline);

	for ( ; pos <= end ; ++pos) {
		switch (*pos) {
		case '\n':
		case '\r':
		case '\0': /* handles end of string */
			if (current_line < pos) {
				/* truncate to prefix */
				buffer_string_set_length(b, prefix_len);

				buffer_append_string_len(b, current_line, pos - current_line);
				log_write(errh, b);
			}
			current_line = pos + 1;
			break;
		default:
			break;
		}
	}

	return 0;
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
log_error_va_list_impl (const log_error_st * const errh,
                        const char * const filename,
                        const unsigned int line,
                        const char * const fmt, va_list ap,
                        const int perr)
{
    const int errnum = errno;
    buffer * const b = errh->b;
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
log_error(const log_error_st * const errh,
          const char * const filename, const unsigned int line,
          const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_error_va_list_impl(errh, filename, line, fmt, ap, 0);
    va_end(ap);
}


void
log_perror (const log_error_st * const errh,
            const char * const filename, const unsigned int line,
            const char * const fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_error_va_list_impl(errh, filename, line, fmt, ap, 1);
    va_end(ap);
}


log_error_st *
log_error_st_init (time_t *cur_ts_ptr, time_t *last_ts_ptr)
{
    log_error_st *errh = calloc(1, sizeof(log_error_st));
    force_assert(errh);
    errh->errorlog_fd = STDERR_FILENO;
    errh->errorlog_mode = ERRORLOG_FD;
    errh->b = buffer_init();
    errh->tb = buffer_init();
    errh->cur_ts = cur_ts_ptr;
    errh->last_ts = last_ts_ptr;
    return errh;
}


void
log_error_st_free (log_error_st *errh)
{
    if (NULL == errh) return;
    buffer_free(errh->tb);
    buffer_free(errh->b);
    free(errh);
}
