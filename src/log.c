#include "first.h"

#include "base.h"
#include "log.h"

#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
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
		case 's':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string_c_escaped(out, s, (NULL != s) ? strlen(s) : 0);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'b':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_c_escaped(out, CONST_BUF_LEN(b));
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'd':           /* int */
			d = va_arg(ap, int);
			buffer_append_int(out, d);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'o':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_int(out, o);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'x':           /* int (hex) */
			d = va_arg(ap, int);
			buffer_append_string_len(out, CONST_STR_LEN("0x"));
			buffer_append_uint_hex(out, d);
			buffer_append_string_len(out, CONST_STR_LEN(" "));
			break;
		case 'S':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string_c_escaped(out, s, (NULL != s) ? strlen(s) : 0);
			break;
		case 'B':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_c_escaped(out, CONST_BUF_LEN(b));
			break;
		case 'D':           /* int */
			d = va_arg(ap, int);
			buffer_append_int(out, d);
			break;
		case 'O':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_int(out, o);
			break;
		case 'X':           /* int (hex) */
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
	}
}

static int log_buffer_prepare(buffer *b, server *srv, const char *filename, unsigned int line) {
	switch(srv->errorlog_mode) {
	case ERRORLOG_PIPE:
	case ERRORLOG_FILE:
	case ERRORLOG_FD:
		if (-1 == srv->errorlog_fd) return -1;
		/* cache the generated timestamp */
		if (srv->cur_ts != srv->last_generated_debug_ts) {
			buffer_string_prepare_copy(srv->ts_debug_str, 255);
			buffer_append_strftime(srv->ts_debug_str, "%Y-%m-%d %H:%M:%S", localtime(&(srv->cur_ts)));

			srv->last_generated_debug_ts = srv->cur_ts;
		}

		buffer_copy_buffer(b, srv->ts_debug_str);
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

static void log_write(server *srv, buffer *b) {
	switch(srv->errorlog_mode) {
	case ERRORLOG_PIPE:
	case ERRORLOG_FILE:
	case ERRORLOG_FD:
		buffer_append_string_len(b, CONST_STR_LEN("\n"));
		write_all(srv->errorlog_fd, CONST_BUF_LEN(b));
		break;
	case ERRORLOG_SYSLOG:
		syslog(LOG_ERR, "%s", b->ptr);
		break;
	}
}

int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...) {
	va_list ap;

	if (-1 == log_buffer_prepare(srv->errorlog_buf, srv, filename, line)) return 0;

	va_start(ap, fmt);
	log_buffer_append_printf(srv->errorlog_buf, fmt, ap);
	va_end(ap);

	log_write(srv, srv->errorlog_buf);

	return 0;
}

int log_error_write_multiline_buffer(server *srv, const char *filename, unsigned int line, buffer *multiline, const char *fmt, ...) {
	va_list ap;
	size_t prefix_len;
	buffer *b = srv->errorlog_buf;
	char *pos, *end, *current_line;

	if (buffer_string_is_empty(multiline)) return 0;

	if (-1 == log_buffer_prepare(b, srv, filename, line)) return 0;

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
				log_write(srv, b);
			}
			current_line = pos + 1;
			break;
		default:
			break;
		}
	}

	return 0;
}
