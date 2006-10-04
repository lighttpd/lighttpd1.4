#define _GNU_SOURCE

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include "log.h"
#include "array.h"

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

/**
 * open the errorlog
 *
 * we have 3 possibilities:
 * - stderr (default)
 * - syslog
 * - logfile
 *
 * if the open failed, report to the user and die
 *
 */

int log_error_open(server *srv) {
	int fd;
	int close_stderr = 1;

#ifdef HAVE_SYSLOG_H
	/* perhaps someone wants to use syslog() */
	openlog("lighttpd", LOG_CONS | LOG_PID, LOG_DAEMON);
#endif
	srv->errorlog_mode = ERRORLOG_STDERR;

	if (srv->srvconf.errorlog_use_syslog) {
		srv->errorlog_mode = ERRORLOG_SYSLOG;
	} else if (!buffer_is_empty(srv->srvconf.errorlog_file)) {
		const char *logfile = srv->srvconf.errorlog_file->ptr;

		if (-1 == (srv->errorlog_fd = open(logfile, O_APPEND | O_WRONLY | O_CREAT | O_LARGEFILE, 0644))) {
			log_error_write(srv, __FILE__, __LINE__, "SSSS",
					"opening errorlog '", logfile,
					"' failed: ", strerror(errno));

			return -1;
		}
#ifdef FD_CLOEXEC
		/* close fd on exec (cgi) */
		fcntl(srv->errorlog_fd, F_SETFD, FD_CLOEXEC);
#endif
		srv->errorlog_mode = ERRORLOG_FILE;
	}

	log_error_write(srv, __FILE__, __LINE__, "s", "server started");

#ifdef HAVE_VALGRIND_VALGRIND_H
	/* don't close stderr for debugging purposes if run in valgrind */
	if (RUNNING_ON_VALGRIND) close_stderr = 0;
#endif
	if (srv->errorlog_mode == ERRORLOG_STDERR) close_stderr = 0;

	/* move stderr to /dev/null */
	if (close_stderr &&
	    -1 != (fd = open("/dev/null", O_WRONLY))) {
		close(STDERR_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}
	return 0;
}

/**
 * open the errorlog
 *
 * if the open failed, report to the user and die
 * if no filename is given, use syslog instead
 *
 */

int log_error_cycle(server *srv) {
	/* only cycle if we are not in syslog-mode */

	if (srv->errorlog_mode == ERRORLOG_FILE) {
		const char *logfile = srv->srvconf.errorlog_file->ptr;
		/* already check of opening time */

		int new_fd;

		if (-1 == (new_fd = open(logfile, O_APPEND | O_WRONLY | O_CREAT | O_LARGEFILE, 0644))) {
			/* write to old log */
			log_error_write(srv, __FILE__, __LINE__, "SSSSS",
					"cycling errorlog '", logfile,
					"' failed: ", strerror(errno),
					", falling back to syslog()");

			close(srv->errorlog_fd);
			srv->errorlog_fd = -1;
#ifdef HAVE_SYSLOG_H
			srv->errorlog_mode = ERRORLOG_SYSLOG;
#endif
		} else {
			/* ok, new log is open, close the old one */
			close(srv->errorlog_fd);
			srv->errorlog_fd = new_fd;
		}
	}

	log_error_write(srv, __FILE__, __LINE__, "s", "logfiles cycled");

	return 0;
}

int log_error_close(server *srv) {
	log_error_write(srv, __FILE__, __LINE__, "s", "server stopped");

	switch(srv->errorlog_mode) {
	case ERRORLOG_FILE:
		close(srv->errorlog_fd);
		break;
	case ERRORLOG_SYSLOG:
#ifdef HAVE_SYSLOG_H
		closelog();
#endif
		break;
	case ERRORLOG_STDERR:
		break;
	}

	return 0;
}

int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...) {
	va_list ap;

	switch(srv->errorlog_mode) {
	case ERRORLOG_FILE:
	case ERRORLOG_STDERR:
		/* cache the generated timestamp */
		if (srv->cur_ts != srv->last_generated_debug_ts) {
			buffer_prepare_copy(srv->ts_debug_str, 255);
			strftime(srv->ts_debug_str->ptr, srv->ts_debug_str->size - 1, "%Y-%m-%d %H:%M:%S", localtime(&(srv->cur_ts)));
			srv->ts_debug_str->used = strlen(srv->ts_debug_str->ptr) + 1;

			srv->last_generated_debug_ts = srv->cur_ts;
		}

		buffer_copy_string_buffer(srv->errorlog_buf, srv->ts_debug_str);
		BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, ": (");
		break;
	case ERRORLOG_SYSLOG:
		/* syslog is generating its own timestamps */
		BUFFER_COPY_STRING_CONST(srv->errorlog_buf, "(");
		break;
	}

	buffer_append_string(srv->errorlog_buf, filename);
	BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, ".");
	buffer_append_long(srv->errorlog_buf, line);
	BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, ") ");


	for(va_start(ap, fmt); *fmt; fmt++) {
		int d;
		char *s;
		buffer *b;
		off_t o;

		switch(*fmt) {
		case 's':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string(srv->errorlog_buf, s);
			BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, " ");
			break;
		case 'b':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_buffer(srv->errorlog_buf, b);
			BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, " ");
			break;
		case 'd':           /* int */
			d = va_arg(ap, int);
			buffer_append_long(srv->errorlog_buf, d);
			BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, " ");
			break;
		case 'o':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_off_t(srv->errorlog_buf, o);
			BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, " ");
			break;
		case 'x':           /* int (hex) */
			d = va_arg(ap, int);
			BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, "0x");
			buffer_append_long_hex(srv->errorlog_buf, d);
			BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, " ");
			break;
		case 'S':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string(srv->errorlog_buf, s);
			break;
		case 'B':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_buffer(srv->errorlog_buf, b);
			break;
		case 'D':           /* int */
			d = va_arg(ap, int);
			buffer_append_long(srv->errorlog_buf, d);
			break;
		case '(':
		case ')':
		case '<':
		case '>':
		case ',':
		case ' ':
			buffer_append_string_len(srv->errorlog_buf, fmt, 1);
			break;
		}
	}
	va_end(ap);

	switch(srv->errorlog_mode) {
	case ERRORLOG_FILE:
		BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, "\n");
		write(srv->errorlog_fd, srv->errorlog_buf->ptr, srv->errorlog_buf->used - 1);
		break;
	case ERRORLOG_STDERR:
		BUFFER_APPEND_STRING_CONST(srv->errorlog_buf, "\n");
		write(STDERR_FILENO, srv->errorlog_buf->ptr, srv->errorlog_buf->used - 1);
		break;
	case ERRORLOG_SYSLOG:
		syslog(LOG_ERR, "%s", srv->errorlog_buf->ptr);
		break;
	}

	return 0;
}

