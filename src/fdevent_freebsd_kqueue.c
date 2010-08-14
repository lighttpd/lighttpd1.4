#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <sys/types.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#ifdef USE_FREEBSD_KQUEUE
#include <sys/event.h>
#include <sys/time.h>

static void fdevent_freebsd_kqueue_free(fdevents *ev) {
	close(ev->kq_fd);
	free(ev->kq_results);
}

static int fdevent_freebsd_kqueue_event_del(fdevents *ev, int fde_ndx, int fd) {
	int ret;
	struct kevent kev[2];
	struct timespec ts;

	if (fde_ndx < 0) return -1;

	EV_SET(&kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

	ts.tv_sec  = 0;
	ts.tv_nsec = 0;

	ret = kevent(ev->kq_fd,
		&kev, 2,
		NULL, 0,
		&ts);

	/* Ignore errors for now, as we remove for READ and WRITE without knowing what was registered */
#if 0
	if (ret == -1) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SS",
			"kqueue event delete failed: ", strerror(errno));

		return -1;
	}
#endif

	return -1;
}

static int fdevent_freebsd_kqueue_event_add(fdevents *ev, int fde_ndx, int fd, int events) {
	int filter, ret;
	struct kevent kev;
	struct timespec ts;

	UNUSED(fde_ndx);

	filter = (events & FDEVENT_IN) ? EVFILT_READ : EVFILT_WRITE;

	EV_SET(&kev, fd, filter, EV_ADD|EV_CLEAR, 0, 0, NULL);

	ts.tv_sec  = 0;
	ts.tv_nsec = 0;

	ret = kevent(ev->kq_fd,
		&kev, 1,
		NULL, 0,
		&ts);

	if (ret == -1) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SS",
			"kqueue event add failed: ", strerror(errno));

		return -1;
	}

	return fd;
}

static int fdevent_freebsd_kqueue_poll(fdevents *ev, int timeout_ms) {
	int ret;
	struct timespec ts;

	ts.tv_sec  = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000;

	ret = kevent(ev->kq_fd,
		NULL, 0,
		ev->kq_results, ev->maxfds,
		&ts);

	if (ret == -1) {
		switch(errno) {
		case EINTR:
			/* we got interrupted, perhaps just a SIGCHLD of a CGI script */
			return 0;
		default:
			log_error_write(ev->srv, __FILE__, __LINE__, "SS",
				"kqueue failed polling: ", strerror(errno));
			break;
		}
	}

	return ret;
}

static int fdevent_freebsd_kqueue_event_get_revent(fdevents *ev, size_t ndx) {
	int events = 0, e;

	e = ev->kq_results[ndx].filter;

	if (e == EVFILT_READ) {
		events |= FDEVENT_IN;
	} else if (e == EVFILT_WRITE) {
		events |= FDEVENT_OUT;
	}

	e = ev->kq_results[ndx].flags;

	if (e & EV_EOF) {
		events |= FDEVENT_HUP;
	}

	if (e & EV_ERROR) {
		events |= FDEVENT_ERR;
	}

	return events;
}

static int fdevent_freebsd_kqueue_event_get_fd(fdevents *ev, size_t ndx) {
	return ev->kq_results[ndx].ident;
}

static int fdevent_freebsd_kqueue_event_next_fdndx(fdevents *ev, int ndx) {
	UNUSED(ev);

	return (ndx < 0) ? 0 : ndx + 1;
}

static int fdevent_freebsd_kqueue_reset(fdevents *ev) {
	if (-1 == (ev->kq_fd = kqueue())) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"kqueue failed (", strerror(errno), "), try to set server.event-handler = \"poll\" or \"select\"");

		return -1;
	}

	return 0;
}


int fdevent_freebsd_kqueue_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_FREEBSD_KQUEUE;
#define SET(x) \
	ev->x = fdevent_freebsd_kqueue_##x;

	SET(free);
	SET(poll);
	SET(reset);

	SET(event_del);
	SET(event_add);

	SET(event_next_fdndx);
	SET(event_get_fd);
	SET(event_get_revent);

	ev->kq_fd = -1;

	ev->kq_results = calloc(ev->maxfds, sizeof(*ev->kq_results));

	/* check that kqueue works */

	if (-1 == (ev->kq_fd = kqueue())) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"kqueue failed (", strerror(errno), "), try to set server.event-handler = \"poll\" or \"select\"");

		return -1;
	}

	close(ev->kq_fd);
	ev->kq_fd = -1;

	return 0;
}
#else
int fdevent_freebsd_kqueue_init(fdevents *ev) {
	UNUSED(ev);

	log_error_write(ev->srv, __FILE__, __LINE__, "S",
		"kqueue not available, try to set server.event-handler = \"poll\" or \"select\"");

	return -1;
}
#endif
