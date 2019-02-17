#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <sys/types.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef FDEVENT_USE_LINUX_EPOLL

# include <sys/epoll.h>

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0
#endif

static void fdevent_linux_sysepoll_free(fdevents *ev) {
	close(ev->epoll_fd);
	free(ev->epoll_events);
}

static int fdevent_linux_sysepoll_event_del(fdevents *ev, int fde_ndx, int fd) {
	if (fde_ndx < 0) return -1;

	if (0 != epoll_ctl(ev->epoll_fd, EPOLL_CTL_DEL, fd, NULL)) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"epoll_ctl failed: ", strerror(errno), ", dying");

		SEGFAULT();

		return 0;
	}

	return -1;
}

static int fdevent_linux_sysepoll_event_set(fdevents *ev, int fde_ndx, int fd, int events) {
	struct epoll_event ep;
	int add = (-1 == fde_ndx);

	/**
	 *
	 * with EPOLLET we don't get a FDEVENT_HUP
	 * if the close is delay after everything has
	 * sent.
	 *
	 */

	ep.events = events | EPOLLERR | EPOLLHUP /* | EPOLLET */;
	ep.data.fd = fd;

	if (0 != epoll_ctl(ev->epoll_fd, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &ep)) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"epoll_ctl failed: ", strerror(errno), ", dying");

		SEGFAULT();

		return 0;
	}

	return fd;
}

static int fdevent_linux_sysepoll_poll(fdevents * const ev, int timeout_ms) {
    int n = epoll_wait(ev->epoll_fd, ev->epoll_events, ev->maxfds, timeout_ms);
    server * const srv = ev->srv;
    for (int i = 0; i < n; ++i) {
        int revents = ev->epoll_events[i].events;
        fdnode * const fdn = ev->fdarray[ev->epoll_events[i].data.fd];
        if (0 == ((uintptr_t)fdn & 0x3)) {
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

int fdevent_linux_sysepoll_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_LINUX_SYSEPOLL;
	force_assert(EPOLLIN    == FDEVENT_IN);
	force_assert(EPOLLPRI   == FDEVENT_PRI);
	force_assert(EPOLLOUT   == FDEVENT_OUT);
	force_assert(EPOLLERR   == FDEVENT_ERR);
	force_assert(EPOLLHUP   == FDEVENT_HUP);
      #if 0 != EPOLLRDHUP
	force_assert(EPOLLRDHUP == FDEVENT_RDHUP);
      #endif
#define SET(x) \
	ev->x = fdevent_linux_sysepoll_##x;

	SET(free);
	SET(poll);

	SET(event_del);
	SET(event_set);

	if (-1 == (ev->epoll_fd = epoll_create(ev->maxfds))) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"epoll_create failed (", strerror(errno), "), try to set server.event-handler = \"poll\" or \"select\"");

		return -1;
	}

	fdevent_setfd_cloexec(ev->epoll_fd);

	ev->epoll_events = malloc(ev->maxfds * sizeof(*ev->epoll_events));
	force_assert(NULL != ev->epoll_events);

	return 0;
}

#else
int fdevent_linux_sysepoll_init(fdevents *ev) {
	UNUSED(ev);

	log_error_write(ev->srv, __FILE__, __LINE__, "S",
		"linux-sysepoll not supported, try to set server.event-handler = \"poll\" or \"select\"");

	return -1;
}
#endif
