#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef FDEVENT_USE_LINUX_EPOLL

# include <sys/epoll.h>

__attribute_cold__
static void fdevent_linux_sysepoll_free(fdevents *ev) {
	close(ev->epoll_fd);
	free(ev->epoll_events);
}

static int fdevent_linux_sysepoll_event_del(fdevents *ev, fdnode *fdn) {
    return epoll_ctl(ev->epoll_fd, EPOLL_CTL_DEL, fdn->fd, NULL);
}

static int fdevent_linux_sysepoll_event_set(fdevents *ev, fdnode *fdn, int events) {
    int op = (-1 == fdn->fde_ndx) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    int fd = fdn->fde_ndx = fdn->fd;
    struct epoll_event ep;
  #ifndef EPOLLRDHUP
    events &= ~FDEVENT_RDHUP;
  #endif
    ep.events = events | EPOLLERR | EPOLLHUP;
    ep.data.ptr = fdn;
    return epoll_ctl(ev->epoll_fd, op, fd, &ep);
}

static int fdevent_linux_sysepoll_poll(fdevents * const ev, int timeout_ms) {
    int n = epoll_wait(ev->epoll_fd, ev->epoll_events, ev->maxfds, timeout_ms);
    server * const srv = ev->srv;
    for (int i = 0; i < n; ++i) {
        fdnode * const fdn = (fdnode *)ev->epoll_events[i].data.ptr;
        int revents = ev->epoll_events[i].events;
        if ((fdevent_handler)NULL != fdn->handler) {
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

__attribute_cold__
int fdevent_linux_sysepoll_init(fdevents *ev) {
	force_assert(EPOLLIN    == FDEVENT_IN);
	force_assert(EPOLLPRI   == FDEVENT_PRI);
	force_assert(EPOLLOUT   == FDEVENT_OUT);
	force_assert(EPOLLERR   == FDEVENT_ERR);
	force_assert(EPOLLHUP   == FDEVENT_HUP);
      #ifdef EPOLLRDHUP
	force_assert(EPOLLRDHUP == FDEVENT_RDHUP);
      #endif

	ev->type      = FDEVENT_HANDLER_LINUX_SYSEPOLL;
	ev->event_set = fdevent_linux_sysepoll_event_set;
	ev->event_del = fdevent_linux_sysepoll_event_del;
	ev->poll      = fdevent_linux_sysepoll_poll;
	ev->free      = fdevent_linux_sysepoll_free;

	if (-1 == (ev->epoll_fd = epoll_create(ev->maxfds))) return -1;

	fdevent_setfd_cloexec(ev->epoll_fd);

	ev->epoll_events = malloc(ev->maxfds * sizeof(*ev->epoll_events));
	force_assert(NULL != ev->epoll_events);

	return 0;
}

#endif
