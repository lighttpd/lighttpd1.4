#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef FDEVENT_USE_FREEBSD_KQUEUE

# include <sys/event.h>
# include <sys/time.h>

__attribute_cold__
static void fdevent_freebsd_kqueue_free(fdevents *ev) {
	close(ev->kq_fd);
	free(ev->kq_results);
}

static int fdevent_freebsd_kqueue_event_del(fdevents *ev, fdnode *fdn) {
	struct kevent kev[2];
	struct timespec ts = {0, 0};
	int fd = fdn->fd;
	int n = 0;
	int oevents = fdn->events;

	if (oevents & FDEVENT_IN)  {
		EV_SET(&kev[n], fd, EVFILT_READ, EV_DELETE, 0, 0, fdn);
		n++;
	}
	if (oevents & FDEVENT_OUT)  {
		EV_SET(&kev[n], fd, EVFILT_WRITE, EV_DELETE, 0, 0, fdn);
		n++;
	}

	return (0 != n) ? kevent(ev->kq_fd, kev, n, NULL, 0, &ts) : 0;
}

static int fdevent_freebsd_kqueue_event_set(fdevents *ev, fdnode *fdn, int events) {
	struct kevent kev[2];
	struct timespec ts = {0, 0};
	int fd = fdn->fde_ndx = fdn->fd;
	int n = 0;
	int oevents = fdn->events;
	int addevents = events & ~oevents;
	int delevents = ~events & oevents;

	if (addevents & FDEVENT_IN)  {
		EV_SET(&kev[n], fd, EVFILT_READ, EV_ADD, 0, 0, fdn);
		n++;
	} else if (delevents & FDEVENT_IN) {
		EV_SET(&kev[n], fd, EVFILT_READ, EV_DELETE, 0, 0, fdn);
		n++;
	}
	if (addevents & FDEVENT_OUT)  {
		EV_SET(&kev[n], fd, EVFILT_WRITE, EV_ADD, 0, 0, fdn);
		n++;
	} else if (delevents & FDEVENT_OUT) {
		EV_SET(&kev[n], fd, EVFILT_WRITE, EV_DELETE, 0, 0, fdn);
		n++;
	}

	return (0 != n) ? kevent(ev->kq_fd, kev, n, NULL, 0, &ts) : 0;
}

static int fdevent_freebsd_kqueue_poll(fdevents * const ev, int timeout_ms) {
    server * const srv = ev->srv;
    struct timespec ts;
    int n;

    ts.tv_sec  = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;

    n = kevent(ev->kq_fd, NULL, 0, ev->kq_results, ev->maxfds, &ts);

    for (int i = 0; i < n; ++i) {
        fdnode * const fdn = (fdnode *)ev->kq_results[i].udata;
        int filt = ev->kq_results[i].filter;
        int e = ev->kq_results[i].flags;
        if ((fdevent_handler)NULL != fdn->handler) {
            int revents = (filt == EVFILT_READ) ? FDEVENT_IN : FDEVENT_OUT;
            if (e & EV_EOF)
                revents |= (filt == EVFILT_READ ? FDEVENT_RDHUP : FDEVENT_HUP);
            if (e & EV_ERROR)
                revents |= FDEVENT_ERR;
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

__attribute_cold__
static int fdevent_freebsd_kqueue_reset(fdevents *ev) {
	return (-1 != (ev->kq_fd = kqueue())) ? 0 : -1;
}

__attribute_cold__
int fdevent_freebsd_kqueue_init(fdevents *ev) {
	ev->type       = FDEVENT_HANDLER_FREEBSD_KQUEUE;
	ev->event_set  = fdevent_freebsd_kqueue_event_set;
	ev->event_del  = fdevent_freebsd_kqueue_event_del;
	ev->poll       = fdevent_freebsd_kqueue_poll;
	ev->reset      = fdevent_freebsd_kqueue_reset;
	ev->free       = fdevent_freebsd_kqueue_free;
	ev->kq_fd      = -1;
	ev->kq_results = calloc(ev->maxfds, sizeof(*ev->kq_results));
	force_assert(NULL != ev->kq_results);
	return 0;
}

#endif
