#include "first.h"

#include <stdlib.h>

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"

#ifdef FDEVENT_USE_LIBEV

# include <ev.h>

static void io_watcher_cb(struct ev_loop *loop, ev_io *w, int revents) {
	fdevents *ev = w->data;
	fdnode *fdn = ev->fdarray[w->fd];
	int r = 0;
	UNUSED(loop);

	if (revents & EV_READ) r |= FDEVENT_IN;
	if (revents & EV_WRITE) r |= FDEVENT_OUT;
	if (revents & EV_ERROR) r |= FDEVENT_ERR;

	if (0 == ((uintptr_t)fdn & 0x3)) {
		(*fdn->handler)(ev->srv, fdn->ctx, r);
	}
}

__attribute_cold__
static void fdevent_libev_free(fdevents *ev) {
	UNUSED(ev);
}

static int fdevent_libev_event_del(fdevents *ev, fdnode *fdn) {
	ev_io *watcher = fdn->handler_ctx;
	if (!watcher) return 0;
	fdn->handler_ctx = NULL;

	ev_io_stop(ev->libev_loop, watcher);
	free(watcher);

	return 0;
}

static int fdevent_libev_event_set(fdevents *ev, fdnode *fdn, int events) {
	ev_io *watcher = fdn->handler_ctx;
	int ev_events = 0;

	if (events & FDEVENT_IN)  ev_events |= EV_READ;
	if (events & FDEVENT_OUT) ev_events |= EV_WRITE;

	if (!watcher) {
		fdn->handler_ctx = watcher = calloc(1, sizeof(ev_io));
		force_assert(watcher);
		fdn->fde_ndx = fdn->fd;

		ev_io_init(watcher, io_watcher_cb, fdn->fd, ev_events);
		watcher->data = ev;
		ev_io_start(ev->libev_loop, watcher);
	} else {
		if ((watcher->events & (EV_READ | EV_WRITE)) != ev_events) {
			ev_io_stop(ev->libev_loop, watcher);
			ev_io_set(watcher, watcher->fd, ev_events);
			ev_io_start(ev->libev_loop, watcher);
		}
	}

	return 0;
}

static void timeout_watcher_cb(struct ev_loop *loop, ev_timer *w, int revents) {
	UNUSED(loop);
	UNUSED(w);
	UNUSED(revents);
}

static ev_timer timeout_watcher;

static int fdevent_libev_poll(fdevents *ev, int timeout_ms) {
	timeout_watcher.repeat = (timeout_ms > 0) ? timeout_ms/1000.0 : 0.001;

	ev_timer_again(ev->libev_loop, &timeout_watcher);
	ev_run(ev->libev_loop, EVRUN_ONCE);

	return 0;
}

__attribute_cold__
static int fdevent_libev_reset(fdevents *ev) {
	UNUSED(ev);
	ev_default_fork();
	return 0;
}

__attribute_cold__
int fdevent_libev_init(fdevents *ev) {
	struct ev_timer * const timer = &timeout_watcher;
	memset(timer, 0, sizeof(*timer));

	ev->type      = FDEVENT_HANDLER_LIBEV;
	ev->event_set = fdevent_libev_event_set;
	ev->event_del = fdevent_libev_event_del;
	ev->poll      = fdevent_libev_poll;
	ev->reset     = fdevent_libev_reset;
	ev->free      = fdevent_libev_free;

	if (NULL == (ev->libev_loop = ev_default_loop(0))) return -1;

	ev_timer_init(timer, timeout_watcher_cb, 0.0, 1.0);

	return 0;
}

#endif
