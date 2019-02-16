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

#ifdef FDEVENT_USE_POLL

# ifdef HAVE_POLL_H
#  include <poll.h>
# else
#  include <sys/poll.h>
# endif

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

static void fdevent_poll_free(fdevents *ev) {
	free(ev->pollfds);
	if (ev->unused.ptr) free(ev->unused.ptr);
}

static int fdevent_poll_event_del(fdevents *ev, int fde_ndx, int fd) {
	if (fde_ndx < 0) return -1;

	if ((size_t)fde_ndx >= ev->used) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SdD",
			"del! out of range ", fde_ndx, (int) ev->used);
		SEGFAULT();
	}

	if (ev->pollfds[fde_ndx].fd == fd) {
		size_t k = fde_ndx;

		ev->pollfds[k].fd = -1;
		/* ev->pollfds[k].events = 0; */
		/* ev->pollfds[k].revents = 0; */

		if (ev->unused.size == ev->unused.used) {
			ev->unused.size += 16;
			ev->unused.ptr = realloc(ev->unused.ptr, sizeof(*(ev->unused.ptr)) * ev->unused.size);
			force_assert(NULL != ev->unused.ptr);
		}

		ev->unused.ptr[ev->unused.used++] = k;
	} else {
		log_error_write(ev->srv, __FILE__, __LINE__, "SdD",
			"del! ", ev->pollfds[fde_ndx].fd, fd);

		SEGFAULT();
	}

	return -1;
}

#if 0
static int fdevent_poll_event_compress(fdevents *ev) {
	size_t j;

	if (ev->used == 0) return 0;
	if (ev->unused.used != 0) return 0;

	for (j = ev->used - 1; j + 1 > 0 && ev->pollfds[j].fd == -1; j--) ev->used--;

	return 0;
}
#endif

static int fdevent_poll_event_set(fdevents *ev, int fde_ndx, int fd, int events) {
	int pevents = 0;
	if (events & FDEVENT_IN)  pevents |= POLLIN;
	if (events & FDEVENT_OUT) pevents |= POLLOUT;
	if (events & FDEVENT_RDHUP) pevents |= POLLRDHUP;

	/* known index */

	if (fde_ndx != -1) {
		if (ev->pollfds[fde_ndx].fd == fd) {
			ev->pollfds[fde_ndx].events = pevents;

			return fde_ndx;
		}
		log_error_write(ev->srv, __FILE__, __LINE__, "SdD",
			"set: ", fde_ndx, ev->pollfds[fde_ndx].fd);
		SEGFAULT();
	}

	if (ev->unused.used > 0) {
		int k = ev->unused.ptr[--ev->unused.used];

		ev->pollfds[k].fd = fd;
		ev->pollfds[k].events = pevents;

		return k;
	} else {
		if (ev->size == ev->used) {
			ev->size += 16;
			ev->pollfds = realloc(ev->pollfds, sizeof(*ev->pollfds) * ev->size);
			force_assert(NULL != ev->pollfds);
		}

		ev->pollfds[ev->used].fd = fd;
		ev->pollfds[ev->used].events = pevents;

		return ev->used++;
	}
}

static int fdevent_poll_event_get_revent(const fdevents *ev, size_t ndx) {
	int r, poll_r;

	if (ndx >= ev->used) {
		log_error_write(ev->srv, __FILE__, __LINE__, "sii",
			"dying because: event: ", (int) ndx, (int) ev->used);

		SEGFAULT();

		return 0;
	}

	if (ev->pollfds[ndx].revents & POLLNVAL) {
		/* should never happen */
		SEGFAULT();
	}

	r = 0;
	poll_r = ev->pollfds[ndx].revents;

	/* map POLL* to FDEVEN_*; they are probably the same, but still. */

	if (poll_r & POLLIN) r |= FDEVENT_IN;
	if (poll_r & POLLOUT) r |= FDEVENT_OUT;
	if (poll_r & POLLERR) r |= FDEVENT_ERR;
	if (poll_r & POLLHUP) r |= FDEVENT_HUP;
	if (poll_r & POLLNVAL) r |= FDEVENT_NVAL;
	if (poll_r & POLLPRI) r |= FDEVENT_PRI;
	if (poll_r & POLLRDHUP) r |= FDEVENT_RDHUP;

	return r;
}

static int fdevent_poll_event_next_fdndx(const fdevents *ev, int ndx) {
	for (size_t i = (size_t)(ndx+1); i < ev->used; ++i) {
		if (ev->pollfds[i].revents) return i;
	}
	return -1;
}

static int fdevent_poll_poll(fdevents *ev, int timeout_ms) {
  #if 0
    fdevent_poll_event_compress(ev);
  #endif
    int n = poll(ev->pollfds, ev->used, timeout_ms);
    server * const srv = ev->srv;
    for (int ndx = -1, i = 0; i < n; ++i) {
        fdnode *fdn;
        ndx = fdevent_poll_event_next_fdndx(ev, ndx);
        if (-1 == ndx) break;
        fdn = ev->fdarray[ndx];
        if (0 == ((uintptr_t)fdn & 0x3)) {
            int revents = fdevent_poll_event_get_revent(ev, i);
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

int fdevent_poll_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_POLL;
#define SET(x) \
	ev->x = fdevent_poll_##x;

	SET(free);
	SET(poll);

	SET(event_del);
	SET(event_set);

	return 0;
}




#else
int fdevent_poll_init(fdevents *ev) {
	UNUSED(ev);

	log_error_write(ev->srv, __FILE__, __LINE__,
		"s", "poll is not supported, try to set server.event-handler = \"select\"");

	return -1;
}
#endif
