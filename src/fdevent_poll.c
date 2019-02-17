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

static int fdevent_poll_event_set(fdevents *ev, int fde_ndx, int fd, int events) {
	int k;

	if (fde_ndx != -1) {
		if (ev->pollfds[fde_ndx].fd == fd) {
			ev->pollfds[fde_ndx].events = events;

			return fde_ndx;
		}
		log_error_write(ev->srv, __FILE__, __LINE__, "SdD",
			"set: ", fde_ndx, ev->pollfds[fde_ndx].fd);
		SEGFAULT();
	}

	if (ev->unused.used > 0) {
		k = ev->unused.ptr[--ev->unused.used];

	} else {
		if (ev->size == ev->used) {
			ev->size += 16;
			ev->pollfds = realloc(ev->pollfds, sizeof(*ev->pollfds) * ev->size);
			force_assert(NULL != ev->pollfds);
		}

		k = ev->used++;
	}

	ev->pollfds[k].fd = fd;
	ev->pollfds[k].events = events;

	return k;
}

static int fdevent_poll_next_ndx(const fdevents *ev, int ndx) {
	for (size_t i = (size_t)(ndx+1); i < ev->used; ++i) {
		if (ev->pollfds[i].revents) return i;
	}
	return -1;
}

static int fdevent_poll_poll(fdevents *ev, int timeout_ms) {
    const int n = poll(ev->pollfds, ev->used, timeout_ms);
    server * const srv = ev->srv;
    for (int ndx=-1,i=0; i<n && -1!=(ndx=fdevent_poll_next_ndx(ev,ndx)); ++i){
        int revents = ev->pollfds[ndx].revents;
        fdnode *fdn = ev->fdarray[ev->pollfds[ndx].fd];
        if (0 == ((uintptr_t)fdn & 0x3)) {
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

int fdevent_poll_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_POLL;
	force_assert(POLLIN    == FDEVENT_IN);
	force_assert(POLLPRI   == FDEVENT_PRI);
	force_assert(POLLOUT   == FDEVENT_OUT);
	force_assert(POLLERR   == FDEVENT_ERR);
	force_assert(POLLHUP   == FDEVENT_HUP);
	force_assert(POLLNVAL  == FDEVENT_NVAL);
      #if 0 != POLLRDHUP
	force_assert(POLLRDHUP == FDEVENT_RDHUP);
      #endif
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
