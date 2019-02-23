#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef FDEVENT_USE_SOLARIS_PORT

#include <sys/poll.h>

static int fdevent_solaris_port_event_del(fdevents *ev, fdnode *fdn) {
    return port_dissociate(ev->port_fd, PORT_SOURCE_FD, fdn->fd);
}

static int fdevent_solaris_port_event_set(fdevents *ev, fdnode *fdn, int events) {
    int fd = fdn->fdn_ndx = fdn->fd;
    intptr_t ud = events & (POLLIN|POLLOUT);
    return port_associate(ev->port_fd,PORT_SOURCE_FD,fd,(int)ud,(void*)ud);
}

__attribute_cold__
static void fdevent_solaris_port_free(fdevents *ev) {
	close(ev->port_fd);
	free(ev->port_events);
}

/* if there is any error it will return the return values of port_getn, otherwise it will return number of events **/
static int fdevent_solaris_port_poll(fdevents *ev, int timeout_ms) {
	const int pfd = ev->port_fd;
	int ret;
	unsigned int available_events, wait_for_events = 0;

	struct timespec  timeout;

	timeout.tv_sec  = timeout_ms/1000L;
	timeout.tv_nsec = (timeout_ms % 1000L) * 1000000L;

	/* get the number of file descriptors with events */
	if ((ret = port_getn(pfd, ev->port_events, 0, &wait_for_events, &timeout)) < 0) return ret;

	/* wait for at least one event */
	if (0 == wait_for_events) wait_for_events = 1;

	available_events = wait_for_events;

	/* get the events of the file descriptors */
	if ((ret = port_getn(pfd, ev->port_events, ev->maxfds, &available_events, &timeout)) < 0) {
		/* if errno == ETIME and available_event == wait_for_events we didn't get any events */
		/* for other errors we didn't get any events either */
		if (!(errno == ETIME && wait_for_events != available_events)) return ret;
	}

    for (int i = 0; i < (int)available_events; ++i) {
        int fd = (int)ev->port_events[i].portev_object;
        fdnode * const fdn = ev->fdarray[fd];
        const intptr_t ud = (intptr_t)ev->port_events[i].portev_user;
        int revents = ev->port_events[i].portev_events;
        if (0 == ((uintptr_t)fdn & 0x3)) {
            if (port_associate(pfd,PORT_SOURCE_FD,fd,(int)ud,(void*)ud) < 0) {
                log_error_write(ev->srv, __FILE__, __LINE__, "SS",
                                "port_associate failed: ", strerror(errno));
            }
            (*fdn->handler)(ev->srv, fdn->ctx, revents);
        }
        else {
            fdn->fde_ndx = -1;
        }
    }
    return available_events;
}

__attribute_cold__
int fdevent_solaris_port_init(fdevents *ev) {
	force_assert(POLLIN    == FDEVENT_IN);
	force_assert(POLLPRI   == FDEVENT_PRI);
	force_assert(POLLOUT   == FDEVENT_OUT);
	force_assert(POLLERR   == FDEVENT_ERR);
	force_assert(POLLHUP   == FDEVENT_HUP);
	force_assert(POLLNVAL  == FDEVENT_NVAL);
	force_assert(POLLRDHUP == FDEVENT_RDHUP);

	ev->type        = FDEVENT_HANDLER_SOLARIS_PORT;
	ev->event_set   = fdevent_solaris_port_event_set;
	ev->event_del   = fdevent_solaris_port_event_del;
	ev->poll        = fdevent_solaris_port_poll;
	ev->free        = fdevent_solaris_port_free;
	ev->port_events = malloc(ev->maxfds * sizeof(*ev->port_events));
	force_assert(NULL != ev->port_events);

	if ((ev->port_fd = port_create()) < 0) return -1;

	return 0;
}

#endif
