#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef FDEVENT_USE_SOLARIS_DEVPOLL

# include <sys/devpoll.h>
# include <sys/ioctl.h>

__attribute_cold__
static void fdevent_solaris_devpoll_free(fdevents *ev) {
	free(ev->devpollfds);
	close(ev->devpoll_fd);
}

/* return -1 is fine here */

static int fdevent_solaris_devpoll_event_del(fdevents *ev, fdnode *fdn) {
	struct pollfd pfd;
	pfd.fd = fdn->fd;
	pfd.events = POLLREMOVE;
	pfd.revents = 0;
	return (-1 != write(ev->devpoll_fd, &pfd, sizeof(pfd))) ? 0 : -1;
}

static int fdevent_solaris_devpoll_event_set(fdevents *ev, fdnode *fdn, int events) {
	struct pollfd pfd;
	pfd.fd = fdn->fde_ndx = fdn->fd;
	pfd.events = events;
	pfd.revents = 0;
	return (-1 != write(ev->devpoll_fd, &pfd, sizeof(pfd))) ? 0 : -1;
}

static int fdevent_solaris_devpoll_poll(fdevents *ev, int timeout_ms) {
    int n;
    server * const srv = ev->srv;
    struct dvpoll dopoll;

    dopoll.dp_timeout = timeout_ms;
    dopoll.dp_nfds = ev->maxfds - 1;
    dopoll.dp_fds = ev->devpollfds;

    n = ioctl(ev->devpoll_fd, DP_POLL, &dopoll);

    for (int i = 0; i < n; ++i) {
        fdnode * const fdn = ev->fdarray[ev->devpollfds[i].fd];
        int revents = ev->devpollfds[i].revents;
        if (0 == ((uintptr_t)fdn & 0x3)) {
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

__attribute_cold__
int fdevent_solaris_devpoll_reset(fdevents *ev) {
	/* a forked process does only inherit the filedescriptor,
	 * but every operation on the device will lead to a EACCES */
	if ((ev->devpoll_fd = fdevent_open_cloexec("/dev/poll", 1, O_RDWR, 0)) < 0) return -1;
	return 0;
}

__attribute_cold__
int fdevent_solaris_devpoll_init(fdevents *ev) {
	force_assert(POLLIN    == FDEVENT_IN);
	force_assert(POLLPRI   == FDEVENT_PRI);
	force_assert(POLLOUT   == FDEVENT_OUT);
	force_assert(POLLERR   == FDEVENT_ERR);
	force_assert(POLLHUP   == FDEVENT_HUP);
	force_assert(POLLNVAL  == FDEVENT_NVAL);
	force_assert(POLLRDHUP == FDEVENT_RDHUP);

	ev->type       = FDEVENT_HANDLER_SOLARIS_DEVPOLL;
	ev->event_set  = fdevent_solaris_devpoll_event_set;
	ev->event_del  = fdevent_solaris_devpoll_event_del;
	ev->poll       = fdevent_solaris_devpoll_poll;
	ev->reset      = fdevent_solaris_devpoll_reset;
	ev->free       = fdevent_solaris_devpoll_free;
	ev->devpoll_fd = -1;
	ev->devpollfds = malloc(sizeof(*ev->devpollfds) * ev->maxfds);
	force_assert(NULL != ev->devpollfds);
	return 0;
}

#endif
