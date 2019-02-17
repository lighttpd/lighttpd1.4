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
#include <fcntl.h>

#ifdef FDEVENT_USE_SOLARIS_DEVPOLL

# include <sys/devpoll.h>
# include <sys/ioctl.h>

static void fdevent_solaris_devpoll_free(fdevents *ev) {
	free(ev->devpollfds);
	close(ev->devpoll_fd);
}

/* return -1 is fine here */

static int fdevent_solaris_devpoll_event_del(fdevents *ev, int fde_ndx, int fd) {
	struct pollfd pfd;

	if (fde_ndx < 0) return -1;

	pfd.fd = fd;
	pfd.events = POLLREMOVE;
	pfd.revents = 0;

	if (-1 == write(ev->devpoll_fd, &pfd, sizeof(pfd))) {
		log_error_write(ev->srv, __FILE__, __LINE__, "S(D, S)",
			"(del) write failed: ", fd, strerror(errno));

		return -1;
	}

	return -1;
}

static int fdevent_solaris_devpoll_event_set(fdevents *ev, int fde_ndx, int fd, int events) {
	struct pollfd pfd;
	int add = (-1 == fde_ndx);

	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;

	if (-1 == write(ev->devpoll_fd, &pfd, sizeof(pfd))) {
		log_error_write(ev->srv, __FILE__, __LINE__, "S(D, S)",
			"(set) write failed: ", fd, strerror(errno));

		return -1;
	}

	return fd;
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
        int revents = ev->devpollfds[i].revents;
        fdnode * const fdn = ev->fdarray[ev->devpollfds[i].fd];
        if (0 == ((uintptr_t)fdn & 0x3)) {
            (*fdn->handler)(srv, fdn->ctx, revents);
        }
    }
    return n;
}

int fdevent_solaris_devpoll_reset(fdevents *ev) {
	/* a forked process does only inherit the filedescriptor,
	 * but every operation on the device will lead to a EACCES */
	if ((ev->devpoll_fd = open("/dev/poll", O_RDWR)) < 0) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"opening /dev/poll failed (", strerror(errno), "), try to set server.event-handler = \"poll\" or \"select\"");

		return -1;
	}

	fdevent_setfd_cloexec(ev->devpoll_fd);
	return 0;
}
int fdevent_solaris_devpoll_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_SOLARIS_DEVPOLL;
	force_assert(POLLIN    == FDEVENT_IN);
	force_assert(POLLPRI   == FDEVENT_PRI);
	force_assert(POLLOUT   == FDEVENT_OUT);
	force_assert(POLLERR   == FDEVENT_ERR);
	force_assert(POLLHUP   == FDEVENT_HUP);
	force_assert(POLLNVAL  == FDEVENT_NVAL);
	force_assert(POLLRDHUP == FDEVENT_RDHUP);
#define SET(x) \
	ev->x = fdevent_solaris_devpoll_##x;

	SET(free);
	SET(poll);
	SET(reset);

	SET(event_del);
	SET(event_set);

	ev->devpollfds = malloc(sizeof(*ev->devpollfds) * ev->maxfds);
	force_assert(NULL != ev->devpollfds);

	if ((ev->devpoll_fd = open("/dev/poll", O_RDWR)) < 0) {
		log_error_write(ev->srv, __FILE__, __LINE__, "SSS",
			"opening /dev/poll failed (", strerror(errno), "), try to set server.event-handler = \"poll\" or \"select\"");

		return -1;
	}

	/* we just wanted to check if it works */
	close(ev->devpoll_fd);

	ev->devpoll_fd = -1;

	return 0;
}

#else
int fdevent_solaris_devpoll_init(fdevents *ev) {
	UNUSED(ev);

	log_error_write(ev->srv, __FILE__, __LINE__, "S",
		"solaris-devpoll not supported, try to set server.event-handler = \"poll\" or \"select\"");

	return -1;
}
#endif
