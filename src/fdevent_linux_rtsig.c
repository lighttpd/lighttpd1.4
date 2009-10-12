#include "fdevent.h"
#include "buffer.h"

#include <sys/types.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>

#include <fcntl.h>

#ifdef USE_LINUX_SIGIO
static void fdevent_linux_rtsig_free(fdevents *ev) {
	free(ev->pollfds);
	if (ev->unused.ptr) free(ev->unused.ptr);

	bitset_free(ev->sigbset);
}


static int fdevent_linux_rtsig_event_del(fdevents *ev, int fde_ndx, int fd) {
	if (fde_ndx < 0) return -1;

	if ((size_t)fde_ndx >= ev->used) {
		fprintf(stderr, "%s.%d: del! out of range %d %zu\n", __FILE__, __LINE__, fde_ndx, ev->used);
		SEGFAULT();
	}

	if (ev->pollfds[fde_ndx].fd == fd) {
		size_t k = fde_ndx;

		ev->pollfds[k].fd = -1;

		bitset_clear_bit(ev->sigbset, fd);

		if (ev->unused.size == 0) {
			ev->unused.size = 16;
			ev->unused.ptr = malloc(sizeof(*(ev->unused.ptr)) * ev->unused.size);
		} else if (ev->unused.size == ev->unused.used) {
			ev->unused.size += 16;
			ev->unused.ptr = realloc(ev->unused.ptr, sizeof(*(ev->unused.ptr)) * ev->unused.size);
		}

		ev->unused.ptr[ev->unused.used++] = k;
	} else {
		fprintf(stderr, "%s.%d: del! %d %d\n", __FILE__, __LINE__, ev->pollfds[fde_ndx].fd, fd);

		SEGFAULT();
	}

	return -1;
}

#if 0
static int fdevent_linux_rtsig_event_compress(fdevents *ev) {
	size_t j;

	if (ev->used == 0) return 0;
	if (ev->unused.used != 0) return 0;

	for (j = ev->used - 1; j + 1 > 0; j--) {
		if (ev->pollfds[j].fd == -1) ev->used--;
	}


	return 0;
}
#endif

static int fdevent_linux_rtsig_event_add(fdevents *ev, int fde_ndx, int fd, int events) {
	/* known index */
	if (fde_ndx != -1) {
		if (ev->pollfds[fde_ndx].fd == fd) {
			ev->pollfds[fde_ndx].events = events;

			return fde_ndx;
		}
		fprintf(stderr, "%s.%d: add: (%d, %d)\n", __FILE__, __LINE__, fde_ndx, ev->pollfds[fde_ndx].fd);
		SEGFAULT();
	}

	if (ev->unused.used > 0) {
		int k = ev->unused.ptr[--ev->unused.used];

		ev->pollfds[k].fd = fd;
		ev->pollfds[k].events = events;

		bitset_set_bit(ev->sigbset, fd);

		return k;
	} else {
		if (ev->size == 0) {
			ev->size = 16;
			ev->pollfds = malloc(sizeof(*ev->pollfds) * ev->size);
		} else if (ev->size == ev->used) {
			ev->size += 16;
			ev->pollfds = realloc(ev->pollfds, sizeof(*ev->pollfds) * ev->size);
		}

		ev->pollfds[ev->used].fd = fd;
		ev->pollfds[ev->used].events = events;

		bitset_set_bit(ev->sigbset, fd);

		return ev->used++;
	}
}

static int fdevent_linux_rtsig_poll(fdevents *ev, int timeout_ms) {
	struct timespec ts;
	int r;

#if 0
	fdevent_linux_rtsig_event_compress(ev);
#endif

	ev->in_sigio = 1;

	ts.tv_sec =  timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000;
	r = sigtimedwait(&(ev->sigset), &(ev->siginfo), &(ts));

	if (r == -1) {
		if (errno == EAGAIN) return 0;
		return r;
	} else if (r == SIGIO) {
		struct sigaction act;

		/* flush the signal queue */
		memset(&act, 0, sizeof(act));
		act.sa_handler = SIG_IGN;
		sigaction(ev->signum, &act, NULL);

		/* re-enable the signal queue */
		act.sa_handler = SIG_DFL;
		sigaction(ev->signum, &act, NULL);

		ev->in_sigio = 0;
		r = poll(ev->pollfds, ev->used, timeout_ms);

		return r;
	} else if (r == ev->signum) {
#  if 0
		fprintf(stderr, "event: %d %02lx\n", ev->siginfo.si_fd, ev->siginfo.si_band);
#  endif
		return bitset_test_bit(ev->sigbset, ev->siginfo.si_fd);
	} else {
		/* ? */
		return -1;
	}
}

static int fdevent_linux_rtsig_event_get_revent(fdevents *ev, size_t ndx) {
	if (ev->in_sigio == 1) {
#  if 0
		if (ev->siginfo.si_band == POLLERR) {
			fprintf(stderr, "event: %d %02lx %02x %s\n", ev->siginfo.si_fd, ev->siginfo.si_band, errno, strerror(errno));
		}
#  endif
		if (ndx != 0) {
			fprintf(stderr, "+\n");
			return 0;
		}

		return ev->siginfo.si_band & 0x3f;
	} else {
		if (ndx >= ev->used) {
			fprintf(stderr, "%s.%d: event: %zu %zu\n", __FILE__, __LINE__, ndx, ev->used);
			return 0;
		}
		return ev->pollfds[ndx].revents;
	}
}

static int fdevent_linux_rtsig_event_get_fd(fdevents *ev, size_t ndx) {
	if (ev->in_sigio == 1) {
		return ev->siginfo.si_fd;
	} else {
		return ev->pollfds[ndx].fd;
	}
}

static int fdevent_linux_rtsig_fcntl_set(fdevents *ev, int fd) {
	static pid_t pid = 0;

	if (pid == 0) pid = getpid();

	if (-1 == fcntl(fd, F_SETSIG, ev->signum)) return -1;

	if (-1 == fcntl(fd, F_SETOWN, (int) pid)) return -1;

	return fcntl(fd, F_SETFL, O_ASYNC | O_NONBLOCK | O_RDWR);
}


static int fdevent_linux_rtsig_event_next_fdndx(fdevents *ev, int ndx) {
	if (ev->in_sigio == 1) {
		if (ndx < 0) return 0;
		return -1;
	} else {
		size_t i;

		i = (ndx < 0) ? 0 : ndx + 1;
		for (; i < ev->used; i++) {
			if (ev->pollfds[i].revents) break;
		}

		return i;
	}
}

int fdevent_linux_rtsig_init(fdevents *ev) {
	ev->type = FDEVENT_HANDLER_LINUX_RTSIG;
#define SET(x) \
	ev->x = fdevent_linux_rtsig_##x;

	SET(free);
	SET(poll);

	SET(event_del);
	SET(event_add);

	SET(event_next_fdndx);
	SET(fcntl_set);
	SET(event_get_fd);
	SET(event_get_revent);

	ev->signum = SIGRTMIN + 1;

	sigemptyset(&(ev->sigset));
	sigaddset(&(ev->sigset), ev->signum);
	sigaddset(&(ev->sigset), SIGIO);
	if (-1 == sigprocmask(SIG_BLOCK, &(ev->sigset), NULL)) {
		fprintf(stderr, "%s.%d: sigprocmask failed (%s), try to set server.event-handler = \"poll\" or \"select\"\n",
			__FILE__, __LINE__, strerror(errno));

		return -1;
	}

	ev->in_sigio = 1;

	ev->sigbset = bitset_init(ev->maxfds);

	return 0;
}
#else
int fdevent_linux_rtsig_init(fdevents *ev) {
	UNUSED(ev);

	fprintf(stderr, "%s.%d: linux-rtsig not supported, try to set server.event-handler = \"poll\" or \"select\"\n",
		__FILE__, __LINE__);
	return -1;
}
#endif
