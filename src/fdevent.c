#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <sys/types.h>
#include "sys-socket.h"
#include "sys-time.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef _WIN32
#include <sys/stat.h>   /* _S_IREAD _S_IWRITE */
#include <io.h>
#include <share.h>      /* _SH_DENYRW */
#endif

#ifdef SOCK_CLOEXEC
static int use_sock_cloexec;
#endif
#ifdef SOCK_NONBLOCK
static int use_sock_nonblock;
#endif

int fdevent_config(const char **event_handler_name, log_error_st *errh) {
	static const struct ev_map { fdevent_handler_t et; const char *name; } event_handlers[] =
	{
		/* - epoll is most reliable
		 * - select works everywhere
		 */
#ifdef FDEVENT_USE_LINUX_EPOLL
		{ FDEVENT_HANDLER_LINUX_SYSEPOLL, "linux-sysepoll" },
		{ FDEVENT_HANDLER_LINUX_SYSEPOLL, "epoll" },
#endif
#ifdef FDEVENT_USE_SOLARIS_PORT
		{ FDEVENT_HANDLER_SOLARIS_PORT,   "solaris-eventports" },
#endif
#ifdef FDEVENT_USE_SOLARIS_DEVPOLL
		{ FDEVENT_HANDLER_SOLARIS_DEVPOLL,"solaris-devpoll" },
#endif
#ifdef FDEVENT_USE_FREEBSD_KQUEUE
		{ FDEVENT_HANDLER_FREEBSD_KQUEUE, "freebsd-kqueue" },
		{ FDEVENT_HANDLER_FREEBSD_KQUEUE, "kqueue" },
#endif
#ifdef FDEVENT_USE_POLL
		{ FDEVENT_HANDLER_POLL,           "poll" },
#endif
#ifdef FDEVENT_USE_SELECT
		{ FDEVENT_HANDLER_SELECT,         "select" },
#endif
#ifdef FDEVENT_USE_LIBEV
		{ FDEVENT_HANDLER_LIBEV,          "libev" },
#endif
		{ FDEVENT_HANDLER_UNSET,          NULL }
	};

	const char * event_handler = *event_handler_name;
	fdevent_handler_t et = FDEVENT_HANDLER_UNSET;

#ifndef FDEVENT_USE_LIBEV
	if (NULL != event_handler && 0 == strcmp(event_handler, "libev"))
		event_handler = NULL;
#endif
#ifdef FDEVENT_USE_POLL
	if (NULL != event_handler && 0 == strcmp(event_handler, "select"))
		event_handler = "poll";
#endif

	if (NULL == event_handler) {
		/* choose a good default
		 *
		 * the event_handler list is sorted by 'goodness'
		 * taking the first available should be the best solution
		 */
		et = event_handlers[0].et;
		*event_handler_name = event_handlers[0].name;

		if (FDEVENT_HANDLER_UNSET == et) {
			log_error(errh, __FILE__, __LINE__,
			  "sorry, there is no event handler for this system");

			return -1;
		}
	} else {
		/*
		 * User override
		 */

		for (uint32_t i = 0; event_handlers[i].name; ++i) {
			if (0 == strcmp(event_handlers[i].name, event_handler)) {
				et = event_handlers[i].et;
				break;
			}
		}

		if (FDEVENT_HANDLER_UNSET == et) {
			log_error(errh, __FILE__, __LINE__,
			  "the selected event-handler in unknown or not supported: %s",
			  event_handler);
			return -1;
		}
	}

	return et;
}

const char * fdevent_show_event_handlers(void) {
    return
      "\nEvent Handlers:\n\n"
#ifdef FDEVENT_USE_SELECT
      "\t+ select (generic)\n"
#else
      "\t- select (generic)\n"
#endif
#ifdef FDEVENT_USE_POLL
      "\t+ poll (Unix)\n"
#else
      "\t- poll (Unix)\n"
#endif
#ifdef FDEVENT_USE_LINUX_EPOLL
      "\t+ epoll (Linux)\n"
#else
      "\t- epoll (Linux)\n"
#endif
#ifdef FDEVENT_USE_SOLARIS_DEVPOLL
      "\t+ /dev/poll (Solaris)\n"
#else
      "\t- /dev/poll (Solaris)\n"
#endif
#ifdef FDEVENT_USE_SOLARIS_PORT
      "\t+ eventports (Solaris)\n"
#else
      "\t- eventports (Solaris)\n"
#endif
#ifdef FDEVENT_USE_FREEBSD_KQUEUE
      "\t+ kqueue (FreeBSD)\n"
#else
      "\t- kqueue (FreeBSD)\n"
#endif
#ifdef FDEVENT_USE_LIBEV
      "\t+ libev (generic)\n"
#else
      "\t- libev (generic)\n"
#endif
      ;
}

fdevents * fdevent_init(const char *event_handler, int *max_fds, int *cur_fds, log_error_st *errh) {
	fdevents *ev;
	uint32_t maxfds = (0 != *max_fds)
	  ? (uint32_t)*max_fds
	  : 4096;
	int type = fdevent_config(&event_handler, errh);
	if (type <= 0) return NULL;

      #ifdef SOCK_CLOEXEC
	/* Test if SOCK_CLOEXEC is supported by kernel.
	 * Linux kernels < 2.6.27 might return EINVAL if SOCK_CLOEXEC used
	 * https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529929
	 * http://www.linksysinfo.org/index.php?threads/lighttpd-no-longer-starts-toastman-1-28-0510-7.73132/
	 * Test if SOCK_NONBLOCK is ignored by kernel on sockets.
	 * (reported on Android running a custom ROM)
	 * https://redmine.lighttpd.net/issues/2883
	 */
       #ifdef SOCK_NONBLOCK
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
       #else
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
       #endif
	if (fd >= 0) {
		int flags = fcntl(fd, F_GETFL, 0);
              #ifdef SOCK_NONBLOCK
		use_sock_nonblock = (-1 != flags && (flags & O_NONBLOCK));
              #endif
		use_sock_cloexec = 1;
		close(fd);
	}
      #endif

      #ifdef FDEVENT_USE_SELECT
	/* select limits itself
	 * as it is a hard limit and will lead to a segfault we add some safety
	 * */
	if (type == FDEVENT_HANDLER_SELECT) {
		if (maxfds > (uint32_t)FD_SETSIZE - 200)
		    maxfds = (uint32_t)FD_SETSIZE - 200;
	}
      #endif
	*max_fds = (int)maxfds;
	++maxfds; /*(+1 for event-handler fd)*/

	ev = calloc(1, sizeof(*ev));
	force_assert(NULL != ev);
	ev->errh = errh;
	ev->cur_fds = cur_fds;
	ev->event_handler = event_handler;
	ev->fdarray = calloc(maxfds, sizeof(*ev->fdarray));
	if (NULL == ev->fdarray) {
		log_error(ev->errh, __FILE__, __LINE__,
		  "server.max-fds too large? (%u)", maxfds-1);
		free(ev);
		return NULL;
	}
	ev->maxfds = maxfds;

	switch(type) {
	#ifdef FDEVENT_USE_POLL
	case FDEVENT_HANDLER_POLL:
		if (0 == fdevent_poll_init(ev)) return ev;
		break;
	#endif
	#ifdef FDEVENT_USE_SELECT
	case FDEVENT_HANDLER_SELECT:
		if (0 == fdevent_select_init(ev)) return ev;
		break;
	#endif
	#ifdef FDEVENT_USE_LINUX_EPOLL
	case FDEVENT_HANDLER_LINUX_SYSEPOLL:
		if (0 == fdevent_linux_sysepoll_init(ev)) return ev;
		break;
	#endif
	#ifdef FDEVENT_USE_SOLARIS_DEVPOLL
	case FDEVENT_HANDLER_SOLARIS_DEVPOLL:
		if (0 == fdevent_solaris_devpoll_init(ev)) return ev;
		break;
	#endif
	#ifdef FDEVENT_USE_SOLARIS_PORT
	case FDEVENT_HANDLER_SOLARIS_PORT:
		if (0 == fdevent_solaris_port_init(ev)) return ev;
		break;
	#endif
	#ifdef FDEVENT_USE_FREEBSD_KQUEUE
	case FDEVENT_HANDLER_FREEBSD_KQUEUE:
		if (0 == fdevent_freebsd_kqueue_init(ev)) return ev;
		break;
	#endif
	#ifdef FDEVENT_USE_LIBEV
	case FDEVENT_HANDLER_LIBEV:
		if (0 == fdevent_libev_init(ev)) return ev;
		break;
	#endif
	/*case FDEVENT_HANDLER_UNSET:*/
	default:
		break;
	}

	free(ev->fdarray);
	free(ev);

	log_error(errh, __FILE__, __LINE__,
	  "event-handler failed: %s; "
	  "try to set server.event-handler = \"poll\" or \"select\"",
	  event_handler);
	return NULL;
}

void fdevent_free(fdevents *ev) {
	if (!ev) return;

	if (ev->free) ev->free(ev);

	for (uint32_t i = 0; i < ev->maxfds; ++i) {
		/* (fdevent_sched_run() should already have been run,
		 *  but take reasonable precautions anyway) */
		if (ev->fdarray[i])
			free((fdnode *)((uintptr_t)ev->fdarray[i] & ~0x3));
	}

	free(ev->fdarray);
	free(ev);
}

int fdevent_reset(fdevents *ev) {
	int rc = (NULL != ev->reset) ? ev->reset(ev) : 0;
	if (-1 == rc) {
		log_error(ev->errh, __FILE__, __LINE__,
		  "event-handler failed: %s; "
		  "try to set server.event-handler = \"poll\" or \"select\"",
		  ev->event_handler ? ev->event_handler : "");
	}
	return rc;
}

__attribute_malloc__
__attribute_returns_nonnull__
static fdnode *fdnode_init(void) {
	fdnode * const restrict fdn = calloc(1, sizeof(fdnode));
	force_assert(NULL != fdn);
	return fdn;
}

static void fdnode_free(fdnode *fdn) {
	free(fdn);
}

fdnode * fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx) {
	fdnode *fdn  = ev->fdarray[fd] = fdnode_init();
	fdn->handler = handler;
	fdn->fd      = fd;
	fdn->ctx     = ctx;
	fdn->events  = 0;
	fdn->fde_ndx = -1;
      #ifdef FDEVENT_USE_LIBEV
	fdn->handler_ctx = NULL;
      #endif
	return fdn;
}

void fdevent_unregister(fdevents *ev, int fd) {
	fdnode *fdn = ev->fdarray[fd];
	if ((uintptr_t)fdn & 0x3) return; /*(should not happen)*/
	ev->fdarray[fd] = NULL;
	fdnode_free(fdn);
}

void fdevent_sched_close(fdevents *ev, int fd, int issock) {
	fdnode *fdn = ev->fdarray[fd];
	if ((uintptr_t)fdn & 0x3) return;
	ev->fdarray[fd] = (fdnode *)((uintptr_t)fdn | (issock ? 0x1 : 0x2));
	fdn->handler = (fdevent_handler)NULL;
	fdn->ctx = ev->pendclose;
	ev->pendclose = fdn;
}

static void fdevent_sched_run(fdevents *ev) {
	for (fdnode *fdn = ev->pendclose; fdn; ) {
		int fd, rc;
		fdnode *fdn_tmp;
	      #ifdef _WIN32
		rc = (uintptr_t)fdn & 0x3;
	      #endif
		fdn = (fdnode *)((uintptr_t)fdn & ~0x3);
		fd = fdn->fd;
	      #ifdef _WIN32
		if (rc == 0x1) {
			rc = closesocket(fd);
		}
		else if (rc == 0x2) {
			rc = close(fd);
		}
	      #else
		rc = close(fd);
	      #endif

		if (0 != rc) {
			log_perror(ev->errh, __FILE__, __LINE__, "close failed %d", fd);
		}
		else {
			--(*ev->cur_fds);
		}

		fdn_tmp = fdn;
		fdn = (fdnode *)fdn->ctx; /* next */
		/*(fdevent_unregister)*/
		fdnode_free(fdn_tmp);
		ev->fdarray[fd] = NULL;
	}
	ev->pendclose = NULL;
}

__attribute_cold__
__attribute_noinline__
static int fdevent_fdnode_event_unsetter_retry(fdevents *ev, fdnode *fdn) {
    do {
        switch (errno) {
         #ifdef EWOULDBLOCK
         #if EAGAIN != EWOULDBLOCK
          case EWOULDBLOCK:
         #endif
         #endif
          case EAGAIN:
          case EINTR:
            /* temporary error; retry */
            break;
          /*case ENOMEM:*/
          default:
            /* unrecoverable error; might leak fd */
            log_perror(ev->errh, __FILE__, __LINE__,
              "fdevent event_del failed on fd %d", fdn->fd);
            return 0;
        }
    } while (0 != ev->event_del(ev, fdn));
    return 1;
}

static void fdevent_fdnode_event_unsetter(fdevents *ev, fdnode *fdn) {
    if (-1 == fdn->fde_ndx) return;
    if (0 != ev->event_del(ev, fdn))
        fdevent_fdnode_event_unsetter_retry(ev, fdn);
    fdn->fde_ndx = -1;
    fdn->events = 0;
}

__attribute_cold__
__attribute_noinline__
static int fdevent_fdnode_event_setter_retry(fdevents *ev, fdnode *fdn, int events) {
    do {
        switch (errno) {
         #ifdef EWOULDBLOCK
         #if EAGAIN != EWOULDBLOCK
          case EWOULDBLOCK:
         #endif
         #endif
          case EAGAIN:
          case EINTR:
            /* temporary error; retry */
            break;
          /*case ENOMEM:*/
          default:
            /* unrecoverable error */
            log_perror(ev->errh, __FILE__, __LINE__,
              "fdevent event_set failed on fd %d", fdn->fd);
            return 0;
        }
    } while (0 != ev->event_set(ev, fdn, events));
    return 1;
}

static void fdevent_fdnode_event_setter(fdevents *ev, fdnode *fdn, int events) {
    /*(Note: skips registering with kernel if initial events is 0,
     * so caller should pass non-zero events for initial registration.
     * If never registered due to never being called with non-zero events,
     * then FDEVENT_HUP or FDEVENT_ERR will never be returned.) */
    if (fdn->events == events) return;/*(no change; nothing to do)*/

    if (0 == ev->event_set(ev, fdn, events)
        || fdevent_fdnode_event_setter_retry(ev, fdn, events))
        fdn->events = events;
}

void fdevent_fdnode_event_del(fdevents *ev, fdnode *fdn) {
    if (NULL != fdn) fdevent_fdnode_event_unsetter(ev, fdn);
}

void fdevent_fdnode_event_set(fdevents *ev, fdnode *fdn, int events) {
    if (NULL != fdn) fdevent_fdnode_event_setter(ev, fdn, events);
}

void fdevent_fdnode_event_add(fdevents *ev, fdnode *fdn, int event) {
    if (NULL != fdn) fdevent_fdnode_event_setter(ev, fdn, (fdn->events|event));
}

void fdevent_fdnode_event_clr(fdevents *ev, fdnode *fdn, int event) {
    if (NULL != fdn) fdevent_fdnode_event_setter(ev, fdn, (fdn->events&~event));
}

int fdevent_poll(fdevents *ev, int timeout_ms) {
    int n = ev->poll(ev, timeout_ms);
    if (n >= 0)
        fdevent_sched_run(ev);
    else if (errno != EINTR)
        log_perror(ev->errh, __FILE__, __LINE__, "fdevent_poll failed");
    return n;
}

void fdevent_setfd_cloexec(int fd) {
#ifdef FD_CLOEXEC
	if (fd < 0) return;
	force_assert(-1 != fcntl(fd, F_SETFD, FD_CLOEXEC));
#else
	UNUSED(fd);
#endif
}

void fdevent_clrfd_cloexec(int fd) {
#ifdef FD_CLOEXEC
	if (fd >= 0) force_assert(-1 != fcntl(fd, F_SETFD, 0));
#else
	UNUSED(fd);
#endif
}

int fdevent_fcntl_set_nb(int fd) {
#ifdef O_NONBLOCK
	return fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);
#else
	UNUSED(fd);
	return 0;
#endif
}

int fdevent_fcntl_set_nb_cloexec(int fd) {
	fdevent_setfd_cloexec(fd);
	return fdevent_fcntl_set_nb(fd);
}

int fdevent_fcntl_set_nb_cloexec_sock(int fd) {
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
	if (use_sock_cloexec && use_sock_nonblock)
		return 0;
#endif
	return fdevent_fcntl_set_nb_cloexec(fd);
}

int fdevent_socket_cloexec(int domain, int type, int protocol) {
	int fd;
#ifdef SOCK_CLOEXEC
	if (use_sock_cloexec)
		return socket(domain, type | SOCK_CLOEXEC, protocol);
#endif
	if (-1 != (fd = socket(domain, type, protocol))) {
#ifdef FD_CLOEXEC
		force_assert(-1 != fcntl(fd, F_SETFD, FD_CLOEXEC));
#endif
	}
	return fd;
}

int fdevent_socket_nb_cloexec(int domain, int type, int protocol) {
	int fd;
#ifdef SOCK_CLOEXEC
       #ifdef SOCK_NONBLOCK
	if (use_sock_cloexec && use_sock_nonblock)
		return socket(domain, type | SOCK_CLOEXEC | SOCK_NONBLOCK, protocol);
       #else
	if (use_sock_cloexec) {
		fd = socket(domain, type | SOCK_CLOEXEC, protocol);
	      #ifdef O_NONBLOCK
		if (-1 != fd) force_assert(-1 != fcntl(fd,F_SETFL,O_NONBLOCK|O_RDWR));
	      #endif
		return fd;
	}
       #endif
#endif
	if (-1 != (fd = socket(domain, type, protocol))) {
#ifdef FD_CLOEXEC
		force_assert(-1 != fcntl(fd, F_SETFD, FD_CLOEXEC));
#endif
#ifdef O_NONBLOCK
		force_assert(-1 != fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR));
#endif
	}
	return fd;
}

int fdevent_dup_cloexec (int fd) {
  #ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 3);
  #else
    const int newfd = fcntl(fd, F_DUPFD, 3);
    if (newfd >= 0) fdevent_setfd_cloexec(newfd);
    return newfd;
  #endif
}

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

/*(O_NOFOLLOW is not handled here)*/
/*(Note: O_NOFOLLOW affects only the final path segment, the target file,
 * not any intermediate symlinks along the path)*/

/* O_CLOEXEC handled further below, if defined) */
#ifdef O_NONBLOCK
#define FDEVENT_O_FLAGS \
        (O_BINARY | O_LARGEFILE | O_NOCTTY | O_NONBLOCK)
#else
#define FDEVENT_O_FLAGS \
        (O_BINARY | O_LARGEFILE | O_NOCTTY )
#endif

int fdevent_open_cloexec(const char *pathname, int symlinks, int flags, mode_t mode) {
	if (!symlinks) flags |= O_NOFOLLOW;
#ifdef O_CLOEXEC
	return open(pathname, flags | O_CLOEXEC | FDEVENT_O_FLAGS, mode);
#else
	int fd = open(pathname, flags | FDEVENT_O_FLAGS, mode);
#ifdef FD_CLOEXEC
	if (fd != -1)
		force_assert(-1 != fcntl(fd, F_SETFD, FD_CLOEXEC));
#endif
	return fd;
#endif
}


int fdevent_open_devnull(void) {
  #if defined(_WIN32)
    return fdevent_open_cloexec("nul", 0, O_RDWR, 0);
  #else
    return fdevent_open_cloexec("/dev/null", 0, O_RDWR, 0);
  #endif
}


int fdevent_open_dirname(char *path, int symlinks) {
    /*(handle special cases of no dirname or dirname is root directory)*/
    char * const c = strrchr(path, '/');
    const char * const dname = (NULL != c ? c == path ? "/" : path : ".");
    int dfd;
    int flags = O_RDONLY;
  #ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
  #endif
    if (NULL != c) *c = '\0';
    dfd = fdevent_open_cloexec(dname, symlinks, flags, 0);
    if (NULL != c) *c = '/';
    return dfd;
}


#ifdef _WIN32
#include <stdio.h>
#endif

int fdevent_pipe_cloexec (int * const fds, const unsigned int bufsz_hint) {
 #ifdef _WIN32
    return _pipe(fds, bufsz_hint, _O_BINARY | _O_NOINHERIT);
 #else
  #ifdef HAVE_PIPE2
    if (0 != pipe2(fds, O_CLOEXEC))
  #endif
    {
        if (0 != pipe(fds)
         #ifdef FD_CLOEXEC
         || 0 != fcntl(fds[0], F_SETFD, FD_CLOEXEC)
         || 0 != fcntl(fds[1], F_SETFD, FD_CLOEXEC)
         #endif
           )
            return -1;
    }
  #ifdef F_SETPIPE_SZ
    if (bufsz_hint > 65536)
        if (0 != fcntl(fds[1], F_SETPIPE_SZ, bufsz_hint)) { } /*(ignore error)*/
  #else
    UNUSED(bufsz_hint);
  #endif
    return 0;
 #endif
}


int fdevent_mkostemp(char *path, int flags) {
 #ifdef _WIN32
    /* future: if _sopen_s() returns EEXIST, might reset template (path) with
     * trailing "XXXXXX", and then loop to try again */
    int fd;      /*(flags might have _O_APPEND)*/
    return (0 == _mktemp_s(path, strlen(path)+1))
        && (0 == _sopen_s(&fd, path, _O_CREAT  | _O_EXCL   | _O_TEMPORARY
                                   | flags     | _O_BINARY | _O_NOINHERIT,
                          _SH_DENYRW, _S_IREAD | _S_IWRITE))
      ? fd
      : -1;
 #elif defined(HAVE_MKOSTEMP)
    return mkostemp(path, O_CLOEXEC | flags);
 #else
  #ifdef __COVERITY__
    /* POSIX-2008 requires mkstemp create file with 0600 perms */
    umask(0600);
  #endif
    /* coverity[secure_temp : FALSE] */
    const int fd = mkstemp(path);
    if (fd < 0) return fd;

    if (flags && 0 != fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | flags)) {
        /* (should not happen; fd is regular file) */
        int errnum = errno;
        close(fd);
        errno = errnum;
        return -1;
    }

    fdevent_setfd_cloexec(fd);
    return fd;
 #endif
}


int fdevent_accept_listenfd(int listenfd, struct sockaddr *addr, size_t *addrlen) {
	int fd;
	socklen_t len = (socklen_t) *addrlen;

      #if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
       #if defined(__NetBSD__)
	const int sock_cloexec = 1;
	fd = paccept(listenfd, addr, &len, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
       #else
	int sock_cloexec = use_sock_cloexec;
	if (sock_cloexec) {
		fd = accept4(listenfd, addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (fd >= 0) {
			if (!use_sock_nonblock) {
				if (0 != fdevent_fcntl_set_nb(fd)) {
					close(fd);
					fd = -1;
				}
			}
		}
		else {
			switch (errno) {
			case ENOSYS:
			case ENOTSUP:
			case EPERM:
				fd = accept(listenfd, addr, &len);
				sock_cloexec = 0;
				break;
			default:
				break;
			}
		}
	}
	else {
		fd = accept(listenfd, addr, &len);
	}
       #endif
      #else
	const int sock_cloexec = 0;
	fd = accept(listenfd, addr, &len);
      #endif

	if (fd >= 0) {
		*addrlen = (size_t)len;
		if (!sock_cloexec && 0 != fdevent_fcntl_set_nb_cloexec(fd)) {
			close(fd);
			fd = -1;
		}
	}
	return fd;
}


#ifdef __APPLE__
#include <crt_externs.h>
#define environ (* _NSGetEnviron())
#else
extern char **environ;
#endif
char ** fdevent_environ (void) { return environ; }


#ifdef FD_CLOEXEC
static int fdevent_dup2_close_clrfd_cloexec(int oldfd, int newfd) {
    if (oldfd >= 0) {
        if (oldfd != newfd) {
            force_assert(oldfd > STDERR_FILENO);
            if (newfd != dup2(oldfd, newfd)) return -1;
        }
        else {
            fdevent_clrfd_cloexec(newfd);
        }
    }
    return newfd;
}
#else
static int fdevent_dup2_close_clrfd_cloexec(int oldfd, int newfd, int reuse) {
    if (oldfd >= 0) {
        if (oldfd != newfd) {
            force_assert(oldfd > STDERR_FILENO);
            if (newfd != dup2(oldfd, newfd)) return -1;
            if (!reuse) close(oldfd);
        }
    }
    return newfd;
}
#endif


int fdevent_set_stdin_stdout_stderr(int fdin, int fdout, int fderr) {
  #ifdef FD_CLOEXEC
    if (STDIN_FILENO != fdevent_dup2_close_clrfd_cloexec(fdin, STDIN_FILENO))
        return -1;
    if (STDOUT_FILENO != fdevent_dup2_close_clrfd_cloexec(fdout, STDOUT_FILENO))
        return -1;
    if (STDERR_FILENO != fdevent_dup2_close_clrfd_cloexec(fderr, STDERR_FILENO))
        return -1;
  #else
    if (STDIN_FILENO != fdevent_dup2_close_clrfd_cloexec(fdin, STDIN_FILENO,
                                                         fdin == fdout
                                                         || fdin == fderr))
        return -1;
    if (STDOUT_FILENO != fdevent_dup2_close_clrfd_cloexec(fdout, STDOUT_FILENO,
                                                          fdout == fderr))
        return -1;
    if (STDERR_FILENO != fdevent_dup2_close_clrfd_cloexec(fderr, STDERR_FILENO,
                                                          0))
        return -1;
  #endif

    return 0;
}


#include <stdio.h>      /* perror() rename() */
#include <signal.h>     /* signal() */


int fdevent_rename(const char *oldpath, const char *newpath) {
    return rename(oldpath, newpath);
}


pid_t fdevent_fork_execve(const char *name, char *argv[], char *envp[], int fdin, int fdout, int fderr, int dfd) {
 #ifdef HAVE_FORK

    pid_t pid = fork();
    if (0 != pid) return pid; /* parent (pid > 0) or fork() error (-1 == pid) */

    /* child (0 == pid) */

    if (-1 != dfd) {
        if (0 != fchdir(dfd))
            _exit(errno);
        close(dfd);
    }

    if (0 != fdevent_set_stdin_stdout_stderr(fdin, fdout, fderr)) _exit(errno);
  #ifndef FD_CLOEXEC
    /*(might not be sufficient for open fds, but modern OS have FD_CLOEXEC)*/
    for (int i = 3; i < 256; ++i) close(i);
  #endif

    /* reset_signals which may have been ignored (SIG_IGN) */
  #ifdef SIGTTOU
    signal(SIGTTOU, SIG_DFL);
  #endif
  #ifdef SIGTTIN
    signal(SIGTTIN, SIG_DFL);
  #endif
  #ifdef SIGTSTP
    signal(SIGTSTP, SIG_DFL);
  #endif
    signal(SIGPIPE, SIG_DFL);

    execve(name, argv, envp ? envp : environ);

    int errnum = errno;
    int argnum =
      (0 == strcmp(argv[0], "/bin/sh") && argv[1] && 0 == strcmp(argv[1], "-c"))
      ? 2
      : 0;
    perror(argv[argnum]);
    _exit(errnum);

 #else

    UNUSED(name);
    UNUSED(argv);
    UNUSED(envp);
    UNUSED(fdin);
    UNUSED(fdout);
    UNUSED(fderr);
    UNUSED(dfd);
    return (pid_t)-1;

 #endif
}


#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

int fdevent_waitpid(pid_t pid, int * const status, int nb) {
    const int flags = nb ? WNOHANG : 0;
    pid_t rv;
    do { rv = waitpid(pid, status, flags); } while (-1 == rv && errno == EINTR);
    return rv;
}

int fdevent_waitpid_intr(pid_t pid, int * const status) {
    return waitpid(pid, status, 0);
}


#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif


ssize_t fdevent_socket_read_discard (int fd, char *buf, size_t sz, int family, int so_type) {
  #if defined(MSG_TRUNC) && defined(__linux__)
    if ((family == AF_INET || family == AF_INET6) && so_type == SOCK_STREAM) {
        ssize_t len = recv(fd, buf, sz, MSG_TRUNC|MSG_DONTWAIT|MSG_NOSIGNAL);
        if (len >= 0 || errno != EINVAL) return len;
    }
  #else
    UNUSED(family);
    UNUSED(so_type);
  #endif
    return read(fd, buf, sz);
}


#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>  /* FIONREAD (for illumos (OpenIndiana)) */
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif
int fdevent_ioctl_fionread (int fd, int fdfmt, int *toread) {
  #ifdef _WIN32
    if (fdfmt != S_IFSOCK) { errno = ENOTSOCK; return -1; }
    return ioctlsocket(fd, FIONREAD, toread);
  #else
   #ifdef __CYGWIN__
    /*(cygwin supports FIONREAD on pipes, not sockets)*/
    if (fdfmt != S_IFIFO) { errno = EOPNOTSUPP; return -1; }
   #else
    UNUSED(fdfmt);
   #endif
    return ioctl(fd, FIONREAD, toread);
  #endif
}


int fdevent_connect_status(int fd) {
    /* try to finish the connect() */
    /*(should be called after connect() only when fd is writable (POLLOUT))*/
    int opt;
    socklen_t len = sizeof(opt);
    return (0 == getsockopt(fd,SOL_SOCKET,SO_ERROR,&opt,&len)) ? opt : errno;
}


#include <netinet/tcp.h>
#if (defined(__APPLE__) && defined(__MACH__)) \
  || defined(__FreeBSD__) || defined(__NetBSD__) \
  || defined(__OpenBSD__) || defined(__DragonFly__)
#include <netinet/tcp_fsm.h>
#endif

/* fd must be TCP socket (AF_INET, AF_INET6), end-of-stream recv() 0 bytes */
int fdevent_is_tcp_half_closed(int fd) {
  #ifdef TCP_CONNECTION_INFO     /* Darwin */
    struct tcp_connection_info tcpi;
    socklen_t tlen = sizeof(tcpi);
    return (0 == getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &tcpi, &tlen)
            && tcpi.tcpi_state == TCPS_CLOSE_WAIT);
  #elif defined(TCP_INFO) && defined(TCPS_CLOSE_WAIT)
    /* FreeBSD, NetBSD (not present in OpenBSD or DragonFlyBSD) */
    struct tcp_info tcpi;
    socklen_t tlen = sizeof(tcpi);
    return (0 == getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcpi, &tlen)
            && tcpi.tcpi_state == TCPS_CLOSE_WAIT);
  #elif defined(TCP_INFO) && defined(__linux__)
    /* Linux (TCP_CLOSE_WAIT is enum, so can not #ifdef TCP_CLOSE_WAIT) */
    struct tcp_info tcpi;
    socklen_t tlen = sizeof(tcpi);/*SOL_TCP == IPPROTO_TCP*/
    return (0 == getsockopt(fd,     SOL_TCP, TCP_INFO, &tcpi, &tlen)
            && tcpi.tcpi_state == TCP_CLOSE_WAIT);
  #else
    UNUSED(fd);
    /*(0 != getpeername() error might indicate TCP RST, but success
     * would not differentiate between half-close and full-close)*/
    return 0; /* false (not half-closed) or TCP state unknown */
  #endif
}


int fdevent_set_tcp_nodelay (const int fd, const int opt)
{
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}


int fdevent_set_so_reuseaddr (const int fd, const int opt)
{
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}


#include <sys/stat.h>
#include "ck.h"
__attribute_cold__ /*(convenience routine for use at config at startup)*/
char *
fdevent_load_file (const char * const fn, off_t *lim, log_error_st *errh, void *(malloc_fn)(size_t), void(free_fn)(void *))
{
    int fd;
    off_t sz = 0;
    char *buf = NULL;
    do {
        fd = fdevent_open_cloexec(fn, 1, O_RDONLY, 0); /*(1: follows symlinks)*/
        if (fd < 0) break;

        struct stat st;
        if (0 != fstat(fd, &st)) break;
        if ((sizeof(off_t) > sizeof(size_t) && st.st_size >= (off_t)~(size_t)0u)
            || (*lim != 0 && st.st_size >= *lim)) {
            errno = EOVERFLOW;
            break;
        }

        sz = st.st_size;
        buf = malloc_fn((size_t)sz+1);/*+1 trailing '\0' for str funcs on data*/
        if (NULL == buf) break;

        if (sz) {
            ssize_t rd = 0;
            off_t off = 0;
            do {
                rd = read(fd, buf+off, (size_t)(sz-off));
            } while (rd > 0 ? (off += rd) != sz : rd < 0 && errno == EINTR);
            if (off != sz) { /*(file truncated?)*/
                if (rd >= 0) errno = EIO;
                break;
            }
        }

        buf[sz] = '\0';
        *lim = sz;
        close(fd);
        return buf;
    } while (0);
    int errnum = errno;
    if (errh)
        log_perror(errh, __FILE__, __LINE__, "%s() %s", __func__, fn);
    if (fd >= 0) close(fd);
    if (buf) {
        ck_memzero(buf, (size_t)sz);
        free_fn(buf);
    }
    *lim = 0;
    errno = errnum;
    return NULL;
}


int
fdevent_load_file_bytes (char * const buf, const off_t sz, off_t off, const char * const fn, log_error_st *errh)
{
    int fd;
    do {
        fd = fdevent_open_cloexec(fn, 1, O_RDONLY, 0); /*(1: follows symlinks)*/
        if (fd < 0) break;

        if (0 != off && (off_t)-1 == lseek(fd, off, SEEK_SET)) break;
        off = 0;

        ssize_t rd = 0;
        do {
            rd = read(fd, buf+off, (size_t)(sz-off));
        } while (rd > 0 ? (off += rd) != sz : rd < 0 && errno == EINTR);
        if (off != sz) { /*(file truncated? or incorrect sz requested)*/
            if (rd >= 0) errno = EIO;
            break;
        }

        close(fd);
        return 0;
    } while (0);
    int errnum = errno;
    if (errh)
        log_perror(errh, __FILE__, __LINE__, "%s() %s", __func__, fn);
    if (fd >= 0) close(fd);
    ck_memzero(buf, (size_t)sz);
    errno = errnum;
    return -1;
}
