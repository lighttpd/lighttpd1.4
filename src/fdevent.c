#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "base.h"
#include "buffer.h"
#include "log.h"

#include <sys/types.h>
#include <sys/wait.h>
#include "sys-socket.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#ifdef SOCK_CLOEXEC
static int use_sock_cloexec;
#endif
#ifdef SOCK_NONBLOCK
static int use_sock_nonblock;
#endif

int fdevent_config(server *srv) {
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

	if (buffer_string_is_empty(srv->srvconf.event_handler)) {
		/* choose a good default
		 *
		 * the event_handler list is sorted by 'goodness'
		 * taking the first available should be the best solution
		 */
		srv->event_handler = event_handlers[0].et;

		if (FDEVENT_HANDLER_UNSET == srv->event_handler) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"sorry, there is no event handler for this system");

			return -1;
		}

		buffer_copy_string(srv->srvconf.event_handler, event_handlers[0].name);
	} else {
		/*
		 * User override
		 */

		for (size_t i = 0; event_handlers[i].name; i++) {
			if (0 == strcmp(event_handlers[i].name, srv->srvconf.event_handler->ptr)) {
				srv->event_handler = event_handlers[i].et;
				break;
			}
		}

		if (FDEVENT_HANDLER_UNSET == srv->event_handler) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"the selected event-handler in unknown or not supported:",
					srv->srvconf.event_handler );

			return -1;
		}
	}

      #ifdef FDEVENT_USE_SELECT
	if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
		/* select limits itself
		 *
		 * as it is a hard limit and will lead to a segfault we add some safety
		 * */
		srv->max_fds = FD_SETSIZE - 200;
	}
	else
      #endif
	{
		srv->max_fds = 4096;
	}

	return 0;
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

fdevents *fdevent_init(server *srv) {
	fdevents *ev;
	int type = srv->event_handler;
	size_t maxfds;

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
	if (type == FDEVENT_HANDLER_SELECT) {
		if (srv->max_fds > (int)FD_SETSIZE - 200) {
			srv->max_fds = (int)FD_SETSIZE - 200;
		}
	}
      #endif
	maxfds = srv->max_fds + 1; /*(+1 for event-handler fd)*/

	ev = calloc(1, sizeof(*ev));
	force_assert(NULL != ev);
	ev->srv = srv;
	ev->fdarray = calloc(maxfds, sizeof(*ev->fdarray));
	if (NULL == ev->fdarray) {
		log_error_write(srv, __FILE__, __LINE__, "SDS",
				"server.max-fds too large? (", maxfds-1, ")");
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
	case FDEVENT_HANDLER_UNSET:
	default:
		break;
	}

	free(ev->fdarray);
	free(ev);

	log_error_write(srv, __FILE__, __LINE__, "sBS",
		"event-handler failed:", srv->srvconf.event_handler, "; try to set server.event-handler = \"poll\" or \"select\"");
	return NULL;
}

void fdevent_free(fdevents *ev) {
	size_t i;
	if (!ev) return;

	if (ev->free) ev->free(ev);

	for (i = 0; i < ev->maxfds; i++) {
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
		log_error_write(ev->srv, __FILE__, __LINE__, "sBS",
			"event-handler failed:", ev->srv->srvconf.event_handler, "; try to set server.event-handler = \"poll\" or \"select\"");
	}
	return rc;
}

static fdnode *fdnode_init(void) {
	return calloc(1, sizeof(fdnode));
}

static void fdnode_free(fdnode *fdn) {
	free(fdn);
}

fdnode * fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx) {
	fdnode *fdn  = ev->fdarray[fd] = fdnode_init();
	force_assert(NULL != fdn);
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
	server *srv = ev->srv;
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
			log_error_write(srv, __FILE__, __LINE__, "sds", "close failed ", fd, strerror(errno));
		}
		else {
			--srv->cur_fds;
		}

		fdn_tmp = fdn;
		fdn = (fdnode *)fdn->ctx; /* next */
		/*(fdevent_unregister)*/
		fdnode_free(fdn_tmp);
		ev->fdarray[fd] = NULL;
	}
	ev->pendclose = NULL;
}

static void fdevent_fdnode_event_unsetter(fdevents *ev, fdnode *fdn) {
    if (-1 == fdn->fde_ndx) return;
    if (0 == ev->event_del(ev, fdn)) {
        fdn->fde_ndx = -1;
        fdn->events = 0;
    }
    else {
        log_error_write(ev->srv, __FILE__, __LINE__, "SS",
                        "fdevent event_del failed: ", strerror(errno));
    }
}

static void fdevent_fdnode_event_setter(fdevents *ev, fdnode *fdn, int events) {
    /*(Note: skips registering with kernel if initial events is 0,
     * so caller should pass non-zero events for initial registration.
     * If never registered due to never being called with non-zero events,
     * then FDEVENT_HUP or FDEVENT_ERR will never be returned.) */
    if (fdn->events == events) return;/*(no change; nothing to do)*/

    if (0 == ev->event_set(ev, fdn, events))
        fdn->events = events;
    else
        log_error_write(ev->srv, __FILE__, __LINE__, "SS",
                        "fdevent event_set failed: ", strerror(errno));
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
        log_error_write(ev->srv, __FILE__, __LINE__, "SS",
                        "fdevent_poll failed: ", strerror(errno));
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

int fdevent_fcntl_set_nb(fdevents *ev, int fd) {
	UNUSED(ev);
#ifdef O_NONBLOCK
	return fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);
#else
	UNUSED(fd);
	return 0;
#endif
}

int fdevent_fcntl_set_nb_cloexec(fdevents *ev, int fd) {
	fdevent_setfd_cloexec(fd);
	return fdevent_fcntl_set_nb(ev, fd);
}

int fdevent_fcntl_set_nb_cloexec_sock(fdevents *ev, int fd) {
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
	if (use_sock_cloexec && use_sock_nonblock)
		return 0;
#endif
	return fdevent_fcntl_set_nb_cloexec(ev, fd);
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


int fdevent_mkstemp_append(char *path) {
  #ifdef __COVERITY__
    /* POSIX-2008 requires mkstemp create file with 0600 perms */
    umask(0600);
  #endif
    /* coverity[secure_temp : FALSE] */
    const int fd = mkstemp(path);
    if (fd < 0) return fd;

    if (0 != fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_APPEND)) {
        /* (should not happen; fd is regular file) */
        int errnum = errno;
        close(fd);
        errno = errnum;
        return -1;
    }

    fdevent_setfd_cloexec(fd);
    return fd;
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
				if (0 != fdevent_fcntl_set_nb(NULL, fd)) {
					close(fd);
					fd = -1;
				}
			}
		} else if (errno == ENOSYS || errno == ENOTSUP) {
			fd = accept(listenfd, addr, &len);
			sock_cloexec = 0;
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
		if (!sock_cloexec && 0 != fdevent_fcntl_set_nb_cloexec(NULL, fd)) {
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


#include <stdio.h>      /* perror() */
#include <signal.h>     /* signal() */

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
  #ifdef FD_CLOEXEC
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

    if (0 == memcmp(argv[0], "/bin/sh", sizeof("/bin/sh")-1)
        && argv[1] && 0 == memcmp(argv[1], "-c", sizeof("-c")-1))
        perror(argv[2]);
    else
        perror(argv[0]);
    _exit(errno);

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


typedef struct fdevent_cmd_pipe {
    pid_t pid;
    int fds[2];
    const char *cmd;
    time_t start;
} fdevent_cmd_pipe;

typedef struct fdevent_cmd_pipes {
    fdevent_cmd_pipe *ptr;
    size_t used;
    size_t size;
} fdevent_cmd_pipes;

static fdevent_cmd_pipes cmd_pipes;


static pid_t fdevent_open_logger_pipe_spawn(const char *logger, int rfd) {
    char *args[4];
    int devnull = fdevent_open_devnull();
    pid_t pid;

    if (-1 == devnull) {
        return -1;
    }

    *(const char **)&args[0] = "/bin/sh";
    *(const char **)&args[1] = "-c";
    *(const char **)&args[2] = logger;
    args[3] = NULL;

    pid = fdevent_fork_execve(args[0], args, NULL, rfd, devnull, devnull, -1);

    if (pid > 0) {
        close(devnull);
    }
    else {
        int errnum = errno;
        close(devnull);
        errno = errnum;
    }
    return pid;
}


static void fdevent_restart_logger_pipe(fdevent_cmd_pipe *fcp, time_t ts) {
    if (fcp->pid > 0) return;  /* assert */
    if (fcp->start + 5 < ts) { /* limit restart to once every 5 sec */
        /* restart child process using existing pipe fds */
        fcp->start = ts;
        fcp->pid = fdevent_open_logger_pipe_spawn(fcp->cmd, fcp->fds[0]);
    }
}


void fdevent_restart_logger_pipes(time_t ts) {
    for (size_t i = 0; i < cmd_pipes.used; ++i) {
        fdevent_cmd_pipe * const fcp = cmd_pipes.ptr+i;
        if (fcp->pid > 0) continue;
        fdevent_restart_logger_pipe(fcp, ts);
    }
}


int fdevent_waitpid_logger_pipe_pid(pid_t pid, time_t ts) {
    for (size_t i = 0; i < cmd_pipes.used; ++i) {
        fdevent_cmd_pipe * const fcp = cmd_pipes.ptr+i;
        if (pid != fcp->pid) continue;
        fcp->pid = -1;
        fdevent_restart_logger_pipe(fcp, ts);
        return 1;
    }
    return 0;
}


void fdevent_clr_logger_pipe_pids(void) {
    for (size_t i = 0; i < cmd_pipes.used; ++i) {
        fdevent_cmd_pipe *fcp = cmd_pipes.ptr+i;
        fcp->pid = -1;
    }
}


int fdevent_reaped_logger_pipe(pid_t pid) {
    for (size_t i = 0; i < cmd_pipes.used; ++i) {
        fdevent_cmd_pipe *fcp = cmd_pipes.ptr+i;
        if (fcp->pid == pid) {
            time_t ts = time(NULL);
            if (fcp->start + 5 < ts) { /* limit restart to once every 5 sec */
                fcp->start = ts;
                fcp->pid = fdevent_open_logger_pipe_spawn(fcp->cmd,fcp->fds[0]);
                return 1;
            }
            else {
                fcp->pid = -1;
                return -1;
            }
        }
    }
    return 0;
}


void fdevent_close_logger_pipes(void) {
    for (size_t i = 0; i < cmd_pipes.used; ++i) {
        fdevent_cmd_pipe *fcp = cmd_pipes.ptr+i;
        close(fcp->fds[0]);
        if (fcp->fds[1] != STDERR_FILENO) close(fcp->fds[1]);
    }
    free(cmd_pipes.ptr);
    cmd_pipes.ptr = NULL;
    cmd_pipes.used = 0;
    cmd_pipes.size = 0;
}


void fdevent_breakagelog_logger_pipe(int fd) {
    for (size_t i = 0; i < cmd_pipes.used; ++i) {
        fdevent_cmd_pipe *fcp = cmd_pipes.ptr+i;
        if (fcp->fds[1] != fd) continue;
        fcp->fds[1] = STDERR_FILENO;
        break;
    }
}


static void fdevent_init_logger_pipe(const char *cmd, int fds[2], pid_t pid) {
    fdevent_cmd_pipe *fcp;
    if (cmd_pipes.used == cmd_pipes.size) {
        cmd_pipes.size += 4;
        cmd_pipes.ptr =
          realloc(cmd_pipes.ptr, cmd_pipes.size * sizeof(fdevent_cmd_pipe));
        force_assert(cmd_pipes.ptr);
    }
    fcp = cmd_pipes.ptr + cmd_pipes.used++;
    fcp->cmd = cmd; /* note: cmd must persist in memory (or else copy here) */
    fcp->fds[0] = fds[0];
    fcp->fds[1] = fds[1];
    fcp->pid = pid;
    fcp->start = time(NULL);
}


static int fdevent_open_logger_pipe(const char *logger) {
    int fds[2];
    pid_t pid;
    if (pipe(fds)) {
        return -1;
    }
    fdevent_setfd_cloexec(fds[0]);
    fdevent_setfd_cloexec(fds[1]);
    /*(nonblocking write() from lighttpd)*/
    if (0 != fdevent_fcntl_set_nb(NULL, fds[1])) { /*(ignore)*/ }

    pid = fdevent_open_logger_pipe_spawn(logger, fds[0]);

    if (pid > 0) {
        fdevent_init_logger_pipe(logger, fds, pid);
        return fds[1];
    }
    else {
        int errnum = errno;
        close(fds[0]);
        close(fds[1]);
        errno = errnum;
        return -1;
    }
}


int fdevent_open_logger(const char *logger) {
    if (logger[0] != '|') { /*(permit symlinks)*/
        int flags = O_APPEND | O_WRONLY | O_CREAT;
        return fdevent_open_cloexec(logger, 1, flags, 0644);
    }
    else {
        return fdevent_open_logger_pipe(logger+1); /*(skip the '|')*/
    }
}

int fdevent_cycle_logger(const char *logger, int *curfd) {
    if (logger[0] != '|') {
        int fd = fdevent_open_logger(logger);
        if (-1 == fd) return -1; /*(error; leave *curfd as-is)*/
        if (-1 != *curfd) close(*curfd);
        *curfd = fd;
    }
    return *curfd;
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
