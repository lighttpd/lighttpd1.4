#include "first.h"

#include "base.h"
#include "fdevent.h"
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

fdevents *fdevent_init(server *srv, size_t maxfds, int type) {
	fdevents *ev;

      #ifdef SOCK_CLOEXEC
	/* Test if SOCK_CLOEXEC is supported by kernel.
	 * Linux kernels < 2.6.27 might return EINVAL if SOCK_CLOEXEC used
	 * https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529929
	 * http://www.linksysinfo.org/index.php?threads/lighttpd-no-longer-starts-toastman-1-28-0510-7.73132/ */
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		use_sock_cloexec = 1;
		close(fd);
	}
      #endif

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
	case FDEVENT_HANDLER_POLL:
		if (0 != fdevent_poll_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler poll failed");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_SELECT:
		if (0 != fdevent_select_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler select failed");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_LINUX_SYSEPOLL:
		if (0 != fdevent_linux_sysepoll_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler linux-sysepoll failed, try to set server.event-handler = \"poll\" or \"select\"");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_SOLARIS_DEVPOLL:
		if (0 != fdevent_solaris_devpoll_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler solaris-devpoll failed, try to set server.event-handler = \"poll\" or \"select\"");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_SOLARIS_PORT:
		if (0 != fdevent_solaris_port_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler solaris-eventports failed, try to set server.event-handler = \"poll\" or \"select\"");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_FREEBSD_KQUEUE:
		if (0 != fdevent_freebsd_kqueue_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler freebsd-kqueue failed, try to set server.event-handler = \"poll\" or \"select\"");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_LIBEV:
		if (0 != fdevent_libev_init(ev)) {
			log_error_write(srv, __FILE__, __LINE__, "S",
				"event-handler libev failed, try to set server.event-handler = \"poll\" or \"select\"");
			goto error;
		}
		return ev;
	case FDEVENT_HANDLER_UNSET:
	default:
		break;
	}

error:
	free(ev->fdarray);
	free(ev);

	log_error_write(srv, __FILE__, __LINE__, "S",
		"event-handler is unknown, try to set server.event-handler = \"poll\" or \"select\"");
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
	if (ev->reset) return ev->reset(ev);

	return 0;
}

static fdnode *fdnode_init(void) {
	fdnode *fdn;

	fdn = calloc(1, sizeof(*fdn));
	force_assert(NULL != fdn);
	fdn->fd = -1;
	return fdn;
}

static void fdnode_free(fdnode *fdn) {
	free(fdn);
}

int fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx) {
	fdnode *fdn;

	fdn = fdnode_init();
	fdn->handler = handler;
	fdn->fd      = fd;
	fdn->ctx     = ctx;
	fdn->handler_ctx = NULL;
	fdn->events  = 0;

	ev->fdarray[fd] = fdn;

	return 0;
}

int fdevent_unregister(fdevents *ev, int fd) {
	fdnode *fdn;

	if (!ev) return 0;
	fdn = ev->fdarray[fd];
	if ((uintptr_t)fdn & 0x3) return 0; /*(should not happen)*/

	fdnode_free(fdn);

	ev->fdarray[fd] = NULL;

	return 0;
}

void fdevent_sched_close(fdevents *ev, int fd, int issock) {
	fdnode *fdn;
	if (!ev) return;
	fdn = ev->fdarray[fd];
	if ((uintptr_t)fdn & 0x3) return;
	ev->fdarray[fd] = (fdnode *)((uintptr_t)fdn | (issock ? 0x1 : 0x2));
	fdn->ctx = ev->pendclose;
	ev->pendclose = fdn;
}

void fdevent_sched_run(server *srv, fdevents *ev) {
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

void fdevent_event_del(fdevents *ev, int *fde_ndx, int fd) {
	if (-1 == fd) return;
	if ((uintptr_t)ev->fdarray[fd] & 0x3) return;

	if (ev->event_del) *fde_ndx = ev->event_del(ev, *fde_ndx, fd);
	ev->fdarray[fd]->events = 0;
}

void fdevent_event_set(fdevents *ev, int *fde_ndx, int fd, int events) {
	if (-1 == fd) return;

	/*(Note: skips registering with kernel if initial events is 0,
         * so caller should pass non-zero events for initial registration.
         * If never registered due to never being called with non-zero events,
         * then FDEVENT_HUP or FDEVENT_ERR will never be returned.) */
	if (ev->fdarray[fd]->events == events) return;/*(no change; nothing to do)*/

	if (ev->event_set) *fde_ndx = ev->event_set(ev, *fde_ndx, fd, events);
	ev->fdarray[fd]->events = events;
}

void fdevent_event_add(fdevents *ev, int *fde_ndx, int fd, int event) {
	int events;
	if (-1 == fd) return;

	events = ev->fdarray[fd]->events;
	if ((events & event) || 0 == event) return; /*(no change; nothing to do)*/

	events |= event;
	if (ev->event_set) *fde_ndx = ev->event_set(ev, *fde_ndx, fd, events);
	ev->fdarray[fd]->events = events;
}

void fdevent_event_clr(fdevents *ev, int *fde_ndx, int fd, int event) {
	int events;
	if (-1 == fd) return;

	events = ev->fdarray[fd]->events;
	if (!(events & event)) return; /*(no change; nothing to do)*/

	events &= ~event;
	if (ev->event_set) *fde_ndx = ev->event_set(ev, *fde_ndx, fd, events);
	ev->fdarray[fd]->events = events;
}

int fdevent_poll(fdevents *ev, int timeout_ms) {
	if (ev->poll == NULL) SEGFAULT();
	return ev->poll(ev, timeout_ms);
}

int fdevent_event_get_revent(fdevents *ev, size_t ndx) {
	if (ev->event_get_revent == NULL) SEGFAULT();

	return ev->event_get_revent(ev, ndx);
}

int fdevent_event_get_fd(fdevents *ev, size_t ndx) {
	if (ev->event_get_fd == NULL) SEGFAULT();

	return ev->event_get_fd(ev, ndx);
}

fdevent_handler fdevent_get_handler(fdevents *ev, int fd) {
	if (ev->fdarray[fd] == NULL) SEGFAULT();
	if ((uintptr_t)ev->fdarray[fd] & 0x3) return NULL;
	if (ev->fdarray[fd]->fd != fd) SEGFAULT();

	return ev->fdarray[fd]->handler;
}

void * fdevent_get_context(fdevents *ev, int fd) {
	if (ev->fdarray[fd] == NULL) SEGFAULT();
	if ((uintptr_t)ev->fdarray[fd] & 0x3) return NULL;
	if (ev->fdarray[fd]->fd != fd) SEGFAULT();

	return ev->fdarray[fd]->ctx;
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
	if (use_sock_cloexec)
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
	if (use_sock_cloexec)
		return socket(domain, type | SOCK_CLOEXEC | SOCK_NONBLOCK, protocol);
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

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

int fdevent_open_cloexec(const char *pathname, int flags, mode_t mode) {
#ifdef O_CLOEXEC
	return open(pathname, flags | O_CLOEXEC | O_NOCTTY, mode);
#else
	int fd = open(pathname, flags | O_NOCTTY, mode);
#ifdef FD_CLOEXEC
	if (fd != -1)
		force_assert(-1 != fcntl(fd, F_SETFD, FD_CLOEXEC));
#endif
	return fd;
#endif
}


int fdevent_open_devnull(void) {
  #if defined(_WIN32)
    return fdevent_open_cloexec("nul", O_RDWR, 0);
  #else
    return fdevent_open_cloexec("/dev/null", O_RDWR, 0);
  #endif
}


int fdevent_open_dirname(char *path) {
    /*(handle special cases of no dirname or dirname is root directory)*/
    char * const c = strrchr(path, '/');
    const char * const dname = (NULL != c ? c == path ? "/" : path : ".");
    int dfd;
    int flags = O_RDONLY;
  #ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
  #endif
    if (NULL != c) *c = '\0';
    dfd = fdevent_open_cloexec(dname, flags, 0);
    if (NULL != c) *c = '/';
    return dfd;
}


int fdevent_accept_listenfd(int listenfd, struct sockaddr *addr, size_t *addrlen) {
	int fd;
	socklen_t len = (socklen_t) *addrlen;

      #if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
       #if defined(__NetBSD__)
	fd = paccept(listenfd, addr, &len, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
       #else
	fd = (use_sock_cloexec)
	  ? accept4(listenfd, addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK)
	  : accept(listenfd, addr, &len);
       #endif
      #else
	fd = accept(listenfd, addr, &len);
      #endif

	if (fd >= 0) *addrlen = (size_t)len;
	return fd;
}


int fdevent_event_next_fdndx(fdevents *ev, int ndx) {
	if (ev->event_next_fdndx) return ev->event_next_fdndx(ev, ndx);

	return -1;
}


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


#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

int fdevent_open_logger(const char *logger) {
    if (logger[0] != '|') {
        int flags = O_APPEND | O_WRONLY | O_CREAT | O_LARGEFILE;
        return fdevent_open_cloexec(logger, flags, 0644);
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
