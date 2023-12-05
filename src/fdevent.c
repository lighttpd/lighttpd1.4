#include "first.h"

#include "fdevent.h"

#include <sys/types.h>
#include "sys-socket.h"
#include "sys-unistd.h" /* <unistd.h> */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "ck.h"
#define force_assert(x) ck_assert(x)

#ifndef _WIN32

#ifdef SOCK_CLOEXEC
static int use_sock_cloexec;
#endif
#ifdef SOCK_NONBLOCK
static int use_sock_nonblock;
#endif

void fdevent_socket_nb_cloexec_init (void)
{
      #ifdef SOCK_CLOEXEC
	if (use_sock_cloexec) return; /* init once (if successful) */
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

#if 0 /* not used */

int fdevent_socketpair_cloexec (int domain, int typ, int protocol, int sv[2])
{
    sv[0] = sv[1] = -1;
  #if defined(SOCK_CLOEXEC)
    return socketpair(domain, typ | SOCK_CLOEXEC, protocol, sv);
  #else
    if (0 == socketpair(domain, typ, protocol, sv)) {
        if (0 == fdevent_socket_set_cloexec(sv[0])
         && 0 == fdevent_socket_set_cloexec(sv[1]))
            return 0;

        close(sv[0]);
        close(sv[1]);
        sv[0] = sv[1] = -1;
    }
    return -1;
  #endif
}

int fdevent_socketpair_nb_cloexec (int domain, int typ, int protocol, int sv[2])
{
    sv[0] = sv[1] = -1;
  #if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    return socketpair(domain, typ | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol, sv);
  #else
    if (0 == socketpair(domain, typ, protocol, sv)) {
        if (0 == fdevent_socket_set_nb_cloexec(sv[0])
         && 0 == fdevent_socket_set_nb_cloexec(sv[1]))
            return 0;

        close(sv[0]);
        close(sv[1]);
        sv[0] = sv[1] = -1;
    }
    return -1;
  #endif
}

#endif /* not used */

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
  #if defined(__sun) /* /dev/null is a symlink on Illumos */
    return fdevent_open_cloexec("/dev/null", 1, O_RDWR, 0);
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


int fdevent_pipe_cloexec (int * const fds, const unsigned int bufsz_hint) {
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
}


int fdevent_socket_close(int fd) {
    return close(fd);
}


int fdevent_mkostemp(char *path, int flags) {
 #if defined(HAVE_MKOSTEMP)
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


/* accept4() added in Linux x86 in kernel 2.6.28, but not in arm until 2.6.36
 * https://lwn.net/Articles/789961/ */
#if defined(__linux__) \
 && (defined(__arm__) || defined(__thumb__) || defined(__arm64__))
#ifdef __has_include
#if __has_include(<sys/syscall.h>)
#include <sys/syscall.h>
#endif
#endif
#ifndef SYS_accept4
#define accept4(a,b,c,d) ((errno = ENOTSUP), -1)
#endif
#endif

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


/* iOS does not allow subprocess creation; avoid compiling advanced interfaces*/
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h> /* TARGET_OS_IPHONE, TARGET_OS_MAC */
#if TARGET_OS_IPHONE            /* iOS, tvOS, or watchOS device */
#undef HAVE_POSIX_SPAWN
#endif
#endif


#include <stdio.h>      /* perror() rename() */
#include <signal.h>     /* signal() kill() */
#ifdef HAVE_POSIX_SPAWN
#include <spawn.h>      /* posix_spawn*() */
#endif


int fdevent_rename(const char *oldpath, const char *newpath) {
    return rename(oldpath, newpath);
}


#ifdef HAVE_POSIX_SPAWN
#if !defined(HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP) \
 && defined(POSIX_SPAWN_CLOEXEC_DEFAULT) /* Mac OS */
__attribute_noinline__
static int fdevent_cloexec_default_prep (posix_spawn_file_actions_t *file_actions, int fd, int stdfd) {
    /* (other file actions already prepped in caller,
     *  so ok to dup2() and overwrite 3+stdfd) */
    int rc;
    if (fd < 0) fd = stdfd;
    rc = posix_spawn_file_actions_adddup2(file_actions, fd, 3+stdfd);
    if (0 != rc) return rc;
    rc = posix_spawn_file_actions_adddup2(file_actions, 3+stdfd, stdfd);
    if (0 != rc) return rc;
    rc = posix_spawn_file_actions_addclose(file_actions, 3+stdfd);
    return rc;
}
#endif
#endif


pid_t fdevent_fork_execve(const char *name, char *argv[], char *envp[], int fdin, int fdout, int fderr, int dfd) {
 #ifdef HAVE_POSIX_SPAWN

    /* Caller must ensure that all fd* args are >= 3, i.e. > STDERR_FILENO (2),
     * unless fd* arg is -1, in which case we preserve existing target fd, or
     * unless fd does not have FD_CLOEXEC set *and* is not being replaced,
     * e.g. if fd 1 is open to /dev/null and fdout is -1 and fderr is 1 so
     * that fd 1 (STDOUT_FILENO) to /dev/null is dup2() to fd 2 (STDERR_FILENO).
     * Caller must handle so that if any dup() is required to make fd* >= 3,
     * then the caller has access to the new fds.  The reason fd* args >= 3
     * is required is that we set FD_CLOEXEC on all fds (thread-safety) and
     * a dup2() in child is used for dup2() side effect of removing FD_CLOEXEC.
     * (posix_spawn() provides posix_spawn_file_actions_adddup2() whereas
     *  it does not provide a means to use fcntl() to remove FD_CLOEXEC) */

    sigset_t sigs;
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_t attr;
    int rc;
    pid_t pid = -1;
    if (0 != (rc = posix_spawn_file_actions_init(&file_actions)))
        return pid;
    if (0 != (rc = posix_spawnattr_init(&attr))) {
        posix_spawn_file_actions_destroy(&file_actions);
        return pid;
    }
    if (   0 == (rc = (fdin  >= 0)
                    ? posix_spawn_file_actions_adddup2(
                        &file_actions, fdin,  STDIN_FILENO)
                    : 0)
        && 0 == (rc = (fdout >= 0)
                    ? posix_spawn_file_actions_adddup2(
                        &file_actions, fdout, STDOUT_FILENO)
                    : 0)
        && 0 == (rc = (fderr >= 0)
                    ? posix_spawn_file_actions_adddup2(
                        &file_actions, fderr, STDERR_FILENO)
                    : 0)
       #ifdef HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDFCHDIR_NP
        && 0 == (rc = (-1 != dfd)
                    ? posix_spawn_file_actions_addfchdir_np(
                        &file_actions, dfd)
                    : 0)
       #endif
       #ifdef HAVE_POSIX_SPAWNATTR_SETCWD_NP /* (QNX Neutrino 7.1 or later) */
        && 0 == (rc = posix_spawnattr_setcwd_np(&attr, dfd))
        && 0 == (rc = posix_spawnattr_setxflags(&spawnattr,
                                                  POSIX_SPAWN_SETCWD
                                                | POSIX_SPAWN_SETSIGDEF
                                                | POSIX_SPAWN_SETSIGMASK))
       #else
        && 0 == (rc = posix_spawnattr_setflags(
                        &attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))
       #endif
        && 0 == (rc = sigemptyset(&sigs))
        && 0 == (rc = posix_spawnattr_setsigmask(&attr, &sigs))
      #if defined(__GLIBC__) \
       && (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 24 && __GLIBC_MINOR__ <= 37)
        /* glibc appears to walk all signals and to query and preserve some
         * sigaction flags even if setting to SIG_DFL, though if specified
         * in posix_spawnattr_setsigdefault(), resets to SIG_DFL without query.
         * Therefore, resetting all signals results in about 1/2 the syscalls.*/
        && 0 == (rc = sigfillset(&sigs))
      #else
        /*(force reset signals to SIG_DFL if server.c set to SIG_IGN)*/
       #ifdef SIGTTOU
        && 0 == (rc = sigaddset(&sigs, SIGTTOU))
       #endif
       #ifdef SIGTTIN
        && 0 == (rc = sigaddset(&sigs, SIGTTIN))
       #endif
       #ifdef SIGTSTP
        && 0 == (rc = sigaddset(&sigs, SIGTSTP))
       #endif
        && 0 == (rc = sigaddset(&sigs, SIGPIPE))
        && 0 == (rc = sigaddset(&sigs, SIGUSR1))
      #endif
        && 0 == (rc = posix_spawnattr_setsigdefault(&attr, &sigs))) {

          #if defined(HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP) \
           || defined(POSIX_SPAWN_CLOEXEC_DEFAULT) /* Mac OS */
            /* optional: potentially improve performance when many fds open
             * (might create new file descriptor table containing only 0,1,2
             *  instead of close() on all other fds with O_CLOEXEC flag set)
             * optional: disable manually and externally via gdb or other
             *   debugger by setting trace_children to non-zero value */
            static volatile sig_atomic_t trace_children;
            if (!trace_children) {
              #ifdef HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDCLOSEFROM_NP
                posix_spawn_file_actions_addclosefrom_np(&file_actions, 3);
              #elif defined(POSIX_SPAWN_CLOEXEC_DEFAULT) /* Mac OS */
                /* Apple: this workaround should not be necessary.
                 * Please implement posix_spawn_file_actions_addclosefrom_np()*/
                if (fdin  < 3) /* <= STDERR_FILENO */
                    rc |= fdevent_cloexec_default_prep(&file_actions,
                                                       fdin,  STDIN_FILENO);
                if (fdout < 3) /* <= STDERR_FILENO */
                    rc |= fdevent_cloexec_default_prep(&file_actions,
                                                       fdout, STDOUT_FILENO);
                if (fderr < 3) /* <= STDERR_FILENO */
                    rc |= fdevent_cloexec_default_prep(&file_actions,
                                                       fderr, STDERR_FILENO);
                /* (not expecting any failures above and these are on fds that
                 *  are inherited, so not cleaning up excess fds from previous
                 *  adddup2 if any error occurs in this block) */
                if (0 == rc)
                    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT
                                                  | POSIX_SPAWN_SETSIGDEF
                                                  | POSIX_SPAWN_SETSIGMASK);
                rc = 0;
              #endif
            }
          #endif

          #if !defined(HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDFCHDIR_NP) \
           && !defined(HAVE_POSIX_SPAWNATTR_SETCWD_NP)
            /* not thread-safe, but ok since lighttpd not (currently) threaded
             * (alternatively, check HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDFCHDIR_NP
             *  along with HAVE_POSIX_SPAWN at top of block and use HAVE_FORK
             *  below if HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDFCHDIR_NP not avail)*/
            if (-1 != dfd) {
                int ndfd = dfd;
                dfd = fdevent_open_dirname(".", 1); /* reuse dfd for cwd fd */
                if (-1 == dfd || 0 != fchdir(ndfd))
                    rc = -1; /*(or could set to errno for posix consistency)*/
            }
            if (0 == rc)
          #endif

                 rc = posix_spawn(&pid, name, &file_actions, &attr,
                                  argv, envp ? envp : environ);

            if (0 != rc)
                pid = -1;

          #if !defined(HAVE_POSIX_SPAWN_FILE_ACTIONS_ADDFCHDIR_NP) \
           && !defined(HAVE_POSIX_SPAWNATTR_SETCWD_NP)
            if (-1 != dfd) {
                if (0 != fchdir(dfd)) { /* ignore error; best effort */
                    /*rc = errno;*/
                }
                close(dfd);
            }
          #endif
    }
    posix_spawn_file_actions_destroy(&file_actions);
    posix_spawnattr_destroy(&attr);
    return pid;

 #elif defined(HAVE_FORK)

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
    signal(SIGUSR1, SIG_DFL);

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


/* Check if cmd string can bypass shell expansion
 *
 * Commands in lighttpd.conf are trusted; lighttpd.conf is controlled by admin.
 * As an optimization, skip running command via "/bin/sh -c ..." if the command
 * begins with '/' and does not contain shell metacharacters which might need
 * to be interpretted by the shell.  Assume that IFS is set to shell defaults.
 * Allows 8-bit UTF-8, but does not validate UTF-8.  Does not flag CTL
 * characters besides IFS defaults.  cmd must be '\0'-terminated.
 *
 * An alternative approach could pass cmd through wordexp() using WRDE_NOCMD
 * and compare input cmd to match wordexp() output, if single word returned.
 * Another alternative would be to prepend <cmd> with "exec <cmd>" on stack
 * to try to have the shell 'exec' the result of shell expansion (if cmd did
 * not already begin with "exec ").
 *
 * For portability with older systems without wordexp(), instead use strcspn()
 * on list of known characters which might be processed during shell expansion.
 * With the goal of correctness, err on side of continuing to call the shell
 * rather than potentially incorrectly skipping shell expansion.
 *
 * Allow %+,-./:=_~^@ and alphanumeric, as well as 8-bit for UTF-8.
 * Tilde '~' allowed since not first char, as first char is checked to be '/'.
 * Equal '=' allowed since string is checked to contain no whitespace, so no
 * variable assignment preceding command.
 */
#define fdevent_cmd_might_bypass_shell_expansion(cmd) \
  (*cmd == '/' && (cmd)[strcspn((cmd), "\t\n !\"#$&'()*;<>?[\\]`{|}")] == '\0')

__attribute_cold__
pid_t fdevent_sh_exec(const char *cmdstr, char *envp[], int fdin, int fdout, int fderr) {
    char *args[4];
    if (fdevent_cmd_might_bypass_shell_expansion(cmdstr)) {
        *(const char **)&args[0] = cmdstr;
        args[1] = NULL;
    }
    else {
        const char *shell = getenv("SHELL");
        if (shell && (0 == strcmp(shell, "/usr/bin/false")
                      || 0 == strcmp(shell, "/bin/false")))
            shell = NULL;
        *(const char **)&args[0] = shell ? shell : "/bin/sh";
        *(const char **)&args[1] = "-c";
        *(const char **)&args[2] = cmdstr;
        args[3] = NULL;
    }

    return fdevent_fork_execve(args[0], args, envp, fdin, fdout, fderr, -1);
}


int fdevent_kill (pid_t pid, int sig) {
    return kill(pid, sig);
}


#include "sys-wait.h"

pid_t fdevent_waitpid(pid_t pid, int * const status, int nb) {
    const int flags = nb ? WNOHANG : 0;
    pid_t rv;
    do { rv = waitpid(pid, status, flags); } while (-1 == rv && errno == EINTR);
    return rv;
}

pid_t fdevent_waitpid_intr(pid_t pid, int * const status) {
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
int fdevent_ioctl_fionread (int fd, int fdfmt, int *toread) {
   #ifdef __CYGWIN__
    /*(cygwin supports FIONREAD on pipes, not sockets)*/
    if (fdfmt != S_IFIFO) { errno = EOPNOTSUPP; return -1; }
   #else
    UNUSED(fdfmt);
   #endif
    return ioctl(fd, FIONREAD, toread);
}


int fdevent_connect_status(int fd) {
    /* try to finish the connect() */
    /*(should be called after connect() only when fd is writable (POLLOUT))*/
    int opt;
    socklen_t len = sizeof(opt);
    return (0 == getsockopt(fd,SOL_SOCKET,SO_ERROR,&opt,&len)) ? opt : errno;
}

#endif /* !_WIN32 */


#ifndef _WIN32
#include <netinet/tcp.h>
#endif
#if  defined(__FreeBSD__) || defined(__NetBSD__) \
  || defined(__OpenBSD__) || defined(__DragonFly__)
#include <netinet/tcp_fsm.h>
#endif
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h> /* TARGET_OS_IPHONE, TARGET_OS_MAC */
#if TARGET_OS_IPHONE            /* iOS, tvOS, or watchOS device */
/*#define TCPS_CLOSE_WAIT 5*/   /* ??? which header contains this, if any ??? */
#elif TARGET_OS_MAC             /* MacOS */
#include <netinet/tcp_fsm.h>
#endif
#endif

/* fd must be TCP socket (AF_INET, AF_INET6), end-of-stream recv() 0 bytes */
int fdevent_is_tcp_half_closed(int fd) {
  #ifdef TCP_CONNECTION_INFO     /* Darwin */
    struct tcp_connection_info tcpi;
    socklen_t tlen = sizeof(tcpi);
    return (0 == getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &tcpi, &tlen)
            && tcpi.tcpi_state == TCPS_CLOSE_WAIT);
  #elif defined(TCP_INFO) && defined(TCPS_CLOSE_WAIT)
    /* FreeBSD, NetBSD, OpenBSD (not present in DragonFlyBSD) */
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


#include "sys-stat.h"
#include "ck.h"
#include "log.h"
__attribute_cold__ /*(convenience routine for use at config at startup)*/
char *
fdevent_load_file (const char * const fn, off_t *lim, log_error_st *errh, void *(malloc_fn)(size_t), void(free_fn)(void *))
{
    int fd;
    off_t sz = 0;
    char *buf = NULL;
    do {
      #if 0
        /* /dev/fd/ and /proc/self/fd/ might be special-cased, but then would
         * be close()d at end of func before returning.  Then again, that might
         * be desirable since otherwise those fds do not have FD_CLOEXEC set. */
        fd = 0 == memcmp(fn, "/dev/fd/", sizeof("/dev/fd/")-1)
           ? atoi(fn + sizeof("/dev/fd/")-1)
           : 0 == memcmp(fn, "/proc/self/fd/", sizeof("/proc/self/fd/")-1)
           ? atoi(fn + sizeof("/proc/self/fd/")-1)
           : fdevent_open_cloexec(fn, 1, O_RDONLY, 0); /*(1: follows symlinks)*/
      #else
        fd = (0 != strcmp(fn, "/dev/stdin"))
           ? fdevent_open_cloexec(fn, 1, O_RDONLY, 0)  /*(1: follows symlinks)*/
           : STDIN_FILENO;
      #endif
        if (fd < 0) break;

        struct stat st;
        if (0 != fstat(fd, &st)) break;
        if (S_ISREG(st.st_mode)) {
            sz = st.st_size;
            if ((sizeof(off_t) > sizeof(size_t) && sz >= (off_t)~(size_t)0u)
                || (*lim != 0 && sz >= *lim)) {
                errno = EOVERFLOW;
                break;
            }
            buf = malloc_fn((size_t)sz+1); /* +1 trailing '\0' for str funcs */
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
        }
        else {
            /* attempt to read from non-regular file
             * e.g. FIFO/pipe from shell HERE doc (turns into e.g. "/dev/fd/63")
             * Note: read() might block! */
          #ifndef _WIN32
          #ifdef O_NONBLOCK
            /*(else read() might err EAGAIN Resource temporarily unavailable)*/
            if (fcntl(fd, F_SETFL, (O_RDONLY|FDEVENT_O_FLAGS) & ~O_NONBLOCK)) {}
            /*(ignore fcntl() error; not expected and detected later if err)*/
          #endif
          #endif
            ssize_t rd;
            off_t bsz = 0;
            if (*lim == 0)
                *lim = 32*1024*1024; /* set arbitrary limit, if not specified */
            do {
                if (bsz <= sz+2) {
                    if (bsz >= *lim) { rd = -1; errno = EOVERFLOW; break; }
                    bsz = bsz ? (bsz << 1) : 65536;
                    if (bsz > *lim) bsz = *lim;
                    char *nbuf = malloc_fn((size_t)bsz);
                    if (NULL == nbuf) { rd = -1; break; }
                    if (buf) {
                        memcpy(nbuf, buf, sz);
                        ck_memzero(buf, (size_t)sz);
                        free_fn(buf);
                    }
                    buf = nbuf;
                }
                rd = read(fd, buf+sz, (size_t)(bsz-sz-1));
            } while (rd > 0 ? (sz += rd) : rd < 0 && errno == EINTR);
            if (rd != 0) break;
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
