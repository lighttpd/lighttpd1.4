#ifndef _FDEVENT_H_
#define _FDEVENT_H_
#include "first.h"

#include "base_decls.h" /* handler_t */

struct fdevents;        /* declaration */
typedef struct fdevents fdevents;

typedef handler_t (*fdevent_handler)(void *ctx, int revents);

struct fdnode_st {
    fdevent_handler handler;
    void *ctx;
    int fd;
    int events;
    int fde_ndx;
  #ifdef _WIN32
    int fda_ndx;
  #endif
};

/* These must match POLL* values from operating system headers */

#ifdef _WIN32 /* MS is different; definitely not better */
#define FDEVENT_IN     (0x0100 | 0x0200)
#define FDEVENT_PRI    (0x0400)
#define FDEVENT_OUT    (0x0010)
#define FDEVENT_ERR    (0x0001)
#define FDEVENT_HUP    (0x0002)
#define FDEVENT_NVAL   (0x0004)
#define FDEVENT_RDHUP  0x2000
#else
#define FDEVENT_IN     0x0001
#define FDEVENT_PRI    0x0002
#define FDEVENT_OUT    0x0004
#define FDEVENT_ERR    0x0008
#define FDEVENT_HUP    0x0010
#define FDEVENT_NVAL   0x0020
#if defined(__sun) && defined(__SVR4) /* Solaris */
#define FDEVENT_RDHUP  0x4000
#else
#define FDEVENT_RDHUP  0x2000
#endif
#endif

#define FDEVENT_STREAM_REQUEST                  BV(0)
#define FDEVENT_STREAM_REQUEST_BUFMIN           BV(1)
#define FDEVENT_STREAM_REQUEST_POLLRDHUP        BV(12)
#define FDEVENT_STREAM_REQUEST_TCP_FIN          BV(13)
#define FDEVENT_STREAM_REQUEST_BACKEND_SHUT_WR  BV(14)
#define FDEVENT_STREAM_REQUEST_POLLIN           BV(15)

#define FDEVENT_STREAM_RESPONSE           BV(0)
#define FDEVENT_STREAM_RESPONSE_BUFMIN    BV(1)
#define FDEVENT_STREAM_RESPONSE_POLLRDHUP BV(15)

__attribute_cold__
int fdevent_config(const char **event_handler_name, log_error_st *errh);

__attribute_cold__
__attribute_const__
__attribute_returns_nonnull__
const char * fdevent_show_event_handlers(void);

__attribute_cold__
fdevents * fdevent_init(const char *event_handler, int *max_fds, int *cur_fds, log_error_st *errh);

__attribute_cold__
int fdevent_reset(fdevents *ev); /* "init" after fork() */

__attribute_cold__
void fdevent_free(fdevents *ev);

__attribute_cold__
void fdevent_socket_nb_cloexec_init(void);

#define fdevent_fdnode_interest(fdn) (NULL != (fdn) ? (fdn)->events : 0)
void fdevent_fdnode_event_del(fdevents *ev, fdnode *fdn);
void fdevent_fdnode_event_set(fdevents *ev, fdnode *fdn, int events);
void fdevent_fdnode_event_add(fdevents *ev, fdnode *fdn, int event);
void fdevent_fdnode_event_clr(fdevents *ev, fdnode *fdn, int event);

int fdevent_poll(fdevents *ev, int timeout_ms);

__attribute_returns_nonnull__
fdnode * fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx);

void fdevent_unregister(fdevents *ev, fdnode *fdn);
void fdevent_sched_close(fdevents *ev, fdnode *fdn);

void fdevent_setfd_cloexec(int fd);
void fdevent_clrfd_cloexec(int fd);
int fdevent_fcntl_set_nb(int fd);
int fdevent_fcntl_set_nb_cloexec(int fd);
int fdevent_fcntl_set_nb_cloexec_sock(int fd);
int fdevent_socket_cloexec(int domain, int type, int protocol);
int fdevent_socket_nb_cloexec(int domain, int type, int protocol);
int fdevent_socketpair_cloexec(int domain, int typ, int protocol, int sv[2]);
int fdevent_socketpair_nb_cloexec(int domain, int typ, int protocol, int sv[2]);
int fdevent_dup_cloexec(int fd);
int fdevent_open_cloexec(const char *pathname, int symlinks, int flags, mode_t mode);
int fdevent_pipe_cloexec (int *fds, unsigned int bufsz_hint);
int fdevent_mkostemp(char *path, int flags);
int fdevent_rename(const char *oldpath, const char *newpath);

struct sockaddr;
int fdevent_accept_listenfd(int listenfd, struct sockaddr *addr, size_t *addrlen);

__attribute_pure__
char ** fdevent_environ(void);

int fdevent_open_devnull(void);
int fdevent_open_dirname(char *path, int symlinks);
#ifndef _WIN32
int fdevent_set_stdin_stdout_stderr(int fdin, int fdout, int fderr);
pid_t fdevent_fork_execve(const char *name, char *argv[], char *envp[], int fdin, int fdout, int fderr, int dfd);
pid_t fdevent_sh_exec(const char *cmdstr, char *envp[], int fdin, int fdout, int fderr);
#endif
pid_t fdevent_waitpid(pid_t pid, int *status, int nb);
pid_t fdevent_waitpid_intr(pid_t pid, int *status);
int fdevent_kill(pid_t pid, int sig);

#ifdef _WIN32
__attribute_cold__
void fdevent_win32_cleanup (void);
#define fdevent_fork_execve(name, argv, envp, fdin, fdout, fderr, dfd) \
        fdevent_createprocess((argv),(envp),(fdin),(fdout),(fderr),(dfd))
pid_t fdevent_sh_exec(const char *cmdstr, char *envp[], intptr_t fdin, intptr_t fdout, int fderr);
pid_t fdevent_createprocess(char *argv[], char *envp[], intptr_t fdin, intptr_t fdout, int fderr, int dfd);
#endif /* _WIN32 */

#define fdio_close_dirfd(fd) close(fd)
#define fdio_close_file(fd) close(fd)
#define fdio_close_pipe(fd) close(fd)
#define fdio_close_socket(fd) fdevent_socket_close(fd)
#ifdef _WIN32
int fdevent_socket_set_cloexec(int fd);
int fdevent_socket_clr_cloexec(int fd);
int fdevent_socket_set_nb(int fd);
int fdevent_socket_set_nb_cloexec(int fd);
#else
#define fdevent_socket_set_cloexec(fd)    (fdevent_setfd_cloexec(fd), 0)
#define fdevent_socket_clr_cloexec(fd)    (fdevent_clrfd_cloexec(fd), 0)
#define fdevent_socket_set_nb(fd)         fdevent_fcntl_set_nb(fd)
#define fdevent_socket_set_nb_cloexec(fd) fdevent_fcntl_set_nb_cloexec(fd)
#endif
int fdevent_socket_close (int fd);
ssize_t fdevent_socket_read_discard (int fd, char *buf, size_t sz, int family, int so_type);

int fdevent_ioctl_fionread (int fd, int fdfmt, int *toread);

int fdevent_connect_status(int fd);

/* fd must be TCP socket (AF_INET, AF_INET6), end-of-stream recv() 0 bytes */
int fdevent_is_tcp_half_closed(int fd);
int fdevent_set_tcp_nodelay (const int fd, const int opt);

int fdevent_set_so_reuseaddr (const int fd, const int opt);

char * fdevent_load_file (const char * const fn, off_t *lim, log_error_st *errh, void *(malloc_fn)(size_t), void(free_fn)(void *));

int fdevent_load_file_bytes (char *buf, off_t sz, off_t off, const char *fn, log_error_st *errh);

#endif
