#ifndef _FDEVENT_H_
#define _FDEVENT_H_
#include "first.h"

#include "base_decls.h"

struct fdevents;        /* declaration */
typedef struct fdevents fdevents;

typedef handler_t (*fdevent_handler)(struct server *srv, void *ctx, int revents);

struct fdnode_st {
    fdevent_handler handler;
    void *ctx;
    int fd;
    int events;
    int fde_ndx;
  #ifdef HAVE_LIBEV
    void *handler_ctx;
  #endif
};

/* These must match POLL* values from operating system headers */

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
int fdevent_config(server *srv);

__attribute_cold__
const char * fdevent_show_event_handlers(void);

__attribute_cold__
fdevents *fdevent_init(struct server *srv);

__attribute_cold__
int fdevent_reset(fdevents *ev); /* "init" after fork() */

__attribute_cold__
void fdevent_free(fdevents *ev);

#define fdevent_fdnode_interest(fdn) (NULL != (fdn) ? (fdn)->events : 0)
void fdevent_fdnode_event_del(fdevents *ev, fdnode *fdn);
void fdevent_fdnode_event_set(fdevents *ev, fdnode *fdn, int events);
void fdevent_fdnode_event_add(fdevents *ev, fdnode *fdn, int event);
void fdevent_fdnode_event_clr(fdevents *ev, fdnode *fdn, int event);

int fdevent_poll(fdevents *ev, int timeout_ms);

fdnode * fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx);
void fdevent_unregister(fdevents *ev, int fd);
void fdevent_sched_close(fdevents *ev, int fd, int issock);

void fdevent_setfd_cloexec(int fd);
void fdevent_clrfd_cloexec(int fd);
int fdevent_fcntl_set_nb(fdevents *ev, int fd);
int fdevent_fcntl_set_nb_cloexec(fdevents *ev, int fd);
int fdevent_fcntl_set_nb_cloexec_sock(fdevents *ev, int fd);
int fdevent_socket_cloexec(int domain, int type, int protocol);
int fdevent_socket_nb_cloexec(int domain, int type, int protocol);
int fdevent_open_cloexec(const char *pathname, int symlinks, int flags, mode_t mode);
int fdevent_mkstemp_append(char *path);

struct sockaddr;
int fdevent_accept_listenfd(int listenfd, struct sockaddr *addr, size_t *addrlen);

char ** fdevent_environ(void);
int fdevent_open_devnull(void);
int fdevent_open_dirname(char *path, int symlinks);
int fdevent_set_stdin_stdout_stderr(int fdin, int fdout, int fderr);
pid_t fdevent_fork_execve(const char *name, char *argv[], char *envp[], int fdin, int fdout, int fderr, int dfd);
int fdevent_open_logger(const char *logger);
int fdevent_cycle_logger(const char *logger, int *curfd);
int fdevent_reaped_logger_pipe(pid_t pid);
int fdevent_waitpid_logger_pipe_pid(pid_t pid, time_t ts);
void fdevent_restart_logger_pipes(time_t ts);
void fdevent_close_logger_pipes(void);
void fdevent_breakagelog_logger_pipe(int fd);
void fdevent_clr_logger_pipe_pids(void);

ssize_t fdevent_socket_read_discard (int fd, char *buf, size_t sz, int family, int so_type);

int fdevent_ioctl_fionread (int fd, int fdfmt, int *toread);

int fdevent_connect_status(int fd);

/* fd must be TCP socket (AF_INET, AF_INET6), end-of-stream recv() 0 bytes */
int fdevent_is_tcp_half_closed(int fd);
int fdevent_set_tcp_nodelay (const int fd, const int opt);

int fdevent_set_so_reuseaddr (const int fd, const int opt);

#endif
