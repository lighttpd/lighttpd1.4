#ifndef _FDEVENT_H_
#define _FDEVENT_H_
#include "first.h"

#include "base_decls.h"
#include "settings.h"   /* (handler_t) */

struct fdevents;        /* declaration */
typedef struct fdevents fdevents;

typedef handler_t (*fdevent_handler)(struct server *srv, void *ctx, int revents);

/* these are the POLL* values from <bits/poll.h> (linux poll)
 */

#define FDEVENT_IN     BV(0)
#define FDEVENT_PRI    BV(1)
#define FDEVENT_OUT    BV(2)
#define FDEVENT_ERR    BV(3)
#define FDEVENT_HUP    BV(4)
#define FDEVENT_NVAL   BV(5)
#define FDEVENT_RDHUP  BV(13)

#define FDEVENT_STREAM_REQUEST          BV(0)
#define FDEVENT_STREAM_REQUEST_BUFMIN   BV(1)
#define FDEVENT_STREAM_REQUEST_POLLIN   BV(15)

#define FDEVENT_STREAM_RESPONSE         BV(0)
#define FDEVENT_STREAM_RESPONSE_BUFMIN  BV(1)

int fdevent_config(server *srv);
const char * fdevent_show_event_handlers(void);
fdevents *fdevent_init(struct server *srv);
int fdevent_reset(fdevents *ev); /* "init" after fork() */
void fdevent_free(fdevents *ev);

int fdevent_event_get_interest(const fdevents *ev, int fd);
void fdevent_event_set(fdevents *ev, int *fde_ndx, int fd, int events); /* events can be FDEVENT_IN, FDEVENT_OUT or FDEVENT_IN | FDEVENT_OUT */
void fdevent_event_add(fdevents *ev, int *fde_ndx, int fd, int event); /* events can be FDEVENT_IN or FDEVENT_OUT */
void fdevent_event_clr(fdevents *ev, int *fde_ndx, int fd, int event); /* events can be FDEVENT_IN or FDEVENT_OUT */
void fdevent_event_del(fdevents *ev, int *fde_ndx, int fd);
int fdevent_event_get_revent(fdevents *ev, size_t ndx);
int fdevent_event_get_fd(fdevents *ev, size_t ndx);
fdevent_handler fdevent_get_handler(fdevents *ev, int fd);
void * fdevent_get_context(fdevents *ev, int fd);

int fdevent_event_next_fdndx(fdevents *ev, int ndx);

int fdevent_poll(fdevents *ev, int timeout_ms);

int fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx);
int fdevent_unregister(fdevents *ev, int fd);
void fdevent_sched_close(fdevents *ev, int fd, int issock);
void fdevent_sched_run(struct server *srv, fdevents *ev);

void fdevent_setfd_cloexec(int fd);
void fdevent_clrfd_cloexec(int fd);
int fdevent_fcntl_set_nb(fdevents *ev, int fd);
int fdevent_fcntl_set_nb_cloexec(fdevents *ev, int fd);
int fdevent_fcntl_set_nb_cloexec_sock(fdevents *ev, int fd);
int fdevent_socket_cloexec(int domain, int type, int protocol);
int fdevent_socket_nb_cloexec(int domain, int type, int protocol);
int fdevent_open_cloexec(const char *pathname, int flags, mode_t mode);

struct sockaddr;
int fdevent_accept_listenfd(int listenfd, struct sockaddr *addr, size_t *addrlen);

int fdevent_open_devnull(void);
int fdevent_open_dirname(char *path);
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
