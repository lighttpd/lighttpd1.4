#ifndef INCLUDED_FDEVENT_IMPL_H
#define INCLUDED_FDEVENT_IMPL_H
#include "first.h"

/* select event-system */

#if defined(HAVE_EPOLL_CTL) && defined(HAVE_SYS_EPOLL_H)
# define FDEVENT_USE_LINUX_EPOLL
struct epoll_event;     /* declaration */
#endif

/* MacOS 10.3.x has poll.h under /usr/include/, all other unixes
 * under /usr/include/sys/ */
#if defined HAVE_POLL && (defined(HAVE_SYS_POLL_H) || defined(HAVE_POLL_H))
# define FDEVENT_USE_POLL
struct pollfd;          /* declaration */
#endif

#if defined HAVE_SELECT
# ifdef __WIN32
#  include <winsock2.h>
# endif
# define FDEVENT_USE_SELECT
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# endif
#endif

#if defined HAVE_SYS_DEVPOLL_H && defined(__sun)
# define FDEVENT_USE_SOLARIS_DEVPOLL
struct pollfd;          /* declaration */
#endif

#if defined HAVE_PORT_H && defined HAVE_PORT_CREATE && defined(__sun)
# define FDEVENT_USE_SOLARIS_PORT
# include <port.h>
#endif

#if defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
# define FDEVENT_USE_FREEBSD_KQUEUE
struct kevent;          /* declaration */
#endif

#if defined HAVE_LIBEV
# define FDEVENT_USE_LIBEV
struct ev_loop;         /* declaration */
#endif

#include "base_decls.h"
#include "fdevent.h"    /* (*fdevent_handler) */

typedef enum {
    FDEVENT_HANDLER_UNSET,
    FDEVENT_HANDLER_SELECT,
    FDEVENT_HANDLER_POLL,
    FDEVENT_HANDLER_LINUX_SYSEPOLL,
    FDEVENT_HANDLER_SOLARIS_DEVPOLL,
    FDEVENT_HANDLER_SOLARIS_PORT,
    FDEVENT_HANDLER_FREEBSD_KQUEUE,
    FDEVENT_HANDLER_LIBEV
} fdevent_handler_t;

/**
 * array of unused fd's
 *
 */

#ifdef FDEVENT_USE_POLL
typedef struct {
    int *ptr;

    size_t used;
    size_t size;
} buffer_int;
#endif

struct fdevents {
    fdnode **fdarray;
    fdnode *pendclose;

    int (*event_set)(struct fdevents *ev, fdnode *fdn, int events);
    int (*event_del)(struct fdevents *ev, fdnode *fdn);
    int (*poll)(struct fdevents *ev, int timeout_ms);

    struct server *srv;
    size_t maxfds;
  #ifdef FDEVENT_USE_LINUX_EPOLL
    int epoll_fd;
    struct epoll_event *epoll_events;
  #endif
  #ifdef FDEVENT_USE_SOLARIS_DEVPOLL
    int devpoll_fd;
    struct pollfd *devpollfds;
  #endif
  #ifdef FDEVENT_USE_SOLARIS_PORT
    int port_fd;
    port_event_t *port_events;
  #endif
  #ifdef FDEVENT_USE_FREEBSD_KQUEUE
    int kq_fd;
    struct kevent *kq_results;
  #endif
  #ifdef FDEVENT_USE_LIBEV
    struct ev_loop *libev_loop;
  #endif
  #ifdef FDEVENT_USE_POLL
    struct pollfd *pollfds;

    size_t size;
    size_t used;

    buffer_int unused;
  #endif
  #ifdef FDEVENT_USE_SELECT
    fd_set select_read;
    fd_set select_write;
    fd_set select_error;

    fd_set select_set_read;
    fd_set select_set_write;
    fd_set select_set_error;

    int select_max_fd;
  #endif

    int (*reset)(struct fdevents *ev);
    void (*free)(struct fdevents *ev);
    fdevent_handler_t type;
};

__attribute_cold__
int fdevent_select_init(struct fdevents *ev);
__attribute_cold__
int fdevent_poll_init(struct fdevents *ev);
__attribute_cold__
int fdevent_linux_sysepoll_init(struct fdevents *ev);
__attribute_cold__
int fdevent_solaris_devpoll_init(struct fdevents *ev);
__attribute_cold__
int fdevent_solaris_port_init(struct fdevents *ev);
__attribute_cold__
int fdevent_freebsd_kqueue_init(struct fdevents *ev);
__attribute_cold__
int fdevent_libev_init(struct fdevents *ev);

#endif
