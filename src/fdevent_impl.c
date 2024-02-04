#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <sys/types.h>
#include "sys-unistd.h" /* <unistd.h> */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#include <winsock2.h>   /* closesocket(), WSAPoll() */
#endif

#ifdef FDEVENT_USE_LINUX_EPOLL
__attribute_cold__
static int fdevent_linux_sysepoll_init(struct fdevents *ev);
#endif
#ifdef FDEVENT_USE_FREEBSD_KQUEUE
__attribute_cold__
static int fdevent_freebsd_kqueue_init(struct fdevents *ev);
#endif
#ifdef FDEVENT_USE_SOLARIS_PORT
__attribute_cold__
static int fdevent_solaris_port_init(struct fdevents *ev);
#endif
#ifdef FDEVENT_USE_SOLARIS_DEVPOLL
__attribute_cold__
static int fdevent_solaris_devpoll_init(struct fdevents *ev);
#endif
#ifdef FDEVENT_USE_POLL
__attribute_cold__
static int fdevent_poll_init(struct fdevents *ev);
#endif
#ifdef FDEVENT_USE_SELECT
__attribute_cold__
static int fdevent_select_init(struct fdevents *ev);
#endif


int
fdevent_config (const char **event_handler_name, log_error_st *errh)
{
  #ifndef _WIN32
    fdevent_socket_nb_cloexec_init();
  #endif

    static const struct ev_map { fdevent_handler_t et; const char *name; }
      event_handlers[] =
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
        { FDEVENT_HANDLER_UNSET,          NULL }
    };

    const char *event_handler = *event_handler_name;
    fdevent_handler_t et = FDEVENT_HANDLER_UNSET;

    if (NULL != event_handler && 0 == strcmp(event_handler, "libev"))
        event_handler = NULL;
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
    }
    else {
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


const char *
fdevent_show_event_handlers (void)
{
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
      ;
}


fdevents *
fdevent_init (const char *event_handler, int *max_fds, int *cur_fds, log_error_st *errh)
{
    fdevents *ev;
    uint32_t maxfds = (0 != *max_fds)
      ? (uint32_t)*max_fds
      : 4096;
    int type = fdevent_config(&event_handler, errh);
    if (type <= 0) return NULL;

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

    ev = ck_calloc(1, sizeof(*ev));
    ev->errh = errh;
    ev->cur_fds = cur_fds;
    ev->event_handler = event_handler;
    ev->fdarray = ck_calloc(maxfds, sizeof(*ev->fdarray));
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


void
fdevent_free (fdevents *ev)
{
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


int
fdevent_reset (fdevents *ev)
{
    int rc = (NULL != ev->reset) ? ev->reset(ev) : 0;
    if (-1 == rc) {
        log_error(ev->errh, __FILE__, __LINE__,
          "event-handler failed: %s; "
          "try to set server.event-handler = \"poll\" or \"select\"",
          ev->event_handler ? ev->event_handler : "");
    }
    return rc;
}


static void
fdevent_sched_run (fdevents * const ev)
{
    for (fdnode *fdn = ev->pendclose; fdn; ) {
        int fd = fdn->fd;
        /*(inlined fdio_close_socket() for tighter loop; worthwhile?)*/
      #ifdef _WIN32
        if (0 != closesocket(fd)) /* WSAPoll() valid only on SOCKET */
      #else
        if (0 != close(fd))
      #endif
            log_serror(ev->errh, __FILE__, __LINE__, "close() %d", fd);

        --(*ev->cur_fds);

        fdnode * const fdn_tmp = fdn;
        fdn = (fdnode *)fdn->ctx; /* next */
      #ifdef _WIN32
        /*(remove 0x3 flags from fdarray fdn before call to unregister below)*/
        ev->fdarray[fdn_tmp->fda_ndx] = fdn_tmp;
        fdevent_unregister(ev, fdn_tmp);
      #else
        /*(fdevent_unregister)*/
        ev->fdarray[fd] = NULL;
        free(fdn_tmp); /*fdnode_free(fdn_tmp);*/
      #endif
    }
    ev->pendclose = NULL;
}


int
fdevent_poll (fdevents * const ev, const int timeout_ms)
{
    const int n = ev->poll(ev, ev->pendclose ? 0 : timeout_ms);
    if (n >= 0)
        fdevent_sched_run(ev);
    else if (errno != EINTR)
        log_serror(ev->errh, __FILE__, __LINE__, "fdevent_poll()");
    return n;
}


#ifdef FDEVENT_USE_LINUX_EPOLL

#include <sys/epoll.h>

static int
fdevent_linux_sysepoll_event_del (fdevents *ev, fdnode *fdn)
{
    return epoll_ctl(ev->epoll_fd, EPOLL_CTL_DEL, fdn->fd, NULL);
}

static int
fdevent_linux_sysepoll_event_set (fdevents *ev, fdnode *fdn, int events)
{
    int op = (-1 == fdn->fde_ndx) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    int fd = fdn->fde_ndx = fdn->fd;
    struct epoll_event ep;
  #ifndef EPOLLRDHUP
    events &= ~FDEVENT_RDHUP;
  #endif
    ep.events = events | EPOLLERR | EPOLLHUP;
    ep.data.ptr = fdn;
    return epoll_ctl(ev->epoll_fd, op, fd, &ep);
}

static int
fdevent_linux_sysepoll_poll (fdevents * const ev, int timeout_ms)
{
    struct epoll_event * const restrict epoll_events = ev->epoll_events;
    int n = epoll_wait(ev->epoll_fd, epoll_events, ev->maxfds, timeout_ms);
    for (int i = 0; i < n; ++i) {
        fdnode * const fdn = (fdnode *)epoll_events[i].data.ptr;
        int revents = epoll_events[i].events;
        if ((fdevent_handler)NULL != fdn->handler)
            (*fdn->handler)(fdn->ctx, revents);
    }
    return n;
}

__attribute_cold__
static void
fdevent_linux_sysepoll_free (fdevents *ev)
{
    close(ev->epoll_fd);
    free(ev->epoll_events);
}

__attribute_cold__
static int
fdevent_linux_sysepoll_init (fdevents *ev)
{
    ck_static_assert(EPOLLIN    == FDEVENT_IN);
    ck_static_assert(EPOLLPRI   == FDEVENT_PRI);
    ck_static_assert(EPOLLOUT   == FDEVENT_OUT);
    ck_static_assert(EPOLLERR   == FDEVENT_ERR);
    ck_static_assert(EPOLLHUP   == FDEVENT_HUP);
  #ifdef EPOLLRDHUP
    ck_static_assert(EPOLLRDHUP == FDEVENT_RDHUP);
  #endif

    ev->type      = FDEVENT_HANDLER_LINUX_SYSEPOLL;
    ev->event_set = fdevent_linux_sysepoll_event_set;
    ev->event_del = fdevent_linux_sysepoll_event_del;
    ev->poll      = fdevent_linux_sysepoll_poll;
    ev->free      = fdevent_linux_sysepoll_free;

  #ifdef EPOLL_CLOEXEC
    if (-1 == (ev->epoll_fd = epoll_create1(EPOLL_CLOEXEC))) return -1;
  #else
    if (-1 == (ev->epoll_fd = epoll_create(ev->maxfds))) return -1;
    fdevent_setfd_cloexec(ev->epoll_fd);
  #endif

    ev->epoll_events = ck_calloc(ev->maxfds, sizeof(*ev->epoll_events));

    return 0;
}

#endif /* FDEVENT_USE_LINUX_EPOLL */


#ifdef FDEVENT_USE_FREEBSD_KQUEUE

#include <sys/event.h>
#include "sys-time.h"
#include <fcntl.h>

static int
fdevent_freebsd_kqueue_event_del (fdevents *ev, fdnode *fdn)
{
    struct kevent kev[2];
    struct timespec ts = {0, 0};
    int fd = fdn->fd;
    int n = 0;
    int oevents = fdn->events;

    if (oevents & FDEVENT_IN)  {
        EV_SET(&kev[n], fd, EVFILT_READ, EV_DELETE, 0, 0, fdn);
        n++;
    }
    if (oevents & FDEVENT_OUT)  {
        EV_SET(&kev[n], fd, EVFILT_WRITE, EV_DELETE, 0, 0, fdn);
        n++;
    }

    return (0 != n) ? kevent(ev->kq_fd, kev, n, NULL, 0, &ts) : 0;
    /*(kevent() changelist still processed on EINTR,
     * but EINTR should not be received since 0 == nevents)*/
}

static int
fdevent_freebsd_kqueue_event_set (fdevents *ev, fdnode *fdn, int events)
{
    struct kevent kev[2];
    struct timespec ts = {0, 0};
    int fd = fdn->fde_ndx = fdn->fd;
    int n = 0;
    int oevents = fdn->events;
    int addevents = events & ~oevents;
    int delevents = ~events & oevents;

    if (addevents & FDEVENT_IN)  {
        EV_SET(&kev[n], fd, EVFILT_READ, EV_ADD, 0, 0, fdn);
        n++;
    }
    else if (delevents & FDEVENT_IN) {
        EV_SET(&kev[n], fd, EVFILT_READ, EV_DELETE, 0, 0, fdn);
        n++;
    }

    if (addevents & FDEVENT_OUT)  {
        EV_SET(&kev[n], fd, EVFILT_WRITE, EV_ADD, 0, 0, fdn);
        n++;
    }
    else if (delevents & FDEVENT_OUT) {
        EV_SET(&kev[n], fd, EVFILT_WRITE, EV_DELETE, 0, 0, fdn);
        n++;
    }

    return (0 != n) ? kevent(ev->kq_fd, kev, n, NULL, 0, &ts) : 0;
    /*(kevent() changelist still processed on EINTR,
     * but EINTR should not be received since 0 == nevents)*/
}

static int
fdevent_freebsd_kqueue_poll (fdevents * const ev, int timeout_ms)
{
    struct timespec ts;
    ts.tv_sec  = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;

    struct kevent * const restrict kq_results = ev->kq_results;
    const int n = kevent(ev->kq_fd, NULL, 0, kq_results, ev->maxfds, &ts);

    for (int i = 0; i < n; ++i) {
        fdnode * const fdn = (fdnode *)kq_results[i].udata;
        int filt = kq_results[i].filter;
        int e = kq_results[i].flags;
        if ((fdevent_handler)NULL != fdn->handler) {
            int revents = (filt == EVFILT_READ) ? FDEVENT_IN : FDEVENT_OUT;
            if (e & EV_EOF)
                revents |= (filt == EVFILT_READ ? FDEVENT_RDHUP : FDEVENT_HUP);
            if (e & EV_ERROR)
                revents |= FDEVENT_ERR;
            (*fdn->handler)(fdn->ctx, revents);
        }
    }
    return n;
}

__attribute_cold__
static int
fdevent_freebsd_kqueue_reset (fdevents *ev)
{
  #ifdef __NetBSD__
    ev->kq_fd = kqueue1(O_NONBLOCK|O_CLOEXEC|O_NOSIGPIPE);
    return (-1 != ev->kq_fd) ? 0 : -1;
  #else
    ev->kq_fd = kqueue();
    if (-1 == ev->kq_fd) return -1;
    fdevent_setfd_cloexec(ev->kq_fd);
    return 0;
  #endif
}

__attribute_cold__
static void
fdevent_freebsd_kqueue_free (fdevents *ev)
{
    close(ev->kq_fd);
    free(ev->kq_results);
}

__attribute_cold__
static int
fdevent_freebsd_kqueue_init (fdevents *ev)
{
    ev->type       = FDEVENT_HANDLER_FREEBSD_KQUEUE;
    ev->event_set  = fdevent_freebsd_kqueue_event_set;
    ev->event_del  = fdevent_freebsd_kqueue_event_del;
    ev->poll       = fdevent_freebsd_kqueue_poll;
    ev->reset      = fdevent_freebsd_kqueue_reset;
    ev->free       = fdevent_freebsd_kqueue_free;
    ev->kq_fd      = -1;
    ev->kq_results = ck_calloc(ev->maxfds, sizeof(*ev->kq_results));
    return 0;
}

#endif /* FDEVENT_USE_FREEBSD_KQUEUE */


#ifdef FDEVENT_USE_SOLARIS_PORT

#include <sys/poll.h>
#include <fcntl.h>

static int
fdevent_solaris_port_event_del (fdevents *ev, fdnode *fdn)
{
    return port_dissociate(ev->port_fd, PORT_SOURCE_FD, fdn->fd);
}

static int
fdevent_solaris_port_event_set (fdevents *ev, fdnode *fdn, int events)
{
    int fd = fdn->fde_ndx = fdn->fd;
    intptr_t ud = events & (POLLIN|POLLOUT);
    return port_associate(ev->port_fd,PORT_SOURCE_FD,fd,(int)ud,(void*)ud);
}

/* if there is any error it will return the return values of port_getn,
 * otherwise it will return number of events */
static int
fdevent_solaris_port_poll (fdevents *ev, int timeout_ms)
{
    const int pfd = ev->port_fd;
    int ret;
    unsigned int available_events, wait_for_events = 0;

    struct timespec  timeout;

    timeout.tv_sec  = timeout_ms/1000L;
    timeout.tv_nsec = (timeout_ms % 1000L) * 1000000L;

    /* get the number of file descriptors with events */
    if ((ret = port_getn(pfd, ev->port_events, 0, &wait_for_events, &timeout)) < 0) return ret;

    /* wait for at least one event */
    if (0 == wait_for_events) wait_for_events = 1;

    available_events = wait_for_events;

    /* get the events of the file descriptors */
    if ((ret = port_getn(pfd, ev->port_events, ev->maxfds, &available_events, &timeout)) < 0) {
        /* if errno == ETIME and available_event == wait_for_events we didn't get any events */
        /* for other errors we didn't get any events either */
        if (!(errno == ETIME && wait_for_events != available_events)) return ret;
    }

    for (int i = 0; i < (int)available_events; ++i) {
        int fd = (int)ev->port_events[i].portev_object;
        fdnode * const fdn = ev->fdarray[fd];
        const intptr_t ud = (intptr_t)ev->port_events[i].portev_user;
        int revents = ev->port_events[i].portev_events;
        if (0 == ((uintptr_t)fdn & 0x3)) {
            if (port_associate(pfd,PORT_SOURCE_FD,fd,(int)ud,(void*)ud) < 0)
                log_error(ev->errh,__FILE__,__LINE__,"port_associate failed");
            (*fdn->handler)(fdn->ctx, revents);
        }
        else {
            fdn->fde_ndx = -1;
        }
    }
    return available_events;
}

__attribute_cold__
static void
fdevent_solaris_port_free (fdevents *ev)
{
    close(ev->port_fd);
    free(ev->port_events);
}

__attribute_cold__
static int
fdevent_solaris_port_init (fdevents *ev)
{
    ck_static_assert(POLLIN    == FDEVENT_IN);
    ck_static_assert(POLLPRI   == FDEVENT_PRI);
    ck_static_assert(POLLOUT   == FDEVENT_OUT);
    ck_static_assert(POLLERR   == FDEVENT_ERR);
    ck_static_assert(POLLHUP   == FDEVENT_HUP);
    ck_static_assert(POLLNVAL  == FDEVENT_NVAL);
  #ifdef POLLRDHUP
    ck_static_assert(POLLRDHUP == FDEVENT_RDHUP);
  #endif

    ev->type        = FDEVENT_HANDLER_SOLARIS_PORT;
    ev->event_set   = fdevent_solaris_port_event_set;
    ev->event_del   = fdevent_solaris_port_event_del;
    ev->poll        = fdevent_solaris_port_poll;
    ev->free        = fdevent_solaris_port_free;
    ev->port_events = ck_calloc(ev->maxfds, sizeof(*ev->port_events));

    if ((ev->port_fd = port_create()) < 0) return -1;

    return 0;
}

#endif /* FDEVENT_USE_SOLARIS_PORT */


#ifdef FDEVENT_USE_SOLARIS_DEVPOLL

#include <sys/devpoll.h>
#include <sys/ioctl.h>
#include <fcntl.h>

static int
fdevent_solaris_devpoll_event_del (fdevents *ev, fdnode *fdn)
{
    struct pollfd pfd;
    pfd.fd = fdn->fd;
    pfd.events = POLLREMOVE;
    pfd.revents = 0;
    return (-1 != write(ev->devpoll_fd, &pfd, sizeof(pfd))) ? 0 : -1;
}

static int
fdevent_solaris_devpoll_event_set (fdevents *ev, fdnode *fdn, int events)
{
    struct pollfd pfd;
    pfd.fd = fdn->fde_ndx = fdn->fd;
  #ifndef POLLRDHUP
    events &= ~FDEVENT_RDHUP;
  #endif
    pfd.events = events;
    pfd.revents = 0;
    return (-1 != write(ev->devpoll_fd, &pfd, sizeof(pfd))) ? 0 : -1;
}

static int
fdevent_solaris_devpoll_poll (fdevents *ev, int timeout_ms)
{
    fdnode ** const fdarray = ev->fdarray;
    struct pollfd * const devpollfds = ev->devpollfds;
    struct dvpoll dopoll;

    dopoll.dp_timeout = timeout_ms;
    dopoll.dp_nfds = ev->maxfds - 1;
    dopoll.dp_fds = devpollfds;

    const int n = ioctl(ev->devpoll_fd, DP_POLL, &dopoll);

    for (int i = 0; i < n; ++i) {
        fdnode * const fdn = fdarray[devpollfds[i].fd];
        int revents = devpollfds[i].revents;
        if (0 == ((uintptr_t)fdn & 0x3))
            (*fdn->handler)(fdn->ctx, revents);
    }
    return n;
}

__attribute_cold__
static int
fdevent_solaris_devpoll_reset (fdevents *ev)
{
    /* a forked process does only inherit the filedescriptor,
     * but every operation on the device will lead to a EACCES */
    ev->devpoll_fd = fdevent_open_cloexec("/dev/poll", 1, O_RDWR, 0);
    return (ev->devpoll_fd >= 0) ? 0 : -1;
}

__attribute_cold__
static void
fdevent_solaris_devpoll_free (fdevents *ev)
{
    free(ev->devpollfds);
    close(ev->devpoll_fd);
}

__attribute_cold__
static int
fdevent_solaris_devpoll_init (fdevents *ev)
{
    ck_static_assert(POLLIN    == FDEVENT_IN);
    ck_static_assert(POLLPRI   == FDEVENT_PRI);
    ck_static_assert(POLLOUT   == FDEVENT_OUT);
    ck_static_assert(POLLERR   == FDEVENT_ERR);
    ck_static_assert(POLLHUP   == FDEVENT_HUP);
    ck_static_assert(POLLNVAL  == FDEVENT_NVAL);
  #ifdef POLLRDHUP
    ck_static_assert(POLLRDHUP == FDEVENT_RDHUP);
  #endif

    ev->type       = FDEVENT_HANDLER_SOLARIS_DEVPOLL;
    ev->event_set  = fdevent_solaris_devpoll_event_set;
    ev->event_del  = fdevent_solaris_devpoll_event_del;
    ev->poll       = fdevent_solaris_devpoll_poll;
    ev->reset      = fdevent_solaris_devpoll_reset;
    ev->free       = fdevent_solaris_devpoll_free;
    ev->devpoll_fd = -1;
    ev->devpollfds = ck_calloc(ev->maxfds, sizeof(*ev->devpollfds));
    return 0;
}

#endif /* FDEVENT_USE_SOLARIS_DEVPOLL */


#ifdef FDEVENT_USE_POLL

#ifdef HAVE_POLL_H
#include <poll.h>
#elif defined(_WIN32)
#define poll(fdArray,fds,timeout) WSAPoll((fdArray),(fds),(timeout))
#else
#include <sys/poll.h>
#endif

static int
fdevent_poll_event_del (fdevents *ev, fdnode *fdn)
{
    int fd = fdn->fd;
    int k = fdn->fde_ndx;
    if ((uint32_t)k >= ev->used || (int)ev->pollfds[k].fd != fd)
        return (errno = EINVAL, -1);

    ev->pollfds[k].fd = -1;
    /* ev->pollfds[k].events = 0; */
    /* ev->pollfds[k].revents = 0; */

    if (ev->unused.size == ev->unused.used) {
        ck_realloc_u32((void **)&ev->unused.ptr, ev->unused.size,
                       16, sizeof(*ev->unused.ptr));
        ev->unused.size += 16;
    }

    ev->unused.ptr[ev->unused.used++] = k;

    return 0;
}

static int
fdevent_poll_event_set (fdevents *ev, fdnode *fdn, int events)
{
    int fd = fdn->fd;
    int k = fdn->fde_ndx;

  #ifndef POLLRDHUP
    events &= ~FDEVENT_RDHUP;
  #endif

    if (k >= 0) {
        if ((uint32_t)k >= ev->used || (int)ev->pollfds[k].fd != fd)
            return (errno = EINVAL, -1);
        ev->pollfds[k].events = events;
        return 0;
    }

    if (ev->unused.used > 0) {
        k = ev->unused.ptr[--ev->unused.used];
    }
    else {
        if (ev->size == ev->used) {
            ck_realloc_u32((void **)&ev->pollfds, ev->size,
                           16, sizeof(*ev->pollfds));
            ev->size += 16;
        }

        k = ev->used++;
    }

    fdn->fde_ndx = k;
    ev->pollfds[k].fd = fd;
    ev->pollfds[k].events = events;

    return 0;
}

static int
fdevent_poll_poll (fdevents *ev, int timeout_ms)
{
    const int n = poll(ev->pollfds, ev->used, timeout_ms);
    fdnode ** const fdarray = ev->fdarray;
  #ifdef _WIN32
    /* XXX: O(m x n) search through fdarray; improve later for many fds
     * Since number of ready events is typically going to be small,
     * walk fdarray and for each fdn, scan ready pollfds (rather than
     * walking ready pollfds and then scanning fdarray for matching fd) */
    const int nfds = (int)ev->used;
    const int count = ev->count;
    for (int m = 0, a = 0; m < n && a < count; ++a) {
        struct pollfd * const restrict pfds = ev->pollfds;
        const fdnode * const fdn = fdarray[a];
        SOCKET fd = (SOCKET)((fdnode *)((uintptr_t)fdn & ~0x3))->fd;
        for (int i = 0; i < nfds; ++i) {
            if (0 == pfds[i].revents || fd != pfds[i].fd) continue;
            if (0 == ((uintptr_t)fdn & 0x3))
                (*fdn->handler)(fdn->ctx, pfds[i].revents);
            ++m;
            break;
        }
    }
  #else
    for (int i = 0, m = 0; m < n; ++i, ++m) {
        struct pollfd * const restrict pfds = ev->pollfds;
        while (0 == pfds[i].revents) ++i;
        fdnode *fdn = fdarray[pfds[i].fd];
        if (0 == ((uintptr_t)fdn & 0x3))
            (*fdn->handler)(fdn->ctx, pfds[i].revents);
    }
  #endif
    return n;
}

__attribute_cold__
static void
fdevent_poll_free (fdevents *ev)
{
    free(ev->pollfds);
    if (ev->unused.ptr) free(ev->unused.ptr);
}

__attribute_cold__
static int
fdevent_poll_init (fdevents *ev)
{
    ck_static_assert(POLLIN    == FDEVENT_IN);
    ck_static_assert(POLLPRI   == FDEVENT_PRI);
    ck_static_assert(POLLOUT   == FDEVENT_OUT);
    ck_static_assert(POLLERR   == FDEVENT_ERR);
    ck_static_assert(POLLHUP   == FDEVENT_HUP);
    ck_static_assert(POLLNVAL  == FDEVENT_NVAL);
  #ifdef POLLRDHUP
    ck_static_assert(POLLRDHUP == FDEVENT_RDHUP);
  #endif

    ev->type      = FDEVENT_HANDLER_POLL;
    ev->event_set = fdevent_poll_event_set;
    ev->event_del = fdevent_poll_event_del;
    ev->poll      = fdevent_poll_poll;
    ev->free      = fdevent_poll_free;
    return 0;
}

#endif /* FDEVENT_USE_POLL */


#ifdef FDEVENT_USE_SELECT

#include "sys-time.h"

__attribute_cold__
static int
fdevent_select_reset (fdevents *ev)
{
    FD_ZERO(&(ev->select_set_read));
    FD_ZERO(&(ev->select_set_write));
    FD_ZERO(&(ev->select_set_error));
  #ifndef _WIN32
    ev->select_max_fd = -1;
  #endif
    return 0;
}

static int
fdevent_select_event_del (fdevents *ev, fdnode *fdn)
{
    int fd = fdn->fd;
    FD_CLR(fd, &(ev->select_set_read));
    FD_CLR(fd, &(ev->select_set_write));
    FD_CLR(fd, &(ev->select_set_error));
    return 0;
}

static int
fdevent_select_event_set (fdevents *ev, fdnode *fdn, int events)
{
    int fd = fdn->fde_ndx = fdn->fd;

    /* we should be protected by max-fds, but you never know */
  #ifdef _WIN32
    force_assert(ev->count < ((int)FD_SETSIZE));
  #else
    force_assert(fd < ((int)FD_SETSIZE));
    if (fd > ev->select_max_fd) ev->select_max_fd = fd;
  #endif

    if (events & FDEVENT_IN)
        FD_SET(fd, &(ev->select_set_read));
    else
        FD_CLR(fd, &(ev->select_set_read));

    if (events & FDEVENT_OUT)
        FD_SET(fd, &(ev->select_set_write));
    else
        FD_CLR(fd, &(ev->select_set_write));

    FD_SET(fd, &(ev->select_set_error));

    return 0;
}

static int
fdevent_select_poll (fdevents *ev, int timeout_ms)
{
    struct timeval tv;
    tv.tv_sec =  timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ev->select_read  = ev->select_set_read;
    ev->select_write = ev->select_set_write;
    ev->select_error = ev->select_set_error;

  #ifdef _WIN32

    const int nfds = ev->count;
    const int n =
      select(nfds, &ev->select_read, &ev->select_write, &ev->select_error, &tv);
    if (n <= 0) return n;
    fdnode **fda = ev->fdarray;
    for (int ndx = -1, i = n; ++ndx < nfds; ) {
        const fdnode *fdn = *fda++;
        int fd = ((fdnode *)((uintptr_t)fdn & ~0x3))->fd;
        int revents = 0;
        if (FD_ISSET(fd, &ev->select_read))  revents |= FDEVENT_IN;
        if (FD_ISSET(fd, &ev->select_write)) revents |= FDEVENT_OUT;
        if (FD_ISSET(fd, &ev->select_error)) revents |= FDEVENT_ERR;
        if (revents) {
            if (0 == ((uintptr_t)fdn & 0x3))
                (*fdn->handler)(fdn->ctx, revents);
            if (0 == --i)
                break;
        }
    }

  #else

    const int nfds = ev->select_max_fd + 1;
    const int n =
      select(nfds, &ev->select_read, &ev->select_write, &ev->select_error, &tv);
    if (n <= 0) return n;
    for (int ndx = -1, i = n; ++ndx < nfds; ) {
        int revents = 0;
        if (FD_ISSET(ndx, &ev->select_read))  revents |= FDEVENT_IN;
        if (FD_ISSET(ndx, &ev->select_write)) revents |= FDEVENT_OUT;
        if (FD_ISSET(ndx, &ev->select_error)) revents |= FDEVENT_ERR;
        if (revents) {
            const fdnode *fdn = ev->fdarray[ndx];
            if (0 == ((uintptr_t)fdn & 0x3))
                (*fdn->handler)(fdn->ctx, revents);
            if (0 == --i)
                break;
        }
    }

  #endif

    return n;
}

__attribute_cold__
static int fdevent_select_init (fdevents *ev)
{
    ev->type      = FDEVENT_HANDLER_SELECT;
    ev->event_set = fdevent_select_event_set;
    ev->event_del = fdevent_select_event_del;
    ev->poll      = fdevent_select_poll;
    ev->reset     = fdevent_select_reset;
    return 0;
}

#endif /* FDEVENT_USE_SELECT */
