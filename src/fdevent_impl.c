#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>   /* closesocket */
#endif

int
fdevent_config (const char **event_handler_name, log_error_st *errh)
{
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
      #ifdef FDEVENT_USE_LIBEV
        { FDEVENT_HANDLER_LIBEV,          "libev" },
      #endif
        { FDEVENT_HANDLER_UNSET,          NULL }
    };

    const char *event_handler = *event_handler_name;
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
     #ifdef FDEVENT_USE_LIBEV
      "\t+ libev (generic)\n"
     #else
      "\t- libev (generic)\n"
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

    fdevent_socket_nb_cloexec_init();

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
        int fd, rc;
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

        fdnode * const fdn_tmp = fdn;
        fdn = (fdnode *)fdn->ctx; /* next */
        /*(fdevent_unregister)*/
        free(fdn_tmp); /*fdnode_free(fdn_tmp);*/
        ev->fdarray[fd] = NULL;
    }
    ev->pendclose = NULL;
}


int
fdevent_poll (fdevents * const ev, const int timeout_ms)
{
    const int n = ev->poll(ev, timeout_ms);
    if (n >= 0)
        fdevent_sched_run(ev);
    else if (errno != EINTR)
        log_perror(ev->errh, __FILE__, __LINE__, "fdevent_poll failed");
    return n;
}
