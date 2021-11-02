#include "first.h"

#include "fdevent_impl.h"
#include "fdevent.h"
#include "buffer.h"
#include "log.h"

#include <stdlib.h>
#include <errno.h>

__attribute_malloc__
__attribute_returns_nonnull__
static fdnode *
fdnode_init (void)
{
    fdnode * const restrict fdn = calloc(1, sizeof(fdnode));
    force_assert(NULL != fdn);
    return fdn;
}

static void
fdnode_free (fdnode *fdn)
{
    free(fdn);
}

fdnode *
fdevent_register (fdevents *ev, int fd, fdevent_handler handler, void *ctx)
{
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

void
fdevent_unregister (fdevents *ev, int fd)
{
    fdnode *fdn = ev->fdarray[fd];
    if ((uintptr_t)fdn & 0x3) return; /*(should not happen)*/
    ev->fdarray[fd] = NULL;
    fdnode_free(fdn);
}

void
fdevent_sched_close (fdevents *ev, int fd, int issock)
{
    fdnode *fdn = ev->fdarray[fd];
    if ((uintptr_t)fdn & 0x3) return;
    ev->fdarray[fd] = (fdnode *)((uintptr_t)fdn | (issock ? 0x1 : 0x2));
    fdn->handler = (fdevent_handler)NULL;
    fdn->ctx = ev->pendclose;
    ev->pendclose = fdn;
}

__attribute_cold__
__attribute_noinline__
static int
fdevent_fdnode_event_unsetter_retry (fdevents *ev, fdnode *fdn)
{
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

static void
fdevent_fdnode_event_unsetter (fdevents *ev, fdnode *fdn)
{
    if (-1 == fdn->fde_ndx) return;
    if (0 != ev->event_del(ev, fdn))
        fdevent_fdnode_event_unsetter_retry(ev, fdn);
    fdn->fde_ndx = -1;
    fdn->events = 0;
}

__attribute_cold__
__attribute_noinline__
static int
fdevent_fdnode_event_setter_retry (fdevents *ev, fdnode *fdn, int events)
{
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

static void
fdevent_fdnode_event_setter (fdevents *ev, fdnode *fdn, int events)
{
    /*(Note: skips registering with kernel if initial events is 0,
     * so caller should pass non-zero events for initial registration.
     * If never registered due to never being called with non-zero events,
     * then FDEVENT_HUP or FDEVENT_ERR will never be returned.) */
    if (fdn->events == events) return;/*(no change; nothing to do)*/

    if (0 == ev->event_set(ev, fdn, events)
        || fdevent_fdnode_event_setter_retry(ev, fdn, events))
        fdn->events = events;
}

void
fdevent_fdnode_event_del (fdevents *ev, fdnode *fdn)
{
    if (NULL != fdn) fdevent_fdnode_event_unsetter(ev, fdn);
}

void
fdevent_fdnode_event_set (fdevents *ev, fdnode *fdn, int events)
{
    if (NULL != fdn) fdevent_fdnode_event_setter(ev, fdn, events);
}

void
fdevent_fdnode_event_add (fdevents *ev, fdnode *fdn, int event)
{
    if (NULL != fdn) fdevent_fdnode_event_setter(ev, fdn, (fdn->events|event));
}

void
fdevent_fdnode_event_clr (fdevents *ev, fdnode *fdn, int event)
{
    if (NULL != fdn) fdevent_fdnode_event_setter(ev, fdn, (fdn->events&~event));
}
