#include "first.h"
#include "fdlog.h"

#include <stdlib.h>
#include <unistd.h>     /* close() STDERR_FILENO */

#include "ck.h"

fdlog_st *
fdlog_init (const char * const fn, const int fd, const int mode)
{
    fdlog_st * const fdlog = calloc(1, sizeof(fdlog_st));
    ck_assert(fdlog);
    fdlog->fn = fn; /* note: fn must persist in memory (or else copy here) */
    fdlog->fd = fd >= 0 ? fd : STDERR_FILENO;
    fdlog->mode = mode;
    return fdlog;
}


void
fdlog_free (fdlog_st * const fdlog)
{
    if (fdlog->fd > STDERR_FILENO)
        close(fdlog->fd);
    free(fdlog->b.ptr);
    free(fdlog);
}
