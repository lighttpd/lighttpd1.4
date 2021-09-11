#include "first.h"

#include "fdlog.h"

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "fdevent.h"
#include "log.h"

typedef struct fdlog_pipe {
    pid_t pid;
    int fds[2];
    const char *cmd;
    unix_time64_t start;
} fdlog_pipe;

struct fdlog_pipes_t {
    fdlog_pipe *ptr;
    uint32_t used;
    uint32_t size;
};

static struct fdlog_pipes_t fdlog_pipes;


static pid_t
fdlog_pipe_spawn (const char * const fn, const int rfd)
{
    char *args[4];
    int devnull = fdevent_open_devnull();
    pid_t pid;

    if (-1 == devnull) {
        return -1;
    }

    *(const char **)&args[0] = "/bin/sh";
    *(const char **)&args[1] = "-c";
    *(const char **)&args[2] = fn;
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


__attribute_noinline__
static int
fdlog_pipe_restart (fdlog_pipe * const fdp, const unix_time64_t ts)
{
    if (fdp->start + 5 < ts) { /* limit restart to once every 5 sec */
        /* restart child process using existing pipe fds */
        fdp->start = ts;
        fdp->pid = fdlog_pipe_spawn(fdp->cmd, fdp->fds[0]);
    }
    return (fdp->pid > 0) ? 1 : -1;
}


void
fdlog_pipes_restart (const unix_time64_t ts)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_pipe * const fdp = fdlog_pipes.ptr+i;
        if (fdp->pid > 0) continue;
        fdlog_pipe_restart(fdp, ts);
    }
}


int
fdlog_pipes_waitpid_cb (const pid_t pid)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_pipe * const fdp = fdlog_pipes.ptr+i;
        if (fdp->pid != pid) continue;

        fdp->pid = -1;
        return fdlog_pipe_restart(fdp, log_monotonic_secs);
    }
    return 0;
}


void
fdlog_pipes_close (void)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_pipe * const fdp = fdlog_pipes.ptr+i;
        close(fdp->fds[0]);
        if (fdp->fds[1] != STDERR_FILENO) close(fdp->fds[1]);
    }
    free(fdlog_pipes.ptr);
    fdlog_pipes.ptr = NULL;
    fdlog_pipes.used = 0;
    fdlog_pipes.size = 0;
}


void
fdlog_pipes_abandon_pids (void)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_pipe * const fdp = fdlog_pipes.ptr+i;
        fdp->pid = -1;
    }
}


void
fdlog_pipe_serrh (const int fd)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_pipe * const fdp = fdlog_pipes.ptr+i;
        if (fdp->fds[1] != fd) continue;

        fdp->fds[1] = STDERR_FILENO;
        break;
    }
}


static void
fdlog_pipe_init (const char * const cmd, const int fds[2], const pid_t pid)
{
    if (fdlog_pipes.used == fdlog_pipes.size) {
        fdlog_pipes.size += 4;
        fdlog_pipes.ptr =
          realloc(fdlog_pipes.ptr, fdlog_pipes.size * sizeof(fdlog_pipe));
        force_assert(fdlog_pipes.ptr);
    }
    fdlog_pipe * const fdp = fdlog_pipes.ptr + fdlog_pipes.used++;
    fdp->cmd = cmd; /* note: cmd must persist in memory (or else copy here) */
    fdp->fds[0] = fds[0];
    fdp->fds[1] = fds[1];
    fdp->pid = pid;
    fdp->start = log_monotonic_secs;
}


static int
fdlog_pipe_open (const char * const fn)
{
    int fds[2];
    if (pipe(fds))
        return -1;
    fdevent_setfd_cloexec(fds[0]);
    fdevent_setfd_cloexec(fds[1]);

    pid_t pid = fdlog_pipe_spawn(fn, fds[0]);
    if (pid > 0) {
        /*(nonblocking write() from lighttpd)*/
        if (0 != fdevent_fcntl_set_nb(fds[1])) { /*(ignore)*/ }
        fdlog_pipe_init(fn, fds, pid);
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


int
fdlog_open (const char * const fn)
{
    if (fn[0] != '|') { /*(permit symlinks)*/
        int flags = O_APPEND | O_WRONLY | O_CREAT;
        return fdevent_open_cloexec(fn, 1, flags, 0644);
    }
    else {
        return fdlog_pipe_open(fn+1); /*(skip the '|')*/
    }
}


int
fdlog_cycle (const char * const fn, int * const curfd)
{
    if (fn[0] != '|') {
        int fd = fdlog_open(fn);
        if (-1 == fd) return -1; /*(error; leave *curfd as-is)*/
        if (-1 != *curfd) close(*curfd);
        *curfd = fd;
    }
    return *curfd;
}
