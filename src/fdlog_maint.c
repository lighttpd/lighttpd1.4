#include "first.h"

#include "fdlog.h"

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdevent.h"
#include "ck.h"
#include "log.h"

/*
 * Notes:
 * - Use of "/dev/stdin" and "/dev/stdout" is not recommended
 *   since those are manipulated at startup in server_main_setup()
 *   "/dev/stderr" might similarly be manipulated at startup.
 * - Use of "/proc/self/fd/..." is permitted, and admin may use a shell script
 *   to dup standard fds to higher numbers before starting lighttpd if admin
 *   wants to direct logs to the standard fds on which lighttpd was started.
 *   Future: might detect and use the open fd rather than open() a new fd to the
 *   already-open path.  If so, should stat() to check that fd actually exists,
 *   and must check for and not close() those paths when closing fdlog_st fds.
 */

struct fdlog_files_t {
    fdlog_st **ptr;
    uint32_t used;
    uint32_t size;
};

static struct fdlog_files_t fdlog_files;

typedef struct fdlog_pipe {
    /* ((fdlog_st *) is ptr rather than inlined struct since multiple callers
     *  might have reference to (fdlog_st *), and if fdlog_pipes.ptr is
     *  reallocated those ptrs could be invalided if inlined struct) */
    fdlog_st *fdlog; /*(contains write-side of pipe)*/
    pid_t pid;
    int fd;         /*(contains read-side of pipe)*/
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
        fdp->pid = fdlog_pipe_spawn(fdp->fdlog->fn, fdp->fd);
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


static void
fdlog_pipes_close (fdlog_st * const retain)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_pipe * const fdp = fdlog_pipes.ptr+i;
        fdlog_st * const fdlog = fdp->fdlog;
        close(fdp->fd);
        fdp->fd = -1;
        if (fdlog == retain) continue; /*(free'd later)*/
        fdlog_free(fdlog);
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
        fdlog_st * const fdlog = fdlog_pipes.ptr[i].fdlog;
        if (fdlog->fd != fd) continue;

        fdlog->fd = STDERR_FILENO;
        break;
    }
}


static fdlog_st *
fdlog_pipe_init (const char * const fn, const int fds[2], const pid_t pid)
{
    if (fdlog_pipes.used == fdlog_pipes.size) {
        fdlog_pipes.size += 4;
        fdlog_pipes.ptr =
          realloc(fdlog_pipes.ptr, fdlog_pipes.size * sizeof(fdlog_pipe));
        force_assert(fdlog_pipes.ptr);
    }
    fdlog_pipe * const fdp = fdlog_pipes.ptr + fdlog_pipes.used++;
    fdp->fd = fds[0];
    fdp->pid = pid;
    fdp->start = log_monotonic_secs;
    return (fdp->fdlog = fdlog_init(fn, fds[1], FDLOG_PIPE));
}


static fdlog_st *
fdlog_pipe_open (const char * const fn)
{
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        fdlog_st * const fdlog = fdlog_pipes.ptr[i].fdlog;
        if (0 != strcmp(fdlog->fn, fn)) continue;
        return fdlog;
    }

    int fds[2];
    if (fdevent_pipe_cloexec(fds, 65536))
        return NULL;

    pid_t pid = fdlog_pipe_spawn(fn, fds[0]);
    if (pid > 0) {
        /*(nonblocking write() from lighttpd)*/
        if (0 != fdevent_fcntl_set_nb(fds[1])) { /*(ignore)*/ }
        return fdlog_pipe_init(fn, fds, pid);
    }
    else {
        int errnum = errno;
        close(fds[0]);
        close(fds[1]);
        errno = errnum;
        return NULL;
    }
}


static fdlog_st *
fdlog_file_init (const char * const fn, const int fd)
{
    if (fdlog_files.used == fdlog_files.size) {
        fdlog_files.size += 4;
        fdlog_files.ptr =
          realloc(fdlog_files.ptr, fdlog_files.size * sizeof(fdlog_st *));
        force_assert(fdlog_files.ptr);
    }
    return (fdlog_files.ptr[fdlog_files.used++] = fdlog_init(fn,fd,FDLOG_FILE));
}


static int
fdlog_file_open_fd (const char * const fn)
{
    int flags = O_APPEND | O_WRONLY | O_CREAT;
    return fdevent_open_cloexec(fn, 1, flags, 0644); /*(permit symlinks)*/
}


static fdlog_st *
fdlog_file_open (const char * const fn)
{
    for (uint32_t i = 0; i < fdlog_files.used; ++i) {
        fdlog_st * const fdlog = fdlog_files.ptr[i];
        if (0 != strcmp(fdlog->fn, fn)) continue;
        return fdlog;
    }

    int fd = fdlog_file_open_fd(fn);
    return (-1 != fd) ? fdlog_file_init(fn, fd) : NULL;
}


fdlog_st *
fdlog_open (const char * const fn)
{
    return (fn[0] != '|')
      ? fdlog_file_open(fn)
      : fdlog_pipe_open(fn+1); /*(skip the '|')*/
}


void
fdlog_files_flush (fdlog_st * const errh, const int memrel)
{
    for (uint32_t i = 0; i < fdlog_files.used; ++i) {
        fdlog_st * const fdlog = fdlog_files.ptr[i];
        buffer * const b = &fdlog->b;
        if (!buffer_is_blank(b)) {
            const ssize_t wr = write_all(fdlog->fd, BUF_PTR_LEN(b));
            buffer_clear(b); /*(clear buffer, even on error)*/
            if (-1 == wr)
                log_perror(errh, __FILE__, __LINE__,
                  "error flushing log %s", fdlog->fn);
        }
        if (memrel && b->ptr) buffer_free_ptr(b);
    }
}


void
fdlog_files_cycle (fdlog_st * const errh)
{
    fdlog_files_flush(errh, 0);
    for (uint32_t i = 0; i < fdlog_files.used; ++i) {
        fdlog_st * const fdlog = fdlog_files.ptr[i];
        int fd = fdlog_file_open_fd(fdlog->fn);
        if (-1 != fd) {
            if (fdlog->fd > STDERR_FILENO) {
                close(fdlog->fd);
                fdlog->fd = fd;
            }
            else {
                if (fdlog->fd != dup2(fd, fdlog->fd))
                    log_perror(errh, __FILE__, __LINE__,
                      "dup2() %s to %d", fdlog->fn, fdlog->fd);
                close(fd);
            }
        }
        else {
            log_perror(errh, __FILE__, __LINE__,
              "error cycling log %s", fdlog->fn);
            /*(leave prior log file open)*/
        }
    }
}


static void
fdlog_files_close (fdlog_st * const retain)
{
    fdlog_files_flush(retain, 0);
    for (uint32_t i = 0; i < fdlog_files.used; ++i) {
        fdlog_st * const fdlog = fdlog_files.ptr[i];
        if (fdlog == retain) continue; /*(free'd later)*/
        fdlog_free(fdlog);
    }
    free(fdlog_files.ptr);
    fdlog_files.ptr = NULL;
    fdlog_files.used = 0;
    fdlog_files.size = 0;
}


void
fdlog_closeall (fdlog_st * const errh)
{
    fdlog_files_close(errh);
    fdlog_pipes_close(errh);
}


void
fdlog_flushall (fdlog_st * const errh)
{
    fdlog_files_flush(errh, 1); /*(flush, then release buffer memory)*/
    /*(at the moment, pipe loggers clear buffer after each write attempt,
     * so there is nothing to flush, though there are buffers to be freed)*/
    for (uint32_t i = 0; i < fdlog_pipes.used; ++i) {
        buffer * const b = &fdlog_pipes.ptr[i].fdlog->b;
        if (b->ptr) buffer_free_ptr(b);
    }
    if (errh->b.ptr) buffer_free_ptr(&errh->b);
}
