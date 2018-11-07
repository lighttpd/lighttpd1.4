#include "first.h"

#include "network_write.h"

#include "base.h"
#include "log.h"

#include <sys/types.h>
#include "sys-socket.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>


/* on linux 2.4.x you get either sendfile or LFS */
#if defined HAVE_SYS_SENDFILE_H && defined HAVE_SENDFILE \
 && (!defined _LARGEFILE_SOURCE || defined HAVE_SENDFILE64) \
 && defined(__linux__) && !defined HAVE_SENDFILE_BROKEN
# ifdef NETWORK_WRITE_USE_SENDFILE
#  error "can't have more than one sendfile implementation"
# endif
# define NETWORK_WRITE_USE_SENDFILE "linux-sendfile"
# define NETWORK_WRITE_USE_LINUX_SENDFILE
#endif

#if defined HAVE_SENDFILE && (defined(__FreeBSD__) || defined(__DragonFly__))
# ifdef NETWORK_WRITE_USE_SENDFILE
#  error "can't have more than one sendfile implementation"
# endif
# define NETWORK_WRITE_USE_SENDFILE "freebsd-sendfile"
# define NETWORK_WRITE_USE_FREEBSD_SENDFILE
#endif

#if defined HAVE_SENDFILE && defined(__APPLE__)
# ifdef NETWORK_WRITE_USE_SENDFILE
#  error "can't have more than one sendfile implementation"
# endif
# define NETWORK_WRITE_USE_SENDFILE "darwin-sendfile"
# define NETWORK_WRITE_USE_DARWIN_SENDFILE
#endif

#if defined HAVE_SYS_SENDFILE_H && defined HAVE_SENDFILEV && defined(__sun)
# ifdef NETWORK_WRITE_USE_SENDFILE
#  error "can't have more than one sendfile implementation"
# endif
# define NETWORK_WRITE_USE_SENDFILE "solaris-sendfilev"
# define NETWORK_WRITE_USE_SOLARIS_SENDFILEV
#endif

/* not supported so far
#if defined HAVE_SEND_FILE && defined(__aix)
# ifdef NETWORK_WRITE_USE_SENDFILE
#  error "can't have more than one sendfile implementation"
# endif
# define NETWORK_WRITE_USE_SENDFILE "aix-sendfile"
# define NETWORK_WRITE_USE_AIX_SENDFILE
#endif
*/

#if defined HAVE_SYS_UIO_H && defined HAVE_WRITEV
# define NETWORK_WRITE_USE_WRITEV
#endif

#if defined HAVE_SYS_MMAN_H && defined HAVE_MMAP && defined ENABLE_MMAP
# define NETWORK_WRITE_USE_MMAP
#endif


static int network_write_error(server *srv, int fd) {
  #if defined(__WIN32)
    int lastError = WSAGetLastError();
    switch (lastError) {
      case WSAEINTR:
      case WSAEWOULDBLOCK:
        return -3;
      case WSAECONNRESET:
      case WSAETIMEDOUT:
      case WSAECONNABORTED:
        return -2;
      default:
        log_error_write(srv, __FILE__, __LINE__, "sdd",
                        "send failed: ", lastError, fd);
        return -1;
    }
  #else /* __WIN32 */
    switch (errno) {
      case EAGAIN:
      case EINTR:
        return -3;
      case EPIPE:
        case ECONNRESET:
        return -2;
      default:
        log_error_write(srv, __FILE__, __LINE__, "ssd",
                        "write failed:", strerror(errno), fd);
        return -1;
    }
  #endif /* __WIN32 */
}

inline
static ssize_t network_write_data_len(int fd, const char *data, off_t len) {
  #if defined(__WIN32)
    return send(fd, data, len, 0);
  #else /* __WIN32 */
    return write(fd, data, len);
  #endif /* __WIN32 */
}




/* write next chunk(s); finished chunks are removed afterwards after successful writes.
 * return values: similar as backends (0 succes, -1 error, -2 remote close, -3 try again later (EINTR/EAGAIN)) */
/* next chunk must be MEM_CHUNK. use write()/send() */
static int network_write_mem_chunk(server *srv, int fd, chunkqueue *cq, off_t *p_max_bytes) {
    chunk* const c = cq->first;
    ssize_t wr;
    off_t c_len = (off_t)buffer_string_length(c->mem);
    force_assert(c->offset >= 0 && c->offset <= c_len);
    c_len -= c->offset;
    if (c_len > *p_max_bytes) c_len = *p_max_bytes;

    if (0 == c_len) {
        chunkqueue_remove_finished_chunks(cq);
        return 0;
    }

    wr = network_write_data_len(fd, c->mem->ptr + c->offset, c_len);
    if (wr >= 0) {
        *p_max_bytes -= wr;
        chunkqueue_mark_written(cq, wr);
        return (wr > 0 && wr == c_len) ? 0 : -3;
    } else {
        return network_write_error(srv, fd);
    }
}




#if !defined(NETWORK_WRITE_USE_MMAP)

static int network_write_file_chunk_no_mmap(server *srv, int fd, chunkqueue *cq, off_t *p_max_bytes) {
    chunk* const c = cq->first;
    off_t offset, toSend;
    ssize_t wr;

    force_assert(c->offset >= 0 && c->offset <= c->file.length);

    offset = c->file.start + c->offset;
    toSend = c->file.length - c->offset;
    if (toSend > *p_max_bytes) toSend = *p_max_bytes;

    if (0 == toSend) {
        chunkqueue_remove_finished_chunks(cq);
        return 0;
    }

    if (0 != chunkqueue_open_file_chunk(srv, cq)) return -1;

    if (toSend > 64*1024) toSend = 64*1024; /* max read 64kb in one step */
    buffer_string_prepare_copy(srv->tmp_buf, toSend);

    if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
        log_error_write(srv, __FILE__, __LINE__, "ss","lseek:",strerror(errno));
        return -1;
    }
    if (-1 == (toSend = read(c->file.fd, srv->tmp_buf->ptr, toSend))) {
        log_error_write(srv, __FILE__, __LINE__, "ss","read:",strerror(errno));
        return -1;
    }

    wr = network_write_data_len(fd, srv->tmp_buf->ptr, toSend);
    if (wr >= 0) {
        *p_max_bytes -= wr;
        chunkqueue_mark_written(cq, wr);
        return (wr > 0 && wr == toSend) ? 0 : -3;
    } else {
        return network_write_error(srv, fd);
    }
}

#endif




#if defined(NETWORK_WRITE_USE_MMAP)

#include "sys-mmap.h"

#include <setjmp.h>
#include <signal.h>

#define MMAP_CHUNK_SIZE (512*1024)

static off_t mmap_align_offset(off_t start) {
    static long pagesize = 0;
    if (0 == pagesize) {
        pagesize = sysconf(_SC_PAGESIZE);
        force_assert(pagesize < MMAP_CHUNK_SIZE);
    }
    force_assert(start >= (start % pagesize));
    return start - (start % pagesize);
}

static volatile int sigbus_jmp_valid;
static sigjmp_buf sigbus_jmp;

static void sigbus_handler(int sig) {
    UNUSED(sig);
    if (sigbus_jmp_valid) siglongjmp(sigbus_jmp, 1);
    log_failed_assert(__FILE__, __LINE__, "SIGBUS");
}

/* next chunk must be FILE_CHUNK. send mmap()ed file with write() */
static int network_write_file_chunk_mmap(server *srv, int fd, chunkqueue *cq, off_t *p_max_bytes) {
    chunk* const c = cq->first;
    off_t offset, toSend, file_end;
    ssize_t r;
    size_t mmap_offset, mmap_avail;
    const char *data;

    force_assert(c->offset >= 0 && c->offset <= c->file.length);

    offset = c->file.start + c->offset;
    toSend = c->file.length - c->offset;
    if (toSend > *p_max_bytes) toSend = *p_max_bytes;
    file_end = c->file.start + c->file.length; /*file end offset in this chunk*/

    if (0 == toSend) {
        chunkqueue_remove_finished_chunks(cq);
        return 0;
    }

    if (0 != chunkqueue_open_file_chunk(srv, cq)) return -1;

    /* mmap buffer if offset is outside old mmap area or not mapped at all */
    if (MAP_FAILED == c->file.mmap.start
        || offset < c->file.mmap.offset
        || offset >= (off_t)(c->file.mmap.offset + c->file.mmap.length)) {

        if (MAP_FAILED != c->file.mmap.start) {
            munmap(c->file.mmap.start, c->file.mmap.length);
            c->file.mmap.start = MAP_FAILED;
        }

        /* Optimizations for the future:
         *
         * adaptive mem-mapping
         *   the problem:
         *     we mmap() the whole file. If someone has alot large files and
         *     32-bit machine the virtual address area will be unrun and we
         *     will have a failing mmap() call.
         *   solution:
         *     only mmap 16M in one chunk and move the window as soon as we have
         *     finished the first 8M
         *
         * read-ahead buffering
         *   the problem:
         *     sending out several large files in parallel trashes read-ahead
         *     of the kernel leading to long wait-for-seek times.
         *   solutions: (increasing complexity)
         *     1. use madvise
         *     2. use a internal read-ahead buffer in the chunk-structure
         *     3. use non-blocking IO for file-transfers
         *   */

        c->file.mmap.offset = mmap_align_offset(offset);

        /* all mmap()ed areas are MMAP_CHUNK_SIZE
         * except the last which might be smaller */
        c->file.mmap.length = MMAP_CHUNK_SIZE;
        if (c->file.mmap.offset > file_end - (off_t)c->file.mmap.length) {
            c->file.mmap.length = file_end - c->file.mmap.offset;
        }

        c->file.mmap.start = mmap(NULL, c->file.mmap.length, PROT_READ,
                                  MAP_SHARED, c->file.fd, c->file.mmap.offset);
        if (MAP_FAILED == c->file.mmap.start) {
            log_error_write(srv, __FILE__, __LINE__, "ssbdoo", "mmap failed:",
                            strerror(errno), c->mem, c->file.fd,
                            c->file.mmap.offset, (off_t) c->file.mmap.length);
            return -1;
        }

      #if defined(HAVE_MADVISE)
        /* don't advise files < 64Kb */
        if (c->file.mmap.length > (64*1024)) {
            /* darwin 7 is returning EINVAL all the time and I don't know how to
             * detect this at runtime.
             *
             * ignore the return value for now */
            madvise(c->file.mmap.start, c->file.mmap.length, MADV_WILLNEED);
        }
      #endif
    }

    force_assert(offset >= c->file.mmap.offset);
    mmap_offset = offset - c->file.mmap.offset;
    force_assert(c->file.mmap.length > mmap_offset);
    mmap_avail = c->file.mmap.length - mmap_offset;
    if (toSend > (off_t) mmap_avail) toSend = mmap_avail;

    data = c->file.mmap.start + mmap_offset;

    /* setup SIGBUS handler, but don't activate sigbus_jmp_valid yet */
    if (0 == sigsetjmp(sigbus_jmp, 1)) {
        signal(SIGBUS, sigbus_handler);

        sigbus_jmp_valid = 1;
        r = network_write_data_len(fd, data, toSend);
        sigbus_jmp_valid = 0;
    } else {
        sigbus_jmp_valid = 0;

        log_error_write(srv, __FILE__, __LINE__, "sbd", "SIGBUS in mmap:",
                        c->mem, c->file.fd);

        munmap(c->file.mmap.start, c->file.mmap.length);
        c->file.mmap.start = MAP_FAILED;
        return -1;
    }

    if (r >= 0) {
        *p_max_bytes -= r;
        chunkqueue_mark_written(cq, r);
        return (r > 0 && r == toSend) ? 0 : -3;
    } else {
        return network_write_error(srv, fd);
    }
}

#endif /* NETWORK_WRITE_USE_MMAP */




#if defined(NETWORK_WRITE_USE_WRITEV)

#if defined(HAVE_SYS_UIO_H)
# include <sys/uio.h>
#endif

#if defined(UIO_MAXIOV)
# define SYS_MAX_CHUNKS UIO_MAXIOV
#elif defined(IOV_MAX)
/* new name for UIO_MAXIOV since IEEE Std 1003.1-2001 */
# define SYS_MAX_CHUNKS IOV_MAX
#elif defined(_XOPEN_IOV_MAX)
/* minimum value for sysconf(_SC_IOV_MAX); posix requires this to be at least 16, which is good enough - no need to call sysconf() */
# define SYS_MAX_CHUNKS _XOPEN_IOV_MAX
#else
# error neither UIO_MAXIOV nor IOV_MAX nor _XOPEN_IOV_MAX are defined
#endif

/* allocate iovec[MAX_CHUNKS] on stack, so pick a sane limit:
 * - each entry will use 1 pointer + 1 size_t
 * - 32 chunks -> 256 / 512 bytes (32-bit/64-bit pointers)
 */
#define STACK_MAX_ALLOC_CHUNKS 32
#if SYS_MAX_CHUNKS > STACK_MAX_ALLOC_CHUNKS
# define MAX_CHUNKS STACK_MAX_ALLOC_CHUNKS
#else
# define MAX_CHUNKS SYS_MAX_CHUNKS
#endif

/* next chunk must be MEM_CHUNK. send multiple mem chunks using writev() */
static int network_writev_mem_chunks(server *srv, int fd, chunkqueue *cq, off_t *p_max_bytes) {
    struct iovec chunks[MAX_CHUNKS];
    size_t num_chunks = 0;
    off_t max_bytes = *p_max_bytes;
    off_t toSend = 0;
    ssize_t r;

    for (const chunk *c = cq->first;
         NULL != c && MEM_CHUNK == c->type
           && num_chunks < MAX_CHUNKS && toSend < max_bytes;
         c = c->next) {
        size_t c_len = buffer_string_length(c->mem);
        force_assert(c->offset >= 0 && c->offset <= (off_t)c_len);
        c_len -= c->offset;
        if (c_len > 0) {
            toSend += c_len;

            chunks[num_chunks].iov_base = c->mem->ptr + c->offset;
            chunks[num_chunks].iov_len = c_len;

            ++num_chunks;
        }
    }

    if (0 == num_chunks) {
        chunkqueue_remove_finished_chunks(cq);
        return 0;
    }

    r = writev(fd, chunks, num_chunks);

    if (r < 0) switch (errno) {
      case EAGAIN:
      case EINTR:
        break;
      case EPIPE:
      case ECONNRESET:
        return -2;
      default:
        log_error_write(srv, __FILE__, __LINE__, "ssd",
                        "writev failed:", strerror(errno), fd);
        return -1;
    }

    if (r >= 0) {
        *p_max_bytes -= r;
        chunkqueue_mark_written(cq, r);
    }

    return (r > 0 && r == toSend) ? 0 : -3;
}

#endif /* NETWORK_WRITE_USE_WRITEV */




#if defined(NETWORK_WRITE_USE_SENDFILE)

#if defined(NETWORK_WRITE_USE_LINUX_SENDFILE) \
 || defined(NETWORK_WRITE_USE_SOLARIS_SENDFILEV)
#include <sys/sendfile.h>
#endif

#if defined(NETWORK_WRITE_USE_FREEBSD_SENDFILE) \
 || defined(NETWORK_WRITE_USE_DARWIN_SENDFILE)
#include <sys/uio.h>
#endif

static int network_write_file_chunk_sendfile(server *srv, int fd, chunkqueue *cq, off_t *p_max_bytes) {
    chunk * const c = cq->first;
    ssize_t r;
    off_t offset;
    off_t toSend;
    off_t written = 0;

    force_assert(c->offset >= 0 && c->offset <= c->file.length);

    offset = c->file.start + c->offset;
    toSend = c->file.length - c->offset;
    if (toSend > *p_max_bytes) toSend = *p_max_bytes;

    if (0 == toSend) {
        chunkqueue_remove_finished_chunks(cq);
        return 0;
    }

    if (0 != chunkqueue_open_file_chunk(srv, cq)) return -1;

    /* Darwin, FreeBSD, and Solaris variants support iovecs and could
     * be optimized to send more than just file in single syscall */

  #if defined(NETWORK_WRITE_USE_LINUX_SENDFILE)

    r = sendfile(fd, c->file.fd, &offset, toSend);
    if (r > 0) written = (off_t)r;

  #elif defined(NETWORK_WRITE_USE_DARWIN_SENDFILE)

    written = toSend;
    r = sendfile(c->file.fd, fd, offset, &written, NULL, 0);
    /* (for EAGAIN/EINTR written still contains the sent bytes) */

  #elif defined(NETWORK_WRITE_USE_FREEBSD_SENDFILE)

    r = sendfile(c->file.fd, fd, offset, toSend, NULL, &written, 0);
    /* (for EAGAIN/EINTR written still contains the sent bytes) */

  #elif defined(NETWORK_WRITE_USE_SOLARIS_SENDFILEV)
    {
        sendfilevec_t fvec;
        fvec.sfv_fd = c->file.fd;
        fvec.sfv_flag = 0;
        fvec.sfv_off = offset;
        fvec.sfv_len = toSend;

        /* Solaris sendfilev() */
        r = sendfilev(fd, &fvec, 1, (size_t *)&written);
        /* (for EAGAIN/EINTR written still contains the sent bytes) */
    }
  #else

    r = -1;
    errno = ENOSYS;

  #endif

    if (-1 == r) {
        switch(errno) {
          case EAGAIN:
          case EINTR:
            break; /* try again later */
          case EPIPE:
          case ECONNRESET:
          case ENOTCONN:
            return -2;
          case EINVAL:
          case ENOSYS:
         #if defined(ENOTSUP) && (!defined(EOPNOTSUPP) || EOPNOTSUPP != ENOTSUP)
          case ENOTSUP:
         #endif
         #ifdef EOPNOTSUPP
          case EOPNOTSUPP:
         #endif
         #ifdef ESOCKTNOSUPPORT
          case ESOCKTNOSUPPORT:
         #endif
         #ifdef EAFNOSUPPORT
          case EAFNOSUPPORT:
         #endif
           #ifdef NETWORK_WRITE_USE_MMAP
            return network_write_file_chunk_mmap(srv, fd, cq, p_max_bytes);
           #else
            return network_write_file_chunk_no_mmap(srv, fd, cq, p_max_bytes);
           #endif
          default:
            log_error_write(srv, __FILE__, __LINE__, "ssdSd",
                            "sendfile():", strerror(errno), errno, "fd:", fd);
            return -1;
        }
    }

    if (written >= 0) { /*(always true)*/
        chunkqueue_mark_written(cq, written);
        *p_max_bytes -= written;
    }

    return (r >= 0 && written == toSend) ? 0 : -3;
}

#endif




/* return values:
 * >= 0 : no error
 *   -1 : error (on our side)
 *   -2 : remote close
 */

static int network_write_chunkqueue_write(server *srv, int fd, chunkqueue *cq, off_t max_bytes) {
    while (max_bytes > 0 && NULL != cq->first) {
        int r = -1;

        switch (cq->first->type) {
        case MEM_CHUNK:
            r = network_write_mem_chunk(srv, fd, cq, &max_bytes);
            break;
        case FILE_CHUNK:
          #ifdef NETWORK_WRITE_USE_MMAP
            r = network_write_file_chunk_mmap(srv, fd, cq, &max_bytes);
          #else
            r = network_write_file_chunk_no_mmap(srv, fd, cq, &max_bytes);
          #endif
            break;
        }

        if (-3 == r) return 0;
        if (0 != r) return r;
    }

    return 0;
}

#if defined(NETWORK_WRITE_USE_WRITEV)
static int network_write_chunkqueue_writev(server *srv, int fd, chunkqueue *cq, off_t max_bytes) {
    while (max_bytes > 0 && NULL != cq->first) {
        int r = -1;

        switch (cq->first->type) {
        case MEM_CHUNK:
          #if defined(NETWORK_WRITE_USE_WRITEV)
            r = network_writev_mem_chunks(srv, fd, cq, &max_bytes);
          #else
            r = network_write_mem_chunk(srv, fd, cq, &max_bytes);
          #endif
            break;
        case FILE_CHUNK:
          #ifdef NETWORK_WRITE_USE_MMAP
            r = network_write_file_chunk_mmap(srv, fd, cq, &max_bytes);
          #else
            r = network_write_file_chunk_no_mmap(srv, fd, cq, &max_bytes);
          #endif
            break;
        }

        if (-3 == r) return 0;
        if (0 != r) return r;
    }

    return 0;
}
#endif

#if defined(NETWORK_WRITE_USE_SENDFILE)
static int network_write_chunkqueue_sendfile(server *srv, int fd, chunkqueue *cq, off_t max_bytes) {
    while (max_bytes > 0 && NULL != cq->first) {
        int r = -1;

        switch (cq->first->type) {
        case MEM_CHUNK:
          #if defined(NETWORK_WRITE_USE_WRITEV)
            r = network_writev_mem_chunks(srv, fd, cq, &max_bytes);
          #else
            r = network_write_mem_chunk(srv, fd, cq, &max_bytes);
          #endif
            break;
        case FILE_CHUNK:
          #if defined(NETWORK_WRITE_USE_SENDFILE)
            r = network_write_file_chunk_sendfile(srv, fd, cq, &max_bytes);
          #elif defined(NETWORK_WRITE_USE_MMAP)
            r = network_write_file_chunk_mmap(srv, fd, cq, &max_bytes);
          #else
            r = network_write_file_chunk_no_mmap(srv, fd, cq, &max_bytes);
          #endif
            break;
        }

        if (-3 == r) return 0;
        if (0 != r) return r;
    }

    return 0;
}
#endif

int network_write_init(server *srv) {
    typedef enum {
        NETWORK_BACKEND_UNSET,
        NETWORK_BACKEND_WRITE,
        NETWORK_BACKEND_WRITEV,
        NETWORK_BACKEND_SENDFILE,
    } network_backend_t;

    network_backend_t backend;

    struct nb_map {
        network_backend_t nb;
        const char *name;
    } network_backends[] = {
        /* lowest id wins */
        { NETWORK_BACKEND_SENDFILE, "sendfile" },
        { NETWORK_BACKEND_SENDFILE, "linux-sendfile" },
        { NETWORK_BACKEND_SENDFILE, "freebsd-sendfile" },
        { NETWORK_BACKEND_SENDFILE, "solaris-sendfilev" },
        { NETWORK_BACKEND_WRITEV,   "writev" },
        { NETWORK_BACKEND_WRITE,    "write" },
        { NETWORK_BACKEND_UNSET,    NULL }
    };

    /* get a useful default */
    backend = network_backends[0].nb;

    /* match name against known types */
    if (!buffer_string_is_empty(srv->srvconf.network_backend)) {
        const char *name;
        for (size_t i = 0; NULL != (name = network_backends[i].name); ++i) {
            if (0 == strcmp(srv->srvconf.network_backend->ptr, name)) {
                backend = network_backends[i].nb;
                break;
            }
        }
        if (NULL == name) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "server.network-backend has an unknown value:",
                            srv->srvconf.network_backend);
            return -1;
        }
    }

    switch(backend) {
    case NETWORK_BACKEND_SENDFILE:
      #if defined(NETWORK_WRITE_USE_SENDFILE)
        srv->network_backend_write = network_write_chunkqueue_sendfile;
        break;
      #endif
    case NETWORK_BACKEND_WRITEV:
      #if defined(NETWORK_WRITE_USE_WRITEV)
        srv->network_backend_write = network_write_chunkqueue_writev;
        break;
      #endif
    case NETWORK_BACKEND_WRITE:
        srv->network_backend_write = network_write_chunkqueue_write;
        break;
    default:
        return -1;
    }

    return 0;
}

const char * network_write_show_handlers(void) {
    return
      "\nNetwork handler:\n\n"
     #if defined NETWORK_WRITE_USE_LINUX_SENDFILE
      "\t+ linux-sendfile\n"
     #else
      "\t- linux-sendfile\n"
     #endif
     #if defined NETWORK_WRITE_USE_FREEBSD_SENDFILE
      "\t+ freebsd-sendfile\n"
     #else
      "\t- freebsd-sendfile\n"
     #endif
     #if defined NETWORK_WRITE_USE_DARWIN_SENDFILE
      "\t+ darwin-sendfile\n"
     #else
      "\t- darwin-sendfile\n"
     #endif
     #if defined NETWORK_WRITE_USE_SOLARIS_SENDFILEV
      "\t+ solaris-sendfilev\n"
     #else
      "\t- solaris-sendfilev\n"
     #endif
     #if defined NETWORK_WRITE_USE_WRITEV
      "\t+ writev\n"
     #else
      "\t- writev\n"
     #endif
      "\t+ write\n"
     #ifdef NETWORK_WRITE_USE_MMAP
      "\t+ mmap support\n"
     #else
      "\t- mmap support\n"
     #endif
      ;
}
