#include "first.h"

/**
 * the HTTP chunk-API
 *
 *
 */

#include "http_chunk.h"
#include "base.h"
#include "chunk.h"
#include "stat_cache.h"
#include "fdevent.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>

static void http_chunk_len_append(chunkqueue * const cq, uintmax_t len) {
    char buf[24]; /* 64-bit (8 bytes) is 16 hex chars (+2 \r\n, +1 \0 = 19) */
  #if 0
    buffer b = { buf, 0, sizeof(buf) };
    buffer_append_uint_hex(&b, len);
    buffer_append_string_len(&b, CONST_STR_LEN("\r\n"));
    chunkqueue_append_mem(cq, b.ptr, b.used-1);
  #else
    int i = (int)(sizeof(buf));
    buf[--i] = '\n';
    buf[--i] = '\r';
    do { buf[--i] = "0123456789abcdef"[len & 0x0F]; } while (len >>= 4);
    chunkqueue_append_mem(cq, buf+i, sizeof(buf)-i);
  #endif
}

static int http_chunk_len_append_tempfile(chunkqueue * const cq, uintmax_t len, log_error_st * const errh) {
    char buf[24]; /* 64-bit (8 bytes) is 16 hex chars (+2 \r\n, +1 \0 = 19) */
  #if 0
    buffer b = { buf, 0, sizeof(buf) };
    buffer_append_uint_hex(&b, len);
    buffer_append_string_len(&b, CONST_STR_LEN("\r\n"));
    return chunkqueue_append_mem_to_tempfile(cq, b.ptr, b.used-1, errh);
  #else
    int i = (int)(sizeof(buf));
    buf[--i] = '\n';
    buf[--i] = '\r';
    do { buf[--i] = "0123456789abcdef"[len & 0x0F]; } while (len >>= 4);
    return chunkqueue_append_mem_to_tempfile(cq, buf+i, sizeof(buf)-i, errh);
  #endif
}

static int http_chunk_append_file_open_fstat(connection * const con, const buffer * const fn, struct stat * const st) {
    return
      (con->conf.follow_symlink
       || !stat_cache_path_contains_symlink(fn, con->conf.errh))
        ? stat_cache_open_rdonly_fstat(fn, st, con->conf.follow_symlink)
        : -1;
}

static int http_chunk_append_read_fd_range(connection * const con, const buffer * const fn, const int fd, off_t offset, off_t len) {
    /* note: this routine should not be used for range requests
     * unless the total size of ranges requested is small */
    /* note: future: could read into existing MEM_CHUNK in cq->last if
     * there is sufficient space, but would need to adjust for existing
     * offset in for cq->bytes_in in chunkqueue_append_buffer_commit() */
    UNUSED(fn);

    chunkqueue * const cq = con->write_queue;

    if (con->response.send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    if (0 != offset && -1 == lseek(fd, offset, SEEK_SET)) return -1;
    buffer * const b = chunkqueue_append_buffer_open_sz(cq, len+2);
    ssize_t rd;
    offset = 0;
    do {
        rd = read(fd, b->ptr+offset, len-offset);
    } while (rd > 0 ? (offset += rd, len -= rd) : errno == EINTR);
    buffer_commit(b, offset);

    if (con->response.send_chunked)
        buffer_append_string_len(b, CONST_STR_LEN("\r\n"));

    chunkqueue_append_buffer_commit(cq);
    return (rd >= 0) ? 0 : -1;
}

static void http_chunk_append_file_fd_range(connection * const con, const buffer * const fn, const int fd, const off_t offset, const off_t len) {
    chunkqueue * const cq = con->write_queue;

    if (con->response.send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    chunkqueue_append_file_fd(cq, fn, fd, offset, len);

    if (con->response.send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
}

int http_chunk_append_file_range(connection * const con, const buffer * const fn, const off_t offset, off_t len) {
    struct stat st;
    const int fd = http_chunk_append_file_open_fstat(con, fn, &st);
    if (fd < 0) return -1;

    if (-1 == len) {
        if (offset >= st.st_size) {
            close(fd);
            return (offset == st.st_size) ? 0 : -1;
        }
        len = st.st_size - offset;
    }
    else if (st.st_size - offset < len) {
        close(fd);
        return -1;
    }

    http_chunk_append_file_fd_range(con, fn, fd, offset, len);
    return 0;
}

int http_chunk_append_file(connection * const con, const buffer * const fn) {
    struct stat st;
    const int fd = http_chunk_append_file_open_fstat(con, fn, &st);
    if (fd < 0) return -1;
    http_chunk_append_file_fd(con, fn, fd, st.st_size);
    return 0;
}

int http_chunk_append_file_fd(connection * const con, const buffer * const fn, const int fd, const off_t sz) {
    if (sz > 32768) {
        http_chunk_append_file_fd_range(con, fn, fd, 0, sz);
        return 0;
    }

    /*(read small files into memory)*/
    int rc = (0 != sz) ? http_chunk_append_read_fd_range(con,fn,fd,0,sz) : 0;
    close(fd);
    return rc;
}

static int http_chunk_append_to_tempfile(connection * const con, const char * const mem, const size_t len) {
    chunkqueue * const cq = con->write_queue;
    log_error_st * const errh = con->conf.errh;

    if (con->response.send_chunked
        && 0 != http_chunk_len_append_tempfile(cq, len, errh))
        return -1;

    if (0 != chunkqueue_append_mem_to_tempfile(cq, mem, len, errh))
        return -1;

    if (con->response.send_chunked
        && 0 !=
           chunkqueue_append_mem_to_tempfile(cq, CONST_STR_LEN("\r\n"), errh))
        return -1;

    return 0;
}

static int http_chunk_append_cq_to_tempfile(connection * const con, chunkqueue * const src, const size_t len) {
    chunkqueue * const cq = con->write_queue;
    log_error_st * const errh = con->conf.errh;

    if (con->response.send_chunked
        && 0 != http_chunk_len_append_tempfile(cq, len, errh))
        return -1;

    if (0 != chunkqueue_steal_with_tempfiles(cq, src, len, errh))
        return -1;

    if (con->response.send_chunked
        && 0 !=
           chunkqueue_append_mem_to_tempfile(cq, CONST_STR_LEN("\r\n"), errh))
        return -1;

    return 0;
}

__attribute_pure__
static int http_chunk_uses_tempfile(const connection * const con, const chunkqueue * const cq, const size_t len) {

    /* current usage does not append_mem or append_buffer after appending
     * file, so not checking if users of this interface have appended large
     * (references to) files to chunkqueue, which would not be in memory
     * (but included in calculation for whether or not to use temp file) */

    /*(allow slightly larger mem use if FDEVENT_STREAM_RESPONSE_BUFMIN
     * to reduce creation of temp files when backend producer will be
     * blocked until more data is sent to network to client)*/

    const chunk * const c = cq->last;
    return
      ((c && c->type == FILE_CHUNK && c->file.is_temp)
       || cq->bytes_in - cq->bytes_out + len
          > ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
             ? 128*1024
             :  64*1024));
}

int http_chunk_append_buffer(connection * const con, buffer * const mem) {
    size_t len = buffer_string_length(mem);
    if (0 == len) return 0;

    chunkqueue * const cq = con->write_queue;

    if (http_chunk_uses_tempfile(con, cq, len))
        return http_chunk_append_to_tempfile(con, mem->ptr, len);

    if (con->response.send_chunked)
        http_chunk_len_append(cq, len);

    /*(chunkqueue_append_buffer() might steal buffer contents)*/
    chunkqueue_append_buffer(cq, mem);

    if (con->response.send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

int http_chunk_append_mem(connection * const con, const char * const mem, const size_t len) {
    if (0 == len) return 0;
    force_assert(NULL != mem);

    chunkqueue * const cq = con->write_queue;

    if (http_chunk_uses_tempfile(con, cq, len))
        return http_chunk_append_to_tempfile(con, mem, len);

    if (con->response.send_chunked)
        http_chunk_len_append(cq, len);

    chunkqueue_append_mem(cq, mem, len);

    if (con->response.send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

int http_chunk_transfer_cqlen(connection * const con, chunkqueue * const src, const size_t len) {
    if (0 == len) return 0;

    chunkqueue * const cq = con->write_queue;

    if (http_chunk_uses_tempfile(con, cq, len))
        return http_chunk_append_cq_to_tempfile(con, src, len);

    if (con->response.send_chunked)
        http_chunk_len_append(cq, len);

    chunkqueue_steal(cq, src, len);

    if (con->response.send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

void http_chunk_close(connection * const con) {
    if (con->response.send_chunked)
        chunkqueue_append_mem(con->write_queue, CONST_STR_LEN("0\r\n\r\n"));
}
