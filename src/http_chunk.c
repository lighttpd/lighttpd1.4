#include "first.h"

/**
 * the HTTP chunk-API
 *
 *
 */

#include "base.h"
#include "chunk.h"
#include "http_chunk.h"
#include "stat_cache.h"
#include "fdevent.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>

static buffer * http_chunk_header(buffer *b, uintmax_t len) {
    buffer_clear(b);
    buffer_append_uint_hex(b, len);
    buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
    return b;
}

static void http_chunk_append_len(server *srv, connection *con, uintmax_t len) {
    buffer *b = http_chunk_header(srv->tmp_chunk_len, len);
    chunkqueue_append_mem(con->write_queue, CONST_BUF_LEN(b));
}

static int http_chunk_append_file_open_fstat(server *srv, connection *con, buffer *fn, struct stat *st) {
	if (!con->conf.follow_symlink
	    && 0 != stat_cache_path_contains_symlink(srv, fn)) {
		return -1;
	}

	return stat_cache_open_rdonly_fstat(fn, st, con->conf.follow_symlink);
}

static int http_chunk_append_read_fd_range(server *srv, connection *con, buffer *fn, int fd, off_t offset, off_t len) {
    /* note: this routine should not be used for range requests
     * unless the total size of ranges requested is small */
    /* note: future: could read into existing MEM_CHUNK in cq->last if
     * there is sufficient space, but would need to adjust for existing
     * offset in for cq->bytes_in in chunkqueue_append_buffer_commit() */
    UNUSED(fn);

    if (con->response.send_chunked) {
        http_chunk_append_len(srv, con, (uintmax_t)len);
    }

    if (0 != offset && -1 == lseek(fd, offset, SEEK_SET)) return -1;
    chunkqueue * const cq = con->write_queue;
    buffer * const b = chunkqueue_append_buffer_open_sz(cq, len+2);
    ssize_t rd;
    offset = 0;
    do {
        rd = read(fd, b->ptr+offset, len-offset);
    } while (rd > 0 ? (offset += rd, len -= rd) : errno == EINTR);
    buffer_commit(b, offset);

    if (con->response.send_chunked) {
        buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
    }

    chunkqueue_append_buffer_commit(cq);
    return (rd >= 0) ? 0 : -1;
}

static void http_chunk_append_file_fd_range(server *srv, connection *con, buffer *fn, int fd, off_t offset, off_t len) {
	chunkqueue *cq = con->write_queue;

	if (con->response.send_chunked) {
		http_chunk_append_len(srv, con, (uintmax_t)len);
	}

	chunkqueue_append_file_fd(cq, fn, fd, offset, len);

	if (con->response.send_chunked) {
		chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
	}
}

int http_chunk_append_file_range(server *srv, connection *con, buffer *fn, off_t offset, off_t len) {
	struct stat st;
	const int fd = http_chunk_append_file_open_fstat(srv, con, fn, &st);
	if (fd < 0) return -1;

	if (-1 == len) {
		if (offset >= st.st_size) {
			close(fd);
			return (offset == st.st_size) ? 0 : -1;
		}
		len = st.st_size - offset;
	} else if (st.st_size - offset < len) {
		close(fd);
		return -1;
	}

	http_chunk_append_file_fd_range(srv, con, fn, fd, offset, len);
	return 0;
}

int http_chunk_append_file(server *srv, connection *con, buffer *fn) {
	struct stat st;
	const int fd = http_chunk_append_file_open_fstat(srv, con, fn, &st);
	if (fd < 0) return -1;
	http_chunk_append_file_fd(srv, con, fn, fd, st.st_size);
	return 0;
}

int http_chunk_append_file_fd(server *srv, connection *con, buffer *fn, int fd, off_t sz) {
	if (sz > 32768) {
		http_chunk_append_file_fd_range(srv, con, fn, fd, 0, sz);
		return 0;
	} else {
		int rc = (0 != sz) /*(read small files into memory)*/
		  ? http_chunk_append_read_fd_range(srv, con, fn, fd, 0, sz)
		  : 0;
		close(fd);
		return rc;
	}
}

static int http_chunk_append_to_tempfile(server *srv, connection *con, const char * mem, size_t len) {
	chunkqueue * const cq = con->write_queue;

	if (con->response.send_chunked) {
		buffer *b = http_chunk_header(srv->tmp_chunk_len, len);
		if (0 != chunkqueue_append_mem_to_tempfile(srv, cq, CONST_BUF_LEN(b))) {
			return -1;
		}
	}

	if (0 != chunkqueue_append_mem_to_tempfile(srv, cq, mem, len)) {
		return -1;
	}

	if (con->response.send_chunked) {
		if (0 != chunkqueue_append_mem_to_tempfile(srv, cq, CONST_STR_LEN("\r\n"))) {
			return -1;
		}
	}

	return 0;
}

static int http_chunk_append_cq_to_tempfile(server *srv, connection *con, chunkqueue *src, size_t len) {
    chunkqueue * const cq = con->write_queue;

    if (con->response.send_chunked) {
        buffer *b = http_chunk_header(srv->tmp_chunk_len, len);
        if (0 != chunkqueue_append_mem_to_tempfile(srv, cq, CONST_BUF_LEN(b))) {
            return -1;
        }
    }

    if (0 != chunkqueue_steal_with_tempfiles(srv, cq, src, len)) {
        return -1;
    }

    if (con->response.send_chunked) {
        if (0!=chunkqueue_append_mem_to_tempfile(srv,cq,CONST_STR_LEN("\r\n"))){
            return -1;
        }
    }

    return 0;
}

static int http_chunk_uses_tempfile(server *srv, connection *con, size_t len) {
	chunkqueue * const cq = con->write_queue;
	chunk *c = cq->last;
	UNUSED(srv);

	/* current usage does not append_mem or append_buffer after appending
	 * file, so not checking if users of this interface have appended large
	 * (references to) files to chunkqueue, which would not be in memory
	 * (but included in calculation for whether or not to use temp file) */

	/*(allow slightly larger mem use if FDEVENT_STREAM_RESPONSE_BUFMIN
	 * to reduce creation of temp files when backend producer will be
	 * blocked until more data is sent to network to client)*/

	if ((c && c->type == FILE_CHUNK && c->file.is_temp)
	    || cq->bytes_in - cq->bytes_out + len
		> 1024 * ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN) ? 128 : 64)) {
		return 1;
	}

	return 0;
}

int http_chunk_append_buffer(server *srv, connection *con, buffer *mem) {
    chunkqueue * const cq = con->write_queue;
    size_t len = buffer_string_length(mem);
    if (0 == len) return 0;

    if (http_chunk_uses_tempfile(srv, con, len)) {
        return http_chunk_append_to_tempfile(srv, con, mem->ptr, len);
    }

    if (con->response.send_chunked) {
        http_chunk_append_len(srv, con, len);
    }

    /*(chunkqueue_append_buffer() might steal buffer contents)*/
    chunkqueue_append_buffer(cq, mem);

    if (con->response.send_chunked) {
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
    }

    return 0;
}

int http_chunk_append_mem(server *srv, connection *con, const char * mem, size_t len) {
    chunkqueue * const cq = con->write_queue;
    if (0 == len) return 0;
    force_assert(NULL != mem);

    if (http_chunk_uses_tempfile(srv, con, len)) {
        return http_chunk_append_to_tempfile(srv, con, mem, len);
    }

    if (con->response.send_chunked) {
        http_chunk_append_len(srv, con, len);
    }

    chunkqueue_append_mem(cq, mem, len);

    if (con->response.send_chunked) {
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
    }

    return 0;
}

int http_chunk_transfer_cqlen(server *srv, connection *con, chunkqueue *src, size_t len) {
    chunkqueue * const cq = con->write_queue;
    if (0 == len) return 0;

    if (http_chunk_uses_tempfile(srv, con, len)) {
        return http_chunk_append_cq_to_tempfile(srv, con, src, len);
    }

    if (con->response.send_chunked) {
        http_chunk_append_len(srv, con, len);
    }

    chunkqueue_steal(cq, src, len);

    if (con->response.send_chunked) {
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
    }

    return 0;
}

void http_chunk_close(server *srv, connection *con) {
	UNUSED(srv);
	force_assert(NULL != con);

	if (con->response.send_chunked) {
		chunkqueue_append_mem(con->write_queue, CONST_STR_LEN("0\r\n\r\n"));
	}
}
