#include "first.h"

/**
 * the HTTP chunk-API
 *
 *
 */

#include "server.h"
#include "chunk.h"
#include "http_chunk.h"
#include "stat_cache.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

static void http_chunk_append_len(server *srv, connection *con, uintmax_t len) {
	buffer *b;

	force_assert(NULL != srv);

	b = srv->tmp_chunk_len;

	buffer_string_set_length(b, 0);
	buffer_append_uint_hex(b, len);
	buffer_append_string_len(b, CONST_STR_LEN("\r\n"));

	chunkqueue_append_buffer(con->write_queue, b);
}

static int http_chunk_append_file_open_fstat(server *srv, connection *con, buffer *fn, struct stat *st) {
	if (!con->conf.follow_symlink) {
		/*(preserve existing stat_cache symlink checks)*/
		stat_cache_entry *sce;
		if (HANDLER_ERROR == stat_cache_get_entry(srv, con, fn, &sce)) return -1;
	}

	return stat_cache_open_rdonly_fstat(srv, con, fn, st);
}

static void http_chunk_append_file_fd_range(server *srv, connection *con, buffer *fn, int fd, off_t offset, off_t len) {
	chunkqueue *cq = con->write_queue;

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		http_chunk_append_len(srv, con, (uintmax_t)len);
	}

	chunkqueue_append_file_fd(cq, fn, fd, offset, len);

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
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

	if (0 != st.st_size) {
		http_chunk_append_file_fd_range(srv, con, fn, fd, 0, st.st_size);
	} else {
		close(fd);
	}
	return 0;
}

void http_chunk_append_buffer(server *srv, connection *con, buffer *mem) {
	chunkqueue *cq;

	force_assert(NULL != con);

	if (buffer_string_is_empty(mem)) return;

	cq = con->write_queue;

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		http_chunk_append_len(srv, con, buffer_string_length(mem));
	}

	chunkqueue_append_buffer(cq, mem);

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
	}
}

void http_chunk_append_mem(server *srv, connection *con, const char * mem, size_t len) {
	chunkqueue *cq;

	force_assert(NULL != con);
	force_assert(NULL != mem || 0 == len);

	if (NULL == mem || 0 == len) return;

	cq = con->write_queue;

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		http_chunk_append_len(srv, con, len);
	}

	chunkqueue_append_mem(cq, mem, len);

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
	}
}

void http_chunk_close(server *srv, connection *con) {
	UNUSED(srv);
	force_assert(NULL != con);

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		chunkqueue_append_mem(con->write_queue, CONST_STR_LEN("0\r\n\r\n"));
	}
}
