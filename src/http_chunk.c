/**
 * the HTTP chunk-API
 *
 *
 */

#include "server.h"
#include "chunk.h"
#include "http_chunk.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

static void http_chunk_append_len(server *srv, connection *con, size_t len) {
	size_t i, olen = len, j;
	buffer *b;

	force_assert(NULL != srv);

	b = srv->tmp_chunk_len;

	if (len == 0) {
		buffer_copy_string_len(b, CONST_STR_LEN("0\r\n"));
	} else {
		for (i = 0; i < 8 && len; i++) {
			len >>= 4;
		}

		/* i is the number of hex digits we have */
		buffer_prepare_copy(b, i + 2);

		for (j = i-1, len = olen; j+1 > 0; j--) {
			b->ptr[j] = (len & 0xf) + (((len & 0xf) <= 9) ? '0' : 'a' - 10);
			len >>= 4;
		}
		b->used = i;
		b->ptr[b->used++] = '\0';

		buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
	}

	chunkqueue_append_buffer(con->write_queue, b);
}


void http_chunk_append_file(server *srv, connection *con, buffer *fn, off_t offset, off_t len) {
	chunkqueue *cq;

	force_assert(NULL != con);
	if (0 == len) return;

	cq = con->write_queue;


	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		http_chunk_append_len(srv, con, len);
	}

	chunkqueue_append_file(cq, fn, offset, len);

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
	}
}

void http_chunk_append_buffer(server *srv, connection *con, buffer *mem) {
	chunkqueue *cq;

	force_assert(NULL != con);

	if (buffer_string_is_empty(mem)) return;

	cq = con->write_queue;

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		http_chunk_append_len(srv, con, mem->used - 1);
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
