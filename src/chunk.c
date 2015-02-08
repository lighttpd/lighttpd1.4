/**
 * the network chunk-API
 *
 *
 */

#include "chunk.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

chunkqueue *chunkqueue_init(void) {
	chunkqueue *cq;

	cq = calloc(1, sizeof(*cq));

	cq->first = NULL;
	cq->last = NULL;

	cq->unused = NULL;

	return cq;
}

static chunk *chunk_init(void) {
	chunk *c;

	c = calloc(1, sizeof(*c));

	c->type = MEM_CHUNK;
	c->mem = buffer_init();
	c->file.name = buffer_init();
	c->file.start = c->file.length = c->file.mmap.offset = 0;
	c->file.fd = -1;
	c->file.mmap.start = MAP_FAILED;
	c->file.mmap.length = 0;
	c->file.is_temp = 0;
	c->offset = 0;
	c->next = NULL;

	return c;
}

static void chunk_reset(chunk *c) {
	if (NULL == c) return;

	c->type = MEM_CHUNK;

	buffer_reset(c->mem);

	if (c->file.is_temp && !buffer_string_is_empty(c->file.name)) {
		unlink(c->file.name->ptr);
	}

	buffer_reset(c->file.name);

	if (c->file.fd != -1) {
		close(c->file.fd);
		c->file.fd = -1;
	}
	if (MAP_FAILED != c->file.mmap.start) {
		munmap(c->file.mmap.start, c->file.mmap.length);
		c->file.mmap.start = MAP_FAILED;
	}
	c->file.start = c->file.length = c->file.mmap.offset = 0;
	c->file.mmap.length = 0;
	c->file.is_temp = 0;
	c->offset = 0;
	c->next = NULL;
}

static void chunk_free(chunk *c) {
	if (NULL == c) return;

	chunk_reset(c);

	buffer_free(c->mem);
	buffer_free(c->file.name);

	free(c);
}

void chunkqueue_free(chunkqueue *cq) {
	chunk *c, *pc;

	if (NULL == cq) return;

	for (c = cq->first; c; ) {
		pc = c;
		c = c->next;
		chunk_free(pc);
	}

	for (c = cq->unused; c; ) {
		pc = c;
		c = c->next;
		chunk_free(pc);
	}

	free(cq);
}

static void chunkqueue_push_unused_chunk(chunkqueue *cq, chunk *c) {
	force_assert(NULL != cq && NULL != c);

	/* keep at max 4 chunks in the 'unused'-cache */
	if (cq->unused_chunks > 4) {
		chunk_free(c);
	} else {
		chunk_reset(c);
		c->next = cq->unused;
		cq->unused = c;
		cq->unused_chunks++;
	}
}

static chunk *chunkqueue_get_unused_chunk(chunkqueue *cq) {
	chunk *c;

	force_assert(NULL != cq);

	/* check if we have a unused chunk */
	if (0 == cq->unused) {
		c = chunk_init();
	} else {
		/* take the first element from the list (a stack) */
		c = cq->unused;
		cq->unused = c->next;
		c->next = NULL;
		cq->unused_chunks--;
	}

	return c;
}

static void chunkqueue_prepend_chunk(chunkqueue *cq, chunk *c) {
	c->next = cq->first;
	cq->first = c;

	if (NULL == cq->last) {
		cq->last = c;
	}
}

static void chunkqueue_append_chunk(chunkqueue *cq, chunk *c) {
	if (cq->last) {
		cq->last->next = c;
	}
	cq->last = c;

	if (NULL == cq->first) {
		cq->first = c;
	}
}

void chunkqueue_reset(chunkqueue *cq) {
	chunk *cur = cq->first;

	cq->first = cq->last = NULL;

	while (NULL != cur) {
		chunk *next = cur->next;
		chunkqueue_push_unused_chunk(cq, cur);
		cur = next;
	}

	cq->bytes_in = 0;
	cq->bytes_out = 0;
}

void chunkqueue_append_file(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
	chunk *c;

	if (0 == len) return;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = FILE_CHUNK;

	buffer_copy_buffer(c->file.name, fn);
	c->file.start = offset;
	c->file.length = len;
	c->offset = 0;

	chunkqueue_append_chunk(cq, c);
}

void chunkqueue_append_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (buffer_string_is_empty(mem)) return;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	force_assert(NULL != c->mem);
	buffer_move(c->mem, mem);

	chunkqueue_append_chunk(cq, c);
}

void chunkqueue_prepend_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (buffer_string_is_empty(mem)) return;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	force_assert(NULL != c->mem);
	buffer_move(c->mem, mem);

	chunkqueue_prepend_chunk(cq, c);
}


void chunkqueue_append_mem(chunkqueue *cq, const char * mem, size_t len) {
	chunk *c;

	if (0 == len) return;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	buffer_copy_string_len(c->mem, mem, len);

	chunkqueue_append_chunk(cq, c);
}

buffer * chunkqueue_get_prepend_buffer(chunkqueue *cq) {
	chunk *c;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = MEM_CHUNK;

	chunkqueue_prepend_chunk(cq, c);

	return c->mem;
}

buffer *chunkqueue_get_append_buffer(chunkqueue *cq) {
	chunk *c;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = MEM_CHUNK;

	chunkqueue_append_chunk(cq, c);

	return c->mem;
}

void chunkqueue_set_tempdirs(chunkqueue *cq, array *tempdirs) {
	force_assert(NULL != cq);
	cq->tempdirs = tempdirs;
}

chunk *chunkqueue_get_append_tempfile(chunkqueue *cq) {
	chunk *c;
	buffer *template = buffer_init_string("/var/tmp/lighttpd-upload-XXXXXX");

	c = chunkqueue_get_unused_chunk(cq);

	c->type = FILE_CHUNK;

	if (cq->tempdirs && cq->tempdirs->used) {
		size_t i;

		/* we have several tempdirs, only if all of them fail we jump out */

		for (i = 0; i < cq->tempdirs->used; i++) {
			data_string *ds = (data_string *)cq->tempdirs->data[i];

			buffer_copy_buffer(template, ds->value);
			buffer_append_slash(template);
			buffer_append_string_len(template, CONST_STR_LEN("lighttpd-upload-XXXXXX"));

			if (-1 != (c->file.fd = mkstemp(template->ptr))) {
				/* only trigger the unlink if we created the temp-file successfully */
				c->file.is_temp = 1;
				break;
			}
		}
	} else {
		if (-1 != (c->file.fd = mkstemp(template->ptr))) {
			/* only trigger the unlink if we created the temp-file successfully */
			c->file.is_temp = 1;
		}
	}

	buffer_copy_buffer(c->file.name, template);
	c->file.length = 0;

	chunkqueue_append_chunk(cq, c);

	buffer_free(template);

	return c;
}

void chunkqueue_steal(chunkqueue *dest, chunkqueue *src, off_t len) {
	while (len > 0) {
		chunk *c = src->first;
		off_t clen = 0;

		if (NULL == c) break;

		switch (c->type) {
		case MEM_CHUNK:
			clen = buffer_string_length(c->mem);
			break;
		case FILE_CHUNK:
			clen = c->file.length;
			break;
		}
		force_assert(clen >= c->offset);
		clen -= c->offset;

		if (len >= clen) {
			/* move complete chunk */
			src->first = c->next;
			if (c == src->last) src->last = NULL;

			chunkqueue_append_chunk(dest, c);
			src->bytes_out += clen;
			dest->bytes_in += clen;
			len -= clen;
			continue;
		}

		/* partial chunk with length "len" */

		switch (c->type) {
		case MEM_CHUNK:
			chunkqueue_append_mem(dest, c->mem->ptr + c->offset, len);
			break;
		case FILE_CHUNK:
			/* tempfile flag is in "last" chunk after the split */
			chunkqueue_append_file(dest, c->file.name, c->file.start + c->offset, len);
			break;
		}

		c->offset += len;
		src->bytes_out += len;
		dest->bytes_in += len;
		len = 0;
	}
}

off_t chunkqueue_length(chunkqueue *cq) {
	off_t len = 0;
	chunk *c;

	for (c = cq->first; c; c = c->next) {
		off_t c_len = 0;

		switch (c->type) {
		case MEM_CHUNK:
			c_len = buffer_string_length(c->mem);
			break;
		case FILE_CHUNK:
			c_len = c->file.length;
			break;
		}
		force_assert(c_len >= c->offset);
		len += c_len - c->offset;
	}

	return len;
}

int chunkqueue_is_empty(chunkqueue *cq) {
	return NULL == cq->first;
}

void chunkqueue_remove_finished_chunks(chunkqueue *cq) {
	chunk *c;

	for (c = cq->first; c; c = cq->first) {
		off_t c_len = 0;

		switch (c->type) {
		case MEM_CHUNK:
			c_len = buffer_string_length(c->mem);
			break;
		case FILE_CHUNK:
			c_len = c->file.length;
			break;
		}
		force_assert(c_len >= c->offset);

		if (c_len > c->offset) break; /* not finished yet */

		cq->first = c->next;
		if (c == cq->last) cq->last = NULL;

		chunkqueue_push_unused_chunk(cq, c);
	}
}
