#include "first.h"

/**
 * the network chunk-API
 *
 *
 */

#include "chunk.h"
#include "fdevent.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-mmap.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>

/* default 1MB, upper limit 128MB */
#define DEFAULT_TEMPFILE_SIZE (1 * 1024 * 1024)
#define MAX_TEMPFILE_SIZE (128 * 1024 * 1024)

static size_t chunk_buf_sz = 4096;
static chunk *chunks;
static chunk *chunk_buffers;
static array *chunkqueue_default_tempdirs = NULL;
static unsigned int chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;

void chunkqueue_set_chunk_size (size_t sz)
{
    chunk_buf_sz = sz > 0 ? ((sz + 1023) & ~1023uL) : 4096;
}

void chunkqueue_set_tempdirs_default_reset (void)
{
    chunkqueue_default_tempdirs = NULL;
    chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;
}

chunkqueue *chunkqueue_init(void) {
	chunkqueue *cq;

	cq = calloc(1, sizeof(*cq));
	force_assert(NULL != cq);

	cq->first = NULL;
	cq->last = NULL;

	cq->tempdirs              = chunkqueue_default_tempdirs;
	cq->upload_temp_file_size = chunkqueue_default_tempfile_size;

	return cq;
}

static chunk *chunk_init(size_t sz) {
	chunk *c;

	c = calloc(1, sizeof(*c));
	force_assert(NULL != c);

	c->type = MEM_CHUNK;
	c->mem = buffer_init();
	c->file.start = c->file.length = c->file.mmap.offset = 0;
	c->file.fd = -1;
	c->file.mmap.start = MAP_FAILED;
	c->file.mmap.length = 0;
	c->file.is_temp = 0;
	c->offset = 0;
	c->next = NULL;

	buffer_string_prepare_copy(c->mem, sz-1);

	return c;
}

static void chunk_reset_file_chunk(chunk *c) {
	if (c->file.is_temp && !buffer_string_is_empty(c->mem)) {
		unlink(c->mem->ptr);
	}
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
	c->type = MEM_CHUNK;
}

static void chunk_reset(chunk *c) {
	if (c->type == FILE_CHUNK) chunk_reset_file_chunk(c);

	buffer_clear(c->mem);
	c->offset = 0;
}

static void chunk_free(chunk *c) {
	if (c->type == FILE_CHUNK) chunk_reset_file_chunk(c);
	buffer_free(c->mem);
	free(c);
}

buffer * chunk_buffer_acquire(void) {
    chunk *c;
    buffer *b;
    if (chunks) {
        c = chunks;
        chunks = c->next;
    }
    else {
        c = chunk_init(chunk_buf_sz);
    }
    c->next = chunk_buffers;
    chunk_buffers = c;
    b = c->mem;
    c->mem = NULL;
    return b;
}

void chunk_buffer_release(buffer *b) {
    if (NULL == b) return;
    if (b->size >= chunk_buf_sz && chunk_buffers) {
        chunk *c = chunk_buffers;
        chunk_buffers = c->next;
        c->mem = b;
        c->next = chunks;
        chunks = c;
        buffer_clear(b);
    }
    else {
        buffer_free(b);
    }
}

static chunk * chunk_acquire(void) {
    if (chunks) {
        chunk *c = chunks;
        chunks = c->next;
        return c;
    }
    else {
        return chunk_init(chunk_buf_sz);
    }
}

static void chunk_release(chunk *c) {
    if (c->mem->size >= chunk_buf_sz) {
        chunk_reset(c);
        c->next = chunks;
        chunks = c;
    }
    else {
        chunk_free(c);
    }
}

void chunkqueue_chunk_pool_clear(void)
{
    for (chunk *next, *c = chunks; c; c = next) {
        next = c->next;
        chunk_free(c);
    }
    chunks = NULL;
}

void chunkqueue_chunk_pool_free(void)
{
    chunkqueue_chunk_pool_clear();
    for (chunk *next, *c = chunk_buffers; c; c = next) {
        next = c->next;
        c->mem = buffer_init(); /*(chunk_reset() expects c->mem != NULL)*/
        chunk_free(c);
    }
    chunk_buffers = NULL;
}

static off_t chunk_remaining_length(const chunk *c) {
	off_t len = 0;
	switch (c->type) {
	case MEM_CHUNK:
		len = buffer_string_length(c->mem);
		break;
	case FILE_CHUNK:
		len = c->file.length;
		break;
	default:
		force_assert(c->type == MEM_CHUNK || c->type == FILE_CHUNK);
		break;
	}
	force_assert(c->offset <= len);
	return len - c->offset;
}

void chunkqueue_free(chunkqueue *cq) {
	chunk *c, *pc;

	if (NULL == cq) return;

	for (c = cq->first; c; ) {
		pc = c;
		c = c->next;
		chunk_release(pc);
	}

	free(cq);
}

static void chunkqueue_prepend_chunk(chunkqueue *cq, chunk *c) {
	c->next = cq->first;
	cq->first = c;

	if (NULL == cq->last) {
		cq->last = c;
	}
}

static void chunkqueue_append_chunk(chunkqueue *cq, chunk *c) {
	c->next = NULL;
	if (cq->last) {
		cq->last->next = c;
	}
	cq->last = c;

	if (NULL == cq->first) {
		cq->first = c;
	}
}

static chunk * chunkqueue_prepend_mem_chunk(chunkqueue *cq) {
    chunk *c = chunk_acquire();
    chunkqueue_prepend_chunk(cq, c);
    return c;
}

static chunk * chunkqueue_append_mem_chunk(chunkqueue *cq) {
    chunk *c = chunk_acquire();
    chunkqueue_append_chunk(cq, c);
    return c;
}

static chunk * chunkqueue_append_file_chunk(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
    chunk *c = chunk_acquire();
    chunkqueue_append_chunk(cq, c);
    c->type = FILE_CHUNK;
    c->file.start = offset;
    c->file.length = len;
    cq->bytes_in += len;
    buffer_copy_buffer(c->mem, fn);
    return c;
}

void chunkqueue_reset(chunkqueue *cq) {
	chunk *cur = cq->first;

	cq->first = cq->last = NULL;

	while (NULL != cur) {
		chunk *next = cur->next;
		chunk_release(cur);
		cur = next;
	}

	cq->bytes_in = 0;
	cq->bytes_out = 0;
	cq->tempdir_idx = 0;
}

void chunkqueue_append_file_fd(chunkqueue *cq, buffer *fn, int fd, off_t offset, off_t len) {
    if (len > 0) {
        (chunkqueue_append_file_chunk(cq, fn, offset, len))->file.fd = fd;
    }
    else {
        close(fd);
    }
}

void chunkqueue_append_file(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
    if (len > 0) {
        chunkqueue_append_file_chunk(cq, fn, offset, len);
    }
}


static int chunkqueue_append_mem_extend_chunk(chunkqueue *cq, const char *mem, size_t len) {
	chunk *c = cq->last;
	if (0 == len) return 1;
	if (c != NULL && c->type == MEM_CHUNK
	    && buffer_string_space(c->mem) >= len) {
		buffer_append_string_len(c->mem, mem, len);
		cq->bytes_in += len;
		return 1;
	}
	return 0;
}


void chunkqueue_append_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;
	size_t len = buffer_string_length(mem);
	if (len < 256 && chunkqueue_append_mem_extend_chunk(cq, mem->ptr, len)) return;

	c = chunkqueue_append_mem_chunk(cq);
	cq->bytes_in += len;
	buffer_move(c->mem, mem);
}


void chunkqueue_append_mem(chunkqueue *cq, const char * mem, size_t len) {
	chunk *c;
	if (len < chunk_buf_sz && chunkqueue_append_mem_extend_chunk(cq, mem, len))
		return;

	c = chunkqueue_append_mem_chunk(cq);
	cq->bytes_in += len;
	buffer_copy_string_len(c->mem, mem, len);
}


void chunkqueue_append_mem_min(chunkqueue *cq, const char * mem, size_t len) {
	chunk *c;
	if (len < chunk_buf_sz && chunkqueue_append_mem_extend_chunk(cq, mem, len))
		return;

	c = chunk_init(len+1);
	chunkqueue_append_chunk(cq, c);
	cq->bytes_in += len;
	buffer_copy_string_len(c->mem, mem, len);
}


void chunkqueue_append_chunkqueue(chunkqueue *cq, chunkqueue *src) {
	if (src == NULL || NULL == src->first) return;

	if (NULL == cq->first) {
		cq->first = src->first;
	} else {
		cq->last->next = src->first;
	}
	cq->last = src->last;
	cq->bytes_in += (src->bytes_in - src->bytes_out);

	src->first = NULL;
	src->last = NULL;
	src->bytes_out = src->bytes_in;
}


__attribute_cold__
static void chunkqueue_buffer_open_resize(chunk *c, size_t sz) {
	chunk * const n = chunk_init((sz + 4095) & ~4095uL);
	buffer * const b = c->mem;
	c->mem = n->mem;
	n->mem = b;
	chunk_release(n);
}


buffer * chunkqueue_prepend_buffer_open_sz(chunkqueue *cq, size_t sz) {
	chunk * const c = chunkqueue_prepend_mem_chunk(cq);
	if (buffer_string_space(c->mem) < sz) {
		chunkqueue_buffer_open_resize(c, sz);
	}
	return c->mem;
}


buffer * chunkqueue_prepend_buffer_open(chunkqueue *cq) {
	chunk *c = chunkqueue_prepend_mem_chunk(cq);
	return c->mem;
}


void chunkqueue_prepend_buffer_commit(chunkqueue *cq) {
	cq->bytes_in += buffer_string_length(cq->first->mem);
}


buffer * chunkqueue_append_buffer_open_sz(chunkqueue *cq, size_t sz) {
	chunk * const c = chunkqueue_append_mem_chunk(cq);
	if (buffer_string_space(c->mem) < sz) {
		chunkqueue_buffer_open_resize(c, sz);
	}
	return c->mem;
}


buffer * chunkqueue_append_buffer_open(chunkqueue *cq) {
	chunk *c = chunkqueue_append_mem_chunk(cq);
	return c->mem;
}


void chunkqueue_append_buffer_commit(chunkqueue *cq) {
	cq->bytes_in += buffer_string_length(cq->last->mem);
}


static void chunkqueue_remove_empty_chunks(chunkqueue *cq);


char * chunkqueue_get_memory(chunkqueue *cq, size_t *len) {
	size_t sz = *len ? *len : (chunk_buf_sz >> 1);
	buffer *b;
	chunk *c = cq->last;
	if (NULL != c && MEM_CHUNK == c->type) {
		/* return pointer into existing buffer if large enough */
		size_t avail = buffer_string_space(c->mem);
		if (avail >= sz) {
			*len = avail;
			b = c->mem;
			return b->ptr + buffer_string_length(b);
		}
	}

	/* allocate new chunk */
	b = chunkqueue_append_buffer_open_sz(cq, sz);
	*len = buffer_string_space(b);
	return b->ptr;
}

void chunkqueue_use_memory(chunkqueue *cq, size_t len) {
	buffer *b;

	force_assert(NULL != cq);
	force_assert(NULL != cq->last && MEM_CHUNK == cq->last->type);
	b = cq->last->mem;

	if (len > 0) {
		buffer_commit(b, len);
		cq->bytes_in += len;
	} else if (buffer_string_is_empty(b)) {
		/* scan chunkqueue to remove empty last chunk
		 * (generally not expecting a deep queue) */
		chunkqueue_remove_empty_chunks(cq);
	}
}

void chunkqueue_set_tempdirs_default (array *tempdirs, unsigned int upload_temp_file_size) {
	chunkqueue_default_tempdirs = tempdirs;
	chunkqueue_default_tempfile_size
		= (0 == upload_temp_file_size)                ? DEFAULT_TEMPFILE_SIZE
		: (upload_temp_file_size > MAX_TEMPFILE_SIZE) ? MAX_TEMPFILE_SIZE
		                                              : upload_temp_file_size;
}

#if 0
void chunkqueue_set_tempdirs(chunkqueue *cq, array *tempdirs, unsigned int upload_temp_file_size) {
	force_assert(NULL != cq);
	cq->tempdirs = tempdirs;
	cq->upload_temp_file_size
		= (0 == upload_temp_file_size)                ? DEFAULT_TEMPFILE_SIZE
		: (upload_temp_file_size > MAX_TEMPFILE_SIZE) ? MAX_TEMPFILE_SIZE
		                                              : upload_temp_file_size;
	cq->tempdir_idx = 0;
}
#endif

void chunkqueue_steal(chunkqueue *dest, chunkqueue *src, off_t len) {
	while (len > 0) {
		chunk *c = src->first;
		off_t clen = 0, use;

		if (NULL == c) break;

		clen = chunk_remaining_length(c);
		if (0 == clen) {
			/* drop empty chunk */
			src->first = c->next;
			if (c == src->last) src->last = NULL;
			chunk_release(c);
			continue;
		}

		use = len >= clen ? clen : len;
		len -= use;

		if (use == clen) {
			/* move complete chunk */
			src->first = c->next;
			if (c == src->last) src->last = NULL;

			chunkqueue_append_chunk(dest, c);
			dest->bytes_in += use;
		} else {
			/* partial chunk with length "use" */

			switch (c->type) {
			case MEM_CHUNK:
				chunkqueue_append_mem(dest, c->mem->ptr + c->offset, use);
				break;
			case FILE_CHUNK:
				/* tempfile flag is in "last" chunk after the split */
				chunkqueue_append_file(dest, c->mem, c->file.start + c->offset, use);
				break;
			}

			c->offset += use;
			force_assert(0 == len);
		}

		src->bytes_out += use;
	}
}

static chunk *chunkqueue_get_append_tempfile(server *srv, chunkqueue *cq) {
	chunk *c;
	buffer *template = buffer_init_string("/var/tmp/lighttpd-upload-XXXXXX");
	int fd = -1;

	if (cq->tempdirs && cq->tempdirs->used) {
		/* we have several tempdirs, only if all of them fail we jump out */

		for (errno = EIO; cq->tempdir_idx < cq->tempdirs->used; ++cq->tempdir_idx) {
			data_string *ds = (data_string *)cq->tempdirs->data[cq->tempdir_idx];

			buffer_copy_buffer(template, ds->value);
			buffer_append_path_len(template, CONST_STR_LEN("lighttpd-upload-XXXXXX"));

		      #ifdef __COVERITY__
			/* POSIX-2008 requires mkstemp create file with 0600 perms */
			umask(0600);
		      #endif
			/* coverity[secure_temp : FALSE] */
			if (-1 != (fd = mkstemp(template->ptr))) break;
		}
	} else {
	      #ifdef __COVERITY__
		/* POSIX-2008 requires mkstemp create file with 0600 perms */
		umask(0600);
	      #endif
		/* coverity[secure_temp : FALSE] */
		fd = mkstemp(template->ptr);
	}

	if (fd < 0) {
		/* (report only the last error to mkstemp()
		 *  if multiple temp dirs attempted) */
		log_error_write(srv, __FILE__, __LINE__, "sbs",
				"opening temp-file failed:",
				template, strerror(errno));
		buffer_free(template);
		return NULL;
	}

	if (0 != fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_APPEND)) {
		/* (should not happen; fd is regular file) */
		log_error_write(srv, __FILE__, __LINE__, "sbs",
				"fcntl():", template, strerror(errno));
		close(fd);
		buffer_free(template);
		return NULL;
	}
	fdevent_setfd_cloexec(fd);

	c = chunkqueue_append_file_chunk(cq, template, 0, 0);
	c->file.fd = fd;
	c->file.is_temp = 1;

	buffer_free(template);

	return c;
}

int chunkqueue_append_mem_to_tempfile(server *srv, chunkqueue *dest, const char *mem, size_t len) {
	chunk *dst_c;
	ssize_t written;

	do {
		/*
		 * if the last chunk is
		 * - smaller than dest->upload_temp_file_size
		 * - not read yet (offset == 0)
		 * -> append to it (so it might actually become larger than dest->upload_temp_file_size)
		 * otherwise
		 * -> create a new chunk
		 *
		 * */

		dst_c = dest->last;
		if (NULL != dst_c
			&& FILE_CHUNK == dst_c->type
			&& dst_c->file.is_temp
			&& dst_c->file.fd >= 0
			&& 0 == dst_c->offset) {
			/* ok, take the last chunk for our job */

			if (dst_c->file.length >= (off_t)dest->upload_temp_file_size) {
				/* the chunk is too large now, close it */
				int rc = close(dst_c->file.fd);
				dst_c->file.fd = -1;
				if (0 != rc) {
					log_error_write(srv, __FILE__, __LINE__, "sbss",
						"close() temp-file", dst_c->mem, "failed:",
						strerror(errno));
					return -1;
				}
				dst_c = NULL;
			}
		} else {
			dst_c = NULL;
		}

		if (NULL == dst_c && NULL == (dst_c = chunkqueue_get_append_tempfile(srv, dest))) {
			return -1;
		}
	      #ifdef __COVERITY__
		if (dst_c->file.fd < 0) return -1;
	      #endif

		/* (dst_c->file.fd >= 0) */
		/* coverity[negative_returns : FALSE] */
		written = write(dst_c->file.fd, mem, len);

		if ((size_t) written == len) {
			dst_c->file.length += len;
			dest->bytes_in += len;

			return 0;
		} else if (written >= 0) {
			/*(assume EINTR if partial write and retry write();
			 * retry write() might fail with ENOSPC if no more space on volume)*/
			dest->bytes_in += written;
			mem += written;
			len -= (size_t)written;
			dst_c->file.length += (size_t)written;
			/* continue; retry */
		} else if (errno == EINTR) {
			/* continue; retry */
		} else {
			int retry = (errno == ENOSPC && dest->tempdirs && ++dest->tempdir_idx < dest->tempdirs->used);
			if (!retry) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"write() temp-file", dst_c->mem, "failed:",
						strerror(errno));
			}

			if (0 == chunk_remaining_length(dst_c)) {
				/*(remove empty chunk and unlink tempfile)*/
				chunkqueue_remove_empty_chunks(dest);
			} else {/*(close tempfile; avoid later attempts to append)*/
				int rc = close(dst_c->file.fd);
				dst_c->file.fd = -1;
				if (0 != rc) {
					log_error_write(srv, __FILE__, __LINE__, "sbss",
						"close() temp-file", dst_c->mem, "failed:",
						strerror(errno));
					return -1;
				}
			}
			if (!retry) break; /* return -1; */

			/* continue; retry */
		}

	} while (dst_c);

	return -1;
}

int chunkqueue_steal_with_tempfiles(server *srv, chunkqueue *dest, chunkqueue *src, off_t len) {
	while (len > 0) {
		chunk *c = src->first;
		off_t clen = 0, use;

		if (NULL == c) break;

		clen = chunk_remaining_length(c);
		if (0 == clen) {
			/* drop empty chunk */
			src->first = c->next;
			if (c == src->last) src->last = NULL;
			chunk_release(c);
			continue;
		}

		use = (len >= clen) ? clen : len;
		len -= use;

		switch (c->type) {
		case FILE_CHUNK:
			if (use == clen) {
				/* move complete chunk */
				src->first = c->next;
				if (c == src->last) src->last = NULL;
				chunkqueue_append_chunk(dest, c);
				dest->bytes_in += use;
			} else {
				/* partial chunk with length "use" */
				/* tempfile flag is in "last" chunk after the split */
				chunkqueue_append_file(dest, c->mem, c->file.start + c->offset, use);

				c->offset += use;
				force_assert(0 == len);
			}
			break;

		case MEM_CHUNK:
			/* store "use" bytes from memory chunk in tempfile */
			if (0 != chunkqueue_append_mem_to_tempfile(srv, dest, c->mem->ptr + c->offset, use)) {
				return -1;
			}

			if (use == clen) {
				/* finished chunk */
				src->first = c->next;
				if (c == src->last) src->last = NULL;
				chunk_release(c);
			} else {
				/* partial chunk */
				c->offset += use;
				force_assert(0 == len);
			}
			break;
		}

		src->bytes_out += use;
	}

	return 0;
}

off_t chunkqueue_length(chunkqueue *cq) {
	off_t len = 0;
	chunk *c;

	for (c = cq->first; c; c = c->next) {
		len += chunk_remaining_length(c);
	}

	return len;
}

void chunkqueue_mark_written(chunkqueue *cq, off_t len) {
	off_t written = len;
	chunk *c;
	force_assert(len >= 0);

	for (c = cq->first; NULL != c; c = cq->first) {
		off_t c_len = chunk_remaining_length(c);

		if (0 == written && 0 != c_len) break; /* no more finished chunks */

		if (written >= c_len) { /* chunk got finished */
			c->offset += c_len;
			written -= c_len;

			cq->first = c->next;
			if (c == cq->last) cq->last = NULL;
			chunk_release(c);
		} else { /* partial chunk */
			c->offset += written;
			written = 0;
			break; /* chunk not finished */
		}
	}

	force_assert(0 == written);
	cq->bytes_out += len;
}

void chunkqueue_remove_finished_chunks(chunkqueue *cq) {
	chunk *c;

	for (c = cq->first; c; c = cq->first) {
		if (0 != chunk_remaining_length(c)) break; /* not finished yet */

		cq->first = c->next;
		if (c == cq->last) cq->last = NULL;
		chunk_release(c);
	}
}

static void chunkqueue_remove_empty_chunks(chunkqueue *cq) {
	chunk *c;
	chunkqueue_remove_finished_chunks(cq);
	if (chunkqueue_is_empty(cq)) return;

	for (c = cq->first; c && c->next; c = c->next) {
		if (0 == chunk_remaining_length(c->next)) {
			chunk *empty = c->next;
			c->next = empty->next;
			if (empty == cq->last) cq->last = c;
			chunk_release(empty);
		}
	}
}

int chunkqueue_open_file_chunk(server *srv, chunkqueue *cq) {
	chunk* const c = cq->first;
	off_t offset, toSend;
	struct stat st;

	force_assert(NULL != c);
	force_assert(FILE_CHUNK == c->type);
	force_assert(c->offset >= 0 && c->offset <= c->file.length);

	offset = c->file.start + c->offset;
	toSend = c->file.length - c->offset;

	if (-1 == c->file.fd) {
		/* (permit symlinks; should already have been checked.  However, TOC-TOU remains) */
		if (-1 == (c->file.fd = fdevent_open_cloexec(c->mem->ptr, 1, O_RDONLY, 0))) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "open failed:", strerror(errno), c->mem);
			return -1;
		}
	}

	/*(skip file size checks if file is temp file created by lighttpd)*/
	if (c->file.is_temp) return 0;

	if (-1 == fstat(c->file.fd, &st)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "fstat failed:", strerror(errno));
		return -1;
	}

	if (offset > st.st_size || toSend > st.st_size || offset > st.st_size - toSend) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "file shrunk:", c->mem);
		return -1;
	}

	return 0;
}
