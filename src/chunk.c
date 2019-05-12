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
static chunk *chunks, *chunks_oversized;
static chunk *chunk_buffers;
static array *chunkqueue_default_tempdirs = NULL;
static off_t chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;

void chunkqueue_set_chunk_size (size_t sz)
{
    chunk_buf_sz = sz > 0 ? ((sz + 1023) & ~1023uL) : 4096;
}

void chunkqueue_set_tempdirs_default_reset (void)
{
    chunkqueue_default_tempdirs = NULL;
    chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;
}

/* chunk buffer (c->mem) is never NULL; specialize routines from buffer.h */
static inline size_t chunk_buffer_string_length(const buffer *b) {
    return 0 != b->used ? b->used - 1 : 0;
}
static inline int chunk_buffer_string_is_empty(const buffer *b) {
    return b->used < 2;
}
static inline size_t chunk_buffer_string_space(const buffer *b) {
    return b->size ? b->size - (b->used | (0 == b->used)) : 0;
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
	if (c->file.is_temp && !chunk_buffer_string_is_empty(c->mem)) {
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

static chunk * chunk_acquire(size_t sz) {
    if (sz <= chunk_buf_sz) {
        if (chunks) {
            chunk *c = chunks;
            chunks = c->next;
            return c;
        }
        sz = chunk_buf_sz;
    }
    else {
        sz = (sz + 8191) & ~8191uL;
        /* future: might have buckets of certain sizes, up to socket buf sizes*/
        if (chunks_oversized && chunks_oversized->mem->size >= sz) {
            chunk *c = chunks_oversized;
            chunks_oversized = c->next;
            return c;
        }
    }

    return chunk_init(sz);
}

static void chunk_release(chunk *c) {
    const size_t sz = c->mem->size;
    if (sz == chunk_buf_sz) {
        chunk_reset(c);
        c->next = chunks;
        chunks = c;
    }
    else if (sz > chunk_buf_sz) {
        chunk_reset(c);
        chunk **co = &chunks_oversized;
        while (*co && sz < (*co)->mem->size) co = &(*co)->next;
        c->next = *co;
        *co = c;
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
    for (chunk *next, *c = chunks_oversized; c; c = next) {
        next = c->next;
        chunk_free(c);
    }
    chunks_oversized = NULL;
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
    /* MEM_CHUNK or FILE_CHUNK */
    return (c->type == MEM_CHUNK
              ? (off_t)chunk_buffer_string_length(c->mem)
              : c->file.length)
           - c->offset;
}

static void chunkqueue_release_chunks(chunkqueue *cq) {
    cq->last = NULL;
    for (chunk *c; (c = cq->first); ) {
        cq->first = c->next;
        chunk_release(c);
    }
}

void chunkqueue_free(chunkqueue *cq) {
    if (NULL == cq) return;
    chunkqueue_release_chunks(cq);
    free(cq);
}

static void chunkqueue_prepend_chunk(chunkqueue *cq, chunk *c) {
    if (NULL == (c->next = cq->first)) cq->last = c;
    cq->first = c;
}

static void chunkqueue_append_chunk(chunkqueue *cq, chunk *c) {
    c->next = NULL;
    *(cq->last ? &cq->last->next : &cq->first) = c;
    cq->last = c;
}

static chunk * chunkqueue_prepend_mem_chunk(chunkqueue *cq, size_t sz) {
    chunk *c = chunk_acquire(sz);
    chunkqueue_prepend_chunk(cq, c);
    return c;
}

static chunk * chunkqueue_append_mem_chunk(chunkqueue *cq, size_t sz) {
    chunk *c = chunk_acquire(sz);
    chunkqueue_append_chunk(cq, c);
    return c;
}

static chunk * chunkqueue_append_file_chunk(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
    chunk *c = chunk_acquire(buffer_string_length(fn)+1);
    chunkqueue_append_chunk(cq, c);
    c->type = FILE_CHUNK;
    c->file.start = offset;
    c->file.length = len;
    cq->bytes_in += len;
    buffer_copy_buffer(c->mem, fn);
    return c;
}

void chunkqueue_reset(chunkqueue *cq) {
    chunkqueue_release_chunks(cq);
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
	    && chunk_buffer_string_space(c->mem) >= len) {
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

	c = chunkqueue_append_mem_chunk(cq, chunk_buf_sz);
	cq->bytes_in += len;
	buffer_move(c->mem, mem);
}


void chunkqueue_append_mem(chunkqueue *cq, const char * mem, size_t len) {
	chunk *c;
	if (len < chunk_buf_sz && chunkqueue_append_mem_extend_chunk(cq, mem, len))
		return;

	c = chunkqueue_append_mem_chunk(cq, len+1);
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


buffer * chunkqueue_prepend_buffer_open_sz(chunkqueue *cq, size_t sz) {
	chunk * const c = chunkqueue_prepend_mem_chunk(cq, sz);
	return c->mem;
}


buffer * chunkqueue_prepend_buffer_open(chunkqueue *cq) {
	return chunkqueue_prepend_buffer_open_sz(cq, chunk_buf_sz);
}


void chunkqueue_prepend_buffer_commit(chunkqueue *cq) {
	cq->bytes_in += chunk_buffer_string_length(cq->first->mem);
}


buffer * chunkqueue_append_buffer_open_sz(chunkqueue *cq, size_t sz) {
	chunk * const c = chunkqueue_append_mem_chunk(cq, sz);
	return c->mem;
}


buffer * chunkqueue_append_buffer_open(chunkqueue *cq) {
	return chunkqueue_append_buffer_open_sz(cq, chunk_buf_sz);
}


void chunkqueue_append_buffer_commit(chunkqueue *cq) {
	cq->bytes_in += chunk_buffer_string_length(cq->last->mem);
}


static void chunkqueue_remove_empty_chunks(chunkqueue *cq);


char * chunkqueue_get_memory(chunkqueue *cq, size_t *len) {
	size_t sz = *len ? *len : (chunk_buf_sz >> 1);
	buffer *b;
	chunk *c = cq->last;
	if (NULL != c && MEM_CHUNK == c->type) {
		/* return pointer into existing buffer if large enough */
		size_t avail = chunk_buffer_string_space(c->mem);
		if (avail >= sz) {
			*len = avail;
			b = c->mem;
			return b->ptr + chunk_buffer_string_length(b);
		}
	}

	/* allocate new chunk */
	b = chunkqueue_append_buffer_open_sz(cq, sz);
	*len = chunk_buffer_string_space(b);
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
	} else if (chunk_buffer_string_is_empty(b)) {
		/* scan chunkqueue to remove empty last chunk
		 * (generally not expecting a deep queue) */
		chunkqueue_remove_empty_chunks(cq);
	}
}

void chunkqueue_set_tempdirs_default (array *tempdirs, off_t upload_temp_file_size) {
	chunkqueue_default_tempdirs = tempdirs;
	chunkqueue_default_tempfile_size
		= (0 == upload_temp_file_size)                ? DEFAULT_TEMPFILE_SIZE
		: (upload_temp_file_size > MAX_TEMPFILE_SIZE) ? MAX_TEMPFILE_SIZE
		                                              : upload_temp_file_size;
}

void chunkqueue_set_tempdirs(chunkqueue *cq, array *tempdirs, off_t upload_temp_file_size) {
	force_assert(NULL != cq);
	cq->tempdirs = tempdirs;
	cq->upload_temp_file_size
		= (0 == upload_temp_file_size)                ? DEFAULT_TEMPFILE_SIZE
		: (upload_temp_file_size > MAX_TEMPFILE_SIZE) ? MAX_TEMPFILE_SIZE
		                                              : upload_temp_file_size;
	cq->tempdir_idx = 0;
}

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
			if (-1 != (fd = fdevent_mkstemp_append(template->ptr))) break;
		}
	} else {
		fd = fdevent_mkstemp_append(template->ptr);
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
    cq->bytes_out += len;

    for (chunk *c; (c = cq->first); ) {
        off_t c_len = chunk_remaining_length(c);
        if (len >= c_len) { /* chunk got finished */
            len -= c_len;
            cq->first = c->next;
            chunk_release(c);
            if (0 == len) break;
        }
        else { /* partial chunk */
            c->offset += len;
            return; /* chunk not finished */
        }
    }

    if (NULL == cq->first)
        cq->last = NULL;
    else
        chunkqueue_remove_finished_chunks(cq);
}

void chunkqueue_remove_finished_chunks(chunkqueue *cq) {
    for (chunk *c; (c = cq->first) && 0 == chunk_remaining_length(c); ){
        if (NULL == (cq->first = c->next)) cq->last = NULL;
        chunk_release(c);
    }
}

static void chunkqueue_remove_empty_chunks(chunkqueue *cq) {
	chunk *c;
	chunkqueue_remove_finished_chunks(cq);

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
