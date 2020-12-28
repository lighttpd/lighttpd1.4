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

static size_t chunk_buf_sz = 8192;
static chunk *chunks, *chunks_oversized;
static chunk *chunk_buffers;
static int chunks_oversized_n;
static const array *chunkqueue_default_tempdirs = NULL;
static off_t chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;

void chunkqueue_set_chunk_size (size_t sz)
{
    size_t x = 1024;
    while (x < sz && x < (1u << 30)) x <<= 1;
    chunk_buf_sz = sz > 0 ? x : 8192;
}

void chunkqueue_set_tempdirs_default_reset (void)
{
    chunk_buf_sz = 8192;
    chunkqueue_default_tempdirs = NULL;
    chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;
}

/* chunk buffer (c->mem) is never NULL; specialize routines from buffer.h */
__attribute_pure__
static inline size_t chunk_buffer_string_length(const buffer *b) {
    return 0 != b->used ? b->used - 1 : 0;
}
__attribute_pure__
static inline int chunk_buffer_string_is_empty(const buffer *b) {
    return b->used < 2;
}
__attribute_pure__
static inline size_t chunk_buffer_string_space(const buffer *b) {
    return b->size ? b->size - (b->used | (0 == b->used)) : 0;
}

chunkqueue *chunkqueue_init(chunkqueue *cq) {
	/* (if caller passes non-NULL cq, it must be 0-init) */
	if (NULL == cq) {
		cq = calloc(1, sizeof(*cq));
		force_assert(NULL != cq);
	}

	cq->first = NULL;
	cq->last = NULL;

	cq->tempdirs              = chunkqueue_default_tempdirs;
	cq->upload_temp_file_size = chunkqueue_default_tempfile_size;

	return cq;
}

__attribute_returns_nonnull__
static chunk *chunk_init(size_t sz) {
	chunk * const restrict c = calloc(1, sizeof(*c));
	force_assert(NULL != c);

      #if 0 /*(zeroed by calloc())*/
	c->type = MEM_CHUNK;
	c->next = NULL;
	c->offset = 0;
	c->file.length = 0;
	c->file.mmap.length = c->file.mmap.offset = 0;
	c->file.is_temp = 0;
      #endif
	c->file.fd = -1;
	c->file.mmap.start = MAP_FAILED;

	c->mem = buffer_init();
	buffer_string_prepare_copy(c->mem, sz-1);

	return c;
}

static void chunk_reset_file_chunk(chunk *c) {
	if (c->file.is_temp) {
		c->file.is_temp = 0;
		if (!chunk_buffer_string_is_empty(c->mem))
			unlink(c->mem->ptr);
	}
	if (c->file.refchg) {
		c->file.refchg(c->file.ref, -1);
		c->file.refchg = 0; /* NULL fn ptr */
		c->file.ref = NULL;
	}
	else if (c->file.fd != -1) {
		close(c->file.fd);
	}
	if (MAP_FAILED != c->file.mmap.start) {
		munmap(c->file.mmap.start, c->file.mmap.length);
		c->file.mmap.start = MAP_FAILED;
		c->file.mmap.length = c->file.mmap.offset = 0;
	}
	c->file.fd = -1;
	c->file.length = 0;
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

static chunk * chunk_pop_oversized(size_t sz) {
    /* future: might have buckets of certain sizes, up to socket buf sizes */
    if (chunks_oversized && chunks_oversized->mem->size >= sz) {
        --chunks_oversized_n;
        chunk *c = chunks_oversized;
        chunks_oversized = c->next;
        return c;
    }
    return NULL;
}

static void chunk_push_oversized(chunk * const c, const size_t sz) {
    if (chunks_oversized_n < 64 && chunk_buf_sz >= 4096) {
        ++chunks_oversized_n;
        chunk **co = &chunks_oversized;
        while (*co && sz < (*co)->mem->size) co = &(*co)->next;
        c->next = *co;
        *co = c;
    }
    else
        chunk_free(c);
}

__attribute_returns_nonnull__
static buffer * chunk_buffer_acquire_sz(size_t sz) {
    chunk *c;
    buffer *b;
    if (sz <= chunk_buf_sz) {
        if (chunks) {
            c = chunks;
            chunks = c->next;
        }
        else
            c = chunk_init(chunk_buf_sz);
            /* future: might choose to pop from chunks_oversized, if available
             * (even if larger than sz) rather than allocating new chunk
             * (and if doing so, might replace chunks_oversized_n) */
    }
    else {
        /*(round up to nearest chunk_buf_sz)*/
        sz = (sz + (chunk_buf_sz-1)) & ~(chunk_buf_sz-1);
        c = chunk_pop_oversized(sz);
        if (NULL == c)
            c = chunk_init(sz);
    }
    c->next = chunk_buffers;
    chunk_buffers = c;
    b = c->mem;
    c->mem = NULL;
    return b;
}

buffer * chunk_buffer_acquire(void) {
    return chunk_buffer_acquire_sz(chunk_buf_sz);
}

void chunk_buffer_release(buffer *b) {
    if (NULL == b) return;
    if (chunk_buffers) {
        chunk *c = chunk_buffers;
        chunk_buffers = c->next;
        c->mem = b;
        buffer_clear(b);
        if (b->size == chunk_buf_sz) {
            c->next = chunks;
            chunks = c;
        }
        else if (b->size > chunk_buf_sz)
            chunk_push_oversized(c, b->size);
        else
            chunk_free(c);
    }
    else {
        buffer_free(b);
    }
}

size_t chunk_buffer_prepare_append(buffer * const b, size_t sz) {
    if (sz > chunk_buffer_string_space(b)) {
        sz += b->used ? b->used : 1;
        buffer * const cb = chunk_buffer_acquire_sz(sz);
        /* swap buffer contents and copy original b->ptr into larger b->ptr */
        /*(this does more than buffer_move())*/
        buffer tb = *b;
        *b = *cb;
        *cb = tb;
        if ((b->used = tb.used))
            memcpy(b->ptr, tb.ptr, tb.used);
        chunk_buffer_release(cb);
    }
    return chunk_buffer_string_space(b);
}

__attribute_returns_nonnull__
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
        /*(round up to nearest chunk_buf_sz)*/
        sz = (sz + (chunk_buf_sz-1)) & ~(chunk_buf_sz-1);
        chunk *c = chunk_pop_oversized(sz);
        if (c) return c;
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
        chunk_push_oversized(c, sz);
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
    chunks_oversized_n = 0;
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

__attribute_pure__
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

static void chunkqueue_prepend_chunk(chunkqueue * const restrict cq, chunk * const restrict c) {
    if (NULL == (c->next = cq->first)) cq->last = c;
    cq->first = c;
}

static void chunkqueue_append_chunk(chunkqueue * const restrict cq, chunk * const restrict c) {
    c->next = NULL;
    *(cq->last ? &cq->last->next : &cq->first) = c;
    cq->last = c;
}

__attribute_returns_nonnull__
static chunk * chunkqueue_prepend_mem_chunk(chunkqueue *cq, size_t sz) {
    chunk *c = chunk_acquire(sz);
    chunkqueue_prepend_chunk(cq, c);
    return c;
}

__attribute_returns_nonnull__
static chunk * chunkqueue_append_mem_chunk(chunkqueue *cq, size_t sz) {
    chunk *c = chunk_acquire(sz);
    chunkqueue_append_chunk(cq, c);
    return c;
}

__attribute_returns_nonnull__
static chunk * chunkqueue_append_file_chunk(chunkqueue * const restrict cq, const buffer * const restrict fn, off_t offset, off_t len) {
    chunk *c = chunk_acquire(buffer_string_length(fn)+1);
    chunkqueue_append_chunk(cq, c);
    c->type = FILE_CHUNK;
    c->offset = offset;
    c->file.length = offset + len;
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

void chunkqueue_append_file_fd(chunkqueue * const restrict cq, const buffer * const restrict fn, int fd, off_t offset, off_t len) {
    if (len > 0) {
        (chunkqueue_append_file_chunk(cq, fn, offset, len))->file.fd = fd;
    }
    else {
        close(fd);
    }
}

void chunkqueue_append_file(chunkqueue * const restrict cq, const buffer * const restrict fn, off_t offset, off_t len) {
    if (len > 0) {
        chunkqueue_append_file_chunk(cq, fn, offset, len);
    }
}


static int chunkqueue_append_mem_extend_chunk(chunkqueue * const restrict cq, const char * const restrict mem, size_t len) {
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


void chunkqueue_append_buffer(chunkqueue * const restrict cq, buffer * const restrict mem) {
	chunk *c;
	size_t len = buffer_string_length(mem);
	if (len < 256 && chunkqueue_append_mem_extend_chunk(cq, mem->ptr, len)) return;

	c = chunkqueue_append_mem_chunk(cq, chunk_buf_sz);
	cq->bytes_in += len;
	buffer_move(c->mem, mem);
}


void chunkqueue_append_mem(chunkqueue * const restrict cq, const char * const restrict mem, size_t len) {
	chunk *c;
	if (len < chunk_buf_sz && chunkqueue_append_mem_extend_chunk(cq, mem, len))
		return;

	c = chunkqueue_append_mem_chunk(cq, len+1);
	cq->bytes_in += len;
	buffer_copy_string_len(c->mem, mem, len);
}


void chunkqueue_append_mem_min(chunkqueue * const restrict cq, const char * const restrict mem, size_t len) {
	chunk *c;
	if (len < chunk_buf_sz && chunkqueue_append_mem_extend_chunk(cq, mem, len))
		return;

	c = chunk_init(len+1);
	chunkqueue_append_chunk(cq, c);
	cq->bytes_in += len;
	buffer_copy_string_len(c->mem, mem, len);
}


void chunkqueue_append_chunkqueue(chunkqueue * const restrict cq, chunkqueue * const restrict src) {
	if (src == NULL || NULL == src->first) return;

	if (NULL == cq->first) {
		cq->first = src->first;
	} else {
		cq->last->next = src->first;
	}
	cq->last = src->last;
	cq->bytes_in += chunkqueue_length(src);

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


char * chunkqueue_get_memory(chunkqueue * const restrict cq, size_t * const restrict len) {
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

void chunkqueue_use_memory(chunkqueue * const restrict cq, chunk *ckpt, size_t len) {
    buffer *b = cq->last->mem;

    if (len > 0) {
        buffer_commit(b, len);
        cq->bytes_in += len;
        if (cq->last == ckpt || NULL == ckpt || MEM_CHUNK != ckpt->type
            || len > chunk_buffer_string_space(ckpt->mem)) return;

        buffer_append_string_buffer(ckpt->mem, b);
    }
    else if (!chunk_buffer_string_is_empty(b)) { /*(cq->last == ckpt)*/
        return; /* last chunk is not empty */
    }

    /* remove empty last chunk */
    chunk_release(cq->last);
    cq->last = ckpt;
    *(ckpt ? &ckpt->next : &cq->first) = NULL;
}

void chunkqueue_update_file(chunkqueue * const restrict cq, chunk *c, off_t len) {
    /*assert(c->type == FILE_CHUNK);*/
    c->file.length += len;
    cq->bytes_in += len;
}

void chunkqueue_set_tempdirs_default (const array *tempdirs, off_t upload_temp_file_size) {
	chunkqueue_default_tempdirs = tempdirs;
	chunkqueue_default_tempfile_size
		= (0 == upload_temp_file_size)                ? DEFAULT_TEMPFILE_SIZE
		: (upload_temp_file_size > MAX_TEMPFILE_SIZE) ? MAX_TEMPFILE_SIZE
		                                              : upload_temp_file_size;
}

void chunkqueue_set_tempdirs(chunkqueue * const restrict cq, const array * const restrict tempdirs, off_t upload_temp_file_size) {
	force_assert(NULL != cq);
	cq->tempdirs = tempdirs;
	cq->upload_temp_file_size
		= (0 == upload_temp_file_size)                ? DEFAULT_TEMPFILE_SIZE
		: (upload_temp_file_size > MAX_TEMPFILE_SIZE) ? MAX_TEMPFILE_SIZE
		                                              : upload_temp_file_size;
	cq->tempdir_idx = 0;
}

static void chunkqueue_steal_partial_file_chunk(chunkqueue * const restrict dest, const chunk * const restrict c, const off_t len) {
    chunkqueue_append_file(dest, c->mem, c->offset, len);
    if (c->file.fd >= 0) {
        chunk * const d = dest->last;
        if (c->file.refchg) {
            d->file.fd = c->file.fd;
            d->file.ref = c->file.ref;
            d->file.refchg = c->file.refchg;
            d->file.refchg(d->file.ref, 1);
        }
        else
            d->file.fd = fdevent_dup_cloexec(c->file.fd);
    }
}

void chunkqueue_steal(chunkqueue * const restrict dest, chunkqueue * const restrict src, off_t len) {
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
				chunkqueue_steal_partial_file_chunk(dest, c, use);
				break;
			}

			c->offset += use;
			force_assert(0 == len);
		}

		src->bytes_out += use;
	}
}

static chunk *chunkqueue_get_append_tempfile(chunkqueue * const restrict cq, log_error_st * const restrict errh) {
	chunk *c;
	buffer *template = buffer_init_string("/var/tmp/lighttpd-upload-XXXXXX");
	int fd = -1;

	if (cq->tempdirs && cq->tempdirs->used) {
		/* we have several tempdirs, only if all of them fail we jump out */

		for (errno = EIO; cq->tempdir_idx < cq->tempdirs->used; ++cq->tempdir_idx) {
			data_string *ds = (data_string *)cq->tempdirs->data[cq->tempdir_idx];

			buffer_copy_buffer(template, &ds->value);
			buffer_append_path_len(template, CONST_STR_LEN("lighttpd-upload-XXXXXX"));
			if (-1 != (fd = fdevent_mkstemp_append(template->ptr))) break;
		}
	} else {
		fd = fdevent_mkstemp_append(template->ptr);
	}

	if (fd < 0) {
		/* (report only the last error to mkstemp()
		 *  if multiple temp dirs attempted) */
		log_perror(errh, __FILE__, __LINE__,
		  "opening temp-file failed: %s", template->ptr);
		buffer_free(template);
		return NULL;
	}

	c = chunkqueue_append_file_chunk(cq, template, 0, 0);
	c->file.fd = fd;
	c->file.is_temp = 1;

	buffer_free(template);

	return c;
}

int chunkqueue_append_mem_to_tempfile(chunkqueue * const restrict dest, const char * restrict mem, size_t len, log_error_st * const restrict errh) {
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
				force_assert(0 == dst_c->file.refchg); /*(else should not happen)*/
				int rc = close(dst_c->file.fd);
				dst_c->file.fd = -1;
				if (0 != rc) {
					log_perror(errh, __FILE__, __LINE__,
					  "close() temp-file %s failed", dst_c->mem->ptr);
					return -1;
				}
				dst_c = NULL;
			}
		} else {
			dst_c = NULL;
		}

		if (NULL == dst_c && NULL == (dst_c = chunkqueue_get_append_tempfile(dest, errh))) {
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
				log_perror(errh, __FILE__, __LINE__,
				  "write() temp-file %s failed", dst_c->mem->ptr);
			}

			if (0 == chunk_remaining_length(dst_c)) {
				/*(remove empty chunk and unlink tempfile)*/
				chunkqueue_remove_empty_chunks(dest);
			} else {/*(close tempfile; avoid later attempts to append)*/
				force_assert(0 == dst_c->file.refchg); /*(else should not happen)*/
				int rc = close(dst_c->file.fd);
				dst_c->file.fd = -1;
				if (0 != rc) {
					log_perror(errh, __FILE__, __LINE__,
					  "close() temp-file %s failed", dst_c->mem->ptr);
					return -1;
				}
			}
			if (!retry) break; /* return -1; */

			/* continue; retry */
		}

	} while (dst_c);

	return -1;
}

int chunkqueue_steal_with_tempfiles(chunkqueue * const restrict dest, chunkqueue * const restrict src, off_t len, log_error_st * const restrict errh) {
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
				chunkqueue_steal_partial_file_chunk(dest, c, use);
				c->offset += use;
				force_assert(0 == len);
			}
			break;

		case MEM_CHUNK:
			/* store "use" bytes from memory chunk in tempfile */
			if (0 != chunkqueue_append_mem_to_tempfile(dest, c->mem->ptr + c->offset, use, errh)) {
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

void chunkqueue_compact_mem_offset(chunkqueue * const cq) {
    chunk * const restrict c = cq->first;
    if (0 == c->offset) return;
    if (c->type != MEM_CHUNK) return; /*(should not happen)*/

    buffer * const restrict b = c->mem;
    size_t len = chunk_buffer_string_length(b) - c->offset;
    memmove(b->ptr, b->ptr+c->offset, len);
    c->offset = 0;
    buffer_string_set_length(b, len);
}

void chunkqueue_compact_mem(chunkqueue *cq, size_t clen) {
    /* caller must guarantee that chunks in chunkqueue are MEM_CHUNK,
     * which is currently always true when reading input from client */
    chunk *c = cq->first;
    buffer *b = c->mem;
    size_t len = chunk_buffer_string_length(b) - c->offset;
    if (len >= clen) return;
    if (b->size > clen) {
        if (chunk_buffer_string_space(b) < clen - len)
            chunkqueue_compact_mem_offset(cq);
    }
    else {
        b = chunkqueue_prepend_buffer_open_sz(cq, clen+1);
        buffer_append_string_len(b, c->mem->ptr + c->offset, len);
        cq->first->next = c->next;
        if (NULL == c->next) cq->last = cq->first;
        chunk_release(c);
        c = cq->first;
    }

    for (chunk *fc = c; ((clen -= len) && (c = fc->next)); ) {
        len = chunk_buffer_string_length(c->mem) - c->offset;
        if (len > clen) {
            buffer_append_string_len(b, c->mem->ptr + c->offset, clen);
            c->offset += clen;
            break;
        }
        buffer_append_string_len(b, c->mem->ptr + c->offset, len);
        fc->next = c->next;
        if (NULL == c->next) cq->last = fc;
        chunk_release(c);
    }
    /* chunkqueue_prepend_buffer_commit() is not called here;
     * no data added/removed from chunkqueue; consolidated only */
}

static int chunk_open_file_chunk(chunk * const restrict c, log_error_st * const restrict errh) {
	if (-1 == c->file.fd) {
		/* (permit symlinks; should already have been checked.  However, TOC-TOU remains) */
		if (-1 == (c->file.fd = fdevent_open_cloexec(c->mem->ptr, 1, O_RDONLY, 0))) {
			log_perror(errh, __FILE__, __LINE__, "open failed: %s",c->mem->ptr);
			return -1;
		}
	}

	/*(skip file size checks if file is temp file created by lighttpd)*/
	if (c->file.is_temp) return 0;

	force_assert(FILE_CHUNK == c->type);
	force_assert(c->offset >= 0 && c->offset <= c->file.length);

	struct stat st;
	if (-1 == fstat(c->file.fd, &st)) {
		log_perror(errh, __FILE__, __LINE__, "fstat failed");
		return -1;
	}

	const off_t offset = c->offset;
	const off_t len = c->file.length - c->offset;
	if (offset > st.st_size || len > st.st_size || offset > st.st_size - len) {
		log_error(errh, __FILE__, __LINE__, "file shrunk: %s", c->mem->ptr);
		return -1;
	}

	return 0;
}

int chunkqueue_open_file_chunk(chunkqueue * const restrict cq, log_error_st * const restrict errh) {
    return chunk_open_file_chunk(cq->first, errh);
}


#if defined(HAVE_MMAP)
__attribute_cold__
#endif
__attribute_noinline__
static ssize_t
chunkqueue_write_chunk_file_intermed (const int fd, chunk * const restrict c, log_error_st * const errh)
{
    char buf[16384];
    char *data = buf;
    const off_t count = c->file.length - c->offset;
    uint32_t dlen = count < (off_t)sizeof(buf) ? (uint32_t)count : sizeof(buf);
    chunkqueue cq = {c,c,0,0,0,0,0}; /*(fake cq for chunkqueue_peek_data())*/
    if (0 != chunkqueue_peek_data(&cq, &data, &dlen, errh) && 0 == dlen)
        return -1;
    ssize_t wr;
    do { wr = write(fd, data, dlen); } while (-1 == wr && errno == EINTR);
    return wr;
}


#if defined(HAVE_MMAP)
/*(improved from network_write_mmap.c)*/
static off_t
mmap_align_offset (off_t start)
{
    static off_t pagemask = 0;
    if (0 == pagemask) {
        long pagesize = sysconf(_SC_PAGESIZE);
        if (-1 == pagesize) pagesize = 4096;
        pagemask = ~((off_t)pagesize - 1); /* pagesize always power-of-2 */
    }
    return (start & pagemask);
}
#endif


#if defined HAVE_SYS_SENDFILE_H && defined HAVE_SENDFILE \
 && (!defined _LARGEFILE_SOURCE || defined HAVE_SENDFILE64) \
 && defined(__linux__) && !defined HAVE_SENDFILE_BROKEN
#include <sys/sendfile.h>
#include <stdint.h>
#endif
static ssize_t
chunkqueue_write_chunk_file (const int fd, chunk * const restrict c, log_error_st * const errh)
{
    /*(similar to network_write_file_chunk_mmap(), but does not use send() on
    *  Windows because fd is expected to be file or pipe here, not socket)*/

    if (0 != chunk_open_file_chunk(c, errh))
        return -1;

    const off_t count = c->file.length - c->offset;
    if (0 == count) return 0; /*(sanity check)*/

    ssize_t wr;
  #if defined HAVE_SYS_SENDFILE_H && defined HAVE_SENDFILE \
   && (!defined _LARGEFILE_SOURCE || defined HAVE_SENDFILE64) \
   && defined(__linux__) && !defined HAVE_SENDFILE_BROKEN
    /* Linux kernel >= 2.6.33 supports sendfile() between most fd types */
    off_t offset = c->offset;
    wr = sendfile(fd, c->file.fd, &offset, count<INT32_MAX ? count : INT32_MAX);
    if (wr >= 0) return wr;

    if (wr < 0 && (errno == EINVAL || errno == ENOSYS))
  #endif
    {
      #if defined(HAVE_MMAP)
        /*(caller is responsible for handling SIGBUS if chunkqueue might contain
         * untrusted file, i.e. any file other than lighttpd-created tempfile)*/
        /*(tempfiles are expected for input, MAP_PRIVATE used for portability)*/
        /*(mmaps and writes complete chunk instead of only small parts; files
         * are expected to be temp files with reasonable chunk sizes)*/

        /* (re)mmap the buffer if range is not covered completely */
        if (MAP_FAILED == c->file.mmap.start
            || c->offset < c->file.mmap.offset
            || c->file.length
                 > (off_t)(c->file.mmap.offset + c->file.mmap.length)) {

            if (MAP_FAILED != c->file.mmap.start) {
                munmap(c->file.mmap.start, c->file.mmap.length);
                c->file.mmap.start = MAP_FAILED;
            }

            c->file.mmap.offset = mmap_align_offset(c->offset);
            c->file.mmap.length = c->file.length - c->file.mmap.offset;
            c->file.mmap.start  =
              mmap(NULL, c->file.mmap.length, PROT_READ, MAP_PRIVATE,
                   c->file.fd, c->file.mmap.offset);

          #if 0
            /* close() fd as soon as fully mmap() rather than when done w/ chunk
             * (possibly worthwhile to keep active fd count lower) */
            if (c->file.is_temp && !c->file.refchg) {
                close(c->file.fd);
                c->file.fd = -1;
            }
          #endif
        }

        if (MAP_FAILED != c->file.mmap.start) {
            const char * const data =
              c->file.mmap.start + c->offset - c->file.mmap.offset;
            do { wr = write(fd,data,count); } while (-1 == wr && errno==EINTR);
        }
        else
      #endif
            wr = chunkqueue_write_chunk_file_intermed(fd, c, errh);
    }
    return wr;
}


static ssize_t
chunkqueue_write_chunk_mem (const int fd, const chunk * const restrict c)
{
    const void * const buf = c->mem->ptr + c->offset;
    const size_t count = chunk_buffer_string_length(c->mem) - (size_t)c->offset;
    ssize_t wr;
    do { wr = write(fd, buf, count); } while (-1 == wr && errno == EINTR);
    return wr;
}


ssize_t
chunkqueue_write_chunk (const int fd, chunkqueue * const restrict cq, log_error_st * const restrict errh)
{
    /*(note: expects non-empty cq->first)*/
    chunk * const c = cq->first;
    switch (c->type) {
      case MEM_CHUNK:
        return chunkqueue_write_chunk_mem(fd, c);
      case FILE_CHUNK:
        return chunkqueue_write_chunk_file(fd, c, errh);
      default:
        errno = EINVAL;
        return -1;
    }
}


ssize_t
chunkqueue_write_chunk_to_pipe (const int fd, chunkqueue * const restrict cq, log_error_st * const restrict errh)
{
    /*(note: expects non-empty cq->first)*/
  #ifdef SPLICE_F_NONBLOCK /* splice() temp files to pipe on Linux */
    chunk * const c = cq->first;
    if (c->type == FILE_CHUNK) {
        loff_t abs_offset = c->offset;
        return (0 == chunk_open_file_chunk(c, errh))
          ? splice(c->file.fd, &abs_offset, fd, NULL,
                   (size_t)(c->file.length - c->offset), SPLICE_F_NONBLOCK)
          : -1;
    }
  #endif
    return chunkqueue_write_chunk(fd, cq, errh);
}


void
chunkqueue_small_resp_optim (chunkqueue * const restrict cq)
{
    /*(caller must verify response is small (and non-empty) before calling)*/

    /*(optimization to use fewer syscalls to send a small response by reading
     * small files into memory, thereby avoiding use of sendfile() and multiple
     * calls to writev()  (benefit for cleartext (non-TLS) and <= HTTP/1.1))
     *(If TLS, then will shortly need to be in memory for encryption anyway)*/

    /*assert(cq->first);*/
    chunk *c = cq->first;
    chunk * const filec = c->next;
    if (c->type != MEM_CHUNK || filec != cq->last || filec->type != FILE_CHUNK)
        return;

    const int fd = filec->file.fd;
    if (fd < 0) return; /*(require that file already be open)*/
    off_t offset = filec->offset;
    if (-1 == lseek(fd, offset, SEEK_SET)) return;

    /* Note: there should be no size change in chunkqueue,
     * so cq->bytes_in and cq->bytes_out should not be modified */

    buffer *b = c->mem;
    off_t len = filec->file.length - filec->offset;
    if ((size_t)len > chunk_buffer_string_space(b)) {
        chunk * const nc = chunk_acquire((size_t)len+1);
        c->next = nc;
        nc->next = filec;
        b = nc->mem;
    }

    char * const ptr = b->ptr + chunk_buffer_string_length(b);
    ssize_t rd;
    offset = 0; /*(reuse offset var for offset into mem buffer)*/
    do {
        rd = read(fd, ptr+offset, len-offset);
    } while (rd > 0 ? (offset += rd, len -= rd) : errno == EINTR);
    /*(contents of chunkqueue kept valid even if error reading from file)*/
    buffer_commit(b, offset);
    filec->offset += offset;
    chunkqueue_remove_empty_chunks(cq);
}


int
chunkqueue_peek_data (chunkqueue * const cq,
                      char ** const data, uint32_t * const dlen,
                      log_error_st * const errh)
{
    char * const data_in = *data;
    const uint32_t data_insz = *dlen;
    *dlen = 0;

    for (chunk *c = cq->first; c; ) {
        uint32_t space = data_insz - *dlen;
        switch (c->type) {
          case MEM_CHUNK:
            {
                uint32_t have =
                  chunk_buffer_string_length(c->mem) - (uint32_t)c->offset;
                if (have > space)
                    have = space;
                if (*dlen)
                    memcpy(data_in + *dlen, c->mem->ptr + c->offset, have);
                else
                    *data = c->mem->ptr + c->offset; /*(reference; defer copy)*/
                *dlen += have;
                break;
            }

          case FILE_CHUNK:
            if (c->file.fd >= 0 || 0 == chunk_open_file_chunk(c, errh)) {
                off_t offset = c->offset;
                off_t len = c->file.length - c->offset;
                if (len > (off_t)space)
                    len = (off_t)space;

                if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
                    log_perror(errh, __FILE__, __LINE__, "lseek(\"%s\")",
                               c->mem->ptr);
                    return -1;
                }
                ssize_t rd;
                do {
                    rd = read(c->file.fd, data_in + *dlen, (size_t)len);
                } while (-1 == rd && errno == EINTR);
                if (rd <= 0) { /* -1 error; 0 EOF (unexpected) */
                    log_perror(errh, __FILE__, __LINE__, "read(\"%s\")",
                               c->mem->ptr);
                    return -1;
                }

                *dlen += (uint32_t)rd;
                break;
            }
            return -1;

          default:
            return -1;
        }

        if (*dlen == data_insz)
            break;

        c = c->next;
        if (NULL == c)
            break;

        if (*dlen && *data != data_in) {
            memcpy(data_in, *data, *dlen);
            *data = data_in;
        }
    }

    return 0;
}


int
chunkqueue_read_data (chunkqueue * const cq,
                      char * const data, const uint32_t dlen,
                      log_error_st * const errh)
{
    char *ptr = data;
    uint32_t len = dlen;
    if (chunkqueue_peek_data(cq, &ptr, &len, errh) < 0 || len != dlen)
        return -1;
    if (data != ptr) memcpy(data, ptr, len);
    chunkqueue_mark_written(cq, len);
    return 0;
}


buffer *
chunkqueue_read_squash (chunkqueue * const restrict cq, log_error_st * const restrict errh)
{
    /* read and replace chunkqueue contents with single MEM_CHUNK.
     * cq->bytes_out is not modified */

    off_t cqlen = chunkqueue_length(cq);
    if (cqlen >= UINT32_MAX) return NULL;

    if (cq->first && NULL == cq->first->next && cq->first->type == MEM_CHUNK)
        return cq->first->mem;

    chunk * const c = chunk_acquire((uint32_t)cqlen+1);
    char *data = c->mem->ptr;
    uint32_t dlen = (uint32_t)cqlen;
    int rc = chunkqueue_peek_data(cq, &data, &dlen, errh);
    if (rc < 0) {
        chunk_release(c);
        return NULL;
    }
    buffer_string_set_length(c->mem, dlen);

    chunkqueue_release_chunks(cq);
    chunkqueue_append_chunk(cq, c);
    return c->mem;
}
