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
#include "sys-setjmp.h"
#include "sys-unistd.h" /* <unistd.h> */

#include <stdlib.h>
#include <fcntl.h>

#include <errno.h>
#include <string.h>


#ifdef HAVE_MMAP

#define MMAP_CHUNK_SIZE (512*1024)

__attribute_cold__
/*__attribute_noinline__*/
static off_t
mmap_pagemask (void)
{
  #ifndef _WIN32
    long pagesize = sysconf(_SC_PAGESIZE);
  #else
    long pagesize = -1; /*(not implemented (yet))*/
  #endif
    if (-1 == pagesize) pagesize = 4096;
    force_assert(pagesize < MMAP_CHUNK_SIZE);
    return ~((off_t)pagesize - 1); /* pagesize always power-of-2 */
}

#if 0
static off_t
mmap_align_offset (off_t start)
{
    static off_t pagemask = 0;
    if (0 == pagemask)
        pagemask = mmap_pagemask();
    return (start & pagemask);
}
#endif

#define mmap_align_offset(offset) ((offset) & chunk_pagemask)
static off_t chunk_pagemask = 0;
static int chunk_mmap_flags = MAP_SHARED;

#endif /* HAVE_MMAP */


/* default 1 MB */
#define DEFAULT_TEMPFILE_SIZE (1 * 1024 * 1024)

static size_t chunk_buf_sz = 8192;
static chunk *chunks, *chunks_oversized, *chunks_filechunk;
static chunk *chunk_buffers;
static int chunks_oversized_n;
static const array *chunkqueue_default_tempdirs = NULL;
static off_t chunkqueue_default_tempfile_size = DEFAULT_TEMPFILE_SIZE;
static const char *env_tmpdir = NULL;

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

  #ifdef HAVE_MMAP /*(extend this func to initialize statics at startup)*/
    if (0 == chunk_pagemask)
        chunk_pagemask = mmap_pagemask();
    chunk_mmap_flags = MAP_SHARED;
  #endif
}

chunkqueue *chunkqueue_init(chunkqueue *cq) {
	/* (if caller passes non-NULL cq, it must be 0-init) */
	if (NULL == cq)
		cq = ck_calloc(1, sizeof(*cq));

      #if 0 /*(zeroed by calloc())*/
	cq->first = NULL;
	cq->last = NULL;
      #endif

	cq->upload_temp_file_size = chunkqueue_default_tempfile_size;

	return cq;
}

__attribute_returns_nonnull__
static chunk *chunk_init(void) {
	chunk * const restrict c = ck_calloc(1, sizeof(*c));

      #if 0 /*(zeroed by calloc())*/
	c->type = MEM_CHUNK;
	c->next = NULL;
	c->offset = 0;
	c->file.length = 0;
	c->file.is_temp = 0;
	c->file.busy = 0;
	c->file.flagmask = 0;
	c->file.view = NULL;
      #endif
	c->file.fd = -1;

	c->mem = buffer_init();
	return c;
}

__attribute_noinline__
__attribute_returns_nonnull__
static chunk *chunk_init_sz(size_t sz) {
	chunk * const restrict c = chunk_init();
	buffer_string_prepare_copy(c->mem, sz-1);
	return c;
}

#ifdef HAVE_MMAP

__attribute_malloc__
__attribute_returns_nonnull__
static void * chunk_file_view_init (void) {
    chunk_file_view * const restrict cfv = ck_calloc(1, sizeof(*cfv));
    cfv->mptr = MAP_FAILED;
  #if 0 /*(zeroed by calloc())*/
    cfv->mlen = 0;
    cfv->foff = 0;
  #endif
    cfv->refcnt = 1;
    return cfv;
}

__attribute_nonnull__()
static chunk_file_view * chunk_file_view_release (chunk_file_view *cfv) {
    if (0 == --cfv->refcnt) {
        if (MAP_FAILED != cfv->mptr)
            munmap(cfv->mptr, (size_t)cfv->mlen);
        free(cfv);
    }
    return NULL;
}

__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
static chunk_file_view * chunk_file_view_failed (chunk_file_view *cfv) {
    return chunk_file_view_release(cfv);
}

#endif /* HAVE_MMAP */

ssize_t
chunk_file_pread (int fd, void *buf, size_t count, off_t offset)
{
    /*(expects open file for non-empty FILE_CHUNK)*/
  #ifndef HAVE_PREAD
    /*(On systems without pread() or equivalent, lseek() is repeated if this
     * func is called in a loop, but this func is generally used on small files,
     * or reading a small bit at a time.  Even in the case of mod_deflate, files
     * are not expected to be excessively large.) */
    if (-1 == lseek(fd, offset, SEEK_SET))
        return -1;
  #endif

    ssize_t rd;
    do {
      #ifdef HAVE_PREAD
        rd =pread(fd, buf, count, offset);
      #else
        rd = read(fd, buf, count);
      #endif
    } while (-1 == rd && errno == EINTR);
    return rd;
}

#ifdef HAVE_PREADV2
#if defined(HAVE_SYS_UIO_H)
# include <sys/uio.h>
#endif
static ssize_t
chunk_file_preadv2_flags (chunk *c)
{
    if (0 == c->file.flagmask) {
        /* Initialize mask.  About to make syscall to preadv2(), so a
         * few extra instructions to avoid failing syscall is worthwhile */
        c->file.flagmask = RWF_NOWAIT;

        /* Do not attempt preadv2() RWF_NOWAIT on temporary files;
         * strong possibility to be on tmpfs or, if not, likely that tmpfile
         * will still be in page cache when read after being written */
        const char * const fn = c->mem->ptr; /* check "/tmp/" or "/dev/shm/" */
        if (buffer_clen(c->mem) > 5 && fn[4] == '/'
            && (   (fn[1] == 't' && fn[2] == 'm' && fn[3] == 'p')
                || (fn[1] == 'd' && fn[2] == 'e' && fn[3] == 'v')))
            c->file.flagmask = ~RWF_NOWAIT;
      #if 0
        /* already set in chunkqueue_get_append_newtempfile()
         * c->file.is_temp generally should not be set elsewhere
         * (mod_deflate sets is_temp when writing to cache file)
         * (mod_webdav sets is_temp when writing file for PUT) */
        if (c->file.is_temp)
            c->file.flagmask = ~RWF_NOWAIT;
      #endif
    }
    return (RWF_NOWAIT & c->file.flagmask);
}
#endif

ssize_t
chunk_file_pread_chunk (chunk *c, void *buf, size_t count)
{
    /*(expects open file for non-empty FILE_CHUNK)*/
  #if 0 /*(handled by callers)*/
    const off_t len = c->file.length - c->offset;
    if (len < (off_t)count) count = (size_t)len;
  #endif
  #ifdef HAVE_PREADV2
    struct iovec iov[1] = { { buf, count } };
    const int flags = !c->file.busy ? chunk_file_preadv2_flags(c) : 0;
    c->file.busy = 0;
    ssize_t rd = preadv2(c->file.fd, iov, 1, c->offset, flags);
    if (__builtin_expect( (rd > 0), 1)) {
        return rd;
    }
    if (__builtin_expect( (rd < 0), 1)) {
        /* EINTR should be rare since sigaction SA_RESTART is set with SIGCHLD
         * and other signals are expected to be rare.  For convenience, treat
         * EINTR as if EAGAIN was received so that every caller does not need
         * to check EINTR. (sigaction() expected to be present with preadv2())
         * Callers should check c->file.busy before propagating error. */
        int errnum = errno;
        if (errnum == EOPNOTSUPP) {  /* WTH?  tmpfs not supported ?!?! */
            c->file.flagmask = ~RWF_NOWAIT;
            return chunk_file_pread_chunk(c, buf, count);/*(tail recurse once)*/
        }
        c->file.busy = (errnum == EAGAIN || errnum == EINTR);
        return rd;
    }
    /* Linux 5.9 and Linux 5.10 have a bug where preadv2() with the
     * RWF_NOWAIT flag may return 0 even when not at end of file.
     * (Unfortunately, Linux 5.10 is a long-term-support (LTS) release) */
  #endif

    return chunk_file_pread(c->file.fd, buf, count, c->offset);
}

static void chunk_reset_file_chunk(chunk *c) {
	if (c->file.is_temp) {
		c->file.is_temp = 0;
	  #ifdef _WIN32 /*(not expecting c->file.refchg w/ .is_temp)*/
		if (!c->file.refchg && c->file.fd != -1) {
			fdio_close_file(c->file.fd);
			c->file.fd = -1;
		}
	  #endif
		if (!buffer_is_blank(c->mem))
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
  #ifdef HAVE_MMAP
	if (c->file.view)
		c->file.view = chunk_file_view_release(c->file.view);
  #endif
	c->file.fd = -1;
	c->file.length = 0;
	c->file.busy = 0;
	c->file.flagmask = 0;
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
    /* XXX: chunk_buffer_yield() may have removed need for list size limit */
    if (chunks_oversized_n < 64 && chunk_buf_sz >= 4096) {
        ++chunks_oversized_n;
        chunk **co = &chunks_oversized;
        while (*co && sz < (*co)->mem->size) co = &(*co)->next;
        c->next = *co;
        *co = c;
    }
    else {
        buffer * const tb = chunks_oversized ? chunks_oversized->mem : NULL;
        if (tb && tb->size < sz) {
            /* swap larger mem block onto head of list; free smaller mem */
            chunks_oversized->mem = c->mem;
            c->mem = tb;
        }
        chunk_free(c);
    }
}

__attribute_noinline__
__attribute_returns_nonnull__
static buffer * chunk_buffer_acquire_sz(const size_t sz) {
    chunk *c;
    buffer *b;
    if (sz <= (chunk_buf_sz|1)) {
        if (chunks) {
            c = chunks;
            chunks = c->next;
        }
        else
            c = chunk_init_sz(chunk_buf_sz);
    }
    else {
        c = chunk_pop_oversized(sz);
        if (NULL == c) {
            /*(round up to nearest chunk_buf_sz)*/
            /* NB: round down power-2 + 1 to avoid excess allocation
             * (sz & ~1uL) relies on buffer_realloc() adding +1 *and* on callers
             * of this func never passing power-2 + 1 sz unless direct caller
             * adds +1 for '\0', as is done in chunk_buffer_prepare_append() */
            c = chunk_init_sz(((sz&~1uL)+(chunk_buf_sz-1)) & ~(chunk_buf_sz-1));
        }
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
        if (b->size == (chunk_buf_sz|1)) {
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

void chunk_buffer_yield(buffer *b) {
    if (b->size == (chunk_buf_sz|1)) return;

    buffer * const cb = chunk_buffer_acquire_sz(chunk_buf_sz);
    buffer tb = *b;
    *b = *cb;
    *cb = tb;
    chunk_buffer_release(cb);
}

size_t chunk_buffer_prepare_append(buffer * const b, size_t sz) {
    if (sz > buffer_string_space(b)) {
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
    return buffer_string_space(b);
}

__attribute_noinline__
__attribute_returns_nonnull__
static chunk * chunk_acquire(size_t sz) {
    if (sz <= (chunk_buf_sz|1)) {
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

    return chunk_init_sz(sz);
}

static void chunk_release(chunk *c) {
    const size_t sz = c->mem->size;
    if (sz == (chunk_buf_sz|1)) {
        chunk_reset(c);
        c->next = chunks;
        chunks = c;
    }
    else if (sz > chunk_buf_sz) {
        chunk_reset(c);
        chunk_push_oversized(c, sz);
    }
    else if (c->type == FILE_CHUNK) {
        chunk_reset(c);
        c->next = chunks_filechunk;
        chunks_filechunk = c;
    }
    else {
        chunk_free(c);
    }
}

__attribute_returns_nonnull__
static chunk * chunk_acquire_filechunk(void) {
    if (chunks_filechunk) {
        chunk *c = chunks_filechunk;
        chunks_filechunk = c->next;
        return c;
    }
    return chunk_init();
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
    for (chunk *next, *c = chunks_filechunk; c; c = next) {
        next = c->next;
        chunk_free(c);
    }
    chunks_filechunk = NULL;
}

void chunkqueue_chunk_pool_free(void)
{
    chunkqueue_chunk_pool_clear();
    for (chunk *next, *c = chunk_buffers; c; c = next) {
        next = c->next;
      #if 1 /*(chunk_buffers contains MEM_CHUNK with (c->mem == NULL))*/
        free(c);
      #else /*(c->mem = buffer_init() is no longer necessary below)*/
        c->mem = buffer_init(); /*(chunk_reset() expects c->mem != NULL)*/
        chunk_free(c);
      #endif
    }
    chunk_buffers = NULL;
}

__attribute_pure__
static off_t chunk_remaining_length(const chunk *c) {
    /* MEM_CHUNK or FILE_CHUNK */
    return (c->type == MEM_CHUNK
              ? (off_t)buffer_clen(c->mem)
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

__attribute_nonnull__()
__attribute_returns_nonnull__
static chunk * chunkqueue_append_file_chunk(chunkqueue * const restrict cq, const buffer * const restrict fn, off_t offset, off_t len) {
    chunk * const c = chunk_acquire_filechunk();
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
	    && buffer_string_space(c->mem) >= len) {
		buffer_append_string_len(c->mem, mem, len);
		cq->bytes_in += len;
		return 1;
	}
	return 0;
}


void chunkqueue_append_buffer(chunkqueue * const restrict cq, buffer * const restrict mem) {
	chunk *c;
	const size_t len = buffer_clen(mem);
	if (len < 1024 && chunkqueue_append_mem_extend_chunk(cq, mem->ptr, len)) {
		buffer_clear(mem);
		return;
	}

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

	c = chunk_init_sz(len+1);
	chunkqueue_append_chunk(cq, c);
	cq->bytes_in += len;
	buffer_copy_string_len(c->mem, mem, len);
}


void chunkqueue_append_chunkqueue(chunkqueue * const restrict cq, chunkqueue * const restrict src) {
	if (NULL == src->first) return;

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
	cq->bytes_in += buffer_clen(cq->first->mem);
}


buffer * chunkqueue_append_buffer_open_sz(chunkqueue *cq, size_t sz) {
	chunk * const c = chunkqueue_append_mem_chunk(cq, sz);
	return c->mem;
}


buffer * chunkqueue_append_buffer_open(chunkqueue *cq) {
	return chunkqueue_append_buffer_open_sz(cq, chunk_buf_sz);
}


void chunkqueue_append_buffer_commit(chunkqueue *cq) {
	cq->bytes_in += buffer_clen(cq->last->mem);
}


char * chunkqueue_get_memory(chunkqueue * const restrict cq, size_t * const restrict len) {
	size_t sz = *len ? *len : (chunk_buf_sz >> 1);
	buffer *b;
	chunk *c = cq->last;
	if (NULL != c && MEM_CHUNK == c->type) {
		/* return pointer into existing buffer if large enough */
		size_t avail = buffer_string_space(c->mem);
		if (avail >= sz) {
			*len = avail;
			b = c->mem;
			return b->ptr + buffer_clen(b);
		}
	}

	/* allocate new chunk */
	b = chunkqueue_append_buffer_open_sz(cq, sz);
	*len = buffer_string_space(b);
	return b->ptr;
}

void chunkqueue_use_memory(chunkqueue * const restrict cq, chunk *ckpt, size_t len) {
    buffer *b = cq->last->mem;

    if (__builtin_expect( (len > 0), 1)) {
        buffer_commit(b, len);
        cq->bytes_in += len;
        if (cq->last == ckpt || NULL == ckpt || MEM_CHUNK != ckpt->type
            || len > buffer_string_space(ckpt->mem)) return;

        buffer_append_string_buffer(ckpt->mem, b);
    }
    else if (!buffer_is_blank(b)) { /*(cq->last == ckpt)*/
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
    if (0 == chunk_remaining_length(c))
        chunkqueue_remove_empty_chunks(cq);
}

void chunkqueue_set_tempdirs_default (const array *tempdirs, off_t upload_temp_file_size) {
    if (upload_temp_file_size == 0)
        upload_temp_file_size = DEFAULT_TEMPFILE_SIZE;
    chunkqueue_default_tempdirs = tempdirs;
    chunkqueue_default_tempfile_size = upload_temp_file_size;

    env_tmpdir = getenv("TMPDIR");
    #ifdef _WIN32
    if (NULL == env_tmpdir) env_tmpdir = getenv("TEMP");
    #endif
    if (NULL == env_tmpdir) env_tmpdir = "/var/tmp";
}

void chunkqueue_set_tempdirs(chunkqueue * const restrict cq, off_t upload_temp_file_size) {
    if (upload_temp_file_size == 0)
        upload_temp_file_size = chunkqueue_default_tempfile_size;
    cq->upload_temp_file_size = upload_temp_file_size;
    cq->tempdir_idx = 0;
}

const char *chunkqueue_env_tmpdir(void) {
    /*(chunkqueue_set_tempdirs_default() must have been called at startup)*/
    return env_tmpdir;
}

__attribute_noinline__
static void chunkqueue_dup_file_chunk_fd (chunk * const restrict d, const chunk * const restrict c) {
    /*assert(d != c);*/
    /*assert(d->type == FILE_CHUNK);*/
    /*assert(c->type == FILE_CHUNK);*/
    if (c->file.fd >= 0) {
        if (c->file.refchg) {
            d->file.fd = c->file.fd;
            d->file.ref = c->file.ref;
            d->file.refchg = c->file.refchg;
            d->file.refchg(d->file.ref, 1);
        }
        else
            d->file.fd = fdevent_dup_cloexec(c->file.fd);
      #ifdef HAVE_MMAP
        if ((d->file.view = c->file.view))
            ++d->file.view->refcnt;
      #endif
    }
}

__attribute_noinline__
static void chunkqueue_steal_partial_file_chunk(chunkqueue * const restrict dest, const chunk * const restrict c, const off_t len) {
    chunkqueue_append_file(dest, c->mem, c->offset, len);
    chunkqueue_dup_file_chunk_fd(dest->last, c);
}

void chunkqueue_steal(chunkqueue * const restrict dest, chunkqueue * const restrict src, off_t len) {
	/*(0-length first chunk (unexpected) is removed from src even if len == 0;
         * progress is made when caller loops on this func)*/
	off_t clen;
	do {
		chunk * const c = src->first;
		if (__builtin_expect( (NULL == c), 0)) break;

		clen = chunk_remaining_length(c);

		if (len >= clen) {
			/* move complete chunk */
			src->first = c->next;
			if (c == src->last) src->last = NULL;

			if (__builtin_expect( (0 != clen), 1)) {
				chunkqueue_append_chunk(dest, c);
				dest->bytes_in += clen;
			}
			else /* drop empty chunk */
				chunk_release(c);
		} else {
			/* copy partial chunk */

			switch (c->type) {
			case MEM_CHUNK:
				chunkqueue_append_mem(dest, c->mem->ptr + c->offset, len);
				break;
			case FILE_CHUNK:
				/* tempfile flag is in "last" chunk after the split */
				chunkqueue_steal_partial_file_chunk(dest, c, len);
				break;
			}

			c->offset += len;
			clen = len;
		}

		src->bytes_out += clen;
	} while ((len -= clen));
}

static int chunkqueue_get_append_mkstemp(buffer * const b, const char *path, const uint32_t len) {
    buffer_copy_path_len2(b,path,len,CONST_STR_LEN("lighttpd-upload-XXXXXX"));
  #if defined(HAVE_SPLICE) && defined(HAVE_PWRITE)
    /*(splice() rejects O_APPEND target; omit flag if also using pwrite())*/
    return fdevent_mkostemp(b->ptr, 0);
  #else
    return fdevent_mkostemp(b->ptr, O_APPEND);
  #endif
}

static chunk *chunkqueue_get_append_newtempfile(chunkqueue * const restrict cq, log_error_st * const restrict errh) {
    static const buffer emptyb = { "", 0, 0 };
    chunk * const restrict last = cq->last;
    chunk * const restrict c = chunkqueue_append_file_chunk(cq, &emptyb, 0, 0);
    const array * const restrict tempdirs = chunkqueue_default_tempdirs;
    buffer * const restrict template = c->mem;
    c->file.is_temp = 1;
  #ifdef HAVE_PREADV2
    /* strong possibility to be on tmpfs or, if not, likely that tmpfile
     * will still be in page cache when read after being written */
    c->file.flagmask = ~RWF_NOWAIT;
  #endif

    if (tempdirs && tempdirs->used) {
        /* we have several tempdirs, only if all of them fail we jump out */
        for (errno = EIO; cq->tempdir_idx < tempdirs->used; ++cq->tempdir_idx) {
            data_string *ds = (data_string *)tempdirs->data[cq->tempdir_idx];
            c->file.fd =
              chunkqueue_get_append_mkstemp(template, BUF_PTR_LEN(&ds->value));
            if (-1 != c->file.fd) return c;
        }
    }
    else {
        const char *tmpdir = chunkqueue_env_tmpdir();
        c->file.fd =
          chunkqueue_get_append_mkstemp(template, tmpdir, strlen(tmpdir));
        if (-1 != c->file.fd) return c;
    }

    /* (report only last error to mkstemp() even if multiple temp dirs tried) */
    log_perror(errh, __FILE__, __LINE__,
      "opening temp-file failed: %s", template->ptr);
    /* remove (failed) final chunk */
    c->file.is_temp = 0;
    if ((cq->last = last))
        last->next = NULL;
    else
        cq->first = NULL;
    chunk_release(c);
    return NULL;
}

__attribute_cold__
static int chunkqueue_close_tempchunk (chunk * const restrict c, log_error_st * const restrict errh) {
    force_assert(0 == c->file.refchg); /*(else should not happen)*/
    int rc = close(c->file.fd);
    c->file.fd = -1;
    if (0 != rc) {
        log_perror(errh, __FILE__, __LINE__,
          "close() temp-file %s failed", c->mem->ptr);
        return 0;
    }
    return 1;
}

static chunk *chunkqueue_get_append_tempfile(chunkqueue * const restrict cq, log_error_st * const restrict errh) {
    /*
     * if the last chunk is
     * - smaller than cq->upload_temp_file_size
     * -> append to it (and it then might exceed cq->upload_temp_file_size)
     * otherwise
     * -> create a new chunk
     */

    chunk * const c = cq->last;
    if (NULL != c && c->file.is_temp && c->file.fd >= 0) {

        off_t upload_temp_file_size = cq->upload_temp_file_size
                                    ? cq->upload_temp_file_size
                                    : chunkqueue_default_tempfile_size;
        if (c->file.length < upload_temp_file_size)
            return c; /* ok, take the last chunk for our job */

        /* the chunk is too large now, close it */
        if (!chunkqueue_close_tempchunk(c, errh))
            return NULL;
    }
    return chunkqueue_get_append_newtempfile(cq, errh);
}

__attribute_cold__
static int chunkqueue_append_tempfile_err(chunkqueue * const cq, log_error_st * const restrict errh, chunk * const c) {
    const int errnum = errno;
    if (errnum == EINTR) return 1; /* retry */

    const array * const tempdirs = chunkqueue_default_tempdirs;
    int retry = (errnum == ENOSPC && tempdirs
                 && ++cq->tempdir_idx < tempdirs->used);
    if (!retry)
        log_perror(errh, __FILE__, __LINE__,
          "write() temp-file %s failed", c->mem->ptr);

    if (0 == chunk_remaining_length(c)) {
        /*(remove empty chunk and unlink tempfile)*/
        chunkqueue_remove_empty_chunks(cq);
    }
    else {/*(close tempfile; avoid later attempts to append)*/
        if (!chunkqueue_close_tempchunk(c, errh))
            retry = 0;
    }
    return retry;
}

__attribute_cold__
__attribute_noinline__
static int chunkqueue_to_tempfiles(chunkqueue * const restrict dest, log_error_st * const restrict errh) {
    /* transfer chunks from dest to src, adjust dest->bytes_in, and then call
     * chunkqueue_steal_with_tempfiles() to write chunks from src back into
     * dest, but into tempfiles.   chunkqueue_steal_with_tempfiles() calls back
     * into chunkqueue_append_mem_to_tempfile(), but will not re-enter this func
     * since chunks moved to src, and dest made empty before recursive call */
    const off_t cqlen = chunkqueue_length(dest);
    chunkqueue src = *dest; /*(copy struct)*/
    dest->first = dest->last = NULL;
    dest->bytes_in -= cqlen;
    if (0 == chunkqueue_steal_with_tempfiles(dest, &src, cqlen, errh))
        return 0;
    else {
        const int errnum = errno;
        chunkqueue_release_chunks(&src);
        return -errnum;
    }
}

int chunkqueue_append_mem_to_tempfile(chunkqueue * const restrict dest, const char * restrict mem, size_t len, log_error_st * const restrict errh) {
	chunk *dst_c = dest->first;

	/* check if prior MEM_CHUNK(s) exist and write to tempfile
	 * (check first chunk only, since if we are using tempfiles, then
	 *  we expect further chunks to be tempfiles after starting tempfiles)*/
	if (dst_c && dst_c->type == MEM_CHUNK
	    && 0 != chunkqueue_to_tempfiles(dest, errh)) {
		return -1;
	}

	do {
		/*(aside: arg len is permitted to be 0 and creates tempfile as a
		 * side effect.  This is used by mod_ssi for ssi exec, as the func
		 * chunkqueue_get_append_tempfile() is not public.  The result is
		 * an empty chunk at the end of the chunkqueue, which typically
		 * should be avoided)*/
		dst_c = chunkqueue_get_append_tempfile(dest, errh);
		if (NULL == dst_c)
			return -1;
	      #ifdef __COVERITY__
		if (dst_c->file.fd < 0) return -1;
	      #endif
		/* (0 == len) for creation of empty tempfile, but caller should
		 * take pains to avoid leaving 0-length chunk in chunkqueue */
		if (0 == len) return 0;
	      #ifdef HAVE_PWRITE
		/* coverity[negative_returns : FALSE] */
		const ssize_t written =pwrite(dst_c->file.fd, mem, len, dst_c->file.length);
	      #else
		/* coverity[negative_returns : FALSE] */
		const ssize_t written = write(dst_c->file.fd, mem, len);
	      #endif

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
		} else if (!chunkqueue_append_tempfile_err(dest, errh, dst_c)) {
			break; /* return -1; */
		} /* else continue; retry */
	} while (len);

	return -1;
}

#ifdef HAVE_PWRITEV

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

__attribute_cold__
__attribute_noinline__
static ssize_t chunkqueue_append_cqmem_to_tempfile_partial(chunkqueue * const dest, chunk * const c, ssize_t wr, log_error_st * const restrict errh) {
    /* recover from partial write of existing dest MEM_CHUNK to tempfile */
    chunk *ckpt = dest->first;
    while (ckpt->next != c) ckpt = ckpt->next;
    ckpt->next = NULL;
    dest->last = ckpt;
    dest->bytes_in  -= wr; /*(avoid double count in dest cq)*/
    dest->bytes_out -= wr;
    chunkqueue_mark_written(dest, wr);/*(remove MEM_CHUNK written to tempfile)*/

    c->next = dest->first; /*(place tempfile at beginning of dest cq)*/
    dest->first = c;
    return (0 == chunkqueue_to_tempfiles(dest, errh)) ? 0 : -1;
}

static ssize_t chunkqueue_append_cqmem_to_tempfile(chunkqueue * const restrict dest, chunkqueue * const restrict src, off_t len, log_error_st * const restrict errh) {
    /* write multiple MEM_CHUNKs to tempfile in single pwritev() syscall */
    /*(could lseek() and writev() if pwritev() is not available,
     * but if writev() is available, pwritev() is likely available,
     * e.g. any modern Linux or *BSD, and possibly anything not Windows)*/
    unsigned int iovcnt = 0;
    struct iovec iov[16];

    off_t dlen = 0;
    chunk *c;
    for (c = dest->first; c && c->type == MEM_CHUNK; c = c->next) {
        const off_t clen = chunk_remaining_length(c);
        iov[iovcnt].iov_base = c->mem->ptr + c->offset;
        iov[iovcnt].iov_len  = (size_t)clen;
        dlen += clen;
        ++iovcnt;
        if (__builtin_expect( (iovcnt == sizeof(iov)/sizeof(*iov)), 0))
            break; /*(not expecting large number of MEM_CHUNK)*/
    }
    if (__builtin_expect( (c != NULL), 0) && dest->first->type == MEM_CHUNK) {
        /*(expecting only MEM_CHUNK if dest cq starts w/ MEM_CHUNK)*/
        /*(use less efficient fallback if that assumption does not hold true)*/
        if (0 != chunkqueue_to_tempfiles(dest, errh))
            return -1;
        dlen = 0;
        iovcnt = 0;
    }

    if (__builtin_expect( (iovcnt < sizeof(iov)/sizeof(*iov)), 1)) {
        for (c = src->first; c && c->type == MEM_CHUNK; c = c->next) {
            off_t clen = chunk_remaining_length(c);
            if (clen > len) clen = len;
            iov[iovcnt].iov_base = c->mem->ptr + c->offset;
            iov[iovcnt].iov_len  = (size_t)clen;
            len -= clen;
            ++iovcnt;
            if (0 == len) break;
            if (__builtin_expect( (iovcnt == sizeof(iov)/sizeof(*iov)), 0))
                break; /*(not expecting large number of MEM_CHUNK)*/
        }
    }

    if (__builtin_expect( (0 == iovcnt), 0)) return 0; /*(should not happen)*/

    c = chunkqueue_get_append_tempfile(dest, errh);
    if (NULL == c)
        return -1;
  #ifdef __COVERITY__
    if (c->file.fd < 0) return -1;
  #endif
    /* coverity[negative_returns : FALSE] */
    ssize_t wr = pwritev(c->file.fd, iov, (int)iovcnt, c->file.length);

    /*(memory use in chunkqueues is expected to be limited before spilling
     * to tempfiles, so common case will write entire iovec to tempfile,
     * and we return amount written *from src cq*, even if partial write;
     * (not looping here to retry writing more, but caller might loop))*/

    if (wr >= 0) {
        c->file.length += wr;
        dest->bytes_in += wr;
        if (dlen) {
            if (__builtin_expect( (wr < dlen), 0))
                return
                  chunkqueue_append_cqmem_to_tempfile_partial(dest,c,wr,errh);
            wr -= (ssize_t)dlen;
            dest->bytes_in  -= dlen; /*(avoid double count in dest cq)*/
            dest->bytes_out -= dlen;
            chunkqueue_mark_written(dest, dlen);
        }
    }
    else if (chunkqueue_append_tempfile_err(dest, errh, c))
        wr = 0; /*(to trigger continue/retry in caller rather than error)*/

    return wr;
}

#endif /* HAVE_PWRITEV */

#ifdef HAVE_SPLICE

__attribute_cold__
__attribute_noinline__
static ssize_t chunkqueue_append_drain_pipe_tempfile(chunkqueue * const restrict cq, const int fd, unsigned int len, log_error_st * const restrict errh) {
    /* attempt to drain full 'len' from pipe
     * (even if len not reduced to opts->max_per_read limit)
     * since data may have already been moved from socket to pipe
     *(returns 0 on success, or -errno (negative errno) if error,
     * even if partial write occurred)*/
    char buf[16384];
    ssize_t rd;
    do {
        do {
            rd = read(fd, buf, sizeof(buf));
        } while (rd < 0 && errno == EINTR);
        if (rd < 0) break;
        if (0 != chunkqueue_append_mem_to_tempfile(cq, buf, (size_t)rd, errh))
            break;
    } while ((len -= (unsigned int)rd));

    if (0 == len)
        return 0;
    else {
        const int errnum = errno;
        if (cq->last && 0 == chunk_remaining_length(cq->last)) {
            /*(remove empty chunk and unlink tempfile)*/
            chunkqueue_remove_empty_chunks(cq);
        }
        return -errnum;
    }
}

ssize_t chunkqueue_append_splice_pipe_tempfile(chunkqueue * const restrict cq, const int fd, unsigned int len, log_error_st * const restrict errh) {
    /* check if prior MEM_CHUNK(s) exist and write to tempfile
     * (check first chunk only, since if we are using tempfiles, then
     *  we expect further chunks to be tempfiles after starting tempfiles)*/
    if (cq->first && cq->first->type == MEM_CHUNK) {
        int rc = chunkqueue_to_tempfiles(cq, errh);
        if (__builtin_expect( (0 != rc), 0)) return rc;
    }

    /*(returns num bytes written, or -errno (negative errno) if error)*/
    ssize_t total = 0;
    do {
        chunk * const c = chunkqueue_get_append_tempfile(cq, errh);
        if (__builtin_expect( (NULL == c), 0)) return -errno;

        loff_t off = c->file.length;
        ssize_t wr = splice(fd, NULL, c->file.fd, &off, len,
                            SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

        if (__builtin_expect(((size_t)wr == len), 1)) {
            c->file.length += len;
            cq->bytes_in += len;
            return total + len;
        }
        else if (wr >= 0) {
            /*(assume EINTR if partial write and retry;
             * retry might fail with ENOSPC if no more space on volume)*/
            cq->bytes_in += wr;
            total += wr;
            len -= (size_t)wr;
            c->file.length += (size_t)wr;
            /* continue; retry */
        }
        else {
            const int errnum = errno;
            switch (errnum) {
              case EAGAIN:
             #ifdef EWOULDBLOCK
             #if EWOULDBLOCK != EAGAIN
              case EWOULDBLOCK:
             #endif
             #endif
                if (0 == chunk_remaining_length(c)) {
                    /*(remove empty chunk and unlink tempfile)*/
                    chunkqueue_remove_empty_chunks(cq);
                }
                return total;
              case EINVAL: /*(assume total == 0 if EINVAL)*/
                wr = chunkqueue_append_drain_pipe_tempfile(cq, fd, len, errh);
                return (0 == wr) ? total + (ssize_t)len : wr;
              default:
                if (!chunkqueue_append_tempfile_err(cq, errh, c))
                    return -errnum;
                break; /* else continue; retry */
            }
        }
    } while (len);
    return -EIO; /*(not reached)*/
}

static int cqpipes[2] = { -1, -1 };

__attribute_cold__
__attribute_noinline__
void chunkqueue_internal_pipes(int init) {
    /*(intended for internal use within a single lighttpd process;
     * must be initialized after fork() and graceful-restart to avoid
     * sharing pipes between processes)*/
    if (-1 != cqpipes[0]) { close(cqpipes[0]); cqpipes[0] = -1; }
    if (-1 != cqpipes[1]) { close(cqpipes[1]); cqpipes[1] = -1; }
    if (init)
        if (0 != fdevent_pipe_cloexec(cqpipes, 262144)) { } /*(ignore error)*/
}

__attribute_cold__
__attribute_noinline__
static void chunkqueue_pipe_read_discard (void) {
    char buf[16384];
    ssize_t rd;
    do {
        rd = read(cqpipes[0], buf, sizeof(buf));
    } while (rd > 0 || (rd < 0 && errno == EINTR));
    if (rd < 0
      #ifdef EWOULDBLOCK
      #if EWOULDBLOCK != EAGAIN
        && errno != EWOULDBLOCK
      #endif
      #endif
        && errno != EAGAIN) {
        chunkqueue_internal_pipes(1); /*(close() and re-initialize)*/
    }
}

ssize_t chunkqueue_append_splice_sock_tempfile(chunkqueue * const restrict cq, const int fd, unsigned int len, log_error_st * const restrict errh) {
    /*(returns num bytes written, or -errno (negative errno) if error)*/
    int * const pipes = cqpipes;
    if (-1 == pipes[1])
        return -EINVAL; /*(not configured; not handled here)*/

    /* splice() socket data to intermediate pipe */
    ssize_t wr = splice(fd, NULL, pipes[1], NULL, len,
                        SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (__builtin_expect( (wr <= 0), 0))
        return -EINVAL; /*(reuse to indicate not handled here)*/
    len = (unsigned int)wr;

    /* splice() data from intermediate pipe to tempfile */
    wr = chunkqueue_append_splice_pipe_tempfile(cq, pipes[0], len, errh);
    if (wr < 0) /* expect (wr == (ssize_t)len) or (wr == -1) */
        chunkqueue_pipe_read_discard();/* discard data from intermediate pipe */
    return wr;
}

#endif /* HAVE_SPLICE */

int chunkqueue_steal_with_tempfiles(chunkqueue * const restrict dest, chunkqueue * const restrict src, off_t len, log_error_st * const restrict errh) {
	/*(0-length first chunk (unexpected) is removed from src even if len == 0;
         * progress is made when caller loops on this func)*/
	off_t clen;
	do {
		chunk * const c = src->first;
		if (__builtin_expect( (NULL == c), 0)) break;

	  #ifdef HAVE_PWRITEV

		if (c->type == MEM_CHUNK) {
			clen = chunkqueue_append_cqmem_to_tempfile(dest, src, len, errh);
			if (__builtin_expect( (clen < 0), 0)) return -1;
			chunkqueue_mark_written(src, clen);
		}
		else { /* (c->type == FILE_CHUNK) */
			clen = chunk_remaining_length(c);
			if (len < clen) clen = len;
			chunkqueue_steal(dest, src, clen);
		}

	  #else

		clen = chunk_remaining_length(c);
		if (len < clen) clen = len;

		switch (c->type) {
		case FILE_CHUNK:
			chunkqueue_steal(dest, src, clen);
			break;

		case MEM_CHUNK:
			/* store bytes from memory chunk in tempfile */
			if (clen
			    && 0 != chunkqueue_append_mem_to_tempfile(dest,
			                                              c->mem->ptr+c->offset,
			                                              clen, errh))
				return -1;
			chunkqueue_mark_written(src, clen);
			break;
		}

	  #endif
	} while ((len -= clen));

	return 0;
}

void chunkqueue_append_cq_range (chunkqueue * const dst, const chunkqueue * const src, off_t offset, off_t len) {
    /* similar to chunkqueue_steal() but copy and append src range to dst cq */
    /* (dst cq and src cq can be the same cq, so neither is marked restrict) */

    /* copy and append range len from src to dst */
    for (const chunk *c = src->first; len > 0 && c != NULL; c = c->next) {
        /* scan into src to range offset (also skips empty chunks) */
        off_t clen = chunk_remaining_length(c);
        if (offset >= clen) {
            offset -= clen;
            continue;
        }
        clen -= offset;
        if (len < clen) clen = len;
        len -= clen;

        if (c->type == FILE_CHUNK) {
            chunkqueue_append_file(dst, c->mem, c->offset + offset, clen);
            chunkqueue_dup_file_chunk_fd(dst->last, c);
        }
        else { /*(c->type == MEM_CHUNK)*/
            /*(string refs would reduce copying,
             * but this path is not expected to be hot)*/
            chunkqueue_append_mem(dst, c->mem->ptr + c->offset + offset, clen);
        }
        offset = 0;
    }
}

void chunkqueue_mark_written(chunkqueue *cq, off_t len) {
    cq->bytes_out += len;

    for (chunk *c = cq->first; c; ) {
        off_t c_len = chunk_remaining_length(c);
        if (len >= c_len) { /* chunk got finished */
            chunk * const x = c;
            c = c->next;
            len -= c_len;
            chunk_release(x);
        }
        else { /* partial chunk */
            c->offset += len;
            cq->first = c;
            return; /* chunk not finished */
        }
    }
    cq->first = cq->last = NULL;
}

void chunkqueue_remove_finished_chunks(chunkqueue *cq) {
    for (chunk *c; (c = cq->first) && 0 == chunk_remaining_length(c); ){
        if (NULL == (cq->first = c->next)) cq->last = NULL;
        chunk_release(c);
    }
}

void chunkqueue_remove_empty_chunks(chunkqueue *cq) {
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
    size_t len = buffer_clen(b) - c->offset;
    memmove(b->ptr, b->ptr+c->offset, len);
    c->offset = 0;
    buffer_truncate(b, len);
}

void chunkqueue_compact_mem(chunkqueue *cq, size_t clen) {
    /* caller must guarantee that chunks in chunkqueue are MEM_CHUNK,
     * which is currently always true when reading input from client */
    chunk *c = cq->first;
    buffer *b = c->mem;
    size_t len = buffer_clen(b) - c->offset;
    if (len >= clen) return;
    if (b->size > clen) {
        if (buffer_string_space(b) < clen - len)
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
        len = buffer_clen(c->mem) - c->offset;
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

int chunk_open_file_chunk(chunk * const restrict c, log_error_st * const restrict errh) {
	if (-1 == c->file.fd) {
		/* (permit symlinks; should already have been checked.  However, TOC-TOU remains) */
		if (-1 == (c->file.fd = fdevent_open_cloexec(c->mem->ptr, 1, O_RDONLY, 0))) {
			log_perror(errh, __FILE__, __LINE__, "open failed: %s",c->mem->ptr);
			return -1;
		}
	}

	/*(skip file size checks if file is temp file created by lighttpd)*/
	if (c->file.is_temp) return 0;

	struct stat st;
	if (-1 == fstat(c->file.fd, &st)) {
		log_perror(errh, __FILE__, __LINE__, "fstat failed");
		return -1;
	}

	/*(ok if file grew, e.g. a log file)*/
	if (c->file.length > st.st_size) {
		log_error(errh, __FILE__, __LINE__, "file shrunk: %s", c->mem->ptr);
		return -1;
	}

	return 0;
}


static ssize_t
chunkqueue_write_data (const int fd, const void *buf, size_t len)
{
    ssize_t wr = 0;
    if (len)
        do { wr = write(fd, buf, len); } while (-1 == wr && errno == EINTR);
    return wr;
}


#ifdef HAVE_MMAP
__attribute_cold__
#endif
__attribute_noinline__
static ssize_t
chunkqueue_write_chunk_file_intermed (const int fd, chunk * const restrict c, log_error_st * const errh)
{
    char buf[16384];
    char *data = buf;
    const off_t len = c->file.length - c->offset;
    /*if (0 == len) return 0;*//*(sanity check)*//*chunkqueue_write_chunk_file*/
    uint32_t dlen = len < (off_t)sizeof(buf) ? (uint32_t)len : sizeof(buf);
    chunkqueue cq = {c,c,0,0,0,0}; /*(fake cq for chunkqueue_peek_data())*/
    if (0 != chunkqueue_peek_data(&cq, &data, &dlen, errh, 0) && 0 == dlen)
        return -1;
    return chunkqueue_write_data(fd, data, dlen);
}


#if defined HAVE_SYS_SENDFILE_H && defined HAVE_SENDFILE \
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

    const off_t len = c->file.length - c->offset;
    if (0 == len) return 0; /*(sanity check)*/

  #if defined HAVE_SYS_SENDFILE_H && defined HAVE_SENDFILE \
   && defined(__linux__) && !defined HAVE_SENDFILE_BROKEN
    /* Linux kernel >= 2.6.33 supports sendfile() between most fd types */
    off_t offset = c->offset;
    const ssize_t wr =
      sendfile(fd, c->file.fd, &offset, len < INT32_MAX ? len : INT32_MAX);
    if (__builtin_expect( (wr >= 0), 1) || (errno != EINVAL && errno != ENOSYS))
        return wr;
    /*(could fallback to mmap, but if sendfile fails on linux, mmap may, too)*/
  #elif defined(HAVE_MMAP)
    /*(chunkqueue_write_chunk() caller must protect against SIGBUS, if needed)*/
    const chunk_file_view * const restrict cfv =
      chunkqueue_chunk_file_view(c, len, errh);
    if (NULL != cfv) {
        const off_t mmap_avail = chunk_file_view_dlen(cfv, c->offset);
        return chunkqueue_write_data(fd, chunk_file_view_dptr(cfv, c->offset),
                                     len <= mmap_avail ? len : mmap_avail);
    }
  #endif

    return chunkqueue_write_chunk_file_intermed(fd, c, errh);
}


static ssize_t
chunkqueue_write_chunk_mem (const int fd, const chunk * const restrict c)
{
    const void * const buf = c->mem->ptr + c->offset;
    const size_t len = buffer_clen(c->mem) - (size_t)c->offset;
    return chunkqueue_write_data(fd, buf, len);
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
  #ifdef HAVE_SPLICE /* splice() temp files to pipe on Linux */
    chunk * const c = cq->first;
    if (c->type == FILE_CHUNK) {
        const size_t len = (size_t)(c->file.length - c->offset);
        loff_t abs_offset = c->offset;
        if (__builtin_expect( (0 == len), 0)) return 0;
        return (0 == chunk_open_file_chunk(c, errh))
          ? splice(c->file.fd, &abs_offset, fd, NULL, len, SPLICE_F_NONBLOCK)
          : -1;
    }
  #endif
    return chunkqueue_write_chunk(fd, cq, errh);
}


void
chunkqueue_small_resp_optim (chunkqueue * const restrict cq)
{
    /*(caller must verify response is small (and non-empty) before calling)*/
    /*(caller must verify first chunk is MEM_CHUNK, i.e. response headers)*/
    /*(caller must verify response is non-zero length)*/

    /*(optimization to use fewer syscalls to send a small response by reading
     * small files into memory, thereby avoiding use of sendfile() and multiple
     * calls to writev()  (benefit for cleartext (non-TLS) and <= HTTP/1.1))
     *(If TLS, then will shortly need to be in memory for encryption anyway)*/

    /*assert(cq->first);*/
    /*assert(cq->first->type == MEM_CHUNK);*/
    /*assert(cq->first->next);*/
    chunk * restrict c = cq->first;
    chunk * const restrict filec = c->next;  /*(require file already be open)*/
    if (filec != cq->last || filec->type != FILE_CHUNK || filec->file.fd < 0)
        return;

    /* Note: there should be no size change in chunkqueue,
     * so cq->bytes_in and cq->bytes_out should not be modified */

    off_t len = filec->file.length - filec->offset;
    if ((size_t)len > buffer_string_space(c->mem)) {
        c->next = chunk_acquire((size_t)len+1);
        c = c->next;
        /*c->next = filec;*/
    }
    /* detach filec from chunkqueue; file expected to be read fully */
    c->next = NULL;
    cq->last = c;

    ssize_t rd;
    off_t offset = 0;
    char * const ptr = buffer_extend(c->mem, len);
    do {
        rd = chunk_file_pread(filec->file.fd, ptr+offset, (size_t)len,
                              filec->offset+offset);
    } while (rd > 0 && (offset += rd, len -= rd));
    /*(contents of chunkqueue kept valid even if error reading from file)*/
    if (__builtin_expect( (0 == len), 1))
        chunk_release(filec);
    else { /*(unexpected; error recovery)*/
        buffer_truncate(c->mem, (uint32_t)(ptr + offset - c->mem->ptr));
        cq->last = c->next = filec;
        if (offset)
            filec->offset += offset;
        else if (__builtin_expect( (cq->first != c), 0)) {
            cq->first->next = filec;
            chunk_release(c);
        }
    }
}


#if 0
#ifdef HAVE_MMAP
__attribute_noinline__
static off_t
chunk_setjmp_memcpy_cb (void *dst, const void *src, off_t len)
{
    /*(on 32-bit systems, caller should assert len <= SIZE_MAX)*/
    memcpy(dst, src, (size_t)len);
    return len;
}
#endif
#endif


int
chunkqueue_peek_data (chunkqueue * const cq,
                      char ** const data, uint32_t * const dlen,
                      log_error_st * const errh, int nowait)
{
    char * const data_in = *data;
    const uint32_t data_insz = *dlen;
    *dlen = 0;

    for (chunk *c = cq->first; c; ) {
        const uint32_t space = data_insz - *dlen;
        switch (c->type) {
          case MEM_CHUNK:
            {
                uint32_t have = buffer_clen(c->mem) - (uint32_t)c->offset;
                if (__builtin_expect( (0 == have), 0))
                    break;
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
                off_t len = c->file.length - c->offset;
                if (__builtin_expect( (0 == len), 0))
                    break;
                if (len > (off_t)space)
                    len = (off_t)space;

            #if 0 /* XXX: might improve performance on some system workloads */
              #ifdef HAVE_MMAP
                /* mmap file to access data
                 * fd need not be kept open for the mmap once
                 * the mmap has been created, but is currently kept open for
                 * other pre-existing logic which checks fd and opens file,
                 * such as the condition for entering this code block above. */
                /* Note: current use is with somewhat large buffers, e.g. 128k.
                 * If larger buffers are used, then upper limit, e.g. 512k,
                 * should be set for 32-bit to avoid address space issues) */
                /* Note: under heavy load (or microbenchmark), system-reported
                 * memory use for RSS can be very, very large, due to presence
                 * of lots and lots of temp file read-only memory maps.
                 * pmap -X and exclude lighttpd mmap files to get a better
                 * view of memory use */
                const chunk_file_view * const restrict cfv = (!c->file.is_temp)
                  ? chunkqueue_chunk_file_view(c, len, errh)
                  : NULL;
                if (cfv && chunk_file_view_dlen(cfv, c->offset) >= len) {
                    /*(check (above) that mapped chunk length >= requested len)*/
                    char * const mdata = chunk_file_view_dptr(cfv, c->offset);
                    if (!c->file.is_temp) {/*(might be changed to policy flag)*/
                        if (sys_setjmp_eval3(chunk_setjmp_memcpy_cb,
                                             data_in+*dlen, mdata, len) < 0) {
                            log_error(errh, __FILE__, __LINE__,
                              "SIGBUS in mmap: %s %d", c->mem->ptr, c->file.fd);
                            return -1;
                        }
                    }
                    else if (*dlen)
                        memcpy(data_in+*dlen, mdata, (size_t)len);
                    else
                        *data = mdata;
                    *dlen += (uint32_t)len;
                    break;
                }
              #endif
            #endif

                c->file.busy |= !nowait; /* trigger blocking read next try */
                ssize_t rd =
                  chunk_file_pread_chunk(c, data_in+*dlen, (size_t)len);
                if (__builtin_expect( (rd <= 0), 0)) {
                    if (nowait && c->file.busy) /* yield */
                        return 0; /* read I/O would block or signal interrupt */
                    /* -1 error; 0 EOF (unexpected) */
                    log_perror(errh, __FILE__, __LINE__, "read(\"%s\")",
                               c->mem->ptr);
                    return -1;
                }

                *dlen += (uint32_t)rd;
                if (nowait && rd != len)
                    return 0;
                break;
            }
            c->file.busy = 0;
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
    if (chunkqueue_peek_data(cq, &ptr, &len, errh, 0) < 0 || len != dlen)
        return -1;
    if (data != ptr) memcpy(data, ptr, len);
    chunkqueue_mark_written(cq, len);
    return 0;
}


chunk *
chunkqueue_read_squash (chunkqueue * const restrict cq, log_error_st * const restrict errh)
{
    /* read and replace chunkqueue contents with single MEM_CHUNK.
     * cq->bytes_out is not modified */

    off_t cqlen = chunkqueue_length(cq);
    if (cqlen >= UINT32_MAX) return NULL;

    if (cq->first && NULL == cq->first->next && cq->first->type == MEM_CHUNK)
        return cq->first;

    chunk * const c = chunk_acquire((uint32_t)cqlen+1);
    char *data = c->mem->ptr;
    uint32_t dlen = (uint32_t)cqlen;
    int rc = chunkqueue_peek_data(cq, &data, &dlen, errh, 0);
    if (rc < 0) {
        chunk_release(c);
        return NULL;
    }
    buffer_truncate(c->mem, dlen);

    chunkqueue_release_chunks(cq);
    chunkqueue_append_chunk(cq, c);
    return c;
}


#ifdef HAVE_MMAP

const chunk_file_view *
chunkqueue_chunk_file_viewadj (chunk * const c, off_t n, log_error_st * restrict errh)
{
    /*assert(c->type == FILE_CHUNK);*/
    if (c->file.fd < 0 && 0 != chunk_open_file_chunk(c, errh))
        return NULL;

    chunk_file_view * restrict cfv = c->file.view;

    if (NULL == cfv) {
        /* XXX: might add global config check to enable/disable mmap use here */
        cfv = c->file.view = chunk_file_view_init();
    }
    else if (MAP_FAILED != cfv->mptr)
        munmap(cfv->mptr, (size_t)cfv->mlen);
        /*cfv->mptr= MAP_FAILED;*//*(assigned below)*/

    cfv->foff = mmap_align_offset(c->offset);

    if (0 != n) {
        cfv->mlen = c->offset - cfv->foff + n;
      #if !(defined(_LP64) || defined(__LP64__) || defined(_WIN64))
        /*(consider 512k blocks if this func is used more generically)*/
        const off_t mmap_chunk_size = 8 * 1024 * 1024;
        if (cfv->mlen > mmap_chunk_size)
            cfv->mlen = mmap_chunk_size;
      #endif
    }
    else
        cfv->mlen = MMAP_CHUNK_SIZE;
    /* XXX: 64-bit might consider larger min block size, or even entire file */
    if (cfv->mlen < MMAP_CHUNK_SIZE)
        cfv->mlen = MMAP_CHUNK_SIZE;
    if (cfv->mlen > c->file.length - cfv->foff)
        cfv->mlen = c->file.length - cfv->foff;

    cfv->mptr = mmap(NULL, (size_t)cfv->mlen, PROT_READ,
                     c->file.is_temp ? MAP_PRIVATE : chunk_mmap_flags,
                     c->file.fd, cfv->foff);

    if (__builtin_expect( (MAP_FAILED == cfv->mptr), 0)) {
        if (__builtin_expect( (errno == EINVAL), 0)) {
            chunk_mmap_flags &= ~MAP_SHARED;
            chunk_mmap_flags |= MAP_PRIVATE;
            cfv->mptr = mmap(NULL, (size_t)cfv->mlen, PROT_READ,
                             MAP_PRIVATE, c->file.fd, cfv->foff);
        }
        if (__builtin_expect( (MAP_FAILED == cfv->mptr), 0)) {
            c->file.view = chunk_file_view_failed(cfv);
            return NULL;
        }
    }

  #if 0 /*(review callers before changing; some expect open file)*/
    /* close() fd as soon as fully mmap() rather than when done w/ chunk
     * (possibly worthwhile to keep active fd count lower)
     * (probably only reasonable if entire file is mapped) */
    if (c->file.is_temp && !c->file.refchg) {
        close(c->file.fd);
        c->file.fd = -1;
    }
  #endif

 #if 0
    /* disable madvise unless we find common cases where there is a benefit
     * (??? madvise for full mmap length or only for original requested n ???)
     * (??? might additional flags param to func to indicate madvise pref ???)
     * (??? might experiment with Linux mmap flags MAP_POPULATE|MAP_PRIVATE)
     * (??? might experiment with madvise MADV_POPULATE_READ (since Linux 5.14))
     * note: caller might be in better position to know if starting an mmap
     * which will be flushed in entirety, and perform madvise at that point,
     * perhaps with MADV_SEQUENTIAL */
  #ifdef HAVE_MADVISE
    if (cfv->mlen > 65536) /*(skip syscall if size <= 64KB)*/
        (void)madvise(cfv->mptr, (size_t)cfv->mlen, MADV_WILLNEED);
  #endif
 #endif

    return cfv;
}

#endif /* HAVE_MMAP */
