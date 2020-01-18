#ifndef _CHUNK_H_
#define _CHUNK_H_
#include "first.h"

#ifdef _AIX  /*(AIX might #define mmap mmap64)*/
#include "sys-mmap.h"
#endif

#include "buffer.h"
#include "array.h"

struct log_error_st;    /*(declaration)*/

typedef struct chunk {
	struct chunk *next;
	enum { MEM_CHUNK, FILE_CHUNK } type;

	buffer *mem; /* either the storage of the mem-chunk or the name of the file */

	/* the size of the chunk is either:
	 * - mem-chunk: buffer_string_length(chunk::mem)
	 * - file-chunk: chunk::file.length
	 */
	off_t  offset; /* octets sent from this chunk */

	struct {
		/* filechunk */
		off_t  start; /* starting offset in the file */
		off_t  length; /* octets to send from the starting offset */

		int    fd;
		int is_temp; /* file is temporary and will be deleted if on cleanup */
		struct {
			char   *start; /* the start pointer of the mmap'ed area */
			size_t length; /* size of the mmap'ed area */
			off_t  offset; /* start is <n> octet away from the start of the file */
		} mmap;
	} file;
} chunk;

typedef struct chunkqueue {
	chunk *first;
	chunk *last;

	off_t bytes_in, bytes_out;

	const array *tempdirs;
	off_t upload_temp_file_size;
	unsigned int tempdir_idx;
} chunkqueue;

__attribute_returns_nonnull__
buffer * chunk_buffer_acquire(void);

void chunk_buffer_release(buffer *b);

void chunkqueue_chunk_pool_clear(void);
void chunkqueue_chunk_pool_free(void);

__attribute_returns_nonnull__
chunkqueue *chunkqueue_init(void);

void chunkqueue_set_chunk_size (size_t sz);
void chunkqueue_set_tempdirs_default_reset (void);
void chunkqueue_set_tempdirs_default (const array *tempdirs, off_t upload_temp_file_size);
void chunkqueue_set_tempdirs(chunkqueue * restrict cq, const array * restrict tempdirs, off_t upload_temp_file_size);
void chunkqueue_append_file(chunkqueue * restrict cq, const buffer * restrict fn, off_t offset, off_t len); /* copies "fn" */
void chunkqueue_append_file_fd(chunkqueue * restrict cq, const buffer * restrict fn, int fd, off_t offset, off_t len); /* copies "fn" */
void chunkqueue_append_mem(chunkqueue * restrict cq, const char * restrict mem, size_t len); /* copies memory */
void chunkqueue_append_mem_min(chunkqueue * restrict cq, const char * restrict mem, size_t len); /* copies memory */
void chunkqueue_append_buffer(chunkqueue * restrict cq, buffer * restrict mem); /* may reset "mem" */
void chunkqueue_append_chunkqueue(chunkqueue * restrict cq, chunkqueue * restrict src);

__attribute_returns_nonnull__
buffer * chunkqueue_prepend_buffer_open_sz(chunkqueue *cq, size_t sz);

__attribute_returns_nonnull__
buffer * chunkqueue_prepend_buffer_open(chunkqueue *cq);

void chunkqueue_prepend_buffer_commit(chunkqueue *cq);

__attribute_returns_nonnull__
buffer * chunkqueue_append_buffer_open_sz(chunkqueue *cq, size_t sz);

__attribute_returns_nonnull__
buffer * chunkqueue_append_buffer_open(chunkqueue *cq);

void chunkqueue_append_buffer_commit(chunkqueue *cq);

int chunkqueue_append_mem_to_tempfile(chunkqueue * restrict cq, const char * restrict mem, size_t len, struct log_error_st * const restrict errh);

/* functions to handle buffers to read into: */
/* obtain/reserve memory in chunkqueue at least len (input) size,
 * return pointer to memory with len (output) available for use
 * modifying the chunkqueue invalidates the memory area.
 * should always be followed by chunkqueue_get_memory(),
 *  even if nothing was read.
 * pass 0 in len for mem at least half of chunk_buf_sz
 */
__attribute_returns_nonnull__
char * chunkqueue_get_memory(chunkqueue * restrict cq, size_t * restrict len);
/* commit len bytes of mem obtained from chunkqueue_get_memory() */
void chunkqueue_use_memory(chunkqueue * restrict cq, chunk *ckpt, size_t len);

/* mark first "len" bytes as written (incrementing chunk offsets)
 * and remove finished chunks
 */
void chunkqueue_mark_written(chunkqueue *cq, off_t len);

void chunkqueue_remove_finished_chunks(chunkqueue *cq);

void chunkqueue_steal(chunkqueue * restrict dest, chunkqueue * restrict src, off_t len);
int chunkqueue_steal_with_tempfiles(chunkqueue * restrict dest, chunkqueue * restrict src, off_t len, struct log_error_st * const restrict errh);

int chunkqueue_open_file_chunk(chunkqueue * restrict cq, struct log_error_st * const restrict errh);

void chunkqueue_compact_mem(chunkqueue *cq, size_t clen);

__attribute_pure__
off_t chunkqueue_length(chunkqueue *cq);

void chunkqueue_free(chunkqueue *cq);
void chunkqueue_reset(chunkqueue *cq);

__attribute_pure__
static inline int chunkqueue_is_empty(const chunkqueue *cq);
static inline int chunkqueue_is_empty(const chunkqueue *cq) {
	return NULL == cq->first;
}

#endif
