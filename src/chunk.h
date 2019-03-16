#ifndef _CHUNK_H_
#define _CHUNK_H_
#include "first.h"

#ifdef _AIX  /*(AIX might #define mmap mmap64)*/
#include "sys-mmap.h"
#endif

#include "buffer.h"
#include "array.h"

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

typedef struct {
	chunk *first;
	chunk *last;

	off_t bytes_in, bytes_out;

	array *tempdirs;
	off_t upload_temp_file_size;
	unsigned int tempdir_idx;
} chunkqueue;

buffer * chunk_buffer_acquire(void);
void chunk_buffer_release(buffer *b);

void chunkqueue_chunk_pool_clear(void);
void chunkqueue_chunk_pool_free(void);

chunkqueue *chunkqueue_init(void);
void chunkqueue_set_chunk_size (size_t sz);
void chunkqueue_set_tempdirs_default_reset (void);
void chunkqueue_set_tempdirs_default (array *tempdirs, off_t upload_temp_file_size);
void chunkqueue_set_tempdirs(chunkqueue *cq, array *tempdirs, off_t upload_temp_file_size);
void chunkqueue_append_file(chunkqueue *cq, buffer *fn, off_t offset, off_t len); /* copies "fn" */
void chunkqueue_append_file_fd(chunkqueue *cq, buffer *fn, int fd, off_t offset, off_t len); /* copies "fn" */
void chunkqueue_append_mem(chunkqueue *cq, const char *mem, size_t len); /* copies memory */
void chunkqueue_append_mem_min(chunkqueue *cq, const char * mem, size_t len); /* copies memory */
void chunkqueue_append_buffer(chunkqueue *cq, buffer *mem); /* may reset "mem" */
void chunkqueue_append_chunkqueue(chunkqueue *cq, chunkqueue *src);

buffer * chunkqueue_prepend_buffer_open_sz(chunkqueue *cq, size_t sz);
buffer * chunkqueue_prepend_buffer_open(chunkqueue *cq);
void chunkqueue_prepend_buffer_commit(chunkqueue *cq);
buffer * chunkqueue_append_buffer_open_sz(chunkqueue *cq, size_t sz);
buffer * chunkqueue_append_buffer_open(chunkqueue *cq);
void chunkqueue_append_buffer_commit(chunkqueue *cq);

struct server; /*(declaration)*/
int chunkqueue_append_mem_to_tempfile(struct server *srv, chunkqueue *cq, const char *mem, size_t len);

/* functions to handle buffers to read into: */
/* obtain/reserve memory in chunkqueue at least len (input) size,
 * return pointer to memory with len (output) available for use
 * modifying the chunkqueue invalidates the memory area.
 * should always be followed by chunkqueue_get_memory(),
 *  even if nothing was read.
 * pass 0 in len for mem at least half of chunk_buf_sz
 */
char * chunkqueue_get_memory(chunkqueue *cq, size_t *len);
/* commit len bytes of mem obtained from chunkqueue_get_memory() */
void chunkqueue_use_memory(chunkqueue *cq, size_t len);

/* mark first "len" bytes as written (incrementing chunk offsets)
 * and remove finished chunks
 */
void chunkqueue_mark_written(chunkqueue *cq, off_t len);

void chunkqueue_remove_finished_chunks(chunkqueue *cq);

void chunkqueue_steal(chunkqueue *dest, chunkqueue *src, off_t len);
struct server;
int chunkqueue_steal_with_tempfiles(struct server *srv, chunkqueue *dest, chunkqueue *src, off_t len);

int chunkqueue_open_file_chunk(struct server *srv, chunkqueue *cq);

off_t chunkqueue_length(chunkqueue *cq);
void chunkqueue_free(chunkqueue *cq);
void chunkqueue_reset(chunkqueue *cq);

static inline int chunkqueue_is_empty(const chunkqueue *cq);
static inline int chunkqueue_is_empty(const chunkqueue *cq) {
	return NULL == cq->first;
}

#endif
