#ifndef _CHUNK_H_
#define _CHUNK_H_

#include "buffer.h"
#include "array.h"
#include "sys-mmap.h"

typedef struct chunk {
	enum { MEM_CHUNK, FILE_CHUNK } type;

	buffer *mem; /* either the storage of the mem-chunk or the read-ahead buffer */

	struct {
		/* filechunk */
		buffer *name; /* name of the file */
		off_t  start; /* starting offset in the file */
		off_t  length; /* octets to send from the starting offset */

		int    fd;
		struct {
			char   *start; /* the start pointer of the mmap'ed area */
			size_t length; /* size of the mmap'ed area */
			off_t  offset; /* start is <n> octet away from the start of the file */
		} mmap;

		int is_temp; /* file is temporary and will be deleted if on cleanup */
	} file;

	off_t  offset; /* octets sent from this chunk
			  the size of the chunk is either
			  - mem-chunk: mem->used - 1
			  - file-chunk: file.length
			*/

	struct chunk *next;
} chunk;

typedef struct {
	chunk *first;
	chunk *last;

	chunk *unused;
	size_t unused_chunks;

	array *tempdirs;

	off_t  bytes_in, bytes_out;
} chunkqueue;

chunkqueue *chunkqueue_init(void);
void chunkqueue_set_tempdirs(chunkqueue *c, array *tempdirs);
void chunkqueue_append_file(chunkqueue *c, buffer *fn, off_t offset, off_t len); /* copies "fn" */
void chunkqueue_append_mem(chunkqueue *c, const char *mem, size_t len); /* copies memory */
void chunkqueue_append_buffer(chunkqueue *c, buffer *mem); /* may reset "mem" */
void chunkqueue_prepend_buffer(chunkqueue *c, buffer *mem); /* may reset "mem" */

buffer * chunkqueue_get_append_buffer(chunkqueue *c);
buffer * chunkqueue_get_prepend_buffer(chunkqueue *c);
chunk * chunkqueue_get_append_tempfile(chunkqueue *cq);

void chunkqueue_remove_finished_chunks(chunkqueue *cq);

void chunkqueue_steal(chunkqueue *dest, chunkqueue *src, off_t len);

off_t chunkqueue_length(chunkqueue *c);
void chunkqueue_free(chunkqueue *c);
void chunkqueue_reset(chunkqueue *c);

int chunkqueue_is_empty(chunkqueue *c);

#endif
