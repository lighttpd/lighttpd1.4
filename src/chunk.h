#ifndef _CHUNK_H_
#define _CHUNK_H_

#include "buffer.h"

typedef struct chunk {
	/* ok, this one is tricky:
	 * 
	 * MEM_CHUNK
	 *   b: the chunk it self
	 * FILE_CHUNK
	 *   b: a buffer for the filename
	 */
	
	enum { UNUSED_CHUNK, MEM_CHUNK, FILE_CHUNK } type;
	
	union {
		buffer *mem;
		struct {
			buffer *name;
			off_t  offset;
			off_t  length;
		} file;
	} data;
	
	/* how many bytes are already handled */
	
	off_t offset;
	
	struct chunk *next;
} chunk;

typedef struct {
	chunk *first;
	chunk *last;
	
	chunk *unused;
} chunkqueue;

chunkqueue *chunkqueue_init(void);
int chunkqueue_append_file(chunkqueue *c, buffer *fn, off_t offset, off_t len);
int chunkqueue_append_mem(chunkqueue *c, const char *mem, size_t len);
int chunkqueue_append_buffer(chunkqueue *c, buffer *mem);
int chunkqueue_prepend_buffer(chunkqueue *c, buffer *mem);

buffer * chunkqueue_get_append_buffer(chunkqueue *c);
buffer * chunkqueue_get_prepend_buffer(chunkqueue *c);

off_t chunkqueue_length(chunkqueue *c);
off_t chunkqueue_written(chunkqueue *c);
void chunkqueue_free(chunkqueue *c);
void chunkqueue_reset(chunkqueue *c);

int chunkqueue_is_empty(chunkqueue *c);

#endif
