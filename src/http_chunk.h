#ifndef _HTTP_CHUNK_H_
#define _HTTP_CHUNK_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "chunk.h"

struct stat_cache_entry; /* declaration */

int http_chunk_append_mem(request_st *r, const char * mem, size_t len); /* copies memory */
int http_chunk_append_buffer(request_st *r, buffer *mem); /* may reset "mem" */
int http_chunk_decode_append_mem(request_st * const r, const char * const mem, const size_t len);
int http_chunk_decode_append_buffer(request_st * const r, buffer * const mem); /* may reset "mem" */
int http_chunk_transfer_cqlen(request_st *r, chunkqueue *src, size_t len);
int http_chunk_append_file_fd(request_st *r, const buffer *fn, int fd, off_t sz);
int http_chunk_append_file_ref(request_st *r, struct stat_cache_entry *sce); /* copies "fn" */
void http_chunk_append_file_fd_range(request_st *r, const buffer *fn, int fd, off_t offset, off_t len); /* copies "fn" */
void http_chunk_append_file_ref_range(request_st *r, struct stat_cache_entry *sce, off_t offset, off_t len); /* copies "fn" */
void http_chunk_close(request_st *r);

#endif
