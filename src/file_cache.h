#ifndef _FILE_CACHE_H_
#define _FILE_CACHE_H_

#include "base.h"

file_cache *file_cache_init(void);
void file_cache_free(server *srv, file_cache *fc);

handler_t file_cache_get_entry(server *srv, connection *con, buffer *name, file_cache_entry **o_fce);
int file_cache_entry_release(server *srv, connection *con, file_cache_entry *fce);

#endif
