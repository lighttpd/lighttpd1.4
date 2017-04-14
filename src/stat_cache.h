#ifndef _FILE_CACHE_H_
#define _FILE_CACHE_H_
#include "first.h"

#include "base.h"

struct stat_cache;      /* declaration */

struct stat_cache *stat_cache_init(server *srv);
void stat_cache_free(struct stat_cache *fc);

const buffer * stat_cache_mimetype_by_ext(const connection *con, const char *name, size_t nlen);
handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **fce);
int stat_cache_open_rdonly_fstat (server *srv, connection *con, buffer *name, struct stat *st);

int stat_cache_trigger_cleanup(server *srv);
#endif
