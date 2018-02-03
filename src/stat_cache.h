#ifndef _FILE_CACHE_H_
#define _FILE_CACHE_H_
#include "first.h"

#include "base.h"

struct stat_cache;      /* declaration */

int stat_cache_choose_engine (server *srv, const buffer *stat_cache_string);
struct stat_cache *stat_cache_init(server *srv);
void stat_cache_free(struct stat_cache *fc);

const buffer * stat_cache_mimetype_by_ext(const connection *con, const char *name, size_t nlen);
const buffer * stat_cache_content_type_get(server *srv, connection *con, const buffer *name, stat_cache_entry *sce);
const buffer * stat_cache_etag_get(stat_cache_entry *sce, etag_flags_t flags);
handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **sce);
int stat_cache_open_rdonly_fstat (server *srv, connection *con, buffer *name, struct stat *st);

int stat_cache_trigger_cleanup(server *srv);
#endif
