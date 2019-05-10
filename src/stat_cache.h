#ifndef _FILE_CACHE_H_
#define _FILE_CACHE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "etag.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

struct stat_cache;      /* declaration */

typedef struct {
	buffer *name;
	buffer *etag;

	struct stat st;

	time_t stat_ts;

#ifdef HAVE_FAM_H
	void *fam_dir;
#endif

	buffer *content_type;
} stat_cache_entry;

__attribute_cold__
int stat_cache_choose_engine (server *srv, const buffer *stat_cache_string);

__attribute_cold__
struct stat_cache *stat_cache_init(server *srv);

__attribute_cold__
void stat_cache_free(struct stat_cache *fc);

const buffer * stat_cache_mimetype_by_ext(const connection *con, const char *name, size_t nlen);
const buffer * stat_cache_content_type_get(server *srv, connection *con, const buffer *name, stat_cache_entry *sce);
const buffer * stat_cache_etag_get(stat_cache_entry *sce, etag_flags_t flags);
void stat_cache_update_entry(server *srv, const char *name, size_t len, struct stat *st, buffer *etagb);
void stat_cache_delete_entry(server *srv, const char *name, size_t len);
void stat_cache_delete_dir(server *srv, const char *name, size_t len);
void stat_cache_invalidate_entry(server *srv, const char *name, size_t len);
handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **sce);
int stat_cache_path_contains_symlink(server *srv, buffer *name);
int stat_cache_open_rdonly_fstat (buffer *name, struct stat *st, int symlinks);

int stat_cache_trigger_cleanup(server *srv);
#endif
