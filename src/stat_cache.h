#ifndef _FILE_CACHE_H_
#define _FILE_CACHE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "etag.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

typedef struct {
    buffer name;
    time_t stat_ts;
#ifdef HAVE_FAM_H
    void *fam_dir;
#endif
    buffer etag;
    buffer content_type;
    struct stat st;
} stat_cache_entry;

__attribute_cold__
int stat_cache_choose_engine (const buffer *stat_cache_string, log_error_st *errh);

struct fdevents;        /* declaration */

__attribute_cold__
int stat_cache_init(struct fdevents *ev, log_error_st *errh);

__attribute_cold__
void stat_cache_free(void);

__attribute_cold__
void stat_cache_xattrname (const char *name);

const buffer * stat_cache_mimetype_by_ext(const array *mimetypes, const char *name, size_t nlen);
#if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
const buffer * stat_cache_mimetype_by_xattr(const char *name);
const buffer * stat_cache_content_type_get_by_xattr(stat_cache_entry *sce, const array *mimetypes, int use_xattr);
#define stat_cache_content_type_get(con, sce) stat_cache_content_type_get_by_xattr((sce), (con)->conf.mimetypes, (con)->conf.use_xattr)
#else
const buffer * stat_cache_content_type_get_by_ext(stat_cache_entry *sce, const array *mimetypes);
#define stat_cache_content_type_get(con, sce) stat_cache_content_type_get_by_ext((sce), (con)->conf.mimetypes)
#endif
const buffer * stat_cache_etag_get(stat_cache_entry *sce, int flags);
void stat_cache_update_entry(const char *name, size_t len, struct stat *st, buffer *etagb);
void stat_cache_delete_entry(const char *name, size_t len);
void stat_cache_delete_dir(const char *name, size_t len);
void stat_cache_invalidate_entry(const char *name, size_t len);
stat_cache_entry * stat_cache_get_entry(const buffer *name);
int stat_cache_path_contains_symlink(const buffer *name, log_error_st *errh);
int stat_cache_open_rdonly_fstat (const buffer *name, struct stat *st, int symlinks);

void stat_cache_trigger_cleanup(void);
#endif
