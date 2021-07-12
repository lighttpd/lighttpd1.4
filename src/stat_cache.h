#ifndef _FILE_CACHE_H_
#define _FILE_CACHE_H_
#include "first.h"

#include <sys/stat.h>
#include "sys-time.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"

typedef struct stat stat_cache_st;

typedef struct stat_cache_entry {
    buffer name;
    unix_time64_t stat_ts;
    int fd;
    int refcnt;
  #if defined(HAVE_FAM_H) || defined(HAVE_SYS_INOTIFY_H) || defined(HAVE_SYS_EVENT_H)
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

void stat_cache_entry_refchg(void *data, int mod);

__attribute_cold__
void stat_cache_xattrname (const char *name);

__attribute_pure__
const buffer * stat_cache_mimetype_by_ext(const array *mimetypes, const char *name, uint32_t nlen);

#if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
const buffer * stat_cache_mimetype_by_xattr(const char *name);
const buffer * stat_cache_content_type_get_by_xattr(stat_cache_entry *sce, const array *mimetypes, int use_xattr);
#define stat_cache_content_type_get(con, r) stat_cache_content_type_get_by_xattr((sce), (r)->conf.mimetypes, (r)->conf.use_xattr)
#else
const buffer * stat_cache_content_type_get_by_ext(stat_cache_entry *sce, const array *mimetypes);
#define stat_cache_content_type_get(con, r) stat_cache_content_type_get_by_ext((sce), (r)->conf.mimetypes)
#endif
const buffer * stat_cache_etag_get(stat_cache_entry *sce, int flags);
void stat_cache_update_entry(const char *name, uint32_t len, struct stat *st, buffer *etagb);
void stat_cache_delete_entry(const char *name, uint32_t len);
void stat_cache_delete_dir(const char *name, uint32_t len);
void stat_cache_invalidate_entry(const char *name, uint32_t len);
stat_cache_entry * stat_cache_get_entry(const buffer *name);
stat_cache_entry * stat_cache_get_entry_open(const buffer *name, int symlinks);
const stat_cache_st * stat_cache_path_stat(const buffer *name);
int stat_cache_path_isdir(const buffer *name);

__attribute_cold__
int stat_cache_path_contains_symlink(const buffer *name, log_error_st *errh);

int stat_cache_open_rdonly_fstat (const buffer *name, struct stat *st, int symlinks);

void stat_cache_trigger_cleanup(void);
#endif
