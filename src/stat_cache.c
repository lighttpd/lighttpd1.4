#include "first.h"

#include "stat_cache.h"
#include "log.h"
#include "fdevent.h"
#include "etag.h"
#include "splaytree.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_ATTR_ATTRIBUTES_H
# include <attr/attributes.h>
#endif

#ifdef HAVE_SYS_EXTATTR_H
# include <sys/extattr.h>
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#ifndef S_ISLNK
#define S_ISLNK(mode) (0)
#endif
#endif

/*
 * stat-cache
 *
 * - a splay-tree is used as we can use the caching effect of it
 */

enum {
  STAT_CACHE_ENGINE_SIMPLE, /*(default)*/
  STAT_CACHE_ENGINE_NONE,
  STAT_CACHE_ENGINE_FAM
};

struct stat_cache_fam;  /* declaration */

typedef struct stat_cache {
	int stat_cache_engine;
	splay_tree *files; /* nodes of tree are (stat_cache_entry *) */
	struct stat_cache_fam *scf;
} stat_cache;

static stat_cache sc;


/* the famous DJB hash function for strings */
__attribute_pure__
static uint32_t djbhash(const char *str, const size_t len)
{
    const unsigned char * const s = (const unsigned char *)str;
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; ++i) hash = ((hash << 5) + hash) ^ s[i];
    return hash;
}


__attribute_pure__
static uint32_t hashme(const char *str, const size_t len)
{
    /* strip highest bit of hash value for splaytree */
    return djbhash(str,len) & ~(((uint32_t)1) << 31);
}


static void * stat_cache_sptree_find(splay_tree ** const sptree,
                                     const char * const name,
                                     size_t len)
{
    const int ndx = hashme(name, len);
    *sptree = splaytree_splay(*sptree, ndx);
    return (*sptree && (*sptree)->key == ndx) ? (*sptree)->data : NULL;
}


#ifdef HAVE_FAM_H

/* monitor changes in directories using FAM
 *
 * This implementation employing FAM monitors directories as they are used,
 * and maintains a reference count for cache use within stat_cache.c.
 * A periodic job runs in lighttpd every 32 seconds, expiring entires unused
 * in last 64 seconds out of the cache and cancelling FAM monitoring.  Items
 * within the cache are checked against the filesystem upon use if last stat()
 * was greater than or equal to 16 seconds ago.
 *
 * This implementation does not monitor every directory in a tree, and therefore
 * the cache may get out-of-sync with the filesystem.  Delays in receiving and
 * processing events from FAM might also lead to stale cache entries.
 *
 * For many websites, a large number of files are seldom, if ever, modified,
 * and a common practice with images is to create a new file with a new name
 * when a new version is needed, in order for client browsers and CDNs to better
 * cache the content.  Given this, most use will see little difference in
 * performance between server.stat-cache-engine = "fam" and "simple" (default).
 * The default server.stat-cache-engine = "simple" calls stat() on a target once
 * per second, and reuses that information until the next second.  For use where
 * changes must be immediately visible, server.stat-cache-engine = "disable"
 * should be used.
 *
 * When considering use of server.stat-cache-engine = "fam", there are a few
 * additional limitations for this cache implementation using FAM.
 * - symlinks to files located outside of the current directory do not result
 *   in changes to that file being monitored (unless that file is in a directory
 *   which is monitored as a result of a different request).  symlinks can be
 *   chained and can be circular.  This implementation *does not* readlink() or
 *   realpath() to resolve the chains to find and monitor the ultimate target
 *   directory.  While symlinks to files located outside the current directory
 *   are not monitored, symlinks to directories *are* monitored, though chains
 *   of symlinks to directories do not result in monitoring of the directories
 *   containing intermediate symlinks to the target directory.
 * - directory rename of a directory which is not currently being monitored will
 *   result in stale information in the cache if there is a subdirectory that is
 *   being monitored.
 * Even though lighttpd will not receive FAM events in the above cases, lighttpd
 * does re-validate the information in the cache upon use if the cache entry has
 * not been checked in 16 seconds, so that is the upper limit for use of stale
 * data.
 *
 * Use of server.stat-cache-engine = "fam" is discouraged for extremely volatile
 * directories such as temporary directories (e.g. /tmp and maybe /var/tmp) due
 * to the overhead of processing the additional noise generated from changes.
 * Related, server.stat-cache-engine = "fam" is not recommended on trees of
 * untrusted files where a malicious user could generate an excess of change
 * events.
 *
 * Internal note: lighttpd walks the caches to prune trees in stat_cache when an
 * event is received for a directory (or symlink to a directory) which has been
 * deleted or renamed.  The splaytree data structure is suboptimal for frequent
 * changes of large directories trees where there have been a large number of
 * different files recently accessed and part of the stat_cache.
 */

#include <fam.h>

typedef struct fam_dir_entry {
	buffer *name;
	int refcnt;
	FAMRequest req;
	time_t stat_ts;
	dev_t st_dev;
	ino_t st_ino;
	struct fam_dir_entry *fam_parent;
} fam_dir_entry;

typedef struct stat_cache_fam {
	splay_tree *dirs; /* the nodes of the tree are fam_dir_entry */
	FAMConnection fam;
	log_error_st *errh;
	fdevents *ev;
	fdnode *fdn;
	int fd;
} stat_cache_fam;

static fam_dir_entry * fam_dir_entry_init(const char *name, size_t len)
{
    fam_dir_entry * const fam_dir = calloc(1, sizeof(*fam_dir));
    force_assert(NULL != fam_dir);

    fam_dir->name = buffer_init();
    buffer_copy_string_len(fam_dir->name, name, len);
    fam_dir->refcnt = 0;

    return fam_dir;
}

static void fam_dir_entry_free(fam_dir_entry *fam_dir)
{
    if (!fam_dir) return;
    /*(fam_dir->parent might be invalid pointer here; ignore)*/
    buffer_free(fam_dir->name);
    free(fam_dir);
}

static void fam_dir_invalidate_node(fam_dir_entry *fam_dir)
{
    fam_dir->stat_ts = 0;
    if (fam_dir->fam_parent) {
        --fam_dir->fam_parent->refcnt;
        fam_dir->fam_parent = NULL;
    }
}

/*
 * walk though splay_tree and collect contents of dir tree.
 * remove tagged entries in a second loop
 */

static void fam_dir_tag_refcnt(splay_tree *t, int *keys, int *ndx)
{
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/
    if (t->left)  fam_dir_tag_refcnt(t->left,  keys, ndx);
    if (t->right) fam_dir_tag_refcnt(t->right, keys, ndx);
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/

    fam_dir_entry * const fam_dir = t->data;
    if (0 == fam_dir->refcnt) {
        fam_dir_invalidate_node(fam_dir);
        keys[(*ndx)++] = t->key;
    }
}

static void fam_dir_periodic_cleanup() {
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    stat_cache_fam * const scf = sc.scf;
    do {
        if (!scf->dirs) return;
        max_ndx = 0;
        fam_dir_tag_refcnt(scf->dirs, keys, &max_ndx);
        for (i = 0; i < max_ndx; ++i) {
            const int ndx = keys[i];
            splay_tree *node = scf->dirs = splaytree_splay(scf->dirs, ndx);
            if (node && node->key == ndx) {
                fam_dir_entry *fam_dir = node->data;
                scf->dirs = splaytree_delete(scf->dirs, ndx);
                FAMCancelMonitor(&scf->fam, &fam_dir->req);
                fam_dir_entry_free(fam_dir);
            }
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
}

static void fam_dir_invalidate_tree(splay_tree *t, const char *name, size_t len)
{
    /*force_assert(t);*/
    if (t->left)  fam_dir_invalidate_tree(t->left,  name, len);
    if (t->right) fam_dir_invalidate_tree(t->right, name, len);

    fam_dir_entry * const fam_dir = t->data;
    buffer *b = fam_dir->name;
    size_t blen = buffer_string_length(b);
    if (blen > len && b->ptr[len] == '/' && 0 == memcmp(b->ptr, name, len))
        fam_dir_invalidate_node(fam_dir);
}

/* declarations */
static void stat_cache_delete_tree(const char *name, size_t len);
static void stat_cache_invalidate_dir_tree(const char *name, size_t len);

static void stat_cache_handle_fdevent_in(stat_cache_fam *scf)
{
    for (int i = 0, ndx; i || (i = FAMPending(&scf->fam)) > 0; --i) {
        FAMEvent fe;
        if (FAMNextEvent(&scf->fam, &fe) < 0) break;

        /* ignore events which may have been pending for
         * paths recently cancelled via FAMCancelMonitor() */
        ndx = (int)(intptr_t)fe.userdata;
        scf->dirs = splaytree_splay(scf->dirs, ndx);
        if (!scf->dirs || scf->dirs->key != ndx) {
            continue;
        }
        fam_dir_entry *fam_dir = scf->dirs->data;
        if (FAMREQUEST_GETREQNUM(&fam_dir->req)
            != FAMREQUEST_GETREQNUM(&fe.fr)) {
            continue;
        }

        if (fe.filename[0] != '/') {
            buffer * const n = fam_dir->name;
            fam_dir_entry *fam_link;
            size_t len;
            switch(fe.code) {
            case FAMCreated:
                /* file created in monitored dir modifies dir and
                 * we should get a separate FAMChanged event for dir.
                 * Therefore, ignore file FAMCreated event here.
                 * Also, if FAMNoExists() is used, might get spurious
                 * FAMCreated events as changes are made e.g. in monitored
                 * sub-sub-sub dirs and the library discovers new (already
                 * existing) dir entries */
                continue;
            case FAMChanged:
                /* file changed in monitored dir does not modify dir */
            case FAMDeleted:
            case FAMMoved:
                /* file deleted or moved in monitored dir modifies dir,
                 * but FAM provides separate notification for that */

                /* temporarily append filename to dir in fam_dir->name to
                 * construct path, then delete stat_cache entry (if any)*/
                len = buffer_string_length(n);
                buffer_append_string_len(n, CONST_STR_LEN("/"));
                buffer_append_string_len(n,fe.filename,strlen(fe.filename));
                /* (alternatively, could chose to stat() and update)*/
                stat_cache_invalidate_entry(CONST_BUF_LEN(n));

                fam_link = /*(check if might be symlink to monitored dir)*/
                  stat_cache_sptree_find(&scf->dirs, CONST_BUF_LEN(n));
                if (fam_link && !buffer_is_equal(fam_link->name, n))
                    fam_link = NULL;

                buffer_string_set_length(n, len);

                if (fam_link) {
                    /* replaced symlink changes containing dir */
                    stat_cache_invalidate_entry(CONST_BUF_LEN(n));
                    /* handle symlink to dir as deleted dir below */
                    fe.code = FAMDeleted;
                    fam_dir = fam_link;
                    break;
                }
                continue;
            default:
                continue;
            }
        }

        switch(fe.code) {
        case FAMChanged:
            stat_cache_invalidate_entry(CONST_BUF_LEN(fam_dir->name));
            break;
        case FAMDeleted:
        case FAMMoved:
            stat_cache_delete_tree(CONST_BUF_LEN(fam_dir->name));
            fam_dir_invalidate_node(fam_dir);
            if (scf->dirs)
                fam_dir_invalidate_tree(scf->dirs,CONST_BUF_LEN(fam_dir->name));
            fam_dir_periodic_cleanup();
            break;
        default:
            break;
        }
    }
}

static handler_t stat_cache_handle_fdevent(void *ctx, int revent)
{
	stat_cache_fam * const scf = ctx; /* sc.scf */

	if (revent & FDEVENT_IN) {
		stat_cache_handle_fdevent_in(scf);
	}

	if (revent & (FDEVENT_HUP|FDEVENT_RDHUP)) {
		/* fam closed the connection */
		log_error(scf->errh, __FILE__, __LINE__,
		  "FAM connection closed; disabling stat_cache.");
		/* (although effectively STAT_CACHE_ENGINE_NONE,
		 *  do not change here so that periodic jobs clean up memory)*/
		/*sc.stat_cache_engine = STAT_CACHE_ENGINE_NONE; */
		fdevent_fdnode_event_del(scf->ev, scf->fdn);
		fdevent_unregister(scf->ev, scf->fd);
		scf->fdn = NULL;

		FAMClose(&scf->fam);
		scf->fd = -1;
	}

	return HANDLER_GO_ON;
}

static stat_cache_fam * stat_cache_init_fam(fdevents *ev, log_error_st *errh) {
	stat_cache_fam *scf = calloc(1, sizeof(*scf));
	force_assert(scf);
	scf->fd = -1;
	scf->ev = ev;
	scf->errh = errh;

	/* setup FAM */
	if (0 != FAMOpen2(&scf->fam, "lighttpd")) {
		log_error(errh, __FILE__, __LINE__,
		  "could not open a fam connection, dieing.");
		return NULL;
	}
      #ifdef HAVE_FAMNOEXISTS
	FAMNoExists(&scf->fam);
      #endif

	scf->fd = FAMCONNECTION_GETFD(&scf->fam);
	fdevent_setfd_cloexec(scf->fd);
	scf->fdn = fdevent_register(scf->ev, scf->fd, stat_cache_handle_fdevent, scf);
	fdevent_fdnode_event_set(scf->ev, scf->fdn, FDEVENT_IN | FDEVENT_RDHUP);

	return scf;
}

static void stat_cache_free_fam(stat_cache_fam *scf) {
	if (NULL == scf) return;

	while (scf->dirs) {
		/*(skip entry invalidation and FAMCancelMonitor())*/
		splay_tree *node = scf->dirs;
		fam_dir_entry_free((fam_dir_entry *)node->data);
		scf->dirs = splaytree_delete(scf->dirs, node->key);
	}

	if (-1 != scf->fd) {
		/*scf->fdn already cleaned up in fdevent_free()*/
		FAMClose(&scf->fam);
		/*scf->fd = -1;*/
	}

	free(scf);
}

static fam_dir_entry * fam_dir_monitor(stat_cache_fam *scf, char *fn, size_t dirlen, struct stat *st)
{
    if (NULL == scf->fdn) return NULL; /* FAM connection closed; do nothing */
    const int fn_is_dir = S_ISDIR(st->st_mode);
    /*force_assert(0 != dirlen);*/
    /*force_assert(fn[0] == '/');*/
    /* consistency: ensure fn does not end in '/' unless root "/"
     * FAM events will not end in '/', so easier to match this way */
    if (fn[dirlen-1] == '/') --dirlen;
    if (0 == dirlen) dirlen = 1; /* root dir ("/") */
    /* Note: paths are expected to be normalized before calling stat_cache,
     * e.g. without repeated '/' */
    if (!fn_is_dir) {
        while (fn[--dirlen] != '/') ;
        if (0 == dirlen) dirlen = 1; /*(should not happen for file)*/
    }
    int dir_ndx = hashme(fn, dirlen);
    fam_dir_entry *fam_dir = NULL;

    scf->dirs = splaytree_splay(scf->dirs, dir_ndx);
    if (NULL != scf->dirs && scf->dirs->key == dir_ndx) {
        fam_dir = scf->dirs->data;
        if (!buffer_is_equal_string(fam_dir->name, fn, dirlen)) {
            /* hash collision; preserve existing
             * do not monitor new to avoid cache thrashing */
            return NULL;
        }
        /* directory already registered */
    }

    const time_t cur_ts = log_epoch_secs;
    struct stat lst;
    int ck_dir = fn_is_dir;
    if (!fn_is_dir && (NULL==fam_dir || cur_ts - fam_dir->stat_ts >= 16)) {
        ck_dir = 1;
        /*(temporarily modify fn)*/
        fn[dirlen] = '\0';
        if (0 != lstat(fn, &lst)) {
            fn[dirlen] = '/';
            return NULL;
        }
        if (!S_ISLNK(lst.st_mode)) {
            st = &lst;
        }
        else if (0 != stat(fn, st)) { /*st passed in now is stat() of dir*/
            fn[dirlen] = '/';
            return NULL;
        }
        fn[dirlen] = '/';
    }

    int ck_lnk = (NULL == fam_dir);
    if (ck_dir && NULL != fam_dir) {
        /* check stat() matches device and inode, just in case an external event
         * not being monitored occurs (e.g. rename of unmonitored parent dir)*/
        if (st->st_dev != fam_dir->st_dev || st->st_ino != fam_dir->st_ino) {
            ck_lnk = 1;
            /*(modifies scf->dirs but no need to re-splay for dir_ndx since
             * fam_dir is not NULL and so splaytree_insert not called below)*/
            if (scf->dirs) fam_dir_invalidate_tree(scf->dirs, fn, dirlen);
            if (!fn_is_dir) /*(if dir, caller is updating stat_cache_entry)*/
                stat_cache_update_entry(fn, dirlen, st, NULL);
            /*(must not delete tree since caller is holding a valid node)*/
            stat_cache_invalidate_dir_tree(fn, dirlen);
            if (0 != FAMCancelMonitor(&scf->fam, &fam_dir->req)
                || 0 != FAMMonitorDirectory(&scf->fam, fam_dir->name->ptr,
                                            &fam_dir->req,
                                            (void *)(intptr_t)dir_ndx)) {
                fam_dir->stat_ts = 0; /* invalidate */
                return NULL;
            }
            fam_dir->st_dev = st->st_dev;
            fam_dir->st_ino = st->st_ino;
        }
        fam_dir->stat_ts = cur_ts;
    }

    if (NULL == fam_dir) {
        fam_dir = fam_dir_entry_init(fn, dirlen);

        if (0 != FAMMonitorDirectory(&scf->fam,fam_dir->name->ptr,&fam_dir->req,
                                     (void *)(intptr_t)dir_ndx)) {
            log_error(scf->errh, __FILE__, __LINE__,
              "monitoring dir failed: %s file: %s %s",
              fam_dir->name->ptr, fn, FamErrlist[FAMErrno]);
            fam_dir_entry_free(fam_dir);
            return NULL;
        }

        scf->dirs = splaytree_insert(scf->dirs, dir_ndx, fam_dir);
        fam_dir->stat_ts= cur_ts;
        fam_dir->st_dev = st->st_dev;
        fam_dir->st_ino = st->st_ino;
    }

    if (ck_lnk) {
        if (fn_is_dir) {
            /*(temporarily modify fn)*/
            char e = fn[dirlen];
            fn[dirlen] = '\0';
            if (0 != lstat(fn, &lst)) {
                fn[dirlen] = e;
                return NULL;
            }
            fn[dirlen] = e;
        }
        if (fam_dir->fam_parent) {
            --fam_dir->fam_parent->refcnt;
            fam_dir->fam_parent = NULL;
        }
        if (S_ISLNK(lst.st_mode)) {
            fam_dir->fam_parent = fam_dir_monitor(scf, fn, dirlen, &lst);
        }
    }

    ++fam_dir->refcnt;
    return fam_dir;
}

#endif


static stat_cache_entry * stat_cache_entry_init(void) {
    stat_cache_entry *sce = calloc(1, sizeof(*sce));
    force_assert(NULL != sce);
    return sce;
}

static void stat_cache_entry_free(void *data) {
    stat_cache_entry *sce = data;
    if (!sce) return;

  #ifdef HAVE_FAM_H
    /*(decrement refcnt only;
     * defer cancelling FAM monitor on dir even if refcnt reaches zero)*/
    if (sce->fam_dir) --((fam_dir_entry *)sce->fam_dir)->refcnt;
  #endif

    free(sce->name.ptr);
    free(sce->etag.ptr);
    if (sce->content_type.size) free(sce->content_type.ptr);

    free(sce);
}

#if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)

static const char *attrname = "Content-Type";
static char attrval[128];
static buffer attrb = { attrval, 0, 0 };

static int stat_cache_attr_get(char *name) {
  #if defined(HAVE_XATTR)
    int attrlen = sizeof(attrval)-1;
    if (0 == attr_get(name, attrname, attrval, &attrlen, 0))
  #elif defined(HAVE_EXTATTR)
    ssize_t attrlen;
    if (0 < (attrlen = extattr_get_file(name, EXTATTR_NAMESPACE_USER, attrname,
                                        attrval, sizeof(attrval)-1)))
  #endif
    {
        attrval[attrlen] = '\0';
        attrb.used = (uint32_t)(attrlen + 1);
        return 1;
    }
    return 0;
}

#endif

int stat_cache_init(fdevents *ev, log_error_st *errh) {
  #ifdef HAVE_FAM_H
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
        sc.scf = stat_cache_init_fam(ev, errh);
        if (NULL == sc.scf) return 0;
    }
  #else
    UNUSED(ev);
    UNUSED(errh);
  #endif

    return 1;
}

void stat_cache_free(void) {
    splay_tree *sptree = sc.files;
    while (sptree) {
        stat_cache_entry_free(sptree->data);
        sptree = splaytree_delete(sptree, sptree->key);
    }
    sc.files = NULL;

  #ifdef HAVE_FAM_H
    stat_cache_free_fam(sc.scf);
    sc.scf = NULL;
  #endif

  #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
    attrname = "Content-Type";
  #endif

    sc.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE; /*(default)*/
}

void stat_cache_xattrname (const char *name) {
  #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
    attrname = name;
  #else
    UNUSED(name);
  #endif
}

int stat_cache_choose_engine (const buffer *stat_cache_string, log_error_st *errh) {
    if (buffer_string_is_empty(stat_cache_string))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE;
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("simple")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE;
#ifdef HAVE_FAM_H
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("fam")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_FAM;
#endif
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("disable")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_NONE;
    else {
        log_error(errh, __FILE__, __LINE__,
          "server.stat-cache-engine can be one of \"disable\", \"simple\","
#ifdef HAVE_FAM_H
          " \"fam\","
#endif
          " but not: %s", stat_cache_string->ptr);
        return -1;
    }
    return 0;
}

const buffer * stat_cache_mimetype_by_ext(const array * const mimetypes, const char * const name, const size_t nlen)
{
    const char * const end = name + nlen; /*(end of string)*/
    const uint32_t used = mimetypes->used;
    if (used < 16) {
        for (uint32_t i = 0; i < used; ++i) {
            /* suffix match */
            const data_string *ds = (data_string *)mimetypes->data[i];
            const size_t klen = buffer_string_length(&ds->key);
            if (klen <= nlen && buffer_eq_icase_ssn(end-klen, ds->key.ptr, klen))
                return &ds->value;
        }
    }
    else {
        const char *s;
        const data_string *ds;
        if (nlen) {
            for (s = end-1; s != name && *s != '/'; --s) ; /*(like memrchr())*/
            if (*s == '/') ++s;
        }
        else {
            s = name;
        }
        /* search for basename, then longest .ext2.ext1, then .ext1, then "" */
        ds = (const data_string *)array_get_element_klen(mimetypes, s, end - s);
        if (NULL != ds) return &ds->value;
        while (++s < end) {
            while (*s != '.' && ++s != end) ;
            if (s == end) break;
            /* search ".ext" then "ext" */
            ds = (const data_string *)array_get_element_klen(mimetypes, s, end - s);
            if (NULL != ds) return &ds->value;
            /* repeat search without leading '.' to handle situation where
             * admin configured mimetype.assign keys without leading '.' */
            if (++s < end) {
                if (*s == '.') { --s; continue; }
                ds = (const data_string *)array_get_element_klen(mimetypes, s, end - s);
                if (NULL != ds) return &ds->value;
            }
        }
        /* search for ""; catchall */
        ds = (const data_string *)array_get_element_klen(mimetypes, CONST_STR_LEN(""));
        if (NULL != ds) return &ds->value;
    }

    return NULL;
}

#if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)

const buffer * stat_cache_mimetype_by_xattr(const char * const name)
{
    return stat_cache_attr_get(name) ? &attrb : NULL;
}

const buffer * stat_cache_content_type_get_by_xattr(stat_cache_entry *sce, const array *mimetypes, int use_xattr)
{
    /*(invalid caching if user config has multiple, different
     * r->conf.mimetypes for same extension (not expected))*/
    if (!buffer_string_is_empty(&sce->content_type)) return &sce->content_type;

    if (!S_ISREG(sce->st.st_mode)) return NULL;

    /* cache mimetype */
    const buffer *mtype =
      (use_xattr) ? stat_cache_mimetype_by_xattr(sce->name.ptr) : NULL;
    if (NULL == mtype)
        mtype = stat_cache_mimetype_by_ext(mimetypes,CONST_BUF_LEN(&sce->name));
    if (NULL != mtype) {
        if (sce->content_type.size) {
            buffer_copy_buffer(&sce->content_type, mtype);
        }
        else if (mtype == &attrb) {
            sce->content_type.ptr = NULL;
            buffer_copy_buffer(&sce->content_type, mtype);
        }
        else {
            /*(copy pointers from mimetypes array; avoid allocation)*/
            sce->content_type.ptr = mtype->ptr;
            sce->content_type.used = mtype->used;
            /*(leave sce->content_type.size = 0 to flag not-allocated)*/
        }
    }
    else
        buffer_clear(&sce->content_type);

    return &sce->content_type;
}

#else

const buffer * stat_cache_content_type_get_by_ext(stat_cache_entry *sce, const array *mimetypes)
{
    /*(invalid caching if user config has multiple, different
     * r->conf.mimetypes for same extension (not expected))*/
    if (!buffer_string_is_empty(&sce->content_type)) return &sce->content_type;

    if (!S_ISREG(sce->st.st_mode)) return NULL;

    /* cache mimetype */
    const buffer * const mtype =
      stat_cache_mimetype_by_ext(mimetypes, CONST_BUF_LEN(&sce->name));
    if (NULL != mtype) {
        /*(copy pointers from mimetypes array; avoid allocation)*/
        sce->content_type.ptr = mtype->ptr;
        sce->content_type.used = mtype->used;
        /*(leave sce->content_type.size = 0 to flag not-allocated)*/
    }
    else
        buffer_clear(&sce->content_type);

    return &sce->content_type;
}

#endif

const buffer * stat_cache_etag_get(stat_cache_entry *sce, int flags) {
    /*(invalid caching if user cfg has multiple, different r->conf.etag_flags
     * for same path (not expected, since etag flags should be by filesystem))*/
    if (!buffer_string_is_empty(&sce->etag)) return &sce->etag;

    if (S_ISREG(sce->st.st_mode) || S_ISDIR(sce->st.st_mode)) {
        if (0 == flags) return NULL;
        etag_create(&sce->etag, &sce->st, flags);
        return &sce->etag;
    }

    return NULL;
}

void stat_cache_update_entry(const char *name, size_t len,
                             struct stat *st, buffer *etagb)
{
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_NONE) return;
    force_assert(0 != len);
    if (name[len-1] == '/') { if (0 == --len) len = 1; }
    splay_tree **sptree = &sc.files;
    stat_cache_entry *sce =
      stat_cache_sptree_find(sptree, name, len);
    if (sce && buffer_is_equal_string(&sce->name, name, len)) {
        sce->stat_ts = log_epoch_secs;
        sce->st = *st; /* etagb might be NULL to clear etag (invalidate) */
        buffer_copy_string_len(&sce->etag, CONST_BUF_LEN(etagb));
      #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
        buffer_clear(&sce->content_type);
      #endif
    }
}

void stat_cache_delete_entry(const char *name, size_t len)
{
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_NONE) return;
    force_assert(0 != len);
    if (name[len-1] == '/') { if (0 == --len) len = 1; }
    splay_tree **sptree = &sc.files;
    stat_cache_entry *sce = stat_cache_sptree_find(sptree, name, len);
    if (sce && buffer_is_equal_string(&sce->name, name, len)) {
        stat_cache_entry_free(sce);
        *sptree = splaytree_delete(*sptree, (*sptree)->key);
    }
}

void stat_cache_invalidate_entry(const char *name, size_t len)
{
    splay_tree **sptree = &sc.files;
    stat_cache_entry *sce = stat_cache_sptree_find(sptree, name, len);
    if (sce && buffer_is_equal_string(&sce->name, name, len)) {
        sce->stat_ts = 0;
      #ifdef HAVE_FAM_H
        if (sce->fam_dir != NULL) {
            --((fam_dir_entry *)sce->fam_dir)->refcnt;
            sce->fam_dir = NULL;
        }
      #endif
    }
}

#ifdef HAVE_FAM_H

static void stat_cache_invalidate_dir_tree_walk(splay_tree *t,
                                                const char *name, size_t len)
{
    if (t->left)  stat_cache_invalidate_dir_tree_walk(t->left,  name, len);
    if (t->right) stat_cache_invalidate_dir_tree_walk(t->right, name, len);

    buffer *b = &((stat_cache_entry *)t->data)->name;
    size_t blen = buffer_string_length(b);
    if (blen > len && b->ptr[len] == '/' && 0 == memcmp(b->ptr, name, len)) {
        stat_cache_entry *sce = t->data;
        sce->stat_ts = 0;
        if (sce->fam_dir != NULL) {
            --((fam_dir_entry *)sce->fam_dir)->refcnt;
            sce->fam_dir = NULL;
        }
    }
}

static void stat_cache_invalidate_dir_tree(const char *name, size_t len)
{
    splay_tree * const sptree = sc.files;
    if (sptree) stat_cache_invalidate_dir_tree_walk(sptree, name, len);
}

#endif

/*
 * walk though splay_tree and collect contents of dir tree.
 * remove tagged entries in a second loop
 */

static void stat_cache_tag_dir_tree(splay_tree *t, const char *name, size_t len,
                                    int *keys, int *ndx)
{
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/
    if (t->left)  stat_cache_tag_dir_tree(t->left,  name, len, keys, ndx);
    if (t->right) stat_cache_tag_dir_tree(t->right, name, len, keys, ndx);
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/

    buffer *b = &((stat_cache_entry *)t->data)->name;
    size_t blen = buffer_string_length(b);
    if (blen > len && b->ptr[len] == '/' && 0 == memcmp(b->ptr, name, len))
        keys[(*ndx)++] = t->key;
}

static void stat_cache_prune_dir_tree(const char *name, size_t len)
{
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    splay_tree *sptree = sc.files;
    do {
        if (!sptree) return;
        max_ndx = 0;
        stat_cache_tag_dir_tree(sptree, name, len, keys, &max_ndx);
        for (i = 0; i < max_ndx; ++i) {
            const int ndx = keys[i];
            splay_tree *node = sptree = splaytree_splay(sptree, ndx);
            if (node && node->key == ndx) {
                stat_cache_entry_free(node->data);
                sptree = splaytree_delete(sptree, ndx);
            }
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
    sc.files = sptree;
}

static void stat_cache_delete_tree(const char *name, size_t len)
{
    stat_cache_delete_entry(name, len);
    stat_cache_prune_dir_tree(name, len);
}

void stat_cache_delete_dir(const char *name, size_t len)
{
    force_assert(0 != len);
    if (name[len-1] == '/') { if (0 == --len) len = 1; }
    stat_cache_delete_tree(name, len);
  #ifdef HAVE_FAM_H
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
        splay_tree **sptree = &sc.scf->dirs;
        fam_dir_entry *fam_dir = stat_cache_sptree_find(sptree, name, len);
        if (fam_dir && buffer_is_equal_string(fam_dir->name, name, len))
            fam_dir_invalidate_node(fam_dir);
        if (*sptree) fam_dir_invalidate_tree(*sptree, name, len);
        fam_dir_periodic_cleanup();
    }
  #endif
}

/***
 *
 *
 *
 * returns:
 *  - HANDLER_FINISHED on cache-miss (don't forget to reopen the file)
 *  - HANDLER_ERROR on stat() failed -> see errno for problem
 */

stat_cache_entry * stat_cache_get_entry(const buffer *name) {
	stat_cache_entry *sce = NULL;
	struct stat st;
	int file_ndx;

	/* consistency: ensure lookup name does not end in '/' unless root "/"
	 * (but use full path given with stat(), even with trailing '/') */
	int final_slash = 0;
	size_t len = buffer_string_length(name);
	force_assert(0 != len);
	if (name->ptr[len-1] == '/') { final_slash = 1; if (0 == --len) len = 1; }
	/* Note: paths are expected to be normalized before calling stat_cache,
	 * e.g. without repeated '/' */

	if (name->ptr[0] != '/') return NULL;

	/*
	 * check if the directory for this file has changed
	 */

	const time_t cur_ts = log_epoch_secs;

	file_ndx = hashme(name->ptr, len);
	splay_tree * const sptree = sc.files = splaytree_splay(sc.files, file_ndx);

	if (sptree && (sptree->key == file_ndx)) {
		/* we have seen this file already and
		 * don't stat() it again in the same second */

		sce = sptree->data;

		/* check if the name is the same, we might have a collision */

		if (buffer_is_equal_string(&sce->name, name->ptr, len)) {
			if (sc.stat_cache_engine == STAT_CACHE_ENGINE_SIMPLE) {
				if (sce->stat_ts == cur_ts) {
					if (final_slash && !S_ISDIR(sce->st.st_mode)) {
						errno = ENOTDIR;
						return NULL;
					}
					return sce;
				}
			}
		      #ifdef HAVE_FAM_H
			else if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM
				 && sce->fam_dir) { /* entry is in monitored dir */
				/* re-stat() periodically, even if monitoring for changes
				 * (due to limitations in stat_cache.c use of FAM)
				 * (gaps due to not continually monitoring an entire tree) */
				if (cur_ts - sce->stat_ts < 16) {
					if (final_slash && !S_ISDIR(sce->st.st_mode)) {
						errno = ENOTDIR;
						return NULL;
					}
					return sce;
				}
			}
		      #endif
		} else {
			/* collision, forget about the entry */
			sce = NULL;
		}
	}

	if (-1 == stat(name->ptr, &st)) {
		return NULL;
	}

	if (S_ISREG(st.st_mode)) {
		/* fix broken stat/open for symlinks to reg files with appended slash on freebsd,osx */
		if (name->ptr[buffer_string_length(name) - 1] == '/') {
			errno = ENOTDIR;
			return NULL;
		}
	}

	if (NULL == sce) {

		sce = stat_cache_entry_init();
		buffer_copy_string_len(&sce->name, name->ptr, len);

		/* already splayed file_ndx */
		if (NULL != sptree && sptree->key == file_ndx) {
			/* hash collision: replace old entry */
			stat_cache_entry_free(sptree->data);
			sptree->data = sce;
		} else {
			sc.files = splaytree_insert(sptree, file_ndx, sce);
		}

	} else {

		buffer_clear(&sce->etag);
	      #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
		buffer_clear(&sce->content_type);
	      #endif

	}

	sce->st = st; /*(copy prior to calling fam_dir_monitor())*/

#ifdef HAVE_FAM_H
	if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
		if (sce->fam_dir) --((fam_dir_entry *)sce->fam_dir)->refcnt;
		sce->fam_dir =
		  fam_dir_monitor(sc.scf, CONST_BUF_LEN(name), &st);
	      #if 0 /*(performed below)*/
		if (NULL != sce->fam_dir) {
			/*(may have been invalidated by dir change)*/
			sce->stat_ts = cur_ts;
		}
	      #endif
	}
#endif

	sce->stat_ts = cur_ts;
	return sce;
}

int stat_cache_path_contains_symlink(const buffer *name, log_error_st *errh) {
    /* caller should check for symlinks only if we should block symlinks. */

    /* catch the obvious symlinks
     *
     * this is not a secure check as we still have a race-condition between
     * the stat() and the open. We can only solve this by
     * 1. open() the file
     * 2. fstat() the fd
     *
     * and keeping the file open for the rest of the time. But this can
     * only be done at network level.
     * */

  #ifdef HAVE_LSTAT
    /* we assume "/" can not be symlink,
     * so skip the symlink stuff if path is "/" */
    size_t len = buffer_string_length(name);
    force_assert(0 != len);
    force_assert(name->ptr[0] == '/');
    if (1 == len) return 0;
   #ifndef PATH_MAX
   #define PATH_MAX 4096
   #endif
    if (len >= PATH_MAX) return -1;

    char buf[PATH_MAX];
    memcpy(buf, name->ptr, len);
    char *s_cur = buf+len;
    do {
        *s_cur = '\0';
        struct stat st;
        if (0 == lstat(buf, &st)) {
            if (S_ISLNK(st.st_mode)) return 1;
        }
        else {
            log_perror(errh, __FILE__, __LINE__, "lstat failed for: %s", buf);
            return -1;
        }
    } while ((s_cur = strrchr(buf, '/')) != buf);
  #endif

    return 0;
}

int stat_cache_open_rdonly_fstat (const buffer *name, struct stat *st, int symlinks) {
	/*(Note: O_NOFOLLOW affects only the final path segment, the target file,
	 * not any intermediate symlinks along the path)*/
	const int fd = fdevent_open_cloexec(name->ptr, symlinks, O_RDONLY, 0);
	if (fd >= 0) {
		if (0 == fstat(fd, st)) {
			return fd;
		} else {
			close(fd);
		}
	}
	return -1;
}

/**
 * remove stat() from cache which haven't been stat()ed for
 * more than 2 seconds
 *
 *
 * walk though the stat-cache, collect the ids which are too old
 * and remove them in a second loop
 */

static void stat_cache_tag_old_entries(splay_tree * const t, int * const keys, uint32_t * const ndx, const time_t max_age, const time_t cur_ts) {
    if (!t) return;

    stat_cache_tag_old_entries(t->left, keys, ndx, max_age, cur_ts);
    stat_cache_tag_old_entries(t->right, keys, ndx, max_age, cur_ts);

    const stat_cache_entry * const sce = t->data;

    if (cur_ts - sce->stat_ts > max_age) {
        keys[(*ndx)++] = t->key;
    }
}

static void stat_cache_periodic_cleanup(const time_t max_age, const time_t cur_ts) {
	splay_tree *sptree = sc.files;
	if (!sptree) return;

	int * const keys = calloc(1, sizeof(int) * sptree->size);
	force_assert(NULL != keys);

	uint32_t max_ndx = 0;
	stat_cache_tag_old_entries(sptree, keys, &max_ndx, max_age, cur_ts);

	for (uint32_t i = 0; i < max_ndx; ++i) {
		int ndx = keys[i];
		sptree = splaytree_splay(sptree, ndx);
		if (sptree && sptree->key == ndx) {
			stat_cache_entry_free(sptree->data);
			sptree = splaytree_delete(sptree, ndx);
		}
	}

	sc.files = sptree;

	free(keys);
}

void stat_cache_trigger_cleanup(void) {
	time_t max_age = 2;

      #ifdef HAVE_FAM_H
	if (STAT_CACHE_ENGINE_FAM == sc.stat_cache_engine) {
		if (log_epoch_secs & 0x1F) return;
		/* once every 32 seconds (0x1F == 31) */
		max_age = 32;
		fam_dir_periodic_cleanup();
		/* By doing this before stat_cache_periodic_cleanup(),
		 * entries used within the next max_age secs will remain
		 * monitored, instead of effectively flushing and
		 * rebuilding the FAM monitoring every max_age seconds */
	}
      #endif

	stat_cache_periodic_cleanup(max_age, log_epoch_secs);
}
