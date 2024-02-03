#include "first.h"

#include "stat_cache.h"

#include "sys-stat.h"
#include "sys-unistd.h" /* <unistd.h> */

#include "log.h"
#include "fdevent.h"
#include "http_etag.h"
#include "algo_splaytree.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#if defined(HAVE_SYS_XATTR_H)
# include <sys/xattr.h>
#elif defined(HAVE_ATTR_ATTRIBUTES_H)
# include <attr/attributes.h>
#endif

#ifdef HAVE_SYS_EXTATTR_H
# include <sys/extattr.h>
#endif

/*
 * stat-cache
 *
 * - a splay-tree is used as we can use the caching effect of it
 */

enum {
  STAT_CACHE_ENGINE_SIMPLE  = 0  /*(default)*/
 ,STAT_CACHE_ENGINE_NONE    = 1
 ,STAT_CACHE_ENGINE_FAM     = 2  /* same as STAT_CACHE_ENGINE_INOTIFY */
 ,STAT_CACHE_ENGINE_INOTIFY = 2  /* same as STAT_CACHE_ENGINE_FAM */
 ,STAT_CACHE_ENGINE_KQUEUE  = 2  /* same as STAT_CACHE_ENGINE_FAM */
};

struct stat_cache_fam;  /* declaration */

typedef struct stat_cache {
	int stat_cache_engine;
	splay_tree *files; /* nodes of tree are (stat_cache_entry *) */
	struct stat_cache_fam *scf;
} stat_cache;

static stat_cache sc;


__attribute_noinline__
static void * stat_cache_sptree_ndx(splay_tree ** const sptree,
                                    int * const ndxp,
                                    const char * const name,
                                    uint32_t len)
{
    const int ndx = splaytree_djbhash(name, len);
    if (ndxp) *ndxp = ndx;
    *sptree = splaytree_splay(*sptree, ndx);
    return (*sptree && (*sptree)->key == ndx) ? (*sptree)->data : NULL;
}

static void * stat_cache_sptree_find(splay_tree ** const sptree,
                                     const char * const name,
                                     uint32_t len)
{
    return stat_cache_sptree_ndx(sptree, NULL, name, len);
}


#if defined(HAVE_SYS_INOTIFY_H) \
 || (defined(HAVE_SYS_EVENT_H) && defined(HAVE_KQUEUE))
#ifndef HAVE_FAM_H
#define HAVE_FAM_H
#endif
#endif

#ifdef HAVE_FAM_H

/* monitor changes in directories using FAM
 *
 * This implementation employing FAM monitors directories as they are used,
 * and maintains a reference count for cache use within stat_cache.c.
 * A periodic job runs in lighttpd every 32 seconds, expiring entries unused
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

#if defined(HAVE_SYS_INOTIFY_H) \
 && !(defined(HAVE_SYS_EVENT_H) && defined(HAVE_KQUEUE))

#include <sys/inotify.h>
#ifndef IN_EXCL_UNLINK /*(not defined in some very old glibc headers)*/
#define IN_EXCL_UNLINK 0x04000000
#endif

/*(translate FAM API to inotify; this is specific to stat_cache.c use of FAM)*/
#define fam fd /*(translate struct stat_cache_fam scf->fam -> scf->fd)*/
typedef int FAMRequest; /*(fr)*/
#define FAMClose(fd) \
        close(*(fd))
#define FAMCancelMonitor(fd, wd) \
        inotify_rm_watch(*(fd), *(wd))
#define fam_watch_mask ( IN_ATTRIB | IN_CREATE | IN_DELETE | IN_DELETE_SELF \
                       | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM \
                       | IN_EXCL_UNLINK | IN_ONLYDIR )
                     /*(note: follows symlinks; not providing IN_DONT_FOLLOW)*/
#define FAMMonitorDirectory(fd, fn, wd, userData) \
        ((*(wd) = inotify_add_watch(*(fd), (fn), (fam_watch_mask))) < 0)
typedef enum FAMCodes { /*(copied from fam.h to define arbitrary enum values)*/
    FAMChanged=1,
    FAMDeleted=2,
    FAMCreated=5,
    FAMMoved=6,
} FAMCodes;

#elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
#undef HAVE_SYS_INOTIFY_H

#include <sys/event.h>
#include <sys/time.h>

/*(translate FAM API to inotify; this is specific to stat_cache.c use of FAM)*/
#define fam fd /*(translate struct stat_cache_fam scf->fam -> scf->fd)*/
typedef int FAMRequest; /*(fr)*/
#define FAMClose(fd) \
        (-1 != (*(fd)) ? close(*(fd)) : 0)
static int FAMCancelMonitor (const int * const fd, int * const wd)
{
    if (-1 == *fd) return 0;
    if (-1 == *wd) return 0;
    struct timespec t0 = { 0, 0 };
    struct kevent kev;
    EV_SET(&kev, *wd, EVFILT_VNODE, EV_DELETE, 0, 0, 0);
    int rc = kevent(*fd, &kev, 1, NULL, 0, &t0);
    close(*wd);
    *wd = -1;
    return rc;
}
static int FAMMonitorDirectory (int * const fd, char * const fn, int * const wd, void * const userData)
{
    *wd = fdevent_open_dirname(fn, 1); /*(note: follows symlinks)*/
    if (-1 == *wd) return -1;
    struct timespec t0 = { 0, 0 };
    struct kevent kev;
    unsigned short kev_flags = EV_ADD | EV_ENABLE | EV_CLEAR;
    unsigned int kev_fflags = NOTE_ATTRIB | NOTE_EXTEND | NOTE_LINK | NOTE_WRITE
                            | NOTE_DELETE | NOTE_REVOKE | NOTE_RENAME;
    EV_SET(&kev, *wd, EVFILT_VNODE, kev_flags, kev_fflags, 0, userData);
    return kevent(*fd, &kev, 1, NULL, 0, &t0);
}
typedef enum FAMCodes { /*(copied from fam.h to define arbitrary enum values)*/
    FAMChanged=1,
    FAMDeleted=2,
    FAMCreated=5,
    FAMMoved=6,
} FAMCodes;

#else

#include <fam.h>

#ifdef HAVE_FAMNOEXISTS
#ifndef LIGHTTPD_STATIC
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#endif
#endif

#endif

typedef struct fam_dir_entry {
	buffer name;
	int refcnt;
	FAMRequest req;
	unix_time64_t stat_ts;
	dev_t st_dev;
	ino_t st_ino;
	struct fam_dir_entry *fam_parent;
} fam_dir_entry;

typedef struct stat_cache_fam {
	splay_tree *dirs; /* indexed by path; node data is fam_dir_entry */
  #ifdef HAVE_SYS_INOTIFY_H
	splay_tree *wds;  /* indexed by inotify watch descriptor */
  #elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
  #else
	FAMConnection fam;
  #endif
	log_error_st *errh;
	fdevents *ev;
	fdnode *fdn;
	int fd;
} stat_cache_fam;

__attribute_returns_nonnull__
static fam_dir_entry * fam_dir_entry_init(const char *name, size_t len)
{
    fam_dir_entry * const fam_dir = ck_calloc(1, sizeof(*fam_dir));
    buffer_copy_string_len(&fam_dir->name, name, len);
    fam_dir->refcnt = 0;
  #if defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
    fam_dir->req = -1;
  #endif

    return fam_dir;
}

static void fam_dir_entry_free(fam_dir_entry *fam_dir)
{
    if (!fam_dir) return;
    /*(fam_dir->fam_parent might be invalid pointer here; ignore)*/
    free(fam_dir->name.ptr);
  #if defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
    if (-1 != fam_dir->req)
        close(fam_dir->req);
  #endif
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
    if (*ndx == 512) return; /*(must match num array entries in keys[])*/
    if (t->left)  fam_dir_tag_refcnt(t->left,  keys, ndx);
    if (t->right) fam_dir_tag_refcnt(t->right, keys, ndx);
    if (*ndx == 512) return; /*(must match num array entries in keys[])*/

    fam_dir_entry * const fam_dir = t->data;
    if (0 == fam_dir->refcnt) {
        fam_dir_invalidate_node(fam_dir);
        keys[(*ndx)++] = t->key;
    }
}

__attribute_noinline__
static void fam_dir_periodic_cleanup(void) {
    stat_cache_fam * const scf = sc.scf;
    int max_ndx, i;
    int keys[512]; /* 2k size on stack */
  #if defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
    struct kevent kevl[512]; /* 32k size on stack to batch kevent EV_DELETE */
  #endif
    do {
        if (!scf->dirs) break;
        max_ndx = 0;
        fam_dir_tag_refcnt(scf->dirs, keys, &max_ndx);
        for (i = 0; i < max_ndx; ++i) {
            {
                scf->dirs = splaytree_splay_nonnull(scf->dirs, keys[i]);
                fam_dir_entry *fam_dir = scf->dirs->data;
                scf->dirs = splaytree_delete_splayed_node(scf->dirs);
              #ifdef HAVE_SYS_INOTIFY_H
                scf->wds = splaytree_delete(scf->wds, fam_dir->req);
              #elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
                /* batch process kevent removal; defer cancel */
                EV_SET(kevl+i, fam_dir->req, EVFILT_VNODE, EV_DELETE, 0, 0, 0);
                fam_dir->req = -1; /*(make FAMCancelMonitor() a no-op)*/
              #endif
                FAMCancelMonitor(&scf->fam, &fam_dir->req);
                fam_dir_entry_free(fam_dir);
            }
        }
      #if defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
        /* batch process: kevent() to submit EV_DELETE, then close dir fds */
        if (0 == max_ndx) break;
        struct timespec t0 = { 0, 0 };
        kevent(scf->fd, kevl, max_ndx, NULL, 0, &t0);
        for (i = 0; i < max_ndx; ++i)
            close((int)kevl[i].ident);
      #endif
    } while (max_ndx == sizeof(keys)/sizeof(int));
}

static void fam_dir_invalidate_tree(splay_tree *t, const char *name, size_t len)
{
  #ifdef __clang_analyzer__
    force_assert(name);
  #endif
    /*force_assert(t);*/
    if (t->left)  fam_dir_invalidate_tree(t->left,  name, len);
    if (t->right) fam_dir_invalidate_tree(t->right, name, len);

    fam_dir_entry * const fam_dir = t->data;
  #ifdef __clang_analyzer__
    force_assert(fam_dir);
  #endif
    const buffer * const b = &fam_dir->name;
    size_t blen = buffer_clen(b);
    if (blen > len && b->ptr[len] == '/' && 0 == memcmp(b->ptr, name, len))
        fam_dir_invalidate_node(fam_dir);
}

/* declarations */
static void stat_cache_delete_tree(const char *name, uint32_t len);
static void stat_cache_invalidate_dir_tree(const char *name, size_t len);
static void stat_cache_handle_fdevent_fn(stat_cache_fam * const scf, fam_dir_entry * const fam_dir, const char * const fn, const uint32_t fnlen, int code);

static void stat_cache_handle_fdevent_in(stat_cache_fam *scf)
{
  #ifdef HAVE_SYS_INOTIFY_H
    /*(inotify pads in->len to align struct following in->name[])*/
    char buf[4096]
      __attribute__ ((__aligned__(__alignof__(struct inotify_event))));
    int rd;
    do {
        rd = (int)read(scf->fd, buf, sizeof(buf));
        if (rd <= 0) {
            if (-1 == rd && errno != EINTR && errno != EAGAIN) {
                log_perror(scf->errh, __FILE__, __LINE__, "inotify error");
                /* TODO: could flush cache, close scf->fd, and re-open inotify*/
            }
            break;
        }
        for (int i = 0; i < rd; ) {
            struct inotify_event * const in =
              (struct inotify_event *)((uintptr_t)buf + i);
            uint32_t len = in->len;
            if (len > sizeof(buf)) break; /*(should not happen)*/
            i += sizeof(struct inotify_event) + len;
            if (i > rd) break; /*(should not happen (partial record))*/
            if (in->mask & IN_CREATE)
                continue; /*(see comment below for FAMCreated)*/
            if (in->mask & IN_Q_OVERFLOW) {
                log_error(scf->errh, __FILE__, __LINE__,
                          "inotify queue overflow");
                continue;
            }
            /* ignore events which may have been pending for
             * paths recently cancelled via FAMCancelMonitor() */
            scf->wds = splaytree_splay(scf->wds, in->wd);
            if (!scf->wds || scf->wds->key != in->wd)
                continue;
            fam_dir_entry *fam_dir = scf->wds->data;
            if (NULL == fam_dir)        /*(should not happen)*/
                continue;
            if (fam_dir->req != in->wd) /*(should not happen)*/
                continue;
            /*(specific to use here in stat_cache.c)*/
            int code = 0;
            if (in->mask & (IN_ATTRIB | IN_MODIFY))
                code = FAMChanged;
            else if (in->mask & (IN_DELETE | IN_DELETE_SELF | IN_UNMOUNT))
                code = FAMDeleted;
            else if (in->mask & (IN_MOVE_SELF | IN_MOVED_FROM))
                code = FAMMoved;

            if (len) {
                do { --len; } while (len && in->name[len-1] == '\0');
            }
            stat_cache_handle_fdevent_fn(scf, fam_dir, in->name, len, code);
        }
    } while (rd + sizeof(struct inotify_event) + NAME_MAX + 1 > sizeof(buf));
  #elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
    struct kevent kevl[256];
    struct timespec t0 = { 0, 0 };
    int n;
    do {
        n = kevent(scf->fd, NULL, 0, kevl, sizeof(kevl)/sizeof(*kevl), &t0);
        if (n <= 0) break;
        for (int i = 0; i < n; ++i) {
            const struct kevent * const kev = kevl+i;
            /* ignore events which may have been pending for
             * paths recently cancelled via FAMCancelMonitor() */
            int ndx = (int)(intptr_t)kev->udata;
            scf->dirs = splaytree_splay(scf->dirs, ndx);
            if (!scf->dirs || scf->dirs->key != ndx)
                continue;
            fam_dir_entry *fam_dir = scf->dirs->data;
            if (fam_dir->req != (int)kev->ident)
                continue;
            /*(specific to use here in stat_cache.c)*/
            /* note: stat_cache only monitors on directories,
             *       so events here are only on directories
             * note: changes are treated as FAMDeleted since
             *       it is unknown which file in dir was changed
             *       This is not efficient, but this stat_cache mechanism also
             *       should not be used on frequently modified directories. */
            int code = 0;
            if (kev->fflags & (NOTE_WRITE|NOTE_ATTRIB|NOTE_EXTEND|NOTE_LINK))
                code = FAMDeleted; /*(not FAMChanged; see comment above)*/
            else if (kev->fflags & (NOTE_DELETE|NOTE_REVOKE))
                code = FAMDeleted;
            else if (kev->fflags & NOTE_RENAME)
                code = FAMMoved;
            if (kev->flags & EV_ERROR) /*(not expected; treat as FAMDeleted)*/
                code = FAMDeleted;
            stat_cache_handle_fdevent_fn(scf, fam_dir, NULL, 0, code);
        }
    } while (n == sizeof(kevl)/sizeof(*kevl));
  #else
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

        uint32_t fnlen = (fe.code != FAMCreated && fe.filename[0] != '/')
          ? (uint32_t)strlen(fe.filename)
          : 0;
        stat_cache_handle_fdevent_fn(scf, fam_dir, fe.filename, fnlen, fe.code);
    }
  #endif
}

static void stat_cache_handle_fdevent_fn(stat_cache_fam * const scf, fam_dir_entry *fam_dir, const char * const fn, const uint32_t fnlen, int code)
{
        if (fnlen) {
            buffer * const n = &fam_dir->name;
            fam_dir_entry *fam_link;
            uint32_t len;
            switch (code) {
            case FAMCreated:
                /* file created in monitored dir modifies dir and
                 * we should get a separate FAMChanged event for dir.
                 * Therefore, ignore file FAMCreated event here.
                 * Also, if FAMNoExists() is used, might get spurious
                 * FAMCreated events as changes are made e.g. in monitored
                 * sub-sub-sub dirs and the library discovers new (already
                 * existing) dir entries */
                return;
            case FAMChanged:
                /* file changed in monitored dir does not modify dir */
            case FAMDeleted:
            case FAMMoved:
                /* file deleted or moved in monitored dir modifies dir,
                 * but FAM provides separate notification for that */

                /* temporarily append filename to dir in fam_dir->name to
                 * construct path, then delete stat_cache entry (if any)*/
                len = buffer_clen(n);
                buffer_append_path_len(n, fn, fnlen);
                /* (alternatively, could chose to stat() and update)*/
                stat_cache_invalidate_entry(BUF_PTR_LEN(n));

                fam_link = /*(check if might be symlink to monitored dir)*/
                stat_cache_sptree_find(&scf->dirs, BUF_PTR_LEN(n));
                if (fam_link && !buffer_is_equal(&fam_link->name, n))
                    fam_link = NULL;

                buffer_truncate(n, len);

                if (fam_link) {
                    /* replaced symlink changes containing dir */
                    stat_cache_invalidate_entry(n->ptr, len);
                    /* handle symlink to dir as deleted dir below */
                    code = FAMDeleted;
                    fam_dir = fam_link;
                    break;
                }
                return;
            default:
                return;
            }
        }

        switch(code) {
        case FAMChanged:
            stat_cache_invalidate_entry(BUF_PTR_LEN(&fam_dir->name));
            break;
        case FAMDeleted:
        case FAMMoved:
            stat_cache_delete_tree(BUF_PTR_LEN(&fam_dir->name));
            fam_dir_invalidate_node(fam_dir);
            if (scf->dirs)
                fam_dir_invalidate_tree(scf->dirs,
                                        BUF_PTR_LEN(&fam_dir->name));
            fam_dir_periodic_cleanup();
            break;
        default:
            break;
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
		fdevent_unregister(scf->ev, scf->fdn);
		scf->fdn = NULL;

		FAMClose(&scf->fam);
		scf->fd = -1;
	}

	return HANDLER_GO_ON;
}

static stat_cache_fam * stat_cache_init_fam(fdevents *ev, log_error_st *errh) {
	stat_cache_fam *scf = ck_calloc(1, sizeof(*scf));
	scf->fd = -1;
	scf->ev = ev;
	scf->errh = errh;

  #ifdef HAVE_SYS_INOTIFY_H
   #if !defined(IN_NONBLOCK) || !defined(IN_CLOEXEC)
	scf->fd = inotify_init();
	if (scf->fd >= 0 && 0 != fdevent_fcntl_set_nb_cloexec(scf->fd)) {
		close(scf->fd);
		scf->fd = -1;
	}
   #else
	scf->fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
   #endif
	if (scf->fd < 0) {
		log_perror(errh, __FILE__, __LINE__, "inotify_init1()");
		free(scf);
		return NULL;
	}
  #elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
   #ifdef __NetBSD__
	scf->fd = kqueue1(O_NONBLOCK|O_CLOEXEC|O_NOSIGPIPE);
   #else
	scf->fd = kqueue();
	if (scf->fd >= 0) fdevent_setfd_cloexec(scf->fd);
   #endif
	if (scf->fd < 0) {
		log_perror(errh, __FILE__, __LINE__, "kqueue()");
		free(scf);
		return NULL;
	}
  #else
	/* setup FAM */
	if (0 != FAMOpen2(&scf->fam, "lighttpd")) {
		log_error(errh, __FILE__, __LINE__,
		  "could not open a fam connection, dying.");
		free(scf);
		return NULL;
	}
      #ifdef HAVE_FAMNOEXISTS
      #ifdef LIGHTTPD_STATIC
	FAMNoExists(&scf->fam);
      #else
	int (*FAMNoExists_fn)(FAMConnection *);
	FAMNoExists_fn =
	  (int (*)(FAMConnection *))(intptr_t)dlsym(RTLD_DEFAULT,"FAMNoExists");
	if (FAMNoExists_fn) FAMNoExists_fn(&scf->fam);
      #endif
      #endif

	scf->fd = FAMCONNECTION_GETFD(&scf->fam);
	fdevent_setfd_cloexec(scf->fd);
  #endif
	scf->fdn = fdevent_register(scf->ev, scf->fd, stat_cache_handle_fdevent, scf);
	fdevent_fdnode_event_set(scf->ev, scf->fdn, FDEVENT_IN | FDEVENT_RDHUP);

	return scf;
}

static void stat_cache_free_fam(stat_cache_fam *scf) {
	if (NULL == scf) return;

      #ifdef HAVE_SYS_INOTIFY_H
	while (scf->wds) {
		scf->wds = splaytree_delete_splayed_node(scf->wds);
	}
      #elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
	/*(quicker cleanup to close kqueue() before cancel per entry)*/
	close(scf->fd);
	scf->fd = -1;
      #endif
	while (scf->dirs) {
		/*(skip entry invalidation and FAMCancelMonitor())*/
		fam_dir_entry_free((fam_dir_entry *)scf->dirs->data);
		scf->dirs = splaytree_delete_splayed_node(scf->dirs);
	}

	if (-1 != scf->fd) {
		/*scf->fdn already cleaned up in fdevent_free()*/
		FAMClose(&scf->fam);
		/*scf->fd = -1;*/
	}

	free(scf);
}

static fam_dir_entry * fam_dir_monitor(stat_cache_fam *scf, char *fn, uint32_t dirlen, struct stat *st)
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
    int dir_ndx;
    fam_dir_entry *fam_dir =
      stat_cache_sptree_ndx(&scf->dirs, &dir_ndx, fn, dirlen);

    if (NULL != fam_dir) {
        if (!buffer_eq_slen(&fam_dir->name, fn, dirlen)) {
            /* hash collision; preserve existing
             * do not monitor new to avoid cache thrashing */
            return NULL;
        }
        /* directory already registered */
    }

    const unix_time64_t cur_ts = log_monotonic_secs;
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
          #ifdef HAVE_SYS_INOTIFY_H
            scf->wds = splaytree_delete(scf->wds, fam_dir->req);
          #endif
            if (0 != FAMCancelMonitor(&scf->fam, &fam_dir->req)
                || 0 != FAMMonitorDirectory(&scf->fam, fam_dir->name.ptr,
                                            &fam_dir->req,
                                            (void *)(intptr_t)dir_ndx)) {
                fam_dir->stat_ts = 0; /* invalidate */
                return NULL;
            }
            fam_dir->st_dev = st->st_dev;
            fam_dir->st_ino = st->st_ino;
          #ifdef HAVE_SYS_INOTIFY_H
            scf->wds = splaytree_insert_splayed(scf->wds,fam_dir->req,fam_dir);
          #endif
        }
        fam_dir->stat_ts = cur_ts;
    }

    if (NULL == fam_dir) {
        fam_dir = fam_dir_entry_init(fn, dirlen);

        if (0 != FAMMonitorDirectory(&scf->fam,fam_dir->name.ptr,&fam_dir->req,
                                     (void *)(intptr_t)dir_ndx)) {
          #if defined(HAVE_SYS_INOTIFY_H) \
           || (defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE)
            log_perror(scf->errh, __FILE__, __LINE__,
              "monitoring dir failed: %s file: %s",
              fam_dir->name.ptr, fn);
          #else
            log_error(scf->errh, __FILE__, __LINE__,
              "monitoring dir failed: %s file: %s %s",
              fam_dir->name.ptr, fn, FamErrlist[FAMErrno]);
          #endif
            fam_dir_entry_free(fam_dir);
            return NULL;
        }

        scf->dirs = splaytree_insert_splayed(scf->dirs, dir_ndx, fam_dir);
      #ifdef HAVE_SYS_INOTIFY_H
        scf->wds = splaytree_insert(scf->wds, fam_dir->req, fam_dir);
      #endif
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


__attribute_malloc__
__attribute_noinline__
__attribute_returns_nonnull__
static stat_cache_entry * stat_cache_entry_init(void) {
    stat_cache_entry *sce = ck_calloc(1, sizeof(*sce));
    sce->fd = -1;
    sce->refcnt = 1;
    return sce;
}

static void stat_cache_entry_free(void *data) {
    stat_cache_entry *sce = data;
    if (!sce) return;

    if (--sce->refcnt) return;

  #ifdef HAVE_FAM_H
    /*(decrement refcnt only;
     * defer cancelling FAM monitor on dir even if refcnt reaches zero)*/
    if (sce->fam_dir) --((fam_dir_entry *)sce->fam_dir)->refcnt;
  #endif

    free(sce->name.ptr);
    free(sce->etag.ptr);
    if (sce->content_type.size) free(sce->content_type.ptr);
    if (sce->fd >= 0) close(sce->fd);

    free(sce);
}

void stat_cache_entry_refchg(void *data, int mod) {
    /*(expect mod == -1 or mod == 1)*/
    stat_cache_entry * const sce = data;
    if (mod < 0 && 1 == sce->refcnt)
        stat_cache_entry_free(data);
    else
        sce->refcnt += mod;
}

__attribute_nonnull__()
static splay_tree * stat_cache_sptree_node_free(splay_tree *sptree) {
    stat_cache_entry_free(sptree->data);
    return splaytree_delete_splayed_node(sptree);
}

#if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)

static const char *attrname = "Content-Type";
static char attrval[128];
static buffer attrb = { attrval, 0, 0 };

static int stat_cache_attr_get(const char *name) {
  #if defined(HAVE_XATTR)
   #if defined(HAVE_SYS_XATTR_H)
    ssize_t attrlen;
   #if defined(__APPLE__) && defined(__MACH__)
    if (0 < (attrlen = getxattr(name, attrname,
                                attrval, sizeof(attrval)-1, 0, 0)))
   #else
    if (0 < (attrlen = getxattr(name, attrname,
                                attrval, sizeof(attrval)-1)))
   #endif
   #else
    int attrlen = sizeof(attrval)-1;
    if (0 == attr_get(name, attrname, attrval, &attrlen, 0))
   #endif
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
        sptree = stat_cache_sptree_node_free(sptree);
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
    if (buffer_is_blank(stat_cache_string))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE;
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("simple")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE;
#ifdef HAVE_SYS_INOTIFY_H
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("inotify")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_INOTIFY;
        /*(STAT_CACHE_ENGINE_FAM == STAT_CACHE_ENGINE_INOTIFY)*/
#elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("kqueue")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_KQUEUE;
        /*(STAT_CACHE_ENGINE_FAM == STAT_CACHE_ENGINE_KQUEUE)*/
#endif
#ifdef HAVE_FAM_H
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("fam")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_FAM;
#endif
    else if (buffer_eq_slen(stat_cache_string, CONST_STR_LEN("disable"))
             || buffer_eq_slen(stat_cache_string, CONST_STR_LEN("none")))
        sc.stat_cache_engine = STAT_CACHE_ENGINE_NONE;
    else {
        static const char fmt[] =
          "server.stat-cache-engine can be one of \"disable\", \"simple\","
#ifdef HAVE_SYS_INOTIFY_H
          " \"inotify\","
#elif defined HAVE_SYS_EVENT_H && defined HAVE_KQUEUE
          " \"kqueue\","
#endif
#ifdef HAVE_FAM_H
          " \"fam\","
#endif
          " but not: %s";
        log_error(errh, __FILE__, __LINE__, fmt, stat_cache_string->ptr);
        return -1;
    }
    return 0;
}

const buffer * stat_cache_mimetype_by_ext(const array * const mimetypes, const char * const name, const uint32_t nlen)
{
    const char * const end = name + nlen; /*(end of string)*/
    const uint32_t used = mimetypes->used;
    if (used < 16) {
        for (uint32_t i = 0; i < used; ++i) {
            /* suffix match */
            const data_string *ds = (data_string *)mimetypes->data[i];
            const size_t klen = buffer_clen(&ds->key);
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
    if (!buffer_is_blank(&sce->content_type)) return &sce->content_type;

    if (!S_ISREG(sce->st.st_mode)) return NULL;

    /* cache mimetype */
    const buffer *mtype =
      (use_xattr) ? stat_cache_mimetype_by_xattr(sce->name.ptr) : NULL;
    if (NULL == mtype)
        mtype = stat_cache_mimetype_by_ext(mimetypes, BUF_PTR_LEN(&sce->name));
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
    if (!buffer_is_blank(&sce->content_type)) return &sce->content_type;

    if (!S_ISREG(sce->st.st_mode)) return NULL;

    /* cache mimetype */
    const buffer * const mtype =
      stat_cache_mimetype_by_ext(mimetypes, BUF_PTR_LEN(&sce->name));
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
    if (!buffer_is_blank(&sce->etag)) return &sce->etag;

    if (S_ISREG(sce->st.st_mode) || S_ISDIR(sce->st.st_mode)) {
        if (0 == flags) return NULL;
        http_etag_create(&sce->etag, &sce->st, flags);
        return &sce->etag;
    }

    return NULL;
}

__attribute_pure__
static int stat_cache_stat_eq(const struct stat * const sta, const struct stat * const stb) {
    return
      #ifdef st_mtime /* use high-precision timestamp if available */
      #if defined(__APPLE__) && defined(__MACH__)
        sta->st_mtimespec.tv_nsec == stb->st_mtimespec.tv_nsec
      #else
        sta->st_mtim.tv_nsec == stb->st_mtim.tv_nsec
      #endif
      #else
        1
      #endif
        && sta->st_mtime == stb->st_mtime
        && sta->st_size  == stb->st_size
        && sta->st_ino   == stb->st_ino
        && sta->st_dev   == stb->st_dev;
}

void stat_cache_update_entry(const char *name, uint32_t len,
                             const struct stat *st, const buffer *etagb)
{
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_NONE) return;
    if (__builtin_expect( (0 == len), 0)) return; /*(should not happen)*/
    if (name[len-1] == '/') { if (0 == --len) len = 1; }
    splay_tree **sptree = &sc.files;
    stat_cache_entry *sce =
      stat_cache_sptree_find(sptree, name, len);
    if (sce && buffer_is_equal_string(&sce->name, name, len)) {
        if (!stat_cache_stat_eq(&sce->st, st)) {
            /* etagb might be NULL to clear etag (invalidate) */
            buffer_clear(&sce->etag);
            if (etagb)
                buffer_copy_string_len(&sce->etag, BUF_PTR_LEN(etagb));
          #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
            buffer_clear(&sce->content_type);
          #endif
            if (sce->fd >= 0) {
                if (1 == sce->refcnt) {
                    close(sce->fd);
                    sce->fd = -1;
                }
                else {
                    --sce->refcnt; /* stat_cache_entry_free(sce); */
                    (*sptree)->data = sce = stat_cache_entry_init();
                    buffer_copy_string_len(&sce->name, name, len);
                }
            }
            sce->st = *st;
        }
        sce->stat_ts = log_monotonic_secs;
    }
}

void stat_cache_delete_entry(const char *name, uint32_t len)
{
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_NONE) return;
    if (__builtin_expect( (0 == len), 0)) return; /*(should not happen)*/
    if (name[len-1] == '/') { if (0 == --len) len = 1; }
    splay_tree **sptree = &sc.files;
    stat_cache_entry *sce = stat_cache_sptree_find(sptree, name, len);
    if (sce && buffer_is_equal_string(&sce->name, name, len)) {
        *sptree = stat_cache_sptree_node_free(*sptree);
    }
}

void stat_cache_invalidate_entry(const char *name, uint32_t len)
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

    const buffer * const b = &((stat_cache_entry *)t->data)->name;
    const size_t blen = buffer_clen(b);
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

    const buffer * const b = &((stat_cache_entry *)t->data)->name;
    const size_t blen = buffer_clen(b);
    if (blen > len && b->ptr[len] == '/' && 0 == memcmp(b->ptr, name, len))
        keys[(*ndx)++] = t->key;
}

__attribute_noinline__
static void stat_cache_prune_dir_tree(const char *name, size_t len)
{
    splay_tree *sptree = sc.files;
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    do {
        if (!sptree) break;
        max_ndx = 0;
        stat_cache_tag_dir_tree(sptree, name, len, keys, &max_ndx);
        for (i = 0; i < max_ndx; ++i) {
            sptree = splaytree_splay_nonnull(sptree, keys[i]);
            sptree = stat_cache_sptree_node_free(sptree);
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
    sc.files = sptree;
}

static void stat_cache_delete_tree(const char *name, uint32_t len)
{
    stat_cache_delete_entry(name, len);
    stat_cache_prune_dir_tree(name, len);
}

void stat_cache_delete_dir(const char *name, uint32_t len)
{
    if (__builtin_expect( (0 == len), 0)) return; /*(should not happen)*/
    if (name[len-1] == '/') { if (0 == --len) len = 1; }
    stat_cache_delete_tree(name, len);
  #ifdef HAVE_FAM_H
    if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
        splay_tree **sptree = &sc.scf->dirs;
        fam_dir_entry *fam_dir = stat_cache_sptree_find(sptree, name, len);
        if (fam_dir && buffer_eq_slen(&fam_dir->name, name, len))
            fam_dir_invalidate_node(fam_dir);
        if (*sptree) fam_dir_invalidate_tree(*sptree, name, len);
        fam_dir_periodic_cleanup();
    }
  #endif
}

__attribute_cold__
__attribute_noinline__
static stat_cache_entry * stat_cache_refresh_entry(const buffer * const name, uint32_t len, stat_cache_entry *sce, const int file_ndx, const int refresh) {

  #ifndef _WIN32
    /* sanity check; should not happen; should not be called with rel paths */
    if (__builtin_expect( (name->ptr[0] != '/'), 0)) {
        errno = EINVAL;
        return NULL;
    }
  #endif

    /* use full path w/ stat(), even w/ trailing '/' ('len' may be shorter) */
    struct stat st;
    if (-1 == stat(name->ptr, &st))
        return NULL;

    if (NULL == sce || !stat_cache_stat_eq(&sce->st, &st)) {
        if (NULL != sce && sce->fd >= 0) {
            /* close fd when refresh needed */
            if (1 == sce->refcnt) {
                close(sce->fd);
                sce->fd = -1;
            }
            else {
                --sce->refcnt; /* stat_cache_entry_free(sce); */
                sce = NULL;
            }
        }

        if (NULL == sce) {
            sce = stat_cache_entry_init();
            buffer_copy_string_len(&sce->name, name->ptr, len);

            /* sptree already splayed to file_ndx in stat_cache_get_entry() */
            splay_tree * const sptree = sc.files;
            if (NULL != sptree && sptree->key == file_ndx) {
                if (refresh < 0) { /* hash collision: replace old entry */
                    stat_cache_entry_free(sptree->data);
                } /* else prior sce refcnt was > 1 and decremented above */
                sptree->data = sce;
            }
            else
                sc.files = splaytree_insert_splayed(sptree, file_ndx, sce);
        }
        else {
            buffer_clear(&sce->etag);
          #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
            buffer_clear(&sce->content_type);
          #endif
        }

        sce->st = st; /*(copy prior to calling fam_dir_monitor())*/

      #ifdef HAVE_FAM_H
        if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
            if (sce->fam_dir) --((fam_dir_entry *)sce->fam_dir)->refcnt;
            sce->fam_dir = fam_dir_monitor(sc.scf, name->ptr, len, &st);
          #if 0 /*(performed below)*/
            if (NULL != sce->fam_dir)
                /*(may have been invalidated by dir change)*/
                sce->stat_ts = log_monotonic_secs;
          #endif
        }
      #endif
    }

    sce->stat_ts = log_monotonic_secs;
    return sce;
}

stat_cache_entry * stat_cache_get_entry(const buffer * const name) {

    /* consistency: ensure name in cache does not end in '/' unless root "/"
     * (but use full path given with stat(), even with trailing '/') */
    uint32_t len = buffer_clen(name);
    int final_slash = 0;
    if (__builtin_expect( (0 == len), 0)) return NULL; /*(should not happen)*/
    if (name->ptr[len-1] == '/') { final_slash = 1; if (0 == --len) len = 1; }
    /* Note: paths are expected to be normalized before calling stat_cache,
     * e.g. without repeated '/' */

    /* check if stat cache entry exists, matches name, and is fresh */
    int file_ndx;
    stat_cache_entry *sce =
      stat_cache_sptree_ndx(&sc.files, &file_ndx, name->ptr, len);
    int refresh = -1;/* -1 stat cache entry does not exist, or hash collision */
    if (NULL != sce) {
        /* check if the name is the same; we might have a hash collision */
        if (buffer_is_equal_string(&sce->name, name->ptr, len)) {
            const unix_time64_t cur_ts = log_monotonic_secs;
            refresh = 1; /* 1 stat cache entry exists, but might need refresh */
            if (sc.stat_cache_engine == STAT_CACHE_ENGINE_SIMPLE)
                refresh = (sce->stat_ts != cur_ts);      /* 0 if fresh */
          #ifdef HAVE_FAM_H
            else if (sc.stat_cache_engine == STAT_CACHE_ENGINE_FAM
                     && sce->fam_dir) /* entry is in monitored dir */
                /* re-stat() periodically, even if monitoring for changes
                 * (due to limitations in stat_cache.c use of FAM)
                 * (gaps due to not continually monitoring an entire tree) */
                refresh = !(cur_ts - sce->stat_ts < 16); /* 0 if fresh */
          #endif
        }
        else /* hash collision; forget about entry */
            sce = NULL;
    }

    if (refresh) {
        sce = stat_cache_refresh_entry(name, len, sce, file_ndx, refresh);
        if (NULL == sce) return NULL;
    }

    /* fix broken stat/open for symlinks to reg files with appended slash on
     * old freebsd, osx; fixed in freebsd around 2009:
     *   https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=21768 */
    /* (local fs_win32_stati64UTF8() checks, but repeat since not obvious) */
    if (final_slash && !S_ISDIR(sce->st.st_mode)) {
        errno = ENOTDIR;
        return NULL;
    }

    return sce;
}

stat_cache_entry * stat_cache_get_entry_open(const buffer * const name, const int symlinks) {
    stat_cache_entry * const sce = stat_cache_get_entry(name);
    if (NULL == sce) return NULL;
    if (sce->fd >= 0) return sce;
    if (sce->st.st_size > 0) {
        sce->fd = stat_cache_open_rdonly_fstat(name, &sce->st, symlinks);
        buffer_clear(&sce->etag);
    }
    return sce; /* (note: sce->fd might still be -1 if open() failed) */
}

const stat_cache_st * stat_cache_path_stat (const buffer * const name) {
    const stat_cache_entry * const sce = stat_cache_get_entry(name);
    return sce ? &sce->st : NULL;
}

int stat_cache_path_isdir(const buffer *name) {
    const stat_cache_entry * const sce = stat_cache_get_entry(name);
    return (sce && (S_ISDIR(sce->st.st_mode) ? 1 : (errno = ENOTDIR, 0)));
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
    size_t len = buffer_clen(name);
    if (__builtin_expect( (0 == len), 0)) return -1; /*(should not happen)*/
    if (__builtin_expect( (name->ptr[0] != '/'), 0)) return -1;
    if (__builtin_expect( (1 == len), 0)) return 0;
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
    } while ((s_cur = strrchr(buf, '/')) > buf); /*(&buf[0]==buf; NULL < buf)*/
  #else
    UNUSED(name);
    UNUSED(errh);
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
			const int errnum = errno;
			close(fd);
			errno = errnum;
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

static void stat_cache_tag_old_entries(splay_tree * const t, int * const keys, int * const ndx, const time_t max_age, const unix_time64_t cur_ts) {
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/
    if (t->left)
        stat_cache_tag_old_entries(t->left, keys, ndx, max_age, cur_ts);
    if (t->right)
        stat_cache_tag_old_entries(t->right, keys, ndx, max_age, cur_ts);
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/

    const stat_cache_entry * const sce = t->data;
    if (cur_ts - sce->stat_ts > max_age)
        keys[(*ndx)++] = t->key;
}

static void stat_cache_periodic_cleanup(const time_t max_age, const unix_time64_t cur_ts) {
    splay_tree *sptree = sc.files;
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    do {
        if (!sptree) break;
        max_ndx = 0;
        stat_cache_tag_old_entries(sptree, keys, &max_ndx, max_age, cur_ts);
        for (i = 0; i < max_ndx; ++i) {
            sptree = splaytree_splay_nonnull(sptree, keys[i]);
            sptree = stat_cache_sptree_node_free(sptree);
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
    sc.files = sptree;
}

void stat_cache_trigger_cleanup(void) {
	time_t max_age = 2;

      #ifdef HAVE_FAM_H
	if (STAT_CACHE_ENGINE_FAM == sc.stat_cache_engine) {
		if (log_monotonic_secs & 0x1F) return;
		/* once every 32 seconds (0x1F == 31) */
		max_age = 32;
		fam_dir_periodic_cleanup();
		/* By doing this before stat_cache_periodic_cleanup(),
		 * entries used within the next max_age secs will remain
		 * monitored, instead of effectively flushing and
		 * rebuilding the FAM monitoring every max_age seconds */
	}
      #endif

	stat_cache_periodic_cleanup(max_age, log_monotonic_secs);
}
