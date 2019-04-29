#include "first.h"

#include "stat_cache.h"
#include "base.h"
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
# define lstat stat
#endif

/*
 * stat-cache
 *
 * we cache the stat() calls in our own storage
 * the directories are cached in FAM
 *
 * if we get a change-event from FAM, we increment the version in the FAM->dir mapping
 *
 * if the stat()-cache is queried we check if the version id for the directory is the
 * same and return immediatly.
 *
 *
 * What we need:
 *
 * - for each stat-cache entry we need a fast indirect lookup on the directory name
 * - for each FAMRequest we have to find the version in the directory cache (index as userdata)
 *
 * stat <<-> directory <-> FAMRequest
 *
 * if file is deleted, directory is dirty, file is rechecked ...
 * if directory is deleted, directory mapping is removed
 *
 * */

/* the directory name is too long to always compare on it
 * - we need a hash
 * - the hash-key is used as sorting criteria for a tree
 * - a splay-tree is used as we can use the caching effect of it
 */

/* we want to cleanup the stat-cache every few seconds, let's say 10
 *
 * - remove entries which are outdated since 30s
 * - remove entries which are fresh but havn't been used since 60s
 * - if we don't have a stat-cache entry for a directory, release it from the monitor
 */


enum {
  STAT_CACHE_ENGINE_UNSET,
  STAT_CACHE_ENGINE_NONE,
  STAT_CACHE_ENGINE_SIMPLE,
  STAT_CACHE_ENGINE_FAM
};

#ifdef HAVE_FAM_H
struct stat_cache_fam;
#endif

typedef struct stat_cache {
	splay_tree *files; /* the nodes of the tree are stat_cache_entry's */
      #ifdef HAVE_FAM_H
	struct stat_cache_fam *scf;
      #endif
} stat_cache;


/* the famous DJB hash function for strings */
static uint32_t hashme(const char *str, int z) {
	uint32_t hash = 5381;
	for (const unsigned char *s = (const unsigned char *)str; *s; ++s) {
		hash = ((hash << 5) + hash) ^ *s;
	}

	/* customizations */

	/* (differentiate hash values with and w/o con->conf.follow_symlink) */
	hash = ((hash << 5) + hash) ^ (z ? '1' : '0');

	hash &= ~(((uint32_t)1) << 31); /* strip the highest bit */

	return hash;
}


#ifdef HAVE_FAM_H

#include <fam.h>

typedef struct {
	FAMRequest *req;
	buffer *name;
	int version;
} fam_dir_entry;

typedef struct stat_cache_fam {
	splay_tree *dirs; /* the nodes of the tree are fam_dir_entry */

	FAMConnection fam;

	int dir_ndx;
	fam_dir_entry *fam_dir;
	buffer *dir_name; /* for building the dirname from the filename */
	fdnode *fdn;
	int fd;
} stat_cache_fam;

static fam_dir_entry * fam_dir_entry_init(void) {
	fam_dir_entry *fam_dir = NULL;

	fam_dir = calloc(1, sizeof(*fam_dir));
	force_assert(NULL != fam_dir);

	fam_dir->name = buffer_init();

	return fam_dir;
}

static void fam_dir_entry_free(FAMConnection *fc, void *data) {
	fam_dir_entry *fam_dir = data;

	if (!fam_dir) return;

	FAMCancelMonitor(fc, fam_dir->req);

	buffer_free(fam_dir->name);
	free(fam_dir->req);

	free(fam_dir);
}

static handler_t stat_cache_handle_fdevent(server *srv, void *_fce, int revent) {
	size_t i;
	stat_cache_fam *scf = srv->stat_cache->scf;
	size_t events;

	UNUSED(_fce);
	/* */

	if (revent & FDEVENT_IN) {
		events = FAMPending(&scf->fam);

		for (i = 0; i < events; i++) {
			FAMEvent fe;
			fam_dir_entry *fam_dir;
			splay_tree *node;
			int ndx, j;

			FAMNextEvent(&scf->fam, &fe);

			/* handle event */

			switch(fe.code) {
			case FAMChanged:
			case FAMDeleted:
			case FAMMoved:
				/* if the filename is a directory remove the entry */

				fam_dir = fe.userdata;
				fam_dir->version++;

				/* file/dir is still here */
				if (fe.code == FAMChanged) break;

				/* we have 2 versions, follow and no-follow-symlink */

				for (j = 0; j < 2; j++) {

					ndx = hashme(fe.filename, j);

					scf->dirs = splaytree_splay(scf->dirs, ndx);
					node = scf->dirs;

					if (node && (node->key == ndx)) {
						int osize = splaytree_size(scf->dirs);

						fam_dir_entry_free(&scf->fam, node->data);
						scf->dirs = splaytree_delete(scf->dirs, ndx);

						force_assert(osize - 1 == splaytree_size(scf->dirs));
					}
				}
				break;
			default:
				break;
			}
		}
	}

	if (revent & (FDEVENT_HUP|FDEVENT_RDHUP)) {
		/* fam closed the connection */
		fdevent_fdnode_event_del(srv->ev, scf->fdn);
		fdevent_unregister(srv->ev, scf->fd);
		scf->fdn = NULL;

		FAMClose(&scf->fam);
		scf->fd = -1;
	}

	return HANDLER_GO_ON;
}

static stat_cache_fam * stat_cache_init_fam(server *srv) {
	stat_cache_fam *scf = calloc(1, sizeof(*scf));
	scf->dir_name = buffer_init();
	scf->fd = -1;

	/* setup FAM */
	if (0 != FAMOpen2(&scf->fam, "lighttpd")) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"could not open a fam connection, dieing.");
		return NULL;
	}
      #ifdef HAVE_FAMNOEXISTS
	FAMNoExists(&scf->fam);
      #endif

	scf->fd = FAMCONNECTION_GETFD(&scf->fam);
	fdevent_setfd_cloexec(scf->fd);
	scf->fdn = fdevent_register(srv->ev, scf->fd, stat_cache_handle_fdevent, NULL);
	fdevent_fdnode_event_set(srv->ev, scf->fdn, FDEVENT_IN | FDEVENT_RDHUP);

	return scf;
}

static void stat_cache_free_fam(stat_cache_fam *scf) {
	if (NULL == scf) return;
	buffer_free(scf->dir_name);

	while (scf->dirs) {
		int osize;
		splay_tree *node = scf->dirs;

		osize = scf->dirs->size;

		fam_dir_entry_free(&scf->fam, node->data);
		scf->dirs = splaytree_delete(scf->dirs, node->key);

		if (osize == 1) {
			force_assert(NULL == scf->dirs);
		} else {
			force_assert(osize == (scf->dirs->size + 1));
		}
	}

	if (-1 != scf->fd) {
		/*scf->fdn already cleaned up in fdevent_free()*/
		FAMClose(&scf->fam);
		/*scf->fd = -1;*/
	}

	free(scf);
}

static int buffer_copy_dirname(buffer *dst, const buffer *file) {
	size_t i;

	if (buffer_string_is_empty(file)) return -1;

	for (i = buffer_string_length(file); i > 0; i--) {
		if (file->ptr[i] == '/') {
			buffer_copy_string_len(dst, file->ptr, i);
			return 0;
		}
	}

	return -1;
}

static handler_t stat_cache_fam_dir_check(server *srv, stat_cache_fam *scf, stat_cache_entry *sce, const buffer *name, unsigned int follow_symlink) {
	if (0 != buffer_copy_dirname(scf->dir_name, name)) {
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"no '/' found in filename:", name);
		return HANDLER_ERROR;
	}

	scf->dir_ndx = hashme(scf->dir_name->ptr, follow_symlink);

	scf->dirs = splaytree_splay(scf->dirs, scf->dir_ndx);

	if ((NULL != scf->dirs) && (scf->dirs->key == scf->dir_ndx)) {
		scf->fam_dir = scf->dirs->data;

		/* check whether we got a collision */
		if (buffer_is_equal(scf->dir_name, scf->fam_dir->name)) {
			/* test whether a found file cache entry is still ok */
			if ((NULL != sce) && (scf->fam_dir->version == sce->dir_version)) {
				/* the stat()-cache entry is still ok */
				return HANDLER_FINISHED;
			}
		} else {
			/* hash collision, forget about the entry */
			scf->fam_dir = NULL;
		}
	} else {
		scf->fam_dir = NULL;
	}

	return HANDLER_GO_ON;
}

static void stat_cache_fam_dir_monitor(server *srv, stat_cache_fam *scf, stat_cache_entry *sce, const buffer *name) {
	/* is this directory already registered ? */
	fam_dir_entry *fam_dir = scf->fam_dir;
	if (NULL == fam_dir) {
		fam_dir = fam_dir_entry_init();

		buffer_copy_buffer(fam_dir->name, scf->dir_name);

		fam_dir->version = 1;

		fam_dir->req = calloc(1, sizeof(FAMRequest));
		force_assert(NULL != fam_dir);

		if (0 != FAMMonitorDirectory(&scf->fam, fam_dir->name->ptr,
					     fam_dir->req, fam_dir)) {

			log_error_write(srv, __FILE__, __LINE__, "sbsbs",
					"monitoring dir failed:",
					fam_dir->name,
					"file:", name,
					FamErrlist[FAMErrno]);

			fam_dir_entry_free(&scf->fam, fam_dir);
			fam_dir = NULL;
		} else {
			int osize = splaytree_size(scf->dirs);

			/* already splayed scf->dir_ndx */
			if ((NULL != scf->dirs) && (scf->dirs->key == scf->dir_ndx)) {
				/* hash collision: replace old entry */
				fam_dir_entry_free(&scf->fam, scf->dirs->data);
				scf->dirs->data = fam_dir;
			} else {
				scf->dirs = splaytree_insert(scf->dirs, scf->dir_ndx, fam_dir);
				force_assert(osize == (splaytree_size(scf->dirs) - 1));
			}

			force_assert(scf->dirs);
			force_assert(scf->dirs->data == fam_dir);
			scf->fam_dir = fam_dir;
		}
	}

	/* bind the fam_fc to the stat() cache entry */

	if (fam_dir) {
		sce->dir_version = fam_dir->version;
	}
}

#endif


stat_cache *stat_cache_init(server *srv) {
	stat_cache *sc = NULL;
	UNUSED(srv);

	sc = calloc(1, sizeof(*sc));
	force_assert(NULL != sc);

#ifdef HAVE_FAM_H
	if (STAT_CACHE_ENGINE_FAM == srv->srvconf.stat_cache_engine) {
		sc->scf = stat_cache_init_fam(srv);
		if (NULL == sc->scf) {
			free(sc);
			return NULL;
		}
	}
#endif

	return sc;
}

static stat_cache_entry * stat_cache_entry_init(void) {
	stat_cache_entry *sce = NULL;

	sce = calloc(1, sizeof(*sce));
	force_assert(NULL != sce);

	sce->name = buffer_init();
	sce->etag = buffer_init();
	sce->content_type = buffer_init();

	return sce;
}

static void stat_cache_entry_free(void *data) {
	stat_cache_entry *sce = data;
	if (!sce) return;

	buffer_free(sce->etag);
	buffer_free(sce->name);
	buffer_free(sce->content_type);

	free(sce);
}

void stat_cache_free(stat_cache *sc) {
	while (sc->files) {
		int osize;
		splay_tree *node = sc->files;

		osize = sc->files->size;

		stat_cache_entry_free(node->data);
		sc->files = splaytree_delete(sc->files, node->key);

		force_assert(osize - 1 == splaytree_size(sc->files));
	}

#ifdef HAVE_FAM_H
	stat_cache_free_fam(sc->scf);
#endif
	free(sc);
}

int stat_cache_choose_engine (server *srv, const buffer *stat_cache_string) {
	if (buffer_string_is_empty(stat_cache_string)) {
		srv->srvconf.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE;
	} else if (buffer_is_equal_string(stat_cache_string, CONST_STR_LEN("simple"))) {
		srv->srvconf.stat_cache_engine = STAT_CACHE_ENGINE_SIMPLE;
#ifdef HAVE_FAM_H
	} else if (buffer_is_equal_string(stat_cache_string, CONST_STR_LEN("fam"))) {
		srv->srvconf.stat_cache_engine = STAT_CACHE_ENGINE_FAM;
#endif
	} else if (buffer_is_equal_string(stat_cache_string, CONST_STR_LEN("disable"))) {
		srv->srvconf.stat_cache_engine = STAT_CACHE_ENGINE_NONE;
	} else {
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"server.stat-cache-engine can be one of \"disable\", \"simple\","
#ifdef HAVE_FAM_H
				" \"fam\","
#endif
				" but not:", stat_cache_string);
		return -1;
	}
	return 0;
}

#if defined(HAVE_XATTR)
static int stat_cache_attr_get(buffer *buf, char *name, char *xattrname) {
	int attrlen;
	int ret;

	buffer_string_prepare_copy(buf, 1023);
	attrlen = buf->size - 1;
	if(0 == (ret = attr_get(name, xattrname, buf->ptr, &attrlen, 0))) {
		buffer_commit(buf, attrlen);
	}
	return ret;
}
#elif defined(HAVE_EXTATTR)
static int stat_cache_attr_get(buffer *buf, char *name, char *xattrname) {
	ssize_t attrlen;

	buffer_string_prepare_copy(buf, 1023);

	if (-1 != (attrlen = extattr_get_file(name, EXTATTR_NAMESPACE_USER, xattrname, buf->ptr, buf->size - 1))) {
		buf->used = attrlen + 1;
		buf->ptr[attrlen] = '\0';
		return 0;
	}
	return -1;
}
#endif

const buffer * stat_cache_mimetype_by_ext(const connection *con, const char *name, size_t nlen)
{
    const char *end = name + nlen; /*(end of string)*/
    const size_t used = con->conf.mimetypes->used;
    if (used < 16) {
        for (size_t i = 0; i < used; ++i) {
            /* suffix match */
            const data_string *ds = (data_string *)con->conf.mimetypes->data[i];
            const size_t klen = buffer_string_length(ds->key);
            if (klen <= nlen && 0 == strncasecmp(end-klen, ds->key->ptr, klen))
                return ds->value;
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
        ds = (data_string *)array_get_element_klen(con->conf.mimetypes, s, end - s);
        if (NULL != ds) return ds->value;
        while (++s < end) {
            while (*s != '.' && ++s != end) ;
            if (s == end) break;
            /* search ".ext" then "ext" */
            ds = (data_string *)array_get_element_klen(con->conf.mimetypes, s, end - s);
            if (NULL != ds) return ds->value;
            /* repeat search without leading '.' to handle situation where
             * admin configured mimetype.assign keys without leading '.' */
            if (++s < end) {
                if (*s == '.') { --s; continue; }
                ds = (data_string *)array_get_element_klen(con->conf.mimetypes, s, end - s);
                if (NULL != ds) return ds->value;
            }
        }
        /* search for ""; catchall */
        ds = (data_string *)array_get_element(con->conf.mimetypes, "");
        if (NULL != ds) return ds->value;
    }

    return NULL;
}

const buffer * stat_cache_content_type_get(server *srv, connection *con, const buffer *name, stat_cache_entry *sce)
{
    /*(invalid caching if user config has multiple, different
     * con->conf.mimetypes for same extension (not expected))*/
    if (!buffer_string_is_empty(sce->content_type)) return sce->content_type;

    if (S_ISREG(sce->st.st_mode)) {
        /* determine mimetype */
        buffer_clear(sce->content_type);
      #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
        if (con->conf.use_xattr) {
            stat_cache_attr_get(sce->content_type, name->ptr, srv->srvconf.xattr_name->ptr);
        }
      #else
        UNUSED(srv);
      #endif
        /* xattr did not set a content-type. ask the config */
        if (buffer_string_is_empty(sce->content_type)) {
            const buffer *type = stat_cache_mimetype_by_ext(con, CONST_BUF_LEN(name));
            if (NULL != type) {
                buffer_copy_buffer(sce->content_type, type);
            }
        }
        return sce->content_type;
    }

    return NULL;
}

const buffer * stat_cache_etag_get(stat_cache_entry *sce, etag_flags_t flags) {
    /*(invalid caching if user config has multiple, different con->etag_flags
     * for same path (not expected, since etag flags should be by filesystem))*/
    if (!buffer_string_is_empty(sce->etag)) return sce->etag;

    if (S_ISREG(sce->st.st_mode) || S_ISDIR(sce->st.st_mode)) {
        etag_create(sce->etag, &sce->st, flags);
        return sce->etag;
    }

    return NULL;
}


/***
 *
 *
 *
 * returns:
 *  - HANDLER_FINISHED on cache-miss (don't forget to reopen the file)
 *  - HANDLER_ERROR on stat() failed -> see errno for problem
 */

handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **ret_sce) {
	stat_cache_entry *sce = NULL;
	stat_cache *sc;
	struct stat st;
	int fd;
	const int follow_symlink = con->conf.follow_symlink;
	int file_ndx;

	*ret_sce = NULL;

	/*
	 * check if the directory for this file has changed
	 */

	sc = srv->stat_cache;

	file_ndx = hashme(name->ptr, follow_symlink);
	sc->files = splaytree_splay(sc->files, file_ndx);

	if (sc->files && (sc->files->key == file_ndx)) {
		/* we have seen this file already and
		 * don't stat() it again in the same second */

		sce = sc->files->data;

		/* check if the name is the same, we might have a collision */

		if (buffer_is_equal(name, sce->name)) {
			if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_SIMPLE) {
				if (sce->stat_ts == srv->cur_ts && follow_symlink) {
					*ret_sce = sce;
					return HANDLER_GO_ON;
				}
			}
		} else {
			/* collision, forget about the entry */
			sce = NULL;
		}
	}

#ifdef HAVE_FAM_H
	/* dir-check */
	if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
		switch (stat_cache_fam_dir_check(srv, sc->scf, sce, name, follow_symlink)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
			*ret_sce = sce;
			return HANDLER_GO_ON;
		case HANDLER_ERROR:
		default:
			return HANDLER_ERROR;
		}
	}
#endif

	/*
	 * *lol*
	 * - open() + fstat() on a named-pipe results in a (intended) hang.
	 * - stat() if regular file + open() to see if we can read from it is better
	 *
	 * */
	if (-1 == stat(name->ptr, &st)) {
		return HANDLER_ERROR;
	}


	if (S_ISREG(st.st_mode)) {
		/* fix broken stat/open for symlinks to reg files with appended slash on freebsd,osx */
		if (name->ptr[buffer_string_length(name) - 1] == '/') {
			errno = ENOTDIR;
			return HANDLER_ERROR;
		}

		/* try to open the file to check if we can read it */
	      #ifdef O_NONBLOCK
		fd = open(name->ptr, O_RDONLY | O_NONBLOCK, 0);
	      #else
		fd = open(name->ptr, O_RDONLY, 0);
	      #endif
		if (-1 == fd) {
			return HANDLER_ERROR;
		}
		close(fd);
	}

	if (NULL == sce) {

		sce = stat_cache_entry_init();
		buffer_copy_buffer(sce->name, name);

		/* already splayed file_ndx */
		if ((NULL != sc->files) && (sc->files->key == file_ndx)) {
			/* hash collision: replace old entry */
			stat_cache_entry_free(sc->files->data);
			sc->files->data = sce;
		} else {
			int osize = splaytree_size(sc->files);

			sc->files = splaytree_insert(sc->files, file_ndx, sce);
			force_assert(osize + 1 == splaytree_size(sc->files));
		}
		force_assert(sc->files);
		force_assert(sc->files->data == sce);

	} else {

		buffer_clear(sce->etag);
	      #if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
		buffer_clear(sce->content_type);
	      #endif

	}

	sce->st = st;
	sce->stat_ts = srv->cur_ts;

#ifdef HAVE_FAM_H
	if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
		stat_cache_fam_dir_monitor(srv, sc->scf, sce, name);
	}
#endif

	*ret_sce = sce;

	return HANDLER_GO_ON;
}

int stat_cache_path_contains_symlink(server *srv, buffer *name) {
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
            log_error_write(srv, __FILE__, __LINE__, "sss",
                            "lstat failed for:", buf, strerror(errno));
            return -1;
        }
    } while ((s_cur = strrchr(buf, '/')) != buf);
  #endif

    return 0;
}

int stat_cache_open_rdonly_fstat (buffer *name, struct stat *st, int symlinks) {
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
 * remove stat() from cache which havn't been stat()ed for
 * more than 10 seconds
 *
 *
 * walk though the stat-cache, collect the ids which are too old
 * and remove them in a second loop
 */

static int stat_cache_tag_old_entries(server *srv, splay_tree *t, int *keys, size_t *ndx) {
	stat_cache_entry *sce;

	if (!t) return 0;

	stat_cache_tag_old_entries(srv, t->left, keys, ndx);
	stat_cache_tag_old_entries(srv, t->right, keys, ndx);

	sce = t->data;

	if (srv->cur_ts - sce->stat_ts > 2) {
		keys[(*ndx)++] = t->key;
	}

	return 0;
}

int stat_cache_trigger_cleanup(server *srv) {
	stat_cache *sc;
	size_t max_ndx = 0, i;
	int *keys;

	sc = srv->stat_cache;

	if (!sc->files) return 0;

	keys = calloc(1, sizeof(int) * sc->files->size);
	force_assert(NULL != keys);

	stat_cache_tag_old_entries(srv, sc->files, keys, &max_ndx);

	for (i = 0; i < max_ndx; i++) {
		int ndx = keys[i];
		splay_tree *node;

		sc->files = splaytree_splay(sc->files, ndx);

		node = sc->files;

		if (node && (node->key == ndx)) {
			stat_cache_entry_free(node->data);
			sc->files = splaytree_delete(sc->files, ndx);
		}
	}

	free(keys);

	return 0;
}
