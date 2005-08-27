#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include "log.h"
#include "stat_cache.h"
#include "fdevent.h"
#include "etag.h"

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
#endif

#ifdef HAVE_FAM_H
# include <fam.h>
#endif

#include "sys-mmap.h"

/* NetBSD 1.3.x needs it */
#ifndef MAP_FAILED
# define MAP_FAILED -1
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

#ifndef HAVE_LSTAT
#define lstat stat
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

#ifdef HAVE_FAM_H
typedef struct {
	FAMRequest *req;
	FAMConnection *fc;
	
	buffer *name;

	int version;
} fam_dir_entry;
#endif

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

stat_cache *stat_cache_init(void) {
	stat_cache *fc = NULL;
	
	fc = calloc(1, sizeof(*fc));
	
	fc->dir_name = buffer_init();
#ifdef HAVE_FAM_H
	fc->fam = calloc(1, sizeof(*fc->fam));

	if (0 != FAMOpen2(fc->fam, "lighttpd")) {
		return NULL;
	}
#ifdef HAVE_FAMNOEXISTS
	FAMNoExists(fc->fam);
#endif
#endif

	return fc;
}

static stat_cache_entry * stat_cache_entry_init(void) {
	stat_cache_entry *sce = NULL;
	
	sce = calloc(1, sizeof(*sce));
	
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

static void splaytree_delete_tree(splay_tree *t, void (*data_free)(void *)) {
	if (!t) return;

	splaytree_delete_tree(t->left, data_free);
	splaytree_delete_tree(t->right, data_free);

	if (data_free) {
		data_free(t->data);
	}

	free(t);
}

#ifdef HAVE_FAM_H
static fam_dir_entry * fam_dir_entry_init(void) {
	fam_dir_entry *fam_dir = NULL;

	fam_dir = calloc(1, sizeof(*fam_dir));
	
	fam_dir->name = buffer_init();
	
	return fam_dir;
}

static void fam_dir_entry_free(void *data) {
	fam_dir_entry *fam_dir = data;
	
	if (!fam_dir) return;
	
	FAMCancelMonitor(fam_dir->fc, fam_dir->req);
	
	buffer_free(fam_dir->name);
	free(fam_dir->req);
	
	free(fam_dir);
}
#endif

void stat_cache_free(stat_cache *fc) {
	splaytree_delete_tree(fc->files, stat_cache_entry_free);
	
	buffer_free(fc->dir_name);

#ifdef HAVE_FAM_H
	splaytree_delete_tree(fc->dirs, fam_dir_entry_free);

	if (fc->fam) {
		FAMClose(fc->fam);
		free(fc->fam);
	}
#endif
	free(fc);
}

#ifdef HAVE_XATTR
static int stat_cache_attr_get(buffer *buf, char *name) {
	int attrlen;
	int ret;
	
	attrlen = 1024;
	buffer_prepare_copy(buf, attrlen);
	attrlen--;
	if(0 == (ret = attr_get(name, "Content-Type", buf->ptr, &attrlen, 0))) {
		buf->used = attrlen + 1;
		buf->ptr[attrlen] = '\0';
	}
	return ret;
}
#endif

static int hashme(buffer *str) {
	int hash = 0;
	const char *s;
	for (s = str->ptr; *s; s++) {
		hash = hash * 53 + *s;
	}

	return hash;
}

#ifdef HAVE_FAM_H
handler_t stat_cache_handle_fdevent(void *_srv, void *_fce, int revent) {
	size_t i;
	server *srv = _srv;
	stat_cache *sc = srv->stat_cache;
	size_t events;


	UNUSED(revent);
	/* */

	if ((revent & FDEVENT_IN) &&
	    sc->fam) {

		events = FAMPending(sc->fam);
	
		for (i = 0; i < events; i++) {
			FAMEvent fe;
			fam_dir_entry *fam_dir;
			splay_tree *node;
			int ndx;
		
			FAMNextEvent(sc->fam, &fe);
	
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

				buffer_copy_string(sc->dir_name, fe.filename);

				ndx = hashme(sc->dir_name);

				sc->dirs = splaytree_splay(sc->dirs, ndx);
				node = sc->dirs;
			
				if (node && (node->key == ndx)) {
					fam_dir_entry_free(node->data);
					sc->dirs = splaytree_delete(sc->dirs, ndx);
				}
				break;
			default:
				break;
			}
		}
	}

	if (revent & FDEVENT_HUP) {
		/* fam closed the connection */
		srv->stat_cache->fam_fcce_ndx = -1;

		fdevent_event_del(srv->ev, &(sc->fam_fcce_ndx), FAMCONNECTION_GETFD(sc->fam));
		fdevent_unregister(srv->ev, FAMCONNECTION_GETFD(sc->fam));

		FAMClose(sc->fam);
		free(sc->fam);

		sc->fam = NULL;
	}
	
	return HANDLER_GO_ON;
}

static int buffer_copy_dirname(buffer *dst, buffer *file) {
	size_t i;

	if (buffer_is_empty(file)) return -1;

	for (i = file->used - 1; i+1 > 0; i--) {
		if (file->ptr[i] == '/') {
			buffer_copy_string_len(dst, file->ptr, i);
			return 0;
		}
	}

	return -1;
}
#endif

/***
 *
 *
 *
 * returns: 
 *  - HANDLER_FINISHED on cache-miss (don't forget to reopen the file)
 *  - HANDLER_ERROR on stat() failed -> see errno for problem
 */

handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **ret_sce) {
#ifdef HAVE_FAM_H
	fam_dir_entry *fam_dir = NULL;
	int dir_ndx = -1;
	splay_tree *dir_node = NULL;
#endif
	stat_cache_entry *sce = NULL;
	stat_cache *sc;
	struct stat st;

	int file_ndx;
	splay_tree *file_node = NULL;

	*ret_sce = NULL; 

	/* 
	 * check if the directory for this file has changed
	 */

	sc = srv->stat_cache;

	file_ndx = hashme(name);
	sc->files = splaytree_splay(sc->files, file_ndx);

	if (sc->files && (sc->files->key == file_ndx)) {
		/* we have seen this file already and 
		 * don't stat() it again in the same second */

		file_node = sc->files;
		
		sce = file_node->data;

		if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_SIMPLE) {
			if (sce->stat_ts == srv->cur_ts) {
				*ret_sce = sce; 
				return HANDLER_GO_ON;
			}
		}
	}

#ifdef HAVE_FAM_H
	/* dir-check */
	if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
		if (0 != buffer_copy_dirname(sc->dir_name, name)) {
			SEGFAULT();
		}

		dir_ndx = hashme(sc->dir_name);
		
		sc->dirs = splaytree_splay(sc->dirs, dir_ndx);
		
		if (sc->dirs && (sc->dirs->key == dir_ndx)) {
			dir_node = sc->dirs;
		}
		
		if (dir_node && file_node) {
			/* we found a file */
			
			sce = file_node->data;
			fam_dir = dir_node->data;
			
			if (fam_dir->version == sce->dir_version) {
				/* the stat()-cache entry is still ok */
				
				*ret_sce = sce; 
				return HANDLER_GO_ON;
			}
		}
	}
#endif
	if (-1 == (con->conf.follow_symlink ? stat(name->ptr, &st) : lstat(name->ptr, &st))) {
		/* stat() failed, ENOENT, ... and so on */
		return HANDLER_ERROR;
	}
	
	if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
		size_t k;
	
		if (NULL == sce) {
			sce = stat_cache_entry_init();
			buffer_copy_string_buffer(sce->name, name);
			
			sc->files = splaytree_insert(sc->files, file_ndx, sce); 
		}

		sce->st = st;
		sce->stat_ts = srv->cur_ts;

		if (S_ISREG(st.st_mode)) {	
			/* determine mimetype */
			buffer_reset(sce->content_type);
		
			for (k = 0; k < con->conf.mimetypes->used; k++) {
				data_string *ds = (data_string *)con->conf.mimetypes->data[k];
				buffer *type = ds->key;
			
				if (type->used == 0) continue;

				/* check if the right side is the same */
				if (type->used > name->used) continue;

				if (0 == strncasecmp(name->ptr + name->used - type->used, type->ptr, type->used - 1)) {
					buffer_copy_string_buffer(sce->content_type, ds->value);
					break;
				}
			}
			etag_create(sce->etag, &(sce->st));
#ifdef HAVE_XATTR
			if (buffer_is_empty(sce->content_type)) {
				stat_cache_attr_get(sce->content_type, name->ptr);
			}
#endif
		}
		
#ifdef HAVE_FAM_H
		if (sc->fam &&
		    (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM)) {
			/* is this directory already registered ? */
			if (!dir_node) {
				fam_dir = fam_dir_entry_init();
				fam_dir->fc = sc->fam;
				
				buffer_copy_string_buffer(fam_dir->name, sc->dir_name);
				
				fam_dir->version = 1;
				
				fam_dir->req = calloc(1, sizeof(FAMRequest));
				
				if (0 != FAMMonitorDirectory(sc->fam, fam_dir->name->ptr, 
							     fam_dir->req, fam_dir)) {
					
					log_error_write(srv, __FILE__, __LINE__, "sbs", 
							"monitoring dir failed:", 
							fam_dir->name, 
							FamErrlist[FAMErrno]);
					
					fam_dir_entry_free(fam_dir);
				} else {
					sc->dirs = splaytree_insert(sc->dirs, dir_ndx, fam_dir); 
				}
			} else {
				fam_dir = dir_node->data;
			}
			
			/* bind the fam_fc to the stat() cache entry */
			
			if (fam_dir) {
				sce->dir_version = fam_dir->version;
				sce->dir_ndx     = dir_ndx;
			}
		}
#endif
	}
	*ret_sce = sce;

	return HANDLER_GO_ON;
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

	if (srv->cur_ts - sce->stat_ts > 10) {
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

	keys = calloc(1, sizeof(size_t) * sc->files->size);

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
