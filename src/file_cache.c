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
#include "file_cache.h"
#include "fdevent.h"
#include "etag.h"

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
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

/* don't enable the dir-cache 
 * 
 * F_NOTIFY would be nice but only works with linux-rtsig
 */
#undef USE_LINUX_SIGIO

file_cache *file_cache_init(void) {
	file_cache *fc = NULL;
	
	fc = calloc(1, sizeof(*fc));
	
	fc->dir_name = buffer_init();
	
	return fc;
}

static file_cache_entry * file_cache_entry_init(void) {
	file_cache_entry *fce = NULL;
	
	fce = calloc(1, sizeof(*fce));
	
	fce->fd = -1;
	fce->fde_ndx = -1;
	fce->name = buffer_init();
	fce->etag = buffer_init();
	fce->content_type = buffer_init();
	
	return fce;
}

static void file_cache_entry_free(server *srv, file_cache_entry *fce) {
	if (!fce) return;
	
	if (fce->fd >= 0) {
		close(fce->fd);
		srv->cur_fds--;
	}
	
	buffer_free(fce->etag);
	buffer_free(fce->name);
	buffer_free(fce->content_type);
	
	if (fce->mmap_p) munmap(fce->mmap_p, fce->mmap_length);
	
	free(fce);
}

static int file_cache_entry_reset(server *srv, file_cache_entry *fce) {
	if (fce->fd < 0) return 0;
	
	close(fce->fd);
	srv->cur_fds--;
			
#ifdef USE_LINUX_SIGIO
	/* doesn't work anymore */
	if (fce->fde_ndx != -1) {
		fdevent_event_del(srv->ev, &(fce->fde_ndx), fce->fd);
	}
#else 
	UNUSED(srv);
#endif
	
	if (fce->mmap_p) {
		munmap(fce->mmap_p, fce->mmap_length); 
		fce->mmap_p = NULL;
	}
	fce->fd = -1;
	
	buffer_reset(fce->etag);
	buffer_reset(fce->name);
	buffer_reset(fce->content_type);
	
	return 0;
}

void file_cache_free(server *srv, file_cache *fc) {
	size_t i;
	for (i = 0; i < fc->used; i++) {
		file_cache_entry_free(srv, fc->ptr[i]);
	}
	
	free(fc->ptr);
	
	buffer_free(fc->dir_name);
	
	free(fc);
	
}

#ifdef HAVE_XATTR
int fce_attr_get(buffer *buf, char *name) {
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

file_cache_entry * file_cache_get_unused_entry(server *srv) {
	file_cache_entry *fce = NULL;
	file_cache *fc = srv->file_cache;
	size_t i;
	
	if (fc->size == 0) {
		fc->size = 16;
		fc->ptr = calloc(fc->size, sizeof(*fc->ptr));
		fc->used = 0;
	}
	for (i = 0; i < fc->used; i++) {
		file_cache_entry *f = fc->ptr[i];

		if (f->fd == -1) {
			return f;
		}
	}
	
	if (fc->used < fc->size) {
		fce = file_cache_entry_init();
		fc->ptr[fc->used++] = fce;
	} else {
		/* the cache is full, time to resize */
		
		fc->size += 16;
		fc->ptr = realloc(fc->ptr, sizeof(*fc->ptr) * fc->size);
		
		fce = file_cache_entry_init();
		fc->ptr[fc->used++] = fce;
	}
	
	return fce;
}

handler_t file_cache_handle_fdevent(void *_srv, void *_fce, int revent) {
	size_t i;
	server *srv = _srv;
	file_cache_entry *fce = _fce;
	file_cache *fc = srv->file_cache;;

	UNUSED(revent);
	/* */
#if 0	
	log_error_write(srv, __FILE__, __LINE__, "sds", "dir has changed: ", fce->fd, fce->name->ptr);
#endif	
	/* touch all files below this directory */
	
	for (i = 0; i < fc->used; i++) {
		file_cache_entry *f = fc->ptr[i];
		
		if (fce == f) continue;
		
		if (0 == strncmp(fce->name->ptr, f->name->ptr, fce->name->used - 1)) {
#if 0
			log_error_write(srv, __FILE__, __LINE__, "ss", "file hit: ", f->name->ptr);
#endif
			f->is_dirty = 1;
		}
	}
	
	return HANDLER_GO_ON;
}


#if 0
/* dead code, might be reused somewhere again */

int file_cache_check_cache() {
	file_cache_entry *first_unused_fce = NULL;
	file_cache *fc = srv->file_cache;
	size_t i;
	
	/* check the cache */
	for (i = 0; i < fc->used; i++) {
		fce = fc->ptr[i];
		
		if (buffer_is_equal(name, fce->name)) {
			log_error_write(srv, __FILE__, __LINE__, "sb", "cache hit:", name);

#ifdef USE_LINUX_SIGIO
			if (fce->is_dirty == 0) {
				fce->in_use++;
				return fce;
			}
#endif
			
			/* get the etag information */
			if (-1 == (stat(name->ptr, &(fce->st)))) {
				fce->in_use = 0;
				
				log_error_write(srv, __FILE__, __LINE__, "sbs", "stat failed: ", name, strerror(errno));
				
				file_cache_entry_reset(srv, fce);
				
				return NULL;
			}
			fce->stat_ts = srv->cur_ts;
			
			/* create etag */
			etag_create(srv->file_cache_etag, &(fce->st));
			
			if (!buffer_is_equal(srv->file_cache_etag, fce->etag)) {
				size_t s_len = 0, k;
				/* etag has changed: reopen file */
				
				file_cache_entry_reset(srv, fce);
				
				if (-1 == (fce->fd = open(fce->name->ptr, O_RDONLY | O_LARGEFILE))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));
					
					buffer_reset(fce->name);
					return NULL;
				}
				
				srv->cur_fds++;
			
				buffer_copy_string_buffer(fce->etag, srv->file_cache_etag);
			
				/* determine mimetype */
				buffer_reset(fce->content_type);
		
				s_len = name->used - 1;
		
				for (k = 0; k < con->conf.mimetypes->used; k++) {
					data_string *ds = (data_string *)con->conf.mimetypes->data[k];
					size_t ct_len;
					
					ct_len = ds->key->used - 1;
					
					if (buffer_is_equal_right_len(name, ds->key, ct_len)) {
						buffer_copy_string_buffer(fce->content_type, ds->value);
						break;
					}
				}
			
#ifdef HAVE_XATTR
				if (buffer_is_empty(fce->content_type)) {
					fce_attr_get(fce->content_type, name->ptr);
				}
#endif
			}
			
#ifdef USE_LINUX_SIGIO
			fce->is_dirty = 0;
#endif
			
			fce->in_use++;

	if (fce->fd == -1) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "fd is still -1 !", fce->name);
	}
	if (fce->st.st_size == 0) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "size is still 0 !", fce->name);
	}




			return fce;
		}
		
		if (fce->in_use == 0) {
			if (!first_unused_fce) first_unused_fce = fce;
			
			if (srv->cur_ts - fce->stat_ts > 10) {
				file_cache_entry_reset(srv, fce);
			}
		}
	}
	
	if (first_unused_fce) {
		file_cache_entry_reset(srv, fce);
		
		fce = first_unused_fce;
	} else {
		/* not found, insert */
		fce = file_cache_get_unused_entry(srv);
	}
}
#endif


handler_t file_cache_get_entry(server *srv, connection *con, buffer *name, file_cache_entry **o_fce_ptr) {
	file_cache_entry *fce = NULL;
	file_cache_entry *o_fce = *o_fce_ptr;
	
	
	UNUSED(con);
	
	/* still valid ? */
	if (o_fce != NULL) {
		if (buffer_is_equal(name, o_fce->name) &&
		    (o_fce->fd != -1) &&
		    (o_fce->stat_ts == srv->cur_ts)
		    ) {
			return HANDLER_GO_ON;
		} else {
			o_fce->in_use--;
		}
		file_cache_entry_reset(srv, o_fce);
	}


	fce = file_cache_get_unused_entry(srv);
	
	buffer_copy_string_buffer(fce->name, name);
	fce->in_use = 0;
	fce->fd = -1;
	
	if (-1 == (con->conf.follow_symlink ? stat(name->ptr, &(fce->st)) : lstat(name->ptr, &(fce->st)))) {
		int oerrno = errno;
#if 0
		log_error_write(srv, __FILE__, __LINE__, "sbs", "stat failed:", name, strerror(errno));
#endif
		file_cache_entry_reset(srv, fce);
		
		buffer_reset(fce->name);
		
		errno = oerrno;
		return HANDLER_ERROR;
	}
	
	fce->stat_ts = srv->cur_ts;
	
	if (S_ISREG(fce->st.st_mode)) {
		size_t k, s_len;
#ifdef USE_LINUX_SIGIO		
		file_cache_entry *dir_fce;
		char *slash;
#endif
		
		if (-1 == (fce->fd = open(name->ptr, O_RDONLY | O_LARGEFILE))) {
			int oerrno = errno;
			if (errno == EMFILE || errno == EINTR) {
				return HANDLER_WAIT_FOR_FD;
			}
			
			log_error_write(srv, __FILE__, __LINE__, "sbs", 
					"open failed for:", name, 
					strerror(errno));
			
			buffer_reset(fce->name);
			
			errno = oerrno;
			return HANDLER_ERROR;
		}
		
		srv->cur_fds++;
		
		/* determine mimetype */
		buffer_reset(fce->content_type);
		
		s_len = name->used - 1;
		
		for (k = 0; k < con->conf.mimetypes->used; k++) {
			data_string *ds = (data_string *)con->conf.mimetypes->data[k];
			size_t ct_len;
			
			if (ds->key->used == 0) continue;
			
			ct_len = ds->key->used - 1;
			
			if (s_len < ct_len) continue;
			
			if (0 == strncmp(name->ptr + s_len - ct_len, ds->key->ptr, ct_len)) {
				buffer_copy_string_buffer(fce->content_type, ds->value);
				break;
			}
		}
		
#ifdef HAVE_XATTR
		if (buffer_is_empty(fce->content_type)) {
			fce_attr_get(fce->content_type, name->ptr);
		}
#endif
		
		etag_create(fce->etag, &(fce->st));
		
#ifdef USE_LINUX_SIGIO
		/* register sigio for the directory */
		dir_fce = file_cache_get_unused_entry(srv);
		
		buffer_copy_string_buffer(fc->dir_name, name);
		
		/* get dirname */
		if (0 == (slash = strrchr(fc->dir_name->ptr, '/'))) {
			SEGFAULT();
		}
		*(slash+1) = '\0';
		
		if (-1 == (dir_fce->fd = open(fc->dir_name->ptr, O_RDONLY))) {
			int oerrno = errno;
			log_error_write(srv, __FILE__, __LINE__, "sbs", 
					"open failed:", fc->dir_name, strerror(errno));
			
			errno = oerrno;
			return HANDLER_ERROR;
		}
		
		srv->cur_fds++;
		
		if (fcntl(dir_fce->fd, F_NOTIFY, DN_CREATE|DN_DELETE|DN_MODIFY|DN_MULTISHOT) < 0) {
			int oerrno = errno;
			log_error_write(srv, __FILE__, __LINE__, "ss", 
					"fcntl failed:", strerror(errno));
			
			close(dir_fce->fd);
			srv->cur_fds--;
			
			errno = oerrno;
			return HANDLER_ERROR;
		}
		
		/* ->used is not updated -> no _buffer copy */
		buffer_copy_string(dir_fce->name, fc->dir_name->ptr);
		
		/* register fd-handler */
		fdevent_register(srv->ev, dir_fce->fd, file_cache_handle_fdevent, dir_fce);
		fdevent_event_add(srv->ev, &(dir_fce->fde_ndx), dir_fce->fd, FDEVENT_IN);
# if 1	
		log_error_write(srv, __FILE__, __LINE__, "sddb", "fdevent_event_add:", fce->fde_ndx, fce->fd, fce->name);
# endif
#endif
	}

	fce->in_use++;
	
	*o_fce_ptr = fce;
	
	return HANDLER_GO_ON;
}

int file_cache_entry_release(server *srv, connection *con, file_cache_entry *fce) {
	UNUSED(srv);
	UNUSED(con);

	if (fce->in_use > 0) fce->in_use--;
	file_cache_entry_reset(srv, fce);
	
	return 0;
}

