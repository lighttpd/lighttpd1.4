#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "response.h"

#include "plugin.h"

#include "crc32.h"

#include "config.h"

#if defined HAVE_ZLIB_H && defined HAVE_LIBZ
# define USE_ZLIB
# include <zlib.h>
#endif

#if defined HAVE_BZLIB_H && defined HAVE_LIBBZ2
# define USE_BZ2LIB
/* we don't need stdio interface */
# define BZ_NO_STDIO
# include <bzlib.h>
#endif

#include "sys-mmap.h"

/* request: accept-encoding */
#define HTTP_ACCEPT_ENCODING_IDENTITY BV(0)
#define HTTP_ACCEPT_ENCODING_GZIP     BV(1)
#define HTTP_ACCEPT_ENCODING_DEFLATE  BV(2)
#define HTTP_ACCEPT_ENCODING_COMPRESS BV(3)
#define HTTP_ACCEPT_ENCODING_BZIP2    BV(4)

#ifdef __WIN32
#define mkdir(x,y) mkdir(x)
#endif

typedef struct {
	buffer *compress_cache_dir;
	array  *compress;
	off_t   compress_max_filesize; /** max filesize in kb */
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	buffer *ofn;
	buffer *b;
	
	plugin_config **config_storage;
	plugin_config conf; 
} plugin_data;

INIT_FUNC(mod_compress_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->ofn = buffer_init();
	p->b = buffer_init();
	
	return p;
}

FREE_FUNC(mod_compress_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	buffer_free(p->ofn);
	buffer_free(p->b);
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			array_free(s->compress);
			buffer_free(s->compress_cache_dir);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	
	free(p);
	
	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_compress_setdefaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ "compress.cache-dir",             NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "compress.filetype",              NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
		{ "compress.max-filesize",          NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
		{ NULL,                             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	p->config_storage = malloc(srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = malloc(sizeof(plugin_config));
		s->compress_cache_dir = buffer_init();
		s->compress = array_init();
		s->compress_max_filesize = 0;
		
		cv[0].destination = s->compress_cache_dir;
		cv[1].destination = s->compress;
		cv[2].destination = &(s->compress_max_filesize);
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
		
		if (!buffer_is_empty(s->compress_cache_dir)) {
			struct stat st;
			if (0 != stat(s->compress_cache_dir->ptr, &st)) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", "can't stat compress.cache-dir", 
						s->compress_cache_dir, strerror(errno));
				
				return HANDLER_ERROR;
			}
		}
	}
	
	return HANDLER_GO_ON;
	
}

#ifdef USE_ZLIB
static int deflate_file_to_buffer_gzip(server *srv, connection *con, plugin_data *p, char *start, off_t st_size, time_t mtime) {
	unsigned char *c;
	unsigned long crc;
	z_stream z;
		
	UNUSED(srv);
	UNUSED(con);

	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;
	
	if (Z_OK != deflateInit2(&z, 
				 Z_DEFAULT_COMPRESSION,
				 Z_DEFLATED, 
				 -MAX_WBITS,  /* supress zlib-header */
				 8,
				 Z_DEFAULT_STRATEGY)) {
		return -1;
	}
		
	z.next_in = (unsigned char *)start;
	z.avail_in = st_size;
	z.total_in = 0;
		
			
	buffer_prepare_copy(p->b, (z.avail_in * 1.1) + 12 + 18);
		
	/* write gzip header */
		
	c = (unsigned char *)p->b->ptr;
	c[0] = 0x1f;
	c[1] = 0x8b;
	c[2] = Z_DEFLATED;
	c[3] = 0; /* options */
	c[4] = (mtime >>  0) & 0xff;
	c[5] = (mtime >>  8) & 0xff;
	c[6] = (mtime >> 16) & 0xff;
	c[7] = (mtime >> 24) & 0xff;
	c[8] = 0x00; /* extra flags */
	c[9] = 0x03; /* UNIX */
	
	p->b->used = 10;
	z.next_out = (unsigned char *)p->b->ptr + p->b->used;
	z.avail_out = p->b->size - p->b->used - 8;
	z.total_out = 0;
	
	if (Z_STREAM_END != deflate(&z, Z_FINISH)) {
		deflateEnd(&z);
		return -1;
	}
	
	/* trailer */
	p->b->used += z.total_out;
	
	crc = generate_crc32c(start, st_size);
		
	c = (unsigned char *)p->b->ptr + p->b->used;
		
	c[0] = (crc >>  0) & 0xff;
	c[1] = (crc >>  8) & 0xff;
	c[2] = (crc >> 16) & 0xff;
	c[3] = (crc >> 24) & 0xff;
	c[4] = (z.total_in >>  0) & 0xff;
	c[5] = (z.total_in >>  8) & 0xff;
	c[6] = (z.total_in >> 16) & 0xff;
	c[7] = (z.total_in >> 24) & 0xff;
	p->b->used += 8;

	if (Z_OK != deflateEnd(&z)) {
		return -1;
	}
	
	return 0;
}

static int deflate_file_to_buffer_deflate(server *srv, connection *con, plugin_data *p, unsigned char *start, off_t st_size) {
	z_stream z;
	
	UNUSED(srv);
	UNUSED(con);

	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;
	
	if (Z_OK != deflateInit2(&z, 
				 Z_DEFAULT_COMPRESSION,
				 Z_DEFLATED, 
				 -MAX_WBITS,  /* supress zlib-header */
				 8,
				 Z_DEFAULT_STRATEGY)) {
		return -1;
	}
		
	z.next_in = start;
	z.avail_in = st_size;
	z.total_in = 0;
		
	buffer_prepare_copy(p->b, (z.avail_in * 1.1) + 12);
	
	z.next_out = (unsigned char *)p->b->ptr;
	z.avail_out = p->b->size;
	z.total_out = 0;
	
	if (Z_STREAM_END != deflate(&z, Z_FINISH)) {
		deflateEnd(&z);
		return -1;
	}
	
	/* trailer */
	p->b->used += z.total_out;
	
	if (Z_OK != deflateEnd(&z)) {
		return -1;
	}
	
	return 0;
}

#endif

#ifdef USE_BZ2LIB
static int deflate_file_to_buffer_bzip2(server *srv, connection *con, plugin_data *p, unsigned char *start, off_t st_size) {
	bz_stream bz;
	
	UNUSED(srv);
	UNUSED(con);

	bz.bzalloc = NULL;
	bz.bzfree = NULL;
	bz.opaque = NULL;
	
	if (BZ_OK != BZ2_bzCompressInit(&bz, 
					9, /* blocksize = 900k */
					0, /* no output */
					0)) { /* workFactor: default */
		return -1;
	}
		
	bz.next_in = (char *)start;
	bz.avail_in = st_size;
	bz.total_in_lo32 = 0;
	bz.total_in_hi32 = 0;
		
	buffer_prepare_copy(p->b, (bz.avail_in * 1.1) + 12);
	
	bz.next_out = p->b->ptr;
	bz.avail_out = p->b->size;
	bz.total_out_lo32 = 0;
	bz.total_out_hi32 = 0;
	
	if (BZ_STREAM_END != BZ2_bzCompress(&bz, BZ_FINISH)) {
		BZ2_bzCompressEnd(&bz);
		return -1;
	}
	
	/* file is too large for now */
	if (bz.total_out_hi32) return -1;
	
	/* trailer */
	p->b->used = bz.total_out_lo32;
	
	if (BZ_OK != BZ2_bzCompressEnd(&bz)) {
		return -1;
	}
	
	return 0;
}
#endif

static int deflate_file_to_file(server *srv, connection *con, plugin_data *p, buffer *fn, file_cache_entry *fce, int type) {
	int ifd, ofd;
	int ret = -1;
	void *start;
	const char *filename = fn->ptr;
	ssize_t r;
	
	/* overflow */
	if ((off_t)(fce->st.st_size * 1.1) < fce->st.st_size) return -1;
	
	/* don't mmap files > size_t 
	 * 
	 * we could use a sliding window, but currently there is no need for it
	 */
	
	if (fce->st.st_size > SIZE_MAX) return -1;
	
	buffer_reset(p->ofn);
	buffer_copy_string_buffer(p->ofn, p->conf.compress_cache_dir);
	BUFFER_APPEND_SLASH(p->ofn);
	
	if (0 == strncmp(con->physical.path->ptr, con->physical.doc_root->ptr, con->physical.doc_root->used-1)) {
		size_t offset = p->ofn->used - 1;
		char *dir, *nextdir;
		
		buffer_append_string(p->ofn, con->physical.path->ptr + con->physical.doc_root->used - 1);
		
		buffer_copy_string_buffer(p->b, p->ofn);
		
		/* mkdir -p ... */
		for (dir = p->b->ptr + offset; NULL != (nextdir = strchr(dir, '/')); dir = nextdir + 1) {
			*nextdir = '\0';
			
			if (-1 == mkdir(p->b->ptr, 0700)) {
				if (errno != EEXIST) {
					log_error_write(srv, __FILE__, __LINE__, "ssss", "creating cache-directory", p->b->ptr, "failed", strerror(errno));
					
					return -1;
				}
			}
			
			*nextdir = '/';
		}
	} else {
		buffer_append_string_buffer(p->ofn, con->uri.path);
	}
	
	switch(type) {
	case HTTP_ACCEPT_ENCODING_GZIP:
		buffer_append_string(p->ofn, "-gzip-");
		break;
	case HTTP_ACCEPT_ENCODING_DEFLATE:
		buffer_append_string(p->ofn, "-deflate-");
		break;
	case HTTP_ACCEPT_ENCODING_BZIP2:
		buffer_append_string(p->ofn, "-bzip2-");
		break;
	default:
		log_error_write(srv, __FILE__, __LINE__, "sd", "unknown compression type", type);
		return -1;
	}
	
	buffer_append_string_buffer(p->ofn, fce->etag);
	
	if (-1 == (ofd = open(p->ofn->ptr, O_WRONLY | O_CREAT | O_EXCL, 0600))) {
		if (errno == EEXIST) {
			/* cache-entry exists */
#if 0
			log_error_write(srv, __FILE__, __LINE__, "bs", p->ofn, "compress-cache hit");
#endif
			buffer_copy_string_buffer(con->physical.path, p->ofn);
			
			return 0;
		}
		
		log_error_write(srv, __FILE__, __LINE__, "sbss", "creating cachefile", p->ofn, "failed", strerror(errno));
		
		return -1;
	}
#if 0
	log_error_write(srv, __FILE__, __LINE__, "bs", p->ofn, "compress-cache miss");
#endif	
	if (-1 == (ifd = open(filename, O_RDONLY))) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "opening plain-file", fn, "failed", strerror(errno));
		
		close(ofd);
		
		return -1;
	}
	
	
	if (MAP_FAILED == (start = mmap(NULL, fce->st.st_size, PROT_READ, MAP_SHARED, ifd, 0))) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "mmaping", fn, "failed", strerror(errno));
		
		close(ofd);
		close(ifd);
		return -1;
	}
	
	switch(type) {
#ifdef USE_ZLIB
	case HTTP_ACCEPT_ENCODING_GZIP: 
		ret = deflate_file_to_buffer_gzip(srv, con, p, start, fce->st.st_size, fce->st.st_mtime);
		break;
	case HTTP_ACCEPT_ENCODING_DEFLATE: 
		ret = deflate_file_to_buffer_deflate(srv, con, p, start, fce->st.st_size);
		break;
#endif
#ifdef USE_BZ2LIB
	case HTTP_ACCEPT_ENCODING_BZIP2: 
		ret = deflate_file_to_buffer_bzip2(srv, con, p, start, fce->st.st_size);
		break;
#endif
	default:
		ret = -1;
		break;
	}
	
	if (-1 == (r = write(ofd, p->b->ptr, p->b->used))) {
		return -1;
	}
	
	if ((size_t)r != p->b->used) {
		
	}
		
	munmap(start, fce->st.st_size);
	close(ofd);
	close(ifd);
	
	if (ret != 0) return -1;
	
	buffer_copy_string_buffer(con->physical.path, p->ofn);
	
	return 0;
}

static int deflate_file_to_buffer(server *srv, connection *con, plugin_data *p, buffer *fn, file_cache_entry *fce, int type) {
	int ifd;
	int ret = -1;
	void *start;
	buffer *b;
	
	/* overflow */
	if ((off_t)(fce->st.st_size * 1.1) < fce->st.st_size) return -1;
	
	/* don't mmap files > size_t 
	 * 
	 * we could use a sliding window, but currently there is no need for it
	 */
	
	if (fce->st.st_size > SIZE_MAX) return -1;
	
	
	if (-1 == (ifd = open(fn->ptr, O_RDONLY))) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "opening plain-file", fn, "failed", strerror(errno));
		
		return -1;
	}
	
	
	if (MAP_FAILED == (start = mmap(NULL, fce->st.st_size, PROT_READ, MAP_SHARED, ifd, 0))) {
		log_error_write(srv, __FILE__, __LINE__, "sbss", "mmaping", fn, "failed", strerror(errno));
		
		close(ifd);
		return -1;
	}
	
	switch(type) {
#ifdef USE_ZLIB
	case HTTP_ACCEPT_ENCODING_GZIP: 
		ret = deflate_file_to_buffer_gzip(srv, con, p, start, fce->st.st_size, fce->st.st_mtime);
		break;
	case HTTP_ACCEPT_ENCODING_DEFLATE: 
		ret = deflate_file_to_buffer_deflate(srv, con, p, start, fce->st.st_size);
		break;
#endif
#ifdef USE_BZ2LIB
	case HTTP_ACCEPT_ENCODING_BZIP2: 
		ret = deflate_file_to_buffer_bzip2(srv, con, p, start, fce->st.st_size);
		break;
#endif
	default:
		ret = -1;
		break;
	}
		
	munmap(start, fce->st.st_size);
	close(ifd);
	
	if (ret != 0) return -1;
	
	chunkqueue_reset(con->write_queue);
	b = chunkqueue_get_append_buffer(con->write_queue);
	buffer_copy_memory(b, p->b->ptr, p->b->used);
	
	buffer_reset(con->physical.path);
	
	con->file_finished = 1;
	con->file_started  = 1;
	
	return 0;
}


#define PATCH(x) \
	p->conf.x = s->x;
static int mod_compress_patch_connection(server *srv, connection *con, plugin_data *p, const char *stage, size_t stage_len) {
	size_t i, j;
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		plugin_config *s = p->config_storage[i];
		
		/* not our stage */
		if (!buffer_is_equal_string(dc->comp_key, stage, stage_len)) continue;
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("compress.cache-dir"))) {
				PATCH(compress_cache_dir);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("compress.filetype"))) {
				PATCH(compress);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("compress.max-filesize"))) {
				PATCH(compress_max_filesize);
			}
		}
	}
	
	return 0;
}

static int mod_compress_setup_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	UNUSED(srv);
	UNUSED(con);
		
	PATCH(compress_cache_dir);
	PATCH(compress);
	PATCH(compress_max_filesize);
	
	return 0;
}
#undef PATCH

PHYSICALPATH_FUNC(mod_compress_physical) {
	plugin_data *p = p_d;
	data_string *content_ds;
	size_t m, i;
	off_t max_fsize;
	
	/* only GET and POST can get compressed */
	if (con->request.http_method != HTTP_METHOD_GET && 
	    con->request.http_method != HTTP_METHOD_POST) {
		return HANDLER_GO_ON;
	}
	
	mod_compress_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		mod_compress_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	
	max_fsize = p->conf.compress_max_filesize;
	
	/* don't compress files that are too large as we need to much time to handle them */
	if (max_fsize && (con->fce->st.st_size >> 10) > max_fsize) return HANDLER_GO_ON;
	
	if (NULL == (content_ds = (data_string *)array_get_element(con->response.headers, "Content-Type"))) {
		log_error_write(srv, __FILE__, __LINE__, "sbb", "Content-Type is not set for", con->physical.path, con->uri.path);
		
		return HANDLER_GO_ON;
	}
		
	/* check if mimetype is in compress-config */
	for (m = 0; m < p->conf.compress->used; m++) {
		data_string *compress_ds = (data_string *)p->conf.compress->data[m];
			
		if (!compress_ds) {
			log_error_write(srv, __FILE__, __LINE__, "sbb", "evil", con->physical.path, con->uri.path);
			
			return HANDLER_GO_ON;
		}
		
		if (buffer_is_equal(compress_ds->value, content_ds->value)) {
			/* mimetype found */
			data_string *ds;
				
			/* the response might change according to Accept-Encoding */
			response_header_insert(srv, con, CONST_STR_LEN("Vary"), CONST_STR_LEN("Accept-Encoding"));
				
			if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Accept-Encoding"))) {
				int accept_encoding = 0;
				char *value = ds->value->ptr;
				int srv_encodings = 0;
				int matched_encodings = 0;
				
				/* get client side support encodings */
				if (NULL != strstr(value, "gzip")) accept_encoding |= HTTP_ACCEPT_ENCODING_GZIP;
				if (NULL != strstr(value, "deflate")) accept_encoding |= HTTP_ACCEPT_ENCODING_DEFLATE;
				if (NULL != strstr(value, "compress")) accept_encoding |= HTTP_ACCEPT_ENCODING_COMPRESS;
				if (NULL != strstr(value, "bzip2")) accept_encoding |= HTTP_ACCEPT_ENCODING_BZIP2;
				if (NULL != strstr(value, "identity")) accept_encoding |= HTTP_ACCEPT_ENCODING_IDENTITY;
				
				/* get server side supported ones */
#ifdef USE_BZ2LIB
				srv_encodings |= HTTP_ACCEPT_ENCODING_BZIP2;
#endif
#ifdef USE_ZLIB
				srv_encodings |= HTTP_ACCEPT_ENCODING_GZIP;
				srv_encodings |= HTTP_ACCEPT_ENCODING_DEFLATE;
#endif
				
				/* find matching entries */
				matched_encodings = accept_encoding & srv_encodings;
				
				if (matched_encodings) {
					const char *dflt_gzip = "gzip";
					const char *dflt_deflate = "deflate";
					const char *dflt_bzip2 = "bzip2";
					
					const char *compression_name = NULL;
					int compression_type = 0;
					
					/* select best matching encoding */
					if (matched_encodings & HTTP_ACCEPT_ENCODING_BZIP2) {
						compression_type = HTTP_ACCEPT_ENCODING_BZIP2;
						compression_name = dflt_bzip2;
					} else if (matched_encodings & HTTP_ACCEPT_ENCODING_GZIP) {
						compression_type = HTTP_ACCEPT_ENCODING_GZIP;
						compression_name = dflt_gzip;
					} else if (matched_encodings & HTTP_ACCEPT_ENCODING_DEFLATE) {
						compression_type = HTTP_ACCEPT_ENCODING_DEFLATE;
						compression_name = dflt_deflate;
					}
					
					/* deflate it */
					if (p->conf.compress_cache_dir->used) {
						if (0 == deflate_file_to_file(srv, con, p,
									      con->physical.path, con->fce, compression_type)) {
							struct tm *tm;
							time_t last_mod;
							
							response_header_insert(srv, con, CONST_STR_LEN("Content-Encoding"), compression_name, strlen(compression_name));
							
							/* Set Last-Modified of ORIGINAL file */
							last_mod = con->fce->st.st_mtime;
							
							for (i = 0; i < FILE_CACHE_MAX; i++) {
								if (srv->mtime_cache[i].mtime == last_mod) break;
								
								if (srv->mtime_cache[i].mtime == 0) {
									srv->mtime_cache[i].mtime = last_mod;
									
									buffer_prepare_copy(srv->mtime_cache[i].str, 1024);
									
									tm = gmtime(&(srv->mtime_cache[i].mtime));
									srv->mtime_cache[i].str->used = strftime(srv->mtime_cache[i].str->ptr, 
														 srv->mtime_cache[i].str->size - 1,
														 "%a, %d %b %Y %H:%M:%S GMT", tm);
								
									srv->mtime_cache[i].str->used++;
									break;
								}
							}
							
							if (i == FILE_CACHE_MAX) {
								i = 0;
								
								srv->mtime_cache[i].mtime = last_mod;
								buffer_prepare_copy(srv->mtime_cache[i].str, 1024);
								tm = gmtime(&(srv->mtime_cache[i].mtime));
								srv->mtime_cache[i].str->used = strftime(srv->mtime_cache[i].str->ptr, 
													 srv->mtime_cache[i].str->size - 1,
													 "%a, %d %b %Y %H:%M:%S GMT", tm);
								srv->mtime_cache[i].str->used++;
							}
							
							response_header_insert(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(srv->mtime_cache[i].str));
							
							return HANDLER_FINISHED;
						}
					} else if (0 == deflate_file_to_buffer(srv, con, p,
									       con->physical.path, con->fce, compression_type)) {
							
						response_header_insert(srv, con, CONST_STR_LEN("Content-Encoding"), compression_name, strlen(compression_name));
						
						return HANDLER_FINISHED;
					}
					break;
				}
			}
		}
	}
	
	return HANDLER_GO_ON;
}

int mod_compress_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("compress");
	
	p->init        = mod_compress_init;
	p->set_defaults = mod_compress_setdefaults;
	p->handle_physical_path  = mod_compress_physical;
	p->cleanup     = mod_compress_free;
	
	p->data        = NULL;
	
	return 0;
}
