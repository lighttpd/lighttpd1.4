#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

#include <stdio.h>

#include "response.h"
#include "keyvalue.h"
#include "log.h"
#include "file_cache.h"
#include "etag.h"

#include "connections.h"

#include "plugin.h"

#include "sys-socket.h"

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
#endif

/*
 * This was 'borrowed' from tcpdump.
 *
 *
 * This is fun.
 *
 * In older BSD systems, socket addresses were fixed-length, and
 * "sizeof (struct sockaddr)" gave the size of the structure.
 * All addresses fit within a "struct sockaddr".
 *
 * In newer BSD systems, the socket address is variable-length, and
 * there's an "sa_len" field giving the length of the structure;
 * this allows socket addresses to be longer than 2 bytes of family
 * and 14 bytes of data.
 *
 * Some commercial UNIXes use the old BSD scheme, some use the RFC 2553
 * variant of the old BSD scheme (with "struct sockaddr_storage" rather
 * than "struct sockaddr"), and some use the new BSD scheme.
 *
 * Some versions of GNU libc use neither scheme, but has an "SA_LEN()"
 * macro that determines the size based on the address family.  Other
 * versions don't have "SA_LEN()" (as it was in drafts of RFC 2553
 * but not in the final version).  On the latter systems, we explicitly
 * check the AF_ type to determine the length; we assume that on
 * all those systems we have "struct sockaddr_storage".
 */

#ifdef HAVE_IPV6
# ifndef SA_LEN
#  ifdef HAVE_SOCKADDR_SA_LEN
#   define SA_LEN(addr)   ((addr)->sa_len)
#  else /* HAVE_SOCKADDR_SA_LEN */
#   ifdef HAVE_STRUCT_SOCKADDR_STORAGE
static size_t get_sa_len(const struct sockaddr *addr) {
	switch (addr->sa_family) {
		
#    ifdef AF_INET
	case AF_INET:
		return (sizeof (struct sockaddr_in));
#    endif
		
#    ifdef AF_INET6
	case AF_INET6:
		return (sizeof (struct sockaddr_in6));
#    endif
		
	default:
		return (sizeof (struct sockaddr));
		
	}
}
#    define SA_LEN(addr)   (get_sa_len(addr))
#   else /* HAVE_SOCKADDR_STORAGE */
#    define SA_LEN(addr)   (sizeof (struct sockaddr))
#   endif /* HAVE_SOCKADDR_STORAGE */
#  endif /* HAVE_SOCKADDR_SA_LEN */
# endif /* SA_LEN */
#endif



int response_header_insert(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen) {
	data_string *ds;
	
	UNUSED(srv);

	if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
		ds = data_response_init();
	}
	buffer_copy_string_len(ds->key, key, keylen);
	buffer_copy_string_len(ds->value, value, vallen);
	
	array_insert_unique(con->response.headers, (data_unset *)ds);
	
	return 0;
}

int response_header_overwrite(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen) {
	data_string *ds;
	
	UNUSED(srv);

	/* if there already is a key by this name overwrite the value */
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, key))) {
		buffer_copy_string(ds->value, value);
		
		return 0;
	}
	
	return response_header_insert(srv, con, key, keylen, value, vallen);
}


int http_response_write_basic_header(server *srv, connection *con) {
	size_t i;
	buffer *b;
	
	b = chunkqueue_get_prepend_buffer(con->write_queue);
	
	if (con->request.http_version == HTTP_VERSION_1_1) {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.1 "));
	} else {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.0 "));
	}
	buffer_append_long(b, con->http_status);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	buffer_append_string(b, get_http_status_name(con->http_status));
	
	/* add the connection header if 
	 * HTTP/1.1 -> close
	 * HTTP/1.0 -> keep-alive 
	 */
	if (con->request.http_version != HTTP_VERSION_1_1 || con->keep_alive == 0) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nConnection: ");
		if (con->keep_alive) {
			BUFFER_APPEND_STRING_CONST(b, "keep-alive");
		} else {
			BUFFER_APPEND_STRING_CONST(b, "close");
		}
	}
	
	if (con->request.http_version == HTTP_VERSION_1_1 &&
	    (con->parsed_response & HTTP_DATE) == 0) {
		/* HTTP/1.1 requires a Date: header */
		BUFFER_APPEND_STRING_CONST(b, "\r\nDate: ");
	
		/* cache the generated timestamp */
		if (srv->cur_ts != srv->last_generated_date_ts) {
			buffer_prepare_copy(srv->ts_date_str, 255);
			
			strftime(srv->ts_date_str->ptr, srv->ts_date_str->size - 1, 
				 "%a, %d %b %Y %H:%M:%S GMT", gmtime(&(srv->cur_ts)));
			
			srv->ts_date_str->used = strlen(srv->ts_date_str->ptr) + 1;
			
			srv->last_generated_date_ts = srv->cur_ts;
		}
		
		buffer_append_string_buffer(b, srv->ts_date_str);
	}
	
	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nTransfer-Encoding: chunked");
	}
	
	/* add all headers */
	for (i = 0; i < con->response.headers->used; i++) {
		data_string *ds;
		
		ds = (data_string *)con->response.headers->data[i];
		
		if (ds->value->used && ds->key->used &&
		    0 != strncmp(ds->key->ptr, "X-LIGHTTPD-", sizeof("X-LIGHTTPD-") - 1)) {
			BUFFER_APPEND_STRING_CONST(b, "\r\n");
			buffer_append_string_buffer(b, ds->key);
			BUFFER_APPEND_STRING_CONST(b, ": ");
			buffer_append_string_buffer(b, ds->value);
		}
	}

	if (buffer_is_empty(con->conf.server_tag)) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nServer: "PACKAGE"/"VERSION);
	} else {
		BUFFER_APPEND_STRING_CONST(b, "\r\nServer: ");
		buffer_append_string_buffer(b, con->conf.server_tag);
	}

	BUFFER_APPEND_STRING_CONST(b, "\r\n\r\n");

	if (con->conf.log_response_header) {
		log_error_write(srv, __FILE__, __LINE__, "sdsdSb", 
				"fd:", con->fd, 
				"response-header-len:", b->used - 1, 
				"\n", b);
	}
	
	con->bytes_header = b->used - 1;
	
	return 0;
}


int http_response_write_header(server *srv, connection *con,
			       off_t file_size, 
			       time_t last_mod) {
	buffer *b;
	size_t i;
	
	b = chunkqueue_get_prepend_buffer(con->write_queue);
	
	if (con->request.http_version == HTTP_VERSION_1_1) {
		BUFFER_COPY_STRING_CONST(b, "HTTP/1.1 ");
	} else {
		BUFFER_COPY_STRING_CONST(b, "HTTP/1.0 ");
	}
	buffer_append_long(b, con->http_status);
	BUFFER_APPEND_STRING_CONST(b, " ");
	buffer_append_string(b, get_http_status_name(con->http_status));
	
	if (con->request.http_version != HTTP_VERSION_1_1 || con->keep_alive == 0) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nConnection: ");
		buffer_append_string(b, con->keep_alive ? "keep-alive" : "close");
	}
	
	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nTransfer-Encoding: chunked");
	}
	
	/* HTTP/1.1 requires a Date: header */
	BUFFER_APPEND_STRING_CONST(b, "\r\nDate: ");
	
	/* cache the generated timestamp */
	if (srv->cur_ts != srv->last_generated_date_ts) {
		buffer_prepare_copy(srv->ts_date_str, 255);
		
		strftime(srv->ts_date_str->ptr, srv->ts_date_str->size - 1, 
			 "%a, %d %b %Y %H:%M:%S GMT", gmtime(&(srv->cur_ts)));
			 
		srv->ts_date_str->used = strlen(srv->ts_date_str->ptr) + 1;
		
		srv->last_generated_date_ts = srv->cur_ts;
	}
	
	buffer_append_string_buffer(b, srv->ts_date_str);
	
	/* no Last-Modified specified */
	if (last_mod && NULL == array_get_element(con->response.headers, "Last-Modified")) {
		struct tm *tm;
		
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
		
		BUFFER_APPEND_STRING_CONST(b, "\r\nLast-Modified: ");
		buffer_append_string_buffer(b, srv->mtime_cache[i].str);
	}
	
	if (file_size >= 0 && con->http_status != 304) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nContent-Length: ");
		buffer_append_off_t(b, file_size);
	}
	
	if (con->physical.path->used && con->physical.etag->used) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nETag: ");
		buffer_append_string_buffer(b, con->physical.etag);
	}

	BUFFER_APPEND_STRING_CONST(b, "\r\nAccept-Ranges: bytes");
	
	/* add all headers */
	for (i = 0; i < con->response.headers->used; i++) {
		data_string *ds;
		
		ds = (data_string *)con->response.headers->data[i];
		
		if (ds->value->used && ds->key->used &&
		    0 != strncmp(ds->key->ptr, "X-LIGHTTPD-", sizeof("X-LIGHTTPD-") - 1)) {
			BUFFER_APPEND_STRING_CONST(b, "\r\n");
			buffer_append_string_buffer(b, ds->key);
			BUFFER_APPEND_STRING_CONST(b, ": ");
			buffer_append_string_buffer(b, ds->value);
#if 0
			log_error_write(srv, __FILE__, __LINE__, "bb", 
					ds->key, ds->value);
#endif
		}
	}
	
	if (buffer_is_empty(con->conf.server_tag)) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nServer: "PACKAGE"/"VERSION);
	} else {
		BUFFER_APPEND_STRING_CONST(b, "\r\nServer: ");
		buffer_append_string_buffer(b, con->conf.server_tag);
	}
	
	BUFFER_APPEND_STRING_CONST(b, "\r\n\r\n");
	
	con->bytes_header = b->used - 1;
	
	if (con->conf.log_response_header) {
		log_error_write(srv, __FILE__, __LINE__, "sSb", "Response-Header:", "\n", b);
	}
	
	return 0;
}

static int http_response_parse_range(server *srv, connection *con) {
	struct stat st;
	int multipart = 0;
	int error;
	off_t start, end;
	const char *s, *minus;
	char *boundary = "fkj49sn38dcn3";
	const char *content_type = NULL;
	data_string *ds;
	
	if (-1 == stat(con->physical.path->ptr, &st)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "stat failed: ", strerror(errno));
		return -1;
	}
	
	start = 0;
	end = st.st_size - 1;
	
	con->response.content_length = 0;
	
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, "Content-Type"))) {
		content_type = ds->value->ptr;
	}
	
	for (s = con->request.http_range, error = 0;
	     !error && *s && NULL != (minus = strchr(s, '-')); ) {
		char *err;
		long la, le;
		
		if (s == minus) {
			/* -<stop> */
			
			le = strtol(s, &err, 10);
			
			if (le == 0) {
				/* RFC 2616 - 14.35.1 */
				
				con->http_status = 416;
				error = 1;
			} else if (*err == '\0') {
				/* end */
				s = err;
				
				end = st.st_size - 1;
				start = st.st_size + le;
			} else if (*err == ',') {
				multipart = 1;
				s = err + 1;
				
				end = st.st_size - 1;
				start = st.st_size + le;
			} else {
				error = 1;
			}
			
		} else if (*(minus+1) == '\0' || *(minus+1) == ',') {
			/* <start>- */
			
			la = strtol(s, &err, 10);
			
			if (err == minus) {
				/* ok */
				
				if (*(err + 1) == '\0') {
					s = err + 1;
					
					end = st.st_size - 1;
					start = la;
					
				} else if (*(err + 1) == ',') {
					multipart = 1;
					s = err + 2;
					
					end = st.st_size - 1;
					start = la;
				} else {
					error = 1;
				}
			} else {
				/* error */
				error = 1;
			}
		} else {
			/* <start>-<stop> */
			
			la = strtol(s, &err, 10);
			
			if (err == minus) {
				le = strtol(minus+1, &err, 10);
				
				/* RFC 2616 - 14.35.1 */
				if (la > le) {
					error = 1;
				}
					
				if (*err == '\0') {
					/* ok, end*/
					s = err;
					
					end = le;
					start = la;
				} else if (*err == ',') {
					multipart = 1;
					s = err + 1;
					
					end = le;
					start = la;
				} else {
					/* error */
					
					error = 1;
				}
			} else {
				/* error */
				
				error = 1;
			}
		}
		
		if (!error) {
			if (start < 0) start = 0;
			
			/* RFC 2616 - 14.35.1 */
			if (end > st.st_size - 1) end = st.st_size - 1;
			
			if (start > st.st_size - 1) {
				error = 1;
				
				con->http_status = 416;
			}
		}
		
		if (!error) {
			if (multipart) {
				/* write boundary-header */
				buffer *b;
				
				b = chunkqueue_get_append_buffer(con->write_queue);
				
				buffer_copy_string(b, "\r\n--");
				buffer_append_string(b, boundary);
				
				/* write Content-Range */
				buffer_append_string(b, "\r\nContent-Range: bytes ");
				buffer_append_off_t(b, start);
				buffer_append_string(b, "-");
				buffer_append_off_t(b, end);
				buffer_append_string(b, "/");
				buffer_append_off_t(b, st.st_size);
				
				buffer_append_string(b, "\r\nContent-Type: ");
				buffer_append_string(b, content_type);
				
				/* write END-OF-HEADER */
				buffer_append_string(b, "\r\n\r\n");
				
				con->response.content_length += b->used - 1;
				
			}
			
			chunkqueue_append_file(con->write_queue, con->physical.path, start, end - start + 1);
			con->response.content_length += end - start + 1;
		}
	}
	
	/* something went wrong */
	if (error) {
		return 0;
	}
	
	if (multipart) {
		/* add boundary end */
		buffer *b;
		
		b = chunkqueue_get_append_buffer(con->write_queue);
		
		buffer_copy_string_len(b, "\r\n--", 4);
		buffer_append_string(b, boundary);
		buffer_append_string_len(b, "--\r\n", 4);
		
		con->response.content_length += b->used - 1;
		
		/* set header-fields */
		
		buffer_copy_string(srv->range_buf, "multipart/byteranges; boundary=");
		buffer_append_string(srv->range_buf, boundary);
		
		/* overwrite content-type */
		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(srv->range_buf));
	} else {
		/* add Content-Range-header */
		
		buffer_copy_string(srv->range_buf, "bytes ");
		buffer_append_off_t(srv->range_buf, start);
		buffer_append_string(srv->range_buf, "-");
		buffer_append_off_t(srv->range_buf, end);
		buffer_append_string(srv->range_buf, "/");
		buffer_append_off_t(srv->range_buf, st.st_size);
		
		response_header_insert(srv, con, CONST_STR_LEN("Content-Range"), CONST_BUF_LEN(srv->range_buf));
	}

	/* ok, the file is set-up */
	con->http_status = 206;
	
	return 0;
}

typedef struct {
	char **ptr;
	size_t used;
	size_t size;
} string_buffer;

static int http_list_directory(server *srv, connection *con, buffer *dir) {
	DIR *d;
	struct dirent *dent;
	buffer *b, *date_buf;
	string_buffer *sb;
	size_t i;

	if (NULL == (d = opendir(dir->ptr))) {
		log_error_write(srv, __FILE__, __LINE__, "sbs", 
			"opendir failed:", dir, strerror(errno));
		return -1;
	}
	
	b = chunkqueue_get_append_buffer(con->write_queue);
	buffer_copy_string(b, 
			   "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
			   "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
			   "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
			   "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
			   " <head>\n"
			   "  <title>Directory Listing for ");
	buffer_append_string_html_encoded(b, con->uri.path->ptr);
	
	BUFFER_APPEND_STRING_CONST(b,
			    "</title>\n"
			    "  <style type=\"text/css\">\n");
	
	BUFFER_APPEND_STRING_CONST(b,
			    "th.dirlisting { background-color: black; color: white; }\n"
			    "table.dirlisting { border: black solid thin; }\n"
			    "td.dirlisting { background-color: #f0f0f0; }\n"
			    "td.dirlistingnumber { background-color: #f0f0f0; text-align: right }\n"
			    );
	
	BUFFER_APPEND_STRING_CONST(b,
			    "  </style>\n"
			    " </head>\n"
			    " <body>\n"
			    "  <h2>Directory Listing for ");
	buffer_append_string_html_encoded(b, con->uri.path->ptr);
	BUFFER_APPEND_STRING_CONST(b,"</h2>\n  <table class='dirlisting'>\n");
	BUFFER_APPEND_STRING_CONST(b,"   <tr class='dirlisting'><th class='dirlisting'>date</th><th class='dirlisting'>size</th><th class='dirlisting'>type</th><th class='dirlisting'>name</th></tr>\n");
	
	
	/* allocate memory */
	sb = calloc(1, sizeof(*sb));
	assert(sb);
	
	sb->ptr = NULL;
	sb->used = 0;
	sb->size = 0;
	
	while(NULL != (dent = readdir(d))) {
		size_t j;
		if (sb->size == 0) {
			sb->size = 4;
			sb->ptr = malloc(sizeof(*sb->ptr) * sb->size);
			assert(sb->ptr);
		} else if (sb->used == sb->size) {
			sb->size += 4;
			sb->ptr = realloc(sb->ptr, sizeof(*sb->ptr) * sb->size);
			assert(sb->ptr);
		}
		
		for (i = 0; i < sb->used; i++) {
			if (strcmp(dent->d_name, sb->ptr[i]) < 0) {
				break;
			}
		}
		
		/* <left><right> */
		/* <left>[i]<right> */
		
		for (j = sb->used - 1; sb->used && j >= i && (j+1) > 0; j--) {
			sb->ptr[j + 1] = sb->ptr[j];
		}
		sb->ptr[i] = strdup(dent->d_name);
		
		sb->used++;
		
	}
	
	closedir(d);
	
	date_buf = buffer_init();
	buffer_prepare_copy(date_buf, 22);
	for (i = 0; i < sb->used; i++) {
		struct stat st;
		struct tm tm;
		size_t s_len = strlen(sb->ptr[i]);
		
		
		buffer_copy_string(srv->tmp_buf, dir->ptr);
		buffer_append_string(srv->tmp_buf, sb->ptr[i]);
		
		if (0 != stat(srv->tmp_buf->ptr, &st)) {
			free(sb->ptr[i]);
			continue;
		}
		
		BUFFER_APPEND_STRING_CONST(b,
				    "   <tr><td class='dirlisting'>");
		
#ifdef HAVE_LOCALTIME_R
		/* localtime_r is faster */
		localtime_r(&(st.st_mtime), &tm);
		
		date_buf->used = strftime(date_buf->ptr, date_buf->size - 1, "%Y-%m-%d %H:%M:%S", &tm);
#else
		date_buf->used = strftime(date_buf->ptr, date_buf->size - 1, "%Y-%m-%d %H:%M:%S", localtime(&(st.st_mtime)));
#endif
		date_buf->used++;
		
		buffer_append_string_buffer(b, date_buf);
		BUFFER_APPEND_STRING_CONST(b,
				    "</td><td class='dirlistingnumber'>");
		
		buffer_append_off_t(b, st.st_size);
		
		/* mime type */
		BUFFER_APPEND_STRING_CONST(b,
				    "</td><td class='dirlisting'>");
		
		if (S_ISDIR(st.st_mode)) {
			buffer_append_string_rfill(b, "directory", 28);
		} else {
			size_t k;
			unsigned short have_content_type = 0;

#ifdef HAVE_XATTR
			char attrval[128];
			int attrlen = sizeof(attrval) - 1;
			
			if(con->conf.use_xattr && 0 == attr_get(srv->tmp_buf->ptr, "Content-Type", attrval, &attrlen, 0)) {
				attrval[attrlen] = 0;
				buffer_append_string_rfill(b, attrval, 28);
				have_content_type = 1;
			}
#endif
			
			if(!have_content_type) {
				for (k = 0; k < con->conf.mimetypes->used; k++) {
					data_string *ds = (data_string *)con->conf.mimetypes->data[k];
					size_t ct_len;
					
					if (ds->key->used == 0) continue;
					
					ct_len = ds->key->used - 1;
					
					if (s_len < ct_len) continue;
					
					if (0 == strncmp(sb->ptr[i] + s_len - ct_len, ds->key->ptr, ct_len)) {
						buffer_append_string_rfill(b, ds->value->ptr, 28);
						break;
					}
				}
				
				if (k == con->conf.mimetypes->used) {
					buffer_append_string_rfill(b, "application/octet-stream", 28);
				}
			}
		}
		
		/* URL */
		BUFFER_APPEND_STRING_CONST(b,"</td><td class='dirlisting'><a href=\"");
		/* URL encode */
		buffer_append_string_url_encoded(b, sb->ptr[i]);
		if (S_ISDIR(st.st_mode)) {
			BUFFER_APPEND_STRING_CONST(b,"/");
		}
		BUFFER_APPEND_STRING_CONST(b,"\">");
		/* HTML encode */
		buffer_append_string_html_encoded(b, sb->ptr[i]);
		if (S_ISDIR(st.st_mode)) {
			BUFFER_APPEND_STRING_CONST(b,"/");
		}
		BUFFER_APPEND_STRING_CONST(b,"</a></td></tr>\n");
			
		
		free(sb->ptr[i]);
	}
	
	buffer_free(date_buf);
	free(sb->ptr);
	free(sb);
	
	response_header_insert(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	
	BUFFER_APPEND_STRING_CONST(b,
			    "  </table>\n" 
			    " </body>\n"
			    "</html>\n" );
	
	con->file_finished = 1;
	
	return 0;
}

int http_response_redirect_to_directory(server *srv, connection *con) {
	buffer *o;
	
	o = buffer_init();
	
	if (con->conf.is_ssl) {
		buffer_copy_string(o, "https://");
	} else {
		buffer_copy_string(o, "http://");
	}
	if (con->uri.authority->used) {
		buffer_append_string_buffer(o, con->uri.authority);
	} else {
		/* get the name of the currently connected socket */
		struct hostent *he;
#ifdef HAVE_IPV6
		char hbuf[256];
#endif
		sock_addr our_addr;
		socklen_t our_addr_len;
		
		our_addr_len = sizeof(our_addr);
		
		if (-1 == getsockname(con->fd, &(our_addr.plain), &our_addr_len)) {
			con->http_status = 500;
			
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"can't get sockname", strerror(errno));
			
			buffer_free(o);
			return 0;
		}
		
		
		/* Lookup name: secondly try to get hostname for bind address */
		switch(our_addr.plain.sa_family) {
#ifdef HAVE_IPV6
		case AF_INET6:
			if (0 != getnameinfo((const struct sockaddr *)(&our_addr.ipv6), 
					     SA_LEN((const struct sockaddr *)&our_addr.ipv6), 
					     hbuf, sizeof(hbuf), NULL, 0, 0)) {
				
				char dst[INET6_ADDRSTRLEN];
				
				log_error_write(srv, __FILE__, __LINE__,
						"SSSS", "NOTICE: getnameinfo failed: ",
						strerror(errno), ", using ip-address instead");
				
				buffer_append_string(o, 
						     inet_ntop(AF_INET6, (char *)&our_addr.ipv6.sin6_addr, 
							       dst, sizeof(dst)));
			} else {
				buffer_append_string(o, hbuf);
			}
			break;
#endif
		case AF_INET:
			if (NULL == (he = gethostbyaddr((char *)&our_addr.ipv4.sin_addr, sizeof(struct in_addr), AF_INET))) {
				log_error_write(srv, __FILE__, __LINE__,
						"SSSS", "NOTICE: gethostbyaddr failed: ",
						hstrerror(h_errno), ", using ip-address instead");
				
				buffer_append_string(o, inet_ntoa(our_addr.ipv4.sin_addr));
			} else {
				buffer_append_string(o, he->h_name);
			}
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__,
					"S", "ERROR: unsupported address-type");
			
			buffer_free(o);
			return -1;
		}
		
		if (!((con->conf.is_ssl == 0 && srv->srvconf.port == 80) || 
		      (con->conf.is_ssl == 1 && srv->srvconf.port == 443))) {
			buffer_append_string(o, ":");
			buffer_append_long(o, srv->srvconf.port);
		}
	}
	buffer_append_string_buffer(o, con->uri.path);
	buffer_append_string(o, "/");
	if (!buffer_is_empty(con->uri.query)) {
		buffer_append_string(o, "?");
		buffer_append_string_buffer(o, con->uri.query);
	}
	
	response_header_insert(srv, con, CONST_STR_LEN("Location"), CONST_BUF_LEN(o));
	
	con->http_status = 301;
	
	buffer_free(o);
	
	return 0;
}


handler_t http_response_prepare(server *srv, connection *con) {
	handler_t r;
	
	/* looks like someone has already done a decision */
	if (con->mode == DIRECT && 
	    (con->http_status != 0 && con->http_status != 200)) {
		/* remove a packets in the queue */
		if (con->file_finished == 0) {
			chunkqueue_reset(con->write_queue);
		}
		
		return HANDLER_FINISHED;
	}
	
	/* no decision yet, build conf->filename */
	if (con->mode == DIRECT && con->physical.path->used == 0) {
		char *qstr;
		
		config_patch_connection(srv, con, CONST_STR_LEN("SERVERsocket")); /* SERVERsocket */
		
		/**
		 * prepare strings
		 * 
		 * - uri.path_raw 
		 * - uri.path (secure)
		 * - uri.query
		 * 
		 */
		
		/** 
		 * Name according to RFC 2396
		 * 
		 * - scheme
		 * - authority
		 * - path
		 * - query
		 * 
		 * (scheme)://(authority)(path)?(query)
		 * 
		 * 
		 */
	
		buffer_copy_string(con->uri.scheme, con->conf.is_ssl ? "http" : "https");
		buffer_copy_string_buffer(con->uri.authority, con->request.http_host);
		
		config_patch_connection(srv, con, CONST_STR_LEN("HTTPhost"));      /* Host:        */
		config_patch_connection(srv, con, CONST_STR_LEN("HTTPreferer"));   /* Referer:     */
		config_patch_connection(srv, con, CONST_STR_LEN("HTTPuseragent")); /* User-Agent:  */
		config_patch_connection(srv, con, CONST_STR_LEN("HTTPcookie"));    /* Cookie:  */
		
		/** extract query string from request.uri */
		if (NULL != (qstr = strchr(con->request.uri->ptr, '?'))) {
			buffer_copy_string    (con->uri.query, qstr + 1);
			buffer_copy_string_len(con->uri.path_raw, con->request.uri->ptr, qstr - con->request.uri->ptr);
		} else {
			buffer_reset     (con->uri.query);
			buffer_copy_string_buffer(con->uri.path_raw, con->request.uri);
		}

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- splitting Request-URI");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Request-URI  : ", con->request.uri);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-scheme   : ", con->uri.scheme);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-authority: ", con->uri.authority);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path     : ", con->uri.path_raw);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-query    : ", con->uri.query);
		}
		
		/* disable keep-alive if requested */
		
		if (con->request_count > con->conf.max_keep_alive_requests) {
			con->keep_alive = 0;
		}
		
		
		/**
		 *  
		 * call plugins 
		 * 
		 * - based on the raw URL
		 * 
		 */
		
		switch(r = plugins_call_handle_uri_raw(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sd", "handle_uri_raw: unknown return value", r);
			break;
		}

		/* build filename 
		 *
		 * - decode url-encodings  (e.g. %20 -> ' ')
		 * - remove path-modifiers (e.g. /../)
		 */
		
		
		
		buffer_copy_string_buffer(srv->tmp_buf, con->uri.path_raw);
		buffer_urldecode(srv->tmp_buf);
		buffer_path_simplify(&(srv->dot_stack), con->uri.path, srv->tmp_buf);

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- sanatising URI");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path     : ", con->uri.path);
		}

		/**
		 *  
		 * call plugins 
		 * 
		 * - based on the clean URL
		 * 
		 */
		
		config_patch_connection(srv, con, CONST_STR_LEN("HTTPurl")); /* HTTPurl */
		
		switch(r = plugins_call_handle_uri_clean(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}
		
		/***
		 * 
		 * border 
		 * 
		 * logical filename (URI) becomes a physical filename here
		 * 
		 * 
		 * 
		 */
		
		
		
		
		/* 1. stat()
		 * ... ISREG() -> ok, go on
		 * ... ISDIR() -> index-file -> redirect
		 * 
		 * 2. pathinfo() 
		 * ... ISREG()
		 * 
		 * 3. -> 404
		 * 
		 */
		
		/*
		 * SEARCH DOCUMENT ROOT
		 */
		
		/* set a default */
		
		buffer_copy_string_buffer(con->physical.doc_root, con->conf.document_root);
		buffer_copy_string_buffer(con->physical.rel_path, con->uri.path);
		
		buffer_reset(con->physical.path);
		
		/* the docroot plugin should set the doc_root and might also set the physical.path
		 * for us (all vhost-plugins are supposed to set the doc_root, the alias plugin
		 * sets the path too)
		 * */
		switch(r = plugins_call_handle_docroot(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}
		
		if (buffer_is_empty(con->physical.path)) {
			/** 
			 * create physical filename 
			 * -> physical.path = docroot + rel_path
			 * 
			 */
			
			buffer_copy_string_buffer(con->physical.path, con->physical.doc_root);
			BUFFER_APPEND_SLASH(con->physical.path);
			if (con->physical.rel_path->ptr[0] == '/') {
				buffer_append_string_len(con->physical.path, con->physical.rel_path->ptr + 1, con->physical.rel_path->used - 2);
			} else {
				buffer_append_string_buffer(con->physical.path, con->physical.rel_path);
			}
		}
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- logical -> physical");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}
	}
	
	/* 
	 * only if we are still in DIRECT mode we check for the real existence of the file
	 * 
	 */
	
	if (con->mode == DIRECT) {
		char *slash = NULL;
		char *pathinfo = NULL;
		int found = 0;
		size_t k;
		
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling physical path");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}
		
		switch (file_cache_get_entry(srv, con, con->physical.path, &(con->fce))) {
		case HANDLER_WAIT_FOR_FD:
			return HANDLER_WAIT_FOR_FD;
		case HANDLER_ERROR:
			if (errno == EACCES) {
				con->http_status = 403;
				buffer_reset(con->physical.path);
				
				return HANDLER_FINISHED;
			}
			
			if (errno != ENOENT &&
			    errno != ENOTDIR) {
				/* we have no idea what happend. let's tell the user so. */
				
				con->http_status = 500;
				buffer_reset(con->physical.path);
				
				log_error_write(srv, __FILE__, __LINE__, "ssbsb",
						"file not found ... or so: ", strerror(errno),
						con->uri.path,
						"->", con->physical.path);
				
				return HANDLER_FINISHED;
			}
			
			/* not found, perhaps PATHINFO */
			buffer_copy_string_buffer(srv->tmp_buf, con->physical.rel_path);
			
			/*
			 * 
			 * FIXME:
			 * 
			 * Check for PATHINFO fall to dir of 
			 * 
			 * /a is a dir and
			 * 
			 * /a/b/c is requested
			 * 
			 */
			
			do {
				struct stat st;
				
				buffer_copy_string_buffer(con->physical.path, con->physical.doc_root);
				BUFFER_APPEND_SLASH(con->physical.path);
				if (slash) {
					buffer_append_string_len(con->physical.path, srv->tmp_buf->ptr, slash - srv->tmp_buf->ptr);
				} else {
					buffer_append_string_buffer(con->physical.path, srv->tmp_buf);
				}
				
				if (0 == stat(con->physical.path->ptr, &(st)) &&
				    S_ISREG(st.st_mode)) {
					found = 1;
					break;
				}
				
				if (pathinfo != NULL) {
					*pathinfo = '\0';
				}
				slash = strrchr(srv->tmp_buf->ptr, '/');
				
				if (pathinfo != NULL) {
					/* restore '/' */
					*pathinfo = '/';
				}
				
				if (slash) pathinfo = slash;
			} while ((found == 0) && (slash != NULL) && (slash != srv->tmp_buf->ptr));
			
			if (found == 0) {
				/* no it really doesn't exists */
				con->http_status = 404;
				
				if (con->conf.log_file_not_found) {
					log_error_write(srv, __FILE__, __LINE__, "sbsb",
						"file not found:", con->uri.path,
						"->", con->physical.path);
				}
				
				buffer_reset(con->physical.path);
				
				return HANDLER_FINISHED;
			}
			
			
			/* we have a PATHINFO */
			if (pathinfo) {
				buffer_copy_string(con->request.pathinfo, pathinfo);
				
				/*
				 * shorten uri.path
				 */
				
				con->uri.path->used -= strlen(pathinfo);
				con->uri.path->ptr[con->uri.path->used - 1] = '\0';
				
				
			}
			
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- after pathinfo check");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Pathinfo     :", con->request.pathinfo);
			}
			
			/* setup the right file cache entry (FCE) */
			switch (file_cache_get_entry(srv, con, con->physical.path, &(con->fce))) {
			case HANDLER_ERROR:
				con->http_status = 404;
				
				if (con->conf.log_file_not_found) {
					log_error_write(srv, __FILE__, __LINE__, "sbsb",
						"file not found:", con->uri.path,
						"->", con->physical.path);
				}
				
				return HANDLER_FINISHED;
			case HANDLER_WAIT_FOR_FD:
				return HANDLER_WAIT_FOR_FD;
			case HANDLER_GO_ON:
				break;
			default:
				break;
			}
			
			break;
		case HANDLER_GO_ON:
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- file found");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			}
			
			if (S_ISDIR(con->fce->st.st_mode)) {
				if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
					/* redirect to .../ */
					
					http_response_redirect_to_directory(srv, con);
					
					return HANDLER_FINISHED;
				} else {
					found = 0;
					/* indexfile */
					
					for (k = 0; !found && (k < con->conf.indexfiles->used); k++) {
						data_string *ds = (data_string *)con->conf.indexfiles->data[k];
						
						buffer_copy_string_buffer(srv->tmp_buf, con->physical.path);
						buffer_append_string_buffer(srv->tmp_buf, ds->value);
						
						switch (file_cache_get_entry(srv, con, srv->tmp_buf, &(con->fce))) {
						case HANDLER_GO_ON:
							/* rewrite uri.path to the real path (/ -> /index.php) */
							buffer_append_string_buffer(con->uri.path, ds->value);
							
							found = 1;
							break;
						case HANDLER_ERROR:
							
							if (errno == EACCES) {
								con->http_status = 403;
								buffer_reset(con->physical.path);
								
								return HANDLER_FINISHED;
							}
							
							if (errno != ENOENT &&
							    errno != ENOTDIR) {
								/* we have no idea what happend. let's tell the user so. */
								
								con->http_status = 500;
								buffer_reset(con->physical.path);
								
								log_error_write(srv, __FILE__, __LINE__, "ssbsb",
										"file not found ... or so: ", strerror(errno),
										con->uri.path,
										"->", con->physical.path);
								
								return HANDLER_FINISHED;
							}
							
							break;
						default:
							break;
						}
					}
					
					if (!found &&
					    (k == con->conf.indexfiles->used)) {
						/* directory listing ? */
						
						buffer_reset(srv->tmp_buf);

						if (con->conf.dir_listing == 0) {
							/* dirlisting disabled */
							con->http_status = 403;
						} else if (0 != http_list_directory(srv, con, con->physical.path)) {
							/* dirlisting failed */
							con->http_status = 403;
						}
						
						buffer_reset(con->physical.path);
						
						return HANDLER_FINISHED;
					}
					
					buffer_copy_string_buffer(con->physical.path, srv->tmp_buf);
				}
			}
			break;
		default:
			break;
		}
		
		if (!S_ISREG(con->fce->st.st_mode)) {
			con->http_status = 404;
			
			if (con->conf.log_file_not_found) {
				log_error_write(srv, __FILE__, __LINE__, "sbsb",
					"not a regular file:", con->uri.path,
					"->", con->fce->name);
			}
			
			return HANDLER_FINISHED;
		}
		
		/* call the handlers */
		switch(r = plugins_call_handle_subrequest_start(srv, con)) {
		case HANDLER_FINISHED:
			/* request was handled */
			break;
		case HANDLER_GO_ON:
			/* request was not handled */
			break;
		default:
			/* something strange happend */
			return r;
		}
		
		/* ok, noone has handled the file up to now, so we do the fileserver-stuff */
		if (r == HANDLER_GO_ON) {
			/* DIRECT */
			
			/* set response content-type */

			if (buffer_is_empty(con->fce->content_type)) {
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("application/octet-stream"));
			} else {
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(con->fce->content_type));
			}
			
			/* generate e-tag */
			etag_mutate(con->physical.etag, con->fce->etag);
			
			/*
			 * 14.26 If-None-Match
			 *    [...]
			 *    If none of the entity tags match, then the server MAY perform the
			 *    requested method as if the If-None-Match header field did not exist,
			 *    but MUST also ignore any If-Modified-Since header field(s) in the
			 *    request. That is, if no entity tags match, then the server MUST NOT
			 *    return a 304 (Not Modified) response.
			 */
			
			/* last-modified handling */
			if (con->http_status == 0 && 
			    con->request.http_if_none_match) {
				if (etag_is_equal(con->physical.etag, con->request.http_if_none_match)) {
					if (con->request.http_method == HTTP_METHOD_GET || 
					    con->request.http_method == HTTP_METHOD_HEAD) {
						
						/* check if etag + last-modified */
						if (con->request.http_if_modified_since) {
							char buf[64];
							struct tm *tm;
							size_t used_len;
							char *semicolon;
						
							tm = gmtime(&(con->fce->st.st_mtime));
							strftime(buf, sizeof(buf)-1, "%a, %d %b %Y %H:%M:%S GMT", tm);
							
							if (NULL == (semicolon = strchr(con->request.http_if_modified_since, ';'))) {
								used_len = strlen(con->request.http_if_modified_since);
							} else {
								used_len = semicolon - con->request.http_if_modified_since;
							}
							
							if (0 == strncmp(con->request.http_if_modified_since, buf, used_len)) {
								con->http_status = 304;
							} else {
								log_error_write(srv, __FILE__, __LINE__, "ss", 
										con->request.http_if_modified_since, buf);
								
								con->http_status = 412;
							}
						} else {
							con->http_status = 304;
						}
					} else {
						con->http_status = 412;
					}
				}
			} else if (con->http_status == 0 && con->request.http_if_modified_since) {
				char buf[64];
				struct tm *tm;
				size_t used_len;
				char *semicolon;
				
				tm = gmtime(&(con->fce->st.st_mtime));
				strftime(buf, sizeof(buf)-1, "%a, %d %b %Y %H:%M:%S GMT", tm);
				
				if (NULL == (semicolon = strchr(con->request.http_if_modified_since, ';'))) {
					used_len = strlen(con->request.http_if_modified_since);
				} else {
					used_len = semicolon - con->request.http_if_modified_since;
				}
				
				if (0 == strncmp(con->request.http_if_modified_since, buf, used_len)) {
					con->http_status = 304;
				}
			}
			
			if (con->http_status == 0 && con->request.http_range) {
				http_response_parse_range(srv, con);
			} else if (con->http_status == 0) {
				switch(r = plugins_call_handle_physical_path(srv, con)) {
				case HANDLER_GO_ON:
					break;
				default:
					return r;
				}
			}
		}
	}
	
	switch(r = plugins_call_handle_subrequest(srv, con)) {
	case HANDLER_GO_ON:
		/* request was not handled, looks like we are done */
		
		return HANDLER_FINISHED;
	case HANDLER_FINISHED:
		/* request is finished */
	default:
		/* something strange happend */
		return r;
	}
	
	/* can't happen */
	return HANDLER_COMEBACK;
}
