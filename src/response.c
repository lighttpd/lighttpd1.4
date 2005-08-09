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
#include "stat_cache.h"
#include "etag.h"

#include "connections.h"

#include "plugin.h"

#include "sys-socket.h"

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
#endif

#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

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
	
	if ((con->parsed_response & HTTP_DATE) == 0) {
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
		    0 != strncmp(ds->key->ptr, "X-LIGHTTPD-", sizeof("X-LIGHTTPD-") - 1) &&
		    /* headers we send */
		    !buffer_is_equal_string(ds->key, CONST_STR_LEN("Server")) &&
		    !buffer_is_equal_string(ds->key, CONST_STR_LEN("Date")) &&
		    !buffer_is_equal_string(ds->key, CONST_STR_LEN("Transfer-Encoding")) &&
		    !buffer_is_equal_string(ds->key, CONST_STR_LEN("Connection"))) {
			BUFFER_APPEND_STRING_CONST(b, "\r\n");
			buffer_append_string_buffer(b, ds->key);
			BUFFER_APPEND_STRING_CONST(b, ": ");
			buffer_append_string_buffer(b, ds->value);
		}
	}

	if (buffer_is_empty(con->conf.server_tag)) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nServer: " PACKAGE_NAME "/" PACKAGE_VERSION);
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
	} else if (file_size >= 0 && con->http_status != 304) {
		BUFFER_APPEND_STRING_CONST(b, "\r\nContent-Length: ");
		buffer_append_off_t(b, file_size);
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
		BUFFER_APPEND_STRING_CONST(b, "\r\nServer: " PACKAGE_NAME "/" PACKAGE_VERSION);
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
		off_t la, le;
		
		if (s == minus) {
			/* -<stop> */
			
			le = strtoll(s, &err, 10);
			
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
			
			la = strtoll(s, &err, 10);
			
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
			
			la = strtoll(s, &err, 10);
			
			if (err == minus) {
				le = strtoll(minus+1, &err, 10);
				
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
	size_t  namelen;
	time_t  mtime;
	off_t   size;
} dirls_entry_t;

typedef struct {
	dirls_entry_t **ent;
	int used;
	int size;
} dirls_list_t;

#define DIRLIST_ENT_NAME(ent)	(char*) ent + sizeof(dirls_entry_t)
#define DIRLIST_BLOB_SIZE		16

/* simple combsort algorithm */
static void http_dirls_sort(dirls_entry_t **ent, int num) {
	int gap = num;
	int i, j;
	int swapped;
	dirls_entry_t *tmp;

	do {
		gap = (gap * 10) / 13;
		if (gap == 9 || gap == 10)
			gap = 11;
		if (gap < 1)
			gap = 1;
		swapped = 0;

		for (i = 0; i < num - gap; i++) {
			j = i + gap;
			if (strcmp(DIRLIST_ENT_NAME(ent[i]), DIRLIST_ENT_NAME(ent[j])) > 0) {
				tmp = ent[i];
				ent[i] = ent[j];
				ent[j] = tmp;
				swapped = 1;
			}
		}

	} while (gap > 1 || swapped);
}

/* buffer must be able to hold "999.9K"
 * conversion is simple but not perfect
 */
static int http_list_directory_sizefmt(char *buf, off_t size) {
	const char unit[] = "KMGTPE";	/* Kilo, Mega, Tera, Peta, Exa */
	const char *u = unit - 1;		/* u will always increment at least once */
	int remain;
	char *out = buf;

	if (size < 100)
		size += 99;
	if (size < 100)
		size = 0;

	while (1) {
		remain = (int) size & 1023;
		size >>= 10;
		u++;
		if ((size & (~0 ^ 1023)) == 0)
			break;
	}

	remain /= 100;
	if (remain > 9)
		remain = 9;
	if (size > 999) {
		size   = 0;
		remain = 9;
		u++;
	}

	out   += ltostr(out, size);
	out[0] = '.';
	out[1] = remain + '0';
	out[2] = *u;
	out[3] = '\0';

	return (out + 3 - buf);
}

static void http_list_directory_header(buffer *out, connection *con) {
	BUFFER_APPEND_STRING_CONST(out,
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
		"<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n"
		"<head>\n"
		"<title>Index of "
	);
	buffer_append_string_html_encoded(out, con->uri.path->ptr);
	BUFFER_APPEND_STRING_CONST(out, "</title>\n");

	if (con->conf.dirlist_css->used > 1) {
		BUFFER_APPEND_STRING_CONST(out, "<link rel=\"stylesheet\" type=\"text/css\" href=\"");
		buffer_append_string_buffer(out, con->conf.dirlist_css);
		BUFFER_APPEND_STRING_CONST(out, "\" />\n");
	} else {
		BUFFER_APPEND_STRING_CONST(out,
			"<style type=\"text/css\">\n"
			"a, a:active {text-decoration: none; color: blue;}\n"
			"a:visited {color: #48468F;}\n"
			"a:hover, a:focus {text-decoration: underline; color: red;}\n"
			"body {background-color: #F5F5F5;}\n"
			"h2 {margin-bottom: 12px;}\n"
			"table {margin-left: 12px;}\n"
			"th, td {"
			" font-family: \"Courier New\", Courier, monospace;"
			" font-size: 10pt;"
			" text-align: left;"
			"}\n"
			"th {"
			" font-weight: bold;"
			" padding-right: 14px;"
			" padding-bottom: 3px;"
			"}\n"
		);
		BUFFER_APPEND_STRING_CONST(out,
			"td {padding-right: 14px;}\n"
			"td.s, th.s {text-align: right;}\n"
			"div.list {"
			" background-color: white;"
			" border-top: 1px solid #646464;"
			" border-bottom: 1px solid #646464;"
			" padding-top: 10px;"
			" padding-bottom: 14px;"
			"}\n"
			"div.foot {"
			" font-family: \"Courier New\", Courier, monospace;"
			" font-size: 10pt;"
			" color: #787878;"
			" padding-top: 4px;"
			"}\n"
			"</style>\n"
		);
	}

	BUFFER_APPEND_STRING_CONST(out, "</head>\n<body>\n<h2>Index of ");
	buffer_append_string_html_encoded(out, con->uri.path->ptr);
	BUFFER_APPEND_STRING_CONST(out,
		"</h2>\n"
		"<div class=\"list\">\n"
		"<table cellpadding=\"0\" cellspacing=\"0\">\n"
		"<thead>"
		"<tr>"
			"<th class=\"n\">Name</th>"
			"<th class=\"m\">Last Modified</th>"
			"<th class=\"s\">Size</th>"
			"<th class=\"t\">Type</th>"
		"</tr>"
		"</thead>\n"
		"<tbody>\n"
		"<tr>"
			"<td class=\"n\"><a href=\"../\">Parent Directory</a>/</td>"
			"<td class=\"m\">&nbsp;</td>"
			"<td class=\"s\">- &nbsp;</td>"
			"<td class=\"t\">Directory</td>"
		"</tr>\n"
	);
}

static void http_list_directory_footer(buffer *out, connection *con) {
	BUFFER_APPEND_STRING_CONST(out,
		"</tbody>\n"
		"</table>\n"
		"</div>\n"
		"<div class=\"foot\">"
	);

	if (buffer_is_empty(con->conf.server_tag)) {
		BUFFER_APPEND_STRING_CONST(out, PACKAGE_NAME "/" PACKAGE_VERSION);
	} else {
		buffer_append_string_buffer(out, con->conf.server_tag);
	}

	BUFFER_APPEND_STRING_CONST(out,
		"</div>\n"
		"</body>\n"
		"</html>\n"
	);
}

static int http_list_directory(server *srv, connection *con, buffer *dir) {
	DIR *dp;
	buffer *out;
	struct dirent *dent;
	struct stat st;
	char *path, *path_file;
	int i;
	int hide_dotfiles = con->conf.hide_dotfiles;
	dirls_list_t dirs, files, *list;
	dirls_entry_t *tmp;
	char sizebuf[sizeof("999.9K")];
	char datebuf[sizeof("2005-Jan-01 22:23:24")];
	size_t k;
	const char *content_type;
	long name_max;
#ifdef HAVE_XATTR
	char attrval[128];
	int attrlen;
#endif
#ifdef HAVE_LOCALTIME_R
	struct tm tm;
#endif

	i = dir->used - 1;
	if (i <= 0) return -1;

#ifdef HAVE_PATHCONF
	name_max = pathconf(dir->ptr, _PC_NAME_MAX);
#else
	name_max = NAME_MAX;
#endif
	
	path = malloc(i + name_max + 1);
	assert(path);
	strcpy(path, dir->ptr);
	path_file = path + i;

	if (NULL == (dp = opendir(path))) {
		log_error_write(srv, __FILE__, __LINE__, "sbs", 
			"opendir failed:", dir, strerror(errno));

		free(path);
		return -1;
	}

	dirs.ent   = (dirls_entry_t**) malloc(sizeof(dirls_entry_t*) * DIRLIST_BLOB_SIZE);
	assert(dirs.ent);
	dirs.size  = DIRLIST_BLOB_SIZE;
	dirs.used  = 0;
	files.ent  = (dirls_entry_t**) malloc(sizeof(dirls_entry_t*) * DIRLIST_BLOB_SIZE);
	assert(files.ent);
	files.size = DIRLIST_BLOB_SIZE;
	files.used = 0;

	while ((dent = readdir(dp)) != NULL) {
		if (dent->d_name[0] == '.') {
			if (hide_dotfiles)
				continue;
			if (dent->d_name[1] == '\0')
				continue;
			if (dent->d_name[1] == '.' && dent->d_name[2] == '\0')
				continue;
		}

		/* NOTE: the manual says, d_name is never more than NAME_MAX
		 *       so this should actually not be a buffer-overflow-risk
		 */
		i = strlen(dent->d_name);
		if (i > name_max)
			continue;
		memcpy(path_file, dent->d_name, i + 1);
		if (stat(path, &st) != 0)
			continue;

		list = &files;
		if (S_ISDIR(st.st_mode))
			list = &dirs;

		if (list->used == list->size) {
			list->size += DIRLIST_BLOB_SIZE;
			list->ent   = (dirls_entry_t**) realloc(list->ent, sizeof(dirls_entry_t*) * list->size);
			assert(list->ent);
		}

		tmp = (dirls_entry_t*) malloc(sizeof(dirls_entry_t) + 1 + i);
		tmp->mtime = st.st_mtime;
		tmp->size  = st.st_size;
		tmp->namelen = i;
		memcpy(DIRLIST_ENT_NAME(tmp), dent->d_name, i + 1);

		list->ent[list->used++] = tmp;
	}
	closedir(dp);

	if (dirs.used) http_dirls_sort(dirs.ent, dirs.used);

	if (files.used) http_dirls_sort(files.ent, files.used);

	out = chunkqueue_get_append_buffer(con->write_queue);
	
	if (buffer_is_empty(con->conf.dirlist_encoding)) {
		BUFFER_COPY_STRING_CONST(out, "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n");
	} else {
		BUFFER_COPY_STRING_CONST(out, "<?xml version=\"1.0\" encoding=\"");
		buffer_append_string_buffer(out, con->conf.dirlist_encoding);
		BUFFER_APPEND_STRING_CONST(out, "\"?>\n");
	}
	
	http_list_directory_header(out, con);

	/* directories */
	for (i = 0; i < dirs.used; i++) {
		tmp = dirs.ent[i];

#ifdef HAVE_LOCALTIME_R
		localtime_r(&(tmp->mtime), &tm);
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", &tm);
#else
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", localtime(&(tmp->mtime)));
#endif

		BUFFER_APPEND_STRING_CONST(out, "<tr><td class=\"n\"><a href=\"");
		buffer_append_string_url_encoded(out, DIRLIST_ENT_NAME(tmp));
		BUFFER_APPEND_STRING_CONST(out, "/\">");
		buffer_append_string_html_encoded(out, DIRLIST_ENT_NAME(tmp));
		BUFFER_APPEND_STRING_CONST(out, "</a>/</td><td class=\"m\">");
		buffer_append_string_len(out, datebuf, sizeof(datebuf) - 1);
		BUFFER_APPEND_STRING_CONST(out, "</td><td class=\"s\">- &nbsp;</td><td class=\"t\">Directory</td></tr>\n");

		free(tmp);
	}

	/* files */
	for (i = 0; i < files.used; i++) {
		tmp = files.ent[i];

#ifdef HAVE_XATTR
		content_type = NULL;
		if (con->conf.use_xattr) {
			memcpy(path_file, DIRLIST_ENT_NAME(tmp), tmp->namelen + 1);
			attrlen = sizeof(attrval) - 1;
			if (attr_get(path, "Content-Type", attrval, &attrlen, 0) == 0) {
				attrval[attrlen] = '\0';
				content_type = attrval;
			}
		}
		if (content_type == NULL) {
#else
		if (1) {
#endif
			content_type = "application/octet-stream";
			for (k = 0; k < con->conf.mimetypes->used; k++) {
				data_string *ds = (data_string *)con->conf.mimetypes->data[k];
				size_t ct_len;

				if (ds->key->used == 0)
					continue;

				ct_len = ds->key->used - 1;
				if (tmp->namelen < ct_len)
					continue;

				if (0 == strncmp(DIRLIST_ENT_NAME(tmp) + tmp->namelen - ct_len, ds->key->ptr, ct_len)) {
					content_type = ds->value->ptr;
					break;
				}
			}
		}

#ifdef HAVE_LOCALTIME_R
		localtime_r(&(tmp->mtime), &tm);
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", &tm);
#else
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", localtime(&(tmp->mtime)));
#endif
		http_list_directory_sizefmt(sizebuf, tmp->size);

		BUFFER_APPEND_STRING_CONST(out, "<tr><td class=\"n\"><a href=\"");
		buffer_append_string_url_encoded(out, DIRLIST_ENT_NAME(tmp));
		BUFFER_APPEND_STRING_CONST(out, "\">");
		buffer_append_string_html_encoded(out, DIRLIST_ENT_NAME(tmp));
		BUFFER_APPEND_STRING_CONST(out, "</a></td><td class=\"m\">");
		buffer_append_string_len(out, datebuf, sizeof(datebuf) - 1);
		BUFFER_APPEND_STRING_CONST(out, "</td><td class=\"s\">");
		buffer_append_string(out, sizebuf);
		BUFFER_APPEND_STRING_CONST(out, "</td><td class=\"t\">");
		buffer_append_string(out, content_type);
		BUFFER_APPEND_STRING_CONST(out, "</td></tr>\n");

		free(tmp);
	}

	free(files.ent);
	free(dirs.ent);
	free(path);

	http_list_directory_footer(out, con);
	response_header_insert(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	con->file_finished = 1;

	return 0;
}


int http_response_handle_cachable(server *srv, connection *con, time_t mtime) {
	if (con->http_status != 0) return 0;

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
	if (con->request.http_if_none_match) {
		if (etag_is_equal(con->physical.etag, con->request.http_if_none_match)) {
			if (con->request.http_method == HTTP_METHOD_GET || 
			    con->request.http_method == HTTP_METHOD_HEAD) {
				
				/* check if etag + last-modified */
				if (con->request.http_if_modified_since) {
					char buf[64];
					struct tm tm;
					size_t used_len;
					char *semicolon;
				
					strftime(buf, sizeof(buf)-1, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&mtime));
					
					if (NULL == (semicolon = strchr(con->request.http_if_modified_since, ';'))) {
						used_len = strlen(con->request.http_if_modified_since);
					} else {
						used_len = semicolon - con->request.http_if_modified_since;
					}
					
					if (0 == strncmp(con->request.http_if_modified_since, buf, used_len)) {
						con->http_status = 304;
						return 1;
					} else {
						/* convert to timestamp */
						if (used_len < sizeof(buf) - 1) {
							time_t t;
							strncpy(buf, con->request.http_if_modified_since, used_len);
							buf[used_len] = '\0';
							
							strptime(buf, "%a, %d %b %Y %H:%M:%S GMT", &tm);
							
							if (-1 != (t = mktime(&tm)) &&
							    t <= mtime) {
								con->http_status = 304;
								return 1;
							}
						} else {
							log_error_write(srv, __FILE__, __LINE__, "ss", 
									con->request.http_if_modified_since, buf);
							
							con->http_status = 412;
							return 1;
						}
					}
				} else {
					con->http_status = 304;
					return 1;
				}
			} else {
				con->http_status = 412;	
				return 1;
			}
		}
	} else if (con->request.http_if_modified_since) {
		char buf[64];
		struct tm *tm;
		size_t used_len;
		char *semicolon;
		
		tm = gmtime(&(mtime));
		strftime(buf, sizeof(buf)-1, "%a, %d %b %Y %H:%M:%S GMT", tm);
		
		if (NULL == (semicolon = strchr(con->request.http_if_modified_since, ';'))) {
			used_len = strlen(con->request.http_if_modified_since);
		} else {
			used_len = semicolon - con->request.http_if_modified_since;
		}
		
		if (0 == strncmp(con->request.http_if_modified_since, buf, used_len)) {
			con->http_status = 304;
			return 1;
		}
	}

	return 0;
}

handler_t http_response_prepare(server *srv, connection *con) {
	handler_t r;
	
	if (con->loops_per_request++ > 1000) {
		/* protect us again endless loops in a single request */
		
		log_error_write(srv, __FILE__, __LINE__,  "s",  "ENDLESS LOOP DETECTED ... aborting request");
		
		return HANDLER_ERROR;
	}
	
	/* looks like someone has already done a decision */
	if (con->mode == DIRECT && 
	    (con->http_status != 0 && con->http_status != 200)) {
		/* remove a packets in the queue */
		if (con->file_finished == 0) {
			chunkqueue_reset(con->write_queue);
		}
		
		return HANDLER_FINISHED;
	}

	if (con->request.http_method == HTTP_METHOD_OPTIONS) {
		con->file_finished = 1;
		con->file_started = 1;

		return HANDLER_FINISHED;
	}
	
	/* no decision yet, build conf->filename */
	if (con->mode == DIRECT && con->physical.path->used == 0) {
		char *qstr;
		
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "run condition");
		}
		config_patch_connection(srv, con, COMP_SERVER_SOCKET); /* SERVERsocket */
		
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
	
		buffer_copy_string(con->uri.scheme, con->conf.is_ssl ? "https" : "http");
		buffer_copy_string_buffer(con->uri.authority, con->request.http_host);
		
		config_patch_connection(srv, con, COMP_HTTP_HOST);      /* Host:        */
		config_patch_connection(srv, con, COMP_HTTP_REMOTEIP);  /* Client-IP */
		config_patch_connection(srv, con, COMP_HTTP_REFERER);   /* Referer:     */
		config_patch_connection(srv, con, COMP_HTTP_USERAGENT); /* User-Agent:  */
		config_patch_connection(srv, con, COMP_HTTP_COOKIE);    /* Cookie:  */
		
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
		buffer_urldecode_path(srv->tmp_buf);
		buffer_path_simplify(con->uri.path, srv->tmp_buf);

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- sanitising URI");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path     : ", con->uri.path);
		}

		/**
		 *  
		 * call plugins 
		 * 
		 * - based on the clean URL
		 * 
		 */
		
		config_patch_connection(srv, con, COMP_HTTP_URL); /* HTTPurl */
		
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
		
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- before doc_root");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
		}

		/* the docroot plugin should set the doc_root and might also set the physical.path
		 * for us (all vhost-plugins are supposed to set the doc_root)
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

		/* the docroot plugins might set the servername, if they don't we take http-host */
		if (buffer_is_empty(con->server_name)) {
			buffer_copy_string_buffer(con->server_name, con->uri.authority);
		}
		
		/** 
		 * create physical filename 
		 * -> physical.path = docroot + rel_path
		 * 
		 */
		
		buffer_copy_string_buffer(con->physical.path, con->physical.doc_root);
		BUFFER_APPEND_SLASH(con->physical.path);
		buffer_copy_string_buffer(con->physical.basedir, con->physical.path);
		if (con->physical.rel_path->ptr[0] == '/') {
			buffer_append_string_len(con->physical.path, con->physical.rel_path->ptr + 1, con->physical.rel_path->used - 2);
		} else {
			buffer_append_string_buffer(con->physical.path, con->physical.rel_path);
		}

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- after doc_root");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}

		switch(r = plugins_call_handle_physical(srv, con)) {
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
		
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- logical -> physical");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Server-Name  :", con->server_name);
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
		stat_cache_entry *sce = NULL;
		
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling physical path");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}
		
		switch (stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
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
			buffer_copy_string_buffer(srv->tmp_buf, con->physical.path);
			
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
				
				if (slash) {
					buffer_copy_string_len(con->physical.path, srv->tmp_buf->ptr, slash - srv->tmp_buf->ptr);
				} else {
					buffer_copy_string_buffer(con->physical.path, srv->tmp_buf);
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
			} while ((found == 0) && (slash != NULL) && (slash - srv->tmp_buf->ptr > con->physical.basedir->used - 2));
			
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
				
				con->uri.path->used -= con->request.pathinfo->used - 1;
				con->uri.path->ptr[con->uri.path->used - 1] = '\0';
			}
			
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- after pathinfo check");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				log_error_write(srv, __FILE__, __LINE__,  "sb", "URI          :", con->uri.path);
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Pathinfo     :", con->request.pathinfo);
			}
			
			/* setup the right file cache entry (FCE) */
			switch (stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
			case HANDLER_ERROR:
				con->http_status = 404;
				
				if (con->conf.log_file_not_found) {
					log_error_write(srv, __FILE__, __LINE__, "sbsb",
						"file not found:", con->uri.path,
						"->", con->physical.path);
				}
				
				return HANDLER_FINISHED;
			case HANDLER_GO_ON:
			default:
				break;
			}
			
			break;
		case HANDLER_GO_ON:
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- file found");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			}
			
			if (S_ISDIR(sce->st.st_mode)) {
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
						
						switch (stat_cache_get_entry(srv, con, srv->tmp_buf, &sce)) {
						case HANDLER_COMEBACK:
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
		
		if (!S_ISREG(sce->st.st_mode)) {
			con->http_status = 404;
			
			if (con->conf.log_file_not_found) {
				log_error_write(srv, __FILE__, __LINE__, "sbsb",
					"not a regular file:", con->uri.path,
					"->", sce->name);
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

			if (buffer_is_empty(sce->content_type)) {
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("application/octet-stream"));
			} else {
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(sce->content_type));
			}
			
			/* generate e-tag */
			etag_mutate(con->physical.etag, sce->etag);

			http_response_handle_cachable(srv, con, sce->st.st_mtime);
						
			if (con->conf.range_requests &&
			    con->http_status == 0 && 
			    con->request.http_range) {
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
