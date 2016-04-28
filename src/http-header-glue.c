#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"
#include "etag.h"
#include "http_chunk.h"
#include "response.h"
#include "stat_cache.h"

#include <string.h>
#include <errno.h>

#include <time.h>

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

int response_header_append(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen) {
	data_string *ds;

	UNUSED(srv);

	/* if there already is a key by this name append the value */
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, key))) {
		buffer_append_string_len(ds->value, CONST_STR_LEN(", "));
		buffer_append_string_len(ds->value, value, vallen);
		return 0;
	}

	return response_header_insert(srv, con, key, keylen, value, vallen);
}

int http_response_redirect_to_directory(server *srv, connection *con) {
	buffer *o;

	o = buffer_init();

	buffer_copy_buffer(o, con->uri.scheme);
	buffer_append_string_len(o, CONST_STR_LEN("://"));
	if (!buffer_is_empty(con->uri.authority)) {
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

		if (-1 == getsockname(con->fd, (struct sockaddr *)&our_addr, &our_addr_len)
		    || our_addr_len > sizeof(our_addr)) {
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
						"SSS", "NOTICE: getnameinfo failed: ",
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
						"SdS", "NOTICE: gethostbyaddr failed: ",
						h_errno, ", using ip-address instead");

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

		{
			unsigned short default_port = 80;
			if (buffer_is_equal_caseless_string(con->uri.scheme, CONST_STR_LEN("https"))) {
				default_port = 443;
			}
			if (default_port != srv->srvconf.port) {
				buffer_append_string_len(o, CONST_STR_LEN(":"));
				buffer_append_int(o, srv->srvconf.port);
			}
		}
	}
	buffer_append_string_encoded(o, CONST_BUF_LEN(con->uri.path), ENCODING_REL_URI);
	buffer_append_string_len(o, CONST_STR_LEN("/"));
	if (!buffer_string_is_empty(con->uri.query)) {
		buffer_append_string_len(o, CONST_STR_LEN("?"));
		buffer_append_string_buffer(o, con->uri.query);
	}

	response_header_insert(srv, con, CONST_STR_LEN("Location"), CONST_BUF_LEN(o));

	con->http_status = 301;
	con->file_finished = 1;

	buffer_free(o);

	return 0;
}

buffer * strftime_cache_get(server *srv, time_t last_mod) {
	struct tm *tm;
	size_t i;

	for (i = 0; i < FILE_CACHE_MAX; i++) {
		/* found cache-entry */
		if (srv->mtime_cache[i].mtime == last_mod) return srv->mtime_cache[i].str;

		/* found empty slot */
		if (srv->mtime_cache[i].mtime == 0) break;
	}

	if (i == FILE_CACHE_MAX) {
		i = 0;
	}

	srv->mtime_cache[i].mtime = last_mod;
	buffer_string_prepare_copy(srv->mtime_cache[i].str, 1023);
	tm = gmtime(&(srv->mtime_cache[i].mtime));
	buffer_append_strftime(srv->mtime_cache[i].str, "%a, %d %b %Y %H:%M:%S GMT", tm);

	return srv->mtime_cache[i].str;
}


int http_response_handle_cachable(server *srv, connection *con, buffer *mtime) {
	int head_or_get =
		(  HTTP_METHOD_GET  == con->request.http_method
		|| HTTP_METHOD_HEAD == con->request.http_method);
	UNUSED(srv);

	/*
	 * 14.26 If-None-Match
	 *    [...]
	 *    If none of the entity tags match, then the server MAY perform the
	 *    requested method as if the If-None-Match header field did not exist,
	 *    but MUST also ignore any If-Modified-Since header field(s) in the
	 *    request. That is, if no entity tags match, then the server MUST NOT
	 *    return a 304 (Not Modified) response.
	 */

	if (con->request.http_if_none_match) {
		/* use strong etag checking for now: weak comparison must not be used
		 * for ranged requests
		 */
		if (etag_is_equal(con->physical.etag, con->request.http_if_none_match, 0)) {
			if (head_or_get) {
				con->http_status = 304;
				return HANDLER_FINISHED;
			} else {
				con->http_status = 412;
				con->mode = DIRECT;
				return HANDLER_FINISHED;
			}
		}
	} else if (con->request.http_if_modified_since && head_or_get) {
		/* last-modified handling */
		size_t used_len;
		char *semicolon;

		if (NULL == (semicolon = strchr(con->request.http_if_modified_since, ';'))) {
			used_len = strlen(con->request.http_if_modified_since);
		} else {
			used_len = semicolon - con->request.http_if_modified_since;
		}

		if (0 == strncmp(con->request.http_if_modified_since, mtime->ptr, used_len)) {
			if ('\0' == mtime->ptr[used_len]) con->http_status = 304;
			return HANDLER_FINISHED;
		} else {
			char buf[sizeof("Sat, 23 Jul 2005 21:20:01 GMT")];
			time_t t_header, t_file;
			struct tm tm;

			/* convert to timestamp */
			if (used_len >= sizeof(buf)) return HANDLER_GO_ON;

			strncpy(buf, con->request.http_if_modified_since, used_len);
			buf[used_len] = '\0';

			if (NULL == strptime(buf, "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
				/**
				 * parsing failed, let's get out of here 
				 */
				return HANDLER_GO_ON;
			}
			tm.tm_isdst = 0;
			t_header = mktime(&tm);

			strptime(mtime->ptr, "%a, %d %b %Y %H:%M:%S GMT", &tm);
			tm.tm_isdst = 0;
			t_file = mktime(&tm);

			if (t_file > t_header) return HANDLER_GO_ON;

			con->http_status = 304;
			return HANDLER_FINISHED;
		}
	}

	return HANDLER_GO_ON;
}


static int http_response_parse_range(server *srv, connection *con, buffer *path, stat_cache_entry *sce) {
	int multipart = 0;
	int error;
	off_t start, end;
	const char *s, *minus;
	char *boundary = "fkj49sn38dcn3";
	data_string *ds;
	buffer *content_type = NULL;

	start = 0;
	end = sce->st.st_size - 1;

	con->response.content_length = 0;

	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, "Content-Type"))) {
		content_type = ds->value;
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

				end = sce->st.st_size - 1;
				start = sce->st.st_size + le;
			} else if (*err == ',') {
				multipart = 1;
				s = err + 1;

				end = sce->st.st_size - 1;
				start = sce->st.st_size + le;
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

					end = sce->st.st_size - 1;
					start = la;

				} else if (*(err + 1) == ',') {
					multipart = 1;
					s = err + 2;

					end = sce->st.st_size - 1;
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
			if (end > sce->st.st_size - 1) end = sce->st.st_size - 1;

			if (start > sce->st.st_size - 1) {
				error = 1;

				con->http_status = 416;
			}
		}

		if (!error) {
			if (multipart) {
				/* write boundary-header */
				buffer *b = buffer_init();

				buffer_copy_string_len(b, CONST_STR_LEN("\r\n--"));
				buffer_append_string(b, boundary);

				/* write Content-Range */
				buffer_append_string_len(b, CONST_STR_LEN("\r\nContent-Range: bytes "));
				buffer_append_int(b, start);
				buffer_append_string_len(b, CONST_STR_LEN("-"));
				buffer_append_int(b, end);
				buffer_append_string_len(b, CONST_STR_LEN("/"));
				buffer_append_int(b, sce->st.st_size);

				buffer_append_string_len(b, CONST_STR_LEN("\r\nContent-Type: "));
				buffer_append_string_buffer(b, content_type);

				/* write END-OF-HEADER */
				buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

				con->response.content_length += buffer_string_length(b);
				chunkqueue_append_buffer(con->write_queue, b);
				buffer_free(b);
			}

			chunkqueue_append_file(con->write_queue, path, start, end - start + 1);
			con->response.content_length += end - start + 1;
		}
	}

	/* something went wrong */
	if (error) return -1;

	if (multipart) {
		/* add boundary end */
		buffer *b = buffer_init();

		buffer_copy_string_len(b, "\r\n--", 4);
		buffer_append_string(b, boundary);
		buffer_append_string_len(b, "--\r\n", 4);

		con->response.content_length += buffer_string_length(b);
		chunkqueue_append_buffer(con->write_queue, b);
		buffer_free(b);

		/* set header-fields */

		buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("multipart/byteranges; boundary="));
		buffer_append_string(srv->tmp_buf, boundary);

		/* overwrite content-type */
		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(srv->tmp_buf));
	} else {
		/* add Content-Range-header */

		buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("bytes "));
		buffer_append_int(srv->tmp_buf, start);
		buffer_append_string_len(srv->tmp_buf, CONST_STR_LEN("-"));
		buffer_append_int(srv->tmp_buf, end);
		buffer_append_string_len(srv->tmp_buf, CONST_STR_LEN("/"));
		buffer_append_int(srv->tmp_buf, sce->st.st_size);

		response_header_insert(srv, con, CONST_STR_LEN("Content-Range"), CONST_BUF_LEN(srv->tmp_buf));
	}

	/* ok, the file is set-up */
	return 0;
}


void http_response_send_file (server *srv, connection *con, buffer *path) {
	stat_cache_entry *sce = NULL;
	buffer *mtime = NULL;
	data_string *ds;
	int allow_caching = (0 == con->http_status || 200 == con->http_status);

	if (HANDLER_ERROR == stat_cache_get_entry(srv, con, path, &sce)) {
		con->http_status = (errno == ENOENT) ? 404 : 403;

		log_error_write(srv, __FILE__, __LINE__, "sbsb",
				"not a regular file:", con->uri.path,
				"->", path);

		return;
	}

	/* we only handline regular files */
#ifdef HAVE_LSTAT
	if ((sce->is_symlink == 1) && !con->conf.follow_symlink) {
		con->http_status = 403;

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- access denied due symlink restriction");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", path);
		}

		return;
	}
#endif
	if (!S_ISREG(sce->st.st_mode)) {
		con->http_status = 403;

		if (con->conf.log_file_not_found) {
			log_error_write(srv, __FILE__, __LINE__, "sbsb",
					"not a regular file:", con->uri.path,
					"->", sce->name);
		}

		return;
	}

	/* mod_compress might set several data directly, don't overwrite them */

	/* set response content-type, if not set already */

	if (NULL == array_get_element(con->response.headers, "Content-Type")) {
		if (buffer_string_is_empty(sce->content_type)) {
			/* we are setting application/octet-stream, but also announce that
			 * this header field might change in the seconds few requests
			 *
			 * This should fix the aggressive caching of FF and the script download
			 * seen by the first installations
			 */
			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("application/octet-stream"));

			allow_caching = 0;
		} else {
			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(sce->content_type));
		}
	}

	if (con->conf.range_requests) {
		response_header_overwrite(srv, con, CONST_STR_LEN("Accept-Ranges"), CONST_STR_LEN("bytes"));
	}

	if (allow_caching) {
		if (con->etag_flags != 0 && !buffer_string_is_empty(sce->etag)) {
			if (NULL == array_get_element(con->response.headers, "ETag")) {
				/* generate e-tag */
				etag_mutate(con->physical.etag, sce->etag);

				response_header_overwrite(srv, con, CONST_STR_LEN("ETag"), CONST_BUF_LEN(con->physical.etag));
			}
		}

		/* prepare header */
		if (NULL == (ds = (data_string *)array_get_element(con->response.headers, "Last-Modified"))) {
			mtime = strftime_cache_get(srv, sce->st.st_mtime);
			response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
		} else {
			mtime = ds->value;
		}

		if (HANDLER_FINISHED == http_response_handle_cachable(srv, con, mtime)) {
			return;
		}
	}

	if (con->request.http_range && con->conf.range_requests
	    && (200 == con->http_status || 0 == con->http_status)
	    && NULL == array_get_element(con->response.headers, "Content-Encoding")) {
		int do_range_request = 1;
		/* check if we have a conditional GET */

		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "If-Range"))) {
			/* if the value is the same as our ETag, we do a Range-request,
			 * otherwise a full 200 */

			if (ds->value->ptr[0] == '"') {
				/**
				 * client wants a ETag
				 */
				if (!con->physical.etag) {
					do_range_request = 0;
				} else if (!buffer_is_equal(ds->value, con->physical.etag)) {
					do_range_request = 0;
				}
			} else if (!mtime) {
				/**
				 * we don't have a Last-Modified and can match the If-Range:
				 *
				 * sending all
				 */
				do_range_request = 0;
			} else if (!buffer_is_equal(ds->value, mtime)) {
				do_range_request = 0;
			}
		}

		if (do_range_request) {
			/* content prepared, I'm done */
			con->file_finished = 1;

			if (0 == http_response_parse_range(srv, con, path, sce)) {
				con->http_status = 206;
			}
			return;
		}
	}

	/* if we are still here, prepare body */

	/* we add it here for all requests
	 * the HEAD request will drop it afterwards again
	 */
	if (0 == sce->st.st_size || 0 == http_chunk_append_file(srv, con, path)) {
		con->http_status = 200;
		con->file_finished = 1;
	} else {
		con->http_status = 403;
	}
}

void http_response_xsendfile (server *srv, connection *con, buffer *path, const array *xdocroot) {
	const int status = con->http_status;
	int valid = 1;

	/* reset Content-Length, if set by backend
	 * Content-Length might later be set to size of X-Sendfile static file,
	 * determined by open(), fstat() to reduces race conditions if the file
	 * is modified between stat() (stat_cache_get_entry()) and open(). */
	if (con->parsed_response & HTTP_CONTENT_LENGTH) {
		data_string *ds = (data_string *) array_get_element(con->response.headers, "Content-Length");
		if (ds) buffer_reset(ds->value);
		con->parsed_response &= ~HTTP_CONTENT_LENGTH;
		con->response.content_length = -1;
	}

	buffer_urldecode_path(path);
	buffer_path_simplify(path, path);
	if (con->conf.force_lowercase_filenames) {
		buffer_to_lower(path);
	}

	/* check that path is under xdocroot(s)
	 * - xdocroot should have trailing slash appended at config time
	 * - con->conf.force_lowercase_filenames is not a server-wide setting,
	 *   and so can not be definitively applied to xdocroot at config time*/
	if (xdocroot->used) {
		size_t i, xlen = buffer_string_length(path);
		for (i = 0; i < xdocroot->used; ++i) {
			data_string *ds = (data_string *)xdocroot->data[i];
			size_t dlen = buffer_string_length(ds->value);
			if (dlen <= xlen
			    && (!con->conf.force_lowercase_filenames
				? 0 == memcmp(path->ptr, ds->value->ptr, dlen)
				: 0 == strncasecmp(path->ptr, ds->value->ptr, dlen))) {
				break;
			}
		}
		if (i == xdocroot->used) {
			log_error_write(srv, __FILE__, __LINE__, "SBs",
					"X-Sendfile (", path,
					") not under configured x-sendfile-docroot(s)");
			con->http_status = 403;
			valid = 0;
		}
	}

	if (valid) http_response_send_file(srv, con, path);

	if (con->http_status >= 400 && status < 300) {
		con->mode = DIRECT;
	} else if (0 != status && 200 != status) {
		con->http_status = status;
	}
}
