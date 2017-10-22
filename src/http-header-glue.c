#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "fdevent.h"
#include "log.h"
#include "etag.h"
#include "http_chunk.h"
#include "inet_ntop_cache.h"
#include "response.h"
#include "stat_cache.h"

#include <string.h>
#include <errno.h>

#include <time.h>

#include "sys-strings.h"
#include "sys-socket.h"
#include <unistd.h>


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
	if (NULL != (ds = (data_string *)array_get_element_klen(con->response.headers, key, keylen))) {
		buffer_copy_string_len(ds->value, value, vallen);

		return 0;
	}

	return response_header_insert(srv, con, key, keylen, value, vallen);
}

int response_header_append(server *srv, connection *con, const char *key, size_t keylen, const char *value, size_t vallen) {
	data_string *ds;

	UNUSED(srv);

	/* if there already is a key by this name append the value */
	if (NULL != (ds = (data_string *)array_get_element_klen(con->response.headers, key, keylen))) {
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
		sock_addr our_addr;
		socklen_t our_addr_len;

		our_addr_len = sizeof(our_addr);

		if (-1 == getsockname(con->fd, (struct sockaddr *)&our_addr, &our_addr_len)
		    || our_addr_len > (socklen_t)sizeof(our_addr)) {
			con->http_status = 500;

			log_error_write(srv, __FILE__, __LINE__, "ss",
					"can't get sockname", strerror(errno));

			buffer_free(o);
			return 0;
		}

		/* Lookup name: secondly try to get hostname for bind address */
		if (0 != sock_addr_nameinfo_append_buffer(srv, o, &our_addr)) {
			con->http_status = 500;
			buffer_free(o);
			return -1;
		} else {
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
	static int i;
	struct tm *tm;

	for (int j = 0; j < FILE_CACHE_MAX; ++j) {
		if (srv->mtime_cache[j].mtime == last_mod)
			return srv->mtime_cache[j].str; /* found cache-entry */
	}

	if (++i == FILE_CACHE_MAX) {
		i = 0;
	}

	srv->mtime_cache[i].mtime = last_mod;
	tm = gmtime(&(srv->mtime_cache[i].mtime));
	buffer_string_set_length(srv->mtime_cache[i].str, 0);
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


static void http_response_xsendfile (server *srv, connection *con, buffer *path, const array *xdocroot) {
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


static void http_response_xsendfile2(server *srv, connection *con, const buffer *value, const array *xdocroot) {
    const char *pos = value->ptr;
    buffer *b = srv->tmp_buf;
    const int status = con->http_status;

    /* reset Content-Length, if set by backend */
    if (con->parsed_response & HTTP_CONTENT_LENGTH) {
        data_string *ds = (data_string *)
          array_get_element(con->response.headers, "Content-Length");
        if (ds) buffer_reset(ds->value);
        con->parsed_response &= ~HTTP_CONTENT_LENGTH;
        con->response.content_length = -1;
    }

    while (*pos) {
        const char *filename, *range;
        stat_cache_entry *sce;
        off_t begin_range, end_range, range_len;

        while (' ' == *pos) pos++;
        if (!*pos) break;

        filename = pos;
        if (NULL == (range = strchr(pos, ' '))) {
            /* missing range */
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "Couldn't find range after filename:", filename);
            con->http_status = 502;
            break;
        }
        buffer_copy_string_len(b, filename, range - filename);

        /* find end of range */
        for (pos = ++range; *pos && *pos != ' ' && *pos != ','; pos++) ;

        buffer_urldecode_path(b);
        buffer_path_simplify(b, b);
        if (con->conf.force_lowercase_filenames) {
            buffer_to_lower(b);
        }
        if (xdocroot->used) {
            size_t i, xlen = buffer_string_length(b);
            for (i = 0; i < xdocroot->used; ++i) {
                data_string *ds = (data_string *)xdocroot->data[i];
                size_t dlen = buffer_string_length(ds->value);
                if (dlen <= xlen
                    && (!con->conf.force_lowercase_filenames
                    ? 0 == memcmp(b->ptr, ds->value->ptr, dlen)
                    : 0 == strncasecmp(b->ptr, ds->value->ptr, dlen))) {
                    break;
                }
            }
            if (i == xdocroot->used) {
                log_error_write(srv, __FILE__, __LINE__, "SBs",
                                "X-Sendfile2 (", b,
                                ") not under configured x-sendfile-docroot(s)");
                con->http_status = 403;
                break;
            }
        }

        if (HANDLER_ERROR == stat_cache_get_entry(srv, con, b, &sce)) {
            log_error_write(srv, __FILE__, __LINE__, "sb", "send-file error: "
                            "couldn't get stat_cache entry for X-Sendfile2:",
                            b);
            con->http_status = 404;
            break;
        } else if (!S_ISREG(sce->st.st_mode)) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "send-file error: wrong filetype for X-Sendfile2:",
                            b);
            con->http_status = 502;
            break;
        }
        /* found the file */

        /* parse range */
        end_range = sce->st.st_size - 1;
        {
            char *rpos = NULL;
            errno = 0;
            begin_range = strtoll(range, &rpos, 10);
            if (errno != 0 || begin_range < 0 || rpos == range)
                goto range_failed;
            if ('-' != *rpos++) goto range_failed;
            if (rpos != pos) {
                range = rpos;
                end_range = strtoll(range, &rpos, 10);
                if (errno != 0 || end_range < 0 || rpos == range)
                    goto range_failed;
            }
            if (rpos != pos) goto range_failed;

            goto range_success;

range_failed:
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "Couldn't decode range after filename:", filename);
            con->http_status = 502;
            break;

range_success: ;
        }

        /* no parameters accepted */

        while (*pos == ' ') pos++;
        if (*pos != '\0' && *pos != ',') {
            con->http_status = 502;
            break;
        }

        range_len = end_range - begin_range + 1;
        if (range_len < 0) {
            con->http_status = 502;
            break;
        }
        if (range_len != 0) {
            if (0 != http_chunk_append_file_range(srv, con, b,
                                                  begin_range, range_len)) {
                con->http_status = 502;
                break;
            }
        }

        if (*pos == ',') pos++;
    }

    if (con->http_status >= 400 && status < 300) {
        con->mode = DIRECT;
    } else if (0 != status && 200 != status) {
        con->http_status = status;
    }
}


void http_response_backend_error (server *srv, connection *con) {
	UNUSED(srv);
	if (con->file_started) {
		/*(response might have been already started, kill the connection)*/
		/*(mode == DIRECT to avoid later call to http_response_backend_done())*/
		con->mode = DIRECT;  /*(avoid sending final chunked block)*/
		con->keep_alive = 0; /*(no keep-alive; final chunked block not sent)*/
		con->file_finished = 1;
	} /*(else error status set later by http_response_backend_done())*/
}

void http_response_backend_done (server *srv, connection *con) {
	/* (not CON_STATE_ERROR and not CON_STATE_RESPONSE_END,
	 *  i.e. not called from handle_connection_close or connection_reset
	 *  hooks, except maybe from errdoc handler, which later resets state)*/
	switch (con->state) {
	case CON_STATE_HANDLE_REQUEST:
	case CON_STATE_READ_POST:
		if (!con->file_started) {
			/* Send an error if we haven't sent any data yet */
			con->http_status = 500;
			con->mode = DIRECT;
			break;
		} /* else fall through */
	case CON_STATE_WRITE:
		if (!con->file_finished) {
			http_chunk_close(srv, con);
			con->file_finished = 1;
		}
	default:
		break;
	}
}


void http_response_upgrade_read_body_unknown(server *srv, connection *con) {
    /* act as transparent proxy */
    UNUSED(srv);
    if (!(con->conf.stream_request_body & FDEVENT_STREAM_REQUEST))
        con->conf.stream_request_body |=
          (FDEVENT_STREAM_REQUEST_BUFMIN | FDEVENT_STREAM_REQUEST);
    if (!(con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE))
        con->conf.stream_response_body |=
          (FDEVENT_STREAM_RESPONSE_BUFMIN | FDEVENT_STREAM_RESPONSE);
    con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
    con->request.content_length = -2;
    con->keep_alive = 0;
}


static handler_t http_response_process_local_redir(server *srv, connection *con, size_t blen) {
    /* [RFC3875] The Common Gateway Interface (CGI) Version 1.1
     * [RFC3875] 6.2.2 Local Redirect Response
     *
     *    The CGI script can return a URI path and query-string
     *    ('local-pathquery') for a local resource in a Location header field.
     *    This indicates to the server that it should reprocess the request
     *    using the path specified.
     *
     *      local-redir-response = local-Location NL
     *
     *    The script MUST NOT return any other header fields or a message-body,
     *    and the server MUST generate the response that it would have produced
     *    in response to a request containing the URL
     *
     *      scheme "://" server-name ":" server-port local-pathquery
     *
     * (Might not have begun to receive body yet, but do skip local-redir
     *  if we already have started receiving a response body (blen > 0))
     * (Also, while not required by the RFC, do not send local-redir back
     *  to same URL, since CGI should have handled it internally if it
     *  really wanted to do that internally)
     */

    /* con->http_status >= 300 && con->http_status < 400) */
    size_t ulen = buffer_string_length(con->uri.path);
    data_string *ds = (data_string *)
      array_get_element(con->response.headers, "Location");
    if (NULL != ds
        && ds->value->ptr[0] == '/'
        && (0 != strncmp(ds->value->ptr, con->uri.path->ptr, ulen)
            || (ds->value->ptr[ulen] != '\0'
                && ds->value->ptr[ulen] != '/'
                && ds->value->ptr[ulen] != '?'))
        && 0 == blen
        && !(con->parsed_response & HTTP_STATUS) /*no "Status" or NPH response*/
        && 1 == con->response.headers->used) {
        if (++con->loops_per_request > 5) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "too many internal loops while processing request:",
                            con->request.orig_uri);
            con->http_status = 500; /* Internal Server Error */
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }

        buffer_copy_buffer(con->request.uri, ds->value);

        if (con->request.content_length) {
            if (con->request.content_length
                != con->request_content_queue->bytes_in) {
                con->keep_alive = 0;
            }
            con->request.content_length = 0;
            chunkqueue_reset(con->request_content_queue);
        }

        if (con->http_status != 307 && con->http_status != 308) {
            /* Note: request body (if any) sent to initial dynamic handler
             * and is not available to the internal redirect */
            con->request.http_method = HTTP_METHOD_GET;
        }

        /*(caller must reset request as follows)*/
        /*connection_response_reset(srv, con);*/ /*(sets con->http_status = 0)*/
        /*plugins_call_connection_reset(srv, con);*/

        return HANDLER_COMEBACK;
    }

    return HANDLER_GO_ON;
}


static int http_response_process_headers(server *srv, connection *con, http_response_opts *opts, buffer *hdrs) {
    char *ns;
    const char *s;
    int line = 0;

    for (s = hdrs->ptr; NULL != (ns = strchr(s, '\n')); s = ns + 1, ++line) {
        const char *key, *value;
        int key_len;
        data_string *ds;

        /* strip the \n */
        ns[0] = '\0';
        if (ns > s && ns[-1] == '\r') ns[-1] = '\0';

        if (0 == line && 0 == strncmp(s, "HTTP/1.", 7)) {
            /* non-parsed headers ... we parse them anyway */
            if ((s[7] == '1' || s[7] == '0') && s[8] == ' ') {
                /* after the space should be a status code for us */
                int status = strtol(s+9, NULL, 10);
                if (status >= 100 && status < 1000) {
                    con->parsed_response |= HTTP_STATUS;
                    con->http_status = status;
                } /* else we expected 3 digits and didn't get them */
            }

            if (0 == con->http_status) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "invalid HTTP status line:", s);
                con->http_status = 502; /* Bad Gateway */
                con->mode = DIRECT;
                return -1;
            }

            continue;
        }

        /* parse the headers */
        key = s;
        if (NULL == (value = strchr(s, ':'))) {
            /* we expect: "<key>: <value>\r\n" */
            continue;
        }

        key_len = value - key;
        do { ++value; } while (*value == ' ' || *value == '\t'); /* skip LWS */

        if (opts->authorizer) {
            if (0 == con->http_status || 200 == con->http_status) {
                if (key_len == 6 && 0 == strncasecmp(key, "Status", key_len)) {
                    int status = strtol(value, NULL, 10);
                    if (status >= 100 && status < 1000) {
                        con->http_status = status;
                    } else {
                        con->http_status = 502; /* Bad Gateway */
                        break;
                    }
                } else if (key_len > 9
                           && 0==strncasecmp(key, CONST_STR_LEN("Variable-"))) {
                    ds = (data_string *)
                      array_get_unused_element(con->environment, TYPE_STRING);
                    if (NULL == ds) ds = data_string_init();
                    buffer_copy_string_len(ds->key, key + 9, key_len - 9);
                    buffer_copy_string(ds->value, value);

                    array_insert_unique(con->environment, (data_unset *)ds);
                }
                continue;
            }
        }

        switch(key_len) {
        case 4:
            if (0 == strncasecmp(key, "Date", key_len)) {
                con->parsed_response |= HTTP_DATE;
            }
            break;
        case 6:
            if (0 == strncasecmp(key, "Status", key_len)) {
                int status;
                if (opts->backend == BACKEND_PROXY) break; /*(pass w/o parse)*/
                status = strtol(value, NULL, 10);
                if (status >= 100 && status < 1000) {
                    con->http_status = status;
                    con->parsed_response |= HTTP_STATUS;
                } else {
                    con->http_status = 502;
                    con->mode = DIRECT;
                }
                continue; /* do not send Status to client */
            }
            break;
        case 7:
            if (0 == strncasecmp(key, "Upgrade", key_len)) {
                /*(technically, should also verify Connection: upgrade)*/
                /*(flag only for mod_proxy and mod_cgi (for now))*/
                if (opts->backend == BACKEND_PROXY
                    || opts->backend == BACKEND_CGI) {
                    con->parsed_response |= HTTP_UPGRADE;
                }
            }
            break;
        case 8:
            if (0 == strncasecmp(key, "Location", key_len)) {
                con->parsed_response |= HTTP_LOCATION;
            }
            break;
        case 10:
            if (0 == strncasecmp(key, "Connection", key_len)) {
                if (opts->backend == BACKEND_PROXY) continue;
                con->response.keep_alive =
                  (0 == strcasecmp(value, "Keep-Alive")) ? 1 : 0;
                con->parsed_response |= HTTP_CONNECTION;
            }
            else if (0 == strncasecmp(key, "Set-Cookie", key_len)) {
                con->parsed_response |= HTTP_SET_COOKIE;
            }
            break;
        case 14:
            if (0 == strncasecmp(key, "Content-Length", key_len)) {
                con->response.content_length = strtoul(value, NULL, 10);
                con->parsed_response |= HTTP_CONTENT_LENGTH;
            }
            break;
        case 16:
            if (0 == strncasecmp(key, "Content-Location", key_len)) {
                con->parsed_response |= HTTP_CONTENT_LOCATION;
            }
            break;
        case 17:
            if (0 == strncasecmp(key, "Transfer-Encoding", key_len)) {
                if (opts->backend == BACKEND_PROXY) continue;
                con->parsed_response |= HTTP_TRANSFER_ENCODING;
            }
            break;
        default:
            break;
        }

        ds = (data_string *)
          array_get_unused_element(con->response.headers, TYPE_STRING);
        if (NULL == ds) ds = data_response_init();
        buffer_copy_string_len(ds->key, key, key_len);
        buffer_copy_string(ds->value, value);

        array_insert_unique(con->response.headers, (data_unset *)ds);
    }

    /* CGI/1.1 rev 03 - 7.2.1.2 */
    /* (proxy requires Status-Line, so never true for proxy)*/
    if ((con->parsed_response & HTTP_LOCATION) &&
        !(con->parsed_response & HTTP_STATUS)) {
        con->http_status = 302;
    }

    return 0;
}


handler_t http_response_parse_headers(server *srv, connection *con, http_response_opts *opts, buffer *b) {
    /**
     * possible formats of response headers:
     *
     * proxy or NPH (non-parsed headers):
     *
     *   HTTP/1.0 200 Ok\n
     *   Header: Value\n
     *   \n
     *
     * CGI:
     *
     *   Header: Value\n
     *   Status: 200\n
     *   \n
     *
     * and different mixes of \n and \r\n combinations
     *
     * Some users also forget about CGI and just send a response
     * and hope we handle it. No headers, no header-content separator
     */

    int is_nph = (0 == strncmp(b->ptr, "HTTP/1.", 7)); /*nph (non-parsed hdrs)*/
    int is_header_end = 0;
    size_t last_eol = 0;
    size_t i = 0, header_len = buffer_string_length(b);
    const char *bstart;
    size_t blen;

    if (b->ptr[0] == '\n' || (b->ptr[0] == '\r' && b->ptr[1] == '\n')) {
        /* no HTTP headers */
        i = (b->ptr[0] == '\n') ? 1 : 2;
        is_header_end = 1;
    } else if (is_nph || b->ptr[(i = strcspn(b->ptr, ":\n"))] == ':') {
        /* HTTP headers */
        ++i;
        for (char *c; NULL != (c = strchr(b->ptr+i, '\n')); ++i) {
            i = (uintptr_t)(c - b->ptr);
            /**
             * check if we saw a \n(\r)?\n sequence
             */
            if (last_eol > 0 &&
                ((i - last_eol == 1) ||
                 (i - last_eol == 2 && b->ptr[i - 1] == '\r'))) {
                is_header_end = 1;
                break;
            }

            last_eol = i;
        }
    } else if (opts->backend == BACKEND_CGI) {
        /* no HTTP headers, but a body (special-case for CGI compat) */
        /* no colon found; does not appear to be HTTP headers */
        if (0 != http_chunk_append_buffer(srv, con, b)) {
            return HANDLER_ERROR;
        }
        con->http_status = 200; /* OK */
        con->file_started = 1;
        return HANDLER_GO_ON;
    } else {
        /* invalid response headers */
        con->http_status = 502; /* Bad Gateway */
        con->mode = DIRECT;
        return HANDLER_FINISHED;
    }

    if (!is_header_end) {
        /*(reuse MAX_HTTP_REQUEST_HEADER as max size
         * for response headers from backends)*/
        if (header_len > MAX_HTTP_REQUEST_HEADER) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "response headers too large for", con->uri.path);
            con->http_status = 502; /* Bad Gateway */
            con->mode = DIRECT;
            return HANDLER_FINISHED;
        }
        return HANDLER_GO_ON;
    }

    /* the body starts after the EOL */
    bstart = b->ptr + (i + 1);
    blen = header_len - (i + 1);

    /* strip the last \r?\n */
    if (i > 0 && (b->ptr[i - 1] == '\r')) {
        i--;
    }

    buffer_string_set_length(b, i);

    if (opts->backend == BACKEND_PROXY && !is_nph) {
        /* invalid response Status-Line from HTTP proxy */
        con->http_status = 502; /* Bad Gateway */
        con->mode = DIRECT;
        return HANDLER_FINISHED;
    }

    if (0 != http_response_process_headers(srv, con, opts, b)) {
        return HANDLER_ERROR;
    }

    con->file_started = 1;

    if (opts->authorizer
        && (con->http_status == 0 || con->http_status == 200)) {
        return HANDLER_GO_ON;
    }

    if (con->mode == DIRECT) {
        return HANDLER_FINISHED;
    }

    if (opts->local_redir && con->http_status >= 300 && con->http_status < 400){
        /*(con->parsed_response & HTTP_LOCATION)*/
        handler_t rc = http_response_process_local_redir(srv, con, blen);
        if (con->mode == DIRECT) con->file_started = 0;
        if (rc != HANDLER_GO_ON) return rc;
    }

    if (opts->xsendfile_allow) {
        data_string *ds;
        /* X-Sendfile2 is deprecated; historical for fastcgi */
        if (opts->backend == BACKEND_FASTCGI
            && NULL != (ds = (data_string *) array_get_element(con->response.headers, "X-Sendfile2"))) {
            http_response_xsendfile2(srv, con, ds->value, opts->xsendfile_docroot);
            buffer_reset(ds->value); /*(do not send to client)*/
            if (con->mode == DIRECT) con->file_started = 0;
            return HANDLER_FINISHED;
        } else if (NULL != (ds = (data_string *) array_get_element(con->response.headers, "X-Sendfile"))
                   || (opts->backend == BACKEND_FASTCGI /* X-LIGHTTPD-send-file is deprecated; historical for fastcgi */
                       && NULL != (ds = (data_string *) array_get_element(con->response.headers, "X-LIGHTTPD-send-file")))) {
            http_response_xsendfile(srv, con, ds->value, opts->xsendfile_docroot);
            buffer_reset(ds->value); /*(do not send to client)*/
            if (con->mode == DIRECT) con->file_started = 0;
            return HANDLER_FINISHED;
        }
    }

    if (blen > 0) {
        if (0 != http_chunk_append_mem(srv, con, bstart, blen)) {
            return HANDLER_ERROR;
        }
    }

    /* (callback for response headers complete) */
    return (opts->headers) ? opts->headers(srv, con, opts) : HANDLER_GO_ON;
}


handler_t http_response_read(server *srv, connection *con, http_response_opts *opts, buffer *b, int fd, int *fde_ndx) {
    while (1) {
        ssize_t n;
        size_t avail = buffer_string_space(b);
        unsigned int toread = 4096;

        if (0 == fdevent_ioctl_fionread(fd, opts->fdfmt, (int *)&toread)) {
            if (avail < toread) {
                if (toread < 4096)
                    toread = 4096;
                else if (toread > MAX_READ_LIMIT)
                    toread = MAX_READ_LIMIT;
            }
            else if (0 == toread) {
              #if 0
                return (fdevent_event_get_interest(srv->ev, fd) & FDEVENT_IN)
                  ? HANDLER_FINISHED  /* read finished */
                  : HANDLER_GO_ON;    /* optimistic read; data not ready */
              #else
                if (!(fdevent_event_get_interest(srv->ev, fd) & FDEVENT_IN))
                    return HANDLER_GO_ON; /* optimistic read; data not ready */
                toread = 4096; /* let read() below indicate if EOF or EAGAIN */
              #endif
            }
        }

        if (con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN) {
            off_t cqlen = chunkqueue_length(con->write_queue);
            if (cqlen + (off_t)toread > 65536 - 4096) {
                if (!con->is_writable) {
                    /*(defer removal of FDEVENT_IN interest since
                     * connection_state_machine() might be able to send data
                     * immediately, unless !con->is_writable, where
                     * connection_state_machine() might not loop back to call
                     * mod_proxy_handle_subrequest())*/
                    fdevent_event_clr(srv->ev, fde_ndx, fd, FDEVENT_IN);
                }
                if (cqlen >= 65536-1) return HANDLER_GO_ON;
                toread = 65536 - 1 - (unsigned int)cqlen;
                /* Note: heuristic is fuzzy in that it limits how much to read
                 * from backend based on how much is pending to write to client.
                 * Modules where data from backend is framed (e.g. FastCGI) may
                 * want to limit how much is buffered from backend while waiting
                 * for a complete data frame or data packet from backend. */
            }
        }

        if (avail < toread) {
            /*(add avail+toread to reduce allocations when ioctl EOPNOTSUPP)*/
            avail = avail ? avail - 1 + toread : toread;
            buffer_string_prepare_append(b, avail);
        }

        n = read(fd, b->ptr+buffer_string_length(b), avail);

        if (n < 0) {
            switch (errno) {
              case EAGAIN:
             #ifdef EWOULDBLOCK
             #if EWOULDBLOCK != EAGAIN
              case EWOULDBLOCK:
             #endif
             #endif
              case EINTR:
                return HANDLER_GO_ON;
              default:
                log_error_write(srv, __FILE__, __LINE__, "ssdd",
                                "read():", strerror(errno), con->fd, fd);
                return HANDLER_ERROR;
            }
        }

        buffer_commit(b, (size_t)n);

        if (NULL != opts->parse) {
            handler_t rc = opts->parse(srv, con, opts, b, (size_t)n);
            if (rc != HANDLER_GO_ON) return rc;
        } else if (0 == n) {
            /* note: no further data is sent to backend after read EOF on socket
             * (not checking for half-closed TCP socket)
             * (backend should read all data desired prior to closing socket,
             *  though might send app-level close data frame, if applicable) */
            return HANDLER_FINISHED; /* read finished */
        } else if (0 == con->file_started) {
            /* split header from body */
            handler_t rc = http_response_parse_headers(srv, con, opts, b);
            if (rc != HANDLER_GO_ON) return rc;
            /* accumulate response in b until headers completed (or error) */
            if (con->file_started) buffer_string_set_length(b, 0);
        } else {
            if (0 != http_chunk_append_buffer(srv, con, b)) {
                /* error writing to tempfile;
                 * truncate response or send 500 if nothing sent yet */
                return HANDLER_ERROR;
            }
            buffer_string_set_length(b, 0);
        }

        if ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
            && chunkqueue_length(con->write_queue) > 65536 - 4096) {
            if (!con->is_writable) {
                /*(defer removal of FDEVENT_IN interest since
                 * connection_state_machine() might be able to send
                 * data immediately, unless !con->is_writable, where
                 * connection_state_machine() might not loop back to
                 * call the subrequest handler)*/
                fdevent_event_clr(srv->ev, fde_ndx, fd, FDEVENT_IN);
            }
            break;
        }

        if ((size_t)n < avail)
            break; /* emptied kernel read buffer or partial read */
    }

    return HANDLER_GO_ON;
}


int http_cgi_headers (server *srv, connection *con, http_cgi_opts *opts, http_cgi_header_append_cb cb, void *vdata) {

    /* CGI-SPEC 6.1.2, FastCGI spec 6.3 and SCGI spec */

    int rc = 0;
    server_socket *srv_sock = con->srv_socket;
    const char *s;
    size_t n;
    char buf[LI_ITOSTRING_LENGTH];
  #ifdef HAVE_IPV6
    char b2[INET6_ADDRSTRLEN + 1];
  #else
    char b2[INET_ADDRSTRLEN + 1];
  #endif
    sock_addr *addr;
    sock_addr addrbuf;

    /* (CONTENT_LENGTH must be first for SCGI) */
    if (!opts->authorizer) {
        li_itostrn(buf, sizeof(buf), con->request.content_length);
        rc |= cb(vdata, CONST_STR_LEN("CONTENT_LENGTH"), buf, strlen(buf));
    }

    if (!buffer_string_is_empty(con->uri.query)) {
        rc |= cb(vdata, CONST_STR_LEN("QUERY_STRING"),
                        CONST_BUF_LEN(con->uri.query));
    } else {
        rc |= cb(vdata, CONST_STR_LEN("QUERY_STRING"),
                        CONST_STR_LEN(""));
    }
    if (!buffer_string_is_empty(opts->strip_request_uri)) {
        /**
         * /app1/index/list
         *
         * stripping /app1 or /app1/ should lead to
         *
         * /index/list
         *
         */
        size_t len = buffer_string_length(opts->strip_request_uri);
        if ('/' == opts->strip_request_uri->ptr[len-1]) {
            --len;
        }

        if (buffer_string_length(con->request.orig_uri) >= len
            && 0 == memcmp(con->request.orig_uri->ptr,
                           opts->strip_request_uri->ptr, len)
            && con->request.orig_uri->ptr[len] == '/') {
            rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                            con->request.orig_uri->ptr+len,
                            buffer_string_length(con->request.orig_uri) - len);
        } else {
            rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                            CONST_BUF_LEN(con->request.orig_uri));
        }
    } else {
        rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                        CONST_BUF_LEN(con->request.orig_uri));
    }
    if (!buffer_is_equal(con->request.uri, con->request.orig_uri)) {
        rc |= cb(vdata, CONST_STR_LEN("REDIRECT_URI"),
                        CONST_BUF_LEN(con->request.uri));
    }
    /* set REDIRECT_STATUS for php compiled with --force-redirect
     * (if REDIRECT_STATUS has not already been set by error handler) */
    if (0 == con->error_handler_saved_status) {
        rc |= cb(vdata, CONST_STR_LEN("REDIRECT_STATUS"),
                        CONST_STR_LEN("200"));
    }

    /*
     * SCRIPT_NAME, PATH_INFO and PATH_TRANSLATED according to
     * http://cgi-spec.golux.com/draft-coar-cgi-v11-03-clean.html
     * (6.1.14, 6.1.6, 6.1.7)
     */
    if (!opts->authorizer) {
        rc |= cb(vdata, CONST_STR_LEN("SCRIPT_NAME"),
                        CONST_BUF_LEN(con->uri.path));
        if (!buffer_string_is_empty(con->request.pathinfo)) {
            rc |= cb(vdata, CONST_STR_LEN("PATH_INFO"),
                            CONST_BUF_LEN(con->request.pathinfo));
            /* PATH_TRANSLATED is only defined if PATH_INFO is set */
            if (!buffer_string_is_empty(opts->docroot)) {
                buffer_copy_buffer(srv->tmp_buf, opts->docroot);
            } else {
                buffer_copy_buffer(srv->tmp_buf, con->physical.basedir);
            }
            buffer_append_string_buffer(srv->tmp_buf, con->request.pathinfo);
            rc |= cb(vdata, CONST_STR_LEN("PATH_TRANSLATED"),
                            CONST_BUF_LEN(srv->tmp_buf));
        }
    }

   /*
    * SCRIPT_FILENAME and DOCUMENT_ROOT for php
    * The PHP manual http://www.php.net/manual/en/reserved.variables.php
    * treatment of PATH_TRANSLATED is different from the one of CGI specs.
    * (see php.ini cgi.fix_pathinfo = 1 config parameter)
    */

    if (!buffer_string_is_empty(opts->docroot)) {
        /* alternate docroot, e.g. for remote FastCGI or SCGI server */
        buffer_copy_buffer(srv->tmp_buf, opts->docroot);
        buffer_append_string_buffer(srv->tmp_buf, con->uri.path);
        rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                        CONST_BUF_LEN(srv->tmp_buf));
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        CONST_BUF_LEN(opts->docroot));
    } else {
        if (opts->break_scriptfilename_for_php) {
            /* php.ini config cgi.fix_pathinfo = 1 need a broken SCRIPT_FILENAME
             * to find out what PATH_INFO is itself
             *
             * see src/sapi/cgi_main.c, init_request_info()
             */
            buffer_copy_buffer(srv->tmp_buf, con->physical.path);
            buffer_append_string_buffer(srv->tmp_buf, con->request.pathinfo);
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            CONST_BUF_LEN(srv->tmp_buf));
        } else {
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            CONST_BUF_LEN(con->physical.path));
        }
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        CONST_BUF_LEN(con->physical.basedir));
    }

    s = get_http_method_name(con->request.http_method);
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("REQUEST_METHOD"), s, strlen(s));

    s = get_http_version_name(con->request.http_version);
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PROTOCOL"), s, strlen(s));

    rc |= cb(vdata, CONST_STR_LEN("SERVER_SOFTWARE"),
                    CONST_BUF_LEN(con->conf.server_tag));

    rc |= cb(vdata, CONST_STR_LEN("GATEWAY_INTERFACE"),
                    CONST_STR_LEN("CGI/1.1"));

    rc |= cb(vdata, CONST_STR_LEN("REQUEST_SCHEME"),
                    CONST_BUF_LEN(con->uri.scheme));

    if (buffer_is_equal_caseless_string(con->uri.scheme,
                                        CONST_STR_LEN("https"))) {
        rc |= cb(vdata, CONST_STR_LEN("HTTPS"), CONST_STR_LEN("on"));
    }

    addr = &srv_sock->addr;
    li_utostrn(buf, sizeof(buf), sock_addr_get_port(addr));
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PORT"), buf, strlen(buf));

    switch (addr->plain.sa_family) {
  #ifdef HAVE_IPV6
    case AF_INET6:
        if (0 ==memcmp(&addr->ipv6.sin6_addr,&in6addr_any,sizeof(in6addr_any))){
            socklen_t addrlen = sizeof(addrbuf);
            if (0 == getsockname(con->fd,(struct sockaddr *)&addrbuf,&addrlen)){
                addr = &addrbuf;
            } else {
                s = "";
                break;
            }
        }
        s = sock_addr_inet_ntop(addr, b2, sizeof(b2)-1);
        if (NULL == s) s = "";
        break;
  #endif
    case AF_INET:
        if (srv_sock->addr.ipv4.sin_addr.s_addr == INADDR_ANY) {
            socklen_t addrlen = sizeof(addrbuf);
            if (0 == getsockname(con->fd,(struct sockaddr *)&addrbuf,&addrlen)){
                addr = &addrbuf;
            } else {
                s = "";
                break;
            }
        }
        s = sock_addr_inet_ntop(addr, b2, sizeof(b2)-1);
        if (NULL == s) s = "";
        break;
    default:
        s = "";
        break;
    }
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("SERVER_ADDR"), s, strlen(s));

    if (!buffer_string_is_empty(con->server_name)) {
        size_t len = buffer_string_length(con->server_name);

        if (con->server_name->ptr[0] == '[') {
            const char *colon = strstr(con->server_name->ptr, "]:");
            if (colon) len = (colon + 1) - con->server_name->ptr;
        } else {
            const char *colon = strchr(con->server_name->ptr, ':');
            if (colon) len = colon - con->server_name->ptr;
        }

        rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"),
                        con->server_name->ptr, len);
    } else {
        /* set to be same as SERVER_ADDR (above) */
        rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"), s, strlen(s));
    }

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_ADDR"),
                    CONST_BUF_LEN(con->dst_addr_buf));

    li_utostrn(buf, sizeof(buf), sock_addr_get_port(&con->dst_addr));
    rc |= cb(vdata, CONST_STR_LEN("REMOTE_PORT"), buf, strlen(buf));

    for (n = 0; n < con->request.headers->used; n++) {
        data_string *ds = (data_string *)con->request.headers->data[n];
        if (!buffer_string_is_empty(ds->value) && !buffer_is_empty(ds->key)) {
            /* Security: Do not emit HTTP_PROXY in environment.
             * Some executables use HTTP_PROXY to configure
             * outgoing proxy.  See also https://httpoxy.org/ */
            if (buffer_is_equal_caseless_string(ds->key,
                                                CONST_STR_LEN("Proxy"))) {
                continue;
            }
            buffer_copy_string_encoded_cgi_varnames(srv->tmp_buf,
                                                    CONST_BUF_LEN(ds->key), 1);
            rc |= cb(vdata, CONST_BUF_LEN(srv->tmp_buf),
                            CONST_BUF_LEN(ds->value));
        }
    }

    srv->request_env(srv, con);

    for (n = 0; n < con->environment->used; n++) {
        data_string *ds = (data_string *)con->environment->data[n];
        if (!buffer_is_empty(ds->value) && !buffer_is_empty(ds->key)) {
            buffer_copy_string_encoded_cgi_varnames(srv->tmp_buf,
                                                    CONST_BUF_LEN(ds->key), 0);
            rc |= cb(vdata, CONST_BUF_LEN(srv->tmp_buf),
                            CONST_BUF_LEN(ds->value));
        }
    }

    return rc;
}
