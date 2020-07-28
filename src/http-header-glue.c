#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "fdevent.h"
#include "log.h"
#include "etag.h"
#include "http_chunk.h"
#include "http_header.h"
#include "response.h"
#include "sock_addr.h"
#include "stat_cache.h"
#include "settings.h"   /* MAX_HTTP_REQUEST_HEADER MAX_READ_LIMIT */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <time.h>

#include "sys-socket.h"
#include <unistd.h>


static int http_response_buffer_append_authority(request_st * const r, buffer * const o) {
	if (!buffer_string_is_empty(&r->uri.authority)) {
		buffer_append_string_buffer(o, &r->uri.authority);
	} else {
		/* get the name of the currently connected socket */
		sock_addr our_addr;
		socklen_t our_addr_len;

		our_addr.plain.sa_family = 0;
		our_addr_len = sizeof(our_addr);

		if (-1 == getsockname(r->con->fd, (struct sockaddr *)&our_addr, &our_addr_len)
		    || our_addr_len > (socklen_t)sizeof(our_addr)) {
			r->http_status = 500;
			log_perror(r->conf.errh, __FILE__, __LINE__, "can't get sockname");
			return -1;
		}

		if (our_addr.plain.sa_family == AF_INET
		    && our_addr.ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
			static char lhost[32];
			static size_t lhost_len = 0;
			if (0 != lhost_len) {
				buffer_append_string_len(o, lhost, lhost_len);
			}
			else {
				size_t olen = buffer_string_length(o);
				if (0 == sock_addr_nameinfo_append_buffer(o, &our_addr, r->conf.errh)) {
					lhost_len = buffer_string_length(o) - olen;
					if (lhost_len < sizeof(lhost)) {
						memcpy(lhost, o->ptr+olen, lhost_len+1); /*(+1 for '\0')*/
					}
					else {
						lhost_len = 0;
					}
				}
				else {
					lhost_len = sizeof("localhost")-1;
					memcpy(lhost, "localhost", lhost_len+1); /*(+1 for '\0')*/
					buffer_append_string_len(o, lhost, lhost_len);
				}
			}
		} else if (!buffer_string_is_empty(r->server_name)) {
			buffer_append_string_buffer(o, r->server_name);
		} else
		/* Lookup name: secondly try to get hostname for bind address */
		if (0 != sock_addr_nameinfo_append_buffer(o, &our_addr, r->conf.errh)) {
			r->http_status = 500;
			return -1;
		}

		{
			unsigned short listen_port = sock_addr_get_port(&our_addr);
			unsigned short default_port = 80;
			if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https"))) {
				default_port = 443;
			}
			if (0 == listen_port) listen_port = r->con->srv->srvconf.port;
			if (default_port != listen_port) {
				buffer_append_string_len(o, CONST_STR_LEN(":"));
				buffer_append_int(o, listen_port);
			}
		}
	}
	return 0;
}

int http_response_redirect_to_directory(request_st * const r, int status) {
	buffer *o = r->tmp_buf;
	buffer_copy_buffer(o, &r->uri.scheme);
	buffer_append_string_len(o, CONST_STR_LEN("://"));
	if (0 != http_response_buffer_append_authority(r, o)) {
		return -1;
	}
	buffer_append_string_encoded(o, CONST_BUF_LEN(&r->uri.path), ENCODING_REL_URI);
	buffer_append_string_len(o, CONST_STR_LEN("/"));
	if (!buffer_string_is_empty(&r->uri.query)) {
		buffer_append_string_len(o, CONST_STR_LEN("?"));
		buffer_append_string_buffer(o, &r->uri.query);
	}

	if (status >= 300) {
		http_header_response_set(r, HTTP_HEADER_LOCATION, CONST_STR_LEN("Location"), CONST_BUF_LEN(o));
		r->http_status = status;
		r->resp_body_finished = 1;
	}
	else {
		http_header_response_set(r, HTTP_HEADER_CONTENT_LOCATION, CONST_STR_LEN("Content-Location"), CONST_BUF_LEN(o));
	}

	return 0;
}

#define MTIME_CACHE_MAX 16
struct mtime_cache_type {
    time_t mtime;  /* key */
    buffer str;    /* buffer for string representation */
};
static struct mtime_cache_type mtime_cache[MTIME_CACHE_MAX];
static char mtime_cache_str[MTIME_CACHE_MAX][30];
/* 30-chars for "%a, %d %b %Y %H:%M:%S GMT" */

void strftime_cache_reset(void) {
    for (int i = 0; i < MTIME_CACHE_MAX; ++i) {
        mtime_cache[i].mtime = (time_t)-1;
        mtime_cache[i].str.ptr = mtime_cache_str[i];
        mtime_cache[i].str.used = sizeof(mtime_cache_str[0]);
        mtime_cache[i].str.size = sizeof(mtime_cache_str[0]);
    }
}

const buffer * strftime_cache_get(const time_t last_mod) {
    static int mtime_cache_idx;

    for (int j = 0; j < MTIME_CACHE_MAX; ++j) {
        if (mtime_cache[j].mtime == last_mod)
            return &mtime_cache[j].str; /* found cache-entry */
    }

    if (++mtime_cache_idx == MTIME_CACHE_MAX) mtime_cache_idx = 0;

    const int i = mtime_cache_idx;
    mtime_cache[i].mtime = last_mod;
    strftime(mtime_cache[i].str.ptr, sizeof(mtime_cache_str[0]),
             "%a, %d %b %Y %H:%M:%S GMT", gmtime(&mtime_cache[i].mtime));

    return &mtime_cache[i].str;
}


int http_response_handle_cachable(request_st * const r, const buffer * const mtime) {
	const buffer *vb;

	/*
	 * 14.26 If-None-Match
	 *    [...]
	 *    If none of the entity tags match, then the server MAY perform the
	 *    requested method as if the If-None-Match header field did not exist,
	 *    but MUST also ignore any If-Modified-Since header field(s) in the
	 *    request. That is, if no entity tags match, then the server MUST NOT
	 *    return a 304 (Not Modified) response.
	 */

	if ((vb = http_header_request_get(r, HTTP_HEADER_IF_NONE_MATCH, CONST_STR_LEN("If-None-Match")))) {
		/*(weak etag comparison must not be used for ranged requests)*/
		int range_request =
		  (r->conf.range_requests
		   && (200 == r->http_status || 0 == r->http_status)
		   && NULL != http_header_request_get(r, HTTP_HEADER_RANGE, CONST_STR_LEN("Range")));
		if (etag_is_equal(&r->physical.etag, vb->ptr, !range_request)) {
			if (http_method_get_or_head(r->http_method)) {
				r->http_status = 304;
				return HANDLER_FINISHED;
			} else {
				r->http_status = 412;
				r->handler_module = NULL;
				return HANDLER_FINISHED;
			}
		}
	} else if (http_method_get_or_head(r->http_method)
		   && (vb = http_header_request_get(r, HTTP_HEADER_IF_MODIFIED_SINCE, CONST_STR_LEN("If-Modified-Since")))) {
		/* last-modified handling */
		size_t used_len;
		char *semicolon;

		if (NULL == (semicolon = strchr(vb->ptr, ';'))) {
			used_len = buffer_string_length(vb);
		} else {
			used_len = semicolon - vb->ptr;
		}

		if (buffer_is_equal_string(mtime, vb->ptr, used_len)) {
			if ('\0' == mtime->ptr[used_len]) r->http_status = 304;
			return HANDLER_FINISHED;
		} else {
			char buf[sizeof("Sat, 23 Jul 2005 21:20:01 GMT")];
			time_t t_header, t_file;
			struct tm tm;

			/* convert to timestamp */
			if (used_len >= sizeof(buf)) return HANDLER_GO_ON;

			memcpy(buf, vb->ptr, used_len);
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

			r->http_status = 304;
			return HANDLER_FINISHED;
		}
	}

	return HANDLER_GO_ON;
}


void http_response_body_clear (request_st * const r, int preserve_length) {
    r->resp_send_chunked = 0;
    if (r->resp_htags & HTTP_HEADER_TRANSFER_ENCODING) {
        http_header_response_unset(r, HTTP_HEADER_TRANSFER_ENCODING, CONST_STR_LEN("Transfer-Encoding"));
    }
    if (!preserve_length) { /* preserve for HEAD responses and no-content responses (204, 205, 304) */
        r->content_length = -1;
        if (r->resp_htags & HTTP_HEADER_CONTENT_LENGTH) {
            http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
        }
        /*(if not preserving Content-Length, do not preserve trailers, if any)*/
        r->resp_decode_chunked = 0;
        if (r->gw_dechunk) {
            free(r->gw_dechunk->b.ptr);
            free(r->gw_dechunk);
            r->gw_dechunk = NULL;
        }
    }
    chunkqueue_reset(r->write_queue);
}


static int http_response_parse_range(request_st * const r, buffer * const path, stat_cache_entry * const sce, const char * const range) {
	int multipart = 0;
	int error;
	off_t start, end;
	const char *s, *minus;
	static const char boundary[] = "fkj49sn38dcn3";
	const buffer *content_type = http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"));

	start = 0;
	end = sce->st.st_size - 1;

	r->content_length = 0;

	for (s = range, error = 0;
	     !error && *s && NULL != (minus = strchr(s, '-')); ) {
		char *err;
		off_t la = 0, le;
		*((const char **)&err) = s; /*(quiet clang --analyze)*/

		if (s != minus) {
			la = strtoll(s, &err, 10);
			if (err != minus) {
				/* should not have multiple range-unit in Range, but
				 * handle just in case multiple Range headers merged */
				while (*s == ' ' || *s == '\t') ++s;
				if (0 != strncmp(s, "bytes=", 6)) return -1;
				s += 6;
				if (s != minus) {
					la = strtoll(s, &err, 10);
					if (err != minus) return -1;
				}
			}
		}

		if (s == minus) {
			/* -<stop> */

			le = strtoll(s, &err, 10);

			if (le == 0) {
				/* RFC 2616 - 14.35.1 */

				r->http_status = 416;
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
			/* <start>-<stop> */

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
		}

		if (!error) {
			if (start < 0) start = 0;

			/* RFC 2616 - 14.35.1 */
			if (end > sce->st.st_size - 1) end = sce->st.st_size - 1;

			if (start > sce->st.st_size - 1) {
				error = 1;

				r->http_status = 416;
			}
		}

		if (!error) {
			if (multipart) {
				/* write boundary-header */
				buffer *b = r->tmp_buf;
				buffer_copy_string_len(b, CONST_STR_LEN("\r\n--"));
				buffer_append_string_len(b, boundary, sizeof(boundary)-1);

				/* write Content-Range */
				buffer_append_string_len(b, CONST_STR_LEN("\r\nContent-Range: bytes "));
				buffer_append_int(b, start);
				buffer_append_string_len(b, CONST_STR_LEN("-"));
				buffer_append_int(b, end);
				buffer_append_string_len(b, CONST_STR_LEN("/"));
				buffer_append_int(b, sce->st.st_size);

				if (content_type) {
					buffer_append_string_len(b, CONST_STR_LEN("\r\nContent-Type: "));
					buffer_append_string_buffer(b, content_type);
				}

				/* write END-OF-HEADER */
				buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

				r->content_length += buffer_string_length(b);
				chunkqueue_append_mem(r->write_queue, CONST_BUF_LEN(b));
			}

			chunkqueue_append_file(r->write_queue, path, start, end - start + 1);
			r->content_length += end - start + 1;
		}
	}

	/* something went wrong */
	if (error) return -1;

	buffer * const tb = r->tmp_buf;

	if (multipart) {
		/* add boundary end */
		buffer_copy_string_len(tb, "\r\n--", 4);
		buffer_append_string_len(tb, boundary, sizeof(boundary)-1);
		buffer_append_string_len(tb, "--\r\n", 4);

		r->content_length += buffer_string_length(tb);
		chunkqueue_append_mem(r->write_queue, CONST_BUF_LEN(tb));

		/* set header-fields */

		buffer_copy_string_len(tb, CONST_STR_LEN("multipart/byteranges; boundary="));
		buffer_append_string_len(tb, boundary, sizeof(boundary)-1);

		/* overwrite content-type */
		http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(tb));
	} else {
		/* add Content-Range-header */

		buffer_copy_string_len(tb, CONST_STR_LEN("bytes "));
		buffer_append_int(tb, start);
		buffer_append_string_len(tb, CONST_STR_LEN("-"));
		buffer_append_int(tb, end);
		buffer_append_string_len(tb, CONST_STR_LEN("/"));
		buffer_append_int(tb, sce->st.st_size);

		http_header_response_set(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Content-Range"), CONST_BUF_LEN(tb));
	}

	/* ok, the file is set-up */
	return 0;
}


void http_response_send_file (request_st * const r, buffer * const path) {
	stat_cache_entry * const sce = stat_cache_get_entry(path);
	const buffer *mtime = NULL;
	const buffer *vb;
	int allow_caching = (0 == r->http_status || 200 == r->http_status);

	if (NULL == sce) {
		r->http_status = (errno == ENOENT) ? 404 : 403;
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "not a regular file: %s -> %s", r->uri.path.ptr, path->ptr);
		return;
	}

	if (!r->conf.follow_symlink
	    && 0 != stat_cache_path_contains_symlink(path, r->conf.errh)) {
		r->http_status = 403;
		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- access denied due symlink restriction");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Path         : %s", path->ptr);
		}
		return;
	}

	/* we only handle regular files */
	if (!S_ISREG(sce->st.st_mode)) {
		r->http_status = 403;
		if (r->conf.log_file_not_found) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "not a regular file: %s -> %s",
			  r->uri.path.ptr, path->ptr);
		}
		return;
	}

	/*(Note: O_NOFOLLOW affects only the final path segment,
	 * the target file, not any intermediate symlinks along path)*/
	const int fd = (0 != sce->st.st_size)
	  ? fdevent_open_cloexec(path->ptr, r->conf.follow_symlink, O_RDONLY, 0)
	  : -1;
	if (fd < 0 && 0 != sce->st.st_size) {
		r->http_status = (errno == ENOENT) ? 404 : 403;
		if (r->conf.log_request_handling) {
			log_perror(r->conf.errh, __FILE__, __LINE__,
			  "file open failed: %s", path->ptr);
		}
		return;
	}

	/* set response content-type, if not set already */

	if (NULL == http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"))) {
		const buffer *content_type = stat_cache_content_type_get(sce, r);
		if (buffer_string_is_empty(content_type)) {
			/* we are setting application/octet-stream, but also announce that
			 * this header field might change in the seconds few requests
			 *
			 * This should fix the aggressive caching of FF and the script download
			 * seen by the first installations
			 */
			http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("application/octet-stream"));

			allow_caching = 0;
		} else {
			http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(content_type));
		}
	}

	if (r->conf.range_requests) {
		http_header_response_append(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Accept-Ranges"), CONST_STR_LEN("bytes"));
	}

	if (allow_caching) {
		const buffer *etag = (0 != r->conf.etag_flags)
		  ? stat_cache_etag_get(sce, r->conf.etag_flags)
		  : NULL;
		if (!buffer_string_is_empty(etag)) {
			if (NULL == http_header_response_get(r, HTTP_HEADER_ETAG, CONST_STR_LEN("ETag"))) {
				/* generate e-tag */
				etag_mutate(&r->physical.etag, etag);

				http_header_response_set(r, HTTP_HEADER_ETAG, CONST_STR_LEN("ETag"), CONST_BUF_LEN(&r->physical.etag));
			}
		}

		/* prepare header */
		if (NULL == (mtime = http_header_response_get(r, HTTP_HEADER_LAST_MODIFIED, CONST_STR_LEN("Last-Modified")))) {
			mtime = strftime_cache_get(sce->st.st_mtime);
			http_header_response_set(r, HTTP_HEADER_LAST_MODIFIED, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
		}

		if (HANDLER_FINISHED == http_response_handle_cachable(r, mtime)) {
			if (fd >= 0) close(fd);
			return;
		}
	}

	if (fd < 0) { /* 0-length file */
		r->http_status = 200;
		r->resp_body_finished = 1;
		return;
	}

	if (r->conf.range_requests
	    && (200 == r->http_status || 0 == r->http_status)
	    && NULL != (vb = http_header_request_get(r, HTTP_HEADER_RANGE, CONST_STR_LEN("Range")))
	    && NULL == http_header_response_get(r, HTTP_HEADER_CONTENT_ENCODING, CONST_STR_LEN("Content-Encoding"))) {
		const buffer *range = vb;
		int do_range_request = 1;
		/* check if we have a conditional GET */

		if (NULL != (vb = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("If-Range")))) {
			/* if the value is the same as our ETag, we do a Range-request,
			 * otherwise a full 200 */

			if (vb->ptr[0] == '"') {
				/**
				 * client wants a ETag
				 */
				if (!buffer_is_equal(vb, &r->physical.etag)) {
					do_range_request = 0;
				}
			} else if (!mtime) {
				/**
				 * we don't have a Last-Modified and can match the If-Range:
				 *
				 * sending all
				 */
				do_range_request = 0;
			} else if (!buffer_is_equal(vb, mtime)) {
				do_range_request = 0;
			}
		}

		if (do_range_request
		    && !buffer_string_is_empty(range)
		    && 0 == strncmp(range->ptr, "bytes=", 6)) {
			/* support only "bytes" byte-unit */
			/* content prepared, I'm done */
			r->resp_body_finished = 1;

			if (0 == http_response_parse_range(r, path, sce, range->ptr+6)) {
				r->http_status = 206;
			}
			close(fd);
			return;
		}
	}

	/* if we are still here, prepare body */

	/* we add it here for all requests
	 * the HEAD request will drop it afterwards again
	 */

	if (0 == http_chunk_append_file_fd(r, path, fd, sce->st.st_size)) {
		r->http_status = 200;
		r->resp_body_finished = 1;
	}
	else {
		r->http_status = 500;
	}
}


static void http_response_xsendfile (request_st * const r, buffer * const path, const array * const xdocroot) {
	const int status = r->http_status;
	int valid = 1;

	/* reset Content-Length, if set by backend
	 * Content-Length might later be set to size of X-Sendfile static file,
	 * determined by open(), fstat() to reduces race conditions if the file
	 * is modified between stat() (stat_cache_get_entry()) and open(). */
	if (r->resp_htags & HTTP_HEADER_CONTENT_LENGTH) {
		http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
		r->content_length = -1;
	}

	buffer_urldecode_path(path);
	if (!buffer_is_valid_UTF8(path)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "X-Sendfile invalid UTF-8 after url-decode: %s", path->ptr);
		if (r->http_status < 400) {
			r->http_status = 502;
			r->handler_module = NULL;
		}
		return;
	}
	buffer_path_simplify(path, path);
	if (r->conf.force_lowercase_filenames) {
		buffer_to_lower(path);
	}

	/* check that path is under xdocroot(s)
	 * - xdocroot should have trailing slash appended at config time
	 * - r->conf.force_lowercase_filenames is not a server-wide setting,
	 *   and so can not be definitively applied to xdocroot at config time*/
	if (xdocroot) {
		size_t i, xlen = buffer_string_length(path);
		for (i = 0; i < xdocroot->used; ++i) {
			data_string *ds = (data_string *)xdocroot->data[i];
			size_t dlen = buffer_string_length(&ds->value);
			if (dlen <= xlen
			    && (!r->conf.force_lowercase_filenames
				? 0 == memcmp(path->ptr, ds->value.ptr, dlen)
				: buffer_eq_icase_ssn(path->ptr, ds->value.ptr, dlen))) {
				break;
			}
		}
		if (i == xdocroot->used && 0 != i) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "X-Sendfile (%s) not under configured x-sendfile-docroot(s)", path->ptr);
			r->http_status = 403;
			valid = 0;
		}
	}

	if (valid) http_response_send_file(r, path);

	if (r->http_status >= 400 && status < 300) {
		r->handler_module = NULL;
	} else if (0 != status && 200 != status) {
		r->http_status = status;
	}
}


static void http_response_xsendfile2(request_st * const r, const buffer * const value, const array * const xdocroot) {
    const char *pos = value->ptr;
    buffer * const b = r->tmp_buf;
    const int status = r->http_status;

    /* reset Content-Length, if set by backend */
    if (r->resp_htags & HTTP_HEADER_CONTENT_LENGTH) {
        http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
        r->content_length = -1;
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
            log_error(r->conf.errh, __FILE__, __LINE__,
              "Couldn't find range after filename: %s", filename);
            r->http_status = 502;
            break;
        }
        buffer_copy_string_len(b, filename, range - filename);

        /* find end of range */
        for (pos = ++range; *pos && *pos != ' ' && *pos != ','; pos++) ;

        buffer_urldecode_path(b);
        if (!buffer_is_valid_UTF8(b)) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "X-Sendfile2 invalid UTF-8 after url-decode: %s", b->ptr);
            r->http_status = 502;
            break;
        }
        buffer_path_simplify(b, b);
        if (r->conf.force_lowercase_filenames) {
            buffer_to_lower(b);
        }
        if (xdocroot) {
            size_t i, xlen = buffer_string_length(b);
            for (i = 0; i < xdocroot->used; ++i) {
                data_string *ds = (data_string *)xdocroot->data[i];
                size_t dlen = buffer_string_length(&ds->value);
                if (dlen <= xlen
                    && (!r->conf.force_lowercase_filenames
                    ? 0 == memcmp(b->ptr, ds->value.ptr, dlen)
                    : buffer_eq_icase_ssn(b->ptr, ds->value.ptr, dlen))) {
                    break;
                }
            }
            if (i == xdocroot->used && 0 != i) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "X-Sendfile2 (%s) not under configured x-sendfile-docroot(s)",
                  b->ptr);
                r->http_status = 403;
                break;
            }
        }

        sce = stat_cache_get_entry(b);
        if (NULL == sce) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "send-file error: couldn't get stat_cache entry for "
              "X-Sendfile2: %s", b->ptr);
            r->http_status = 404;
            break;
        } else if (!S_ISREG(sce->st.st_mode)) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "send-file error: wrong filetype for X-Sendfile2: %s", b->ptr);
            r->http_status = 502;
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
            log_error(r->conf.errh, __FILE__, __LINE__,
              "Couldn't decode range after filename: %s", filename);
            r->http_status = 502;
            break;

range_success: ;
        }

        /* no parameters accepted */

        while (*pos == ' ') pos++;
        if (*pos != '\0' && *pos != ',') {
            r->http_status = 502;
            break;
        }

        range_len = end_range - begin_range + 1;
        if (range_len < 0) {
            r->http_status = 502;
            break;
        }
        if (range_len != 0) {
            if (0 !=
                http_chunk_append_file_range(r, b, begin_range, range_len)) {
                r->http_status = 502;
                break;
            }
        }

        if (*pos == ',') pos++;
    }

    if (r->http_status >= 400 && status < 300) {
	r->handler_module = NULL;
    } else if (0 != status && 200 != status) {
        r->http_status = status;
    }
}


void http_response_backend_error (request_st * const r) {
	if (r->resp_body_started) {
		/*(response might have been already started, kill the connection)*/
		/*(mode == DIRECT to avoid later call to http_response_backend_done())*/
		r->handler_module = NULL;  /*(avoid sending final chunked block)*/
		r->keep_alive = 0;
		r->resp_body_finished = 1;
	} /*(else error status set later by http_response_backend_done())*/
}

void http_response_backend_done (request_st * const r) {
	/* (not CON_STATE_ERROR and not CON_STATE_RESPONSE_END,
	 *  i.e. not called from handle_connection_close or handle_request_reset
	 *  hooks, except maybe from errdoc handler, which later resets state)*/
	switch (r->state) {
	case CON_STATE_HANDLE_REQUEST:
	case CON_STATE_READ_POST:
		if (!r->resp_body_started) {
			/* Send an error if we haven't sent any data yet */
			r->http_status = 500;
			r->handler_module = NULL;
			break;
		} /* else fall through */
	case CON_STATE_WRITE:
		if (!r->resp_body_finished) {
			http_chunk_close(r);
			r->resp_body_finished = 1;
		}
	default:
		break;
	}
}


void http_response_upgrade_read_body_unknown(request_st * const r) {
    /* act as transparent proxy */
    if (!(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST))
        r->conf.stream_request_body |=
          (FDEVENT_STREAM_REQUEST_BUFMIN | FDEVENT_STREAM_REQUEST);
    if (!(r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE))
        r->conf.stream_response_body |=
          (FDEVENT_STREAM_RESPONSE_BUFMIN | FDEVENT_STREAM_RESPONSE);
    r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
    r->reqbody_length = -2;
    r->keep_alive = 0;
}


static handler_t http_response_process_local_redir(request_st * const r, size_t blen) {
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

    /* r->http_status >= 300 && r->http_status < 400) */
    size_t ulen = buffer_string_length(&r->uri.path);
    const buffer *vb = http_header_response_get(r, HTTP_HEADER_LOCATION, CONST_STR_LEN("Location"));
    if (NULL != vb
        && vb->ptr[0] == '/'
        && (0 != strncmp(vb->ptr, r->uri.path.ptr, ulen)
            || (   vb->ptr[ulen] != '\0'
                && vb->ptr[ulen] != '/'
                && vb->ptr[ulen] != '?'))
        && 0 == blen
        && !(r->resp_htags & HTTP_HEADER_STATUS) /*no "Status" or NPH response*/
        && 1 == r->resp_headers.used) {
        if (++r->loops_per_request > 5) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "too many internal loops while processing request: %s",
              r->target_orig.ptr);
            r->http_status = 500; /* Internal Server Error */
            r->handler_module = NULL;
            return HANDLER_FINISHED;
        }

        buffer_copy_buffer(&r->target, vb);

        if (r->reqbody_length) {
            if (r->reqbody_length
                != r->reqbody_queue->bytes_in) {
                r->keep_alive = 0;
            }
            r->reqbody_length = 0;
            chunkqueue_reset(r->reqbody_queue);
        }

        if (r->http_status != 307 && r->http_status != 308) {
            /* Note: request body (if any) sent to initial dynamic handler
             * and is not available to the internal redirect */
            r->http_method = HTTP_METHOD_GET;
        }

        /*(caller must reset request as follows)*/
        /*connection_response_reset(r);*/ /*(sets r->http_status = 0)*/
        /*plugins_call_handle_request_reset(r);*/

        return HANDLER_COMEBACK;
    }

    return HANDLER_GO_ON;
}


static int http_response_process_headers(request_st * const r, http_response_opts * const opts, buffer * const hdrs) {
    char *ns;
    const char *s;
    int line = 0;
    int status_is_set = 0;

    for (s = hdrs->ptr; NULL != (ns = strchr(s, '\n')); s = ns + 1, ++line) {
        const char *key, *value;
        int key_len;
        enum http_header_e id;

        /* strip the \n */
        ns[0] = '\0';
        if (ns > s && ns[-1] == '\r') ns[-1] = '\0';

        if (0 == line && 0 == strncmp(s, "HTTP/1.", 7)) {
            /* non-parsed headers ... we parse them anyway */
            if ((s[7] == '1' || s[7] == '0') && s[8] == ' ') {
                /* after the space should be a status code for us */
                int status = http_header_str_to_code(s+9);
                if (status >= 100 && status < 1000) {
                    status_is_set = 1;
                    r->resp_htags |= HTTP_HEADER_STATUS;
                    r->http_status = status;
                } /* else we expected 3 digits and didn't get them */
            }

            if (0 == r->http_status) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "invalid HTTP status line: %s", s);
                r->http_status = 502; /* Bad Gateway */
                r->handler_module = NULL;
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
        id = http_header_hkey_get(key, key_len);

        if (opts->authorizer) {
            if (0 == r->http_status || 200 == r->http_status) {
                if (id == HTTP_HEADER_STATUS) {
                    int status = http_header_str_to_code(value);
                    if (status >= 100 && status < 1000) {
                        r->http_status = status;
                    } else {
                        r->http_status = 502; /* Bad Gateway */
                        break;
                    }
                }
                else if (id == HTTP_HEADER_OTHER && key_len > 9
                         && (key[0] & 0xdf) == 'V'
                         && buffer_eq_icase_ssn(key,
                                                CONST_STR_LEN("Variable-"))) {
                    http_header_env_append(r, key + 9, key_len - 9, value, strlen(value));
                }
                continue;
            }
        }

        switch (id) {
          case HTTP_HEADER_STATUS:
            {
                if (opts->backend == BACKEND_PROXY) break; /*(pass w/o parse)*/
                int status = http_header_str_to_code(value);
                if (status >= 100 && status < 1000) {
                    r->http_status = status;
                    status_is_set = 1;
                } else {
                    r->http_status = 502;
                    r->handler_module = NULL;
                }
                continue; /* do not send Status to client */
            }
            break;
          case HTTP_HEADER_UPGRADE:
            /*(technically, should also verify Connection: upgrade)*/
            /*(flag only for mod_proxy and mod_cgi (for now))*/
            if (opts->backend != BACKEND_PROXY
                && opts->backend != BACKEND_CGI) {
                id = HTTP_HEADER_OTHER;
            }
            break;
          case HTTP_HEADER_CONNECTION:
            if (opts->backend == BACKEND_PROXY) continue;
            /*(should parse for tokens and do case-insensitive match for "close"
             * but this is an imperfect though simplistic attempt to honor
             * backend request to close)*/
            if (NULL != strstr(value, "lose")) r->keep_alive = 0;
            break;
          case HTTP_HEADER_CONTENT_LENGTH:
            r->content_length = strtoul(value, NULL, 10);
            if (*value == '+') ++value;
            break;
          case HTTP_HEADER_TRANSFER_ENCODING:
            /*(assumes "Transfer-Encoding: chunked"; does not verify)*/
            r->resp_decode_chunked = 1;
            r->gw_dechunk = calloc(1, sizeof(response_dechunk));
            /* XXX: future: might consider using chunk_buffer_acquire()
             *      and chunk_buffer_release() for r->gw_dechunk->b */
            force_assert(r->gw_dechunk);
            continue;
          default:
            break;
        }

        http_header_response_insert(r, id, key, key_len, value, strlen(value));
    }

    /* CGI/1.1 rev 03 - 7.2.1.2 */
    /* (proxy requires Status-Line, so never true for proxy)*/
    if (!status_is_set && (r->resp_htags & HTTP_HEADER_LOCATION)) {
        r->http_status = 302;
    }

    return 0;
}


handler_t http_response_parse_headers(request_st * const r, http_response_opts * const opts, buffer * const b) {
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
        i = (b->ptr[0] == '\n') ? 0 : 1;
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
    } else if (i == header_len) { /* (no newline yet; partial header line?) */
    } else if (opts->backend == BACKEND_CGI) {
        /* no HTTP headers, but a body (special-case for CGI compat) */
        /* no colon found; does not appear to be HTTP headers */
        if (0 != http_chunk_append_buffer(r, b)) {
            return HANDLER_ERROR;
        }
        r->http_status = 200; /* OK */
        r->resp_body_started = 1;
        return HANDLER_GO_ON;
    } else {
        /* invalid response headers */
        r->http_status = 502; /* Bad Gateway */
        r->handler_module = NULL;
        return HANDLER_FINISHED;
    }

    if (!is_header_end) {
        /*(reuse MAX_HTTP_REQUEST_HEADER as max size
         * for response headers from backends)*/
        if (header_len > MAX_HTTP_REQUEST_HEADER) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "response headers too large for %s", r->uri.path.ptr);
            r->http_status = 502; /* Bad Gateway */
            r->handler_module = NULL;
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
        r->http_status = 502; /* Bad Gateway */
        r->handler_module = NULL;
        return HANDLER_FINISHED;
    }

    if (0 != http_response_process_headers(r, opts, b)) {
        return HANDLER_ERROR;
    }

    r->resp_body_started = 1;

    if (opts->authorizer
        && (r->http_status == 0 || r->http_status == 200)) {
        return HANDLER_GO_ON;
    }

    if (NULL == r->handler_module) {
        return HANDLER_FINISHED;
    }

    if (opts->local_redir && r->http_status >= 300 && r->http_status < 400){
        /*(r->resp_htags & HTTP_HEADER_LOCATION)*/
        handler_t rc = http_response_process_local_redir(r, blen);
        if (NULL == r->handler_module)
            r->resp_body_started = 0;
        if (rc != HANDLER_GO_ON) return rc;
    }

    if (opts->xsendfile_allow) {
        buffer *vb;
        /* X-Sendfile2 is deprecated; historical for fastcgi */
        if (opts->backend == BACKEND_FASTCGI
            && NULL != (vb = http_header_response_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("X-Sendfile2")))) {
            http_response_xsendfile2(r, vb, opts->xsendfile_docroot);
            /* http_header_response_unset() shortcut for HTTP_HEADER_OTHER */
            buffer_clear(vb); /*(do not send to client)*/
            if (NULL == r->handler_module)
                r->resp_body_started = 0;
            return HANDLER_FINISHED;
        } else if (NULL != (vb = http_header_response_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("X-Sendfile")))
                   || (opts->backend == BACKEND_FASTCGI /* X-LIGHTTPD-send-file is deprecated; historical for fastcgi */
                       && NULL != (vb = http_header_response_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("X-LIGHTTPD-send-file"))))) {
            http_response_xsendfile(r, vb, opts->xsendfile_docroot);
            /* http_header_response_unset() shortcut for HTTP_HEADER_OTHER */
            buffer_clear(vb); /*(do not send to client)*/
            if (NULL == r->handler_module)
                r->resp_body_started = 0;
            return HANDLER_FINISHED;
        }
    }

    if (blen > 0) {
        if (0 != http_chunk_decode_append_mem(r, bstart, blen))
            return HANDLER_ERROR;
    }

    /* (callback for response headers complete) */
    return (opts->headers) ? opts->headers(r, opts) : HANDLER_GO_ON;
}


handler_t http_response_read(request_st * const r, http_response_opts * const opts, buffer * const b, fdnode * const fdn) {
    const int fd = fdn->fd;
    while (1) {
        ssize_t n;
        size_t avail = buffer_string_space(b);
        unsigned int toread = 0;

        if (0 == fdevent_ioctl_fionread(fd, opts->fdfmt, (int *)&toread)) {
            if (avail < toread) {
                size_t blen = buffer_string_length(b);
                if (toread + blen < 4096)
                    toread = 4095 - blen;
                else if (toread > MAX_READ_LIMIT)
                    toread = MAX_READ_LIMIT;
            }
            else if (0 == toread) {
              #if 0
                return (fdevent_fdnode_interest(fdn) & FDEVENT_IN)
                  ? HANDLER_FINISHED  /* read finished */
                  : HANDLER_GO_ON;    /* optimistic read; data not ready */
              #else
                if (!(fdevent_fdnode_interest(fdn) & FDEVENT_IN)) {
                    if (!(r->conf.stream_response_body
                          & FDEVENT_STREAM_RESPONSE_POLLRDHUP))
                        return HANDLER_GO_ON;/*optimistic read; data not ready*/
                }
                if (0 == avail) /* let read() below indicate if EOF or EAGAIN */
                    toread = 1024;
              #endif
            }
        }
        else if (avail < 1024) {
            toread = 4095 - avail;
        }

        if (r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN) {
            off_t cqlen = chunkqueue_length(r->write_queue);
            if (cqlen + (off_t)toread > 65536 - 4096) {
                if (!r->con->is_writable) {
                    /*(defer removal of FDEVENT_IN interest since
                     * connection_state_machine() might be able to send data
                     * immediately, unless !con->is_writable, where
                     * connection_state_machine() might not loop back to call
                     * mod_proxy_handle_subrequest())*/
                    fdevent_fdnode_event_clr(r->con->srv->ev, fdn, FDEVENT_IN);
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
                log_perror(r->conf.errh, __FILE__, __LINE__,
                  "read() %d %d", r->con->fd, fd);
                return HANDLER_ERROR;
            }
        }

        buffer_commit(b, (size_t)n);
      #ifdef __COVERITY__
        /* Coverity Scan overlooks the effect of buffer_commit() */
        b->ptr[buffer_string_length(b)+n] = '\0';
      #endif

        if (NULL != opts->parse) {
            handler_t rc = opts->parse(r, opts, b, (size_t)n);
            if (rc != HANDLER_GO_ON) return rc;
        } else if (0 == n) {
            /* note: no further data is sent to backend after read EOF on socket
             * (not checking for half-closed TCP socket)
             * (backend should read all data desired prior to closing socket,
             *  though might send app-level close data frame, if applicable) */
            return HANDLER_FINISHED; /* read finished */
        } else if (0 == r->resp_body_started) {
            /* split header from body */
            handler_t rc = http_response_parse_headers(r, opts, b);
            if (rc != HANDLER_GO_ON) return rc;
            /* accumulate response in b until headers completed (or error) */
            if (r->resp_body_started) buffer_clear(b);
        } else {
            if (0 != http_chunk_decode_append_buffer(r, b)) {
                /* error writing to tempfile;
                 * truncate response or send 500 if nothing sent yet */
                return HANDLER_ERROR;
            }
            buffer_clear(b);
        }

        if (r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN) {
            if (chunkqueue_length(r->write_queue) > 65536 - 4096) {
                /*(defer removal of FDEVENT_IN interest since
                 * connection_state_machine() might be able to send
                 * data immediately, unless !con->is_writable, where
                 * connection_state_machine() might not loop back to
                 * call the subrequest handler)*/
                if (!r->con->is_writable)
                    fdevent_fdnode_event_clr(r->con->srv->ev, fdn, FDEVENT_IN);
                break;
            }
        }

        if ((size_t)n < avail)
            break; /* emptied kernel read buffer or partial read */
    }

    return HANDLER_GO_ON;
}


int http_cgi_headers (request_st * const r, http_cgi_opts * const opts, http_cgi_header_append_cb cb, void *vdata) {

    /* CGI-SPEC 6.1.2, FastCGI spec 6.3 and SCGI spec */

    int rc = 0;
    const connection * const con = r->con;
    server_socket * const srv_sock = con->srv_socket;
    buffer * const tb = r->tmp_buf;
    const char *s;
    size_t n;
    char buf[LI_ITOSTRING_LENGTH];
    sock_addr *addr;
    sock_addr addrbuf;
    char b2[INET6_ADDRSTRLEN + 1];

    /* (CONTENT_LENGTH must be first for SCGI) */
    if (!opts->authorizer) {
        rc |= cb(vdata, CONST_STR_LEN("CONTENT_LENGTH"),
                 buf, li_itostrn(buf,sizeof(buf),r->reqbody_length));
    }

    if (!buffer_string_is_empty(&r->uri.query)) {
        rc |= cb(vdata, CONST_STR_LEN("QUERY_STRING"),
                        CONST_BUF_LEN(&r->uri.query));
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

        if (buffer_string_length(&r->target_orig) >= len
            && 0 == memcmp(r->target_orig.ptr,
                           opts->strip_request_uri->ptr, len)
            && r->target_orig.ptr[len] == '/') {
            rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                            r->target_orig.ptr+len,
                            buffer_string_length(&r->target_orig)-len);
        } else {
            rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                            CONST_BUF_LEN(&r->target_orig));
        }
    } else {
        rc |= cb(vdata, CONST_STR_LEN("REQUEST_URI"),
                        CONST_BUF_LEN(&r->target_orig));
    }
    if (!buffer_is_equal(&r->target, &r->target_orig)) {
        rc |= cb(vdata, CONST_STR_LEN("REDIRECT_URI"),
                        CONST_BUF_LEN(&r->target));
    }
    /* set REDIRECT_STATUS for php compiled with --force-redirect
     * (if REDIRECT_STATUS has not already been set by error handler) */
    if (0 == r->error_handler_saved_status) {
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
                        CONST_BUF_LEN(&r->uri.path));
        if (!buffer_string_is_empty(&r->pathinfo)) {
            rc |= cb(vdata, CONST_STR_LEN("PATH_INFO"),
                            CONST_BUF_LEN(&r->pathinfo));
            /* PATH_TRANSLATED is only defined if PATH_INFO is set */
            if (!buffer_string_is_empty(opts->docroot)) {
                buffer_copy_buffer(tb, opts->docroot);
            } else {
                buffer_copy_buffer(tb, &r->physical.basedir);
            }
            buffer_append_string_buffer(tb, &r->pathinfo);
            rc |= cb(vdata, CONST_STR_LEN("PATH_TRANSLATED"),
                            CONST_BUF_LEN(tb));
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
        buffer_copy_buffer(tb, opts->docroot);
        buffer_append_string_buffer(tb, &r->uri.path);
        rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                        CONST_BUF_LEN(tb));
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        CONST_BUF_LEN(opts->docroot));
    } else {
        if (opts->break_scriptfilename_for_php) {
            /* php.ini config cgi.fix_pathinfo = 1 need a broken SCRIPT_FILENAME
             * to find out what PATH_INFO is itself
             *
             * see src/sapi/cgi_main.c, init_request_info()
             */
            buffer_copy_buffer(tb, &r->physical.path);
            buffer_append_string_buffer(tb, &r->pathinfo);
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            CONST_BUF_LEN(tb));
        } else {
            rc |= cb(vdata, CONST_STR_LEN("SCRIPT_FILENAME"),
                            CONST_BUF_LEN(&r->physical.path));
        }
        rc |= cb(vdata, CONST_STR_LEN("DOCUMENT_ROOT"),
                        CONST_BUF_LEN(&r->physical.basedir));
    }

    s = get_http_method_name(r->http_method);
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("REQUEST_METHOD"), s, strlen(s));

    s = get_http_version_name(r->http_version);
    force_assert(s);
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PROTOCOL"), s, strlen(s));

    rc |= cb(vdata, CONST_STR_LEN("SERVER_SOFTWARE"),
                    CONST_BUF_LEN(r->conf.server_tag));

    rc |= cb(vdata, CONST_STR_LEN("GATEWAY_INTERFACE"),
                    CONST_STR_LEN("CGI/1.1"));

    rc |= cb(vdata, CONST_STR_LEN("REQUEST_SCHEME"),
                    CONST_BUF_LEN(&r->uri.scheme));

    if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https"))) {
        rc |= cb(vdata, CONST_STR_LEN("HTTPS"), CONST_STR_LEN("on"));
    }

    addr = &srv_sock->addr;
    rc |= cb(vdata, CONST_STR_LEN("SERVER_PORT"),
             buf, li_utostrn(buf,sizeof(buf),sock_addr_get_port(addr)));

    switch (addr->plain.sa_family) {
    case AF_INET:
    case AF_INET6:
        if (sock_addr_is_addr_wildcard(addr)) {
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

    if (!buffer_string_is_empty(r->server_name)) {
        size_t len = buffer_string_length(r->server_name);

        if (r->server_name->ptr[0] == '[') {
            const char *colon = strstr(r->server_name->ptr, "]:");
            if (colon) len = (colon + 1) - r->server_name->ptr;
        } else {
            const char *colon = strchr(r->server_name->ptr, ':');
            if (colon) len = colon - r->server_name->ptr;
        }

        rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"),
                        r->server_name->ptr, len);
    } else {
        /* set to be same as SERVER_ADDR (above) */
        rc |= cb(vdata, CONST_STR_LEN("SERVER_NAME"), s, strlen(s));
    }

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_ADDR"),
                    CONST_BUF_LEN(con->dst_addr_buf));

    rc |= cb(vdata, CONST_STR_LEN("REMOTE_PORT"), buf,
             li_utostrn(buf,sizeof(buf),sock_addr_get_port(&con->dst_addr)));

    for (n = 0; n < r->rqst_headers.used; n++) {
        data_string *ds = (data_string *)r->rqst_headers.data[n];
        if (!buffer_string_is_empty(&ds->value) && !buffer_is_empty(&ds->key)) {
            /* Security: Do not emit HTTP_PROXY in environment.
             * Some executables use HTTP_PROXY to configure
             * outgoing proxy.  See also https://httpoxy.org/ */
            if (buffer_is_equal_caseless_string(&ds->key,
                                                CONST_STR_LEN("Proxy"))) {
                continue;
            }
            buffer_copy_string_encoded_cgi_varnames(tb,
                                                    CONST_BUF_LEN(&ds->key), 1);
            rc |= cb(vdata, CONST_BUF_LEN(tb),
                            CONST_BUF_LEN(&ds->value));
        }
    }

    con->srv->request_env(r);

    for (n = 0; n < r->env.used; n++) {
        data_string *ds = (data_string *)r->env.data[n];
        if (!buffer_is_empty(&ds->value) && !buffer_is_empty(&ds->key)) {
            buffer_copy_string_encoded_cgi_varnames(tb,
                                                    CONST_BUF_LEN(&ds->key), 0);
            rc |= cb(vdata, CONST_BUF_LEN(tb),
                            CONST_BUF_LEN(&ds->value));
        }
    }

    return rc;
}
