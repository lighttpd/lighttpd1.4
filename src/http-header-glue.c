#include "first.h"

#include "sys-time.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"
#include "log.h"
#include "http_chunk.h"
#include "http_cgi.h"
#include "http_date.h"
#include "http_etag.h"
#include "http_header.h"
#include "response.h"
#include "sock_addr.h"
#include "stat_cache.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sys-socket.h"
#include <unistd.h>

/**
 * max size of the HTTP response header from backends
 * (differs from server.max-request-field-size for max request field size)
 */
#define MAX_HTTP_RESPONSE_FIELD_SIZE 65535


__attribute_cold__
int http_response_buffer_append_authority(request_st * const r, buffer * const o) {
	if (!buffer_is_blank(&r->uri.authority)) {
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
				size_t olen = buffer_clen(o);
				if (0 == sock_addr_nameinfo_append_buffer(o, &our_addr, r->conf.errh)) {
					lhost_len = buffer_clen(o) - olen;
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
		} else if (!buffer_is_blank(r->server_name)) {
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
	buffer_clear(o);
	/* XXX: store flag in global at startup? */
	if (r->con->srv->srvconf.absolute_dir_redirect) {
		buffer_append_str2(o, BUF_PTR_LEN(&r->uri.scheme),
		                      CONST_STR_LEN("://"));
		if (0 != http_response_buffer_append_authority(r, o)) {
			return -1;
		}
	}
	buffer *vb;
	if (status >= 300) {
		r->http_status = status;
		r->resp_body_finished = 1;
		vb = http_header_response_set_ptr(r, HTTP_HEADER_LOCATION,
		                                  CONST_STR_LEN("Location"));
	}
	else {
		vb = http_header_response_set_ptr(r, HTTP_HEADER_CONTENT_LOCATION,
		                                  CONST_STR_LEN("Content-Location"));
	}
	buffer_copy_buffer(vb, o);
	buffer_append_string_encoded(vb, BUF_PTR_LEN(&r->uri.path),
	                             ENCODING_REL_URI);
	buffer_append_string_len(vb, CONST_STR_LEN("/"));
	if (!buffer_is_blank(&r->uri.query))
		buffer_append_str2(vb, CONST_STR_LEN("?"),
		                       BUF_PTR_LEN(&r->uri.query));

	return 0;
}

#define MTIME_CACHE_MAX 16
struct mtime_cache_type {
    unix_time64_t mtime;  /* key */
    buffer str;    /* buffer for string representation */
};
static struct mtime_cache_type mtime_cache[MTIME_CACHE_MAX];
static char mtime_cache_str[MTIME_CACHE_MAX][HTTP_DATE_SZ];
/* 30-chars for "%a, %d %b %Y %T GMT" */

void strftime_cache_reset(void) {
    for (int i = 0; i < MTIME_CACHE_MAX; ++i) {
        mtime_cache[i].mtime = -1;
        mtime_cache[i].str.ptr = mtime_cache_str[i];
        mtime_cache[i].str.used = sizeof(mtime_cache_str[0]);
        mtime_cache[i].str.size = sizeof(mtime_cache_str[0]);
    }
}

static const buffer * strftime_cache_get(const unix_time64_t last_mod) {
    /*(note: not bothering to convert *here* if last_mod < 0 (for cache key);
     * last_mod < 0 handled in http_date_time_to_str() call to gmtime64_r())*/

    static int mtime_cache_idx;

    for (int j = 0; j < MTIME_CACHE_MAX; ++j) {
        if (mtime_cache[j].mtime == last_mod)
            return &mtime_cache[j].str; /* found cache-entry */
    }

    if (++mtime_cache_idx == MTIME_CACHE_MAX) mtime_cache_idx = 0;

    const int i = mtime_cache_idx;
    http_date_time_to_str(mtime_cache[i].str.ptr, sizeof(mtime_cache_str[0]),
                          (mtime_cache[i].mtime = last_mod));

    return &mtime_cache[i].str;
}


const buffer * http_response_set_last_modified(request_st * const r, const unix_time64_t lmtime) {
    buffer * const vb =
      http_header_response_set_ptr(r, HTTP_HEADER_LAST_MODIFIED,
                                   CONST_STR_LEN("Last-Modified"));
    buffer_copy_buffer(vb, strftime_cache_get(lmtime));
    return vb;
}


int http_response_handle_cachable(request_st * const r, const buffer * const lmod, const unix_time64_t lmtime) {
	if (!(r->rqst_htags
	      & (light_bshift(HTTP_HEADER_IF_NONE_MATCH)
	        |light_bshift(HTTP_HEADER_IF_MODIFIED_SINCE)))) {
		return HANDLER_GO_ON;
	}

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

	if ((vb = http_header_request_get(r, HTTP_HEADER_IF_NONE_MATCH,
	                                  CONST_STR_LEN("If-None-Match")))) {
		/*(weak etag comparison must not be used for ranged requests)*/
		int range_request = (0 != light_btst(r->rqst_htags, HTTP_HEADER_RANGE));
		if (http_etag_matches(&r->physical.etag, vb->ptr, !range_request)) {
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
		   && (vb = http_header_request_get(r, HTTP_HEADER_IF_MODIFIED_SINCE,
		                                    CONST_STR_LEN("If-Modified-Since")))) {
		/* last-modified handling */
		if (buffer_is_equal(lmod, vb)
		    || !http_date_if_modified_since(BUF_PTR_LEN(vb), lmtime)) {
			r->http_status = 304;
			return HANDLER_FINISHED;
		}
	}

	return HANDLER_GO_ON;
}


void http_response_body_clear (request_st * const r, int preserve_length) {
    r->resp_send_chunked = 0;
    r->resp_body_scratchpad = -1;
    if (light_btst(r->resp_htags, HTTP_HEADER_TRANSFER_ENCODING)) {
        http_header_response_unset(r, HTTP_HEADER_TRANSFER_ENCODING,
                                   CONST_STR_LEN("Transfer-Encoding"));
    }
    if (!preserve_length) { /* preserve for HEAD responses and no-content responses (204, 205, 304) */
        if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)) {
            http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH,
                                       CONST_STR_LEN("Content-Length"));
        }
        /*(if not preserving Content-Length, do not preserve trailers, if any)*/
        r->resp_decode_chunked = 0;
        if (r->gw_dechunk) {
            free(r->gw_dechunk->b.ptr);
            free(r->gw_dechunk);
            r->gw_dechunk = NULL;
        }
    }
    chunkqueue_reset(&r->write_queue);
}


static void http_response_header_clear (request_st * const r) {
    r->http_status = 0;
    r->resp_htags = 0;
    r->resp_header_len = 0;
    r->resp_header_repeated = 0;
    array_reset_data_strings(&r->resp_headers);

    /* Note: http_response_body_clear(r, 0) is not called here
     * r->write_queue should be preserved for additional data after 1xx response
     * However, if http_response_process_headers() was called and response had
     * Transfer-Encoding: chunked set, then other items need to be reset */
    r->resp_send_chunked = 0;
    r->resp_decode_chunked = 0;
    r->resp_body_scratchpad = -1;
    if (r->gw_dechunk) {
        free(r->gw_dechunk->b.ptr);
        free(r->gw_dechunk);
        r->gw_dechunk = NULL;
    }
}


void http_response_reset (request_st * const r) {
    r->http_status = 0;
    r->con->is_writable = 1;
    r->resp_body_finished = 0;
    r->resp_body_started = 0;
    r->handler_module = NULL;
    if (r->physical.path.ptr) { /*(skip for mod_fastcgi authorizer)*/
        buffer_clear(&r->physical.doc_root);
        buffer_clear(&r->physical.basedir);
        buffer_clear(&r->physical.etag);
        buffer_reset(&r->physical.path);
        buffer_reset(&r->physical.rel_path);
    }
    r->resp_htags = 0;
    r->resp_header_len = 0;
    r->resp_header_repeated = 0;
    array_reset_data_strings(&r->resp_headers);
    http_response_body_clear(r, 0);
}


handler_t http_response_reqbody_read_error (request_st * const r, int http_status) {
    r->keep_alive = 0;

    /*(do not change status if response headers already set and possibly sent)*/
    if (0 != r->resp_header_len) return HANDLER_ERROR;

    http_response_body_clear(r, 0);
    r->http_status = http_status;
    r->handler_module = NULL;
    return HANDLER_FINISHED;
}


void http_response_send_file (request_st * const r, buffer * const path, stat_cache_entry *sce) {
	if (NULL == sce
	    || (sce->fd < 0 && __builtin_expect( (0 != sce->st.st_size), 0))) {
		sce = stat_cache_get_entry_open(path, r->conf.follow_symlink);
		if (NULL == sce) {
			r->http_status = (errno == ENOENT) ? 404 : 403;
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "not a regular file: %s -> %s", r->uri.path.ptr, path->ptr);
			return;
		}
		if (sce->fd < 0 && __builtin_expect( (0 != sce->st.st_size), 0)) {
			r->http_status = (errno == ENOENT) ? 404 : 403;
			if (r->conf.log_request_handling) {
				log_perror(r->conf.errh, __FILE__, __LINE__,
				  "file open failed: %s", path->ptr);
			}
			return;
		}
	}

	if (__builtin_expect( (!r->conf.follow_symlink), 0)
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
	if (__builtin_expect( (!S_ISREG(sce->st.st_mode)), 0)) {
		r->http_status = 403;
		if (r->conf.log_file_not_found) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "not a regular file: %s -> %s",
			  r->uri.path.ptr, path->ptr);
		}
		return;
	}

	int allow_caching = (0 == r->http_status || 200 == r->http_status);

	/* set response content-type, if not set already */

	if (!light_btst(r->resp_htags, HTTP_HEADER_CONTENT_TYPE)) {
		const buffer *content_type = stat_cache_content_type_get(sce, r);
		if (content_type && !buffer_is_blank(content_type)) {
			http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
			                         CONST_STR_LEN("Content-Type"),
			                         BUF_PTR_LEN(content_type));
		} else {
			/* we are setting application/octet-stream, but also announce that
			 * this header field might change in the seconds few requests
			 *
			 * This should fix the aggressive caching of FF and the script download
			 * seen by the first installations
			 */
			http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
			                         CONST_STR_LEN("Content-Type"),
			                         CONST_STR_LEN("application/octet-stream"));

			allow_caching = 0;
		}
	}

	if (allow_caching) {
		if (!light_btst(r->resp_htags, HTTP_HEADER_ETAG)
		    && 0 != r->conf.etag_flags) {
			const buffer *etag =
			  stat_cache_etag_get(sce, r->conf.etag_flags);
			if (etag && !buffer_is_blank(etag)) {
				buffer_copy_buffer(&r->physical.etag, etag);
				http_header_response_set(r, HTTP_HEADER_ETAG,
				                         CONST_STR_LEN("ETag"),
				                         BUF_PTR_LEN(&r->physical.etag));
			}
		}

		/* prepare header */
		const buffer *mtime;
		mtime = http_header_response_get(r, HTTP_HEADER_LAST_MODIFIED,
		                                 CONST_STR_LEN("Last-Modified"));
		if (NULL == mtime) {
			mtime = http_response_set_last_modified(r, sce->st.st_mtime);
		}

		if (HANDLER_FINISHED == http_response_handle_cachable(r, mtime, sce->st.st_mtime)) {
			return;
		}
	}

	/* if we are still here, prepare body */

	/* we add it here for all requests
	 * the HEAD request will drop it afterwards again
	 */

	if (0 == sce->st.st_size || 0 == http_chunk_append_file_ref(r, sce)) {
		r->http_status = 200;
		r->resp_body_finished = 1;
		/*(Transfer-Encoding should not have been set at this point)*/
		buffer_append_int(
		  http_header_response_set_ptr(r, HTTP_HEADER_CONTENT_LENGTH,
		                               CONST_STR_LEN("Content-Length")),
		  sce->st.st_size);
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
	if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)) {
		http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH,
		                           CONST_STR_LEN("Content-Length"));
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
	buffer_path_simplify(path);
	if (r->conf.force_lowercase_filenames) {
		buffer_to_lower(path);
	}
	if (buffer_is_blank(path)) {
		r->http_status = 502;
		valid = 0;
	}

	/* check that path is under xdocroot(s)
	 * - xdocroot should have trailing slash appended at config time
	 * - r->conf.force_lowercase_filenames is not a server-wide setting,
	 *   and so can not be definitively applied to xdocroot at config time*/
	if (xdocroot && xdocroot->used) {
		const buffer * const xval = !r->conf.force_lowercase_filenames
		  ? array_match_value_prefix(xdocroot, path)
		  : array_match_value_prefix_nc(xdocroot, path);
		if (NULL == xval) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "X-Sendfile (%s) not under configured x-sendfile-docroot(s)", path->ptr);
			r->http_status = 403;
			valid = 0;
		}
	}

	if (valid) http_response_send_file(r, path, NULL);

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
    if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)) {
        http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH,
                                   CONST_STR_LEN("Content-Length"));
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
        buffer_path_simplify(b);
        if (r->conf.force_lowercase_filenames) {
            buffer_to_lower(b);
        }
        if (buffer_is_blank(b)) {
            r->http_status = 502;
            break;
        }
        if (xdocroot && xdocroot->used) {
            const buffer * const xval = !r->conf.force_lowercase_filenames
              ? array_match_value_prefix(xdocroot, b)
              : array_match_value_prefix_nc(xdocroot, b);
            if (NULL == xval) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "X-Sendfile2 (%s) not under configured x-sendfile-docroot(s)",
                  b->ptr);
                r->http_status = 403;
                break;
            }
        }

        sce = stat_cache_get_entry_open(b, r->conf.follow_symlink);
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
            http_chunk_append_file_ref_range(r, sce, begin_range, range_len);
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
			if (r->http_status < 500 && r->http_status != 400)
				r->http_status = 500;
			r->handler_module = NULL;
			break;
		}
		__attribute_fallthrough__
	case CON_STATE_WRITE:
		if (!r->resp_body_finished) {
			if (r->http_version == HTTP_VERSION_1_1)
				http_chunk_close(r);
		  #if 0
			/* This is a lot of work to make it possible for an HTTP/1.0 client
			 * to detect that response is truncated (after lighttpd made an
			 * HTTP/1.1 request to backend, and backend gave a Transfer-Encoding
			 * chunked response instead of sending Content-Length, and lighttpd
			 * is streaming response to client).  An HTTP/1.0 client is probably
			 * not checking for truncated response, or else client should really
			 * prefer HTTP/1.1 or better.  If lighttpd were streaming response,
			 * there would be no Content-Length and lighttpd would have sent
			 * Connection: close.  Alternatively, since not streaming (if these
			 * conditions are true), could send an HTTP status error instead of
			 * sending partial content with a bogus Content-Length.  If we do
			 * not send an HTTP error status, then response_start hooks may add
			 * caching headers (e.g. mod_expire, mod_setenv).  If in future we
			 * send HTTP error status, might special-case HEAD requests and
			 * clear response body so that response headers (w/o Content-Length)
			 * can be sent.  For now, we have chosen to send partial content,
			 * including generating an incorrect Content-Length (later), and not
			 * to take any of these extra steps. */
			else if (__builtin_expect( (r->http_version == HTTP_VERSION_1_0), 0)
			         && r->gw_dechunk && !r->gw_dechunk->done
			         && !(r->conf.stream_response_body
			              & (FDEVENT_STREAM_RESPONSE
			                |FDEVENT_STREAM_RESPONSE_BUFMIN))) {
				r->keep_alive = 0; /* disable keep-alive, send bogus length */
				http_header_response_set(r, HTTP_HEADER_CONTENT_LENGTH,
				                         CONST_STR_LEN("Content-Length"),
				                         CONST_STR_LEN("9999999999999"));
				http_header_response_unset(r, HTTP_HEADER_ETAG,
				                           CONST_STR_LEN("ETag"));
				http_header_response_unset(r, HTTP_HEADER_LAST_MODIFIED,
				                           CONST_STR_LEN("Last-Modified"));
				http_header_response_unset(r, HTTP_HEADER_CACHE_CONTROL,
				                           CONST_STR_LEN("Cache-Control"));
				http_header_response_unset(r, HTTP_HEADER_EXPIRES,
				                           CONST_STR_LEN("Expires"));
			}
		  #endif
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
    r->resp_body_scratchpad = -1;
    r->keep_alive = 0;
}


__attribute_pure__
static int http_response_append_buffer_simple_accum(const request_st * const r, const off_t len) {
    /*(check to accumulate small reads in buffer before flushing to temp file)*/
    return
      len < 32768 && r->write_queue.last && r->write_queue.last->file.is_temp;
}


static int http_response_append_buffer(request_st * const r, buffer * const mem, const int simple_accum) {
    /* Note: this routine is separate from http_response_append_mem() to
     * potentially avoid copying buffer by using http_chunk_append_buffer(). */

    if (r->resp_decode_chunked)
        return http_chunk_decode_append_buffer(r, mem);

    if (r->resp_body_scratchpad > 0) {
        off_t len = (off_t)buffer_clen(mem);
        r->resp_body_scratchpad -= len;
        if (r->resp_body_scratchpad > 0) {
            if (simple_accum
                && http_response_append_buffer_simple_accum(r, len)) {
                r->resp_body_scratchpad += len;
                return 0; /*(accumulate small reads in buffer)*/
            }
        }
        else { /* (r->resp_body_scratchpad <= 0) */
            r->resp_body_finished = 1;
            if (__builtin_expect( (r->resp_body_scratchpad < 0), 0)) {
                /*(silently truncate if data exceeds Content-Length)*/
                len += r->resp_body_scratchpad;
                r->resp_body_scratchpad = 0;
                buffer_truncate(mem, (uint32_t)len);
            }
        }
    }
    else if (0 == r->resp_body_scratchpad) {
        /*(silently truncate if data exceeds Content-Length)*/
        buffer_clear(mem);
        return 0;
    }
    else if (simple_accum
             && http_response_append_buffer_simple_accum(r, buffer_clen(mem))) {
        return 0; /*(accumulate small reads in buffer)*/
    }
    return http_chunk_append_buffer(r, mem);
}


#ifdef HAVE_SPLICE
static int http_response_append_splice(request_st * const r, http_response_opts * const opts, buffer * const b, const int fd, unsigned int toread) {
    /* check if worthwhile to splice() to avoid copying through userspace */
    /*assert(opts->simple_accum);*//*(checked in caller)*/
    if (r->resp_body_scratchpad >= toread
        && (toread > 32768
            || (toread >= 8192 /*(!http_response_append_buffer_simple_accum())*/
                && r->write_queue.last && r->write_queue.last->file.is_temp))) {

        if (!buffer_is_blank(b)) {
            /*(flush small reads previously accumulated in b)*/
            int rc = http_response_append_buffer(r, b, 0); /*(0 to flush)*/
            chunk_buffer_yield(b); /*(improve large buf reuse)*/
            if (__builtin_expect( (0 != rc), 0)) return -1; /* error */
        }

        /*assert(opts->fdfmt == S_IFSOCK || opts->fdfmt == S_IFIFO);*/
        ssize_t n = (opts->fdfmt == S_IFSOCK)
          ? chunkqueue_append_splice_sock_tempfile(
              &r->write_queue, fd, toread, r->conf.errh)
          : chunkqueue_append_splice_pipe_tempfile(
              &r->write_queue, fd, toread, r->conf.errh);
        if (__builtin_expect( (n >= 0), 1)) {
            if (0 == (r->resp_body_scratchpad -= n))
                r->resp_body_finished = 1;
            return 1; /* success */
        }
        else if (n != -EINVAL)
            return -1; /* error */
        /*(fall through; target filesystem w/o splice() support)*/
    }
    return 0; /* not handled */
}
#endif


static int http_response_append_mem(request_st * const r, const char * const mem, size_t len) {
    if (r->resp_decode_chunked)
        return http_chunk_decode_append_mem(r, mem, len);

    if (r->resp_body_scratchpad > 0) {
        r->resp_body_scratchpad -= (off_t)len;
        if (r->resp_body_scratchpad <= 0) {
            r->resp_body_finished = 1;
            if (__builtin_expect( (r->resp_body_scratchpad < 0), 0)) {
                /*(silently truncate if data exceeds Content-Length)*/
                len = (size_t)(r->resp_body_scratchpad + (off_t)len);
                r->resp_body_scratchpad = 0;
            }
        }
    }
    else if (0 == r->resp_body_scratchpad) {
        /*(silently truncate if data exceeds Content-Length)*/
        return 0;
    }
    return http_chunk_append_mem(r, mem, len);
}


int http_response_transfer_cqlen(request_st * const r, chunkqueue * const cq, size_t len) {
    /*(intended for use as callback from modules setting opts->parse(),
     * e.g. mod_fastcgi and mod_ajp13)
     *(do not set r->resp_body_finished here since those protocols handle it)*/
    if (0 == len) return 0;
    if (__builtin_expect( (!r->resp_decode_chunked), 1)) {
        const size_t olen = len;
        if (r->resp_body_scratchpad >= 0) {
            r->resp_body_scratchpad -= (off_t)len;
            if (__builtin_expect( (r->resp_body_scratchpad < 0), 0)) {
                /*(silently truncate if data exceeds Content-Length)*/
                len = (size_t)(r->resp_body_scratchpad + (off_t)len);
                r->resp_body_scratchpad = 0;
            }
        }
        int rc = http_chunk_transfer_cqlen(r, cq, len);
        if (__builtin_expect( (0 != rc), 0))
            return -1;
        if (__builtin_expect( (olen != len), 0)) /*discard excess data, if any*/
            chunkqueue_mark_written(cq, (off_t)(olen - len));
    }
    else {
        /* specialized use by opts->parse() to decode chunked encoding;
         * FastCGI, AJP13 packet data is all type MEM_CHUNK
         * (This extra copy can be avoided if FastCGI backend does not send
         *  Transfer-Encoding: chunked, which FastCGI is not supposed to do) */
        uint32_t remain = (uint32_t)len, wr;
        for (const chunk *c = cq->first; c && remain; c=c->next, remain-=wr) {
            /*assert(c->type == MEM_CHUNK);*/
            wr = buffer_clen(c->mem) - c->offset;
            if (wr > remain) wr = remain;
            if (0 != http_chunk_decode_append_mem(r, c->mem->ptr+c->offset, wr))
                return -1;
        }
        chunkqueue_mark_written(cq, len);
    }
    return 0;
}


static int http_response_process_headers(request_st * const restrict r, http_response_opts * const restrict opts, char * const restrict s, const unsigned short hoff[8192], const int is_nph) {
    int i = 1;

    if (is_nph) {
        /* non-parsed headers ... we parse them anyway */
        /* (accept HTTP/2.0 and HTTP/3.0 from naive non-proxy backends) */
        /* (http_header_str_to_code() expects certain chars after code) */
        if (s[12] == '\r' || s[12] == '\n') s[12] = '\0';/*(caller checked 12)*/
        if ((s[5] == '1' || opts->backend != BACKEND_PROXY) && s[6] == '.'
            && (s[7] == '1' || s[7] == '0') && s[8] == ' ') {
            /* after the space should be a status code for us */
            int status = http_header_str_to_code(s+9);
            if (status >= 100 && status < 1000) {
              #ifdef __COVERITY__ /* Coverity false positive for tainted data */
                status = 200;/* http_header_str_to_code() validates, untaints */
              #endif
                r->http_status = status;
                opts->local_redir = 0; /*(disable; status was set)*/
                i = 2;
            } /* else we expected 3 digits and didn't get them */
        }

        if (0 == r->http_status) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "invalid HTTP status line: %s", s);
            r->http_status = 502; /* Bad Gateway */
            r->handler_module = NULL;
            return 0;
        }
    }
    else if (__builtin_expect( (opts->backend == BACKEND_PROXY), 0)) {
        /* invalid response Status-Line from HTTP proxy */
        r->http_status = 502; /* Bad Gateway */
        r->handler_module = NULL;
        return 0;
    }

    for (; i < hoff[0]; ++i) {
        const char *k = s+hoff[i], *value;
        char *end = s+hoff[i+1]-1; /*('\n')*/

        /* parse the headers */
        if (NULL == (value = memchr(k, ':', end - k))) {
            /* we expect: "<key>: <value>\r\n" */
            continue;
        }

        const uint32_t klen = (uint32_t)(value - k);
        if (0 == klen) continue; /*(already ignored when writing response)*/
        const enum http_header_e id = http_header_hkey_get(k, klen);

        do { ++value; } while (*value == ' ' || *value == '\t'); /* skip LWS */
        /* strip the \r?\n */
        if (end > value && end[-1] == '\r') --end;
        /*(XXX: not done; could remove trailing whitespace)*/

        if (opts->authorizer && (0 == r->http_status || 200 == r->http_status)){
            if (id == HTTP_HEADER_STATUS) {
                end[0] = '\0';
                int status = http_header_str_to_code(value);
                if (status >= 100 && status < 1000) {
                  #ifdef __COVERITY__ /* Coverity false positive for tainted */
                    status = 200;/* http_header_str_to_code() validates */
                  #endif
                    r->http_status = status;
                    opts->local_redir = 0; /*(disable; status was set)*/
                }
                else {
                    r->http_status = 502; /* Bad Gateway */
                    break; /*(do not unset r->handler_module)*/
                }
            }
            else if (id == HTTP_HEADER_OTHER && klen > 9 && (k[0] & 0xdf) == 'V'
                     && buffer_eq_icase_ssn(k, CONST_STR_LEN("Variable-"))) {
                http_header_env_append(r, k + 9, klen - 9, value, end - value);
            }
            continue;
        }

        switch (id) {
          case HTTP_HEADER_STATUS:
            if (opts->backend != BACKEND_PROXY) {
                end[0] = '\0';
                int status = http_header_str_to_code(value);
                if (status >= 100 && status < 1000) {
                  #ifdef __COVERITY__ /* Coverity false positive for tainted */
                    status = 200;/* http_header_str_to_code() validates */
                  #endif
                    r->http_status = status;
                    opts->local_redir = 0; /*(disable; status was set)*/
                }
                else {
                    r->http_status = 502;
                    r->handler_module = NULL;
                }
                continue; /* do not send Status to client */
            } /*(else pass w/o parse for BACKEND_PROXY)*/
            break;
          case HTTP_HEADER_UPGRADE:
            /*(technically, should also verify Connection: upgrade)*/
            /*(flag only for mod_proxy and mod_cgi (for now))*/
            if (opts->backend != BACKEND_PROXY && opts->backend != BACKEND_CGI)
                continue;
            if (r->http_version >= HTTP_VERSION_2) continue;
            break;
          case HTTP_HEADER_CONNECTION:
            if (opts->backend == BACKEND_PROXY) continue;
            /*(simplistic attempt to honor backend request to close)*/
            if (http_header_str_contains_token(value, end - value,
                                               CONST_STR_LEN("close")))
                r->keep_alive = 0;
            if (r->http_version >= HTTP_VERSION_2) continue;
            break;
          case HTTP_HEADER_CONTENT_LENGTH:
            if (*value == '+') ++value;
            if (!r->resp_decode_chunked
                && !light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)) {
                const char *err = end;
                while (err > value && (err[-1] == ' ' || err[-1] == '\t')) --err;
                if (err <= value) continue; /*(might error 502 Bad Gateway)*/
                uint32_t vlen = (uint32_t)(err - value);
                r->resp_body_scratchpad =
                  (off_t)li_restricted_strtoint64(value, vlen, &err);
                if (err != value + vlen) {
                    /*(invalid Content-Length value from backend;
                     * read from backend until backend close, hope for the best)
                     *(might choose to treat this as 502 Bad Gateway) */
                    r->resp_body_scratchpad = -1;
                }
            }
            else {
                /* ignore Content-Length if Transfer-Encoding: chunked
                 * ignore subsequent (multiple) Content-Length
                 * (might choose to treat this as 502 Bad Gateway) */
                continue;
            }
            break;
          case HTTP_HEADER_TRANSFER_ENCODING:
            if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)) {
                /* ignore Content-Length if Transfer-Encoding: chunked
                 * (might choose to treat this as 502 Bad Gateway) */
                r->resp_body_scratchpad = -1;
                http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH,
                                           CONST_STR_LEN("Content-Length"));
            }
            /*(assumes "Transfer-Encoding: chunked"; does not verify)*/
            r->resp_decode_chunked = 1;
            r->gw_dechunk = calloc(1, sizeof(response_dechunk));
            force_assert(r->gw_dechunk);
            continue;
          case HTTP_HEADER_HTTP2_SETTINGS:
            /* RFC7540 3.2.1
             *   A server MUST NOT send this header field. */
            /* (not bothering to remove HTTP2-Settings from Connection) */
            continue;
          case HTTP_HEADER_OTHER:
            /* ignore invalid headers with whitespace between label and ':'
             * (if less strict behavior is desired, check and correct above
             *  this switch() statement, but not for BACKEND_PROXY) */
            if (k[klen-1] == ' ' || k[klen-1] == '\t')
                continue;
            break;
          default:
            break;
        }

        if (end - value)
            http_header_response_insert(r, id, k, klen, value, end - value);
    }

    /* CGI/1.1 rev 03 - 7.2.1.2 */
    /* (proxy requires Status-Line, so never true for proxy)*/
    if (0 == r->http_status && light_btst(r->resp_htags, HTTP_HEADER_LOCATION)){
        r->http_status = 302;
    }

    return 0;
}


static http_response_send_1xx_cb http_response_send_1xx_h1;
static http_response_send_1xx_cb http_response_send_1xx_h2;

void
http_response_send_1xx_cb_set (http_response_send_1xx_cb fn, int vers)
{
    if (vers >= HTTP_VERSION_2)
        http_response_send_1xx_h2 = fn;
    else if (vers == HTTP_VERSION_1_1)
        http_response_send_1xx_h1 = fn;
}


int
http_response_send_1xx (request_st * const r)
{
    http_response_send_1xx_cb http_response_send_1xx_fn = NULL;
    if (r->http_version >= HTTP_VERSION_2)
        http_response_send_1xx_fn = http_response_send_1xx_h2;
    else if (r->http_version == HTTP_VERSION_1_1)
        http_response_send_1xx_fn = http_response_send_1xx_h1;

    if (http_response_send_1xx_fn && !http_response_send_1xx_fn(r, r->con))
        return 0; /* error occurred */

    http_response_header_clear(r);
    return 1; /* 1xx response handled */
}


__attribute_cold__
__attribute_noinline__
static int
http_response_check_1xx (request_st * const r, buffer * const restrict b, uint32_t hlen, uint32_t dlen)
{
    /* pass through unset r->http_status (not 1xx) or 101 Switching Protocols */
    if (0 == r->http_status || 101 == r->http_status)
        return 0; /* pass through as-is; do not loop for addtl response hdrs */

    /* discard 1xx response from b; already processed
     * (but further response might follow in b, so preserve addtl data) */
    if (dlen)
        memmove(b->ptr, b->ptr+hlen, dlen);
    buffer_truncate(b, dlen);

    /* Note: while GW_AUTHORIZER mode is not expected to return 1xx, as a
     * feature, 1xx responses from authorizer are passed back to client */

    return http_response_send_1xx(r);
    /* 0: error, 1: 1xx response handled; loop for next response headers */
}


__attribute_noinline__
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
    const char *bstart;
    uint32_t blen;

    do {
        uint32_t header_len, is_nph = 0;
        unsigned short hoff[8192]; /* max num header lines + 3; 16k on stack */
        hoff[0] = 1; /* number of lines */
        hoff[1] = 0; /* base offset for all lines */
        hoff[2] = 0; /* offset from base for 2nd line; init 0 to detect '\n' */
        blen = buffer_clen(b);
        header_len = http_header_parse_hoff(b->ptr, blen, hoff);
        if ((header_len ? header_len : blen) > MAX_HTTP_RESPONSE_FIELD_SIZE) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "response headers too large for %s", r->uri.path.ptr);
            r->http_status = 502; /* Bad Gateway */
            r->handler_module = NULL;
            return HANDLER_FINISHED;
        }
        if (hoff[2]) { /*(at least one newline found if offset is non-zero)*/
            /*("HTTP/1.1 200 " is at least 13 chars + \r\n; 12 w/o final ' ')*/
            is_nph = hoff[2] >= 12 && 0 == memcmp(b->ptr, "HTTP/", 5);
            if (!is_nph) {
                const char * colon = memchr(b->ptr, ':', hoff[2]-1);
                if (__builtin_expect( (NULL == colon), 0)) {
                    if (hoff[2] <= 2 && (1 == hoff[2] || b->ptr[0] == '\r')) {
                        /* no HTTP headers */
                    }
                    else if (opts->backend == BACKEND_CGI) {
                        /* no HTTP headers, but body (special-case for CGI)*/
                        /* no colon found; does not appear to be HTTP headers */
                        if (0 != http_chunk_append_buffer(r, b)) {
                            return HANDLER_ERROR;
                        }
                        r->http_status = 200; /* OK */
                        r->resp_body_started = 1;
                        return HANDLER_GO_ON;
                    }
                    else {
                        /* invalid response headers */
                        r->http_status = 502; /* Bad Gateway */
                        r->handler_module = NULL;
                        return HANDLER_FINISHED;
                    }
                }
            }
        } /* else no newline yet; partial header line?) */
        if (0 == header_len) /* headers incomplete */
            return HANDLER_GO_ON;

        /* the body starts after the EOL */
        bstart = b->ptr + header_len;
        blen -= header_len;

        if (0 != http_response_process_headers(r, opts, b->ptr, hoff, is_nph))
            return HANDLER_ERROR;

    } while (r->http_status < 200
             && http_response_check_1xx(r, b, bstart - b->ptr, blen));

    r->resp_body_started = 1;

    if (opts->authorizer
        && (r->http_status == 0 || r->http_status == 200)) {
        return HANDLER_GO_ON;
    }

    if (NULL == r->handler_module) {
        return HANDLER_FINISHED;
    }

    if (opts->local_redir && r->http_status >= 300 && r->http_status < 400
        && 0 == blen) {
        /* (Might not have begun to receive body yet, but do skip local-redir
         *  if we already have started receiving a response body (blen > 0)) */
        /*(light_btst(r->resp_htags, HTTP_HEADER_LOCATION))*/
        handler_t rc = http_cgi_local_redir(r);
        if (rc != HANDLER_GO_ON) return rc;
    }

    if (opts->xsendfile_allow) {
        buffer *vb;
        /* X-Sendfile2 is deprecated; historical for fastcgi */
        if (opts->backend == BACKEND_FASTCGI
            && NULL != (vb = http_header_response_get(r, HTTP_HEADER_OTHER,
                                                      CONST_STR_LEN("X-Sendfile2")))) {
            http_response_xsendfile2(r, vb, opts->xsendfile_docroot);
            /* http_header_response_unset() shortcut for HTTP_HEADER_OTHER */
            buffer_clear(vb); /*(do not send to client)*/
            if (NULL == r->handler_module)
                r->resp_body_started = 0;
            return HANDLER_FINISHED;
        } else if (NULL != (vb = http_header_response_get(r, HTTP_HEADER_OTHER,
                                                          CONST_STR_LEN("X-Sendfile")))
                   || (opts->backend == BACKEND_FASTCGI /* X-LIGHTTPD-send-file is deprecated; historical for fastcgi */
                       && NULL != (vb = http_header_response_get(r, HTTP_HEADER_OTHER,
                                                                 CONST_STR_LEN("X-LIGHTTPD-send-file"))))) {
            http_response_xsendfile(r, vb, opts->xsendfile_docroot);
            /* http_header_response_unset() shortcut for HTTP_HEADER_OTHER */
            buffer_clear(vb); /*(do not send to client)*/
            if (NULL == r->handler_module)
                r->resp_body_started = 0;
            return HANDLER_FINISHED;
        }
    }

    if (blen > 0) {
        /* modules which set opts->parse() (e.g. mod_ajp13, mod_fastcgi) must
         * not pass buffer with excess data to this routine (and do not do so
         * due to framing of response headers separately from response body) */
        int rc = http_response_append_mem(r, bstart, blen);
        if (__builtin_expect( (0 != rc), 0))
            return HANDLER_ERROR;
    }

    /* (callback for response headers complete) */
    return (opts->headers) ? opts->headers(r, opts) : HANDLER_GO_ON;
}


handler_t http_response_read(request_st * const r, http_response_opts * const opts, buffer * const b, fdnode * const fdn) {
    const int fd = fdn->fd;
    ssize_t n;
    size_t avail;
    /*size_t total = 0;*/
    do {
        unsigned int toread = 0;
        avail = buffer_string_space(b);

        if (0 == fdevent_ioctl_fionread(fd, opts->fdfmt, (int *)&toread)) {

          #ifdef HAVE_SPLICE
            /* check if worthwhile to splice() to avoid copying to userspace */
            if (opts->simple_accum) {
                int rc = http_response_append_splice(r, opts, b, fd, toread);
                if (rc) {
                    if (__builtin_expect( (rc > 0), 1))
                        break;
                    return HANDLER_ERROR;
                } /*(fall through to handle traditionally)*/
            }
          #endif

            if (avail < toread) {
                uint32_t blen = buffer_clen(b);
                if (toread + blen < 4096)
                    toread = 4095 - blen;
                else if (toread > opts->max_per_read)
                    toread = opts->max_per_read;
                /* reduce amount read for response headers to reduce extra data
                 * copying for initial data following response headers
                 * (see http_response_parse_headers())
                 * (This seems reasonable to do even if opts->parse is set)
                 * (default chunk buffer is 8k; typical response headers < 8k)
                 * (An alternative might be the opposite: read extra, e.g. 128k,
                 *  if data available, in order to write to temp files sooner)*/
                if (toread > 8192 && !r->resp_body_started) toread = 8192;
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
            off_t cqlen = chunkqueue_length(&r->write_queue);
            if (cqlen + (off_t)toread > 65536 - 4096) {
                if (!r->con->is_writable) {
                    /*(defer removal of FDEVENT_IN interest since
                     * connection_state_machine() might be able to send data
                     * immediately, unless !con->is_writable, where
                     * connection_state_machine() might not loop back to call
                     * mod_proxy_handle_subrequest())*/
                    fdevent_fdnode_event_clr(r->con->srv->ev, fdn, FDEVENT_IN);
                }
                if (cqlen >= 65536-1) {
                    if (buffer_is_blank(b))
                        chunk_buffer_yield(b); /*(improve large buf reuse)*/
                    return HANDLER_GO_ON;
                }
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
            avail = toread < opts->max_per_read && avail
              ? avail-1+toread
              : toread;
            avail = chunk_buffer_prepare_append(b, avail);
        }

        n = read(fd, b->ptr+buffer_clen(b), avail);

        if (n < 0) {
            switch (errno) {
              case EAGAIN:
             #ifdef EWOULDBLOCK
             #if EWOULDBLOCK != EAGAIN
              case EWOULDBLOCK:
             #endif
             #endif
              case EINTR:
                if (buffer_is_blank(b))
                    chunk_buffer_yield(b); /*(improve large buf reuse)*/
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
        b->ptr[buffer_clen(b)+n] = '\0';
      #endif

        if (NULL != opts->parse) {
            handler_t rc = opts->parse(r, opts, b, (size_t)n);
            if (rc != HANDLER_GO_ON) return rc;
        } else if (0 == n) {
            if (buffer_is_blank(b))
                chunk_buffer_yield(b); /*(improve large buf reuse)*/
            else if (opts->simple_accum) {
                /*(flush small reads previously accumulated in b)*/
                int rc = http_response_append_buffer(r, b, 0); /*(0 to flush)*/
                chunk_buffer_yield(b); /*(improve large buf reuse)*/
                if (__builtin_expect( (0 != rc), 0)) {
                    /* error writing to tempfile;
                     * truncate response or send 500 if nothing sent yet */
                    return HANDLER_ERROR;
                }
            }
            /* note: no further data is sent to backend after read EOF on socket
             * (not checking for half-closed TCP socket)
             * (backend should read all data desired prior to closing socket,
             *  though might send app-level close data frame, if applicable) */
            return HANDLER_FINISHED; /* read finished */
        } else if (0 == r->resp_body_started) {
            /* split header from body */
            handler_t rc = http_response_parse_headers(r, opts, b);
            if (rc != HANDLER_GO_ON) return rc;
            /* accumulate response in b until headers completed (or error)*/
            if (r->resp_body_started) {
                buffer_clear(b);
                /* check if Content-Length provided and response body received
                 * (done here instead of http_response_process_headers() since
                 *  backends which set opts->parse() might handle differently)*/
                if (0 == r->resp_body_scratchpad)
                    r->resp_body_finished = 1;
                /* enable simple accumulation of small reads in some situations
                 * no Content-Length (will read to EOF)
                 * Content-Length (will read until r->resp_body_scratchpad == 0)
                 * not chunked-encoding
                 * not bufmin streaming
                 * (no custom parse routine set for opts->parse()) */
                else if (!r->resp_decode_chunked /* && NULL == opts->parse */
                         && !(r->conf.stream_response_body
                              & FDEVENT_STREAM_RESPONSE_BUFMIN))
                    opts->simple_accum = 1;
            }
        } else {
            /* flush b (do not accumulate small reads) if streaming and might
             * write to client since there is a chance that r->write_queue is
             * fully written to client (no more temp files) and then we do not
             * want to hold onto buffered data in b for an indeterminate time
             * until next read of data from backend */
            int simple_accum = opts->simple_accum
                            && (!(r->conf.stream_response_body
                                  & FDEVENT_STREAM_RESPONSE)
                                || !r->con->is_writable);
            int rc = http_response_append_buffer(r, b, simple_accum);
            if (__builtin_expect( (0 != rc), 0)) {
                /* error writing to tempfile;
                 * truncate response or send 500 if nothing sent yet */
                return HANDLER_ERROR;
            }
            /*buffer_clear(b);*//*http_response_append_buffer() clears*/
            /* small reads might accumulate in b; not necessarily cleared */
        }

        if (r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN) {
            if (chunkqueue_length(&r->write_queue) > 65536 - 4096) {
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
    } while (!r->resp_body_started); /*(loop to read large response headers)*/
    /*while (0);*//*(extra logic might benefit systems without FIONREAD)*/
    /*while ((size_t)n == avail && (total += (size_t)n) < opts->max_per_read);*/
    /* else emptied kernel read buffer or partial read or reached read limit */

    if (buffer_is_blank(b)) chunk_buffer_yield(b); /*(improve large buf reuse)*/

    return (!r->resp_body_finished ? HANDLER_GO_ON : HANDLER_FINISHED);
}
