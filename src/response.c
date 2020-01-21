#include "first.h"

#include "response.h"
#include "request.h"
#include "base.h"
#include "burl.h"
#include "fdevent.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "stat_cache.h"
#include "chunk.h"

#include "plugin.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

__attribute_cold__
static int http_response_omit_header(request_st * const r, const data_string * const ds) {
    const size_t klen = buffer_string_length(&ds->key);
    if (klen == sizeof("X-Sendfile")-1
        && buffer_eq_icase_ssn(ds->key.ptr, CONST_STR_LEN("X-Sendfile")))
        return 1;
    if (klen >= sizeof("X-LIGHTTPD-")-1
        && buffer_eq_icase_ssn(ds->key.ptr, CONST_STR_LEN("X-LIGHTTPD-"))) {
        if (klen == sizeof("X-LIGHTTPD-KBytes-per-second")-1
            && buffer_eq_icase_ssn(ds->key.ptr+sizeof("X-LIGHTTPD-")-1,
                                   CONST_STR_LEN("KBytes-per-second"))) {
            /* "X-LIGHTTPD-KBytes-per-second" */
            off_t limit = strtol(ds->value.ptr, NULL, 10) << 10; /*(*=1024)*/
            if (limit > 0
                && (limit < r->conf.bytes_per_second
                    || 0 == r->conf.bytes_per_second)) {
                r->conf.bytes_per_second = limit;
            }
        }
        return 1;
    }
    return 0;
}

int http_response_write_header(request_st * const r) {
	chunkqueue * const cq = r->write_queue;
	buffer * const b = chunkqueue_prepend_buffer_open(cq);

	if (r->http_version == HTTP_VERSION_1_1) {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.1 "));
	} else {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.0 "));
	}
	http_status_append(b, r->http_status);

	/* disable keep-alive if requested */

	if (r->con->request_count > r->conf.max_keep_alive_requests || 0 == r->conf.max_keep_alive_idle) {
		r->keep_alive = 0;
	} else if (0 != r->reqbody_length
		   && r->reqbody_length != r->reqbody_queue->bytes_in
		   && (NULL == r->handler_module || 0 == r->conf.stream_request_body)) {
		r->keep_alive = 0;
	} else {
		r->con->keep_alive_idle = r->conf.max_keep_alive_idle;
	}

	if ((r->resp_htags & HTTP_HEADER_UPGRADE) && r->http_version == HTTP_VERSION_1_1) {
		http_header_response_set(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"), CONST_STR_LEN("upgrade"));
	} else if (0 == r->keep_alive) {
		http_header_response_set(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"), CONST_STR_LEN("close"));
	} else if (r->http_version == HTTP_VERSION_1_0) {/*(&& r->keep_alive != 0)*/
		http_header_response_set(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"), CONST_STR_LEN("keep-alive"));
	}

	if (304 == r->http_status && (r->resp_htags & HTTP_HEADER_CONTENT_ENCODING)) {
		http_header_response_unset(r, HTTP_HEADER_CONTENT_ENCODING, CONST_STR_LEN("Content-Encoding"));
	}

	/* add all headers */
	for (size_t i = 0; i < r->resp_headers.used; ++i) {
		const data_string * const ds = (data_string *)r->resp_headers.data[i];

		if (buffer_string_is_empty(&ds->value)) continue;
		if (buffer_string_is_empty(&ds->key)) continue;
		if ((ds->key.ptr[0] & 0xdf) == 'X' && http_response_omit_header(r, ds))
			continue;

		buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
		buffer_append_string_buffer(b, &ds->key);
		buffer_append_string_len(b, CONST_STR_LEN(": "));
		buffer_append_string_buffer(b, &ds->value);
	}

	if (!(r->resp_htags & HTTP_HEADER_DATE)) {
		static time_t tlast;
		static char tstr[32]; /* 30-chars for "%a, %d %b %Y %H:%M:%S GMT" */
		static size_t tlen;

		/* HTTP/1.1 requires a Date: header */
		buffer_append_string_len(b, CONST_STR_LEN("\r\nDate: "));

		/* cache the generated timestamp */
		const time_t cur_ts = log_epoch_secs;
		if (tlast != cur_ts) {
			tlast = cur_ts;
			tlen = strftime(tstr, sizeof(tstr),
			                "%a, %d %b %Y %H:%M:%S GMT", gmtime(&tlast));
		}

		buffer_append_string_len(b, tstr, tlen);
	}

	if (!(r->resp_htags & HTTP_HEADER_SERVER)) {
		if (!buffer_string_is_empty(r->conf.server_tag)) {
			buffer_append_string_len(b, CONST_STR_LEN("\r\nServer: "));
			buffer_append_string_len(b, CONST_BUF_LEN(r->conf.server_tag));
		}
	}

	buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

	r->resp_header_len = buffer_string_length(b);

	if (r->conf.log_response_header) {
		log_error(r->conf.errh,__FILE__,__LINE__,"Response-Header:\n%s",b->ptr);
	}

	chunkqueue_prepend_buffer_commit(cq);
	return 0;
}

static handler_t http_response_physical_path_check(request_st * const r) {
	stat_cache_entry *sce = stat_cache_get_entry(&r->physical.path);

	if (sce) {
		/* file exists */
	} else {
		char *pathinfo = NULL;
		switch (errno) {
		case EACCES:
			r->http_status = 403;

			if (r->conf.log_request_handling) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "-- access denied");
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "Path         : %s", r->physical.path.ptr);
			}

			buffer_reset(&r->physical.path);
			return HANDLER_FINISHED;
		case ENAMETOOLONG:
			/* file name to be read was too long. return 404 */
		case ENOENT:
			if (r->http_method == HTTP_METHOD_OPTIONS
			    && NULL != http_header_response_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Allow"))) {
				r->http_status = 200;
				return HANDLER_FINISHED;
			}

			r->http_status = 404;

			if (r->conf.log_request_handling) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "-- file not found");
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "Path         : %s", r->physical.path.ptr);
			}

			buffer_reset(&r->physical.path);
			return HANDLER_FINISHED;
		case ENOTDIR:
			/* PATH_INFO ! :) */
			break;
		default:
			/* we have no idea what happend. let's tell the user so. */
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "file not found ... or so: %s -> %s",
			  r->uri.path.ptr, r->physical.path.ptr);

			r->http_status = 500;
			buffer_reset(&r->physical.path);

			return HANDLER_FINISHED;
		}

		/* not found, perhaps PATHINFO */

		{
			/*(might check at startup that s->document_root does not end in '/')*/
			size_t len = buffer_string_length(&r->physical.basedir);
			if (len > 0 && '/' == r->physical.basedir.ptr[len-1]) --len;
			pathinfo = r->physical.path.ptr + len;
			if ('/' != *pathinfo) {
				pathinfo = NULL;
			}
			else if (pathinfo == r->physical.path.ptr) { /*(basedir is "/")*/
				pathinfo = strchr(pathinfo+1, '/');
			}
		}

		buffer * const tb = r->tmp_buf;
		for (char *pprev = pathinfo; pathinfo; pprev = pathinfo, pathinfo = strchr(pathinfo+1, '/')) {
			buffer_copy_string_len(tb, r->physical.path.ptr, pathinfo - r->physical.path.ptr);
			stat_cache_entry *nsce = stat_cache_get_entry(tb);
			if (NULL == nsce) {
				pathinfo = pathinfo != pprev ? pprev : NULL;
				break;
			}
			sce = nsce;
			if (!S_ISDIR(sce->st.st_mode)) break;
		}

		if (NULL == pathinfo || !S_ISREG(sce->st.st_mode)) {
			/* no it really doesn't exists */
			r->http_status = 404;

			if (r->conf.log_file_not_found) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "file not found: %s -> %s",
				  r->uri.path.ptr, r->physical.path.ptr);
			}

			buffer_reset(&r->physical.path);

			return HANDLER_FINISHED;
		}

		/* we have a PATHINFO */
		if (pathinfo) {
			size_t len = strlen(pathinfo), reqlen;
			if (r->conf.force_lowercase_filenames
			    && len <= (reqlen = buffer_string_length(&r->target))
			    && buffer_eq_icase_ssn(r->target.ptr + reqlen - len, pathinfo, len)) {
				/* attempt to preserve case-insensitive PATH_INFO
				 * (works in common case where mod_alias, mod_magnet, and other modules
				 *  have not modified the PATH_INFO portion of request URI, or did so
				 *  with exactly the PATH_INFO desired) */
				buffer_copy_string_len(&r->pathinfo, r->target.ptr + reqlen - len, len);
			} else {
				buffer_copy_string_len(&r->pathinfo, pathinfo, len);
			}

			/*
			 * shorten uri.path
			 */

			buffer_string_set_length(&r->uri.path, buffer_string_length(&r->uri.path) - len);
			buffer_string_set_length(&r->physical.path, (size_t)(pathinfo - r->physical.path.ptr));
		}
	}

	if (!r->conf.follow_symlink
	    && 0 != stat_cache_path_contains_symlink(&r->physical.path, r->conf.errh)) {
		r->http_status = 403;

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- access denied due symlink restriction");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Path         : %s", r->physical.path.ptr);
		}

		buffer_reset(&r->physical.path);
		return HANDLER_FINISHED;
	}

	if (S_ISDIR(sce->st.st_mode)) {
		if (r->uri.path.ptr[buffer_string_length(&r->uri.path) - 1] != '/') {
			/* redirect to .../ */

			http_response_redirect_to_directory(r, 301);

			return HANDLER_FINISHED;
		}
	} else if (!S_ISREG(sce->st.st_mode)) {
		/* any special handling of non-reg files ?*/
	}

	return HANDLER_GO_ON;
}

__attribute_cold__
__attribute_noinline__
static handler_t http_status_set_error_close (request_st * const r, int status) {
    r->keep_alive = 0;
    r->resp_body_finished = 1;
    r->handler_module = NULL;
    r->http_status = status;
    return HANDLER_FINISHED;
}

handler_t http_response_prepare(request_st * const r) {
    handler_t rc;

    do {

	/* looks like someone has already made a decision */
	if (r->http_status != 0 && r->http_status != 200) {
		if (0 == r->resp_body_finished)
			http_response_body_clear(r, 0);
		return HANDLER_FINISHED;
	}

	/* no decision yet, build conf->filename */
	if (buffer_is_empty(&r->physical.path)) {

		/* we only come here when we have the parse the full request again
		 *
		 * a HANDLER_COMEBACK from mod_rewrite and mod_fastcgi might be a
		 * problem here as mod_setenv might get called multiple times
		 *
		 * fastcgi-auth might lead to a COMEBACK too
		 * fastcgi again dead server too
		 *
		 * mod_compress might add headers twice too
		 *
		 */

	    if (!r->async_callback) {

		if (r->conf.log_condition_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__, "run condition");
		}

		config_cond_cache_reset(r);
		config_patch_config(r);

		/* do we have to downgrade to 1.0 ? */
		if (!r->conf.allow_http11) {
			r->http_version = HTTP_VERSION_1_0;
		}

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- splitting Request-URI");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Request-URI     : %s", r->target.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "URI-scheme      : %s", r->uri.scheme.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "URI-authority   : %s", r->uri.authority.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "URI-path (clean): %s", r->uri.path.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "URI-query       : %.*s",
			  BUFFER_INTLEN_PTR(&r->uri.query));
		}

		/* r->conf.max_request_size is in kBytes */
		if (0 != r->conf.max_request_size &&
		    (off_t)r->reqbody_length > ((off_t)r->conf.max_request_size << 10)) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "request-size too long: %lld -> 413", (long long) r->reqbody_length);
			return /* 413 Payload Too Large */
			  http_status_set_error_close(r, 413);
		}


	    }
	    r->async_callback = 0; /* reset */


		/**
		 *
		 * call plugins
		 *
		 * - based on the raw URL
		 *
		 */

		rc = plugins_call_handle_uri_raw(r);
		if (HANDLER_GO_ON != rc) continue;

		/**
		 *
		 * call plugins
		 *
		 * - based on the clean URL
		 *
		 */

		rc = plugins_call_handle_uri_clean(r);
		if (HANDLER_GO_ON != rc) continue;

		if (r->http_method == HTTP_METHOD_OPTIONS &&
		    r->uri.path.ptr[0] == '*' && r->uri.path.ptr[1] == '\0') {
			/* option requests are handled directly without checking of the path */

			http_header_response_append(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Allow"), CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));

			r->http_status = 200;
			r->resp_body_finished = 1;

			return HANDLER_FINISHED;
		}

		if (r->http_method == HTTP_METHOD_CONNECT && NULL == r->handler_module) {
			return /* 405 Method Not Allowed */
			  http_status_set_error_close(r, 405);
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

		buffer_copy_buffer(&r->physical.doc_root, r->conf.document_root);
		buffer_copy_buffer(&r->physical.rel_path, &r->uri.path);

#if defined(__WIN32) || defined(__CYGWIN__)
		/* strip dots from the end and spaces
		 *
		 * windows/dos handle those filenames as the same file
		 *
		 * foo == foo. == foo..... == "foo...   " == "foo..  ./"
		 *
		 * This will affect in some cases PATHINFO
		 *
		 * on native windows we could prepend the filename with \\?\ to circumvent
		 * this behaviour. I have no idea how to push this through cygwin
		 *
		 * */

		if (!buffer_string_is_empty(&r->physical.rel_path)) {
			buffer *b = &r->physical.rel_path;
			size_t len = buffer_string_length(b);

			/* strip trailing " /" or "./" once */
			if (len > 1 &&
			    b->ptr[len - 1] == '/' &&
			    (b->ptr[len - 2] == ' ' || b->ptr[len - 2] == '.')) {
				len -= 2;
			}
			/* strip all trailing " " and "." */
			while (len > 0 &&  ( ' ' == b->ptr[len-1] || '.' == b->ptr[len-1] ) ) --len;
			buffer_string_set_length(b, len);
		}
#endif

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- before doc_root");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Doc-Root     : %s", r->physical.doc_root.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Rel-Path     : %s", r->physical.rel_path.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Path         : %s", r->physical.path.ptr);
		}
		/* the docroot plugin should set the doc_root and might also set the physical.path
		 * for us (all vhost-plugins are supposed to set the doc_root)
		 * */
		rc = plugins_call_handle_docroot(r);
		if (HANDLER_GO_ON != rc) continue;

		/* MacOS X and Windows can't distiguish between upper and lower-case
		 *
		 * convert to lower-case
		 */
		if (r->conf.force_lowercase_filenames) {
			buffer_to_lower(&r->physical.rel_path);
		}

		/* the docroot plugins might set the servername, if they don't we take http-host */
		if (buffer_string_is_empty(r->server_name)) {
			r->server_name = &r->uri.authority;
		}

		/**
		 * create physical filename
		 * -> physical.path = docroot + rel_path
		 *
		 */

		buffer_copy_buffer(&r->physical.basedir, &r->physical.doc_root);
		buffer_copy_buffer(&r->physical.path, &r->physical.doc_root);
		buffer_append_path_len(&r->physical.path, CONST_BUF_LEN(&r->physical.rel_path));

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- after doc_root");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Doc-Root     : %s", r->physical.doc_root.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Rel-Path     : %s", r->physical.rel_path.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Path         : %s", r->physical.path.ptr);
		}

		if (r->http_method == HTTP_METHOD_CONNECT) {
			/* do not permit CONNECT requests to hit filesystem hooks
			 * since the CONNECT URI bypassed path normalization */
			/* (This check is located here so that r->physical.path
			 *  is filled in above to avoid repeating work next time
			 *  http_response_prepare() is called while processing request) */
		} else {
			rc = plugins_call_handle_physical(r);
			if (HANDLER_GO_ON != rc) continue;

			if (r->conf.log_request_handling) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "-- logical -> physical");
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "Doc-Root     : %s", r->physical.doc_root.ptr);
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "Basedir      : %s", r->physical.basedir.ptr);
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "Rel-Path     : %s", r->physical.rel_path.ptr);
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "Path         : %s", r->physical.path.ptr);
			}
		}
	}

	if (NULL != r->handler_module) return HANDLER_GO_ON;

	/*
	 * Noone catched away the file from normal path of execution yet (like mod_access)
	 *
	 * Go on and check of the file exists at all
	 */

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- handling physical path");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Path         : %s", r->physical.path.ptr);
		}

		rc = http_response_physical_path_check(r);
		if (HANDLER_GO_ON != rc) continue;

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- handling subrequest");
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Path         : %s", r->physical.path.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "URI          : %s", r->uri.path.ptr);
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "Pathinfo     : %s", r->pathinfo.ptr);
		}

		/* call the handlers */
		rc = plugins_call_handle_subrequest_start(r);
		if (HANDLER_GO_ON != rc) {
			if (r->conf.log_request_handling) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "-- subrequest finished");
			}
			continue;
		}

		/* if we are still here, no one wanted the file, status 403 is ok I think */
		if (NULL == r->handler_module && 0 == r->http_status) {
			r->http_status = (r->http_method != HTTP_METHOD_OPTIONS) ? 403 : 200;
			return HANDLER_FINISHED;
		}

		return HANDLER_GO_ON;

    } while (HANDLER_COMEBACK == rc
             && HANDLER_GO_ON ==(rc = http_response_comeback(r)));

    return rc;
}

handler_t http_response_comeback (request_st * const r)
{
    if (NULL != r->handler_module || !buffer_is_empty(&r->physical.path))
        return HANDLER_GO_ON;

    config_reset_config(r);

    buffer_copy_buffer(&r->uri.authority,r->http_host);/*copy even if NULL*/
    buffer_to_lower(&r->uri.authority);

    int status = http_request_parse_target(r, r->con->proto_default_port);
    if (0 == status) {
        r->conditional_is_valid = (1 << COMP_SERVER_SOCKET)
                                | (1 << COMP_HTTP_SCHEME)
                                | (1 << COMP_HTTP_HOST)
                                | (1 << COMP_HTTP_REMOTE_IP)
                                | (1 << COMP_HTTP_REQUEST_METHOD)
                                | (1 << COMP_HTTP_URL)
                                | (1 << COMP_HTTP_QUERY_STRING)
                                | (1 << COMP_HTTP_REQUEST_HEADER);
        return HANDLER_GO_ON;
    }
    else {
        r->conditional_is_valid = (1 << COMP_SERVER_SOCKET)
                                | (1 << COMP_HTTP_REMOTE_IP);
        config_cond_cache_reset(r);
        return http_status_set_error_close(r, status);
    }
}
