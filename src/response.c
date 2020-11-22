#include "first.h"

#include "response.h"
#include "request.h"
#include "base.h"
#include "fdevent.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "stat_cache.h"
#include "chunk.h"
#include "http_chunk.h"
#include "http_date.h"

#include "plugin.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


int
http_response_omit_header (request_st * const r, const data_string * const ds)
{
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


__attribute_cold__
static void
http_response_write_header_partial_1xx (request_st * const r, buffer * const b)
{
    /* take data in con->write_queue and move into b
     * (to be sent prior to final response headers in r->write_queue) */
    connection * const con = r->con;
    /*assert(&r->write_queue != con->write_queue);*/
    chunkqueue * const cq = con->write_queue;
    con->write_queue = &r->write_queue;

    /*assert(0 == buffer_string_length(b));*//*expect empty buffer from caller*/
    uint32_t len = (uint32_t)chunkqueue_length(cq);
    /*(expecting MEM_CHUNK(s), so not expecting error reading files)*/
    if (chunkqueue_read_data(cq, buffer_string_prepare_append(b, len),
                             len, r->conf.errh) < 0)
        len = 0;
    buffer_string_set_length(b, len);/*expect initial empty buffer from caller*/
    chunkqueue_free(cq);
}


void
http_response_write_header (request_st * const r)
{
	chunkqueue * const cq = &r->write_queue;
	buffer * const b = chunkqueue_prepend_buffer_open(cq);

        if (cq != r->con->write_queue)
            http_response_write_header_partial_1xx(r, b);

	const char * const httpv = (r->http_version == HTTP_VERSION_1_1) ? "HTTP/1.1 " : "HTTP/1.0 ";
	buffer_append_string_len(b, httpv, sizeof("HTTP/1.1 ")-1);
	http_status_append(b, r->http_status);

	/* disable keep-alive if requested */

	if (r->con->request_count > r->conf.max_keep_alive_requests || 0 == r->conf.max_keep_alive_idle) {
		r->keep_alive = 0;
	} else if (0 != r->reqbody_length
		   && r->reqbody_length != r->reqbody_queue.bytes_in
		   && (NULL == r->handler_module
		       || 0 == (r->conf.stream_request_body
		                & (FDEVENT_STREAM_REQUEST
		                   | FDEVENT_STREAM_REQUEST_BUFMIN)))) {
		r->keep_alive = 0;
	} else {
		r->con->keep_alive_idle = r->conf.max_keep_alive_idle;
	}

	if (light_btst(r->resp_htags, HTTP_HEADER_UPGRADE)
	    && r->http_version == HTTP_VERSION_1_1) {
		http_header_response_set(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"), CONST_STR_LEN("upgrade"));
	} else if (0 == r->keep_alive) {
		http_header_response_set(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"), CONST_STR_LEN("close"));
	} else if (r->http_version == HTTP_VERSION_1_0) {/*(&& r->keep_alive != 0)*/
		http_header_response_set(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"), CONST_STR_LEN("keep-alive"));
	}

	if (304 == r->http_status
	    && light_btst(r->resp_htags, HTTP_HEADER_CONTENT_ENCODING)) {
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

	if (!light_btst(r->resp_htags, HTTP_HEADER_DATE)) {
		/* HTTP/1.1 and later requires a Date: header */
		/* "\r\nDate: " 8-chars + 30-chars "%a, %d %b %Y %H:%M:%S GMT" + '\0' */
		static time_t tlast = 0;
		static char tstr[40] = "\r\nDate: ";

		/* cache the generated timestamp */
		const time_t cur_ts = log_epoch_secs;
		if (__builtin_expect ( (tlast != cur_ts), 0))
			http_date_time_to_str(tstr+8, sizeof(tstr)-8, (tlast = cur_ts));

		buffer_append_string_len(b, tstr, 37);
	}

	if (!light_btst(r->resp_htags, HTTP_HEADER_SERVER)) {
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

	/*(optimization to use fewer syscalls to send a small response)*/
	off_t cqlen;
	if (r->resp_body_finished
	    && light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)
	    && (cqlen = chunkqueue_length(cq) - r->resp_header_len) > 0
	    && cqlen <= 32768)
		chunkqueue_small_resp_optim(cq);
}


static handler_t http_response_physical_path_check(request_st * const r) {
	const stat_cache_st *st = stat_cache_path_stat(&r->physical.path);

	if (st) {
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
			    && light_btst(r->resp_htags, HTTP_HEADER_ALLOW)) {
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
			/* we have no idea what happened. let's tell the user so. */
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
			const stat_cache_st * const nst = stat_cache_path_stat(tb);
			if (NULL == nst) {
				pathinfo = pathinfo != pprev ? pprev : NULL;
				break;
			}
			st = nst;
			if (!S_ISDIR(st->st_mode)) break;
		}

		if (NULL == pathinfo || !S_ISREG(st->st_mode)) {
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

	if (S_ISREG(st->st_mode)) /*(common case)*/
		return HANDLER_GO_ON;

	if (S_ISDIR(st->st_mode)) {
		if (r->uri.path.ptr[buffer_string_length(&r->uri.path) - 1] != '/') {
			/* redirect to .../ */

			http_response_redirect_to_directory(r, 301);

			return HANDLER_FINISHED;
		}
	} else {
		/* any special handling of other non-reg files ?*/
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

static handler_t http_response_config (request_st * const r) {
    if (r->conf.log_condition_handling)
        log_error(r->conf.errh, __FILE__, __LINE__, "run condition");

    config_cond_cache_reset(r);
    config_patch_config(r);

    /* do we have to downgrade from 1.1 to 1.0 ? (ignore for HTTP/2) */
    if (!r->conf.allow_http11 && r->http_version == HTTP_VERSION_1_1)
        r->http_version = HTTP_VERSION_1_0;

    /* r->conf.max_request_size is in kBytes */
    if (0 != r->conf.max_request_size &&
        (off_t)r->reqbody_length > ((off_t)r->conf.max_request_size << 10)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "request-size too long: %lld -> 413", (long long) r->reqbody_length);
        return /* 413 Payload Too Large */
          http_status_set_error_close(r, 413);
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
static handler_t http_response_comeback (request_st * const r);


static handler_t
http_response_prepare (request_st * const r)
{
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

		if (!r->async_callback) {
			rc = http_response_config(r);
			if (HANDLER_GO_ON != rc) continue;
		}
		r->async_callback = 0; /* reset */

		/* we only come here when we have the parse the full request again
		 *
		 * a HANDLER_COMEBACK from mod_rewrite and mod_fastcgi might be a
		 * problem here as mod_setenv might get called multiple times
		 *
		 * fastcgi-auth might lead to a COMEBACK too
		 * fastcgi again dead server too
		 */

		if (r->conf.log_request_handling) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "-- parsed Request-URI");
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

			http_header_response_append(r, HTTP_HEADER_ALLOW,
			  CONST_STR_LEN("Allow"),
			  CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));

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

		/* MacOS X and Windows can't distinguish between upper and lower-case
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
	 * No module grabbed the request yet (like mod_access)
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


__attribute_cold__
static handler_t http_response_comeback (request_st * const r)
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


__attribute_cold__
static void
http_response_errdoc_init (request_st * const r)
{
    /* modules that produce headers required with error response should
     * typically also produce an error document.  Make an exception for
     * mod_auth WWW-Authenticate response header. */
    buffer *www_auth = NULL;
    if (401 == r->http_status) {
        const buffer * const vb =
          http_header_response_get(r, HTTP_HEADER_WWW_AUTHENTICATE,
                                   CONST_STR_LEN("WWW-Authenticate"));
        if (NULL != vb) www_auth = buffer_init_buffer(vb);
    }

    buffer_reset(&r->physical.path);
    r->resp_htags = 0;
    array_reset_data_strings(&r->resp_headers);
    http_response_body_clear(r, 0);

    if (NULL != www_auth) {
        http_header_response_set(r, HTTP_HEADER_WWW_AUTHENTICATE,
                                 CONST_STR_LEN("WWW-Authenticate"),
                                 CONST_BUF_LEN(www_auth));
        buffer_free(www_auth);
    }
}


__attribute_cold__
static void
http_response_static_errdoc (request_st * const r)
{
    if (NULL == r->handler_module
        ? r->error_handler_saved_status >= 65535
        : (!r->conf.error_intercept || r->error_handler_saved_status))
        return;

    http_response_errdoc_init(r);
    r->resp_body_finished = 1;

    /* try to send static errorfile */
    if (!buffer_string_is_empty(r->conf.errorfile_prefix)) {
        buffer_copy_buffer(&r->physical.path, r->conf.errorfile_prefix);
        buffer_append_int(&r->physical.path, r->http_status);
        buffer_append_string_len(&r->physical.path, CONST_STR_LEN(".html"));
        stat_cache_entry *sce =
          stat_cache_get_entry_open(&r->physical.path, r->conf.follow_symlink);
        if (sce && 0 == http_chunk_append_file_ref(r, sce)) {
            const buffer *content_type = stat_cache_content_type_get(sce, r);
            if (content_type)
                http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
                                         CONST_STR_LEN("Content-Type"),
                                         CONST_BUF_LEN(content_type));
            return;
        }
    }

    /* build default error-page */
    buffer_reset(&r->physical.path);
    buffer * const b = r->tmp_buf;
    buffer_copy_string_len(b, CONST_STR_LEN(
      "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
      "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
      "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
      " <head>\n"
      "  <title>"));
    http_status_append(b, r->http_status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</title>\n"
      " </head>\n"
      " <body>\n"
      "  <h1>"));
    http_status_append(b, r->http_status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</h1>\n"
      " </body>\n"
      "</html>\n"));
    (void)http_chunk_append_mem(r, CONST_BUF_LEN(b));

    http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
                             CONST_STR_LEN("Content-Type"),
                             CONST_STR_LEN("text/html"));
}


__attribute_cold__
static void
http_response_merge_trailers (request_st * const r)
{
    /* attempt to merge trailers into headers; header not yet sent by caller */
    if (buffer_string_is_empty(&r->gw_dechunk->b)) return;
    const int done = r->gw_dechunk->done;
    if (!done) return; /* XXX: !done; could scan for '\n' and send only those */

    /* do not include trailers if success status (when response was read from
     * backend) subsequently changed to error status.  http_chunk could add the
     * trailers, but such actions are better on a different code layer than in
     * http_chunk.c */
    if (done < 400 && r->http_status >= 400) return;

    /* XXX: trailers passed through; no sanity check currently done
     * https://tools.ietf.org/html/rfc7230#section-4.1.2
     *
     * Not checking for disallowed fields
     * Not handling (deprecated) line wrapping
     * Not strictly checking fields
     */
    const char *k = strchr(r->gw_dechunk->b.ptr, '\n'); /*(skip final chunk)*/
    if (NULL == k) return; /*(should not happen)*/
    ++k;
    for (const char *v, *e; (e = strchr(k, '\n')); k = e+1) {
        v = memchr(k, ':', (size_t)(e - k));
        if (NULL == v || v == k || *k == ' ' || *k == '\t') continue;
        uint32_t klen = (uint32_t)(v - k);
        do { ++v; } while (*v == ' ' || *v == '\t');
        if (*v == '\r' || *v == '\n') continue;
        enum http_header_e id = http_header_hkey_get(k, klen);
        http_header_response_insert(r, id, k, klen, v, (size_t)(e - v));
    }
    http_header_response_unset(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Trailer"));
    buffer_clear(&r->gw_dechunk->b);
}


static handler_t
http_response_write_prepare(request_st * const r)
{
    if (NULL == r->handler_module) {
        /* static files */
        switch(r->http_method) {
          case HTTP_METHOD_GET:
          case HTTP_METHOD_POST:
          case HTTP_METHOD_HEAD:
            break;
          case HTTP_METHOD_OPTIONS:
            if ((!r->http_status || r->http_status == 200)
                && !buffer_string_is_empty(&r->uri.path)
                && r->uri.path.ptr[0] != '*') {
                http_response_body_clear(r, 0);
                http_header_response_append(r, HTTP_HEADER_ALLOW,
                  CONST_STR_LEN("Allow"),
                  CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));
                r->http_status = 200;
                r->resp_body_finished = 1;
            }
            break;
          default:
            if (r->http_status == 0)
                r->http_status = 501;
            break;
        }
    }

    switch (r->http_status) {
      case 200: /* common case */
        break;
      case 204: /* class: header only */
      case 205:
      case 304:
        /* disable chunked encoding again as we have no body */
        http_response_body_clear(r, 1);
        /* no Content-Body, no Content-Length */
        http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH,
                                   CONST_STR_LEN("Content-Length"));
        r->resp_body_finished = 1;
        break;
      default: /* class: header + body */
        if (r->http_status == 0)
            r->http_status = 403;
        /* only custom body for 4xx and 5xx */
        if (r->http_status >= 400 && r->http_status < 600)
            http_response_static_errdoc(r);
        break;
    }

    if (r->gw_dechunk)
        http_response_merge_trailers(r);

    /* Allow filter plugins to change response headers */
    switch (plugins_call_handle_response_start(r)) {
      case HANDLER_GO_ON:
      case HANDLER_FINISHED:
        break;
      default:
        log_error(r->conf.errh, __FILE__, __LINE__,
          "response_start plugin failed");
        return HANDLER_ERROR;
    }

    if (r->resp_body_finished) {
        /* set content-length if length is known and not already set */
        if (!(r->resp_htags
              & (light_bshift(HTTP_HEADER_CONTENT_LENGTH)
                |light_bshift(HTTP_HEADER_TRANSFER_ENCODING)))) {
            off_t qlen = chunkqueue_length(&r->write_queue);
            /**
             * The Content-Length header can only be sent if we have content:
             * - HEAD does not have a content-body (but can have content-length)
             * - 1xx, 204 and 304 does not have a content-body
             *   (RFC 2616 Section 4.3)
             *
             * Otherwise generate a Content-Length header
             * (if chunked encoding is not available)
             *
             * (should not reach here if 1xx (r->http_status < 200))
             */
            if (qlen > 0) {
                buffer * const tb = r->tmp_buf;
                buffer_clear(tb);
                buffer_append_int(tb, qlen);
                http_header_response_set(r, HTTP_HEADER_CONTENT_LENGTH,
                                         CONST_STR_LEN("Content-Length"),
                                         CONST_BUF_LEN(tb));
            }
            else if (r->http_method != HTTP_METHOD_HEAD
                     && r->http_status != 204 && r->http_status != 304) {
                /* Content-Length: 0 is important for Redirects (301, ...) as
                 * there might be content. */
                http_header_response_set(r, HTTP_HEADER_CONTENT_LENGTH,
                                         CONST_STR_LEN("Content-Length"),
                                         CONST_STR_LEN("0"));
            }
        }
    }
    else if (r->http_version == HTTP_VERSION_2) {
        /* handled by HTTP/2 framing */
    }
    else {
        /**
         * response is not yet finished, but we have all headers
         *
         * keep-alive requires one of:
         * - Content-Length: ... (HTTP/1.0 and HTTP/1.0)
         * - Transfer-Encoding: chunked (HTTP/1.1)
         * - Upgrade: ... (lighttpd then acts as transparent proxy)
         */

        if (!(r->resp_htags
              & (light_bshift(HTTP_HEADER_CONTENT_LENGTH)
                |light_bshift(HTTP_HEADER_TRANSFER_ENCODING)
                |light_bshift(HTTP_HEADER_UPGRADE)))) {
            if (r->http_method == HTTP_METHOD_CONNECT && r->http_status == 200){
                /*(no transfer-encoding if successful CONNECT)*/
            }
            else if (r->http_version == HTTP_VERSION_1_1) {
                off_t qlen = chunkqueue_length(&r->write_queue);
                r->resp_send_chunked = 1;
                if (qlen) {
                    /* create initial Transfer-Encoding: chunked segment */
                    buffer * const b =
                      chunkqueue_prepend_buffer_open(&r->write_queue);
                    if (r->resp_decode_chunked
                        && 0 != r->gw_dechunk->gw_chunked) {
                        /*(reconstitute initial partially-decoded chunk)*/
                        off_t gw_chunked = r->gw_dechunk->gw_chunked;
                        if (gw_chunked > 2)
                            qlen += gw_chunked - 2;
                        else if (1 == gw_chunked)
                            chunkqueue_append_mem(&r->write_queue,
                                                  CONST_STR_LEN("\r"));
                    }
                    else {
                        chunkqueue_append_mem(&r->write_queue,
                                              CONST_STR_LEN("\r\n"));
                    }
                    buffer_append_uint_hex(b, (uintmax_t)qlen);
                    buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
                    chunkqueue_prepend_buffer_commit(&r->write_queue);
                }
                http_header_response_append(r, HTTP_HEADER_TRANSFER_ENCODING,
                                            CONST_STR_LEN("Transfer-Encoding"),
                                            CONST_STR_LEN("chunked"));
            }
            else { /* if (r->http_version == HTTP_VERSION_1_0) */
                r->keep_alive = 0;
            }
        }
    }

    if (r->http_method == HTTP_METHOD_HEAD) {
        /* HEAD request is like a GET, but without the content */
        http_response_body_clear(r, 1);
        r->resp_body_finished = 1;
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
static handler_t
http_response_call_error_handler (request_st * const r, const buffer * const error_handler)
{
    /* call error-handler */

    /* set REDIRECT_STATUS to save current HTTP status code
     * for access by dynamic handlers
     * https://redmine.lighttpd.net/issues/1828 */
    buffer * const tb = r->tmp_buf;
    buffer_clear(tb);
    buffer_append_int(tb, r->http_status);
    http_header_env_set(r, CONST_STR_LEN("REDIRECT_STATUS"), CONST_BUF_LEN(tb));

    if (error_handler == r->conf.error_handler) {
        plugins_call_handle_request_reset(r);

        if (r->reqbody_length) {
            if (r->reqbody_length != r->reqbody_queue.bytes_in)
                r->keep_alive = 0;
            r->reqbody_length = 0;
            chunkqueue_reset(&r->reqbody_queue);
        }

        r->con->is_writable = 1;
        r->resp_body_finished = 0;
        r->resp_body_started = 0;

        r->error_handler_saved_status = r->http_status;
        r->error_handler_saved_method = r->http_method;

        r->http_method = HTTP_METHOD_GET;
    }
    else { /*(preserve behavior for server.error-handler-404)*/
        /*(negative to flag old behavior)*/
        r->error_handler_saved_status = -r->http_status;
    }

    if (r->http_version == HTTP_VERSION_UNSET)
        r->http_version = HTTP_VERSION_1_0;

    buffer_copy_buffer(&r->target, error_handler);
    http_response_errdoc_init(r);
    r->http_status = 0; /*(after http_response_errdoc_init())*/
    http_response_comeback(r);
    return HANDLER_COMEBACK;
}


handler_t
http_response_handler (request_st * const r)
{
    const plugin *p = r->handler_module;
    int rc;
    if (NULL != p
        || ((rc = http_response_prepare(r)) == HANDLER_GO_ON
            && NULL != (p = r->handler_module)))
        rc = p->handle_subrequest(r, p->data);

    switch (rc) {
      case HANDLER_WAIT_FOR_EVENT:
        if (!r->resp_body_finished
            && (!r->resp_body_started
                || 0 == (r->conf.stream_response_body
                         & (FDEVENT_STREAM_RESPONSE
                           |FDEVENT_STREAM_RESPONSE_BUFMIN))))
            return HANDLER_WAIT_FOR_EVENT; /* come back here */
        /* response headers received from backend; start response */
        __attribute_fallthrough__
      case HANDLER_GO_ON:
      case HANDLER_FINISHED: /*(HANDLER_FINISHED if request not handled)*/
        if (r->http_status == 0) r->http_status = 200;
        if (r->error_handler_saved_status > 0)
            r->http_method = r->error_handler_saved_method;
        if (NULL == r->handler_module || r->conf.error_intercept) {
            if (r->error_handler_saved_status) {
                const int subreq_status = r->http_status;
                if (r->error_handler_saved_status > 0)
                    r->http_status = r->error_handler_saved_status;
                else if (r->http_status == 404 || r->http_status == 403)
                    /* error-handler-404 is a 404 */
                    r->http_status = -r->error_handler_saved_status;
                else {
                    /* error-handler-404 is back and has generated content */
                    /* if Status: was set, take it otherwise use 200 */
                }
                if (200 <= subreq_status && subreq_status <= 299) {
                    /*(flag value to indicate that error handler succeeded)
                     *(for (NULL == r->handler_module))*/
                    r->error_handler_saved_status = 65535; /* >= 1000 */
                }
            }
            else if (r->http_status >= 400) {
                const buffer *error_handler = NULL;
                if (!buffer_string_is_empty(r->conf.error_handler))
                    error_handler = r->conf.error_handler;
                else if ((r->http_status == 404 || r->http_status == 403)
                       && !buffer_string_is_empty(r->conf.error_handler_404))
                    error_handler = r->conf.error_handler_404;

                if (error_handler)
                    return http_response_call_error_handler(r, error_handler);
            }
        }

        /* we have something to send; go on */
        /*(CON_STATE_RESPONSE_START; transient state)*/
        return http_response_write_prepare(r);
      case HANDLER_WAIT_FOR_FD:
        return HANDLER_WAIT_FOR_FD;
      case HANDLER_COMEBACK:
        http_response_comeback(r);
        return HANDLER_COMEBACK;
      /*case HANDLER_ERROR:*/
      default:
        return HANDLER_ERROR; /* something went wrong */
    }
}
