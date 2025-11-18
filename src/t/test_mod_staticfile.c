#include "first.h"

#undef NDEBUG
#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mod_staticfile.c"
#include "fdlog.h"
#include "http_date.h"
#include "http_etag.h"
#include "http_header.h"

__attribute_noinline__
static void test_mod_staticfile_reset (request_st * const r)
{
    r->http_status = 0;
    r->resp_htags = 0;
    array_reset_data_strings(&r->resp_headers);
    http_response_body_clear(r, 0);
    r->conf.etag_flags = ETAG_USE_INODE | ETAG_USE_MTIME | ETAG_USE_SIZE;
}

__attribute_noinline__
static void
run_http_response_send_file (request_st * const r, int line, int status, const char *desc)
{
    http_response_send_file(r, &r->physical.path, NULL);
    if (r->http_status != status) {
        fprintf(stderr,
                "%s.%d: %s() failed: expected '%d', got '%d' for test %s\n",
                __FILE__, line, "http_response_send_file", status,
                r->http_status, desc);
        fflush(stderr);
        abort();
    }
}

static void
test_http_response_send_file (request_st * const r, time_t lmtime)
{
    test_mod_staticfile_reset(r);
    const buffer *vb;

    /*(mismatch test must be first, else stat_cache will have cached mimetype)*/
    array * const mimetypes_empty = array_init(0);
    const array * const mimetypes_orig = r->conf.mimetypes;
    r->conf.mimetypes = mimetypes_empty;
    run_http_response_send_file(r, __LINE__, 200,
      "basic static file (w/o mimetype match)");
    vb = http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE,
                                  CONST_STR_LEN("Content-Type"));
    assert(vb && buffer_eq_slen(vb, CONST_STR_LEN("application/octet-stream")));
    test_mod_staticfile_reset(r);
    r->conf.mimetypes = mimetypes_orig;
    array_free(mimetypes_empty);

    run_http_response_send_file(r, __LINE__, 200,
      "basic static file (w/ mimetype match)");
    vb = http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE,
                                  CONST_STR_LEN("Content-Type"));
    assert(vb && buffer_eq_slen(vb, CONST_STR_LEN("text/plain")));
    vb = http_header_response_get(r, HTTP_HEADER_ETAG,
                                  CONST_STR_LEN("ETag"));
    assert(vb && vb->ptr[0] == '"' && vb->ptr[buffer_clen(vb)-1] == '"');
    vb = http_header_response_get(r, HTTP_HEADER_LAST_MODIFIED,
                                  CONST_STR_LEN("Last-Modified"));
    assert(vb);
    test_mod_staticfile_reset(r);

    const uint32_t plen = buffer_clen(&r->physical.path);
    buffer_append_string_len(&r->physical.path, CONST_STR_LEN("-nonexistent"));
    run_http_response_send_file(r, __LINE__, 404,
      "non-existent file");
    test_mod_staticfile_reset(r);
    buffer_truncate(&r->physical.path, plen);

    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            CONST_STR_LEN(""));
    run_http_response_send_file(r, __LINE__, 200,
      "if-modified-since invalid (empty)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            CONST_STR_LEN("foobar"));
    run_http_response_send_file(r, __LINE__, 200,
      "if-modified-since invalid (not time string)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            CONST_STR_LEN("this string is too long to be a valid timestamp"));
    run_http_response_send_file(r, __LINE__, 200,
      "if-modified-since invalid (too long to be valid time string)");
    test_mod_staticfile_reset(r);

    char lmtime_str[HTTP_DATE_SZ];
    uint32_t lmtime_len;

    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),
                                       lmtime ? lmtime-1 : lmtime);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 200,
      "if-modified-since older than st_mtime");
    test_mod_staticfile_reset(r);

    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),lmtime);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 304,
      "if-modified-since matches st_mtime");
    test_mod_staticfile_reset(r);

    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),lmtime+1);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 304,
      "if-modified-since newer than st_mtime");
    test_mod_staticfile_reset(r);

  #ifdef __COVERITY__ /* Coverity misses that this is set a few lines above */
    force_assert(http_header_request_get(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                 CONST_STR_LEN("If-Modified-Since")));
  #endif
    buffer_append_string_len(
      http_header_request_get(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                              CONST_STR_LEN("If-Modified-Since")),
      CONST_STR_LEN("; foo"));
    run_http_response_send_file(r, __LINE__, 200,
      "if-modified-since newer but overload (invalid)");
    test_mod_staticfile_reset(r);

    http_header_request_unset(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                              CONST_STR_LEN("If-Modified-Since"));

    buffer *etag = buffer_init();
    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_STR_LEN("foo"));
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag mismatch)");
    vb = http_header_response_get(r, HTTP_HEADER_ETAG,
                                  CONST_STR_LEN("ETag"));
    assert(vb);
    buffer_copy_buffer(etag, vb);
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_BUF_LEN(etag));
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag match)");
    test_mod_staticfile_reset(r);

    r->conf.etag_flags = 0;
    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_BUF_LEN(etag));
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag would match, but etags disabled in config)");
    test_mod_staticfile_reset(r);
    r->conf.etag_flags = ETAG_USE_INODE | ETAG_USE_MTIME | ETAG_USE_SIZE;

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_BUF_LEN(etag));
    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),
                                       lmtime ? lmtime-1 : lmtime);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag match), "
      "if-modified-since (old) (should be ignored)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_BUF_LEN(etag));
    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),lmtime);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag match), "
      "if-modified-since (now) (should be ignored)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_BUF_LEN(etag));
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            CONST_STR_LEN("Sun, 01 Jan 1970 00:00:01 GMT foo"));
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag match), "
      "if-modified-since (overlong; invalid) (should be ignored)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_STR_LEN("foo"));
    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),
                                       lmtime ? lmtime-1 : lmtime);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag mismatch), "
      "if-modified-since (old) (should be ignored)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_STR_LEN("foo"));
    lmtime_len = http_date_time_to_str(lmtime_str,sizeof(lmtime_str),lmtime);
    http_header_request_set(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                            CONST_STR_LEN("If-Modified-Since"),
                            lmtime_str, lmtime_len);
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag mismatch), "
      "if-modified-since (now) (should be ignored)");
    test_mod_staticfile_reset(r);

    http_header_request_unset(r, HTTP_HEADER_IF_MODIFIED_SINCE,
                              CONST_STR_LEN("If-Modified-Since"));

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            etag->ptr, buffer_clen(etag)-1);
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag invalid; mismatched quotes)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            etag->ptr+1, buffer_clen(etag)-2);
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag invalid; no quotes)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_STR_LEN("*"));
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag * (unquoted) matches any ETag)");
    test_mod_staticfile_reset(r);

    http_header_request_set(r, HTTP_HEADER_IF_NONE_MATCH,
                            CONST_STR_LEN("If-None-Match"),
                            CONST_STR_LEN("\"*\""));
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (etag \"*\" (quoted) is a regular ETag)");
    test_mod_staticfile_reset(r);

    buffer * const rqst_etag =
      http_header_request_set_ptr(r, HTTP_HEADER_IF_NONE_MATCH,
                                  CONST_STR_LEN("If-None-Match"));

    buffer_copy_string_len(rqst_etag, CONST_STR_LEN("W/"));
    buffer_append_buffer(rqst_etag, etag);
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (weak etag) matches like ETag for GET and HEAD)");
    test_mod_staticfile_reset(r);

    /*(200 expected here instead of 206 since Range is handled later)*/
    http_header_request_set(r, HTTP_HEADER_RANGE,
                            CONST_STR_LEN("Range"),
                            CONST_STR_LEN("bytes=0-0"));
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (weak etag) does not match for Range request)");
    test_mod_staticfile_reset(r);
    http_header_request_unset(r, HTTP_HEADER_RANGE, CONST_STR_LEN("Range"));

    buffer_copy_string_len(rqst_etag, CONST_STR_LEN("W/\"12345\""));
    run_http_response_send_file(r, __LINE__, 200,
      "if-none-match (weak etag no match)");
    test_mod_staticfile_reset(r);

    buffer_append_string_len(rqst_etag, CONST_STR_LEN(", "));
    buffer_append_buffer(rqst_etag, etag);
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag list, second etag matches)");
    test_mod_staticfile_reset(r);

    buffer_append_string_len(rqst_etag, CONST_STR_LEN(", W/"));
    buffer_append_buffer(rqst_etag, etag);
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag list, second etag matches weakly)");
    test_mod_staticfile_reset(r);

    buffer_copy_string_len(rqst_etag, CONST_STR_LEN("\"12345\",, ,,  ,  "));
    buffer_append_buffer(rqst_etag, etag);
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag list non-normalized, ending with etag match)");
    test_mod_staticfile_reset(r);

    buffer_copy_string_len(rqst_etag, CONST_STR_LEN("\"1234\", "));
    buffer_append_buffer(rqst_etag, etag);
    buffer_append_string_len(rqst_etag, CONST_STR_LEN(", \"brokentrailing"));
    run_http_response_send_file(r, __LINE__, 304,
      "if-none-match (etag list with etag match then invalid trailing data)");
    test_mod_staticfile_reset(r);

    http_header_request_unset(r, HTTP_HEADER_IF_NONE_MATCH,
                              CONST_STR_LEN("If-None-Match"));

    buffer_free(etag);
}

__attribute_noinline__
static void
run_mod_staticfile_process (request_st * const r, plugin_config * const pconf, int line, int status, const char *desc)
{
    handler_t rc = mod_staticfile_process(r, pconf);
    if (r->http_status != status
        || rc != (status ? HANDLER_FINISHED : HANDLER_GO_ON)) {
        fprintf(stderr,
                "%s.%d: %s() failed: expected '%d', got '%d' for test %s\n",
                __FILE__, line, "mod_staticfile_process", status,
                r->http_status, desc);
        fflush(stderr);
        abort();
    }
}

static void
test_mod_staticfile_process (request_st * const r, plugin_config * const pconf)
{
    test_mod_staticfile_reset(r);

    pconf->pathinfo = 1;
    buffer_copy_string_len(&r->pathinfo, CONST_STR_LEN("/pathinfo"));
    run_mod_staticfile_process(r, pconf, __LINE__, 200,
      "pathinfo allowed and present");
    test_mod_staticfile_reset(r);
    pconf->pathinfo = 0;
    run_mod_staticfile_process(r, pconf, __LINE__, 0,
      "pathinfo denied and present");
    test_mod_staticfile_reset(r);
    buffer_clear(&r->pathinfo);
    run_mod_staticfile_process(r, pconf, __LINE__, 200,
      "pathinfo denied and not present");
    test_mod_staticfile_reset(r);
    pconf->pathinfo = 1;

    array * const a = array_init(1);
    array_insert_value(a, CONST_STR_LEN(".exe"));
    pconf->exclude_ext = a;
    run_mod_staticfile_process(r, pconf, __LINE__, 200,
      "extension disallowed (no match)");
    test_mod_staticfile_reset(r);
    buffer_append_string_len(&r->physical.path, CONST_STR_LEN(".exe"));
    run_mod_staticfile_process(r, pconf, __LINE__, 0,
      "extension disallowed (match)");
    test_mod_staticfile_reset(r);
    pconf->exclude_ext = NULL;
    array_free(a);
}

#include "sys-unistd.h" /* unlink() */
#include "fdevent.h"

void test_mod_staticfile (void);
void test_mod_staticfile (void)
{
    const char *tmpdir = getenv("TMPDIR");
  #ifdef _WIN32
    if (NULL == tmpdir) tmpdir = getenv("TEMP");
  #endif
    if (NULL == tmpdir) tmpdir = "/tmp";
    size_t tmpdirlen = strlen(tmpdir);
    buffer fnb = { NULL, 0, 0 };
    buffer_copy_path_len2(&fnb, tmpdir, tmpdirlen,
                          CONST_STR_LEN("lighttpd_mod_staticfile.XXXXXX"));
    if (fnb.ptr[tmpdirlen] == '/') ++tmpdirlen;
    char * const fn = fnb.ptr;
    const size_t fnlen = buffer_clen(&fnb);
    int fd = fdevent_mkostemp(fn, 0);
    if (fd < 0) {
        perror("mkstemp()");
        buffer_free_ptr(&fnb);
        exit(1);
    }
    struct stat st;
    if (0 != fstat(fd, &st)) {
        perror("fstat()");
        buffer_free_ptr(&fnb);
        exit(1);
    }

    request_st r;

    memset(&r, 0, sizeof(request_st));
    chunkqueue_init(&r.write_queue);
    chunkqueue_init(&r.read_queue);
    chunkqueue_init(&r.reqbody_queue);
    r.http_method            = HTTP_METHOD_GET;
    r.http_version           = HTTP_VERSION_1_1;
    r.tmp_buf                = buffer_init();
    r.conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
    r.conf.errh->fd          = -1; /* (disable) */
    r.conf.follow_symlink    = 1;
    buffer_copy_string_len(&r.uri.path, CONST_STR_LEN("/"));
    array * const mimetypes = array_init(1);
    r.conf.mimetypes = mimetypes;
    array_set_key_value(mimetypes, fn+fnlen-7, 7,
                                   CONST_STR_LEN("text/plain"));

    strftime_cache_reset();

    buffer_copy_string_len(&r.physical.path, fn, fnlen);
    test_http_response_send_file(&r, st.st_mtime);

    r.rqst_htags = 0;
    array_reset_data_strings(&r.rqst_headers);

    buffer_copy_string_len(&r.physical.path, fn, fnlen);
    plugin_config pconf;
    memset(&pconf, '\0', sizeof(pconf));
    pconf.etags_used = 1;
    test_mod_staticfile_process(&r, &pconf);

    array_free(mimetypes);
    fdlog_free(r.conf.errh);
    buffer_free(r.tmp_buf);
    chunkqueue_reset(&r.write_queue);

    free(r.uri.path.ptr);
    free(r.pathinfo.ptr);
    free(r.physical.path.ptr);
    free(r.physical.rel_path.ptr);
    free(r.physical.doc_root.ptr);
    array_free_data(&r.rqst_headers);
    array_free_data(&r.resp_headers);

    stat_cache_free();
    close(fd);
    unlink(fn);
    buffer_free_ptr(&fnb);
}
