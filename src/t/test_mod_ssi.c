#include "first.h"

#undef NDEBUG
#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "mod_ssi.c"
#include "fdlog.h"

static void test_mod_ssi_reset (request_st * const r, handler_ctx * const hctx)
{
    r->http_status = 0;
    r->resp_htags = 0;
    array_reset_data_strings(&r->resp_headers);
    http_response_body_clear(r, 0);

    buffer_clear(hctx->timefmt);
    array_reset_data_strings(hctx->ssi_vars);
    array_reset_data_strings(hctx->ssi_cgi_env);
}

static void test_mod_ssi_write_testfile (int fd, const char *buf, size_t len)
{
    if (0 != lseek(fd, 0, SEEK_SET)
        || (ssize_t)len != write(fd, buf, len)
        || 0 != ftruncate(fd, (off_t)len)
        || 0 != lseek(fd, 0, SEEK_SET)) {
        perror("lseek(),ftruncate(),write()"); /*(unlikely: partial write)*/
        exit(1);
    }
}


static void
test_mod_ssi_read_fd (request_st * const r, handler_ctx * const hctx)
{
    /* TODO: add adjustments for _WIN32 */
    char fn[] = "/tmp/lighttpd_mod_ssi_XXXXXX";
    struct stat st;
    chunkqueue * const cq = &r->write_queue;

    int fd = fdevent_mkostemp(fn, 0);
    if (fd < 0) {
        perror("mkstemp()");
        exit(1);
    }
    if (0 != fstat(fd, &st)) {
        perror("fstat()");
        exit(1);
    }
    unlink(fn);

    const char ssi_simple[] =
      "<!--#echo var=\"SCRIPT_NAME\" -->";
    test_mod_ssi_write_testfile(fd, ssi_simple, sizeof(ssi_simple)-1);
    test_mod_ssi_reset(r, hctx);
    array_set_key_value(hctx->ssi_cgi_env,
                        CONST_STR_LEN("SCRIPT_NAME"),
                        CONST_STR_LEN("/ssi.shtml"));
    mod_ssi_read_fd(r, hctx, &st, fd);
    assert(cq->first);
    assert(buffer_eq_slen(cq->first->mem,
                          CONST_STR_LEN("/ssi.shtml")));

    hctx->conf.ssi_exec = 0; /* default */
    const char ssi_exec[] =
       "<!--#exec cmd=\"expr 1 + 1\"-->";
    test_mod_ssi_write_testfile(fd, ssi_exec, sizeof(ssi_exec)-1);
    test_mod_ssi_reset(r, hctx);
    mod_ssi_read_fd(r, hctx, &st, fd);
    assert(NULL == cq->first);

    hctx->conf.ssi_exec = 1;
    test_mod_ssi_write_testfile(fd, ssi_exec, sizeof(ssi_exec)-1);
    test_mod_ssi_reset(r, hctx);
    mod_ssi_read_fd(r, hctx, &st, fd);
    assert(cq->first);
    assert(cq->first->type == FILE_CHUNK);
    assert(2 == chunkqueue_length(cq));
    char buf[80];
    if (0 != lseek(cq->first->file.fd, 0, SEEK_SET)
        || 2 != read(cq->first->file.fd, buf, sizeof(buf))) {
        perror("lseek(),read()");
        exit(1);
    }
    assert(0 == memcmp(buf, "2\n", 2));
    hctx->conf.ssi_exec = 0;

    char fni[] = "/tmp/lighttpd_mod_ssi_inc_XXXXXX";
    int fdi = fdevent_mkostemp(fni, 0);
    if (fdi < 0) {
        perror("mkstemp()");
        exit(1);
    }
    const char ssi_include[] =
       "ssi-include";
    test_mod_ssi_write_testfile(fdi, ssi_include, sizeof(ssi_include)-1);
    close(fdi);

    const char ssi_include_shtml[] =
      "<!--#echo var=SCRIPT_NAME-->\n"
      "<!--#echo var='SCRIPT_NAME'-->\n"
      "<!--#echo var=\"SCRIPT_NAME\"-->\n";
    buffer * const b = buffer_init();
    buffer_copy_string_len(b, CONST_STR_LEN(ssi_include_shtml));
    buffer_append_str3(b, CONST_STR_LEN("<!--#include virtual=\""),
                          fni+5, strlen(fni)-5, /*(step over "/tmp/")*/
                          CONST_STR_LEN("\" -->\n"));
    buffer_append_str3(b, CONST_STR_LEN("<!--#include file=\""),
                          fni+5, strlen(fni)-5, /*(step over "/tmp/")*/
                          CONST_STR_LEN("\" -->\n"));
    test_mod_ssi_write_testfile(fd, BUF_PTR_LEN(b));
    buffer_free(b);
    test_mod_ssi_reset(r, hctx);
    array_set_key_value(hctx->ssi_cgi_env,
                        CONST_STR_LEN("SCRIPT_NAME"),
                        CONST_STR_LEN("/ssi-include.shtml"));
    buffer_copy_string_len(&r->physical.doc_root, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/ssi-include.shtml"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/ssi-include.shtml"));
    buffer_copy_string_len(&r->physical.path, CONST_STR_LEN("/tmp/ssi-include.shtml"));
    mod_ssi_read_fd(r, hctx, &st, fd);
    chunkqueue_read_squash(cq, r->conf.errh);
    assert(buffer_eq_slen(cq->first->mem,
                          CONST_STR_LEN("/ssi-include.shtml\n"
                                        "/ssi-include.shtml\n"
                                        "/ssi-include.shtml\n"
                                        "ssi-include\n"
                                        "ssi-include\n")));

    unlink(fni);

    test_mod_ssi_reset(r, hctx);
    close(fd);
}

void test_mod_ssi (void);
void test_mod_ssi (void)
{
    plugin_data * const p = mod_ssi_init();
    assert(NULL != p);

    request_st r;

    memset(&r, 0, sizeof(request_st));
    r.tmp_buf                = buffer_init();
    r.conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
    r.conf.errh->fd          = -1; /* (disable) */
    r.conf.follow_symlink    = 1;

    handler_ctx * const hctx = handler_ctx_init(p, r.conf.errh);
    assert(NULL != hctx);

    test_mod_ssi_read_fd(&r, hctx);

    handler_ctx_free(hctx);

    fdlog_free(r.conf.errh);
    buffer_free(r.tmp_buf);
    chunkqueue_reset(&r.write_queue);

    free(r.uri.path.ptr);
    free(r.physical.etag.ptr);
    free(r.physical.path.ptr);
    free(r.physical.rel_path.ptr);
    free(r.physical.doc_root.ptr);

    mod_ssi_free(p);
    free(p);
    stat_cache_free();
}
