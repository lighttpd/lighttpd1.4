#include "first.h"

#undef NDEBUG
#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "mod_indexfile.c"
#include "fdlog.h"

__attribute_noinline__
static void test_mod_indexfile_reset (request_st * const r, const char * const fn, const size_t fnlen)
{
    r->http_status = 0;
    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/"));
    buffer_copy_string_len(&r->physical.doc_root, fn, fnlen-1);
    buffer_copy_string_len(&r->physical.path, fn, fnlen);
}

__attribute_noinline__
static void
run_mod_indexfile_tryfiles (request_st * const r, const array * const indexfiles, int line, int status, const char *desc)
{
    handler_t rc = mod_indexfile_tryfiles(r, indexfiles);
    if (r->http_status != status
        || rc != (status ? HANDLER_FINISHED : HANDLER_GO_ON)) {
        fprintf(stderr,
                "%s.%d: %s() failed: expected '%d', got '%d' for test %s\n",
                __FILE__, line, "mod_indexfile_tryfiles", status,
                r->http_status, desc);
        fflush(stderr);
        abort();
    }
}

#include "sys-unistd.h" /* unlink() */
#include "fdevent.h"

static void
test_mod_indexfile_tryfiles (request_st * const r)
{
    const char *tmpdir = getenv("TMPDIR");
  #ifdef _WIN32
    if (NULL == tmpdir) tmpdir = getenv("TEMP");
  #endif
    if (NULL == tmpdir) tmpdir = "/tmp";
    size_t tmpdirlen = strlen(tmpdir);
    buffer fnb = { NULL, 0, 0 };
    buffer_copy_path_len2(&fnb, tmpdir, tmpdirlen,
                          CONST_STR_LEN("lighttpd_mod_indexfile.XXXXXX"));
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
    array * const indexfiles = array_init(3);

    test_mod_indexfile_reset(r, fn, tmpdirlen);

    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "empty indexfiles");
    assert(buffer_eq_slen(&r->physical.path, fn, tmpdirlen));
    test_mod_indexfile_reset(r, fn, tmpdirlen);

    /*(assumes modified tempfile name does not exist)*/
    array_insert_value(indexfiles, fn+tmpdirlen, fnlen-tmpdirlen-1);
    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "non-matching indexfiles");
    assert(buffer_eq_slen(&r->physical.path, fn, tmpdirlen));
    test_mod_indexfile_reset(r, fn, tmpdirlen);

    array_insert_value(indexfiles, fn+tmpdirlen, fnlen-tmpdirlen);
    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "matching indexfile entry (w/o leading '/')");
    assert(buffer_eq_slen(&r->physical.path, fn, fnlen));
    test_mod_indexfile_reset(r, fn, tmpdirlen);

    array_reset_data_strings(indexfiles);
    array_insert_value(indexfiles, fn+tmpdirlen-1, fnlen-(tmpdirlen-1));
    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "matching indexfile entry (w/ leading '/')");
    assert(buffer_eq_slen(&r->physical.path, fn, fnlen));
    test_mod_indexfile_reset(r, fn, tmpdirlen);

    array_free(indexfiles);
    close(fd);
    unlink(fn);
    buffer_free_ptr(&fnb);
}

void test_mod_indexfile (void);
void test_mod_indexfile (void)
{
    request_st r;

    memset(&r, 0, sizeof(request_st));
    chunkqueue_init(&r.write_queue);
    chunkqueue_init(&r.read_queue);
    chunkqueue_init(&r.reqbody_queue);
    r.conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
    r.conf.errh->fd          = -1; /* (disable) */
    r.conf.follow_symlink    = 1;
    array * const mimetypes = array_init(0);
    r.conf.mimetypes = mimetypes; /*(must not be NULL)*/

    test_mod_indexfile_tryfiles(&r);

    array_free(mimetypes);
    fdlog_free(r.conf.errh);

    free(r.uri.path.ptr);
    free(r.physical.path.ptr);
    free(r.physical.doc_root.ptr);
    array_free_data(&r.env);

    stat_cache_free();
}
