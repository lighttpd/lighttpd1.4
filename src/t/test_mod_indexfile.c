#include "first.h"

#undef NDEBUG
#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "mod_indexfile.c"
#include "fdlog.h"

__attribute_noinline__
static void test_mod_indexfile_reset (request_st * const r)
{
    r->http_status = 0;
    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/"));
    buffer_copy_string_len(&r->physical.doc_root, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r->physical.path, CONST_STR_LEN("/tmp/"));
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

#include <unistd.h>     /* unlink() */

static void
test_mod_indexfile_tryfiles (request_st * const r)
{
    char fn[] = "/tmp/lighttpd_mod_indexfile.XXXXXX";
  #ifdef __COVERITY__
    /* POSIX-2008 requires mkstemp create file with 0600 perms */
    umask(0600);
  #endif
    /* coverity[secure_temp : FALSE] */
    int fd = mkstemp(fn);
    if (fd < 0) {
        perror("mkstemp()");
        exit(1);
    }
    struct stat st;
    if (0 != fstat(fd, &st)) {
        perror("fstat()");
        exit(1);
    }
    array * const indexfiles = array_init(3);

    test_mod_indexfile_reset(r);

    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "empty indexfiles");
    assert(buffer_eq_slen(&r->physical.path, CONST_STR_LEN("/tmp/")));
    test_mod_indexfile_reset(r);

    /*(assumes modified tempfile name does not exist)*/
    array_insert_value(indexfiles, fn+5, sizeof(fn)-6-1);
    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "non-matching indexfiles");
    assert(buffer_eq_slen(&r->physical.path, CONST_STR_LEN("/tmp/")));
    test_mod_indexfile_reset(r);

    array_insert_value(indexfiles, fn+5, sizeof(fn)-5-1);
    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "matching indexfile entry (w/o leading '/')");
    assert(buffer_eq_slen(&r->physical.path, fn, sizeof(fn)-1));
    test_mod_indexfile_reset(r);

    array_reset_data_strings(indexfiles);
    array_insert_value(indexfiles, fn+4, sizeof(fn)-4-1);
    run_mod_indexfile_tryfiles(r, indexfiles, __LINE__, 0,
      "matching indexfile entry (w/ leading '/')");
    assert(buffer_eq_slen(&r->physical.path, fn, sizeof(fn)-1));
    test_mod_indexfile_reset(r);

    array_free(indexfiles);
    unlink(fn);
}

int main (void)
{
    request_st r;

    memset(&r, 0, sizeof(request_st));
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

    stat_cache_free();
    return 0;
}


/*
 * stub functions
 */

#include "fdevent_impl.h"
int fdevent_select_init(struct fdevents *ev) { return NULL == ev; }
int fdevent_poll_init(struct fdevents *ev) { return NULL == ev; }
int fdevent_linux_sysepoll_init(struct fdevents *ev) { return NULL == ev; }
int fdevent_solaris_devpoll_init(struct fdevents *ev) { return NULL == ev; }
int fdevent_solaris_port_init(struct fdevents *ev) { return NULL == ev; }
int fdevent_freebsd_kqueue_init(struct fdevents *ev) { return NULL == ev; }
int fdevent_libev_init(struct fdevents *ev) { return NULL == ev; }

int config_plugin_values_init(server *srv, void *p_d, const config_plugin_keys_t *cpk, const char *mname) {
    UNUSED(srv);
    UNUSED(p_d);
    UNUSED(cpk);
    UNUSED(mname);
    return 0;
}

int config_check_cond(request_st *r, int context_ndx) {
    UNUSED(r);
    UNUSED(context_ndx);
    return 0;
}
