#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>

#include "mod_userdir.c"
#include "fdlog.h"

static void test_mod_userdir_reset(request_st * const r)
{
    r->http_status = 0;
    buffer_clear(&r->physical.basedir);
    buffer_clear(&r->physical.path);
}

static void
test_mod_userdir_docroot_handler(request_st * const r, plugin_data * const p)
{
    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN(""));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    p->defaults.active = 1;

    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/other"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~no-trailing-slash"));
    test_mod_userdir_reset(r);
    assert(HANDLER_FINISHED == mod_userdir_docroot_handler(r, p));
    assert(301 == r->http_status);
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_eq_slen(&r->physical.basedir,
                          CONST_STR_LEN("/web/u/jan/public_html")));
    assert(buffer_eq_slen(&r->physical.path,
                          CONST_STR_LEN("/web/u/jan/public_html/")));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/more"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/more"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_eq_slen(&r->physical.basedir,
                          CONST_STR_LEN("/web/u/jan/public_html")));
    assert(buffer_eq_slen(&r->physical.path,
                          CONST_STR_LEN("/web/u/jan/public_html/more")));

    p->defaults.letterhomes = 1;

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~.jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_eq_slen(&r->physical.basedir,
                          CONST_STR_LEN("/web/u/j/jan/public_html")));
    assert(buffer_eq_slen(&r->physical.path,
                          CONST_STR_LEN("/web/u/j/jan/public_html/")));

    p->defaults.letterhomes = 0;

    array *include_user = array_init(2);
    array *exclude_user = array_init(2);

    array_insert_value(include_user, CONST_STR_LEN("notjan"));

    p->defaults.include_user = include_user;

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    array_insert_value(include_user, CONST_STR_LEN("jan"));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_eq_slen(&r->physical.basedir,
                          CONST_STR_LEN("/web/u/jan/public_html")));
    assert(buffer_eq_slen(&r->physical.path,
                          CONST_STR_LEN("/web/u/jan/public_html/")));

    p->defaults.exclude_user = exclude_user;

    array_insert_value(exclude_user, CONST_STR_LEN("notjan"));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_eq_slen(&r->physical.basedir,
                          CONST_STR_LEN("/web/u/jan/public_html")));
    assert(buffer_eq_slen(&r->physical.path,
                          CONST_STR_LEN("/web/u/jan/public_html/")));

    array_insert_value(exclude_user, CONST_STR_LEN("jan"));

    buffer_copy_string_len(&r->uri.path, CONST_STR_LEN("/~jan/"));
    buffer_copy_string_len(&r->physical.rel_path, CONST_STR_LEN("/~jan/"));
    test_mod_userdir_reset(r);
    assert(HANDLER_GO_ON == mod_userdir_docroot_handler(r, p));
    assert(buffer_is_empty(&r->physical.basedir));
    assert(buffer_is_empty(&r->physical.path));

    p->defaults.include_user = NULL;
    p->defaults.exclude_user = NULL;
    array_free(include_user);
    array_free(exclude_user);
}

#include "base.h"

void test_mod_userdir (void);
void test_mod_userdir (void)
{
    plugin_data * const p = mod_userdir_init();
    assert(NULL != p);

    buffer *basepath = buffer_init();
    buffer *path     = buffer_init();
    buffer_copy_string(basepath, "/web/u/"); /*(skip getpwnam())*/
    buffer_copy_string(path, "public_html");
    p->defaults.basepath = basepath;
    p->defaults.path = path;

    request_st r;
    connection con;
    server srv;

    memset(&r, 0, sizeof(request_st));
    memset(&con, 0, sizeof(connection));
    memset(&srv, 0, sizeof(server));
    chunkqueue_init(&r.write_queue);
    chunkqueue_init(&r.read_queue);
    chunkqueue_init(&r.reqbody_queue);
    r.tmp_buf                = buffer_init();
    r.conf.errh              = fdlog_init(NULL, -1, FDLOG_FD);
    r.conf.errh->fd          = -1; /* (disable) */
    /* r->con->srv->srvconf.absolute_dir_redirect
     * in http_response_redirect_to_directory() */
    r.con = &con;
    con.srv = &srv;

    test_mod_userdir_docroot_handler(&r, p);

    free(r.uri.path.ptr);
    free(r.physical.basedir.ptr);
    free(r.physical.path.ptr);
    free(r.physical.rel_path.ptr);
    array_free_data(&r.resp_headers);

    fdlog_free(r.conf.errh);
    buffer_free(r.tmp_buf);

    buffer_free(basepath);
    buffer_free(path);
    free(p);
}
