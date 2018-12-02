#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "mod_simple_vhost.c"

static void test_mod_simple_vhost_build_doc_root_path(void) {
    buffer *sroot = buffer_init();
    buffer *host  = buffer_init();
    buffer *droot = buffer_init();
    buffer *result= buffer_init();

    buffer_copy_string_len(sroot, CONST_STR_LEN("/sroot/a/"));
    buffer_copy_string_len(host,  CONST_STR_LEN("www.example.org"));
    buffer_copy_string_len(droot, CONST_STR_LEN("/droot/b/"));
    build_doc_root_path(result, sroot, host, droot);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/sroot/a/www.example.org/droot/b/")));

    buffer_copy_string_len(host,  CONST_STR_LEN("www.example.org:8080"));
    build_doc_root_path(result, sroot, host, droot);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/sroot/a/www.example.org/droot/b/")));

    buffer_copy_string_len(droot, CONST_STR_LEN(""));
    build_doc_root_path(result, sroot, host, droot);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/sroot/a/www.example.org/")));

    buffer_free(sroot);
    buffer_free(host);
    buffer_free(droot);
    buffer_free(result);
}

int main (void) {
    test_mod_simple_vhost_build_doc_root_path();

    return 0;
}

/*
 * stub functions
 */

handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **sce) {
    UNUSED(srv);
    UNUSED(con);
    UNUSED(name);
    UNUSED(sce);
    return HANDLER_GO_ON;
}

