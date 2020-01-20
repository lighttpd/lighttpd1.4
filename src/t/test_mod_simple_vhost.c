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

stat_cache_entry * stat_cache_get_entry(const buffer *name) {
    UNUSED(name);
    return NULL;
}

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
