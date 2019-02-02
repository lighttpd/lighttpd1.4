#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "mod_evhost.c"

static plugin_config * test_mod_evhost_plugin_config_init(void) {
    plugin_config *s = calloc(1, sizeof(plugin_config));
    s->path_pieces_raw = buffer_init();
    s->path_pieces = NULL;
    s->len = 0;
    return s;
}

static void test_mod_evhost_plugin_config_free(plugin_config *s) {
    buffer_free(s->path_pieces_raw);
    for (size_t i = 0; i < s->len; ++i) buffer_free(s->path_pieces[i]);
    free(s->path_pieces);
    free(s);
}

struct ttt {
  const char *pattern;
  size_t plen;
  const char *expect;
  size_t elen;
};

static void test_mod_evhost_build_doc_root_path_loop(struct ttt *tt, size_t nelts, buffer *authority, buffer *b, array *a) {
    for (size_t i = 0; i < nelts; ++i) {
        struct ttt *t = tt+i;
        plugin_config *s = test_mod_evhost_plugin_config_init();
        buffer_copy_string_len(s->path_pieces_raw, t->pattern, t->plen);
        assert(0 == mod_evhost_parse_pattern(s));
        mod_evhost_build_doc_root_path(b, a, authority, s->path_pieces, s->len);
        assert(buffer_is_equal_string(b, t->expect, t->elen));
        test_mod_evhost_plugin_config_free(s);
    }
}

static void test_mod_evhost_build_doc_root_path(void) {
    buffer *authority = buffer_init();
    buffer *b = buffer_init();
    array *a = array_init();
    struct ttt tt1[] = {  /* "host.example.org" */
      /* correct pattern not using dot notation */
      { CONST_STR_LEN("/web/%3/"),
        CONST_STR_LEN("/web/host/") }
      /* correct pattern using dot notation */
     ,{ CONST_STR_LEN("/web/%{3.1}/%{3.2}/%3/"),
        CONST_STR_LEN("/web/h/o/host/") }
      /* other pattern 1 */
     ,{ CONST_STR_LEN("/web/%{3.0}/"),
        CONST_STR_LEN("/web/host/") }
      /* other pattern 2 */
     ,{ CONST_STR_LEN("/web/%3.\1/"),
        CONST_STR_LEN("/web/host.\1/") }
     ,{ CONST_STR_LEN("/web/%0/"),
        CONST_STR_LEN("/web/example.org/") }
    }, tt2[] = {          /* "example" */
      { CONST_STR_LEN("/web/%0"),
        CONST_STR_LEN("/web/example/") }
    }, tt3[] = {          /* "[::1]:80" */
      { CONST_STR_LEN("/web/%0"),
        CONST_STR_LEN("/web/[::1]/") }
    };

    array_reset_data_strings(a);
    buffer_copy_string_len(authority, CONST_STR_LEN("host.example.org"));
    test_mod_evhost_build_doc_root_path_loop(tt1, sizeof(tt1)/sizeof(tt1[0]), authority, b, a);
    array_reset_data_strings(a);
    buffer_copy_string_len(authority, CONST_STR_LEN("example"));
    test_mod_evhost_build_doc_root_path_loop(tt2, sizeof(tt2)/sizeof(tt2[0]), authority, b, a);
    array_reset_data_strings(a);
    buffer_copy_string_len(authority, CONST_STR_LEN("[::1]:80"));
    test_mod_evhost_build_doc_root_path_loop(tt3, sizeof(tt3)/sizeof(tt3[0]), authority, b, a);

    buffer_free(authority);
    buffer_free(b);
    array_free(a);
}

int main (void) {
    test_mod_evhost_build_doc_root_path();

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
