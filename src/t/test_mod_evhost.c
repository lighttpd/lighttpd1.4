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

static void test_mod_evhost_build_doc_root_path(void) {
    buffer *authority = buffer_init_string("host.example.org");
    buffer *b = buffer_init();
    array *a = array_init();
    struct ttt {
      const char *pattern;
      size_t plen;
      const char *expect;
      size_t elen;
    } tt[] = {
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
    };

    for (size_t i = 0; i < sizeof(tt)/sizeof(tt[0]); ++i) {
        struct ttt *t = tt+i;
        plugin_config *s = test_mod_evhost_plugin_config_init();
        buffer_copy_string_len(s->path_pieces_raw, t->pattern, t->plen);
        assert(0 == mod_evhost_parse_pattern(s));
        mod_evhost_build_doc_root_path(b, a, authority, s->path_pieces, s->len);
        assert(buffer_is_equal_string(b, t->expect, t->elen));
        test_mod_evhost_plugin_config_free(s);
    }

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
