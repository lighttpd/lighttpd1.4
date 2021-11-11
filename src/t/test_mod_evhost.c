#include "first.h"

#undef NDEBUG
#include <assert.h>

#include "mod_evhost.c"

struct ttt {
  const char *pattern;
  size_t plen;
  const char *expect;
  size_t elen;
};

static void test_mod_evhost_build_doc_root_path_loop(struct ttt *tt, size_t nelts, buffer *authority, buffer *b, array *a) {
    for (size_t i = 0; i < nelts; ++i) {
        struct ttt *t = tt+i;
        const buffer *path_pieces = mod_evhost_parse_pattern(t->pattern);
        assert(NULL != path_pieces);
        mod_evhost_build_doc_root_path(b, a, authority, path_pieces);
        assert(buffer_eq_slen(b, t->expect, t->elen));
        mod_evhost_free_path_pieces(path_pieces);
    }
}

static void test_mod_evhost_build_doc_root_path(void) {
    buffer *authority = buffer_init();
    buffer *b = buffer_init();
    array *a = array_init(0);
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

void test_mod_evhost (void);
void test_mod_evhost (void)
{
    test_mod_evhost_build_doc_root_path();
}
