#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mod_alias.c"

static void test_mod_alias_check(void) {
    request_st r;
    memset(&r, 0, sizeof(request_st));
    array * const aliases = array_init(3);

    /*(empty list; should not happen in practice)*/
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));

    /* Use-after-free bug in mod_alias
     * https://redmine.lighttpd.net/issues/3114 */
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/"), CONST_STR_LEN(
      "/very-long-path/longer-than-64/intended-to-trigger-str-reallocation/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr,
      "/very-long-path/longer-than-64/intended-to-trigger-str-reallocation/"));
    assert(0 == strcmp(r.physical.path.ptr,
      "/very-long-path/longer-than-64/intended-to-trigger-str-reallocation/"));

    /*(admin should prefer to match dirs with trailing '/', but test w/o)*/
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp/"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/"), CONST_STR_LEN("/var/tmp"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr, "/var/tmp"));
    assert(0 == strcmp(r.physical.path.ptr, "/var/tmp"));

    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/foo"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/foo"),
                                 CONST_STR_LEN("/var/tmp/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr, "/var/tmp/"));
    assert(0 == strcmp(r.physical.path.ptr, "/var/tmp/"));

    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/fooddd"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/foo"),
                                 CONST_STR_LEN("/var/tmp/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr, "/var/tmp/"));
    assert(0 == strcmp(r.physical.path.ptr, "/var/tmp/ddd"));

    /* security: path traversal in mod_alias (in some use cases)
     * https://redmine.lighttpd.net/issues/2898 */
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/foo../bad"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/foo"),
                                 CONST_STR_LEN("/var/tmp/"));
    assert(HANDLER_FINISHED == mod_alias_remap(&r, aliases));
    assert(403 == r.http_status);
    r.http_status = 0;

    /* replacement longer */
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/foo/x"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/foo/"),
                                 CONST_STR_LEN("/opt/var/tmp/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr, "/opt/var/tmp/"));
    assert(0 == strcmp(r.physical.path.ptr, "/opt/var/tmp/x"));

    /* replacement shorter */
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/foo/x"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/foo/"),
                                 CONST_STR_LEN("/ba/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr, "/ba/"));
    assert(0 == strcmp(r.physical.path.ptr, "/ba/x"));

    /* replacement same length */
    buffer_copy_string_len(&r.physical.basedir, CONST_STR_LEN("/tmp"));
    buffer_copy_string_len(&r.physical.path, CONST_STR_LEN("/tmp/foo/x"));
    array_reset_data_strings(aliases);
    array_set_key_value(aliases, CONST_STR_LEN("/foo/"),
                                 CONST_STR_LEN("/var/tmp/"));
    assert(HANDLER_GO_ON == mod_alias_remap(&r, aliases));
    assert(0 == strcmp(r.physical.basedir.ptr, "/var/tmp/"));
    assert(0 == strcmp(r.physical.path.ptr, "/var/tmp/x"));

    array_free(aliases);
    free(r.physical.path.ptr);
    free(r.physical.basedir.ptr);
}

void test_mod_alias (void);
void test_mod_alias (void)
{
    test_mod_alias_check();
}
