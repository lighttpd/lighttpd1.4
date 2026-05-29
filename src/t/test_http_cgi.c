#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* stub functions to avoid pulling in chunk.c and fdevent.c */
#include "chunk.h"
#define chunkqueue_reset(cq)                               do { } while (0)

#include "http_cgi.c"

static void test_http_cgi_encode_varname (buffer * const tb) {
    /* varname encoding translates all non-ASCII-alphanumeric chars to '_' */
    const char * const pairs[] = {
      "forwarded",       "HTTP_FORWARDED"
     ,"x-forwarded-for", "HTTP_X_FORWARDED_FOR"
     ,"user-agent",      "HTTP_USER_AGENT"
     ,"something",       "HTTP_SOMETHING"
     ,"something-else",  "HTTP_SOMETHING_ELSE"
     ,"something_else",  "HTTP_SOMETHING_ELSE"
     ,"something+else",  "HTTP_SOMETHING_ELSE"
     ,"something.else",  "HTTP_SOMETHING_ELSE"
     ,"something:else",  "HTTP_SOMETHING_ELSE"
     /*(XXX: could add more variations)*/
    };
    for (size_t i = 0; i < sizeof(pairs)/sizeof(*pairs); i += 2) {
        buffer_clear(tb);
        http_cgi_encode_varname(tb, pairs[i], strlen(pairs[i]), 1);
        assert(buffer_eq_slen(tb, pairs[i+1], strlen(pairs[i+1])));
    }
}

static void test_http_cgi_check_other_conflict (request_st * const r) {
    buffer * const field_name = buffer_init();
    buffer * const tb = r->tmp_buf;

    buffer_copy_string_len(field_name, CONST_STR_LEN("Forwarded"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));

    /* reject header if it conflicts with varname encoding of a
     * different header recognized in src/http_header.c:http_header[] */
    buffer_copy_string_len(field_name, CONST_STR_LEN("X-Forwarded-For"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("X-Forwarded_For"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));

    buffer_copy_string_len(field_name, CONST_STR_LEN("Content-Type"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Content_Type"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));

    buffer_copy_string_len(field_name, CONST_STR_LEN("User-Agent"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("User_Agent"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));

    buffer_copy_string_len(field_name, CONST_STR_LEN("Something"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Something-Else"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Something_Else"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(0 == http_cgi_check_other_conflict(r, field_name, tb));

    /* reject header if it conflicts with another header in request
     * containing only '-' in places that become '_' in varname encoding */
    http_header_request_set(r, HTTP_HEADER_OTHER,
                            CONST_STR_LEN("Something-Else"),
                            CONST_STR_LEN("."));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Something_Else"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Something+Else"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Something.Else"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));
    buffer_copy_string_len(field_name, CONST_STR_LEN("Something:Else"));
    http_cgi_encode_varname(tb, BUF_PTR_LEN(field_name), 1);
    assert(1 == http_cgi_check_other_conflict(r, field_name, tb));

    buffer_free(field_name);
}

void test_http_cgi (void);
void test_http_cgi (void)
{
    request_st r;

    memset(&r, 0, sizeof(request_st));
    r.tmp_buf                = buffer_init();

    test_http_cgi_encode_varname(r.tmp_buf);
    test_http_cgi_check_other_conflict(&r);

    /* TODO (more) */
    /* TODO need to initialize more elements of request_st *r for these tests */
    /*test_http_cgi_headers();*/
    /*test_http_cgi_local_redir();*/

    array_free_data(&r.rqst_headers);
    buffer_free(r.tmp_buf);
}
