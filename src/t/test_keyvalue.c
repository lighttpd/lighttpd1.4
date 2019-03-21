#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* STDERR_FILENO */

#include "keyvalue.c"

#ifdef HAVE_PCRE_H
static pcre_keyvalue_buffer * test_keyvalue_test_kvb_init (void) {
    pcre_keyvalue_buffer *kvb = pcre_keyvalue_buffer_init();
    buffer *k = buffer_init();
    buffer *v = buffer_init();
    server srv;

    memset(&srv, 0, sizeof(srv));
    srv.errh = log_error_st_init(&srv.cur_ts, &srv.last_generated_debug_ts);

    buffer_copy_string_len(k, CONST_STR_LEN("^/foo($|\\?.+)"));
    buffer_copy_string_len(v, CONST_STR_LEN("/foo/$1"));
    assert(0 == pcre_keyvalue_buffer_append(&srv, kvb, k, v));
    buffer_copy_string_len(k, CONST_STR_LEN("^/bar(?:$|\\?(.+))"));
    buffer_copy_string_len(v, CONST_STR_LEN("/?bar&$1"));
    assert(0 == pcre_keyvalue_buffer_append(&srv, kvb, k, v));
    buffer_copy_string_len(k, CONST_STR_LEN("^/redirect(?:\\?(.*))?$"));
    buffer_copy_string_len(v, CONST_STR_LEN("/?seg=%1&$1"));
    assert(0 == pcre_keyvalue_buffer_append(&srv, kvb, k, v));
    buffer_copy_string_len(k, CONST_STR_LEN("^(/[^?]*)(?:\\?(.*))?$"));
    buffer_copy_string_len(v, CONST_STR_LEN("/?file=$1&$2"));
    assert(0 == pcre_keyvalue_buffer_append(&srv, kvb, k, v));

    buffer_free(k);
    buffer_free(v);
    log_error_st_free(srv.errh);

    return kvb;
}

static void test_keyvalue_pcre_keyvalue_buffer_process (void) {
    pcre_keyvalue_buffer *kvb = test_keyvalue_test_kvb_init();
    buffer *url = buffer_init();
    buffer *result = buffer_init();
    struct burl_parts_t burl;
    cond_cache_t cache;
    pcre_keyvalue_ctx ctx;
    handler_t rc;

    ctx.burl = &burl;
    burl.scheme    = buffer_init();
    burl.authority = buffer_init();
    burl.port      = 80;
    burl.path      = buffer_init();
    burl.query     = buffer_init();
    buffer_copy_string_len(burl.scheme, CONST_STR_LEN("http"));
    buffer_copy_string_len(burl.authority, CONST_STR_LEN("www.example.com"));
    /* model outer conditional match of $HTTP["host"] =~ "^(www).example.com$" */
    ctx.cache = &cache;
    memset(&cache, 0, sizeof(cache));
    cache.patterncount = 2;
    cache.comp_value = burl.authority;
    cache.matches[0] = 0;
    cache.matches[1] = 15;
    cache.matches[2] = 0;
    cache.matches[3] = 3;

    /* converted from prior sparse tests/mod-redirect.t and tests/mod-rewrite.t
     * (real-world use should prefer ${url.path} and ${qsa} in substitutions)
     */

    buffer_copy_string_len(url, CONST_STR_LEN("/foo"));
    buffer_copy_string_len(burl.path, CONST_STR_LEN("/foo"));
    buffer_clear(burl.query);
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/foo/")));

    buffer_copy_string_len(url, CONST_STR_LEN("/foo?a=b"));
    buffer_copy_string_len(burl.path, CONST_STR_LEN("/foo"));
    buffer_copy_string_len(burl.query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/foo/?a=b")));

    buffer_copy_string_len(url, CONST_STR_LEN("/bar?a=b"));
    buffer_copy_string_len(burl.path, CONST_STR_LEN("/bar"));
    buffer_copy_string_len(burl.query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/?bar&a=b")));

    buffer_copy_string_len(url, CONST_STR_LEN("/nofile?a=b"));
    buffer_copy_string_len(burl.path, CONST_STR_LEN("/nofile"));
    buffer_copy_string_len(burl.query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/?file=/nofile&a=b")));

    buffer_copy_string_len(url, CONST_STR_LEN("/redirect?a=b"));
    buffer_copy_string_len(burl.path, CONST_STR_LEN("/redirect"));
    buffer_copy_string_len(burl.query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/?seg=www&a=b")));

    buffer_free(url);
    buffer_free(result);
    buffer_free(burl.scheme);
    buffer_free(burl.authority);
    buffer_free(burl.path);
    buffer_free(burl.query);
    pcre_keyvalue_buffer_free(kvb);
}
#endif

int main (void) {
  #ifdef HAVE_PCRE_H
    test_keyvalue_pcre_keyvalue_buffer_process();
  #endif
    return 0;
}
