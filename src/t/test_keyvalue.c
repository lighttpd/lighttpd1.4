#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* STDERR_FILENO */

#include "keyvalue.c"

#include "base.h"   /* struct server */
#include "plugin_config.h" /* struct cond_match_t */

#ifdef HAVE_PCRE_H
static pcre_keyvalue_buffer * test_keyvalue_test_kvb_init (void) {
    pcre_keyvalue_buffer *kvb = pcre_keyvalue_buffer_init();

    log_error_st * const errh = log_error_st_init();

    /* strings must be persistent for pcre_keyvalue_buffer_append() */
    static const buffer kvstr[] = {
      { "^/foo($|\\?.+)",          sizeof("^/foo($|\\?.+)"), 0 },
      { "/foo/$1",                 sizeof("/foo/$1"), 0 },
      { "^/bar(?:$|\\?(.+))",      sizeof("^/bar(?:$|\\?(.+))"), 0 },
      { "/?bar&$1",                sizeof("/?bar&$1"), 0 },
      { "^/redirect(?:\\?(.*))?$", sizeof("^/redirect(?:\\?(.*))?$"), 0 },
      { "/?seg=%1&$1",             sizeof("/?seg=%1&$1"), 0 },
      { "^(/[^?]*)(?:\\?(.*))?$",  sizeof("^(/[^?]*)(?:\\?(.*))?$"), 0 },
      { "/?file=$1&$2",            sizeof("/?file=$1&$2"), 0 }
    };

    assert(pcre_keyvalue_buffer_append(errh, kvb, kvstr+0, kvstr+1));
    assert(pcre_keyvalue_buffer_append(errh, kvb, kvstr+2, kvstr+3));
    assert(pcre_keyvalue_buffer_append(errh, kvb, kvstr+4, kvstr+5));
    assert(pcre_keyvalue_buffer_append(errh, kvb, kvstr+6, kvstr+7));

    log_error_st_free(errh);

    return kvb;
}

static void test_keyvalue_pcre_keyvalue_buffer_process (void) {
    pcre_keyvalue_buffer *kvb = test_keyvalue_test_kvb_init();
    buffer *url = buffer_init();
    buffer *result = buffer_init();
    struct burl_parts_t burl;
    cond_match_t cache;
    pcre_keyvalue_ctx ctx;
    handler_t rc;
    buffer *scheme    = buffer_init();
    buffer *authority = buffer_init();
    buffer *path      = buffer_init();
    buffer *query     = buffer_init();

    ctx.burl = &burl;
    burl.scheme    = scheme;
    burl.authority = authority;
    burl.port      = 80;
    burl.path      = path;
    burl.query     = query;
    buffer_copy_string_len(scheme, CONST_STR_LEN("http"));
    buffer_copy_string_len(authority, CONST_STR_LEN("www.example.com"));
    /* model outer conditional match of $HTTP["host"] =~ "^(www).example.com$" */
    ctx.cond_match_count = 2;
    ctx.cache = &cache;
    memset(&cache, 0, sizeof(cache));
    cache.comp_value = authority;
    cache.matches[0] = 0;
    cache.matches[1] = 15;
    cache.matches[2] = 0;
    cache.matches[3] = 3;

    /* converted from prior sparse tests/mod-redirect.t and tests/mod-rewrite.t
     * (real-world use should prefer ${url.path} and ${qsa} in substitutions)
     */

    buffer_copy_string_len(url, CONST_STR_LEN("/foo"));
    buffer_copy_string_len(path, CONST_STR_LEN("/foo"));
    buffer_clear(query);
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/foo/")));

    buffer_copy_string_len(url, CONST_STR_LEN("/foo?a=b"));
    buffer_copy_string_len(path, CONST_STR_LEN("/foo"));
    buffer_copy_string_len(query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/foo/?a=b")));

    buffer_copy_string_len(url, CONST_STR_LEN("/bar?a=b"));
    buffer_copy_string_len(path, CONST_STR_LEN("/bar"));
    buffer_copy_string_len(query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/?bar&a=b")));

    buffer_copy_string_len(url, CONST_STR_LEN("/nofile?a=b"));
    buffer_copy_string_len(path, CONST_STR_LEN("/nofile"));
    buffer_copy_string_len(query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/?file=/nofile&a=b")));

    buffer_copy_string_len(url, CONST_STR_LEN("/redirect?a=b"));
    buffer_copy_string_len(path, CONST_STR_LEN("/redirect"));
    buffer_copy_string_len(query, CONST_STR_LEN("a=b"));
    rc = pcre_keyvalue_buffer_process(kvb, &ctx, url, result);
    assert(HANDLER_FINISHED == rc);
    assert(buffer_is_equal_string(result, CONST_STR_LEN("/?seg=www&a=b")));

    buffer_free(url);
    buffer_free(result);
    buffer_free(scheme);
    buffer_free(authority);
    buffer_free(path);
    buffer_free(query);
    pcre_keyvalue_buffer_free(kvb);
}
#endif

int main (void) {
  #ifdef HAVE_PCRE_H
    test_keyvalue_pcre_keyvalue_buffer_process();
  #endif
    return 0;
}
