#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "http_kv.c"

static void test_http_kv_tables (void) {
    assert(0 == strcmp(get_http_version_name(HTTP_VERSION_2),   "HTTP/2.0"));
    assert(0 == strcmp(get_http_version_name(HTTP_VERSION_1_1), "HTTP/1.1"));
    assert(0 == strcmp(get_http_version_name(HTTP_VERSION_1_0), "HTTP/1.0"));

    /* TODO (more) */
}

void test_http_kv (void);
void test_http_kv (void)
{
    test_http_kv_tables();
}
