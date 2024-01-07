#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "http_header.c"

static void test_http_header_tables (void) {
    /* verify enum http_header_e presence in http_headers[] */
    unsigned int u;
    for (int i = 0; i < 64; ++i) {
        /* Note: must be kept in sync http_headers[] and http_headers_off[] */
        /* Note: must be kept in sync with http_header.h enum http_header_e */
        /* Note: must be kept in sync with http_header.c http_headers[] */
        /* Note: must be kept in sync h2.c:http_header_lc[] */
        /* Note: must be kept in sync h2.c:http_header_lshpack_idx[] */
        /* Note: must be kept in sync h2.c:lshpack_idx_http_header[] */
        /* switch() statement with each entry in enum http_header_e;
         * no 'default' case to trigger warning if entry is added */
        enum http_header_e x = (enum http_header_e)i;
        switch (x) {
          case HTTP_HEADER_OTHER:
          case HTTP_HEADER_ACCEPT:
          case HTTP_HEADER_ACCEPT_ENCODING:
          case HTTP_HEADER_ACCEPT_LANGUAGE:
          case HTTP_HEADER_ACCEPT_RANGES:
          case HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN:
          case HTTP_HEADER_AGE:
          case HTTP_HEADER_ALLOW:
          case HTTP_HEADER_ALT_SVC:
          case HTTP_HEADER_ALT_USED:
          case HTTP_HEADER_AUTHORIZATION:
          case HTTP_HEADER_CACHE_CONTROL:
          case HTTP_HEADER_CONNECTION:
          case HTTP_HEADER_CONTENT_ENCODING:
          case HTTP_HEADER_CONTENT_LENGTH:
          case HTTP_HEADER_CONTENT_LOCATION:
          case HTTP_HEADER_CONTENT_RANGE:
          case HTTP_HEADER_CONTENT_SECURITY_POLICY:
          case HTTP_HEADER_CONTENT_TYPE:
          case HTTP_HEADER_COOKIE:
          case HTTP_HEADER_DATE:
          case HTTP_HEADER_DNT:
          case HTTP_HEADER_ETAG:
          case HTTP_HEADER_EXPECT:
          case HTTP_HEADER_EXPECT_CT:
          case HTTP_HEADER_EXPIRES:
          case HTTP_HEADER_FORWARDED:
          case HTTP_HEADER_HOST:
          case HTTP_HEADER_HTTP2_SETTINGS:
          case HTTP_HEADER_IF_MATCH:
          case HTTP_HEADER_IF_MODIFIED_SINCE:
          case HTTP_HEADER_IF_NONE_MATCH:
          case HTTP_HEADER_IF_RANGE:
          case HTTP_HEADER_IF_UNMODIFIED_SINCE:
          case HTTP_HEADER_LAST_MODIFIED:
          case HTTP_HEADER_LINK:
          case HTTP_HEADER_LOCATION:
          case HTTP_HEADER_ONION_LOCATION:
          case HTTP_HEADER_P3P:
          case HTTP_HEADER_PRAGMA:
          case HTTP_HEADER_PRIORITY:
          case HTTP_HEADER_RANGE:
          case HTTP_HEADER_REFERER:
          case HTTP_HEADER_REFERRER_POLICY:
          case HTTP_HEADER_SERVER:
          case HTTP_HEADER_SET_COOKIE:
          case HTTP_HEADER_STATUS:
          case HTTP_HEADER_STRICT_TRANSPORT_SECURITY:
          case HTTP_HEADER_TE:
          case HTTP_HEADER_TRANSFER_ENCODING:
          case HTTP_HEADER_UPGRADE:
          case HTTP_HEADER_UPGRADE_INSECURE_REQUESTS:
          case HTTP_HEADER_USER_AGENT:
          case HTTP_HEADER_VARY:
          case HTTP_HEADER_WWW_AUTHENTICATE:
          case HTTP_HEADER_X_CONTENT_TYPE_OPTIONS:
          case HTTP_HEADER_X_FORWARDED_FOR:
          case HTTP_HEADER_X_FORWARDED_PROTO:
          case HTTP_HEADER_X_FRAME_OPTIONS:
          case HTTP_HEADER_X_XSS_PROTECTION:
            for (u = 0; u < sizeof(http_headers)/sizeof(*http_headers); ++u) {
                if (i == http_headers[u].key) {
                    assert(x == http_header_hkey_get(http_headers[u].value,
                                                     http_headers[u].vlen));
                    assert(x == http_header_hkey_get_lc(http_headers[u].value,
                                                        http_headers[u].vlen));
                    break;
                }
            }
            assert(u < sizeof(http_headers)/sizeof(*http_headers));
            break;
        }
    }

    /* verify http_headers_off[] */
    for (u = 0; u < sizeof(http_headers)/sizeof(*http_headers); ++u) {
        if (http_headers[u].vlen == 0) break;
        int8_t x = http_headers_off[http_headers[u].vlen];
        assert((unsigned int)x <= u);
        assert(http_headers[(uint8_t)x].vlen == http_headers[u].vlen);
    }
}

void test_http_header (void);
void test_http_header (void)
{
    test_http_header_tables();
}
