#include "first.h"

#undef NDEBUG
#include <assert.h>

#include "mod_expire.c"

static void test_mod_expire_get_offset_check(void) {
    const char *str;
    time_t mod;

    str = "";
    assert(-1 == mod_expire_get_offset(str, &mod));
    str = "foo plus 0";
    assert(-1 == mod_expire_get_offset(str, &mod));
    str = "access plus 0";
    assert(-1 == mod_expire_get_offset(str, &mod));

    str = "access 0 sec";
    assert(0 == mod_expire_get_offset(str, &mod));
    str = "now 0 sec";
    assert(0 == mod_expire_get_offset(str, &mod));
    str = "modification 0 sec";
    assert(0 == mod_expire_get_offset(str, &mod));

    str = "access 0sec";
    assert(0 == mod_expire_get_offset(str, &mod));
    str = "now 0sec";
    assert(0 == mod_expire_get_offset(str, &mod));
    str = "modification 0sec";
    assert(0 == mod_expire_get_offset(str, &mod));

    str = "access plus 0 sec";
    assert(0 == mod_expire_get_offset(str, &mod));
    str = "now plus 0 sec";
    assert(0 == mod_expire_get_offset(str, &mod));
    str = "modification plus 0 sec";
    assert(0 == mod_expire_get_offset(str, &mod));

    str = "access 1 sec";
    assert(1 == mod_expire_get_offset(str, &mod));
    str = "access 1 secs";
    assert(1 == mod_expire_get_offset(str, &mod));
    str = "access 1 second";
    assert(1 == mod_expire_get_offset(str, &mod));
    str = "access 1 seconds";
    assert(1 == mod_expire_get_offset(str, &mod));
    str = "access 1 min";
    assert(60 == mod_expire_get_offset(str, &mod));
    str = "access 1 mins";
    assert(60 == mod_expire_get_offset(str, &mod));
    str = "access 1 minute";
    assert(60 == mod_expire_get_offset(str, &mod));
    str = "access 1 minutes";
    assert(60 == mod_expire_get_offset(str, &mod));
    str = "access 1 hour";
    assert(60*60 == mod_expire_get_offset(str, &mod));
    str = "access 1 hours";
    assert(60*60 == mod_expire_get_offset(str, &mod));
    str = "access 1 day";
    assert(60*60*24 == mod_expire_get_offset(str, &mod));
    str = "access 1 days";
    assert(60*60*24 == mod_expire_get_offset(str, &mod));
    str = "access 1 week";
    assert(60*60*24*7 == mod_expire_get_offset(str, &mod));
    str = "access 1 weeks";
    assert(60*60*24*7 == mod_expire_get_offset(str, &mod));
    str = "access 1 month";
    assert(60*60*24*30 == mod_expire_get_offset(str, &mod));
    str = "access 1 months";
    assert(60*60*24*30 == mod_expire_get_offset(str, &mod));
    str = "access 1 year";
    assert(60*60*24*365 == mod_expire_get_offset(str, &mod));
    str = "access 1 years";
    assert(60*60*24*365 == mod_expire_get_offset(str, &mod));

    str = "access 2 sec";
    assert(2 == mod_expire_get_offset(str, &mod));
    str = "access 2 secs";
    assert(2 == mod_expire_get_offset(str, &mod));
    str = "access 2 second";
    assert(2 == mod_expire_get_offset(str, &mod));
    str = "access 2 seconds";
    assert(2 == mod_expire_get_offset(str, &mod));
    str = "access 2 min";
    assert(2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 mins";
    assert(2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 minute";
    assert(2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 minutes";
    assert(2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 hour";
    assert(2*60*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 hours";
    assert(2*60*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 day";
    assert(2*60*60*24 == mod_expire_get_offset(str, &mod));
    str = "access 2 days";
    assert(2*60*60*24 == mod_expire_get_offset(str, &mod));
    str = "access 2 week";
    assert(2*60*60*24*7 == mod_expire_get_offset(str, &mod));
    str = "access 2 weeks";
    assert(2*60*60*24*7 == mod_expire_get_offset(str, &mod));
    str = "access 2 month";
    assert(2*60*60*24*30 == mod_expire_get_offset(str, &mod));
    str = "access 2 months";
    assert(2*60*60*24*30 == mod_expire_get_offset(str, &mod));
    str = "access 2 year";
    assert(2*60*60*24*365 == mod_expire_get_offset(str, &mod));
    str = "access 2 years";
    assert(2*60*60*24*365 == mod_expire_get_offset(str, &mod));

    str = "access 2 min 1 sec";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 mins 1 sec";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 minute 1 sec";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 minutes 1 sec";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 hour 1 sec";
    assert(1+2*60*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 hours 1 sec";
    assert(1+2*60*60 == mod_expire_get_offset(str, &mod));
    str = "access 2 day 1 sec";
    assert(1+2*60*60*24 == mod_expire_get_offset(str, &mod));
    str = "access 2 days 1 sec";
    assert(1+2*60*60*24 == mod_expire_get_offset(str, &mod));
    str = "access 2 week 1 sec";
    assert(1+2*60*60*24*7 == mod_expire_get_offset(str, &mod));
    str = "access 2 weeks 1 sec";
    assert(1+2*60*60*24*7 == mod_expire_get_offset(str, &mod));
    str = "access 2 month 1 sec";
    assert(1+2*60*60*24*30 == mod_expire_get_offset(str, &mod));
    str = "access 2 months 1 sec";
    assert(1+2*60*60*24*30 == mod_expire_get_offset(str, &mod));
    str = "access 2 year 1 sec";
    assert(1+2*60*60*24*365 == mod_expire_get_offset(str, &mod));
    str = "access 2 years 1 sec";
    assert(1+2*60*60*24*365 == mod_expire_get_offset(str, &mod));

    str = "access 2  min  1  sec";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2min1sec";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
    str = "access 2min1sec      ";
    assert(1+2*60 == mod_expire_get_offset(str, &mod));
}

#include "response.h"   /* http_response_reset() */

static void test_mod_expire_set_header_check(void) {
    request_st r;
    memset(&r, 0, sizeof(request_st));
    time_t off[2] = { 0, 0 };

    r.http_version = HTTP_VERSION_1_0;
    http_response_reset(&r);
    mod_expire_set_header(&r, off);
    assert(light_btst(r.resp_htags, HTTP_HEADER_EXPIRES));

    r.http_version = HTTP_VERSION_1_1;
    http_response_reset(&r);
    mod_expire_set_header(&r, off);
    assert(light_btst(r.resp_htags, HTTP_HEADER_CACHE_CONTROL));

    http_response_reset(&r);
    array_free_data(&r.resp_headers);
}

void test_mod_expire (void);
void test_mod_expire (void)
{
    test_mod_expire_get_offset_check();
    test_mod_expire_set_header_check();
}
