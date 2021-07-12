/*
 * http_date - HTTP date manipulation
 *
 * Copyright(c) 2015 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "http_date.h"

#include "sys-time.h"
#include <string.h>     /* strlen() */

#include "buffer.h"     /* light_isdigit() */
#include "log.h"        /* log_epoch_secs */

/**
 * https://tools.ietf.org/html/rfc7231
 * [RFC7231] 7.1.1.1 Date/Time Formats
 *   Prior to 1995, there were three different formats commonly used by
 *   servers to communicate timestamps.  For compatibility with old
 *   implementations, all three are defined here.  The preferred format is
 *   a fixed-length and single-zone subset of the date and time
 *   specification used by the Internet Message Format [RFC5322].
 *     HTTP-date    = IMF-fixdate / obs-date
 *   An example of the preferred format is
 *     Sun, 06 Nov 1994 08:49:37 GMT    ; IMF-fixdate
 *
 *
 * (intended for use with strftime() and strptime())
 *   "%a, %d %b %Y %T GMT"
 */


static const char datestrs[] =
  /*0  10  20  30  40  50  60  70  80  90*/
  "\0\x0A\x14\x1E\x28\x32\x3c\x46\x50\x5A"
  "SunMonTueWedThuFriSat"
  "JanFebMarAprMayJunJulAugSepOctNovDec";


__attribute_cold__
static const char *
http_date_parse_RFC_850 (const char *s, struct tm * const tm)
{
    /* RFC 7231 7.1.1.1.
     *   Recipients of a timestamp value in rfc850-date format, which uses a
     *   two-digit year, MUST interpret a timestamp that appears to be more
     *   than 50 years in the future as representing the most recent year in
     *   the past that had the same last two digits.
     */
    static unix_time64_t tm_year_last_check;
    static int tm_year_cur;
    static int tm_year_base;
    /* (log_epoch_secs is a global variable, maintained elsewhere) */
    /* (optimization: check for year change no more than once per min) */
    if (log_epoch_secs >= tm_year_last_check + 60) {
        struct tm tm_cur;
        if (NULL != gmtime64_r(&log_epoch_secs, &tm_cur)) {
            tm_year_last_check = log_epoch_secs;
            if (tm_cur.tm_year != tm_year_cur) {
                tm_year_cur = tm_cur.tm_year;
                tm_year_base = tm_year_cur - (tm_year_cur % 100);
            }
        }
    }

    /* Note: does not validate numerical ranges of
     *       tm_mday, tm_hour, tm_min, tm_sec */
    /* Note: does not validate tm_wday beyond first three chars */

    tm->tm_isdst = 0;
    tm->tm_yday = 0;
    tm->tm_wday = 0;
    tm->tm_mon = 0;

    const char * const tens = datestrs;

    const char *p = tens + 10;
    do {
        if (s[0] == p[0] && s[1] == p[1] && s[2] == p[2]) break;
        p += 3;
    } while (++tm->tm_wday < 7);
    if (7 == tm->tm_wday) return NULL;

    s += 3;
    while (*s != ',' && *s != '\0') ++s;

    if (s[0] != ',' || s[1] != ' '
        || !light_isdigit(s[2]) || !light_isdigit(s[3]))
        return NULL;
    tm->tm_mday = tens[(s[2]-'0')] + (s[3]-'0');

    if ( s[4] != '-') return NULL;
    p = tens + 10 + sizeof("SunMonTueWedThuFriSat")-1;
    do {
        if (s[5] == p[0] && s[6] == p[1] && s[7] == p[2]) break;
        p += 3;
    } while (++tm->tm_mon < 12);
    if (12 == tm->tm_mon) return NULL;

    if (s[8] != '-' || !light_isdigit(s[9]) || !light_isdigit(s[10]))
        return NULL;
    tm->tm_year = tens[(s[9]-'0')] + (s[10]-'0') + tm_year_base;
    if (tm->tm_year > tm_year_cur + 50) tm->tm_year -= 100;

    if (s[11] != ' ' || !light_isdigit(s[12]) || !light_isdigit(s[13]))
        return NULL;
    tm->tm_hour = tens[(s[12]-'0')] + (s[13]-'0');

    if (s[14] != ':' || !light_isdigit(s[15]) || !light_isdigit(s[16]))
        return NULL;
    tm->tm_min  = tens[(s[15]-'0')] + (s[16]-'0');

    if (s[17] != ':' || !light_isdigit(s[18]) || !light_isdigit(s[19]))
        return NULL;
    tm->tm_sec  = tens[(s[18]-'0')] + (s[19]-'0');

    if (s[20] != ' ' || s[21] != 'G' || s[22] != 'M' || s[23] != 'T')
        return NULL;

    return s+24; /*(24 chars from ',' following the variable len wday)*/
}


__attribute_cold__
static const char *
http_date_parse_asctime (const char * const s, struct tm * const tm)
{
    /* Note: does not validate numerical ranges of
     *       tm_mday, tm_hour, tm_min, tm_sec */

    tm->tm_isdst = 0;
    tm->tm_yday = 0;
    tm->tm_wday = 0;
    tm->tm_mon = 0;

    const char * const tens = datestrs;

    const char *p = tens + 10;
    do {
        if (s[0] == p[0] && s[1] == p[1] && s[2] == p[2]) break;
        p += 3;
    } while (++tm->tm_wday < 7);
    if (7 == tm->tm_wday) return NULL;

    if (s[3] != ' ') return NULL;
    p = tens + 10 + sizeof("SunMonTueWedThuFriSat")-1;
    do {
        if (s[4] == p[0] && s[5] == p[1] && s[6] == p[2]) break;
        p += 3;
    } while (++tm->tm_mon < 12);
    if (12 == tm->tm_mon) return NULL;

    if (s[7] != ' ' || (s[8] != ' ' && !light_isdigit(s[8]))
        || !light_isdigit(s[9]))
        return NULL;
    tm->tm_mday = (s[8] == ' ' ? 0 : tens[(s[8]-'0')]) + (s[9]-'0');

    if (s[10] != ' ' || !light_isdigit(s[11]) || !light_isdigit(s[12]))
        return NULL;
    tm->tm_hour = tens[(s[11]-'0')] + (s[12]-'0');

    if (s[13] != ':' || !light_isdigit(s[14]) || !light_isdigit(s[15]))
        return NULL;
    tm->tm_min  = tens[(s[14]-'0')] + (s[15]-'0');

    if (s[16] != ':' || !light_isdigit(s[17]) || !light_isdigit(s[18]))
        return NULL;
    tm->tm_sec  = tens[(s[17]-'0')] + (s[18]-'0');

    if (s[19] != ' ' || !light_isdigit(s[20]) || !light_isdigit(s[21])
        || !light_isdigit(s[22]) || !light_isdigit(s[23])) return NULL;
    tm->tm_year =(tens[(s[20]-'0')] + (s[21]-'0'))*100
                + tens[(s[22]-'0')] + (s[23]-'0') - 1900;

    return s+24;
}


static const char *
http_date_parse_IMF_fixdate (const char * const s, struct tm * const tm)
{
    /* Note: does not validate numerical ranges of
     *       tm_mday, tm_hour, tm_min, tm_sec */

    tm->tm_isdst = 0;
    tm->tm_yday = 0;
    tm->tm_wday = 0;
    tm->tm_mon = 0;

    const char * const tens = datestrs;

    const char *p = tens + 10;
    do {
        if (s[0] == p[0] && s[1] == p[1] && s[2] == p[2]) break;
        p += 3;
    } while (++tm->tm_wday < 7);
    if (7 == tm->tm_wday) return NULL;

    if (s[3] != ',' || s[4] != ' '
        || !light_isdigit(s[5]) || !light_isdigit(s[6]))
        return NULL;
    tm->tm_mday = tens[(s[5]-'0')] + (s[6]-'0');

    if ( s[7] != ' ') return NULL;
    p = tens + 10 + sizeof("SunMonTueWedThuFriSat")-1;
    do {
        if (s[8] == p[0] && s[9] == p[1] && s[10] == p[2]) break;
        p += 3;
    } while (++tm->tm_mon < 12);
    if (12 == tm->tm_mon) return NULL;

    if (s[11] != ' ' || !light_isdigit(s[12]) || !light_isdigit(s[13])
        || !light_isdigit(s[14]) || !light_isdigit(s[15])) return NULL;
    tm->tm_year =(tens[(s[12]-'0')] + (s[13]-'0'))*100
                + tens[(s[14]-'0')] + (s[15]-'0') - 1900;

    if (s[16] != ' ' || !light_isdigit(s[17]) || !light_isdigit(s[18]))
        return NULL;
    tm->tm_hour = tens[(s[17]-'0')] + (s[18]-'0');

    if (s[19] != ':' || !light_isdigit(s[20]) || !light_isdigit(s[21]))
        return NULL;
    tm->tm_min  = tens[(s[20]-'0')] + (s[21]-'0');

    if (s[22] != ':' || !light_isdigit(s[23]) || !light_isdigit(s[24]))
        return NULL;
    tm->tm_sec  = tens[(s[23]-'0')] + (s[24]-'0');

    if (s[25] != ' ' || s[26] != 'G' || s[27] != 'M' || s[28] != 'T')
        return NULL;

    return s+29;
}


static const char *
http_date_str_to_tm (const char * const s, const uint32_t len,
                     struct tm * const tm)
{

    /* attempt strptime() using multiple date formats
     * support RFC 822,1123,7231; RFC 850; and ANSI C asctime() date strings,
     * as required by [RFC7231] https://tools.ietf.org/html/rfc7231#section-7.1
     * [RFC7231] 7.1.1.1 Date/Time Formats
     *   HTTP-date = IMF-fixdate / obs-date
     *   [...]
     *   A recipient that parses a timestamp value in an HTTP header field
     *   MUST accept all three HTTP-date formats.
     */

    /* employ specialized strptime()
     * - HTTP expected date formats are known, so not needed as input param
     * - HTTP expected date string content is in C locale and is case-sensitive
     * - returns (const char *) instead of strptime() (char *) return type
     * - returns NULL if error (if date string could not be parsed)
     * Note: internal implementation requires '\0'-terminated string, or at
     * least one valid char after partial match of RFC 850 or asctime formats */
    if (len == 29)
        return http_date_parse_IMF_fixdate(s, tm);
    else if (len > 29)
        return http_date_parse_RFC_850(s, tm);
    else /* len < 29 */
        return http_date_parse_asctime(s, tm);
}


uint32_t
http_date_time_to_str (char * const s, const size_t sz, const unix_time64_t t)
{
    /*('max' is expected to be >= 30 (IMF-fixdate is 29 chars + '\0'))*/
    struct tm tm;
    const char fmt[] = "%a, %d %b %Y %T GMT";       /*IMF-fixdate fmt*/
    return (__builtin_expect( (NULL != gmtime64_r(&t, &tm)), 1))
      ? (uint32_t)strftime(s, sz, fmt, &tm)
      : 0;
}


int
http_date_if_modified_since (const char * const ifmod, const uint32_t ifmodlen,
                             const unix_time64_t lmtime)
{
    struct tm ifmodtm;
    if (NULL == http_date_str_to_tm(ifmod, ifmodlen, &ifmodtm))
        return 1; /* date parse error */
    const time_t ifmtime = timegm(&ifmodtm);
  #if HAS_TIME_BITS64
    return (lmtime > ifmtime);
  #else
    return (TIME64_CAST(lmtime) > TIME64_CAST(ifmtime) || ifmtime==(time_t)-1);
  #endif
    /* returns 0 if not modified since,
     * returns 1 if modified since or date parse error */
}
