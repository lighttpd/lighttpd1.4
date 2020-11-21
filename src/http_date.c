/*
 * http_date - HTTP date manipulation
 *
 * Copyright(c) 2015 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "http_date.h"

#include "sys-time.h"

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


#if defined(__CYGWIN__) && defined(__STRICT_ANSI__)
/* (prototype for strptime() from cygwin /usr/include/time.h) */
char      *_EXFUN(strptime,     (const char *__restrict,
                                 const char *__restrict,
                                 struct tm *__restrict));
#endif


static char *
http_date_str_to_tm (const char * const s, struct tm * const tm)
{
    /* attempt strptime() using multiple date formats
     * support RFC 822,1123; RFC 850; and ANSI C asctime() date strings,
     * as required by [RFC7231] https://tools.ietf.org/html/rfc7231#section-7.1
     * [RFC7231] 7.1.1.1 Date/Time Formats
     *   HTTP-date = IMF-fixdate / obs-date
     *   [...]
     *   A recipient that parses a timestamp value in an HTTP header field
     *   MUST accept all three HTTP-date formats.
     */

    static const char *datefmts[] = {
      "%a, %d %b %Y %T GMT", /* RFC 822, RFC 1123; RFC 7231 IMF-fixdate */
      "%A, %d-%b-%y %T GMT", /* RFC 850 */
      "%a %b %d %T %Y"       /* ANSI C asctime() (obsolete in POSIX.1-2008) */
    };

    char *p;
    int i = 0;
    do {
        p = strptime(s, datefmts[i], tm);
    } while (__builtin_expect( (NULL == p), 0)
             && ++i < (int)(sizeof(datefmts)/sizeof(char *)));
    return p;  /* NULL if error; date string could not be parsed */
}


size_t
http_date_time_to_str (char * const s, const size_t max, const time_t t)
{
    /*('max' is expected to be >= 30 (IMF-fixdate is 29 chars + '\0'))*/
    struct tm tm;
    return (__builtin_expect( (NULL != gmtime_r(&t, &tm)), 1))
      ? strftime(s, max, "%a, %d %b %Y %T GMT", &tm) /* IMF-fixdate format */
      : 0;
}


#ifdef HAVE_TIMEGM
#define http_date_timegm(tm) timegm(tm)
#else
#ifdef _WIN32
#define http_date_timegm(tm) _mkgmtime(tm)
#else
/* If OS missing timegm(), then for best portability it is recommended to set
 *   $ export LC_TIME=C TZ=UTC0
 *
 * tm->tm_isdst = 0 for mktime() to indicate daylight saving time not in effect
 * which is fine since two strings should be GMT dates, and both are converted
 * with mktime() and then the results compared */
#define http_date_timegm(tm) ((tm)->tm_isdst = 0, mktime(tm))
#endif
#endif


int
http_date_if_modified_since (const char * const ifmod,
                             const char * const lmod, time_t lmtime)
{
    /* if caller provides non-zero lmtime, it must match Last-Modified lmod,
     * and will typically be same arg given to http_response_set_last_modified()
     * (small opt to elide one strptime(),timegm() call)
     * (In absense of timegm(), substitute mktime(), which works reasonably well
     *  since mktime() strings are used for comparison of If-Modified-Since)
     * (use mktime() to convert both strings for compare) */
    struct tm ifmodtm;
    if (NULL == http_date_str_to_tm(ifmod, &ifmodtm))
        return 1; /* date parse error */
  #if defined(HAVE_TIMEGM) || defined(_WIN32)
    if (0 == lmtime)
  #endif
    {
        struct tm lmodtm;
        if (NULL == http_date_str_to_tm(lmod, &lmodtm))
            return 1; /* date parse error */
        lmtime = http_date_timegm(&lmodtm);
    }
    const time_t ifmtime = http_date_timegm(&ifmodtm);
    return (lmtime > ifmtime);
    /* returns 0 if not modified since,
     * returns 1 if modified since or date parse error */
}
