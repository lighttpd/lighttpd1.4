/*
 * sys-time.h - time.h wrapper for localtime_r() and gmtime_r()
 *
 * Copyright(c) 2015 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_SYS_TIME_H
#define INCLUDED_SYS_TIME_H
#include "first.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>/* gettimeofday() */
#endif
#include <time.h>    /* time() localtime_r() gmtime_r() strftime() */

/*(provide rudimentary localtime_r() and gmtime_r() for platforms lacking)
 *(Note that 'result' preprocessor arg is repeated, so callers should avoid
 * side-effects.  Also note that there is still a race condition before the
 * result of localtime()/gmtime() is copied.  In any case, this exists here
 * so that the rest of the code can use localtime_r() and gmtime_r() syntax.
 * Platforms requiring thread-safety and lacking localtime_r() or gmtime_r()
 * could turn these into subroutines which take a local mutex to protect the
 * calls to localtime() or gmtime()) */
#ifndef HAVE_LOCALTIME_R
#define localtime_r(timep,result) ((*(result) = *(localtime(timep))), (result))
#endif
#ifndef HAVE_GMTIME_R
#define gmtime_r(timep,result)    ((*(result) = *(gmtime(timep))),    (result))
#endif

#ifndef HAVE_TIMEGM
#ifdef _WIN32
#define timegm(tm) _mkgmtime(tm)
#else
__attribute_pure__
static inline time_t
timegm (const struct tm * const tm);
static inline time_t
timegm (const struct tm * const tm)
{
    int y = tm->tm_year + 1900;
    int m = tm->tm_mon + 1;
    int d = tm->tm_mday;

    /* days_from_civil() http://howardhinnant.github.io/date_algorithms.html */
    y -= m <= 2;
    int era = y / 400;
    int yoe = y - era * 400;                                   // [0, 399]
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;  // [0, 365]
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           // [0, 146096]
    int days_since_1970 = era * 146097 + doe - 719468;

    return 60*(60*(24L*days_since_1970+tm->tm_hour)+tm->tm_min)+tm->tm_sec;
}
#endif
#endif

#endif
