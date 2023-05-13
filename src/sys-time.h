/*
 * sys-time.h - time.h wrapper for localtime_r() and gmtime_r()
 *
 * Copyright(c) 2015 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef LI_SYS_TIME_H
#define LI_SYS_TIME_H
#include "first.h"

#include <sys/types.h>
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
#ifdef _WIN32
#define localtime_r(timep,result) (localtime_s((result),(timep)),     (result))
#else
#define localtime_r(timep,result) ((*(result) = *(localtime(timep))), (result))
#endif
#endif
#ifndef HAVE_GMTIME_R
#ifdef _WIN32
#define gmtime_r(timep,result)    (gmtime_s((result),(timep)),        (result))
#else
#define gmtime_r(timep,result)    ((*(result) = *(gmtime(timep))),    (result))
#endif
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


/* non-standard functions created for lighttpd for Y2038 problem
 * reference: https://en.wikipedia.org/wiki/Year_2038_problem
 *
 * lighttpd does not expect to deal with dates earlier than 1970,
 * and can therefore treat dates earlier than 1970 as having overflowed
 * 32-bit signed time_t, signifying dates after Tue, 19 Jan 2038 03:14:07 GMT
 *
 * 1954, 1982, 2010, 2038 begin on Thu and are two years offset from leap year.
 * Attempt to adjust a timestamp > INT32_MAX back to a similar year, starting on
 * same weekday, and being same distance from next leap year; use gmtime_r()
 * or localtime_r(); and then adjust tm.tm_year back to the year of the original
 * timestamp.  (Note that the calculations here are valid for the specific range
 * of input timestamps mapped to 1970 and 2099.  The year 2000 was a leap year,
 * so crossing 2000 *does not* require special-casing here, but the year 2100
 * *is not* a leap year in the Gregorian calendar, so this code is not valid
 * after 28 Feb 2100.  Since the max validity of these kludges could only be
 * until 7 Feb 2106, this code has chosen not to special-case 2100-2106 and
 * produces incorrect results after 28 Feb 2100.)
 */
#if HAS_TIME_BITS64

#define gmtime64_r(timep,result)    gmtime_r((timep),(result))
#define localtime64_r(timep,result) localtime_r((timep),(result))

#else  /* !HAS_TIME_BITS64 */

#define gmtime64_r(timep,result)    gmtime_y2038_kludge32(*(timep),(result))
#define localtime64_r(timep,result) localtime_y2038_kludge32(*(timep),(result))

static inline struct tm *
gmtime_y2038_kludge32 (unix_time64_t t, struct tm *result);
static inline struct tm *
gmtime_y2038_kludge32 (unix_time64_t t, struct tm *result)
{
    if ((uint64_t)t <= INT32_MAX) {
        time_t tt = (time_t)t;
        return gmtime_r(&tt, result);
    }
    else {
        /*(treat negative time as having overflowed 32-bit time_t)*/
        if (t < 0)
            t = TIME64_CAST(t);
        time_t tt = (time_t)(t - 2650838400LL);
        if (gmtime_r(&tt, result)) {
            result->tm_year += 84;
            return result;
        }
        else if (t < 3914709247LL) {
            /*(ok through Tue, 19 Jan 2094 03:14:07 GMT)*/
            tt = (time_t)(t - 1767225600LL);
            if (gmtime_r(&tt, result)) {
                result->tm_year += 56;
                return result;
            }
        }

        /*(choose to forever return gmtime_r() equivalent of
         * Thu, 01 Jan 1970 00:00:00 GMT)
         *(returning NULL not expected by lighttpd and might crash)*/
        tt = 0;
        return gmtime_r(&tt, result);
    }
}

static inline struct tm *
localtime_y2038_kludge32 (unix_time64_t t, struct tm *result);
static inline struct tm *
localtime_y2038_kludge32 (unix_time64_t t, struct tm *result)
{
    if ((uint64_t)t <= INT32_MAX) {
        time_t tt = (time_t)t;
        return localtime_r(&tt, result);
    }
    else {
        /*(treat negative time as having overflowed 32-bit time_t)*/
        if (t < 0)
            t = TIME64_CAST(t);
        time_t tt = (time_t)(t - 2650838400LL);
        if (localtime_r(&tt, result)) {
            result->tm_year += 84;
            return result;
        }
        else if (t < 3914709247LL) {
            /*(ok through Tue, 19 Jan 2094 03:14:07 GMT)*/
            tt = (time_t)(t - 1767225600LL);
            if (localtime_r(&tt, result)) {
                result->tm_year += 56;
                return result;
            }
        }

        /*(choose to forever return localtime_r() equivalent of
         * Thu, 01 Jan 1970 00:00:00 GMT)
         *(returning NULL not expected by lighttpd and might crash)*/
        tt = 0;
        return localtime_r(&tt, result);
    }
}

#endif /* !HAS_TIME_BITS64 */


#endif
