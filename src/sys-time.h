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

#endif
