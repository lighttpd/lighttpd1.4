/*
 * ck - C11 Annex K wrappers  (selected functions; not complete)
 *
 * ck is also an abbreviation for "check".
 * These are validating, checking functions.
 *
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_CK_H
#define INCLUDED_CK_H
#ifndef __STDC_WANT_LIB_EXT1__ /*(enable C11 Annex K ext1 *_s functions)*/
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include "first.h"
#ifdef __FreeBSD__
#include <errno.h>
#endif

__BEGIN_DECLS


#ifndef RSIZE_MAX
#define RSIZE_MAX (SIZE_MAX >> 1)
typedef size_t rsize_t;
typedef int errno_t;
#endif


errno_t ck_getenv_s (size_t * restrict len, char * restrict value, rsize_t maxsize, const char * restrict name);

/*(ck_memclear_s() is not from C11 Annex K
 * ck_memclear_s() is similar to memset_s() using constant byte 0 for fill)*/
errno_t ck_memclear_s (void *s, rsize_t smax, rsize_t n);

/*(ck_memzero() is not from C11 Annex K
 * ck_memzero() is a convenience wrapper around ck_memclear_s())*/
static inline errno_t ck_memzero(void *s, rsize_t n);
static inline errno_t ck_memzero(void *s, rsize_t n) {
    return ck_memclear_s(s, n, n);
}

errno_t ck_strerror_s (char *s, rsize_t maxsize, errno_t errnum);


__END_DECLS


#endif
