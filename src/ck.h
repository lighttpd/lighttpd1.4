/*
 * ck - C11 Annex K wrappers  (selected functions; not complete)
 *
 * ck is also an abbreviation for "check".
 * These are validating, checking functions.
 *
 * Copyright(c) 2016,2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_CK_H
#define INCLUDED_CK_H
#ifndef __STDC_WANT_LIB_EXT1__ /*(enable C11 Annex K ext1 *_s functions)*/
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#if defined(__APPLE__) && defined(__MACH__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif
#include "first.h"
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__sun)
#ifndef _RSIZE_T_DEFINED /* expecting __EXT1_VISIBLE 1 and _RSIZE_T_DEFINED */
#define _RSIZE_T_DEFINED
typedef size_t rsize_t;
#endif
#include <errno.h>
#if defined(__DragonFly__)
typedef int errno_t;
#endif
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

/*(ck_memeq_const_time() is not from C11 Annex K)
 * constant time memory compare for equality
 * rounds to next multiple of 64 to avoid potentially leaking exact
 * string lengths when subject to high precision timing attacks */
__attribute_nonnull__()
int ck_memeq_const_time (const void *a, size_t alen, const void *b, size_t blen);

/*(ck_memeq_const_time_fixed_len() is not from C11 Annex K)
 * constant time memory compare for equality for fixed len (e.g. digests)
 * (padding not necessary for digests, which have fixed, defined lengths) */
__attribute_nonnull__()
int ck_memeq_const_time_fixed_len (const void *a, const void *b, size_t len);


/*(ck_malloc() is not from C11 Annex K)
 * ck_malloc() performs malloc() on args and aborts if malloc() fails */
__attribute_malloc__
__attribute_returns_nonnull__
void * ck_malloc (size_t nbytes);

/*(ck_calloc() is not from C11 Annex K)
 * ck_calloc() performs calloc() on args and aborts if calloc() fails */
__attribute_malloc__
__attribute_returns_nonnull__
void * ck_calloc (size_t nmemb, size_t elt_sz);

/*(ck_realloc_u32() is not from C11 Annex K)
 * ck_realloc_u32() performs realloc() on *list or aborts
 * extends *list with n used elements by x elements of elt_sz
 * and ensures n + x <= UINT32_MAX */
__attribute_nonnull__()
__attribute_returns_nonnull__
void * ck_realloc_u32 (void **list, size_t n, size_t x, size_t elt_sz);


/*(ck_bt() is not from C11 Annex K)
 * ck_bt() prints backtrace to stderr */
__attribute_cold__
__attribute_nonnull__()
void ck_bt(const char *filename, unsigned int line, const char *msg);

/*(ck_bt_abort() is not from C11 Annex K)
 * ck_bt_abort() prints backtrace to stderr and calls abort() */
__attribute_cold__
__attribute_nonnull__()
__attribute_noreturn__
void ck_bt_abort(const char *filename, unsigned int line, const char *msg);

/*(ck_assert() and ck_assert_failed() are not from C11 Annex K)
 * ck_assert() executes a runtime assertion test or aborts
 * ck_assert() *is not* optimized away if defined(NDEBUG)
 * (unlike standard assert(), which *is* optimized away if defined(NDEBUG)) */
__attribute_cold__
__attribute_nonnull__()
__attribute_noreturn__
void ck_assert_failed(const char *filename, unsigned int line, const char *msg);

#define ck_assert(x) \
        do { if (!(x)) ck_assert_failed(__FILE__, __LINE__, #x); } while (0)


__END_DECLS


#include <assert.h>     /* C11 static_assert() and _Static_assert() */
#ifndef static_assert
#define static_assert(x,str) ck_assert(x)
#endif
#define ck_static_assert(x) static_assert((x),#x)


#endif
