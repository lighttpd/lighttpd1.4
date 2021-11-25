/*
 * ck - C11 Annex K wrappers  (selected functions; not complete)
 *
 * ck is also an abbreviation for "check".
 * These are validating, checking functions.
 *
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _NETBSD_SOURCE
#define _NETBSD_SOURCE
#endif
#ifdef __OpenBSD__
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif
#include "first.h"

#include "ck.h"

#include <stdlib.h>     /* abort() getenv() getenv_s() */
#include <string.h>     /* memcpy() memset() memset_s() explicit_bzero()
                         * strerror() strerror_r() strerror_s() strlen() */

#ifdef __STDC_LIB_EXT1__
#ifndef HAVE_MEMSET_S
#define HAVE_MEMSET_S
#endif
#else
#include <errno.h>
#include <stdio.h>      /* snprintf() */
#endif

#ifndef HAVE_MEMSET_S

#ifdef _WIN32
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>    /* SecureZeroMemory() */
/*(Windows XP and later provide SecureZeroMemory())*/
#define HAVE_SECUREZEROMEMORY
#else /* !_WIN32 */
#ifdef HAVE_SIGNAL
#include <signal.h>     /* sig_atomic_t */
#else
typedef int sig_atomic_t;
#endif
/*#include <plasma/plasma_membar.h>*/  /* plasma_membar_ccfence() */
#endif

#endif /* !HAVE_MEMSET_S */


#if !defined(HAVE_MEMSET_S)        \
 && !defined(HAVE_EXPLICIT_BZERO)  \
 && !defined(HAVE_EXPLICIT_MEMSET) \
 && !defined(HAVE_SECUREZEROMEMORY)

typedef void *(*ck_memclear_func_t)(void *, int, size_t);
extern volatile ck_memclear_func_t ck_memclear_func;
volatile ck_memclear_func_t ck_memclear_func = memset;

#ifdef HAVE_WEAK_SYMBOLS
/* it seems weak functions are never inlined, even for static builds */
__attribute__((__weak__))
void ck_memclear_s_hook (void *buf, rsize_t len);
void ck_memclear_s_hook (void *buf    __attribute_unused__,
                         rsize_t len  __attribute_unused__)
{
    /*(application might define func to call OPENSSL_cleanse(), if available)*/
    (void)(buf); /* UNUSED */
    (void)(len); /* UNUSED */
}
#endif /* HAVE_WEAK_SYMBOLS */

static void *
ck_memset_compat(void *s, int c, size_t n)
{
    /* attempt to inhibit compiler/linker heuristics which might elide memset()
     * - insert compiler optimization fences around memset()
     * - access s through volatile pointer at volatile index after memset()
     * - pass s to weak (overridable) func to create additional data dependency
     */

    if (0 == n)    /*(must check n > 0 since s[0] will be accessed)*/
        return s;

    static volatile sig_atomic_t vzero;
    volatile unsigned char *vs = (volatile unsigned char *)s;
    do {
        /*plasma_membar_ccfence();*/
        ck_memclear_func(s, c, n);
        /*plasma_membar_ccfence();*/
    } while (vs[vzero] != c);

  #ifdef HAVE_WEAK_SYMBOLS
    ck_memclear_s_hook(s, n);
  #endif

    return s;
}

#endif


errno_t
ck_memclear_s (void * const s, const rsize_t smax, rsize_t n)
{
  #ifdef HAVE_MEMSET_S

    return memset_s(s, smax, 0, n);

  #else

    if (NULL == s)
        /* runtime constraint violation */
        return EINVAL;
    if (RSIZE_MAX < smax)
        /* runtime constraint violation */
        return E2BIG;

    errno_t rc = 0;
    if (RSIZE_MAX < n) {
        /* runtime constraint violation */
        rc = EINVAL;
        n = smax;
    }
    if (smax < n) {
        /* runtime constraint violation */
        rc = EOVERFLOW;
        n = smax;
    }

   #if defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(s, n);
   #elif defined(HAVE_EXPLICIT_MEMSET)
    explicit_memset(s, 0, n);
   #elif defined(HAVE_SECUREZEROMEMORY)
    SecureZeroMemory(s, n);
   #else
    ck_memset_compat(s, 0, n);
   #endif

    return rc;

  #endif
}


#if 0 /*(not currently used in lighttpd; lighttpd process env is stable)*/
errno_t
ck_getenv_s (size_t * const restrict len,
             char * const restrict value, const rsize_t maxsize,
             const char * const restrict name)
{
  #ifdef __STDC_LIB_EXT1__

    return getenv_s(len, value, maxsize, name);

  #else

    if (NULL == name || RSIZE_MAX < maxsize || (0 != maxsize && NULL == value)){
        /* runtime constraint violation */
        if (NULL != len)
            *len = 0;
        if (NULL != value && maxsize)
            *value = '\0';
        return EINVAL;
    }

    const char * const v = getenv(name);
    if (NULL != v) {
        const size_t vlen = strlen(v);
        if (NULL != len)
            *len = vlen;
        if (vlen < maxsize) {
            memcpy(value, v, vlen+1);
            return 0;
        }
        else {
            if (maxsize)
                *value = '\0';
            return ERANGE;
        }
    }
    else {
        if (NULL != len)
            *len = 0;
        if (maxsize)
            *value = '\0';
      #ifdef ENODATA
        return ENODATA;
      #else
        return ENOENT;
      #endif
    }

  #endif
}
#endif


errno_t
ck_strerror_s (char * const s, const rsize_t maxsize, const errno_t errnum)
{
  #ifdef __STDC_LIB_EXT1__

    return strerror_s(s, maxsize, errnum);

  #else

    if (NULL == s || 0 == maxsize || RSIZE_MAX < maxsize) {
        /* runtime constraint violation */
        return EINVAL;
    }

    /*(HAVE_STRERROR_R defined after tests by configure.ac or SConstruct)*/
  #if !defined(HAVE_STRERROR_R) && !defined(HAVE_CONFIG_H)
  #define HAVE_STRERROR_R 1
  #endif /*(assume strerror_r() available if no config.h)*/

  #ifdef HAVE_STRERROR_R
    char buf[1024];
   #if defined(_GNU_SOURCE) && defined(__GLIBC__)
    const char *errstr = strerror_r(errnum,buf,sizeof(buf));
   #else /* XSI-compliant strerror_r() */
    const char *errstr = (0 == strerror_r(errnum,buf,sizeof(buf))) ? buf : NULL;
   #endif
  #else /* !HAVE_STRERROR_R */
    const char *errstr = strerror(errnum);
  #endif
    if (NULL != errstr) {
        const size_t errlen = strlen(errstr);
        if (errlen < maxsize) {
            memcpy(s, errstr, errlen+1);
            return 0;
        }
        else {
            memcpy(s, errstr, maxsize-1);
            s[maxsize-1] = '\0';
            /*(fall through; not enough space to store entire error string)*/
        }
    }
    else {
        if ((rsize_t)snprintf(s, maxsize, "Unknown error %d", errnum) < maxsize)
            return 0;
        /*(else fall through; not enough space to store entire error string)*/
    }

    /*(not enough space to store entire error string)*/
    if (maxsize > 3)
        memcpy(s+maxsize-4, "...", 3);
    return ERANGE;

  #endif
}


int
ck_memeq_const_time (const void *a, size_t alen, const void *b, size_t blen)
{
    /* constant time memory compare for equality */
    /* rounds to next multiple of 64 to avoid potentially leaking exact
     * string lengths when subject to high precision timing attacks
     */
    /* Note: some libs provide similar funcs but might not obscure length, e.g.
     * OpenSSL:
     *   int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
     * Note: some OS provide similar funcs but might not obscure length, e.g.
     * OpenBSD: int timingsafe_bcmp(const void *b1, const void *b2, size_t len)
     * NetBSD: int consttime_memequal(void *b1, void *b2, size_t len)
     */
    const volatile unsigned char * const av =
      (const unsigned char *)(alen ? a : "");
    const volatile unsigned char * const bv =
      (const unsigned char *)(blen ? b : "");
    size_t lim = ((alen >= blen ? alen : blen) + 0x3F) & ~0x3F;
    int diff = (alen != blen); /*(never match if string length mismatch)*/
    alen -= (alen != 0);
    blen -= (blen != 0);
    for (size_t i = 0, j = 0; lim; --lim) {
        diff |= (av[i] ^ bv[j]);
        i += (i < alen);
        j += (j < blen);
    }
    return (0 == diff);
}


int
ck_memeq_const_time_fixed_len (const void *a, const void *b, const size_t len)
{
    /* constant time memory compare for equality for fixed len (e.g. digests)
     * (padding not necessary for digests, which have fixed, defined lengths) */
    /* caller should prefer ck_memeq_const_time() if not operating on digests */
    const volatile unsigned char * const av = (const unsigned char *)a;
    const volatile unsigned char * const bv = (const unsigned char *)b;
    int diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (av[i] ^ bv[i]);
    }
    return (0 == diff);
}




#include <stdio.h>      /* fflush() fprintf() snprintf() */

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
__attribute_cold__
__attribute_noinline__
static void
ck_backtrace (FILE *fp)
{
    int rc;
    unsigned int frame = 0;
    unw_word_t ip;
    unw_word_t offset;
    unw_cursor_t cursor;
    unw_context_t context;
    unw_proc_info_t procinfo;
    char name[256];

    rc = unw_getcontext(&context);
    if (0 != rc) goto error;
    rc = unw_init_local(&cursor, &context);
    if (0 != rc) goto error;

    fprintf(fp, "Backtrace:\n");
    while (0 < (rc = unw_step(&cursor))) {
        ++frame;
        ip = 0;
        rc = unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (0 != rc) break;
        if (0 == ip) {
            /* without an IP the other functions are useless;
             * unw_get_proc_name would return UNW_EUNSPEC */
            fprintf(fp, "%u: (nil)\n", frame);
            continue;
        }

        rc = unw_get_proc_info(&cursor, &procinfo);
        if (0 != rc) break;

        offset = 0;
        rc = unw_get_proc_name(&cursor, name, sizeof(name), &offset);
        if (0 != rc) {
            switch (-rc) {
              case UNW_ENOMEM:
                memcpy(name + sizeof(name) - 4, "...", 4);
                break;
              case UNW_ENOINFO:
                name[0] = '?';
                name[1] = '\0';
                break;
              default:
                snprintf(name, sizeof(name),
                         "?? (unw_get_proc_name error %d)", -rc);
                break;
            }
        }

        fprintf(fp, "%.2u: [%.012lx] (+%04x) %s\n",
                frame,(long unsigned)(uintptr_t)ip,(unsigned int)offset,name);
    }
    if (0 == rc)
        return;

error:
    fprintf(fp, "Error while generating backtrace: unwind error %i\n",(int)-rc);
}
#endif


__attribute_noinline__
__attribute_nonnull__()
static void
ck_bt_stderr (const char *filename, unsigned int line, const char *msg, const char *fmt)
{
    fprintf(stderr, fmt, filename, line, msg);
  #ifdef HAVE_LIBUNWIND
    ck_backtrace(stderr);
  #endif
    fflush(stderr);
}


void
ck_bt (const char *filename, unsigned int line, const char *msg)
{
    ck_bt_stderr(filename, line, msg, "%s.%u: %s\n");
}


__attribute_noreturn__
void
ck_bt_abort (const char *filename, unsigned int line, const char *msg)
{
    ck_bt(filename, line, msg);
    abort();
}


__attribute_noreturn__
void ck_assert_failed(const char *filename, unsigned int line, const char *msg)
{
    /* same as ck_bt_abort() but add "assertion failed: " prefix here
     * to avoid bloating string tables in callers */
    ck_bt_stderr(filename, line, msg, "%s.%u: assertion failed: %s\n");
    abort();
}
