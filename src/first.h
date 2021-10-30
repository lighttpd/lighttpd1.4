#ifndef LI_FIRST_H
#define LI_FIRST_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#else
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#if defined(__APPLE__) && defined(__MACH__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#ifdef __COVERITY__
#define _Float128 long double
#define _Float64x long double
#define _Float64  double
#define _Float32x double
#define _Float32  float
#endif

/* enable glibc Y2038 64-bit time_t (where available on 32-bit systems) */
#ifdef _ILP32
#ifndef _TIME_BITS
#define _TIME_BITS 64
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif


#include <sys/types.h>
#include <stddef.h>

#ifdef __has_include
#if __has_include(<sys/cdefs.h>)
#include <sys/cdefs.h>
#endif
#endif

#ifndef __BEGIN_DECLS
#ifdef __cplusplus
#define __BEGIN_DECLS extern "C" {
#else
#define __BEGIN_DECLS
#endif
#endif

#ifndef __END_DECLS
#ifdef __cplusplus
#define __END_DECLS }
#else
#define __END_DECLS
#endif
#endif

#if defined HAVE_STDINT_H
# include <stdint.h>
#elif defined HAVE_INTTYPES_H
# include <inttypes.h>
#endif


/* solaris and NetBSD 1.3.x again */
#if (!defined(HAVE_STDINT_H)) && (!defined(HAVE_INTTYPES_H)) && (!defined(uint32_t))
# define uint32_t u_int32_t
#endif


#include <limits.h>

#ifndef SIZE_MAX
# ifdef SIZE_T_MAX
#  define SIZE_MAX SIZE_T_MAX
# else
#  define SIZE_MAX (~(size_t)0u)
# endif
#endif

#ifndef SSIZE_MAX
# define SSIZE_MAX ((ssize_t)(SIZE_MAX >> 1))
#endif


/* TODO: would be more accurate to create build-system test for sizeof(time_t)*/
#ifndef HAS_TIME_BITS64
 #if defined(_LP64) || defined(__LP64__) || defined(_WIN64)
  #define HAS_TIME_BITS64 1
 #elif defined(__TIMESIZE)
  #if __TIMESIZE == 64
   #define HAS_TIME_BITS64 1
  #elif defined(__USE_TIME_BITS64)
   #define HAS_TIME_BITS64 1
  #else
   #define HAS_TIME_BITS64 0
  #endif
 #elif defined(_WIN32)
  #ifndef _USE_32BIT_TIME_T
   #define HAS_TIME_BITS64 1
  #else
   #define HAS_TIME_BITS64 0
  #endif
 #elif defined(_ILP32) \
   && !defined(__USE_TIME_BITS64) \
   && !defined(__NetBSD__) && !defined(__OpenBSD__) \
   && (!defined(__FreeBSD__) || !defined(__i386__)) \
   && !(defined(__APPLE__) && defined(__MACH__))
  #define HAS_TIME_BITS64 0
 #else
  #define HAS_TIME_BITS64 1
 #endif
#endif

/* non-standard types created for lighttpd for Y2038 problem
 * reference: https://en.wikipedia.org/wiki/Year_2038_problem */
#if HAS_TIME_BITS64
typedef time_t unix_time64_t;
typedef struct timespec unix_timespec64_t;
#define TIME64_CAST(t)  (t)
#else  /* !HAS_TIME_BITS64 */
typedef int64_t unix_time64_t;
struct unix_timespec64 {
  unix_time64_t tv_sec;        /* seconds */
  long          tv_nsec;       /* nanoseconds */
};
typedef struct unix_timespec64 unix_timespec64_t;
#define TIME64_CAST(t)  ((unix_time64_t)(uint32_t)(t))
#endif /* !HAS_TIME_BITS64 */


#define UNUSED(x) ( (void)(x) )


#ifndef __has_attribute       /* clang */
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin         /* clang */
#define __has_builtin(x) 0
#endif

#ifdef __GNUC__
#ifndef __GNUC_PREREQ
#  ifdef __GNUC_PREREQ__
#    define __GNUC_PREREQ __GNUC_PREREQ__
#  elif defined __GNUC__ && defined __GNUC_MINOR__
#    define __GNUC_PREREQ(maj, min) \
       ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#  else
#    define __GNUC_PREREQ(maj, min) 0
#  endif
#endif
#else
#define __GNUC_PREREQ(maj,min) 0
#endif

#ifndef __builtin_expect
#if !__has_builtin(__builtin_expect) \
 && !__GNUC_PREREQ(2,96)
#define __builtin_expect(x,y) (x)
#endif
#endif

#ifndef __attribute_noinline__
#if __has_attribute(noinline) \
 || __GNUC_PREREQ(3,1)
#define __attribute_noinline__  __attribute__((__noinline__))
#else
#define __attribute_noinline__
#endif
#endif

#ifndef __attribute_cold__
#if __has_attribute(cold) \
 || __GNUC_PREREQ(4,3)
#define __attribute_cold__  __attribute__((__cold__))
#else
#define __attribute_cold__
#endif
#endif

#ifndef __attribute_hot__
#if __has_attribute(hot) \
 || __GNUC_PREREQ(4,3)
#define __attribute_hot__  __attribute__((__hot__))
#else
#define __attribute_hot__
#endif
#endif

#ifndef __attribute_noreturn__
#if __has_attribute(noreturn) \
 || __GNUC_PREREQ(2,5)
#define __attribute_noreturn__  __attribute__((__noreturn__))
#else
#define __attribute_noreturn__
#endif
#endif

#ifndef __attribute_fallthrough__
#if __has_attribute(fallthrough) \
 || __GNUC_PREREQ(7,0)
#define __attribute_fallthrough__  __attribute__((__fallthrough__));
#else
#define __attribute_fallthrough__  /* fall through */
#endif
#endif

#ifndef __attribute_format__
#if __has_attribute(format) \
 || __GNUC_PREREQ(2,95) /*(maybe earlier gcc, too)*/
#define __attribute_format__(x)  __attribute__((__format__ x))
#else
#define __attribute_format__(x)
#endif
#endif

#ifndef __attribute_const__
#if __has_attribute(const) \
 || __GNUC_PREREQ(2,5)
#define __attribute_const__  __attribute__((__const__))
#else
#define __attribute_const__
#endif
#endif

#ifndef __attribute_pure__
#if __has_attribute(pure) \
 || __GNUC_PREREQ(2,96)
#define __attribute_pure__  __attribute__((__pure__))
#else
#define __attribute_pure__
#endif
#endif

#ifndef __attribute_returns_nonnull__
#if __has_attribute(returns_nonnull) \
 || __GNUC_PREREQ(4,9)
#define __attribute_returns_nonnull__  __attribute__((__returns_nonnull__))
#else
#define __attribute_returns_nonnull__
#endif
#endif

#ifndef __attribute_nonnull__
#if __has_attribute(nonnull) \
 || __GNUC_PREREQ(3,3)
#define __attribute_nonnull__(params)  __attribute__((__nonnull__ params))
#else
#define __attribute_nonnull__(params)
#endif
#endif

#ifndef __attribute_malloc__
#if __has_attribute(malloc) \
 || __GNUC_PREREQ(2,96)
#define __attribute_malloc__  __attribute__((__malloc__))
#elif defined(_MSC_VER)
#undef  restrict
#define __attribute_malloc__  __declspec(restrict)
#define restrict __restrict
#else
#define __attribute_malloc__
#endif
#endif

#ifndef __attribute_unused__
#if __has_attribute(unused) \
 || __GNUC_PREREQ(2,95)
#define __attribute_unused__  __attribute__((__unused__))
#else
#define __attribute_unused__
#endif
#endif


#endif
