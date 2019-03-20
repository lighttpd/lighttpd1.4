#ifndef LI_FIRST_H
#define LI_FIRST_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#else
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
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


#include <sys/types.h>
#include <stddef.h>

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


#define UNUSED(x) ( (void)(x) )


#ifndef __has_attribute       /* clang */
#define __has_attribute(x) 0
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


#endif
