#ifndef LI_SYS_CRYPTO_H
#define LI_SYS_CRYPTO_H
#include "first.h"

#if defined HAVE_LIBSSL && defined HAVE_OPENSSL_SSL_H
#define USE_LIB_CRYPTO
#define USE_OPENSSL_CRYPTO
#endif

#ifdef HAVE_WOLFSSL_SSL_H
#define USE_LIB_CRYPTO
#define USE_WOLFSSL_CRYPTO
#endif

#ifdef HAVE_LIBMBEDCRYPTO
#define USE_LIB_CRYPTO
#define USE_MBEDTLS_CRYPTO
#endif

#ifdef HAVE_NSS3_NSS_H
#define USE_LIB_CRYPTO
#define USE_NSS_CRYPTO
#endif
#ifdef HAVE_NSS_NSS_H
#define USE_LIB_CRYPTO
#define USE_NSS_CRYPTO
#endif

#ifdef HAVE_NETTLE_NETTLE_TYPES_H
#define USE_LIB_CRYPTO
#define USE_NETTLE_CRYPTO
#endif

#ifdef HAVE_GNUTLS_CRYPTO_H
#define USE_LIB_CRYPTO
#define USE_GNUTLS_CRYPTO
#endif

#ifdef WITHOUT_LIB_CRYPTO
#undef USE_LIB_CRYPTO
#endif

#endif
