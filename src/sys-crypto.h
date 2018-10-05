#ifndef LI_SYS_CRYPTO_H
#define LI_SYS_CRYPTO_H
#include "first.h"

#if defined HAVE_LIBSSL && defined HAVE_OPENSSL_SSL_H
#define USE_OPENSSL_CRYPTO
#endif

#ifdef HAVE_WOLFSSL_SSL_H
#include <wolfssl/options.h>
#endif

#endif
