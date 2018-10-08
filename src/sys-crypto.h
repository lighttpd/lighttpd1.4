#ifndef LI_SYS_CRYPTO_H
#define LI_SYS_CRYPTO_H
#include "first.h"

#if defined HAVE_LIBSSL && defined HAVE_OPENSSL_SSL_H
#define USE_OPENSSL_CRYPTO
#endif

#ifdef HAVE_WOLFSSL_SSL_H
#define USE_OPENSSL_CRYPTO
/* wolfSSL needs to be built with ./configure --enable-lighty for lighttpd.
 * Doing so defines OPENSSL_EXTRA and HAVE_LIGHTY in <wolfssl/options.h>, and
 * these defines are necessary for wolfSSL headers to expose sufficient openssl
 * compatibility layer for wolfSSL to be able to provide an openssl substitute
 * for use by lighttpd */
#include <wolfssl/options.h>
#endif

#endif
