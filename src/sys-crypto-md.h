/* sys-crypto-md.h - message digest (MD) wrapper
 *
 * message digest (MD) algorithms are not necessarily cryptographically secure
 * (often provided by crypto libraries, hence this file named sys-crypto-md.h)
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef LI_SYS_CRYPTO_MD_H
#define LI_SYS_CRYPTO_MD_H
#include "first.h"

#include "sys-crypto.h" /* USE_LIB_CRYPTO */
#ifdef USE_LIB_CRYPTO

#if defined(USE_NETTLE_CRYPTO)

#include <nettle/md4.h>
#include <nettle/md5.h>
#include <nettle/sha.h>

#define USE_LIB_CRYPTO_MD4
typedef struct md4_ctx MD4_CTX;
#define MD4_Init(ctx) \
        nettle_md4_init(ctx)
#define MD4_Final(digest, ctx) \
        nettle_md4_digest((ctx),sizeof(digest),(digest))
static inline void
MD4_Update(MD4_CTX *ctx, const void *data, size_t length)
{
    nettle_md4_update(ctx, length, data);
}

#define USE_LIB_CRYPTO_MD5
typedef struct md5_ctx MD5_CTX;
#define MD5_Init(ctx) \
        nettle_md5_init(ctx)
#define MD5_Final(digest, ctx) \
        nettle_md5_digest((ctx),sizeof(digest),(digest))
static inline void
MD5_Update(MD5_CTX *ctx, const void *data, size_t length)
{
    nettle_md5_update(ctx, length, data);
}

#define USE_LIB_CRYPTO_SHA1
typedef struct sha1_ctx SHA_CTX;
#define SHA1_Init(ctx) \
        nettle_sha1_init(ctx)
#define SHA1_Final(digest, ctx) \
        nettle_sha1_digest((ctx),sizeof(digest),(digest))
static inline void
SHA1_Update(SHA_CTX *ctx, const void *data, size_t length)
{
    nettle_sha1_update(ctx, length, data);
}

#define USE_LIB_CRYPTO_SHA256
typedef struct sha256_ctx SHA256_CTX;
#define SHA256_Init(ctx) \
        nettle_sha256_init(ctx)
#define SHA256_Final(digest, ctx) \
        nettle_sha256_digest((ctx),sizeof(digest),(digest))
static inline void
SHA256_Update(SHA256_CTX *ctx, const void *data, size_t length)
{
    nettle_sha256_update(ctx, length, data);
}

#define USE_LIB_CRYPTO_SHA512_256
#ifndef SHA512_256_DIGEST_LENGTH
#define SHA512_256_DIGEST_LENGTH 32
#endif
typedef struct sha512_256_ctx SHA512_CTX;    /*(yes, SHA512_CTX)*/
#define SHA512_256_Init(ctx) \
        nettle_sha512_256_init(ctx)
#define SHA512_256_Final(digest, ctx) \
        nettle_sha512_256_digest((ctx),sizeof(digest),(digest))
static inline void
SHA512_256_Update(SHA512_CTX *ctx, const void *data, size_t length)
{
    nettle_sha512_update(ctx, length, data); /*(yes, nettle_sha512_update())*/
}

#elif defined(USE_MBEDTLS_CRYPTO)

#ifdef MBEDTLS_MD4_C
#define USE_LIB_CRYPTO_MD4
#include <mbedtls/md4.h>
typedef struct mbedtls_md4_context MD4_CTX;
#define MD4_Init(ctx) \
        (mbedtls_md4_init(ctx), mbedtls_md4_starts_ret(ctx))
#define MD4_Final(digest, ctx) \
        (mbedtls_md4_finish_ret((ctx),(digest)), mbedtls_md4_free(ctx))
static inline void
MD4_Update(MD4_CTX *ctx, const void *data, size_t length)
{
    mbedtls_md4_update_ret(ctx, data, length);
}
#endif

#ifdef MBEDTLS_MD5_C
#define USE_LIB_CRYPTO_MD5
#include <mbedtls/md5.h>
typedef struct mbedtls_md5_context MD5_CTX;
#define MD5_Init(ctx) \
        (mbedtls_md5_init(ctx), mbedtls_md5_starts_ret(ctx))
#define MD5_Final(digest, ctx) \
        (mbedtls_md5_finish_ret((ctx),(digest)), mbedtls_md5_free(ctx))
static inline void
MD5_Update(MD5_CTX *ctx, const void *data, size_t length)
{
    mbedtls_md5_update_ret(ctx, data, length);
}
#endif

#ifdef MBEDTLS_SHA1_C
#define USE_LIB_CRYPTO_SHA1
#include <mbedtls/sha1.h>
typedef struct mbedtls_sha1_context SHA_CTX;
#define SHA1_Init(ctx) \
        (mbedtls_sha1_init(ctx), mbedtls_sha1_starts_ret(ctx))
#define SHA1_Final(digest, ctx) \
        (mbedtls_sha1_finish_ret((ctx),(digest)), mbedtls_sha1_free(ctx))
static inline void
SHA1_Update(SHA_CTX *ctx, const void *data, size_t length)
{
    mbedtls_sha1_update_ret(ctx, data, length);
}
#endif

#ifdef MBEDTLS_SHA256_C
#define USE_LIB_CRYPTO_SHA256
#include <mbedtls/sha256.h>
typedef struct mbedtls_sha256_context SHA256_CTX;
#define SHA256_Init(ctx) \
        (mbedtls_sha256_init(ctx), mbedtls_sha256_starts_ret((ctx),0))
#define SHA256_Final(digest, ctx) \
        (mbedtls_sha256_finish_ret((ctx),(digest)), mbedtls_sha256_free(ctx))
static inline void
SHA256_Update(SHA256_CTX *ctx, const void *data, size_t length)
{
    mbedtls_sha256_update_ret(ctx, data, length);
}
#endif

#elif defined(USE_OPENSSL_CRYPTO)

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#ifndef OPENSSL_NO_MD4
#ifndef NO_MD4 /*(e.g. wolfSSL built without MD4)*/
#define USE_LIB_CRYPTO_MD4
#endif
#endif
#ifndef OPENSSL_NO_MD5
#define USE_LIB_CRYPTO_MD5
#endif
#define USE_LIB_CRYPTO_SHA1
#define USE_LIB_CRYPTO_SHA256
#ifdef SHA512_256_DIGEST_LENGTH
#define USE_LIB_CRYPTO_SHA512_256
#endif

#elif defined(USE_GNUTLS_CRYPTO)

#include <gnutls/crypto.h>

#define USE_LIB_CRYPTO_MD5
typedef gnutls_hash_hd_t MD5_CTX;
#define MD5_Init(ctx)                                        \
        do {                                                  \
            if (gnutls_hash_init((ctx), GNUTLS_DIG_MD5) < 0) \
                SEGFAULT();                                   \
        } while (0)
#define MD5_Final(digest, ctx) \
        gnutls_hash_deinit(*(ctx),(digest))
static inline void
MD5_Update(MD5_CTX *ctx, const void *data, size_t length)
{
    gnutls_hash(*ctx, data, length);
}

#define USE_LIB_CRYPTO_SHA1
typedef gnutls_hash_hd_t SHA_CTX;
#define SHA1_Init(ctx)                                        \
        do {                                                  \
            if (gnutls_hash_init((ctx), GNUTLS_DIG_SHA1) < 0) \
                SEGFAULT();                                   \
        } while (0)
#define SHA1_Final(digest, ctx) \
        gnutls_hash_deinit(*(ctx),(digest))
static inline void
SHA1_Update(SHA_CTX *ctx, const void *data, size_t length)
{
    gnutls_hash(*ctx, data, length);
}

#define USE_LIB_CRYPTO_SHA256
typedef gnutls_hash_hd_t SHA256_CTX;
#define SHA256_Init(ctx)                                        \
        do {                                                    \
            if (gnutls_hash_init((ctx), GNUTLS_DIG_SHA256) < 0) \
                SEGFAULT();                                     \
        } while (0)
#define SHA256_Final(digest, ctx) \
        gnutls_hash_deinit(*(ctx),(digest))
static inline void
SHA256_Update(SHA256_CTX *ctx, const void *data, size_t length)
{
    gnutls_hash(*ctx, data, length);
}

#endif

#endif /* USE_LIB_CRYPTO */


#ifdef USE_LIB_CRYPTO_MD5
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif
#include "md5.h" /*(for legacy li_MD5_*() name mangling)*/
#else
#include "md5.h"
#endif


#ifdef USE_LIB_CRYPTO_SHA1
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif
#else
#include "algo_sha1.h"
#endif


#endif /* LI_SYS_CRYPTO_MD_H */
