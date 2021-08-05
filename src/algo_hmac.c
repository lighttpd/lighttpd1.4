/* algo_hmac - hash-based message authentication code (HMAC) wrapper
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "algo_hmac.h"

#include "sys-crypto-md.h"
#ifdef USE_LIB_CRYPTO
#if defined(USE_NETTLE_CRYPTO)
#include <nettle/hmac.h>
#elif defined(USE_MBEDTLS_CRYPTO)
#include <mbedtls/md.h>
#elif defined(USE_WOLFSSL_CRYPTO)
#include <wolfssl/wolfcrypt/hmac.h>
#elif defined(USE_OPENSSL_CRYPTO)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#elif defined(USE_GNUTLS_CRYPTO)
#include <gnutls/crypto.h>
#elif defined(USE_NSS_CRYPTO)
#if 0 /*(nss/alghmac.h might not be present)*/
#ifdef NSS_VER_INCLUDE
#include <nss3/alghmac.h>
#else
#include <nss/alghmac.h>
#endif
#endif
#endif
#endif

#ifndef USE_NETTLE_CRYPTO
#if defined(USE_OPENSSL_CRYPTO) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#define HMAC EVP_HMAC
static unsigned char *
EVP_HMAC (const EVP_MD *evp_md, const void *key,
          int key_len, const unsigned char *d, int n,
          unsigned char *md, size_t *md_len)
{
    EVP_PKEY * const pkey =
      EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
    if (NULL == pkey) return NULL;

    EVP_MD_CTX * const ctx = EVP_MD_CTX_new();
    if (NULL == ctx) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    int rc = (1 == EVP_DigestSignInit(ctx, NULL, evp_md, NULL, pkey))
          && (1 == EVP_DigestSignUpdate(ctx, d, n))
          && (1 == EVP_DigestSignFinal(ctx, md, md_len));
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return (1 == rc) ? md : NULL;
}
#endif
#endif


int
li_hmac_md5 (unsigned char digest[MD5_DIGEST_LENGTH],
             const void * const secret, const uint32_t slen,
             const unsigned char * const msg, const uint32_t mlen)
{
    struct const_iovec iov[] = { { secret, slen }, { msg, mlen } };
    MD5_iov(digest, iov, sizeof(iov)/sizeof(*iov));
    return 1;
}


#ifdef USE_LIB_CRYPTO_SHA1
int
li_hmac_sha1 (unsigned char digest[SHA_DIGEST_LENGTH],
              const void * const secret, const uint32_t slen,
              const unsigned char * const msg, const uint32_t mlen)
{
  #ifdef USE_LIB_CRYPTO
   #if defined(USE_NETTLE_CRYPTO)
    struct hmac_sha1_ctx ctx;
    hmac_sha1_set_key(&ctx, slen, (const uint8_t *)secret);
    hmac_sha1_update(&ctx, mlen, (const uint8_t *)msg);
    hmac_sha1_digest(&ctx, SHA_DIGEST_LENGTH, (uint8_t *)digest);
    return 1;
   #elif defined(USE_MBEDTLS_CRYPTO) \
      && defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA1_C)
    return 0 ==
      mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                      (const unsigned char *)secret, slen,
                      (const unsigned char *)msg, mlen, digest);
   #elif defined(USE_WOLFSSL_CRYPTO)
    Hmac hmac;
    if (0 != wc_HmacInit(&hmac, NULL, INVALID_DEVID)
        || wc_HmacSetKey(&hmac, WC_SHA, (const byte *)secret, (word32)slen) < 0
        || wc_HmacUpdate(&hmac, (const byte *)msg, (word32)mlen) < 0
        || wc_HmacFinal(&hmac, (byte *)digest) < 0)
        return 0;
    return 1;
   #elif defined(USE_OPENSSL_CRYPTO)
    return (NULL != HMAC(EVP_sha1(),
                         (const unsigned char *)secret, (int)slen,
                         (const unsigned char *)msg, mlen,
                         digest, NULL));
   #elif defined(USE_GNUTLS_CRYPTO)
    return 0 ==
      gnutls_hmac_fast(GNUTLS_MAC_SHA1,
                       (const unsigned char *)secret, slen,
                       (const unsigned char *)msg, mlen, digest);
   #elif defined(USE_NSS_CRYPTO)
    /*(HMAC* funcs not public export of libfreebl3.so,
     * even though nss3/alghmac.h is public (WTH?!))*/
    #if 0
    HMACContext *hmac =
      HMAC_Create(HASH_GetHashObject(HASH_AlgSHA1),
                  (const unsigned char *)secret, slen, PR_FALSE);
    if (NULL == hmac)
        return 0;
    HMAC_Begin(hmac);
    HMAC_Update(hmac, (const unsigned char *)msg, mlen);
    unsigned int dlen;
    int rc = HMAC_Finish(hmac, digest, &dlen, SHA_DIGEST_LENGTH);
    HMAC_Destroy(hmac, PR_TRUE);
    return (SECSuccess == rc);
    #else
    UNUSED(digest);
    UNUSED(secret);
    UNUSED(slen);
    UNUSED(msg);
    UNUSED(mlen);
    return 0;
    #endif
   #else
   #error "unexpected; crypto lib not configured for HMAC SHA1"
   #endif
  #else
    UNUSED(digest);
    UNUSED(secret);
    UNUSED(slen);
    UNUSED(msg);
    UNUSED(mlen);
    return 0;
  #endif
}
#endif


#ifdef USE_LIB_CRYPTO_SHA256
int
li_hmac_sha256 (unsigned char digest[SHA256_DIGEST_LENGTH],
                const void * const secret, const uint32_t slen,
                const unsigned char * const msg, const uint32_t mlen)
{
  #ifdef USE_LIB_CRYPTO
   #if defined(USE_NETTLE_CRYPTO)
    struct hmac_sha256_ctx ctx;
    hmac_sha256_set_key(&ctx, slen, (const uint8_t *)secret);
    hmac_sha256_update(&ctx, mlen, (const uint8_t *)msg);
    hmac_sha256_digest(&ctx, SHA256_DIGEST_LENGTH, (uint8_t *)digest);
    return 1;
   #elif defined(USE_MBEDTLS_CRYPTO) \
      && defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA256_C)
    return 0 ==
      mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                      (const unsigned char *)secret, slen,
                      (const unsigned char *)msg, mlen, digest);
   #elif defined(USE_WOLFSSL_CRYPTO)
    Hmac hmac;
    if (0 != wc_HmacInit(&hmac, NULL, INVALID_DEVID)
        || wc_HmacSetKey(&hmac, WC_SHA256,(const byte *)secret,(word32)slen) < 0
        || wc_HmacUpdate(&hmac, (const byte *)msg, (word32)mlen) < 0
        || wc_HmacFinal(&hmac, (byte *)digest) < 0)
        return 0;
    return 1;
   #elif defined(USE_OPENSSL_CRYPTO)
    return (NULL != HMAC(EVP_sha256(),
                         (const unsigned char *)secret, (int)slen,
                         (const unsigned char *)msg, mlen,
                         digest, NULL));
   #elif defined(USE_GNUTLS_CRYPTO)
    return 0 ==
      gnutls_hmac_fast(GNUTLS_MAC_SHA256,
                       (const unsigned char *)secret, slen,
                       (const unsigned char *)msg, mlen, digest);
   #elif defined(USE_NSS_CRYPTO)
    /*(HMAC* funcs not public export of libfreebl3.so,
     * even though nss3/alghmac.h is public (WTH?!))*/
    #if 0
    HMACContext *hmac =
      HMAC_Create(HASH_GetHashObject(HASH_AlgSHA256),
                  (const unsigned char *)secret, slen, PR_FALSE);
    if (NULL == hmac)
        return 0;
    HMAC_Begin(hmac);
    HMAC_Update(hmac, (const unsigned char *)msg, mlen);
    unsigned int dlen;
    int rc = HMAC_Finish(hmac, digest, &dlen, SHA256_DIGEST_LENGTH);
    HMAC_Destroy(hmac, PR_TRUE);
    return (SECSuccess == rc);
    #else
    UNUSED(digest);
    UNUSED(secret);
    UNUSED(slen);
    UNUSED(msg);
    UNUSED(mlen);
    return 0;
    #endif
   #else
   #error "unexpected; crypto lib not configured for HMAC SHA256"
   #endif
  #else
    UNUSED(digest);
    UNUSED(secret);
    UNUSED(slen);
    UNUSED(msg);
    UNUSED(mlen);
    return 0;
  #endif
}
#endif


#ifdef USE_LIB_CRYPTO_SHA512
int
li_hmac_sha512 (unsigned char digest[SHA512_DIGEST_LENGTH],
                const void * const secret, const uint32_t slen,
                const unsigned char * const msg, const uint32_t mlen)
{
  #ifdef USE_LIB_CRYPTO
   #if defined(USE_NETTLE_CRYPTO)
    struct hmac_sha512_ctx ctx;
    hmac_sha512_set_key(&ctx, slen, (const uint8_t *)secret);
    hmac_sha512_update(&ctx, mlen, (const uint8_t *)msg);
    hmac_sha512_digest(&ctx, SHA512_DIGEST_LENGTH, (uint8_t *)digest);
    return 1;
   #elif defined(USE_MBEDTLS_CRYPTO) \
      && defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA512_C)
    return 0 ==
      mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                      (const unsigned char *)secret, slen,
                      (const unsigned char *)msg, mlen, digest);
   #elif defined(USE_WOLFSSL_CRYPTO)
    Hmac hmac;
    if (0 != wc_HmacInit(&hmac, NULL, INVALID_DEVID)
        || wc_HmacSetKey(&hmac, WC_SHA512,(const byte *)secret,(word32)slen) < 0
        || wc_HmacUpdate(&hmac, (const byte *)msg, (word32)mlen) < 0
        || wc_HmacFinal(&hmac, (byte *)digest) < 0)
        return 0;
    return 1;
   #elif defined(USE_OPENSSL_CRYPTO)
    return (NULL != HMAC(EVP_sha512(),
                         (const unsigned char *)secret, (int)slen,
                         (const unsigned char *)msg, mlen,
                         digest, NULL));
   #elif defined(USE_GNUTLS_CRYPTO)
    return 0 ==
      gnutls_hmac_fast(GNUTLS_MAC_SHA512,
                       (const unsigned char *)secret, slen,
                       (const unsigned char *)msg, mlen, digest);
   #elif defined(USE_NSS_CRYPTO)
    /*(HMAC* funcs not public export of libfreebl3.so,
     * even though nss3/alghmac.h is public (WTH?!))*/
    #if 0
    HMACContext *hmac =
      HMAC_Create(HASH_GetHashObject(HASH_AlgSHA512),
                  (const unsigned char *)secret, slen, PR_FALSE);
    if (NULL == hmac)
        return 0;
    HMAC_Begin(hmac);
    HMAC_Update(hmac, (const unsigned char *)msg, mlen);
    unsigned int dlen;
    int rc = HMAC_Finish(hmac, digest, &dlen, SHA512_DIGEST_LENGTH);
    HMAC_Destroy(hmac, PR_TRUE);
    return (SECSuccess == rc);
    #else
    UNUSED(digest);
    UNUSED(secret);
    UNUSED(slen);
    UNUSED(msg);
    UNUSED(mlen);
    return 0;
    #endif
   #else
   #error "unexpected; crypto lib not configured for HMAC SHA512"
   #endif
  #else
    UNUSED(digest);
    UNUSED(secret);
    UNUSED(slen);
    UNUSED(msg);
    UNUSED(mlen);
    return 0;
  #endif
}
#endif
