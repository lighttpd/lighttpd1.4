/*
 * rand - generate random bytes
 *
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "rand.h"
#include "ck.h"
#include "fdevent.h"

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-time.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sys-crypto-md.h" /* USE_LIB_CRYPTO and additional crypto lib config */
#ifdef USE_NETTLE_CRYPTO
#undef USE_MBEDTLS_CRYPTO
#undef USE_WOLFSSL_CRYPTO
#undef USE_OPENSSL_CRYPTO
#undef USE_GNUTLS_CRYPTO
#undef USE_NSS_CRYPTO
#include <nettle/knuth-lfib.h>
#include <nettle/arcfour.h>
#include <nettle/yarrow.h>
#endif
#ifdef USE_MBEDTLS_CRYPTO
#undef USE_WOLFSSL_CRYPTO
#undef USE_OPENSSL_CRYPTO
#undef USE_GNUTLS_CRYPTO
#undef USE_NSS_CRYPTO
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif
#ifdef USE_WOLFSSL_CRYPTO
#undef USE_OPENSSL_CRYPTO
#undef USE_GNUTLS_CRYPTO
#undef USE_NSS_CRYPTO
#include <wolfssl/wolfcrypt/random.h>
#endif
#ifdef USE_OPENSSL_CRYPTO
#undef USE_GNUTLS_CRYPTO
#undef USE_NSS_CRYPTO
#include <openssl/opensslv.h> /* OPENSSL_VERSION_NUMBER */
#include <openssl/rand.h>
#endif
#ifdef USE_GNUTLS_CRYPTO
#undef USE_NSS_CRYPTO
#include <gnutls/crypto.h>
#endif
#ifdef USE_NSS_CRYPTO
#ifdef NSS_VER_INCLUDE
#include <nss3/nss.h>
#include <nss3/pk11pub.h>
#else
#include <nss/nss.h>
#include <nss/pk11pub.h>
#endif
#endif
#ifndef USE_LIB_CRYPTO
#undef USE_NETTLE_CRYPTO
#undef USE_MBEDTLS_CRYPTO
#undef USE_WOLFSSL_CRYPTO
#undef USE_OPENSSL_CRYPTO
#undef USE_GNUTLS_CRYPTO
#undef USE_NSS_CRYPTO
#endif
#ifdef HAVE_GETENTROPY
#include <sys/random.h>
#endif
#ifdef HAVE_LINUX_RANDOM_H
#include <sys/syscall.h>
#include <linux/random.h>
#endif
#ifdef RNDGETENTCNT
#include <sys/ioctl.h>
#endif

/* Take some reasonable steps to attempt to *seed* random number generators with
 * cryptographically random data.  Some of these initialization routines may
 * block, and are intended to be called only at startup in lighttpd, or
 * immediately after fork() to start lighttpd workers.
 *
 * Update: li_rand_init() is now deferred until first use so that installations
 * that do not use modules which use these routines do need to potentially block
 * at startup.  Current use by core lighttpd modules is in mod_auth HTTP Digest
 * auth and in mod_usertrack.  Deferring collection of random data until first
 * use may allow sufficient entropy to be collected by kernel before first use,
 * helping reduce or avoid situations in low-entropy-generating embedded devices
 * which might otherwise block lighttpd for minutes at device startup.
 * Further discussion in https://redmine.lighttpd.net/boards/2/topics/6981
 *
 * Note: results from li_rand_pseudo_bytes() are not necessarily
 * cryptographically random and must not be used for purposes such
 * as key generation which require cryptographic randomness.
 *
 * https://wiki.openssl.org/index.php/Random_Numbers
 * https://wiki.openssl.org/index.php/Random_fork-safety
 *
 * openssl random number generators are not thread-safe by default
 * https://wiki.openssl.org/index.php/Manual:Threads(3)
 *
 * RFE: add more paranoid checks from the following to improve confidence:
 * http://insanecoding.blogspot.co.uk/2014/05/a-good-idea-with-bad-usage-devurandom.html
 * RFE: retry on EINTR
 * RFE: check RAND_status()
 */

static int li_getentropy (void *buf, size_t buflen)
{
  #ifdef HAVE_GETENTROPY
    return getentropy(buf, buflen);
  #else
    /*(see NOTES section in 'man getrandom' on Linux)*/
   #if defined(HAVE_GETRANDOM) || defined(SYS_getrandom)
    if (buflen <= 256) {
      #ifdef HAVE_GETRANDOM /*(not implemented in glibc yet)*/
        int num = getrandom(buf, buflen, 0);
      #elif defined(SYS_getrandom)
        /* https://lwn.net/Articles/605828/ */
        /* https://bbs.archlinux.org/viewtopic.php?id=200039 */
        int num = (int)syscall(SYS_getrandom, buf, buflen, 0);
      #endif
        if (num == (int)buflen) return 0;
        if (num < 0)            return num; /* -1 */
    }
   #else
    UNUSED(buf);
    UNUSED(buflen);
   #endif
    errno = EIO;
    return -1;
  #endif
}

static int li_rand_device_bytes (unsigned char *buf, int num)
{
    /* randomness from these devices is cryptographically strong,
     * unless /dev/urandom is low on entropy */

    static const char * const devices[] = {
      #ifdef __OpenBSD__
        "/dev/arandom",
      #endif
        "/dev/urandom",
        "/dev/random"
    };

    /* device files might not be available in chroot environment,
     * so prefer syscall, if available */
    if (0 == li_getentropy(buf, (size_t)num)) return 1;

    for (unsigned int u = 0; u < sizeof(devices)/sizeof(devices[0]); ++u) {
        /*(some systems might have symlink to another device; omit O_NOFOLLOW)*/
        int fd = fdevent_open_cloexec(devices[u], 1, O_RDONLY, 0);
        if (fd >= 0) {
            ssize_t rd = 0;
          #ifdef RNDGETENTCNT
            int entropy;
            if (0 == ioctl(fd, (unsigned long)(RNDGETENTCNT), &entropy)
                && entropy >= num*8)
          #endif
                rd = read(fd, buf, (size_t)num);
            close(fd);
            if (rd == num) {
                return 1;
            }
        }
    }

    return 0;
}

static int li_rand_inited;
static unsigned short xsubi[3];
#ifdef USE_MBEDTLS_CRYPTO
#ifdef MBEDTLS_ENTROPY_C
static mbedtls_entropy_context entropy;
#ifdef MBEDTLS_CTR_DRBG_C
static mbedtls_ctr_drbg_context ctr_drbg;
#endif
#endif
#endif
#ifdef USE_WOLFSSL_CRYPTO
static WC_RNG wolf_globalRNG;
#endif
#ifdef USE_NETTLE_CRYPTO
static struct knuth_lfib_ctx knuth_lfib_ctx;
static struct arcfour_ctx    arcfour_ctx;
static struct yarrow256_ctx  yarrow256_ctx;
#endif

#ifdef USE_NETTLE_CRYPTO
/* adapted from Nettle documentation arcfour_set_key_hashed() in nettle.pdf */
/* A more robust key setup function for ARCFOUR */
static void
li_arcfour_init_random_key_hashed(struct arcfour_ctx *ctx)
{
    uint8_t key[ARCFOUR_KEY_SIZE];
    const size_t length = sizeof(key);
    if (1 != li_rand_device_bytes(key, (int)sizeof(key))) {
        ck_bt_abort(__FILE__, __LINE__,
                    "gathering entropy for arcfour seed failed");
    }
    memset(ctx, 0, sizeof(*ctx));

    struct sha256_ctx hash;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t buf[0x200];
    memset(buf, 0, sizeof(buf));
    sha256_init(&hash);
    sha256_update(&hash, length, key);
    sha256_digest(&hash, SHA256_DIGEST_SIZE, digest);
    nettle_arcfour_set_key(ctx, SHA256_DIGEST_SIZE, digest);
    nettle_arcfour_crypt(ctx, sizeof(buf), buf, buf);
    nettle_arcfour_crypt(ctx, sizeof(buf), buf, buf);
    nettle_arcfour_crypt(ctx, sizeof(buf), buf, buf);
}
#endif

__attribute_cold__
static void li_rand_init (void)
{
    /* (intended to be called at init and after fork() in order to re-seed PRNG
     *  so that forked children, grandchildren, etc do not share PRNG seed)
     * https://github.com/ramsey/uuid/issues/80
     * https://www.agwa.name/blog/post/libressls_prng_is_unsafe_on_linux
     *   (issue in early version of libressl has since been fixed)
     * https://github.com/libressl-portable/portable/commit/32d9eeeecf4e951e1566d5f4a42b36ea37b60f35
     */
    unsigned int u;
    li_rand_inited = 1;
    if (1 == li_rand_device_bytes((unsigned char *)xsubi, (int)sizeof(xsubi))) {
        u = ((unsigned int)xsubi[0] << 16) | xsubi[1];
    }
    else {
      #ifdef HAVE_ARC4RANDOM_BUF
        u = arc4random();
        arc4random_buf(xsubi, sizeof(xsubi));
      #elif defined(__COVERITY__)
        /* Coverity Scan ignores(?) annotation below,
         * so hide fallback path from Coverity Scan */
        u = (unsigned int)(time(NULL) ^ getpid());
      #else
        /* NOTE: not cryptographically random !!! */
        srand((unsigned int)(time(NULL) ^ getpid()));
        for (u = 0; u < sizeof(unsigned short); ++u)
            /* coverity[dont_call : FALSE] */
            xsubi[u] = (unsigned short)(rand() & 0xFFFF);
        u = ((unsigned int)xsubi[0] << 16) | xsubi[1];
      #endif
    }
    srand(u);   /*(initialize just in case rand() used elsewhere)*/
  #ifdef HAVE_SRANDOM
    srandom(u); /*(initialize just in case random() used elsewhere)*/
  #endif
  #ifdef USE_NETTLE_CRYPTO
    nettle_knuth_lfib_init(&knuth_lfib_ctx, u);
    nettle_yarrow256_init(&yarrow256_ctx, 0, NULL);
    li_arcfour_init_random_key_hashed(&arcfour_ctx);
  #endif
  #ifdef USE_WOLFSSL_CRYPTO
    /* xsubi[] is small, so use wc_InitRng() instead of wc_InitRngNonce()
     * to get default behavior of a larger internally-generated nonce */
    if (0 != wolfCrypt_Init() || 0 != wc_InitRng(&wolf_globalRNG))
        ck_bt_abort(__FILE__,__LINE__,"wolfCrypt_Init or wc_InitRng() failed");
  #endif
  #ifdef USE_OPENSSL_CRYPTO
    RAND_poll();
    RAND_seed(xsubi, (int)sizeof(xsubi));
  #endif
  #ifdef USE_MBEDTLS_CRYPTO
  #ifdef MBEDTLS_ENTROPY_C
    mbedtls_entropy_init(&entropy);
  #ifdef MBEDTLS_CTR_DRBG_C
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int rc =
      mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (unsigned char *)xsubi, sizeof(xsubi));
    if (0 != rc) /*(not expecting built-in entropy function to fail)*/
        ck_bt_abort(__FILE__, __LINE__, "mbedtls_ctr_drbg_seed() failed");
  #endif
  #endif
  #endif
  #ifdef USE_NSS_CRYPTO
    if (!NSS_IsInitialized() && NSS_NoDB_Init(NULL) < 0)
        ck_bt_abort(__FILE__, __LINE__, "aborted");
    PK11_RandomUpdate(xsubi, sizeof(xsubi));
  #endif
}

void li_rand_reseed (void)
{
  #ifdef USE_GNUTLS_CRYPTO
    gnutls_rnd_refresh();
    return;
  #endif
  #ifdef USE_WOLFSSL_CRYPTO
    if (li_rand_inited) {
      #if 0 /*(wc_RNG_DRBG_Reseed() is not part of public API)*/
        /*(XXX: might use stack to procure larger seed;
         * xsubi[] is short (6 bytes)) */
        if (1 == li_rand_device_bytes((unsigned char *)xsubi,
                                      (int)sizeof(xsubi))) {
            if (0 != wc_RNG_DRBG_Reseed(&wolf_globalRNG,
                                        (const byte *)xsubi,
                                        (word32)sizeof(xsubi)))
                /*(not expecting this to fail)*/
                ck_bt_abort(__FILE__, __LINE__, "wc_RNG_DRBG_Reseed() failed");
        }
      #else
        wc_FreeRng(&wolf_globalRNG);
        if (0 != wc_InitRng(&wolf_globalRNG))
            ck_bt_abort(__FILE__, __LINE__, "wc_InitRng() failed");
      #endif
        return;
    }
  #endif
  #ifdef USE_MBEDTLS_CRYPTO
    if (li_rand_inited) {
      #ifdef MBEDTLS_ENTROPY_C
      #ifdef MBEDTLS_CTR_DRBG_C
        mbedtls_ctr_drbg_free(&ctr_drbg);
      #endif
        mbedtls_entropy_free(&entropy);
      #endif
    }
  #endif
    if (li_rand_inited) li_rand_init();
}

int li_rand_pseudo (void)
{
  #ifdef USE_GNUTLS_CRYPTO
    int i;
    if (0 == gnutls_rnd(GNUTLS_RND_NONCE, &i, sizeof(i))) return i;
  #endif
    if (!li_rand_inited) li_rand_init();
    /* randomness *is not* cryptographically strong */
    /* (attempt to use better mechanisms to replace the more portable rand()) */
  #ifdef USE_OPENSSL_CRYPTO /* (openssl 1.1.0 deprecates RAND_pseudo_bytes()) */
  #if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    int i;
    if (-1 != RAND_pseudo_bytes((unsigned char *)&i, sizeof(i))) return i;
  #endif
  #endif
  #ifdef USE_WOLFSSL_CRYPTO
    /* RAND_pseudo_bytes() in WolfSSL is equivalent to RAND_bytes() */
    int i;
    if (0 == wc_RNG_GenerateBlock(&wolf_globalRNG,(byte *)&i,(word32)sizeof(i)))
        return i;
  #endif
  #ifdef USE_NETTLE_CRYPTO
    int i = (int)nettle_knuth_lfib_get(&knuth_lfib_ctx);
    nettle_arcfour_crypt(&arcfour_ctx, sizeof(i), (uint8_t *)&i, (uint8_t *)&i);
    if (i) return i; /*(cond to avoid compiler warning for code after return)*/
  #endif
  #ifdef USE_MBEDTLS_CRYPTO
  #ifdef MBEDTLS_CTR_DRBG_C
    int i;
    if (0 == mbedtls_ctr_drbg_random(&ctr_drbg, (unsigned char *)&i, sizeof(i)))
        return i;
  #endif
  #endif
  #ifdef USE_NSS_CRYPTO
    int i;
    if (SECSuccess == PK11_GenerateRandom((unsigned char *)&i, sizeof(i)))
        return i;
  #endif
  #ifdef HAVE_ARC4RANDOM_BUF
    return (int)arc4random();
  #elif defined(__COVERITY__)
    /* li_rand_pseudo() is not intended for cryptographic use */
    /* Coverity Scan ignores(?) annotation below,
     * so hide fallback paths from Coverity Scan */
    return (int)(time(NULL) ^ getpid());
  #elif defined(HAVE_SRANDOM)
    /* coverity[dont_call : FALSE] */
    return (int)random();
  #elif defined(HAVE_JRAND48)
    /*(FYI: jrand48() reentrant, but use of file-scoped static xsubi[] is not)*/
    /* coverity[dont_call : FALSE] */
    return (int)jrand48(xsubi);
  #else
    /* coverity[dont_call : FALSE] */
    return rand();
  #endif
}

void li_rand_pseudo_bytes (unsigned char *buf, int num)
{
  #ifdef USE_GNUTLS_CRYPTO
    if (0 == gnutls_rnd(GNUTLS_RND_NONCE, buf, (size_t)num)) return;
  #endif
    if (!li_rand_inited) li_rand_init();
  #ifdef USE_NSS_CRYPTO
    if (SECSuccess == PK11_GenerateRandom(buf, num)) return;
  #endif
  #ifdef USE_MBEDTLS_CRYPTO
  #ifdef MBEDTLS_CTR_DRBG_C
    if (0 == mbedtls_ctr_drbg_random(&ctr_drbg, buf, (size_t)num)) return;
  #endif
  #endif
  #ifdef USE_WOLFSSL_CRYPTO
    /* RAND_pseudo_bytes() in WolfSSL is equivalent to RAND_bytes() */
    if (0 == wc_RNG_GenerateBlock(&wolf_globalRNG, (byte *)buf, (word32)num))
        return;
  #endif
    for (int i = 0; i < num; ++i)
        buf[i] = li_rand_pseudo() & 0xFF;
}

int li_rand_bytes (unsigned char *buf, int num)
{
  #ifdef USE_GNUTLS_CRYPTO /* should use GNUTLS_RND_KEY for long-term keys */
    if (0 == gnutls_rnd(GNUTLS_RND_RANDOM, buf, (size_t)num)) return 1;
  #endif
  #ifdef USE_NSS_CRYPTO
    if (!li_rand_inited) li_rand_init();
    if (SECSuccess == PK11_GenerateRandom(buf, num)) return 1;
  #endif
  #ifdef USE_NETTLE_CRYPTO
  #if 0 /* not implemented: periodic nettle_yarrow256_update() and reseed */
    if (!nettle_yarrow256_is_seeded(&yarrow256_ctx)) {
        uint8_t seed_file[YARROW256_SEED_FILE_SIZE];
        if (1 == li_rand_device_bytes((unsigned char *)seed_file,
                                      (int)sizeof(seed_file))) {
            nettle_yarrow256_seed(&yarrow256_ctx, sizeof(seed_file), seed_file);
        }
    }
    if (nettle_yarrow256_is_seeded(&yarrow256_ctx)) {
        nettle_yarrow256_random(&yarrow256_ctx, (size_t)num, (uint8_t *)buf);
        return 1;
    }
  #endif
  #endif
  #ifdef USE_OPENSSL_CRYPTO
    int rc = RAND_bytes(buf, num);
    if (-1 != rc) {
        return rc;
    }
  #endif
  #ifdef USE_WOLFSSL_CRYPTO
    if (0 == wc_RNG_GenerateBlock(&wolf_globalRNG, (byte *)buf, (word32)num)) {
        return 1;
    }
  #endif
  #ifdef USE_MBEDTLS_CRYPTO
  #ifdef MBEDTLS_ENTROPY_C
    /*(each call <= MBEDTLS_ENTROPY_BLOCK_SIZE; could implement loop here)*/
    if (num <= MBEDTLS_ENTROPY_BLOCK_SIZE
        && 0 == mbedtls_entropy_func(&entropy, buf, (size_t)num)) {
        return 1;
    }
  #endif
  #endif
    if (1 == li_rand_device_bytes(buf, num)) {
        return 1;
    }
    else {
        /* NOTE: not cryptographically random !!! */
        li_rand_pseudo_bytes(buf, num);
        /*(openssl RAND_pseudo_bytes rc for non-cryptographically random data)*/
        return 0;
    }
}

void li_rand_cleanup (void)
{
  #ifdef USE_WOLFSSL_CRYPTO
    if (li_rand_inited) {
        wc_FreeRng(&wolf_globalRNG);
        wolfCrypt_Cleanup();
        li_rand_inited = 0;
    }
  #endif
  #ifdef USE_OPENSSL_CRYPTO
  #if OPENSSL_VERSION_NUMBER < 0x10100000L
    RAND_cleanup();
  #endif
  #endif
  #ifdef USE_MBEDTLS_CRYPTO
  #ifdef MBEDTLS_ENTROPY_C
  #ifdef MBEDTLS_CTR_DRBG_C
    mbedtls_ctr_drbg_free(&ctr_drbg);
  #endif
    mbedtls_entropy_free(&entropy);
  #endif
  #endif
    ck_memzero(xsubi, sizeof(xsubi));
}
