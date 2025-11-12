/*
 * mod_boringssl - boringssl support for lighttpd
 *
 * Forked from src/mod_openssl.c
 * Copyright(c) 2016,2025 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
/*
 * Note: If session tickets are -not- disabled with
 *     ssl.openssl.ssl-conf-cmd = ("Options" => "-SessionTicket")
 *   mod_openssl rotates server ticket encryption key (STEK) every 8 hours
 *   and keeps the prior two STEKs around, so ticket lifetime is 24 hours.
 *   This is fine for use with a single lighttpd instance, but with multiple
 *   lighttpd workers, no coordinated STEK (server ticket encryption key)
 *   rotation occurs unless ssl.stek-file is defined and maintained (preferred),
 *   or if some external job restarts lighttpd.  Restarting lighttpd generates a
 *   new key that is shared by lighttpd workers for the lifetime of the new key.
 *   If the rotation period expires and lighttpd has not been restarted, and if
 *   ssl.stek-file is not in use, then lighttpd workers will generate new
 *   independent keys, making session tickets less effective for session
 *   resumption, since clients have a lower chance for future connections to
 *   reach the same lighttpd worker.  However, things will still work, and a new
 *   session will be created if session resumption fails.  Admins should plan to
 *   restart lighttpd at least every 8 hours if session tickets are enabled and
 *   multiple lighttpd workers are configured.  Since that is likely disruptive,
 *   if multiple lighttpd workers are configured, ssl.stek-file should be
 *   defined and the file maintained externally.
 */
/*
 * BoringSSL and AWS-LC (fork of BoringSSL) have OpenSSL an compatibility layer
 * and may be used instead of openssl, though functionality should be carefully
 * tested to ensure all the features of TLS required for *your* environment work
 * as expected.  BoringSSL and AWS-LC do not fully reimplement all of OpenSSL,
 * and behavior may differ from OpenSSL behavior.
 *
 * AWS-LC disables the auto-chaining feature by default, though if interested in
 * performance, you should not be relying on auto-chaining and should be
 * providing certificate chains including intermediates, e.g. fullchain.pem.
 * BoringSSL disables the auto-chaining feature when SSL_CREDENTIAL is used,
 * which is now how this module configures certificate selected for connection.
 * BoringSSL disables auto-chaining when using TLS_with_buffers_method()
 * optimization, but SSL_CREDENTIAL use already made auto-chaining unavailable.
 *
 * See BUILDING.md in BoringSSL source tree for BoringSSL build instructions.
 * Choose CMAKE_BUILD_TYPE (e.g. Release, MinSizeRel, RelWithDebInfo, etc.)
 * If choosing to build BoringSSL as shared library:
 *   cmake -GNinja -B build -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_SHARED_LIBS=1
 *   ninja -C build
 * If choosing to build BoringSSL as static library to link with mod_openssl.so:
 *   cmake -GNinja -B build -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_POSITION_INDEPENDENT_CODE=ON
 *   ninja -C build
 * Configure lighttpd build
 *   --with-boringssl
 *   --with-boringssl-includes=/path/to/boringssl/include
 *   --with-boringssl-libs=/path/to/boringssl/build
 * If linking lighttpd against dynamic BoringSSL libs, run lighttpd with
 *   LD_LIBRARY_PATH=/path/to/boringssl/build
 * If linking lighttpd mod_openssl.so against static BoringSSL libs,
 * - static BoringSSL build needs: cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON
 * - mod_openssl.so link must be modified to include: -lssl -lcrypto -lstdc++
 *   (not the default -lssl -lcrypto)
 *
 * Note: BoringSSL can be built single-threaded to reduce locking overhead.
 * Since lighttpd is not currently threaded, then if lighttpd is built against
 * static libraries for BoringSSL, BoringSSL could be built with
 *   -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED
 * as long as those static libs were linked only into single-threaded programs.
 * Note: AWS-LC sets this define for certain specific embedded targets in the
 * AWS-LC source code include/openssl/target.h
 *
 * lighttpd providing OCSP stapled responses is supported with BoringSSL,
 * though there are some limitations: the OCSP staple is not parsed for
 * nextUpdate, so the ssl.stapling-file is reloaded hourly.  Also, the
 * certificate is not parsed for the OCSP Must-Staple flag.  If not using
 * OCSP stapling, lighttpd mod_openssl.c can be told to omit the code here
 * by *commenting out* #undef OPENSSL_NO_OCSP below.
 *
 * To allow for removal of older code paths, this module requires at least
 *   BORINGSSL_API_VERSION >= 3 for TLS_with_buffers_method()
 *   BORINGSSL_API_VERSION >= 5 for BoringSSL impl of various OpenSSL 1.1.0 APIs
 *   BORINGSSL_API_VERSION >= 17 for ECH APIs
 *   BORINGSSL_API_VERSION >= 19 for ASN1_TIME_to_posix()
 *   BORINGSSL_API_VERSION >= 19 for SSL_CTX_set1_groups_list()
 *   BORINGSSL_API_VERSION >= 32 for SSL_CREDENTIAL APIs (unsupported in AWS-LC)
 *   BORINGSSL_API_VERSION >= 32 (~Mar 2024; you should use newer)
 */
#include "first.h"

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-time.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
#undef OCSP_REQUEST /*(defined in wincrypt.h)*/
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pool.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#ifdef AWSLC_API_VERSION /* alt: OPENSSL_IS_AWSLC */
/* AWS-LC derived from BoringSSL, but AWSLC_API_VERSION has different meaning.
 * Reuse BORINGSSL_API_VERSION for (presently) small num of API version checks*/
/* XXX: AWS-LC does not currently support BoringSSL SSL_CREDENTIAL
 * The last commit which was able to build mod_openssl.c (not mod_boringssl.c)
 * against AWS-LC was commit 5ac7eecb */
#ifndef BORINGSSL_API_VERSION
#define BORINGSSL_API_VERSION 19
#endif
#endif
#ifndef BORINGSSL_API_VERSION
#error "mod_boringssl.c build detected non-BoringSSL headers"
#endif
#if BORINGSSL_API_VERSION < 32
#error "mod_boringssl.c build detected old BoringSSL headers"
#endif
#include <openssl/hmac.h>
/* BoringSSL purports to have some OCSP support in C++ pki/ocsp.h
 * but does not provide <openssl/ocsp.h> and sets OPENSSL_NO_OCSP
 * in <openssl/opensslconf.h>, included by <openssl/base.h> */
#undef OPENSSL_NO_OCSP

#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif

#ifndef OPENSSL_NO_ECH
#include <openssl/hpke.h>
#ifndef TLSEXT_TYPE_ech
#define TLSEXT_TYPE_ech TLSEXT_TYPE_encrypted_client_hello
#endif
#ifndef OSSL_ECH_FOR_RETRY
#define OSSL_ECH_FOR_RETRY 1
#endif
#ifndef SSL_ECH_STATUS_SUCCESS
#define SSL_ECH_STATUS_SUCCESS 1
#endif
#endif

#include "base.h"
#include "base64.h"
#include "ck.h"
#include "fdevent.h"
#include "http_date.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "plugin.h"
#include "sock_addr.h"

typedef struct mod_openssl_kp {
    SSL_CREDENTIAL *cred;
    EVP_PKEY *ssl_pemfile_pkey;
    CRYPTO_BUFFER **ssl_pemfile_x509;
    size_t ssl_pemfile_chain;
    CRYPTO_BUFFER *ssl_stapling_der;
    int refcnt;
    int8_t must_staple;
    int8_t self_issued;
    unix_time64_t ssl_stapling_loadts;
    unix_time64_t ssl_stapling_nextts;
    struct mod_openssl_kp *next;
} mod_openssl_kp;

typedef struct {
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    mod_openssl_kp *kp; /* parsed public/private key structures */
    const buffer *ssl_pemfile;
    const buffer *ssl_privkey;
    const buffer *ssl_stapling_file;
    unix_time64_t pkey_ts;
} plugin_cert;

typedef struct {
    SSL_CTX *ssl_ctx;
    plugin_cert *pc;
    mod_openssl_kp *kp;
    buffer *ech_keydir;
    uint32_t ech_keydir_refresh_interval;
    unix_time64_t ech_keydir_refresh_ts;
    const array *ech_public_hosts;
} plugin_ssl_ctx;

typedef struct {
    STACK_OF(CRYPTO_BUFFER) *names;
    X509_STORE *store;
    STACK_OF(X509_CRL) *sk_crls;
    const char *crl_file;
    unix_time64_t crl_loadts;
} plugin_cacerts;

typedef struct {
    SSL_CTX *ssl_ctx; /* output from network_init_ssl() */

    /*(used only during startup; not patched)*/
    unsigned char ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned char ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    const buffer *ssl_cipher_list;
    array *ssl_conf_cmd;
    array *ech_opts;

    /*(copied from plugin_data for socket ssl_ctx config)*/
    plugin_cert *pc;
    const plugin_cacerts *ssl_ca_file;
    STACK_OF(CRYPTO_BUFFER) *ssl_ca_dn_file;
    const buffer *ssl_ca_crl_file;
    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;
    unsigned char ssl_read_ahead;
} plugin_config_socket; /*(used at startup during configuration)*/

typedef struct {
    /* SNI per host: w/ COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    plugin_cert *pc;
    const plugin_cacerts *ssl_ca_file;
    STACK_OF(CRYPTO_BUFFER) *ssl_ca_dn_file;
    const buffer *ssl_ca_crl_file;

    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;
    unsigned char ssl_verifyclient_export_cert;
    unsigned char ssl_read_ahead;
    unsigned char ssl_log_noise;
    const buffer *ssl_verifyclient_username;
    const buffer *ssl_acme_tls_1;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_ssl_ctx **ssl_ctxs;
    plugin_config defaults;
    server *srv;
    array *ech_only_hosts;
    const char *ssl_stek_file;
    CRYPTO_BUFFER_POOL *cbpool;
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[mod_boringssl_plugin_data->id]; */
static plugin_data *mod_boringssl_plugin_data;
#define LOCAL_SEND_BUFSIZE (16 * 1024)
static char *local_send_buffer;
static int feature_refresh_certs;
static int feature_refresh_crls;

typedef struct {
    SSL *ssl;
    request_st *r;
    connection *con;
    short renegotiations; /* count of SSL_CB_HANDSHAKE_START */
    short close_notify;
    uint8_t alpn;
    uint8_t ech_only_policy;
    plugin_config conf;
    log_error_st *errh;
    mod_openssl_kp *kp;
    plugin_cert *ssl_ctx_pc;
    const array *ech_only_hosts;
    const array *ech_public_hosts;
} handler_ctx;


__attribute_cold__
static mod_openssl_kp *
mod_openssl_kp_init (void)
{
    mod_openssl_kp * const kp = ck_calloc(1, sizeof(*kp));
    kp->refcnt = 1;
    kp->cred = SSL_CREDENTIAL_new_x509();
    ck_assert(kp->cred);
    return kp;
}


__attribute_cold__
static void
mod_openssl_kp_free (mod_openssl_kp *kp)
{
    SSL_CREDENTIAL_free(kp->cred);
    EVP_PKEY_free(kp->ssl_pemfile_pkey);
    for (size_t i = 0; i < kp->ssl_pemfile_chain; ++i)
        CRYPTO_BUFFER_free(kp->ssl_pemfile_x509[i]);
    free(kp->ssl_pemfile_x509);
    CRYPTO_BUFFER_free(kp->ssl_stapling_der);
    free(kp);
}


static mod_openssl_kp *
mod_openssl_kp_acq (plugin_cert *pc)
{
    mod_openssl_kp *kp = pc->kp;
    ++kp->refcnt;
    return kp;
}


static void
mod_openssl_kp_rel (mod_openssl_kp *kp)
{
    --kp->refcnt;
}


static handler_ctx *
handler_ctx_init (void)
{
    return ck_calloc(1, sizeof(handler_ctx));
}


static void
handler_ctx_free (handler_ctx *hctx)
{
    if (hctx->ssl) SSL_free(hctx->ssl);
    if (hctx->kp)
        mod_openssl_kp_rel(hctx->kp);
    free(hctx);
}


__attribute_cold__
__attribute_noinline__
static void
elog (log_error_st * const errh, const char * const file, const int line,
      const char * const msg)
{
    /* error logging convenience function which decodes err codes */
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf)); /*(thread-safe)*/
    log_error(errh, file, line, "SSL: %s %s", msg, buf);
}


__attribute_cold__
__attribute_format__((__printf__, 4, 5))
__attribute_noinline__
static void
elogf (log_error_st * const errh, const char * const file, const int line,
       const char * const fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    elog(errh, file, line, msg);
}


__attribute_cold__
__attribute_noinline__
static void
elogc (handler_ctx * const hctx,
       const char * const file, const int line, const int ssl_err)
{
    char buf[256];
    uint32_t err;
    while ((err = ERR_get_error())) {
        switch (ERR_GET_REASON(err)) {
          case SSL_R_SSL_HANDSHAKE_FAILURE:
        #ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
          case SSL_R_UNEXPECTED_EOF_WHILE_READING:
        #endif
        #ifdef SSL_R_TLSV1_ALERT_UNKNOWN_CA
          case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
        #endif
        #ifdef SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN
          case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
        #endif
        #ifdef SSL_R_SSLV3_ALERT_BAD_CERTIFICATE
          case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
        #endif
            if (!hctx->conf.ssl_log_noise) continue;
            break;
          default:
            break;
        }
        ERR_error_string_n(err, buf, sizeof(buf)); /*(thread-safe interface)*/
        log_error(hctx->r->conf.errh, file, line, "SSL: addr:%s ssl_err:%d %s",
                  hctx->con->dst_addr_buf.ptr, ssl_err, buf);
    }
}


#define PEM_BEGIN          "-----BEGIN "
#define PEM_END            "-----END "
#define PEM_BEGIN_CERT     "-----BEGIN CERTIFICATE-----"
#define PEM_END_CERT       "-----END CERTIFICATE-----"
#define PEM_BEGIN_TRUSTED_CERT "-----BEGIN TRUSTED CERTIFICATE-----"
#define PEM_END_TRUSTED_CERT   "-----END TRUSTED CERTIFICATE-----"
#define PEM_BEGIN_PKEY     "-----BEGIN PRIVATE KEY-----"
#define PEM_END_PKEY       "-----END PRIVATE KEY-----"
#define PEM_BEGIN_EC_PKEY  "-----BEGIN EC PRIVATE KEY-----"
#define PEM_END_EC_PKEY    "-----END EC PRIVATE KEY-----"
#define PEM_BEGIN_RSA_PKEY "-----BEGIN RSA PRIVATE KEY-----"
#define PEM_END_RSA_PKEY   "-----END RSA PRIVATE KEY-----"
#define PEM_BEGIN_DSA_PKEY "-----BEGIN DSA PRIVATE KEY-----"
#define PEM_END_DSA_PKEY   "-----END DSA PRIVATE KEY-----"
#define PEM_BEGIN_ANY_PKEY "-----BEGIN ANY PRIVATE KEY-----"
#define PEM_END_ANY_PKEY   "-----END ANY PRIVATE KEY-----"
/* (not implemented: support to get password from user for encrypted key) */
#define PEM_BEGIN_ENCRYPTED_PKEY "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define PEM_END_ENCRYPTED_PKEY   "-----END ENCRYPTED PRIVATE KEY-----"

#define PEM_BEGIN_X509_CRL "-----BEGIN X509 CRL-----"
#define PEM_END_X509_CRL   "-----END X509 CRL-----"


__attribute_pure__
static int
asn1_pem_begins (const struct iovec *iov, const char *label, size_t llen)
{
    /*(presumes input string already matched PEM_BEGIN)*/
    /*assert(llen > (sizeof(PEM_BEGIN)-1) + 4);*/
    size_t len = iov->iov_len - 1;                   /* remove '\n' */
    len -= (((char *)iov->iov_base)[len-1] == '\r'); /* remove '\r' */
    return len == llen /*(compare middle of string until first trailing '-')*/
        && 0 == memcmp((char *)iov->iov_base + (sizeof(PEM_BEGIN)-1),
                                       label + (sizeof(PEM_BEGIN)-1),
                                       llen  - (sizeof(PEM_BEGIN)-1) - 4);
}


__attribute_pure__
static int
asn1_pem_begins_pkey (const struct iovec *iov)
{
    /*(presumes input string already matched PEM_BEGIN)*/
    size_t len = iov->iov_len - 1;                   /* remove '\n' */
    len -= (((char *)iov->iov_base)[len-1] == '\r'); /* remove '\r' */
    /*(compare middle of string until first trailing '-')*/
    return len >= (sizeof(PEM_BEGIN)-1) + (sizeof("PRIVATE KEY-")-1) + 4
        && 0 == memcmp((char *)iov->iov_base
                         + iov->iov_len
                         - (iov->iov_len - len)
                         - (sizeof("PRIVATE KEY-")-1) - 4,
                       "PRIVATE KEY-", (sizeof("PRIVATE KEY-")-1));
}


static struct iovec *
asn1_pem_parse_mem (char *data, size_t dlen, size_t *nvec)
{
    /* intended for use on small files which are infrequently read;
     *   not optimized for highest performance */
    /* (note: using strstr() and strchr() requires that data[dlen] == '\0') */
    /* (could be written to use memmem(), but not quite as portable) */
    /* (could be written to walk data once and resize vec as needed) */
    size_t count = 0;
    for (char *b = data; (b = strstr(b, PEM_BEGIN)); b += sizeof(PEM_BEGIN)-1)
        ++count;
    if (0 == count) {
        if (NULL == strstr(data, "-----")) {
            /* does not look like PEM, treat as DER format */
            *nvec = 1;
            struct iovec * const iov = ck_malloc(sizeof(struct iovec));
            iov[0].iov_base = data;
            iov[0].iov_len  = dlen;
            return iov;
        }
        return NULL;
    }

    *nvec = count * 3;
    struct iovec * const vec = ck_calloc(*nvec, sizeof(struct iovec));
    struct iovec * iov = vec;
    for (char *b, *e = data; (b = strstr(e, PEM_BEGIN)); iov += 3) {
        e = strchr(b + sizeof(PEM_BEGIN)-1, '\n');
        if (NULL == e) break;
        iov[0].iov_base = b;
        iov[0].iov_len  = (size_t)(++e - b);
        iov[1].iov_base = b = e;
        e = strstr(b, PEM_END);
        if (NULL == e) break;
        iov[1].iov_len  = (size_t)(e - b);
        iov[2].iov_base = b = e;
        e = strchr(b + sizeof(PEM_END)-1, '\n');
        if (NULL == e) break;
        iov[2].iov_len  = (size_t)(++e - b);
    }
    if (iov != (vec + *nvec)) {
        free(vec);
        return NULL;
    }

    return vec;
}


/*
 * Note: nvec == 1 suggests vec[0].iov_base is DER format
 *       nvec being multiple of 3 is PEM format, 3 iovecs per PEM item
 *         -----BEGIN ... -----
 *         <base64-encoded data>
 *         -----END ... -----
 *       (If passing each PEM item to a subsequent func for PEM-decoding,
 *        the PEM item is vec[i].iov_base with length
 *        (vec[i].iov_len + vec[i+1].iov_len + vec[i+2].iov_len))
 *
 * Callback should copy data of interest and should wipe buffers
 * of sensitive copies (e.g. after base64-decoding PEM -> DER).
 */
typedef void *(*asn1_pem_parse_cb)(void *cb_arg, struct iovec *vec, size_t nvec);


static void *
asn1_pem_parse_file (const char *fn, log_error_st *errh, asn1_pem_parse_cb cb, void *cb_arg)
{
    /* (note: dlen must be < 4 GB if 64-bit off_t and 32-bit size_t) */
    off_t dlen = 16*1024*1024;/*(arbitrary limit: 16 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;

    size_t nvec;
    struct iovec *vec = asn1_pem_parse_mem(data, (size_t)dlen, &nvec);
    void *rv = (NULL != vec) ? cb(cb_arg, vec, nvec) : NULL;

    if (dlen) ck_memzero(data, dlen);
    free(data);

    return rv;
}


__attribute_cold__
static void *
mod_boringssl_pem_parse_certs_cb (void *cb_arg, struct iovec *vec, size_t nvec)
{
    CRYPTO_BUFFER **certs;
    CRYPTO_BUFFER_POOL * const cbpool =
      *(size_t *)cb_arg ? mod_boringssl_plugin_data->cbpool : NULL;
    /*(cb_arg overloaded as input flag for 'use_pool' or not)*/

    if (1 == nvec) { /* treat data as single DER */
        certs = ck_malloc(sizeof(CRYPTO_BUFFER *));
        certs[0] = CRYPTO_BUFFER_new(vec[0].iov_base, vec[0].iov_len, cbpool);
        if (certs[0] == NULL) {
            free(certs);
            return NULL;
        }
        *(size_t *)cb_arg = 1; /* ncerts */
        return certs;
    }

    size_t ncerts = 0, i;
    for (i = 0; i < nvec; i += 3) {
        if (asn1_pem_begins(vec+i, CONST_STR_LEN(PEM_BEGIN_CERT))
            || asn1_pem_begins(vec+i, CONST_STR_LEN(PEM_BEGIN_TRUSTED_CERT)))
            vec[ncerts++] = vec[i+1];
    }
    if (0 == ncerts)
        return NULL;

    certs = ck_calloc(ncerts, sizeof(CRYPTO_BUFFER *));
    buffer * const tb = buffer_init();
    for (i = 0; i < ncerts; ++i) {
        buffer_clear(tb);
        if (NULL == buffer_append_base64_decode(tb, vec[i].iov_base,
                                                    vec[i].iov_len,
                                                BASE64_STANDARD))
            break;
        certs[i] = CRYPTO_BUFFER_new((uint8_t *)BUF_PTR_LEN(tb), cbpool);
        if (NULL == certs[i])
            break;
    }
    buffer_free(tb);

    if (i == ncerts) {
        *(size_t *)cb_arg = ncerts;
    }
    else if (certs) {
        while (i) CRYPTO_BUFFER_free(certs[--i]);
        free(certs);
        certs = NULL;
    }

    return certs;
}


__attribute_cold__
static void *
mod_boringssl_pem_parse_evp_pkey_cb (void *cb_arg, struct iovec *vec, size_t nvec)
{
    UNUSED(cb_arg);

    if (1 == nvec) { /* treat data as single DER */
        const uint8_t *d = (uint8_t *)vec[0].iov_base;
        return d2i_AutoPrivateKey(NULL, &d, vec[0].iov_len);
    }

    for (size_t i = 0; i < nvec; i += 3) {
        if (asn1_pem_begins_pkey(vec+i)) {
            EVP_PKEY *x = NULL;
            buffer * const tb = buffer_init();
            const uint8_t *d = (uint8_t *)
              buffer_append_base64_decode(tb, vec[i+1].iov_base,
                                              vec[i+1].iov_len,
                                          BASE64_STANDARD);
            if (d)
                x = d2i_AutoPrivateKey(NULL, &d, buffer_clen(tb));
            ck_memzero(tb->ptr, buffer_clen(tb));
            buffer_free(tb);
            return x;
        }
    }

    return NULL;
}


__attribute_cold__
static void *
mod_boringssl_pem_parse_crls_cb (void *cb_arg, struct iovec *vec, size_t nvec)
{
    UNUSED(cb_arg);
    STACK_OF(X509_CRL) *sk_crls = sk_X509_CRL_new_null();

    if (1 == nvec) { /* treat data as single DER */
        const uint8_t *dp = (uint8_t *)vec[0].iov_base;
        X509_CRL *crl = d2i_X509_CRL(NULL, &dp, (long)vec[0].iov_len);
        if (!crl || !sk_X509_CRL_push(sk_crls, crl)) {
            X509_CRL_free(crl);
            sk_X509_CRL_free(sk_crls);
            return NULL;
        }
        return sk_crls;
    }

    size_t ncrls = 0, i;
    for (i = 0; i < nvec; i += 3) {
        if (asn1_pem_begins(vec+i, CONST_STR_LEN(PEM_BEGIN_X509_CRL)))
            vec[ncrls++] = vec[i+1];
    }
    if (0 == ncrls)
        return NULL;

    buffer * const tb = buffer_init();
    for (i = 0; i < ncrls; ++i) {
        buffer_clear(tb);
        if (NULL == buffer_append_base64_decode(tb, vec[i].iov_base,
                                                    vec[i].iov_len,
                                                BASE64_STANDARD))
            break;
        const uint8_t *dp = (uint8_t *)tb->ptr;
        X509_CRL *crl = d2i_X509_CRL(NULL, &dp, (long)buffer_clen(tb));
        if (!crl || !sk_X509_CRL_push(sk_crls, crl)) {
            X509_CRL_free(crl);
            break;
        }
    }
    buffer_free(tb);

    if (i != ncrls) {
        sk_X509_CRL_pop_free(sk_crls, X509_CRL_free);
        sk_crls = NULL;
    }

    return sk_crls;
}


#ifdef TLSEXT_TYPE_session_ticket
/* ssl/ssl_local.h */
#define TLSEXT_KEYNAME_LENGTH  16
#define TLSEXT_TICK_KEY_LENGTH 32

/* openssl has a huge number of interfaces, but not the most useful;
 * construct our own session ticket encryption key structure */
typedef struct tlsext_ticket_key_st {
    unix_time64_t active_ts; /* tickets not issued w/ key until activation ts*/
    unix_time64_t expire_ts; /* key not valid after expiration timestamp */
    unsigned char tick_key_name[TLSEXT_KEYNAME_LENGTH];
    unsigned char tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    unsigned char tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
} tlsext_ticket_key_t;

static tlsext_ticket_key_t session_ticket_keys[4];
static unix_time64_t stek_rotate_ts;


static int
mod_openssl_session_ticket_key_generate (unix_time64_t active_ts, unix_time64_t expire_ts)
{
    /* openssl RAND_*bytes() functions are called multiple times since the
     * funcs might have a 32-byte limit on number of bytes returned each call
     *
     * (Note: session ticket encryption key generation is not expected to fail)
     *
     * 3 keys are stored in session_ticket_keys[]
     * The 4th element of session_ticket_keys[] is used for STEK construction
     */
    /*(RAND_priv_bytes() not in openssl 1.1.0; introduced in openssl 1.1.1)*/
  #define RAND_priv_bytes(x,sz) RAND_bytes((x),(sz))
    if (RAND_bytes(session_ticket_keys[3].tick_key_name,
                   TLSEXT_KEYNAME_LENGTH) <= 0
        || RAND_priv_bytes(session_ticket_keys[3].tick_hmac_key,
                           TLSEXT_TICK_KEY_LENGTH) <= 0
        || RAND_priv_bytes(session_ticket_keys[3].tick_aes_key,
                           TLSEXT_TICK_KEY_LENGTH) <= 0)
        return 0;
    session_ticket_keys[3].active_ts = active_ts;
    session_ticket_keys[3].expire_ts = expire_ts;
    return 1;
}


static void
mod_openssl_session_ticket_key_rotate (void)
{
    /* discard oldest key (session_ticket_keys[2]) and put newest key first
     * 3 keys are stored in session_ticket_keys[0], [1], [2]
     * session_ticket_keys[3] is used to construct and pass new STEK */

    session_ticket_keys[2] = session_ticket_keys[1];
    session_ticket_keys[1] = session_ticket_keys[0];
    /*memmove(session_ticket_keys+1,
              session_ticket_keys+0, sizeof(tlsext_ticket_key_t)*2);*/
    session_ticket_keys[0] = session_ticket_keys[3];

    OPENSSL_cleanse(session_ticket_keys+3, sizeof(tlsext_ticket_key_t));
}


static tlsext_ticket_key_t *
tlsext_ticket_key_get (void)
{
    const unix_time64_t cur_ts = log_epoch_secs;
    const int e = sizeof(session_ticket_keys)/sizeof(*session_ticket_keys) - 1;
    for (int i = 0; i < e; ++i) {
        if (session_ticket_keys[i].active_ts > cur_ts) continue;
        if (session_ticket_keys[i].expire_ts < cur_ts) continue;
        return &session_ticket_keys[i];
    }
    return NULL;
}


static tlsext_ticket_key_t *
tlsext_ticket_key_find (unsigned char key_name[16], int *refresh)
{
    *refresh = 0;
    const unix_time64_t cur_ts = log_epoch_secs;
    const int e = sizeof(session_ticket_keys)/sizeof(*session_ticket_keys) - 1;
    for (int i = 0; i < e; ++i) {
        if (session_ticket_keys[i].expire_ts < cur_ts) continue;
        if (0 == memcmp(session_ticket_keys[i].tick_key_name, key_name, 16))
            return &session_ticket_keys[i];
        if (session_ticket_keys[i].active_ts <= cur_ts)
            *refresh = 1; /* newer active key is available */
    }
    return NULL;
}


static void
tlsext_ticket_wipe_expired (const unix_time64_t cur_ts)
{
    const int e = sizeof(session_ticket_keys)/sizeof(*session_ticket_keys) - 1;
    for (int i = 0; i < e; ++i) {
        if (session_ticket_keys[i].expire_ts != 0
            && session_ticket_keys[i].expire_ts < cur_ts)
            OPENSSL_cleanse(session_ticket_keys+i, sizeof(tlsext_ticket_key_t));
    }
}


/* based on reference implementation from openssl 1.1.1g man page
 *   man SSL_CTX_set_tlsext_ticket_key_cb
 * but mod_openssl code uses EVP_aes_256_cbc() instead of EVP_aes_128_cbc()
 */
static int
ssl_tlsext_ticket_key_cb (SSL *s, unsigned char key_name[16],
                          unsigned char iv[EVP_MAX_IV_LENGTH],
                          EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
    UNUSED(s);
    if (enc) { /* create new session */
        tlsext_ticket_key_t *k = tlsext_ticket_key_get();
        if (NULL == k)
            return 0; /* current key does not exist or is not valid */
        memcpy(key_name, k->tick_key_name, 16);
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) <= 0)
            return -1; /* insufficient random */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k->tick_aes_key, iv);
        HMAC_Init_ex(hctx, k->tick_hmac_key, sizeof(k->tick_hmac_key),
                     EVP_sha256(), NULL);
        return 1;
    }
    else { /* retrieve session */
        int refresh;
        tlsext_ticket_key_t *k = tlsext_ticket_key_find(key_name, &refresh);
        if (NULL == k)
            return 0;
        HMAC_Init_ex(hctx, k->tick_hmac_key, sizeof(k->tick_hmac_key),
                     EVP_sha256(), NULL);
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k->tick_aes_key, iv);
        return refresh ? 2 : 1;
        /* 'refresh' will trigger issuing new ticket for session
         * even though the current ticket is still valid */
    }
}


static int
mod_openssl_session_ticket_key_file (const char *fn)
{
    /* session ticket encryption key (STEK)
     *
     * STEK file should be stored in non-persistent storage,
     *   e.g. /dev/shm/lighttpd/stek-file  (in memory)
     * with appropriate permissions set to keep stek-file from being
     * read by other users.  Where possible, systems should also be
     * configured without swap.
     *
     * admin should schedule an independent job to periodically
     *   generate new STEK up to 3 times during key lifetime
     *   (lighttpd stores up to 3 keys)
     *
     * format of binary file is:
     *    4-byte - format version (always 0; for use if format changes)
     *    4-byte - activation timestamp
     *    4-byte - expiration timestamp
     *   16-byte - session ticket key name
     *   32-byte - session ticket HMAC encrpytion key
     *   32-byte - session ticket AES encrpytion key
     *
     * STEK file can be created with a command such as:
     *   dd if=/dev/random bs=1 count=80 status=none | \
     *     perl -e 'print pack("iii",0,time()+300,time()+86400),<>' \
     *     > STEK-file.$$ && mv STEK-file.$$ STEK-file
     *
     * The above delays activation time by 5 mins (+300 sec) to allow file to
     * be propagated to other machines.  (admin must handle this independently)
     * If STEK generation is performed immediately prior to starting lighttpd,
     * admin should activate keys immediately (without +300).
     */
    int buf[23]; /* 92 bytes */
    int rc = 0; /*(will retry on next check interval upon any error)*/
    if (0 != fdevent_load_file_bytes((char *)buf,(off_t)sizeof(buf),0,fn,NULL))
        return rc;
    if (buf[0] == 0) { /*(format version 0)*/
        session_ticket_keys[3].active_ts = TIME64_CAST(buf[1]);
        session_ticket_keys[3].expire_ts = TIME64_CAST(buf[2]);
      #ifndef __COVERITY__ /* intentional; hide from Coverity Scan */
        /* intentionally copy 80 bytes into consecutive arrays
         * tick_key_name[], tick_hmac_key[], tick_aes_key[] */
        memcpy(&session_ticket_keys[3].tick_key_name, buf+3, 80);
      #endif
        rc = 1;
    }

    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}


static void
mod_openssl_session_ticket_key_check (const plugin_data *p, const unix_time64_t cur_ts)
{
    static unix_time64_t detect_retrograde_ts;
    if (detect_retrograde_ts > cur_ts && detect_retrograde_ts - cur_ts > 28800)
        stek_rotate_ts = 0;
    detect_retrograde_ts = cur_ts;

    int rotate = 0;
    if (p->ssl_stek_file) {
        struct stat st;
        if (0 == stat(p->ssl_stek_file, &st)
            && TIME64_CAST(st.st_mtime) > stek_rotate_ts)
            rotate = mod_openssl_session_ticket_key_file(p->ssl_stek_file);
        tlsext_ticket_wipe_expired(cur_ts);
    }
    else if (cur_ts - 28800 >= stek_rotate_ts || 0 == stek_rotate_ts)/*(8 hrs)*/
        rotate = mod_openssl_session_ticket_key_generate(cur_ts, cur_ts+86400);

    if (rotate) {
        mod_openssl_session_ticket_key_rotate();
        stek_rotate_ts = cur_ts;
    }
}

#endif /* TLSEXT_TYPE_session_ticket */


#ifndef OPENSSL_NO_ECH

__attribute_pure__
static const buffer *
mod_openssl_refresh_ech_key_is_ech_only(plugin_ssl_ctx * const s, const char * const h, size_t hlen)
{
    /* (similar to mod_openssl_ech_only(), but without hctx) */
    const array * const ech_only_hosts =
      mod_boringssl_plugin_data->ech_only_hosts;
    if (ech_only_hosts) {
        const data_unset *du = array_get_element_klen(ech_only_hosts, h, hlen);
        if (du) return &((const data_string *)du)->value;
    }

    const array * const ech_public_hosts = s->ech_public_hosts;
    if (ech_public_hosts
        && NULL == array_get_element_klen(ech_public_hosts, h, hlen)) {
        /*(return first host in ech_public_hosts list as public-name)*/
        return &ech_public_hosts->data[0]->key;
    }

    return NULL;
}

#define PEM_BEGIN_ECHCONFIG "-----BEGIN ECHCONFIG-----"
#define PEM_END_ECHCONFIG   "-----END ECHCONFIG-----"

struct ech_keys_cb_param {
  SSL_ECH_KEYS *keys;
  int is_retry_config;
  buffer *tmp_buf;
};

__attribute_cold__
static void *
mod_boringssl_pem_parse_ech_keys_cb (void *cb_arg, struct iovec *vec, size_t nvec)
{
    struct iovec *vec_pkey = NULL;
    struct iovec *vec_echconfig = NULL;
    for (size_t i = 0; i < nvec; i += 3) {
        if (asn1_pem_begins(vec+i, CONST_STR_LEN(PEM_BEGIN_PKEY))) {
            if (!vec_pkey) /*(expecting only one; take first one)*/
                vec_pkey = vec+i+1;
        }
        else if (asn1_pem_begins(vec+i, CONST_STR_LEN(PEM_BEGIN_ECHCONFIG))) {
            if (!vec_echconfig) /*(expecting only one; take first one)*/
                vec_echconfig = vec+i+1;
        }
    }
    if (!vec_pkey || !vec_echconfig)
        return NULL;

    int rv = 0;
    EVP_HPKE_KEY key;
    EVP_HPKE_KEY_zero(&key);
    const struct ech_keys_cb_param * const params = cb_arg;
    buffer * const tb = params->tmp_buf;
    do {
        buffer_clear(tb);
        if (NULL == buffer_append_base64_decode(tb, vec_pkey->iov_base,
                                                    vec_pkey->iov_len,
                                                BASE64_STANDARD))
            break;

        const uint8_t *x = (uint8_t *)tb->ptr;
        EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &x, (long)buffer_clen(tb));
        /*(BoringSSL tools/bssl outputs raw pkey;
         * handle if that output is subsequently base64-encoded raw pkey)*/
        /*if (NULL == pkey) break;*/

        const EVP_HPKE_KEM * const kem = (pkey == NULL)
          ? EVP_hpke_x25519_hkdf_sha256()
          : EVP_PKEY_id(pkey) == EVP_PKEY_X25519 /* NID_X25519 */
          ? EVP_hpke_x25519_hkdf_sha256()
         #ifndef AWSLC_API_VERSION
          : EVP_PKEY_id(pkey) == EVP_PKEY_EC /* NID_X9_62_id_ecPublicKey */
          ? EVP_hpke_p256_hkdf_sha256()
         #endif
          : NULL;
        if (NULL == kem) {
            EVP_PKEY_free(pkey);
            break;
        }

        size_t out_len = buffer_clen(tb); /*should be large enough tmp_buf*/
        rv = (pkey)
          ? EVP_PKEY_get_raw_private_key(pkey, (uint8_t *)tb->ptr, &out_len)
          : 1;
        EVP_PKEY_free(pkey);
        if (0 == rv)
            break;
        rv = 0;

        EVP_HPKE_KEY_zero(&key);
        if (!EVP_HPKE_KEY_init(&key, kem, (uint8_t *)tb->ptr, out_len))
            break;

        ck_memzero(tb->ptr, buffer_clen(tb));

        buffer_clear(tb);
        if (NULL == buffer_append_base64_decode(tb, vec_echconfig->iov_base,
                                                    vec_echconfig->iov_len,
                                                BASE64_STANDARD))
            break;

        /* OpenSSL tool 'openssl ech' ECHConfig begins with 2-byte len;
         * BoringSSL 'tool/bssl generate-ech' ECHConfig does not */
        if (buffer_clen(tb) > 2
            && (uint32_t)((tb->ptr[0]<<4)|tb->ptr[1]) == buffer_clen(tb)-2){
            memmove(tb->ptr, tb->ptr+2, buffer_clen(tb)-2);
            buffer_truncate(tb, buffer_clen(tb)-2);
        }

        rv = SSL_ECH_KEYS_add(params->keys, params->is_retry_config,
                              (uint8_t *)BUF_PTR_LEN(tb), &key);
    } while (0);
    ck_memzero(tb->ptr, buffer_clen(tb));
    EVP_HPKE_KEY_cleanup(&key);

    return rv ? params->keys : NULL; /*((void *) 'flag' for success or fail)*/
}


#include "sys-dirent.h"
static int
mod_openssl_refresh_ech_keys_ctx (server * const srv, plugin_ssl_ctx * const s, const unix_time64_t cur_ts)
{
    if (NULL == s->ech_keydir)
        return 1;
    if (0 != s->ech_keydir_refresh_ts
        && s->ech_keydir_refresh_ts + s->ech_keydir_refresh_interval > cur_ts)
        return 1;

    /* collect *.ech from s->ech_keydir
     * order matters, so load into array for predictable ordering
     * and allow admin to name files with prefixes for desired order
     * (note: array uses case-insensitive sort) */

    array a = { NULL, NULL, 0, 0 };

    buffer * const kp = s->ech_keydir;
    const uint32_t dirlen = buffer_clen(kp);
    DIR * const dp = opendir(kp->ptr);
    if (NULL == dp) {
        log_perror(srv->errh,__FILE__,__LINE__,"%s dir:%s",__func__,kp->ptr);
        return 0;
    }

    unix_time64_t lmod = 0;
    struct stat st;
    for (struct dirent *ep; (ep = readdir(dp)); ) {
        uint32_t nlen = (uint32_t)_D_EXACT_NAMLEN(ep);
        if (nlen > 4 && 0 == memcmp(ep->d_name+nlen-4, ".ech", 4)
            && ep->d_name[0] != '.'
            && 0 == stat(kp->ptr, &st)) {
            *(array_get_int_ptr(&a, ep->d_name, nlen)) =
              TIME64_CAST(st.st_mtime) > 1 ? (int)st.st_mtime : 2;
            if (lmod < TIME64_CAST(st.st_mtime))
                lmod = TIME64_CAST(st.st_mtime);
        }
    }

    closedir(dp);

    if (s->ech_keydir_refresh_ts > lmod) {
        s->ech_keydir_refresh_ts = cur_ts;
        array_free_data(&a);
        return 1; /* no changes since last refresh */
    }

    /* walk sorted list, change array values from mtime to retry config flag */
    for (uint32_t i = 0; i < a.used; ++i) {
        buffer * const n = &a.sorted[i]->key;
        int *v = &((data_integer *)a.sorted[i])->value;

        /* (arbitrary convention: allow tag prefix followed by '@' for sort) */
        const char *h = strchr(n->ptr, '@');
        uint32_t hlen = buffer_clen(n);
        if (h)
            hlen -= (uint32_t)(++h - n->ptr);
        else
            h = n->ptr;
        hlen -= (hlen > 8 && 0 == memcmp(h+hlen-8, ".pem", 4)) ? 8 : 4;
        for (uint32_t j = i+1; j < a.used; ++j) {
            /* detect if value already converted to retry config flag */
            int * const nv = &((data_integer *)a.sorted[j])->value;
            if (*nv == 0 || *nv == OSSL_ECH_FOR_RETRY)
                continue;

            const buffer * const next = &a.sorted[j]->key;
            const char *nh = strchr(next->ptr, '@');
            uint32_t nhlen = buffer_clen(next);
            if (nh)
                nhlen -= (uint32_t)(++nh - next->ptr);
            else
                nh = next->ptr;
            nhlen -= (nhlen > 8 && 0 == memcmp(nh+nhlen-8, ".pem", 4)) ? 8 : 4;
            if (nhlen != hlen || 0 != memcmp(nh, h, hlen))
                continue;
            if (*(unsigned int *)v < *(unsigned int *)nv) {
                *v = 0;
                v = nv;
            }
            else {
                ((data_integer *)a.sorted[j])->value = 0;
            }
        }
        /* set retry config flag if newest entry for host and no alternate
         * fallback host; do not set retry config for older keys */
        const buffer * const fallback =
          mod_openssl_refresh_ech_key_is_ech_only(s, h, hlen);
        *v = fallback ? 0 : OSSL_ECH_FOR_RETRY;
    }

    SSL_ECH_KEYS *keys = SSL_ECH_KEYS_new();
    if (keys == NULL) {
        array_free_data(&a);
        return 0;
    }

    struct ech_keys_cb_param cb_arg = { keys, 0, srv->tmp_buf };
    int rc = 1;
    for (uint32_t i = 0; i < a.used; ++i) {
        buffer * const n = &a.sorted[i]->key;
        cb_arg.is_retry_config = ((data_integer *)a.sorted[i])->value;
        buffer_append_path_len(kp, BUF_PTR_LEN(n)); /* *.ech */

        if (!asn1_pem_parse_file(kp->ptr, srv->errh,
                                 mod_boringssl_pem_parse_ech_keys_cb, &cb_arg)){
            elog(srv->errh, __FILE__, __LINE__, kp->ptr);
            rc = 0;
        }

        buffer_truncate(kp, dirlen);
    }

    if (1 != SSL_CTX_set1_ech_keys(s->ssl_ctx, keys))
        rc = 0;
    SSL_ECH_KEYS_free(keys);

    array_free_data(&a);

    if (1 == rc) s->ech_keydir_refresh_ts = cur_ts;
    return rc;
}


static void
mod_openssl_refresh_ech_keys (server * const srv, const plugin_data *p, const unix_time64_t cur_ts)
{
    if (NULL != p->ssl_ctxs) {
        /* refresh ech keys (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[i];
            if (s && s != p->ssl_ctxs[0])
                mod_openssl_refresh_ech_keys_ctx(srv, s, cur_ts);
        }
        /* refresh ech keys from global scope */
        if (p->ssl_ctxs[0])
            mod_openssl_refresh_ech_keys_ctx(srv, p->ssl_ctxs[0], cur_ts);
    }
}


__attribute_pure__
static const buffer *
mod_openssl_ech_only (const handler_ctx * const hctx, const char * const h, size_t hlen)
{
    /* design choice: match host SNI without port
     *   (ech_only_hosts also have port stripped from config string at startup)
     *   (might consider being more precise if sni_ech is canonicalized w/ port
     *    if non-default port)
     */
    const char * const colon = memchr(h, ':', hlen);
    if (colon) hlen = (size_t)(colon - h);

    const array * const ech_only_hosts = hctx->ech_only_hosts;
    const array * const ech_public_hosts = hctx->ech_public_hosts; /*("outer")*/
    if (ech_only_hosts) {
        const data_unset *du = array_get_element_klen(ech_only_hosts, h, hlen);
        if (du) return &((const data_string *)du)->value;
    }
    if (ech_public_hosts
        && NULL == array_get_element_klen(ech_public_hosts, h, hlen)) {
        /*(return first host in ech_public_hosts list as public-name)*/
        return &ech_public_hosts->data[0]->key;
    }
    return NULL;
}


__attribute_pure__
static int
mod_openssl_ech_only_host_match (const char *a, size_t alen, const char *b, size_t blen)
{
    /* compare two host strings
     * - host strings    with port must match exactly
     * - host strings without port must match exactly
     * - host string  without port must prefix-match host string with port
     * This comparison tries to do this right thing with regards to what is
     * generally expected when a port is not provided (for whatever reason),
     * but does not reject the case where two ECH-only hosts with the same
     * name, but different ports, are independent rather than the same site */

    if (alen == blen)
        return (0 == memcmp(a, b, alen)); /* chk exact match */

    /* make a longer string, b shorter string, and len the prefix len */
    size_t len = blen;
    if (alen < blen) {
        len = alen;
        const char *t = b;
        b = a;
        a = t;
    }

    if (a[len] == ':' && 0 == memcmp(a, b, len)) {
        for (a += len + 1; light_isdigit(*a); ++a) ;
        return (*a == '\0');              /* chk prefix match, then port num */
    }

    return 0;
}


__attribute_cold__
__attribute_noinline__
static handler_t
mod_openssl_ech_only_policy_check (request_st * const r, handler_ctx * const hctx)
{
    if (NULL == r->http_host)
        return HANDLER_GO_ON; /* ignore HTTP/1.0 without Host: header */

    char *sni_ech = NULL;
    char *sni_clr = NULL;
    handler_t rc = HANDLER_GO_ON;
    switch (SSL_ech_accepted(hctx->ssl))
    {
      case SSL_ECH_STATUS_SUCCESS:
        /* require that request :authority (Host) match SNI in ECH to avoid one
         * ECH-provided host testing for existence of another ECH-only host.
         * 'sni_ech' is assumed normalized since ECH decryption succeeded. */
       {
        const char *ech =
          SSL_get_servername(hctx->ssl, TLSEXT_NAMETYPE_host_name);
        if (mod_openssl_ech_only_host_match(BUF_PTR_LEN(r->http_host),
                                            ech, strlen(ech)))
            break;
       }
        /* allow r->http_host to not match ECH SNI only if
         * r->http_host is in explicit list of public names (if defined)
         * (avoid leaking r->http_host is ECH-only;
         *  do not use mod_openssl_ech_only() here) */
        if (hctx->ech_public_hosts) {
            /* (XXX: not done: adjust length to omit :port from r->http_host)*/
            if (NULL != array_get_element_klen(hctx->ech_public_hosts,
                                               BUF_PTR_LEN(r->http_host)))
                break;
        }
        /* XXX: 421 here exposes that some ECH-only vhosts exist on this server,
         * though not which virtual hosts.  Alternative: fall through to the
         * default case below?  Doing so from here would cause the code below
         * to use the inner SNI for BoringSSL, and the outer SNI for OpenSSL.
         * What are we trying to protect?  If protecting the contents, then
         * mod_auth or other authorization mechanisms should be preferred over
         * hidden ECH-host.  If protecting SNI, then that was already done in
         * the initial ECH, even though to a different vhost.  If there is a
         * super-secret ECH key and ECHConfig for an ECH-only host and that
         * ECHConfig is not public, but was distributed out-of-band, then we
         * would not want to expose its existence to a connection which did not
         * use ECH, or which did use ECH but with ECHConfig from a different
         * anonymity set instead of the super-secret ECHConfig.
         * Should we add config option to disable this 421 policy response? */
        r->http_status = 421; /* Misdirected Request */
        rc = HANDLER_FINISHED;
        break;
      /*case SSL_ECH_STATUS_NOT_TRIED:*/
      default:
        if (0 == r->loops_per_request) {
            /* avoid acknowledging existence of ECH-only host in request
             * if connection not ECH and some hosts configured ECH-only */
            /* always restart request once to minimize timing differences */
            /* always attempt to do equivalent work, even if wasteful */
            /* always attempt to provide same behavior for authority in
             * request whether or not it matches cleartext SNI */
            /* (r->uri.authority is ECH-only if redo_host *is not* NULL) */
            const buffer *redo_host =
              mod_openssl_ech_only(hctx, BUF_PTR_LEN(&r->uri.authority));
            buffer * const http_host = r->http_host;
            const char *clr = sni_clr
              ? sni_clr
              : SSL_get_servername(hctx->ssl, TLSEXT_NAMETYPE_host_name);
            if (NULL != clr) {
                buffer * const tb = r->tmp_buf;/*(normalized in policy checks)*/
                buffer_copy_string_len_lc(tb, clr, strlen(clr));
                if (0 != http_request_host_policy(tb,
                                                  r->conf.http_parseopts, 443)){
                    r->http_status = 400;
                    rc = HANDLER_FINISHED;
                    break;
                }
                const buffer * const redo_host_sni =
                  mod_openssl_ech_only(hctx, BUF_PTR_LEN(tb));
                redo_host = (NULL != redo_host)
                  ? (NULL == redo_host_sni) ? tb : redo_host_sni
                  : http_host;
            }
            else if (NULL == redo_host)
                redo_host = http_host;
            /* always copy r->http_host; avoid memcpy UB if copying over self */
            buffer_copy_buffer(http_host != redo_host ? http_host : r->tmp_buf,
                               redo_host);
            /* always normalize port, if not 443 */
            const server_socket * const srv_sock = r->con->srv_socket;
            if (sock_addr_get_port(&srv_sock->addr) != 443) {
                const char * const colon = strchr(http_host->ptr, ':');
                if (colon)
                    buffer_string_set_length(http_host, colon - http_host->ptr);
                const buffer * const srv_token = srv_sock->srv_token;
                const size_t o = srv_sock->srv_token_colon;
                const size_t n = buffer_string_length(srv_token) - o;
                buffer_append_string_len(http_host, srv_token->ptr+o, n);
            }
            ++r->loops_per_request;
            rc = HANDLER_COMEBACK;
        }
        break;
    }
    OPENSSL_free(sni_ech);
    OPENSSL_free(sni_clr);
    return rc;
}

#endif /* !OPENSSL_NO_ECH */


INIT_FUNC(mod_openssl_init)
{
    return (mod_boringssl_plugin_data = ck_calloc(1, sizeof(plugin_data)));
}


static int mod_openssl_init_once_openssl (server *srv)
{
    if (ssl_is_init) return 1;

    ssl_is_init = 1;

    if (0 == RAND_status()) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: not enough entropy in the pool");
        return 0;
    }

    local_send_buffer = ck_malloc(LOCAL_SEND_BUFSIZE);
    return 1;
}


static void mod_openssl_free_openssl (void)
{
    if (!ssl_is_init) return;

  #ifdef TLSEXT_TYPE_session_ticket
    OPENSSL_cleanse(session_ticket_keys, sizeof(session_ticket_keys));
    stek_rotate_ts = 0;
  #endif

    ERR_clear_error();

    free(local_send_buffer);
    ssl_is_init = 0;
}


static void
mod_openssl_free_plugin_ssl_ctx (plugin_ssl_ctx * const s)
{
    SSL_CTX_free(s->ssl_ctx);
    if (s->kp)
        mod_openssl_kp_rel(s->kp);
    free(s);
}


static void
mod_openssl_free_config (server *srv, plugin_data * const p)
{
    array_free(p->ech_only_hosts);

    if (NULL != p->ssl_ctxs) {
        /* free ssl_ctx from $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[i];
            if (s && s != p->ssl_ctxs[0])
                mod_openssl_free_plugin_ssl_ctx(s);
        }
        /* free ssl_ctx from global scope */
        if (p->ssl_ctxs[0])
            mod_openssl_free_plugin_ssl_ctx(p->ssl_ctxs[0]);
        free(p->ssl_ctxs);
    }

    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_cert *pc = cpv->v.v;
                    mod_openssl_kp *kp = pc->kp;
                    while (kp) {
                        mod_openssl_kp *o = kp;
                        kp = kp->next;
                        mod_openssl_kp_free(o);
                    }
                    free(pc);
                }
                break;
              case 2: /* ssl.ca-file */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_cacerts *cacerts = cpv->v.v;
                    sk_CRYPTO_BUFFER_pop_free(cacerts->names, CRYPTO_BUFFER_free);
                    X509_STORE_free(cacerts->store);
                    sk_X509_CRL_pop_free(cacerts->sk_crls, X509_CRL_free);
                    free(cacerts);
                }
                break;
              case 3: /* ssl.ca-dn-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    sk_CRYPTO_BUFFER_pop_free(cpv->v.v, CRYPTO_BUFFER_free);
                break;
              default:
                break;
            }
        }
    }

    /*(doc states: CRYPTO_BUFFER_POOL_free frees |pool|, which must be empty.)*/
    CRYPTO_BUFFER_POOL_free(p->cbpool);
}


static plugin_cacerts *
mod_boringssl_load_cacerts_x509 (CRYPTO_BUFFER * const * const certs, size_t num_certs)
{
    STACK_OF(CRYPTO_BUFFER) *names = sk_CRYPTO_BUFFER_new_null();
    array *dedupa = array_init((uint32_t)num_certs);
    X509_STORE * const chain_store = X509_STORE_new();
    int rc = 0;
    do {
        if (NULL == names || NULL == chain_store) break;

        size_t i;
        for (i = 0; i < num_certs; ++i) {
            X509 *x509 = X509_parse_from_buffer(certs[i]);
            if (NULL == x509 || !X509_STORE_add_cert(chain_store, x509)) {
                X509_free(x509);
                break;
            }

            uint8_t *subj = NULL;
            int len = i2d_X509_NAME(X509_get_subject_name(x509), &subj);
            if (len < 0)
                break;
            /* skip duplicates (using a temporary array and binary search)
             * (expecting short list of certificates and without duplicates) */
            int *n = array_get_int_ptr(dedupa, (char *)subj, (uint32_t)len);
            if (*n) {
                OPENSSL_free(subj);
                continue;
            }
            *n = 1;
            /* insert into sk, preserving order from (CRYPTO_BUFFER *)certs
             * (admin might have preferred CA order for client cert selection)*/
            CRYPTO_BUFFER *subject =
              CRYPTO_BUFFER_new(subj, len, mod_boringssl_plugin_data->cbpool);
            OPENSSL_free(subj);
            if (!subject || !sk_CRYPTO_BUFFER_push(names, subject)) {
                CRYPTO_BUFFER_free(subject);
                break;
            }
        }
        if (i != num_certs)
            break;

        rc = 1;
    } while (0);

    array_free(dedupa);

    if (!rc) {
        sk_CRYPTO_BUFFER_pop_free(names, CRYPTO_BUFFER_free);
        X509_STORE_free(chain_store);
        return NULL;
    }

    plugin_cacerts *cacerts = ck_malloc(sizeof(plugin_cacerts));
    cacerts->names = names;
    cacerts->store = chain_store;
    cacerts->crl_file = NULL;
    cacerts->crl_loadts = 0;
    return cacerts;
}


static plugin_cacerts *
mod_openssl_load_cacerts (const buffer *ssl_ca_file, log_error_st *errh)
{
    size_t num_certs = 0; /* overloaded as input param use_pool=0 */
    CRYPTO_BUFFER **certs =
      asn1_pem_parse_file(ssl_ca_file->ptr, errh,
                          mod_boringssl_pem_parse_certs_cb, &num_certs);
    if (NULL == certs) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: valid cert(s) not found in ssl.verifyclient.ca-(dn-)file %s",
          ssl_ca_file->ptr);
        return NULL;
    }

    plugin_cacerts *cacerts = mod_boringssl_load_cacerts_x509(certs, num_certs);
    if (NULL == cacerts)
        log_error(errh, __FILE__, __LINE__,
          "SSL: error parsing ssl.verifyclient.ca-(dn-)file %s",
          ssl_ca_file->ptr);

    for (size_t i = 0; i < num_certs; ++i)
        CRYPTO_BUFFER_free(certs[i]);
    free(certs);

    return cacerts;
}


FREE_FUNC(mod_openssl_free)
{
    plugin_data *p = p_d;
    if (NULL == p->srv) return;
    mod_openssl_free_config(p->srv, p);
    mod_openssl_free_openssl();
}


static void
mod_openssl_merge_config_cpv (plugin_config * const pconf, const config_plugin_value_t * const cpv)
{
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* ssl.pemfile */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->pc = cpv->v.v;
        break;
      case 1: /* ssl.privkey */
        break;
      case 2: /* ssl.ca-file */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ssl_ca_file = cpv->v.v;
        break;
      case 3: /* ssl.ca-dn-file */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ssl_ca_dn_file = cpv->v.v;
        break;
      case 4: /* ssl.ca-crl-file */
        pconf->ssl_ca_crl_file = cpv->v.b;
        break;
      case 5: /* ssl.read-ahead */
        pconf->ssl_read_ahead = (0 != cpv->v.u);
        break;
      case 6: /* ssl.disable-client-renegotiation */
        /*(ignored; unsafe renegotiation disabled by default)*/
        break;
      case 7: /* ssl.verifyclient.activate */
        pconf->ssl_verifyclient = (0 != cpv->v.u);
        break;
      case 8: /* ssl.verifyclient.enforce */
        pconf->ssl_verifyclient_enforce = (0 != cpv->v.u);
        break;
      case 9: /* ssl.verifyclient.depth */
        pconf->ssl_verifyclient_depth = (unsigned char)cpv->v.shrt;
        break;
      case 10:/* ssl.verifyclient.username */
        pconf->ssl_verifyclient_username = cpv->v.b;
        break;
      case 11:/* ssl.verifyclient.exportcert */
        pconf->ssl_verifyclient_export_cert = (0 != cpv->v.u);
        break;
      case 12:/* ssl.acme-tls-1 */
        pconf->ssl_acme_tls_1 = cpv->v.b;
        break;
      case 13:/* ssl.stapling-file */
        break;
      case 14:/* debug.log-ssl-noise */
        pconf->ssl_log_noise = (0 != cpv->v.u);
        break;
     #if 0    /*(cpk->k_id remapped in mod_openssl_set_defaults())*/
      case 15:/* ssl.verifyclient.ca-file */
      case 16:/* ssl.verifyclient.ca-dn-file */
      case 17:/* ssl.verifyclient.ca-crl-file */
        break;
     #endif
      case 18:/* ssl.ech-public-name */
        break;
      default:/* should not happen */
        return;
    }
}


static void
mod_openssl_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv)
{
    do {
        mod_openssl_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_openssl_patch_config (request_st * const r, plugin_config * const pconf)
{
    plugin_data * const p = mod_boringssl_plugin_data;
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_openssl_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


static int
safer_X509_NAME_oneline(X509_NAME *name, char *buf, size_t sz)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio) {
        int len = X509_NAME_print_ex(bio, name, 0,
                                     XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        BIO_gets(bio, buf, (int)sz); /*(may be truncated if len >= sz)*/
        BIO_free(bio);
        return len; /*return value has similar semantics to that of snprintf()*/
    }
    else {
        buf[0] = '\0';
        return -1;
    }
}


static void
ssl_info_callback (const SSL *ssl, int where, int ret)
{
    UNUSED(ret);

    if (0 != (where & SSL_CB_HANDSHAKE_START)) {
        handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
        if (hctx->renegotiations >= 0) ++hctx->renegotiations;
    }
  #ifdef TLS1_3_VERSION
    /* https://github.com/openssl/openssl/issues/5721
     * "TLSv1.3 unexpected InfoCallback after handshake completed" */
    if (0 != (where & SSL_CB_HANDSHAKE_DONE)) {
        /* SSL_version() is valid after initial handshake completed */
        if (SSL_version(ssl) >= TLS1_3_VERSION) {
            /* https://wiki.openssl.org/index.php/TLS1.3
             * "Renegotiation is not possible in a TLSv1.3 connection" */
            handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
            hctx->renegotiations = -1;
        }
    }
  #endif
}


__attribute_cold__
__attribute_noinline__
static int
verify_error_trace (handler_ctx *hctx, X509 *x509, int depth, int err)
{
    char buf[256];
    buf[0] = '\0';
    if (!x509) {
        /* SSL_get_peer_certificate() would require X509_free() before return */
        SSL_SESSION *session = SSL_get0_session(hctx->ssl);
        x509 = session ? SSL_SESSION_get0_peer(session) : NULL;
    }
    if (x509)
        safer_X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
    if (err == X509_V_OK)
        err = X509_V_ERR_UNSPECIFIED;
    log_error(hctx->errh, __FILE__, __LINE__,
      "SSL: addr:%s verify error:num=%d:%s:depth=%d:subject=%s",
      hctx->con->dst_addr_buf.ptr,
      err, X509_verify_cert_error_string(err), depth, buf);
    if (   err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        || err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
        safer_X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: addr:%s issuer=%s", hctx->con->dst_addr_buf.ptr, buf);
    }
    return err;
}


/*static enum ssl_verify_result_t*/
/*custom_verify_callback (SSL *ssl, uint8_t *out_alert)*/
static int
mod_boringssl_custom_verify_callback (SSL * const ssl, handler_ctx * const hctx)
{
    /*handler_ctx * const hctx = (handler_ctx *) SSL_get_app_data(ssl);*/

    const STACK_OF(CRYPTO_BUFFER) * const peer_certs =
      SSL_get0_peer_certificates(ssl);
    if (!peer_certs) { /*(should not happen if custom_verify_callback called)*/
        /**out_alert = SSL_AD_INTERNAL_ERROR;*/
        /*return ssl_verify_invalid;*/
        return verify_error_trace(hctx, NULL, 0, X509_V_ERR_UNSPECIFIED);
    }

    if (sk_CRYPTO_BUFFER_num(peer_certs) > hctx->conf.ssl_verifyclient_depth) {
        /* For a server with a well-defined set of trusted CAs, testing length
         * of chain provided by client is sufficient, rather than the convoluted
         * steps in the example provided at the bottom of
         *   https://docs.openssl.org/master/man3/SSL_CTX_set_verify/
         * which may be better for a client testing the certificate chain
         * against a large list of public internet CAs */
        /**out_alert = SSL_AD_UNKNOWN_CA;*/
        /*return ssl_verify_invalid;*/
        return
          verify_error_trace(hctx, NULL, 0, X509_V_ERR_CERT_CHAIN_TOO_LONG);
    }

    /* (SSL_get_peer_certificate() would require X509_free() before return)*/
    SSL_SESSION *session = SSL_get0_session(ssl);
    X509 * const peer_x509 = session ? SSL_SESSION_get0_peer(session) : NULL;
    /*if (!peer_x509) return ssl_verify_invalid;*/ /*(should not happen here)*/
    if (!peer_x509)
        return verify_error_trace(hctx, NULL, 0, X509_V_ERR_UNSPECIFIED);

    if (hctx->conf.ssl_ca_dn_file) {
        uint8_t *issuer = NULL;
        /* future: parse issuer from sk_CRYPTO_BUFFER_value(peer_certs, 0) */
        /* get issuer of peer cert and re-encode name to DER format */
        int issuer_len = i2d_X509_NAME(X509_get_issuer_name(peer_x509),&issuer);

      #if 0
        /* copying into CRYPTO_BUFFER and setting stack cmp_func
         * just to use sk_CRYPTO_BUFFER_find() is excessive
         * and less efficient than straightforward comparison
         * (Also, ca_dn_names would need to be sorted at init time,
         *  and a separate stack kept for ca_dn list sent to client
         *  in the order given by admin input file (not sorted)) */
        STACK_OF(CRYPTO_BUFFER) * const ca_dn_names = hctx->conf.ssl_ca_dn_file;
        if (sk_CRYPTO_BUFFER_find(ca_dn_names, NULL, issuer)) {
            free(issuer);
            issuer = NULL;
        }
      #else
        if (issuer_len < 0) /*(unexpected)*/
            issuer_len = 0; /*(cause no match and cert rejection below)*/
        const size_t ilen = (size_t)issuer_len;
        STACK_OF(CRYPTO_BUFFER) * const ca_dn_names = hctx->conf.ssl_ca_dn_file;
        for (int i = 0, len = sk_CRYPTO_BUFFER_num(ca_dn_names); i < len; ++i) {
            const CRYPTO_BUFFER *name = sk_CRYPTO_BUFFER_value(ca_dn_names, i);
            if (ilen == CRYPTO_BUFFER_len(name)
                && 0 == memcmp(CRYPTO_BUFFER_data(name), issuer, ilen)) {
                free(issuer);
                issuer = NULL;
                break; /* match */
            }
        }
      #endif
        if (issuer != NULL) {
            free(issuer);
            /**out_alert = SSL_AD_BAD_CERTIFICATE;*/
            /*return ssl_verify_invalid;*/
            return                               /*?X509_V_ERR_CERT_UNTRUSTED?*/
              verify_error_trace(hctx, peer_x509, 0, X509_V_ERR_CERT_REJECTED);
        }
    }

    return X509_V_OK;

  #if 0 /* handled via app_verify_callback() call to X509_verify_cert() */
    /* verify client certificate */
    /* reference: ssl/ssl_x509.cc:ssl_crypto_x509_session_verify_cert_chain() */
    /* (this block originally coded to be part of custom_verify_callback()) */
    int rc = -1;
    X509_STORE_CTX * const store_ctx = X509_STORE_CTX_new();
    do {
        if (!store_ctx)
            break;
        if (!X509_STORE_CTX_init(store_ctx, hctx->conf.ssl_ca_file->store,
                                 peer_x509, SSL_get_peer_cert_chain(ssl)))
            break;

        X509_VERIFY_PARAM * const param = X509_STORE_CTX_get0_param(store_ctx);

      #if 0
        if (!X509_STORE_CTX_set_default(store_ctx, "ssl_client"))/*client cert*/
            break;
      #else
        X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_CLIENT);
        X509_VERIFY_PARAM_set_trust(param, X509_TRUST_SSL_CLIENT);
      #endif

        /* elide extra calls to get time() to check cert and CRL times */
        X509_VERIFY_PARAM_set_time_posix(param, (int64_t)log_epoch_secs);

        /* could set X509_STORE_set_depth() and inherit from X509_STORE
         * if lighttpd.conf added requirement that ssl.verifyclient.depth
         * be configured in same context as CA certs and CRLs.
         * (https://docs.openssl.org/master/man3/SSL_CTX_set_verify/ example
         *  setting ssl_verifyclient_depth + 1 and checking depth manually
         *  in SSL_set_verify() with own verify_callback() might be excessive)*/
        X509_VERIFY_PARAM_set_depth(param, hctx->conf.ssl_verifyclient_depth);

        if (hctx->conf.ssl_ca_file->sk_crls) {
            X509_STORE_CTX_set0_crls(store_ctx,hctx->conf.ssl_ca_file->sk_crls);
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK
                                             | X509_V_FLAG_CRL_CHECK_ALL);
        }

      #ifndef OPENSSL_NO_ECH
        /* ClientHelloOuter connections use a different name */
        const char *name;
        size_t name_len = 0;
        SSL_get0_ech_name_override(ssl, &name, &name_len);
        if (name_len && !X509_VERIFY_PARAM_set1_host(param, name, name_len)))
            break;
      #endif

        rc = X509_verify_cert(store_ctx);
        if (1 != rc) {
            rc = 0;
            verify_error_trace(hctx, X509_STORE_CTX_get_current_cert(store_ctx),
                                     X509_STORE_CTX_get_error_depth(store_ctx),
                                     X509_STORE_CTX_get_error(store_ctx));
        }
    } while (0);
    if (-1 == rc)
        verify_error_trace(hctx, peer_x509, 0, X509_V_ERR_UNSPECIFIED);

    X509_STORE_CTX_free(store_ctx);
    return (1 == rc) ? ssl_verify_ok : ssl_verify_invalid;
  #endif
}


static int
app_verify_callback (X509_STORE_CTX *store_ctx, void *arg)
{
    /* Using SSL_CTX_set_cert_verify_callback() to set app_verify_callback
     * leverages ssl/ssl_x509.cc:ssl_crypto_x509_session_verify_cert_chain()
     * to set up X509_STORE_CTX.  app_verify_callback() replaces the call
     * from ssl/ssl_x509.cc:ssl_crypto_x509_session_verify_cert_chain() to
     * X509_verify_cert(), but this intercepts and then turn around and call
     * X509_verify_cert().  This is an alternative to custom_verify_callback
     * which repaces ssl/ssl_x509.cc:ssl_crypto_x509_session_verify_cert_chain()
     * and results in custom_verify_callback having to replicate X509_STORE_CTX,
     * which is very complicated. */
    UNUSED(arg);
    SSL * const ssl =
      X509_STORE_CTX_get_ex_data(store_ctx,
                                 SSL_get_ex_data_X509_STORE_CTX_idx());

    /* SSL_CTX_set_cert_verify_callback() sets callback on SSL_CTX
     * Skip verification if client certificate verification is not enabled */
    handler_ctx * const hctx = (handler_ctx *) SSL_get_app_data(ssl);
    if (!hctx->conf.ssl_verifyclient) /*(certificates were not requested)*/
        return 1; /* feign success */

    int rc = mod_boringssl_custom_verify_callback(ssl, hctx);
    if (rc != X509_V_OK) {
        X509_STORE_CTX_set_error(store_ctx, rc);
        return !hctx->conf.ssl_verifyclient_enforce;
    }

    X509_VERIFY_PARAM * const param = X509_STORE_CTX_get0_param(store_ctx);
    X509_VERIFY_PARAM_set_time_posix(param, (int64_t)log_epoch_secs);
    X509_VERIFY_PARAM_set_depth(param, hctx->conf.ssl_verifyclient_depth);
    if (hctx->conf.ssl_ca_file->sk_crls) {
        X509_STORE_CTX_set0_crls(store_ctx, hctx->conf.ssl_ca_file->sk_crls);
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK
                                         | X509_V_FLAG_CRL_CHECK_ALL);
    }

    rc = X509_verify_cert(store_ctx);
    if (rc <= 0) {
        verify_error_trace(hctx, X509_STORE_CTX_get_current_cert(store_ctx),
                                 X509_STORE_CTX_get_error_depth(store_ctx),
                                 X509_STORE_CTX_get_error(store_ctx));
        rc = !hctx->conf.ssl_verifyclient_enforce;
    }
    return rc;
}


enum {
  MOD_OPENSSL_ALPN_HTTP11      = 1
 ,MOD_OPENSSL_ALPN_HTTP10      = 2
 ,MOD_OPENSSL_ALPN_H2          = 3
 ,MOD_OPENSSL_ALPN_ACME_TLS_1  = 4
};

static int
mod_openssl_cert_cb (SSL *ssl, void *arg)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    plugin_cert *pc = hctx->conf.pc;
    UNUSED(arg);
    if (hctx->alpn == MOD_OPENSSL_ALPN_ACME_TLS_1) return 1;

    if (!pc) {
        /* x509/pkey available <=> pemfile was set <=> pemfile got patched:
         * so this should never happen, unless you nest $SERVER["socket"] */
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: no certificate/private key for TLS server name \"%s\".  "
          "$SERVER[\"socket\"] should not be nested in other conditions.",
          hctx->r->uri.authority.ptr);
        return 0;
    }

 #if 0 /* disabled due to openssl quirks selecting incorrect certificate */
    /* reuse cert chain/privkey assigned to ssl_ctx where cert matches */
  if (hctx->ssl_ctx_pc
      && buffer_is_equal(hctx->ssl_ctx_pc->ssl_pemfile, pc->ssl_pemfile)) {
    hctx->kp = mod_openssl_kp_acq(hctx->ssl_ctx_pc);
  }
  else
 #endif
  {
    hctx->kp = mod_openssl_kp_acq(pc);

    if (1 != SSL_add1_credential(ssl, hctx->kp->cred)) {
        elogf(hctx->r->conf.errh, __FILE__, __LINE__,
          "failed to set cert for TLS server name %s",
          hctx->r->uri.authority.ptr);
        return 0;
    }
  }

    /* (boringssl library keeps refcnt on SSL_CREDENTIAL; ok to release here) */
    {
        mod_openssl_kp_rel(hctx->kp);
        hctx->kp = NULL;
    }

    if (hctx->conf.ssl_verifyclient) {
        if (NULL == hctx->conf.ssl_ca_file) {
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
              "SSL: can't verify client without ssl.verifyclient.ca-file "
              "for TLS server name %s", hctx->r->uri.authority.ptr);
            return 0;
        }
        SSL_set1_verify_cert_store(ssl, hctx->conf.ssl_ca_file->store);
        STACK_OF(CRYPTO_BUFFER) * const ca_dn_names = hctx->conf.ssl_ca_dn_file
          ? hctx->conf.ssl_ca_dn_file
          : hctx->conf.ssl_ca_file->names;
        SSL_set0_client_CAs(ssl, ca_dn_names);
        int mode = SSL_VERIFY_PEER;
        if (hctx->conf.ssl_verifyclient_enforce)
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_set_verify(ssl, mode, NULL);
    }

    return 1;
}

#ifndef OPENSSL_NO_TLSEXT
static int
mod_openssl_SNI (handler_ctx *hctx, const char *servername, size_t len)
{
    request_st * const r = hctx->r;
    if (len >= 1024) { /*(expecting < 256; TLSEXT_MAXLEN_host_name is 255)*/
        log_error(r->conf.errh, __FILE__, __LINE__,
          "SSL: addr:%s SNI name too long (%zu) %.*s...",
          hctx->con->dst_addr_buf.ptr, len, 1024, servername);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* use SNI to patch mod_openssl config and then reset COMP_HTTP_HOST */
    buffer_copy_string_len_lc(&r->uri.authority, servername, len);

    /*(r->uri.authority used below for configuration before request read)
     *(r->uri.authority is set here since it is used by config merging,
     * but r->uri.authority is later overwritten by each HTTP request)*/
    if (0 != http_request_host_policy(&r->uri.authority,
                                      r->conf.http_parseopts, 443))
        return SSL_TLSEXT_ERR_ALERT_FATAL;

  #ifndef OPENSSL_NO_ECH
    if (hctx->ech_only_policy) { /* ECH-only hosts are configured */
        /*(given: r->uri.authority contains value from SSL_get_servername())*/
        /*(check if host is ech-only before mod_openssl_patch_config() to try to
         * avoid timing differences (which might reveal existence of specific
         * ech-only host due to having to reset, re-patch if host is ech-only).
         * This is possible with the global list of ech_only_hosts configured
         * w/ ssl.ech-public-name.  We have chosen to unconditionally strip port
         * to help admins avoid mistakes where ech-only host might be accessed
         * on a different port.  Admin can use separate lighttpd instances if
         * there is a need for such complex behavior on different ports.) */
        int rc = SSL_ech_accepted(hctx->ssl);
        switch (rc) {
          case SSL_ECH_STATUS_SUCCESS:
            break;
          /*case SSL_ECH_STATUS_NOT_TRIED:*/
          default:
            /* **ignore** cleartext SNI if servername is marked ECH-only;
             * avoid acknowledging existence of host sent in cleartext SNI */
            /* alternative: apply config for mod_openssl_ech_only() fallback */
            if (NULL != mod_openssl_ech_only(hctx,
                                             BUF_PTR_LEN(&r->uri.authority))) {
                buffer_clear(&r->uri.authority);
                return SSL_TLSEXT_ERR_OK;
            }
            break;
        }
    }

    /* (might be called again after ECH is decrypted) */
    if (r->conditional_is_valid & (1 << COMP_HTTP_HOST))
        config_cond_cache_reset_item(r, COMP_HTTP_HOST);
  #endif

    r->conditional_is_valid |= (1 << COMP_HTTP_SCHEME)
                            |  (1 << COMP_HTTP_HOST);
    mod_openssl_patch_config(r, &hctx->conf);
    /* reset COMP_HTTP_HOST so that conditions re-run after request hdrs read */
    /*(done in response.c:config_cond_cache_reset() after request hdrs read)*/
    /*config_cond_cache_reset_item(r, COMP_HTTP_HOST);*/
    /*buffer_clear(&r->uri.authority);*/

    return SSL_TLSEXT_ERR_OK;
}

static int
network_ssl_servername_callback (SSL *ssl, int *al, void *srv)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    buffer_copy_string_len(&hctx->r->uri.scheme, CONST_STR_LEN("https"));
    UNUSED(al);
    UNUSED(srv);

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (NULL == servername)
        return SSL_TLSEXT_ERR_NOACK; /* client did not provide SNI */
    return mod_openssl_SNI(hctx, servername, strlen(servername));
}
#endif


static unix_time64_t
mod_openssl_asn1_time_to_posix (const ASN1_TIME *asn1time)
{
    int64_t t;
    return ASN1_TIME_to_posix(asn1time, &t) ? (unix_time64_t)t : -1;
}


static int
mod_openssl_cert_is_active (const X509 *crt)
{
    const ASN1_TIME *notBefore = X509_get0_notBefore(crt);
    const ASN1_TIME *notAfter  = X509_get0_notAfter(crt);
    const unix_time64_t before = mod_openssl_asn1_time_to_posix(notBefore);
    const unix_time64_t after  = mod_openssl_asn1_time_to_posix(notAfter);
    const unix_time64_t now = log_epoch_secs;
    return (0 <= before && before <= now && now <= after);
}


static int
mod_boringssl_cert_is_active (CRYPTO_BUFFER *cert)
{
    X509 *x509 = X509_parse_from_buffer(cert);
    int rc = 0;
    if (x509) {
        rc = mod_openssl_cert_is_active(x509);
        X509_free(x509);
    }
    return rc;
}


__attribute_noinline__
static int
mod_openssl_reload_crl_file (server *srv, plugin_cacerts *cacerts, const unix_time64_t cur_ts)
{
    /* CRLs can be updated at any time, though expected on/before Next Update */
    STACK_OF(X509_CRL) *sk_crls =
      asn1_pem_parse_file(cacerts->crl_file, srv->errh,
                          mod_boringssl_pem_parse_crls_cb, NULL);
    /* XXX: not thread-safe if another thread has pointer to sk_crls
     * and is about to perform client certificate verification */
    if (sk_crls) {
        sk_X509_CRL_pop_free(cacerts->sk_crls, X509_CRL_free);
        cacerts->sk_crls = sk_crls;
        cacerts->crl_loadts = cur_ts;
    }
    else
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: error parsing %s", cacerts->crl_file);

    return (sk_crls != NULL);
}


static int
mod_openssl_refresh_crl_file (server *srv, plugin_cacerts *cacerts, const unix_time64_t cur_ts)
{
    struct stat st;
    if (0 != stat(cacerts->crl_file, &st)
        || (TIME64_CAST(st.st_mtime) <= cacerts->crl_loadts
            && cacerts->crl_loadts != (unix_time64_t)-1))
        return 1;
    return mod_openssl_reload_crl_file(srv, cacerts, cur_ts);
}


static void
mod_openssl_refresh_crl_files (server *srv, const plugin_data *p, const unix_time64_t cur_ts)
{
    /* future: might construct array of (plugin_cacerts *) at startup
     *         to avoid the need to search for them here */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    if (NULL == p->cvlist) return;
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; cpv->k_id != -1; ++cpv) {
            if (cpv->k_id != 2) continue; /* k_id == 2 for ssl.ca-file */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            plugin_cacerts *cacerts = cpv->v.v;
            if (cacerts->crl_file)
                mod_openssl_refresh_crl_file(srv, cacerts, cur_ts);
        }
    }
}


#ifndef OPENSSL_NO_OCSP

static CRYPTO_BUFFER *
mod_boringssl_load_stapling_file (const char *file, log_error_st *errh)
{
    /* load raw .der file */
    off_t dlen = 1*1024*1024;/*(arbitrary limit: 1 MB file; expect < 1 KB)*/
    char *data = fdevent_load_file(file, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;

    CRYPTO_BUFFER *ocsp_staple =
      CRYPTO_BUFFER_new((uint8_t *)data, (size_t)dlen, NULL);
    free(data);
    return ocsp_staple;
}


__attribute_cold__
static void
mod_openssl_expire_stapling_file (server *srv, plugin_cert *pc)
{
    mod_openssl_kp * const kp = pc->kp;
    if (NULL == kp->ssl_stapling_der) /*(previously discarded or never loaded)*/
        return;

    /* discard expired OCSP stapling response */
    /* note: BoringSSL still sends expired OCSP staple in SSL_CREDENTIAL
     * (unless we create new kp with new SSL_CREDENTIAL w/o OCSP staple) */
    CRYPTO_BUFFER_free(kp->ssl_stapling_der);
    kp->ssl_stapling_der = NULL;
    if (kp->must_staple)
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate marked OCSP Must-Staple, "
                  "but OCSP response expired from ssl.stapling-file %s",
                  pc->ssl_stapling_file->ptr);
}


static int
mod_openssl_reload_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    CRYPTO_BUFFER *b =
      mod_boringssl_load_stapling_file(pc->ssl_stapling_file->ptr, srv->errh);
    if (!b) return 0;

    mod_openssl_kp *kp = pc->kp;
    if (kp->ssl_stapling_nextts != (time_t)-1) {
        /* SSL_CREDENTIAL should be treated as immutable once assigned to a
         * connection, so create new ref-counted kp with new SSL_CREDENTIAL
         * to update OCSP staple */
        kp = mod_openssl_kp_init();
        if (!SSL_CREDENTIAL_set1_cert_chain(kp->cred, pc->kp->ssl_pemfile_x509,
                                            (size_t)pc->kp->ssl_pemfile_chain)
            || !SSL_CREDENTIAL_set1_private_key(kp->cred,
                                                pc->kp->ssl_pemfile_pkey)) {
            /*(unexpected; already validated in pc->kp->cred)*/
            mod_openssl_kp_free(kp);
            CRYPTO_BUFFER_free(b);
            return 0;
        }
    }
    if (!SSL_CREDENTIAL_set1_ocsp_response(kp->cred, b)) {
        /* continue without OCSP response if there is an error */
        /* future: check and warn if kp->must_staple is set */
        if (kp != pc->kp)
            mod_openssl_kp_free(kp);
        CRYPTO_BUFFER_free(b);
        return 0;
    }
    if (kp != pc->kp) {
        /* move (steal) privkey and chain from old kp */
        mod_openssl_kp * const okp = pc->kp;
        kp->ssl_pemfile_pkey = okp->ssl_pemfile_pkey;
        okp->ssl_pemfile_pkey = NULL;
        kp->ssl_pemfile_x509 = okp->ssl_pemfile_x509;
        okp->ssl_pemfile_x509 = NULL;
        kp->ssl_pemfile_chain = okp->ssl_pemfile_chain;
        okp->ssl_pemfile_chain = 0;
        kp->must_staple = okp->must_staple;
        kp->self_issued = okp->self_issued;
        kp->next = okp;
        pc->kp = kp;
        mod_openssl_kp_rel(okp);
    }

    kp->ssl_stapling_der = b; /*(unchanged unless orig was NULL)*/
    kp->ssl_stapling_loadts = cur_ts;
    kp->ssl_stapling_nextts = (time_t)-1; /* retrieval not implemented for C */
    if (kp->ssl_stapling_nextts == (time_t)-1) {
        /* "Next Update" might not be provided by OCSP responder
         * Use 3600 sec (1 hour) in that case. */
        /* Trigger reload in 1 hour if unable to determine Next Update */
        kp->ssl_stapling_nextts = cur_ts + 3600;
        kp->ssl_stapling_loadts = 0;
    }
    else if (kp->ssl_stapling_nextts < cur_ts) {
        mod_openssl_expire_stapling_file(srv, pc);
        return 0;
    }

    return 1;
}


static int
mod_openssl_refresh_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    mod_openssl_kp * const kp = pc->kp;
    if (kp->ssl_stapling_der && kp->ssl_stapling_nextts > cur_ts + 256)
        return 1; /* skip check for refresh unless close to expire */
    struct stat st;
    if (0 != stat(pc->ssl_stapling_file->ptr, &st)
        || TIME64_CAST(st.st_mtime) <= kp->ssl_stapling_loadts) {
        if (kp->ssl_stapling_der && kp->ssl_stapling_nextts < cur_ts)
            mod_openssl_expire_stapling_file(srv, pc);
        return 1;
    }
    return mod_openssl_reload_stapling_file(srv, pc, cur_ts);
}


static void
mod_openssl_refresh_stapling_files (server *srv, const plugin_data *p, const unix_time64_t cur_ts)
{
    /* future: might construct array of (plugin_cert *) at startup
     *         to avoid the need to search for them here */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    if (NULL == p->cvlist) return;
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; cpv->k_id != -1; ++cpv) {
            if (cpv->k_id != 0) continue; /* k_id == 0 for ssl.pemfile */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            plugin_cert *pc = cpv->v.v;
            if (pc->ssl_stapling_file)
                mod_openssl_refresh_stapling_file(srv, pc, cur_ts);
        }
    }
}

#endif /* OPENSSL_NO_OCSP */


__attribute_noinline__
static plugin_cert *
network_openssl_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey, const buffer *ssl_stapling_file)
{
    if (!mod_openssl_init_once_openssl(srv)) return NULL;

    EVP_PKEY *ssl_pemfile_pkey =
      asn1_pem_parse_file(privkey->ptr, srv->errh,
                          mod_boringssl_pem_parse_evp_pkey_cb, NULL);
    if (NULL == ssl_pemfile_pkey) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: couldn't read private key from '%s'", privkey->ptr);
        return NULL;
    }

    size_t ssl_pemfile_chain = 1; /* overloaded as input param use_pool=1 */
    CRYPTO_BUFFER **ssl_pemfile_x509 =
      asn1_pem_parse_file(pemfile->ptr, srv->errh,
                          mod_boringssl_pem_parse_certs_cb, &ssl_pemfile_chain);
    if (NULL == ssl_pemfile_x509) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: error parsing %s", pemfile->ptr);
        EVP_PKEY_free(ssl_pemfile_pkey);
        return NULL;
    }
    if (!mod_boringssl_cert_is_active(ssl_pemfile_x509[0])
        && log_epoch_secs > 300)
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: inactive/expired X509 certificate '%s'", pemfile->ptr);

    plugin_cert *pc = ck_malloc(sizeof(plugin_cert));
    mod_openssl_kp * const kp = pc->kp = mod_openssl_kp_init();
    kp->ssl_pemfile_pkey = ssl_pemfile_pkey;
    kp->ssl_pemfile_x509 = ssl_pemfile_x509;
    kp->ssl_pemfile_chain= ssl_pemfile_chain;
    pc->ssl_pemfile = pemfile;
    pc->ssl_privkey = privkey;
    pc->ssl_stapling_file= ssl_stapling_file;
    pc->pkey_ts = log_epoch_secs;
    /*kp->must_staple = 0;*//* not implemented: obtain value from parsing cert*/
    /*kp->self_issued = 0;*//* not implemented: obtain value from parsing cert*/
    /* kp->self_issued was used to avoid config for self-signed cert
     * if auto-chaining was enabled; not done for BoringSSL */
    if (!SSL_CREDENTIAL_set1_cert_chain(kp->cred, ssl_pemfile_x509,
                                        ssl_pemfile_chain)
        || !SSL_CREDENTIAL_set1_private_key(kp->cred, ssl_pemfile_pkey)) {
        elogf(srv->errh, __FILE__, __LINE__,
          "SSL_CREDENTIAL init %s %s", pemfile->ptr, privkey->ptr);
        mod_openssl_kp_free(kp);
        free(pc);
        return NULL;
    }

    if (pc->ssl_stapling_file) {
      #ifndef OPENSSL_NO_OCSP
        kp->ssl_stapling_nextts = (time_t)-1; /*flag for BoringSSL to reuse kp*/
        if (!mod_openssl_reload_stapling_file(srv, pc, log_epoch_secs)) {
            kp->ssl_stapling_nextts = 0;
            /* continue without OCSP response if there is an error */
        }
      #else
        log_error(srv->errh, __FILE__, __LINE__, "SSL:"
          "OCSP stapling not supported; ignoring %s",
          pc->ssl_stapling_file->ptr);
      #endif
    }
    else if (kp->must_staple) {
        log_error(srv->errh, __FILE__, __LINE__, "SSL:"
                  "certificate %s marked OCSP Must-Staple, "
                  "but ssl.stapling-file not provided", pemfile->ptr);
    }

  #if 0
    const ASN1_TIME *notAfter = X509_get0_notAfter(ssl_pemfile_x509);
    pc->notAfter = mod_openssl_asn1_time_to_posix(notAfter);
  #endif

    return pc;
}


#ifndef OPENSSL_NO_TLSEXT

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
mod_openssl_acme_tls_1 (SSL *ssl, handler_ctx *hctx)
{
    const buffer * const name = &hctx->r->uri.authority;
    log_error_st * const errh = hctx->r->conf.errh;
    size_t ssl_pemfile_chain = 0;
    CRYPTO_BUFFER **ssl_pemfile_x509 = NULL;
    EVP_PKEY *ssl_pemfile_pkey = NULL;
    size_t len;
    int rc = SSL_TLSEXT_ERR_ALERT_FATAL;

    /* check if acme-tls/1 protocol is enabled (path to dir of cert(s) is set)*/
    if (!hctx->conf.ssl_acme_tls_1)
        return SSL_TLSEXT_ERR_NOACK; /*(reuse value here for not-configured)*/

    /* check if SNI set server name (required for acme-tls/1 protocol)
     * and perform simple path checks for no '/'
     * and no leading '.' (e.g. ignore "." or ".." or anything beginning '.') */
    if (buffer_is_blank(name))          return rc;
    if (NULL != strchr(name->ptr, '/')) return rc;
    if (name->ptr[0] == '.')            return rc;
  #if 0
    if (0 != http_request_host_policy(name,hctx->r->conf.http_parseopts,443))
        return rc;
  #endif
    buffer * const b = buffer_init();
    buffer_copy_path_len2(b, BUF_PTR_LEN(hctx->conf.ssl_acme_tls_1),
                             BUF_PTR_LEN(name));
    len = buffer_clen(b);

    do {
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        ssl_pemfile_pkey =
          asn1_pem_parse_file(b->ptr, errh,
                              mod_boringssl_pem_parse_evp_pkey_cb, NULL);
        if (NULL == ssl_pemfile_pkey) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        buffer_truncate(b, len); /*(remove ".key.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
        ssl_pemfile_x509 =
          asn1_pem_parse_file(b->ptr, errh, mod_boringssl_pem_parse_certs_cb,
                              &ssl_pemfile_chain);/* overloaded as use_pool=0 */
        if (NULL == ssl_pemfile_x509) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        if (1 != SSL_set_chain_and_key(ssl,
                                       ssl_pemfile_x509,
                                       ssl_pemfile_chain, /* num_certs */
                                       ssl_pemfile_pkey,
                                       NULL)) {
            elogf(errh, __FILE__, __LINE__,
              "failed to set acme-tls/1 certificate for TLS server name %s",
              name->ptr);
            break;
        }

        hctx->conf.ssl_verifyclient = 0;
        rc = SSL_TLSEXT_ERR_OK;
    } while (0);

    if (ssl_pemfile_pkey) EVP_PKEY_free(ssl_pemfile_pkey);
    if (ssl_pemfile_x509) {
        for (size_t i = 0; i < ssl_pemfile_chain; ++i)
            CRYPTO_BUFFER_free(ssl_pemfile_x509[i]);
        free(ssl_pemfile_x509);
    }

    buffer_free(b);
    return rc;
}

static int
mod_openssl_alpn_h2_policy (handler_ctx * const hctx)
{
    /*(currently called after handshake has completed)*/
  #if 0 /* SNI omitted by client when connecting to IP instead of to name */
    if (buffer_is_blank(&hctx->r->uri.authority)) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: addr:%s error ALPN h2 without SNI",
          hctx->con->dst_addr_buf.ptr);
        return -1;
    }
  #endif
    if (SSL_version(hctx->ssl) < TLS1_2_VERSION) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: addr:%s error ALPN h2 requires TLSv1.2 or later",
          hctx->con->dst_addr_buf.ptr);
        return -1;
    }

    return 0;
}

/* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
static int
mod_openssl_alpn_select_cb (SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    unsigned short proto;
    UNUSED(arg);

    for (unsigned int i = 0, n; i < inlen; i += n) {
        n = in[i++];
        if (i+n > inlen || 0 == n) break;
        switch (n) {
          case 2:  /* "h2" */
            if (in[i] == 'h' && in[i+1] == '2') {
                if (!hctx->r->conf.h2proto) continue;
                proto = MOD_OPENSSL_ALPN_H2;
                if (hctx->r->handler_module == NULL)/*(e.g. not mod_sockproxy)*/
                    hctx->r->http_version = HTTP_VERSION_2;
                break;
            }
            continue;
          case 8:  /* "http/1.1" "http/1.0" */
            if (0 == memcmp(in+i, "http/1.", 7)) {
                if (in[i+7] == '1') {
                    proto = MOD_OPENSSL_ALPN_HTTP11;
                    break;
                }
                if (in[i+7] == '0') {
                    proto = MOD_OPENSSL_ALPN_HTTP10;
                    break;
                }
            }
            continue;
          case 10: /* "acme-tls/1" */
            if (0 == memcmp(in+i, "acme-tls/1", 10)) {
                int rc = mod_openssl_acme_tls_1(ssl, hctx);
                if (rc == SSL_TLSEXT_ERR_OK) {
                    proto = MOD_OPENSSL_ALPN_ACME_TLS_1;
                    break;
                }
                /* (use SSL_TLSEXT_ERR_NOACK for not-configured) */
                if (rc == SSL_TLSEXT_ERR_NOACK) continue;
                return rc;
            }
            continue;
          default:
            continue;
        }

        hctx->alpn = proto;
        *out = in+i;
        *outlen = n;
        return SSL_TLSEXT_ERR_OK;
    }

    return hctx->r->handler_module /*(e.g. mod_sockproxy)*/
      ? SSL_TLSEXT_ERR_NOACK
      : SSL_TLSEXT_ERR_ALERT_FATAL;
}

#endif /* TLSEXT_TYPE_application_layer_protocol_negotiation */

#endif /* OPENSSL_NO_TLSEXT */


static int
mod_openssl_ssl_conf_cmd (server *srv, plugin_config_socket *s);


static int
mod_openssl_ssl_conf_dhparameters(server *srv, plugin_config_socket *s, const buffer *dhparameters)
{
    if (dhparameters) {
        UNUSED(s);
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: BoringSSL/AWS-LC does not support FFDH cipher suites; "
          "skipping loading parameters from %s", dhparameters->ptr);
    }
    return 1;
}


static int
mod_openssl_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *ssl_ec_curve)
{
  #ifndef OPENSSL_NO_ECDH
    /* boringssl eccurves_default[] (now kDefaultGroups[])
     * has been the equivalent of "X25519:secp256r1:secp384r1" since 2016
     * (previously with secp521r1 appended for Android)
     * (and before that the equivalent of "secp256r1:secp384r1:secp521r1"
     *  since mid 2014) */
    if (NULL == ssl_ec_curve || buffer_is_blank(ssl_ec_curve))
        return 1;

    const char *groups = ssl_ec_curve && !buffer_is_blank(ssl_ec_curve)
      ? ssl_ec_curve->ptr
      :
        /* boringssl include/openssl/evp.h contains comment:
         * > EVP_PKEY_X448 is defined for OpenSSL compatibility, but we do not
         * > support X448 and attempts to create keys will fail.
         */
        "X25519:P-256:P-384";

    int rc = SSL_CTX_set1_groups_list(s->ssl_ctx, groups);
    if (1 != rc) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: Unable to config groups %s", groups);
        return 0;
    }
  #endif
    UNUSED(srv);
    UNUSED(s);
    UNUSED(ssl_ec_curve);

    return 1;
}


static void
li_get_current_time (const SSL *ssl, struct timeval *out_clock)
{
    /* use cached time in sec since already available; elide excess time() calls
     * (note: *inappropriate* for DTLS, which uses higher precision timers)
     * (this lighttpd module does not currently support DTLS) */
    UNUSED(ssl);
    out_clock->tv_sec = log_epoch_secs;
    out_clock->tv_usec = 0;
}

static int mod_boringssl_verifyclient_selective;

static int
network_init_ssl (server *srv, plugin_config_socket *s, plugin_data *p)
{
    /* load SSL certificates */

      #ifndef SSL_OP_NO_COMPRESSION
      #define SSL_OP_NO_COMPRESSION 0
      #endif
      #ifndef SSL_MODE_RELEASE_BUFFERS    /* OpenSSL >= 1.0.0 */
      #define SSL_MODE_RELEASE_BUFFERS 0
      #endif
        uint32_t ssloptions =
                          SSL_OP_ALL
                        | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                        | SSL_OP_NO_COMPRESSION;

        /* prefer more efficient BoringSSL API TLS_with_buffers_method()
         * when client certificate verification not configured */
        s->ssl_ctx = SSL_CTX_new(!s->ssl_verifyclient
                                   && !mod_boringssl_verifyclient_selective
                                 ? TLS_with_buffers_method()
                                 : TLS_server_method());
        if (NULL == s->ssl_ctx) {
            elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_new");
            return -1;
        }
        SSL_CTX_set0_buffer_pool(s->ssl_ctx, p->cbpool);
        /* use cached time since already available; elide excess time() calls
         * (note: *inappropriate* for DTLS, which uses higher precision timers)
         * (this lighttpd module does not currently support DTLS) */
        /* (while intended for testing, prototype is public in openssl/ssl.h) */
        SSL_CTX_set_current_time_cb(s->ssl_ctx, li_get_current_time);
        SSL_CTX_set_cert_verify_callback(s->ssl_ctx, app_verify_callback, NULL);

      #ifdef SSL_OP_NO_RENEGOTIATION /* openssl 1.1.0 */
        ssloptions |= SSL_OP_NO_RENEGOTIATION;
      #endif

        /* completely useless identifier;
         * required for client cert verification to work with sessions */
        if (0 == SSL_CTX_set_session_id_context(
                   s->ssl_ctx,(const unsigned char*)CONST_STR_LEN("lighttpd"))){
            elog(srv->errh,__FILE__,__LINE__,"SSL_CTX_set_session_id_context");
            return -1;
        }

        const int disable_sess_cache =
          !config_feature_bool(srv, "ssl.session-cache", 0);
        if (disable_sess_cache)
            /* disable session cache; session tickets are preferred */
            SSL_CTX_set_session_cache_mode(s->ssl_ctx,
                                             SSL_SESS_CACHE_OFF
                                           | SSL_SESS_CACHE_NO_AUTO_CLEAR
                                           | SSL_SESS_CACHE_NO_INTERNAL);

        SSL_CTX_set_options(s->ssl_ctx, ssloptions);
        SSL_CTX_set_info_callback(s->ssl_ctx, ssl_info_callback);

        if (0 != SSL_OP_NO_SSLv2) {
            /* disable SSLv2 */
            if ((SSL_OP_NO_SSLv2
                 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv2))
                != SSL_OP_NO_SSLv2) {
                elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_set_options");
                return -1;
            }
        }

        if (0 != SSL_OP_NO_SSLv3) {
            /* disable SSLv3 */
            if ((SSL_OP_NO_SSLv3
                 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv3))
                != SSL_OP_NO_SSLv3) {
                elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_set_options");
                return -1;
            }
        }

        if (s->ssl_cipher_list) {
            /* Disable support for low encryption ciphers */
            if (SSL_CTX_set_cipher_list(s->ssl_ctx,s->ssl_cipher_list->ptr)!=1){
                elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_set_cipher_list");
                return -1;
            }

            if (s->ssl_honor_cipher_order) {
                SSL_CTX_set_options(s->ssl_ctx,SSL_OP_CIPHER_SERVER_PREFERENCE);
            }
        }

      #ifdef SSL_OP_PRIORITIZE_CHACHA /*(openssl 1.1.1)*/
        if (s->ssl_honor_cipher_order)
            SSL_CTX_set_options(s->ssl_ctx, SSL_OP_PRIORITIZE_CHACHA);
      #endif

        if (!mod_openssl_ssl_conf_dhparameters(srv, s, NULL))
            return -1;

        if (!mod_openssl_ssl_conf_curves(srv, s, NULL))
            return -1;

      #ifdef TLSEXT_TYPE_session_ticket
        SSL_CTX_set_tlsext_ticket_key_cb(s->ssl_ctx, ssl_tlsext_ticket_key_cb);
      #endif

        SSL_CTX_set_cert_cb(s->ssl_ctx, mod_openssl_cert_cb, NULL);
        UNUSED(p);

        SSL_CTX_set_mode(s->ssl_ctx, SSL_CTX_get_mode(s->ssl_ctx)
                                   | SSL_MODE_ENABLE_PARTIAL_WRITE
                                   | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
                                   | SSL_MODE_RELEASE_BUFFERS);

      #ifndef OPENSSL_NO_TLSEXT
        if (!SSL_CTX_set_tlsext_servername_callback(
               s->ssl_ctx, network_ssl_servername_callback) ||
            !SSL_CTX_set_tlsext_servername_arg(s->ssl_ctx, srv)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: failed to initialize TLS servername callback, "
              "openssl library does not support TLS servername extension");
            return -1;
        }

       #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        SSL_CTX_set_alpn_select_cb(s->ssl_ctx,mod_openssl_alpn_select_cb,NULL);
       #endif
      #endif

        if (!SSL_CTX_set_min_proto_version(s->ssl_ctx, TLS1_3_VERSION))
            return -1;

        if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
            if (0 != mod_openssl_ssl_conf_cmd(srv, s)) return -1;
            /* (force compression disabled, the default, if HTTP/2 enabled) */
            if (srv->srvconf.h2proto)
                SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_COMPRESSION);
        }

        return 0;
}


#define LIGHTTPD_DEFAULT_CIPHER_LIST \
"EECDH+AESGCM:CHACHA20:!PSK:!DHE"


static int
mod_openssl_set_defaults_sockets(server *srv, plugin_data *p)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.engine"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("ssl.cipher-list"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("ssl.openssl.ssl-conf-cmd"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("ssl.pemfile"), /* included to process global scope */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.stek-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("ssl.ech-opts"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_SOCKET }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };
    static const buffer default_ssl_cipher_list =
      { CONST_STR_LEN(LIGHTTPD_DEFAULT_CIPHER_LIST), 0 };

    p->ssl_ctxs = ck_calloc(srv->config_context->used,sizeof(plugin_ssl_ctx *));

    int rc = HANDLER_GO_ON;
    plugin_data_base srvplug;
    memset(&srvplug, 0, sizeof(srvplug));
    plugin_data_base * const ps = &srvplug;
    if (!config_plugin_values_init(srv, ps, cpk, "mod_openssl"))
        return HANDLER_ERROR;

    plugin_config_socket defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.ssl_cipher_list = &default_ssl_cipher_list;

    /* flag if ssl.verifyclient.activate is enabled in any conditions
     * which are not global and not $SERVER["socket"], as this prevents
     * use of TLS_with_buffers_method() optimization vs TLS_server_method()
     * in network_init_ssl() */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_cond_info cfginfo;
        config_get_config_cond_info(&cfginfo, (uint32_t)p->cvlist[i].k_id);
        if (0 == i || cfginfo.comp == COMP_SERVER_SOCKET) continue;
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 7: /* ssl.verifyclient.activate */
                if (0 != cpv->v.u)
                    mod_boringssl_verifyclient_selective = 1;
                break;
              default:
                break;
            }
        }
    }

    /* process and validate config directives for global and $SERVER["socket"]
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !ps->cvlist[0].v.u2[1]; i < ps->nconfig; ++i) {
        config_cond_info cfginfo;
        config_get_config_cond_info(&cfginfo, (uint32_t)ps->cvlist[i].k_id);
        int is_socket_scope = (0 == i || cfginfo.comp == COMP_SERVER_SOCKET);
        int count_not_engine = 0;

        plugin_config_socket conf;
        memcpy(&conf, &defaults, sizeof(conf));
        config_plugin_value_t *cpv = ps->cvlist + ps->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            /* ignore ssl.pemfile (k_id=3); included to process global scope */
            if (!is_socket_scope && cpv->k_id != 3) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "%s is valid only in global scope or "
                  "$SERVER[\"socket\"] condition", cpk[cpv->k_id].k);
                continue;
            }
            ++count_not_engine;
            switch (cpv->k_id) {
              case 0: /* ssl.engine */
                conf.ssl_enabled = (0 != cpv->v.u);
                --count_not_engine;
                break;
              case 1: /* ssl.cipher-list */
                if (!buffer_is_blank(cpv->v.b)) {
                    conf.ssl_cipher_list = cpv->v.b;
                    /*(historical use might list non-PFS ciphers)*/
                    conf.ssl_honor_cipher_order = 1;
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s is deprecated.  "
                      "Please prefer lighttpd secure TLS defaults, or use "
                      "ssl.openssl.ssl-conf-cmd \"CipherString\" to set custom "
                      "cipher list.", cpk[cpv->k_id].k);
                }
                break;
              case 2: /* ssl.openssl.ssl-conf-cmd */
                *(const array **)&conf.ssl_conf_cmd = cpv->v.a;
                break;
              case 3: /* ssl.pemfile */
                /* ignore here; included to process global scope when
                 * ssl.pemfile is set, but ssl.engine is not "enable" */
                break;
              case 4: /* ssl.stek-file */
                if (!buffer_is_blank(cpv->v.b))
                    p->ssl_stek_file = cpv->v.b->ptr;
                break;
              case 5: /* ssl.ech-opts */
                *(const array **)&conf.ech_opts = cpv->v.a;
                break;
              default:/* should not happen */
                break;
            }
        }
        if (HANDLER_GO_ON != rc) break;
        if (0 == i) memcpy(&defaults, &conf, sizeof(conf));

        if (0 != i && !conf.ssl_enabled) continue;
        if (0 != i && !is_socket_scope) continue;

        /* fill plugin_config_socket with global context then $SERVER["socket"]
         * only for directives directly in current $SERVER["socket"] condition*/

        /*conf.pc                     = p->defaults.pc;*/
        conf.ssl_ca_file              = p->defaults.ssl_ca_file;
        conf.ssl_ca_dn_file           = p->defaults.ssl_ca_dn_file;
        conf.ssl_ca_crl_file          = p->defaults.ssl_ca_crl_file;
        conf.ssl_verifyclient         = p->defaults.ssl_verifyclient;
        conf.ssl_verifyclient_enforce = p->defaults.ssl_verifyclient_enforce;
        conf.ssl_verifyclient_depth   = p->defaults.ssl_verifyclient_depth;
        conf.ssl_read_ahead           = p->defaults.ssl_read_ahead;

        int sidx = ps->cvlist[i].k_id;
        for (int j = !p->cvlist[0].v.u2[1]; j < p->nconfig; ++j) {
            if (p->cvlist[j].k_id != sidx) continue;
            /*if (0 == sidx) break;*//*(repeat to get ssl_pemfile,ssl_privkey)*/
            cpv = p->cvlist + p->cvlist[j].v.u2[0];
            for (; -1 != cpv->k_id; ++cpv) {
                ++count_not_engine;
                switch (cpv->k_id) {
                  case 0: /* ssl.pemfile */
                    if (cpv->vtype == T_CONFIG_LOCAL)
                        conf.pc = cpv->v.v;
                    break;
                  case 2: /* ssl.ca-file */
                    if (cpv->vtype == T_CONFIG_LOCAL)
                        conf.ssl_ca_file = cpv->v.v;
                    break;
                  case 3: /* ssl.ca-dn-file */
                    if (cpv->vtype == T_CONFIG_LOCAL)
                        conf.ssl_ca_dn_file = cpv->v.v;
                    break;
                  case 4: /* ssl.ca-crl-file */
                    conf.ssl_ca_crl_file = cpv->v.b;
                    break;
                  case 5: /* ssl.read-ahead */
                    conf.ssl_read_ahead = (0 != cpv->v.u);
                    break;
                  case 6: /* ssl.disable-client-renegotiation */
                    /*(ignored; unsafe renegotiation disabled by default)*/
                    break;
                  case 7: /* ssl.verifyclient.activate */
                    conf.ssl_verifyclient = (0 != cpv->v.u);
                    break;
                  case 8: /* ssl.verifyclient.enforce */
                    conf.ssl_verifyclient_enforce = (0 != cpv->v.u);
                    break;
                  case 9: /* ssl.verifyclient.depth */
                    conf.ssl_verifyclient_depth = (unsigned char)cpv->v.shrt;
                    break;
                 #if 0    /*(cpk->k_id remapped in mod_openssl_set_defaults())*/
                  case 15:/* ssl.verifyclient.ca-file */
                  case 16:/* ssl.verifyclient.ca-dn-file */
                  case 17:/* ssl.verifyclient.ca-crl-file */
                 #endif
                  default:
                    break;
                }
            }
            break;
        }

        if (NULL == conf.pc) {
            if (0 == i && !conf.ssl_enabled) continue;
            if (0 != i) {
                /* inherit ssl settings from global scope
                 * (if only ssl.engine = "enable" and no other ssl.* settings)
                 * (This is for convenience when defining both IPv4 and IPv6
                 *  and desiring to inherit the ssl config from global context
                 *  without having to duplicate the directives)*/
                if (count_not_engine
                    || (conf.ssl_enabled && NULL == p->ssl_ctxs[0])) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "ssl.pemfile has to be set in same $SERVER[\"socket\"] scope "
                      "as other ssl.* directives, unless only ssl.engine is set, "
                      "inheriting ssl.* from global scope");
                    rc = HANDLER_ERROR;
                    continue;
                }
                p->ssl_ctxs[sidx] = p->ssl_ctxs[0]; /*(copy global scope)*/
                continue;
            }
            /* PEM file is required */
            log_error(srv->errh, __FILE__, __LINE__,
              "ssl.pemfile has to be set when ssl.engine = \"enable\"");
            rc = HANDLER_ERROR;
            continue;
        }

        /* configure ssl_ctx for socket */

        /*conf.ssl_ctx = NULL;*//*(filled by network_init_ssl() even on error)*/
        if (0 == network_init_ssl(srv, &conf, p)) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[sidx] =
              ck_calloc(1, sizeof(plugin_ssl_ctx));
            s->ssl_ctx = conf.ssl_ctx;
            s->pc = conf.pc;
            s->kp = mod_openssl_kp_acq(s->pc);
            if (conf.ech_opts) {
                const array * const ech_opts = conf.ech_opts;
                const data_unset *du;
                du = array_get_element_klen(ech_opts, CONST_STR_LEN("keydir"));
                s->ech_keydir = du ? &((data_string *)du)->value : NULL;
                if (s->ech_keydir && buffer_string_is_empty(s->ech_keydir))
                    s->ech_keydir = NULL;
                du = array_get_element_klen(ech_opts, CONST_STR_LEN("refresh"));
                s->ech_keydir_refresh_interval =
                  (uint32_t)config_plugin_value_to_int32(du, 300);
                du = array_get_element_klen(ech_opts,
                                            CONST_STR_LEN("public-names"));
                if (du && du->type == TYPE_ARRAY) {
                    s->ech_public_hosts = &((data_array *)du)->value;
                    if (s->ech_public_hosts->used == 0)
                        s->ech_public_hosts = NULL;
                    else {
                        /*(error out if "public-names" has ports appended)
                         *(could instead re-create/re-index array, but naw)*/
                        const array * const a = s->ech_public_hosts;
                        for (uint32_t j = 0; j < a->used; ++j) {
                            const buffer * h = &a->data[j]->key;
                            if (NULL != strchr(h->ptr, ':')) {
                                log_error(srv->errh, __FILE__, __LINE__,
                                  "ssl.ech-opts \"public-names\" must be listed"
                                  "without port: %s", h->ptr);
                                rc = HANDLER_ERROR;
                            }
                        }
                    }
                }
            }
        }
        else {
            SSL_CTX_free(conf.ssl_ctx);
            rc = HANDLER_ERROR;
        }
    }

    free(srvplug.cvlist);

    if (rc == HANDLER_GO_ON && ssl_is_init) {
      #ifdef TLSEXT_TYPE_session_ticket
        mod_openssl_session_ticket_key_check(p, log_epoch_secs);
      #endif

      #ifdef TLSEXT_TYPE_ech
        mod_openssl_refresh_ech_keys(srv, p, log_epoch_secs);
      #endif

        mod_openssl_refresh_crl_files(srv, p, log_epoch_secs);
    }

  #if 0 /*(alt: inherit from global scope in mod_openssl_handle_con_accept()*/
    if (defaults.ssl_enabled) {
      #if 0 /* used == 0; priv_defaults hook is called before network_init() */
        for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
            if (!srv->srv_sockets.ptr[i]->is_ssl) continue;
            plugin_ssl_ctx *s = p->ssl_ctxs[srv->srv_sockets.ptr[i]->sidx];
            if (NULL == s) /*(no ssl.* directives; inherit from global scope)*/
                p->ssl_ctxs[srv->srv_sockets.ptr[i]->sidx] = p->ssl_ctxs[0];
        }
      #endif
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            config_cond_info cfginfo;
            config_get_config_cond_info(&cfginfo, (uint32_t)i);
            if (cfginfo.comp != COMP_SERVER_SOCKET) continue;
            plugin_ssl_ctx * const s = p->ssl_ctxs[i];
            if (NULL == s)
                p->ssl_ctxs[i] = p->ssl_ctxs[0]; /*(copy from global scope)*/
                /* note: copied even when ssl.engine = "disabled",
                 * even though config will not be used when disabled */
        }
    }
  #endif

    return rc;
}


SETDEFAULTS_FUNC(mod_openssl_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.pemfile"), /* expect pos 0 for refresh certs,staple*/
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.privkey"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-file"), /* expect pos 2 for refresh crl */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-dn-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-crl-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.read-ahead"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.disable-client-renegotiation"),
        T_CONFIG_BOOL, /*(directive ignored)*/
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.activate"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.enforce"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.depth"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.username"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.exportcert"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.acme-tls-1"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.stapling-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-ssl-noise"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.ca-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.ca-dn-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.ca-crl-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ech-public-name"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    p->srv = srv;
    p->cbpool = CRYPTO_BUFFER_POOL_new();
    if (!config_plugin_values_init(srv, p, cpk, "mod_openssl"))
        return HANDLER_ERROR;

    const buffer *default_ssl_ca_crl_file = NULL;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        config_plugin_value_t *pemfile = NULL;
        config_plugin_value_t *privkey = NULL;
        const buffer *ssl_stapling_file = NULL;
        const buffer *ssl_ca_crl_file = NULL;
        plugin_cacerts *cacerts = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (!buffer_is_blank(cpv->v.b)) pemfile = cpv;
                break;
              case 1: /* ssl.privkey */
                if (!buffer_is_blank(cpv->v.b)) privkey = cpv;
                break;
              case 15:/* ssl.verifyclient.ca-file */
                cpv->k_id = 2;
                __attribute_fallthrough__
              case 2: /* ssl.ca-file */
                if (buffer_is_blank(cpv->v.b)) break;
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                cpv->v.v = mod_openssl_load_cacerts(cpv->v.b, srv->errh);
                if (NULL != cpv->v.v) {
                    cpv->vtype = T_CONFIG_LOCAL;
                    cacerts = (plugin_cacerts *)cpv->v.v;
                }
                else
                    return HANDLER_ERROR;
                break;
              case 16:/* ssl.verifyclient.ca-dn-file */
                cpv->k_id = 3;
                __attribute_fallthrough__
              case 3: /* ssl.ca-dn-file */
                if (buffer_is_blank(cpv->v.b)) break;
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                cpv->v.v = mod_openssl_load_cacerts(cpv->v.b, srv->errh);
                if (NULL != cpv->v.v) {
                    cpv->vtype = T_CONFIG_LOCAL;
                    plugin_cacerts *ca_dn_certs = cpv->v.v;
                    cpv->v.v = ca_dn_certs->names;
                    X509_STORE_free(ca_dn_certs->store);
                    free(ca_dn_certs);
                }
                else
                    return HANDLER_ERROR;
                break;
              case 17:/* ssl.verifyclient.ca-crl-file */
                cpv->k_id = 4;
                __attribute_fallthrough__
              case 4: /* ssl.ca-crl-file */
                if (buffer_is_blank(cpv->v.b)) break;
                ssl_ca_crl_file = cpv->v.b;
                if (0 == i) default_ssl_ca_crl_file = cpv->v.b;
                break;
              case 5: /* ssl.read-ahead */
              case 6: /* ssl.disable-client-renegotiation */
                /*(ignored; unsafe renegotiation disabled by default)*/
              case 7: /* ssl.verifyclient.activate */
              case 8: /* ssl.verifyclient.enforce */
                break;
              case 9: /* ssl.verifyclient.depth */
                if (cpv->v.shrt > 255) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s is absurdly large (%hu); limiting to 255",
                      cpk[cpv->k_id].k, cpv->v.shrt);
                    cpv->v.shrt = 255;
                }
                break;
              case 10:/* ssl.verifyclient.username */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 11:/* ssl.verifyclient.exportcert */
                break;
              case 12:/* ssl.acme-tls-1 */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 13:/* ssl.stapling-file */
                if (!buffer_is_blank(cpv->v.b))
                    ssl_stapling_file = cpv->v.b;
                break;
              case 14:/* debug.log-ssl-noise */
             #if 0    /*(handled further above)*/
              case 15:/* ssl.verifyclient.ca-file */
              case 16:/* ssl.verifyclient.ca-dn-file */
              case 17:/* ssl.verifyclient.ca-crl-file */
             #endif
                break;
              case 18:/* ssl.ech-public-name */
                if (0 != i) {
                    config_cond_info cfginfo;
                    config_get_config_cond_info(&cfginfo,
                                                (uint32_t)p->cvlist[i].k_id);
                    if (cfginfo.comp == COMP_HTTP_HOST
                        && cfginfo.cond == CONFIG_COND_EQ) {
                        if (NULL == p->ech_only_hosts)
                            p->ech_only_hosts = array_init(4);
                      #if 0
                        array_set_key_value(p->ech_only_hosts,
                                            BUF_PTR_LEN(cfginfo.string),
                                            BUF_PTR_LEN(cpv->v.b));
                      #else
                        /*(not expecting IPv6-literal as ECH-only)*/
                        const char *kcolon = strchr(cfginfo.string->ptr, ':');
                        size_t klen = kcolon
                          ? (size_t)(kcolon - cfginfo.string->ptr)
                          : buffer_string_length(cfginfo.string);
                        array_set_key_value(p->ech_only_hosts,
                                            cfginfo.string->ptr, klen,
                                            BUF_PTR_LEN(cpv->v.b));
                      #endif
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "%s valid only in $HTTP[\"...\"] == \"...\" config "
                          "condition, not: %s", cpk[cpv->k_id].k,
                          cfginfo.comp_key);
                    }
                }
                break;
              default:/* should not happen */
                break;
            }
        }

        if (NULL == cacerts && ssl_ca_crl_file && i != 0) {
            log_error(srv->errh, __FILE__, __LINE__,
              "ssl.verifyclient.ca-crl-file (%s) ignored unless issued with "
              "ssl.verifyclient.ca-file", ssl_ca_crl_file->ptr);
        }
        else if (cacerts && (ssl_ca_crl_file || default_ssl_ca_crl_file)) {
            /* prior behavior in lighttpd allowed ssl.ca-crl-file only in global
             * scope or $SERVER["socket"], so this inheritance from global scope
             * is reasonable.  This code does not implement inheritance of
             * ssl.ca-crl-file from $SERVER["socket"] into nested $HTTP["host"],
             * but the solution is to repeat ssl.ca-crl-file where ssl.ca-file
             * is issued (and to not unnecessarily repeat ssl.ca-file)
             * Alternative: write code to load ssl.ca-crl-file into (X509_CRL *)
             * using PEM_read_bio_X509_CRL() and in mod_openssl_cert_cb(),
             * create a new (X509_STORE *) which merges with CA (X509_STORE *)
             * using X509_STORE_add_cert() and X509_STORE_add_crl(), and keeps
             * the result in our (plugin_cert *) for reuse */
            if (NULL == ssl_ca_crl_file)
                ssl_ca_crl_file = default_ssl_ca_crl_file;
            cacerts->crl_file = ssl_ca_crl_file->ptr;
            cacerts->crl_loadts = (time_t)-1;
        }

        if (pemfile) {
          #ifdef OPENSSL_NO_TLSEXT
            config_cond_info cfginfo;
            uint32_t j = (uint32_t)p->cvlist[i].k_id;
            config_get_config_cond_info(&cfginfo, j);
            if (j > 0 && (COMP_SERVER_SOCKET != cfginfo.comp
                          || cfginfo.cond != CONFIG_COND_EQ)) {
                if (COMP_HTTP_HOST == cfginfo.comp)
                    log_error(srv->errh, __FILE__, __LINE__, "SSL:"
                      "can't use ssl.pemfile with $HTTP[\"host\"], "
                      "as openssl version does not support TLS extensions");
                else
                    log_error(srv->errh, __FILE__, __LINE__, "SSL:"
                      "ssl.pemfile only works in SSL socket binding context "
                      "as openssl version does not support TLS extensions");
                return HANDLER_ERROR;
            }
          #endif
            if (NULL == privkey) privkey = pemfile;
            pemfile->v.v =
              network_openssl_load_pemfile(srv, pemfile->v.b, privkey->v.b,
                                           ssl_stapling_file);
            if (pemfile->v.v)
                pemfile->vtype = T_CONFIG_LOCAL;
            else
                return HANDLER_ERROR;
        }
    }

    p->defaults.ssl_verifyclient = 0;
    p->defaults.ssl_verifyclient_enforce = 1;
    p->defaults.ssl_verifyclient_depth = 9;
    p->defaults.ssl_verifyclient_export_cert = 0;
    p->defaults.ssl_read_ahead = 0;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_openssl_merge_config(&p->defaults, cpv);
    }

    feature_refresh_certs = config_feature_bool(srv, "ssl.refresh-certs", 0);
    feature_refresh_crls  = config_feature_bool(srv, "ssl.refresh-crls",  0);

    return mod_openssl_set_defaults_sockets(srv, p);
}


static void
mod_openssl_detach(handler_ctx *hctx);


__attribute_cold__
static int
mod_openssl_write_err (handler_ctx * const restrict hctx, int wr)
{
    /* Note: caller calls ERR_clear_error() before SSL_write() */
    const int ssl_err = SSL_get_error(hctx->ssl, wr);
    switch (ssl_err) {
      case SSL_ERROR_WANT_READ:
        hctx->con->is_readable = -1;
        return 0; /* try again later */
      case SSL_ERROR_WANT_WRITE:
        hctx->con->is_writable = -1;
        return 0; /* try again later */
      case SSL_ERROR_ZERO_RETURN:
        /* clean shutdown on the remote side */
        if (wr == 0) return -2;
        __attribute_fallthrough__
      case SSL_ERROR_SYSCALL:
        {
            int errnum = errno;
            switch (errnum) {
              case EAGAIN:
             #ifdef EWOULDBLOCK
             #if EWOULDBLOCK != EAGAIN
              case EWOULDBLOCK:
             #endif
             #endif
              case EINTR:
             #if defined(__FreeBSD__) && defined(SF_NODISKIO)
              case EBUSY:
             #endif
                return 0; /* try again later */
              case EPIPE:
              case ECONNRESET:
               #if 0
                if (hctx->conf.ssl_log_noise)
                    log_perror(hctx->errh, __FILE__, __LINE__,
                      "SSL: addr:%s ssl_err:%d errno:%d",
                      hctx->con->dst_addr_buf.ptr, ssl_err, errnum);
               #endif
                mod_openssl_detach(hctx); /*non-recoverable; skip CLOSE_NOTIFY*/
                return -2;
              default:
                if (0 == ERR_peek_error())
                    log_perror(hctx->errh, __FILE__, __LINE__,
                      "SSL: addr:%s ssl_err:%d wr:%d errno:%d",
                      hctx->con->dst_addr_buf.ptr, ssl_err, wr, errnum);
                break;
            }
        }
        break;
      default:
        break;
    }

    elogc(hctx, __FILE__, __LINE__, ssl_err);
    mod_openssl_detach(hctx); /* non-recoverable; skip CLOSE_NOTIFY */
    return -1;
}


    /* local_send_buffer is a static buffer of size (LOCAL_SEND_BUFSIZE)
     *
     * it has to stay at the same location all the time to satisfy the needs
     * of SSL_write to pass the SAME parameter in case of a _WANT_WRITE
     *
     * buffer is allocated once, is NOT realloced (note: not thread-safe)
     *
     * (Note: above restriction no longer true since SSL_CTX_set_mode() is
     *        called with SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
     * */

            /* copy small mem chunks into single large buffer before SSL_write()
             * to reduce number times write() called underneath SSL_write() and
             * potentially reduce number of packets generated if TCP_NODELAY */


static int
mod_openssl_close_notify(handler_ctx *hctx);


static int
connection_write_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[mod_boringssl_plugin_data->id];

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_openssl_close_notify(hctx);

    while (max_bytes > 0 && !chunkqueue_is_empty(cq)) {
        char *data = local_send_buffer;
        uint32_t data_len = LOCAL_SEND_BUFSIZE < max_bytes
          ? LOCAL_SEND_BUFSIZE
          : (uint32_t)max_bytes;
        int wr;

        if (0 != chunkqueue_peek_data(cq, &data, &data_len, hctx->errh, 1))
            return -1;
        if (__builtin_expect( (0 == data_len), 0)) {
            if (!cq->first->file.busy)
                chunkqueue_remove_finished_chunks(cq);
            break; /* try again later */
        }

        /**
         * SSL_write man-page
         *
         * WARNING
         *        When an SSL_write() operation has to be repeated because of
         *        SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be
         *        repeated with the same arguments.
         */

        ERR_clear_error();
        wr = SSL_write(hctx->ssl, data, data_len);

        if (__builtin_expect( (hctx->renegotiations > 1), 0)) {
            log_error(hctx->errh, __FILE__, __LINE__,
              "SSL: addr:%s renegotiation initiated by client, "
              "killing connection", con->dst_addr_buf.ptr);
            return -1;
        }

        if (wr <= 0)
            return mod_openssl_write_err(hctx, wr);

        chunkqueue_mark_written(cq, wr);

        /* yield if wrote less than read or read less than requested
         * (if starting cqlen was less than requested read amount, then
         *  chunkqueue should be empty now, so no need to calculate that) */
        if ((uint32_t)wr < data_len || data_len <(LOCAL_SEND_BUFSIZE < max_bytes
                                                 ?LOCAL_SEND_BUFSIZE
                                                 :(uint32_t)max_bytes))
            break; /* try again later */

        max_bytes -= wr;
    }

    return 0;
}


static int
connection_read_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[mod_boringssl_plugin_data->id];
    int len;
    char *mem = NULL;
    size_t mem_len = 0;

    UNUSED(max_bytes);

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_openssl_close_notify(hctx);

    ERR_clear_error();
    int pend = SSL_pending(hctx->ssl);
    do {
        mem_len = pend < 2048 ? 2048 : (size_t)pend;
        chunk * const ckpt = cq->last;
        mem = chunkqueue_get_memory(cq, &mem_len);

        len = SSL_read(hctx->ssl, mem, mem_len);
        chunkqueue_use_memory(cq, ckpt, len > 0 ? len : 0);

        if (hctx->renegotiations > 1) {
            log_error(hctx->errh, __FILE__, __LINE__,
              "SSL: addr:%s renegotiation initiated by client, "
              "killing connection", con->dst_addr_buf.ptr);
            return -1;
        }

      #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        if (hctx->alpn) {
            if (hctx->alpn == MOD_OPENSSL_ALPN_H2) {
                if (0 != mod_openssl_alpn_h2_policy(hctx))
                    return -1;
            }
            else if (hctx->alpn == MOD_OPENSSL_ALPN_ACME_TLS_1) {
                chunkqueue_reset(cq);
                /* initiate handshake in order to send ServerHello.
                 * Once TLS handshake is complete, return -1 to result in
                 * CON_STATE_ERROR so that socket connection is quickly closed*/
                if (1 == SSL_do_handshake(hctx->ssl)) return -1;
                len = -1;
                break;
            }
            hctx->alpn = 0;
        }
      #endif
    } while (len > 0 && (pend = SSL_pending(hctx->ssl)) > 0);

    if (len < 0) {
        const int ssl_err = SSL_get_error(hctx->ssl, len);
        switch (ssl_err) {
        case SSL_ERROR_WANT_WRITE:
            con->is_writable = -1;
            __attribute_fallthrough__
        case SSL_ERROR_WANT_READ:
            con->is_readable = 0;

            /* the manual says we have to call SSL_read with the same arguments
             * next time.  we ignore this restriction; no one has complained
             * about it in 1.5 yet, so it probably works anyway.
             */

            return 0;
        case SSL_ERROR_SYSCALL:
            /**
             * man SSL_get_error()
             *
             * SSL_ERROR_SYSCALL
             *   Some I/O error occurred.  The OpenSSL error queue may contain
             *   more information on the error.  If the error queue is empty
             *   (i.e. ERR_get_error() returns 0), ret can be used to find out
             *   more about the error: If ret == 0, an EOF was observed that
             *   violates the protocol.  If ret == -1, the underlying BIO
             *   reported an I/O error (for socket I/O on Unix systems, consult
             *   errno for details).
             *
             */
           {
            const int errnum = errno;
            switch(errnum) {
            case EPIPE:
            case ECONNRESET:
                if (!hctx->conf.ssl_log_noise) break;
                __attribute_fallthrough__
            default:
                /* (errnum should be something like ECONNABORTED not 0
                 *  if client disconnected before anything was sent
                 *  (e.g. TCP connection probe), but it does not appear
                 *  that openssl provides such notification, not even
                 *  something like SSL_R_SSL_HANDSHAKE_FAILURE) */
                if (0==errnum && 0==cq->bytes_in && !hctx->conf.ssl_log_noise)
                    break;

                if (0 == ERR_peek_error())
                    log_perror(hctx->errh, __FILE__, __LINE__,
                      "SSL: addr:%s ssl_err:%d rd:%d errno:%d",
                      con->dst_addr_buf.ptr, ssl_err, len, errnum);
                else
                    elogc(hctx, __FILE__, __LINE__, ssl_err);
                break;
            }
            break;
           }
        case SSL_ERROR_ZERO_RETURN:
            /* clean shutdown on the remote side */

            /* future: might set flag to record that we received CLOSE_NOTIFY
             * TLS alert from peer, then have future calls to this func return
             * the equivalent of EOF, but we also want to remove read interest
             * on fd, perhaps by setting RDHUP.  If setting is_readable, ensure
             * that callers avoid spinning if we return EOF while is_readable.
             *
             * Should we treat this like len == 0 below and return -2 ? */

            /*__attribute_fallthrough__*/
        default:
            /* get all errors from the error-queue */
            elogc(hctx, __FILE__, __LINE__, ssl_err);
            break;
        }
        mod_openssl_detach(hctx); /* non-recoverable; skip CLOSE_NOTIFY */
        return -1;
    } else if (len == 0) {
        con->is_readable = 0;
        /* the other end close the connection -> KEEP-ALIVE */

        return -2;
    } else {
        return 0;
    }
}


CONNECTION_FUNC(mod_openssl_handle_con_accept)
{
    const server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    plugin_data *p = p_d;
    handler_ctx * const hctx = handler_ctx_init();
    request_st * const r = &con->request;
    hctx->r = r;
    hctx->con = con;
    hctx->errh = r->conf.errh;
    con->plugin_ctx[p->id] = hctx;
    buffer_blank(&r->uri.authority);

    plugin_ssl_ctx *s = p->ssl_ctxs[srv_sock->sidx]
                      ? p->ssl_ctxs[srv_sock->sidx]
                      : p->ssl_ctxs[0];
    if (s) {
        hctx->ssl_ctx_pc = s->pc;
      #ifndef OPENSSL_NO_ECH
        hctx->ech_public_hosts = s->ech_public_hosts;
        hctx->ech_only_hosts   = p->ech_only_hosts;
        hctx->ech_only_policy  = (hctx->ech_only_hosts||hctx->ech_public_hosts);
      #endif
        hctx->ssl = SSL_new(s->ssl_ctx);
    }
    if (NULL != hctx->ssl
        && SSL_set_app_data(hctx->ssl, hctx)
        && SSL_set_fd(hctx->ssl, con->fd)) {
        SSL_set_accept_state(hctx->ssl);
        con->network_read = connection_read_cq_ssl;
        con->network_write = connection_write_cq_ssl;
        con->proto_default_port = 443; /* "https" */
        mod_openssl_patch_config(r, &hctx->conf);
        return HANDLER_GO_ON;
    }
    else {
        elog(hctx->r->conf.errh, __FILE__, __LINE__, "accept");
        return HANDLER_ERROR;
    }
}


static void
mod_openssl_detach(handler_ctx *hctx)
{
    /* step aside from further SSL processing
     * (used after handle_connection_shut_wr hook) */
    /* future: might restore prior network_read and network_write fn ptrs */
    hctx->con->is_ssl_sock = 0;
    /* if called after handle_connection_shut_wr hook, shutdown SHUT_WR */
    if (-1 == hctx->close_notify) shutdown(hctx->con->fd, SHUT_WR);
    hctx->close_notify = 1;
}


CONNECTION_FUNC(mod_openssl_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx || 1 == hctx->close_notify) return HANDLER_GO_ON;

    hctx->close_notify = -2;
    if (SSL_is_init_finished(hctx->ssl)) {
        mod_openssl_close_notify(hctx);
    }
    else {
        mod_openssl_detach(hctx);
    }

    return HANDLER_GO_ON;
}


static int
mod_openssl_close_notify(handler_ctx *hctx)
{
        int ret, ssl_r;

        if (1 == hctx->close_notify) return -2;

        ERR_clear_error();
        switch ((ret = SSL_shutdown(hctx->ssl))) {
        case 1:
            break;
        case 0:
            /* Drain SSL read buffers in case pending records need processing.
             * Limit to reading next record to avoid denial of service when CPU
             * processing TLS is slower than arrival speed of TLS data packets.
             *
             * references:
             *
             * "New session ticket breaks bidirectional shutdown of TLS 1.3 connection"
             * https://github.com/openssl/openssl/issues/6262
             *
             * The peer is still allowed to send data after receiving the
             * "close notify" event. If the peer did send data it need to be
             * processed by calling SSL_read() before calling SSL_shutdown() a
             * second time. SSL_read() will indicate the end of the peer data by
             * returning <= 0 and SSL_get_error() returning
             * SSL_ERROR_ZERO_RETURN. It is recommended to call SSL_read()
             * between SSL_shutdown() calls.
             *
             * Additional discussion in "Auto retry in shutdown"
             * https://github.com/openssl/openssl/pull/6340
             */
            ssl_r = SSL_pending(hctx->ssl);
            if (ssl_r) {
                do {
                    char buf[4096];
                    ret = SSL_read(hctx->ssl, buf, (int)sizeof(buf));
                } while (ret > 0 && (ssl_r -= ret));
            }

            ERR_clear_error();
            ret = SSL_shutdown(hctx->ssl);
            if (1 == ret)
                break;
            else if (0 == ret) {
                hctx->close_notify = -1;
                return 0; /* try again later */
            }

            __attribute_fallthrough__
        default:

            if (!SSL_is_init_finished(hctx->ssl))
                break;

            switch ((ssl_r = SSL_get_error(hctx->ssl, ret))) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                hctx->close_notify = -1;
                return 0; /* try again later */
            case SSL_ERROR_SYSCALL:
                {
                    const int errnum = errno;
                    switch (errnum) {
                    case 0: /*ssl bug (see lighttpd ticket #2213)*/
                    case EPIPE:
                    case ECONNRESET:
                        break;
                    default:
                        if (0 == ERR_peek_error())
                            log_perror(hctx->r->conf.errh, __FILE__, __LINE__,
                              "SSL: addr:%s ssl_err:%d ret:%d errno:%d",
                              hctx->con->dst_addr_buf.ptr, ssl_r, ret, errnum);
                        else
                            elogc(hctx, __FILE__, __LINE__, ssl_r);
                        break;
                    }
                }
                break;
            default:
                elogc(hctx, __FILE__, __LINE__, ssl_r);
                break;
            }

            break;
        }

        mod_openssl_detach(hctx);
        return -2;
}


CONNECTION_FUNC(mod_openssl_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL != hctx) {
        con->plugin_ctx[p->id] = NULL;
        handler_ctx_free(hctx);
    }

    return HANDLER_GO_ON;
}


static void
https_add_ssl_client_subject (request_st * const r, X509_NAME *xn)
{
    const size_t prelen = sizeof("SSL_CLIENT_S_DN_")-1;
    char key[64] = "SSL_CLIENT_S_DN_";
    for (int i = 0, nentries = X509_NAME_entry_count(xn); i < nentries; ++i) {
        int xobjnid;
        const char * xobjsn;
        X509_NAME_ENTRY *xe;

        if (!(xe = X509_NAME_get_entry(xn, i))) {
            continue;
        }
        xobjnid = OBJ_obj2nid((ASN1_OBJECT*)X509_NAME_ENTRY_get_object(xe));
        xobjsn = OBJ_nid2sn(xobjnid);
        if (xobjsn) {
            const size_t len = strlen(xobjsn);
            if (prelen+len >= sizeof(key)) continue;
            memcpy(key+prelen, xobjsn, len); /*(not '\0'-terminated)*/
            http_header_env_set(r, key, prelen+len,
                                (const char*)X509_NAME_ENTRY_get_data(xe)->data,
                                X509_NAME_ENTRY_get_data(xe)->length);
        }
    }
}


__attribute_cold__
static void
https_add_ssl_client_verify_err (buffer * const b, long status)
{
    char errstr[256];
    ERR_error_string_n(status, errstr, sizeof(errstr));
    buffer_append_string(b, errstr);
}


__attribute_noinline__
static void
https_add_ssl_client_entries (request_st * const r, handler_ctx * const hctx)
{
    buffer *vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_VERIFY"));

    long vr = SSL_get_verify_result(hctx->ssl);
    if (vr != X509_V_OK) {
        buffer_copy_string_len(vb, CONST_STR_LEN("FAILED:"));
        https_add_ssl_client_verify_err(vb, vr);
        return;
    }

    const STACK_OF(CRYPTO_BUFFER) * const peer_certs =
      SSL_get0_peer_certificates(hctx->ssl);
    if (!peer_certs) {
        buffer_copy_string_len(vb, CONST_STR_LEN("NONE"));
        return;
    }

    buffer_copy_string_len(vb, CONST_STR_LEN("SUCCESS"));

    CRYPTO_BUFFER * const cert = sk_CRYPTO_BUFFER_value(peer_certs, 0);
    if (!cert) return;
  #if 0
    X509 * const xs = X509_parse_from_buffer(cert);
  #else /*(avoid extra work above since still using TLS_server_method())*/
    X509 * const xs = SSL_get_peer_certificate(hctx->ssl);
  #endif
    if (!xs) return;

    X509_NAME * const xn = X509_get_subject_name(xs);
    {
        char buf[256];
        int len = safer_X509_NAME_oneline(xn, buf, sizeof(buf));
        if (len > 0) {
            if (len >= (int)sizeof(buf)) len = (int)sizeof(buf)-1;
            http_header_env_set(r,
                                CONST_STR_LEN("SSL_CLIENT_S_DN"),
                                buf, (size_t)len);
        }
    }

    https_add_ssl_client_subject(r, xn);

    {
        ASN1_INTEGER *xsn = X509_get_serialNumber(xs);
        BIGNUM *serialBN = ASN1_INTEGER_to_BN(xsn, NULL);
        if (serialBN) {
            char *serialHex = BN_bn2hex(serialBN);
            if (serialHex) {
                http_header_env_set(r,
                                    CONST_STR_LEN("SSL_CLIENT_M_SERIAL"),
                                    serialHex, strlen(serialHex));
                OPENSSL_free(serialHex);
            }
            BN_free(serialBN);
        }
    }

    if (hctx->conf.ssl_verifyclient_username) {
        /* pick one of the exported values as "REMOTE_USER", for example
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_UID"
         * or
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_emailAddress"
         */
        const buffer *varname = hctx->conf.ssl_verifyclient_username;
        vb = http_header_env_get(r, BUF_PTR_LEN(varname));
        if (vb) { /* same as mod_auth_api.c:http_auth_setenv() */
            http_header_env_set(r,
                                CONST_STR_LEN("REMOTE_USER"),
                                BUF_PTR_LEN(vb));
            http_header_env_set(r,
                                CONST_STR_LEN("AUTH_TYPE"),
                                CONST_STR_LEN("SSL_CLIENT_VERIFY"));
        }
    }

    if (hctx->conf.ssl_verifyclient_export_cert) {
        buffer * const tb = r->tmp_buf;
        buffer_clear(tb);
        buffer_append_base64_encode(tb, CRYPTO_BUFFER_data(cert),
                                    CRYPTO_BUFFER_len(cert), BASE64_STANDARD);
        vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_CERT"));
      #if 0 /*(slightly more efficient, but more code)*/
        char *p = buffer_extend(vb, sizeof(PEM_BEGIN_CERT"\n")
                                   +buffer_clen(tb)
                                   +(buffer_clen(tb) >> 6)
                                   +((buffer_clen(tb) & 0x3F) != 0)
                                   +sizeof(PEM_END_CERT"\n"));
        memcpy(p, CONST_STR_LEN(PEM_BEGIN_CERT"\n"));
        p += sizeof(PEM_BEGIN_CERT"\n")-1;
        for (uint32_t off = 0, len = buffer_clen(tb); len; ) {
            const uint32_t n = len > 64 ? 64 : len;
            memcpy(p, tb->ptr+off, n);
            p[n] = '\n';
            p += n + 1;
            off += n;
            len -= n;
        }
        memcpy(p, CONST_STR_LEN(PEM_END_CERT"\n"));
        /*p += sizeof(PEM_END_CERT"\n")-1;*/
      #else
        buffer_string_prepare_append(vb, sizeof(PEM_BEGIN_CERT"\n")
                                        +buffer_clen(tb)
                                        +(buffer_clen(tb) >> 6) + 1
                                        +sizeof(PEM_END_CERT"\n"));
        buffer_append_string_len(vb, CONST_STR_LEN(PEM_BEGIN_CERT"\n"));
        for (uint32_t off = 0, len = buffer_clen(tb); len; ) {
            uint32_t n = len > 64 ? 64 : len;
            buffer_append_str2(vb, tb->ptr+off, n, CONST_STR_LEN("\n"));
            off += n;
            len -= n;
        }
        buffer_append_string_len(vb, CONST_STR_LEN(PEM_END_CERT"\n"));
      #endif
    }
    X509_free(xs);
}


static void
http_cgi_ssl_env (request_st * const r, handler_ctx * const hctx)
{
    const char *s;
    const SSL_CIPHER *cipher;

    s = SSL_get_version(hctx->ssl);
    http_header_env_set(r, CONST_STR_LEN("SSL_PROTOCOL"), s, strlen(s));

    if ((cipher = SSL_get_current_cipher(hctx->ssl))) {
        int usekeysize, algkeysize = 0;
        char buf[LI_ITOSTRING_LENGTH];
        s = SSL_CIPHER_get_name(cipher);
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER"), s, strlen(s));
        usekeysize = SSL_CIPHER_get_bits(cipher, &algkeysize);
        if (0 == algkeysize) algkeysize = usekeysize;
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, li_itostrn(buf, sizeof(buf), usekeysize));
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                            buf, li_itostrn(buf, sizeof(buf), algkeysize));
    }
}


REQUEST_FUNC(mod_openssl_handle_request_env)
{
    plugin_data *p = p_d;
    /* simple flag for request_env_patched */
    if (r->plugin_ctx[p->id]) return HANDLER_GO_ON;
    handler_ctx *hctx = r->con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    r->plugin_ctx[p->id] = (void *)(uintptr_t)1u;

    http_cgi_ssl_env(r, hctx);
    if (hctx->conf.ssl_verifyclient) {
        https_add_ssl_client_entries(r, hctx);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_openssl_handle_uri_raw)
{
    /* mod_openssl must be loaded prior to mod_auth
     * if mod_openssl is configured to set REMOTE_USER based on client cert */
    /* mod_openssl must be loaded after mod_extforward
     * if mod_openssl config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward, *unless* PROXY protocol
     * is enabled with extforward.hap-PROXY = "enable", in which case the
     * reverse is true: mod_extforward must be loaded after mod_openssl */
    plugin_data *p = p_d;
    handler_ctx *hctx = r->con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

  #ifndef OPENSSL_NO_ECH
    if (hctx->ech_only_policy) { /* ECH-only hosts are configured */
        handler_t rc = mod_openssl_ech_only_policy_check(r, hctx);
        if (HANDLER_GO_ON != rc) return rc;
    }
  #endif

    mod_openssl_patch_config(r, &hctx->conf);
    if (hctx->conf.ssl_verifyclient) {
        mod_openssl_handle_request_env(r, p);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_openssl_handle_request_reset)
{
    plugin_data *p = p_d;
    r->plugin_ctx[p->id] = NULL; /* simple flag for request_env_patched */
    return HANDLER_GO_ON;
}


static void
mod_openssl_refresh_plugin_ssl_ctx (server * const srv, plugin_ssl_ctx * const s)
{
    if (NULL == s->kp || NULL == s->pc || s->kp == s->pc->kp) return;
    mod_openssl_kp_rel(s->kp);
    s->kp = mod_openssl_kp_acq(s->pc);

  #if 0 /* disabled due to openssl quirks selecting incorrect certificate */
    /* BoringSSL certificate selection also does not currently check SNI */
    if (1 != SSL_CTX_add1_credential(s->ssl_ctx, s->kp->cred)) {
        elogf(srv->errh, __FILE__, __LINE__,
          "SSL_CTX_add1_credential %s %s",
          s->pc->pemfile->ptr, s->pc->privkey->ptr);
        /* no recovery until admin fixes input files */
    }
  #else
    UNUSED(srv);
  #endif
}


__attribute_cold__
static int
mod_openssl_refresh_plugin_cert_fail (server * const srv, plugin_cert * const pc)
{
    log_perror(srv->errh, __FILE__, __LINE__,
               "SSL: unable to check/refresh cert key; "
               "continuing to use already-loaded %s",
               pc->ssl_privkey->ptr);
    return 0;
}


static int
mod_openssl_refresh_plugin_cert (server * const srv, plugin_cert * const pc)
{
    /* Check for and free updated items from prior refresh iteration and which
     * now have refcnt 0.  Waiting for next iteration is a not-quite thread-safe
     * but lock-free way to have extremely low probability that another thread
     * might have a reference but was suspended between storing pointer and
     * updating refcnt (kp_acq), and still suspended full refresh period later;
     * highly unlikely unless thread is stopped in a debugger.  There should be
     * single maint thread, other threads read only pc->kp head, and pc->kp head
     * should always have refcnt >= 1, except possibly during process shutdown*/
    /*(lighttpd is currently single-threaded)*/
    for (mod_openssl_kp **kpp = &pc->kp->next; *kpp; ) {
        mod_openssl_kp *kp = *kpp;
        if (kp->refcnt)
            kpp = &kp->next;
        else {
            *kpp = kp->next;
            mod_openssl_kp_free(kp);
        }
    }

    /* Note: check last modification timestamp only on privkey file, so when
     * 'mv' updated files into place from generation location, script should
     * update privkey last, after pem file (and OCSP stapling file) */
    struct stat st;
    if (0 != stat(pc->ssl_privkey->ptr, &st))
        return mod_openssl_refresh_plugin_cert_fail(srv, pc);
        /* ignore if stat() error; keep using existing crt/pk */
    if (TIME64_CAST(st.st_mtime) <= pc->pkey_ts)
        return 0; /* mtime match; no change */

    plugin_cert *npc =
      network_openssl_load_pemfile(srv, pc->ssl_pemfile, pc->ssl_privkey,
                                   pc->ssl_stapling_file);
    if (NULL == npc)
        return mod_openssl_refresh_plugin_cert_fail(srv, pc);
        /* ignore if crt/pk error; keep using existing crt/pk */

    /*(future: if threaded, only one thread should update pcs)*/

    mod_openssl_kp * const kp = pc->kp;
    mod_openssl_kp * const nkp = npc->kp;
    nkp->next = kp;
    pc->pkey_ts = npc->pkey_ts;
    pc->kp = nkp;
    mod_openssl_kp_rel(kp);

    free(npc);
    return 1;
}


static void
mod_openssl_refresh_certs (server *srv, const plugin_data * const p)
{
    if (NULL == p->cvlist) return;
    int newpcs = 0;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->k_id != 0) continue; /* k_id == 0 for ssl.pemfile */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            newpcs |= mod_openssl_refresh_plugin_cert(srv, cpv->v.v);
        }
    }

    if (newpcs && NULL != p->ssl_ctxs) {
        if (p->ssl_ctxs[0])
            mod_openssl_refresh_plugin_ssl_ctx(srv, p->ssl_ctxs[0]);
        /* refresh $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[i];
            if (s && s != p->ssl_ctxs[0])
                mod_openssl_refresh_plugin_ssl_ctx(srv, s);
        }
    }
}


TRIGGER_FUNC(mod_openssl_handle_trigger) {
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/
    UNUSED(srv);
    UNUSED(p);

  #ifdef TLSEXT_TYPE_session_ticket
    mod_openssl_session_ticket_key_check(p, cur_ts);
  #endif

    /* enable with SSL_CTX_set_cert_cb() which runs unconditionally;
     * not enabled for older openssl or for LibreSSL since refcnt not incr if
     * SNI not present (when SSL_CTX_set_cert_cb() is not supported and used) */
    /*if (!(cur_ts & 0x3ff))*/ /*(once each 1024 sec (~17 min))*/
        if (feature_refresh_certs)
            mod_openssl_refresh_certs(srv, p);

  #ifndef OPENSSL_NO_OCSP
    mod_openssl_refresh_stapling_files(srv, p, cur_ts);
  #endif

  #ifdef TLSEXT_TYPE_ech
    mod_openssl_refresh_ech_keys(srv, p, cur_ts);
  #endif

    if (feature_refresh_crls)
        mod_openssl_refresh_crl_files(srv, p, cur_ts);

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_boringssl_plugin_init (plugin *p);
int mod_boringssl_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "boringssl";
    p->init         = mod_openssl_init;
    p->cleanup      = mod_openssl_free;
    p->priv_defaults= mod_openssl_set_defaults;

    p->handle_connection_accept  = mod_openssl_handle_con_accept;
    p->handle_connection_shut_wr = mod_openssl_handle_con_shut_wr;
    p->handle_connection_close   = mod_openssl_handle_con_close;
    p->handle_uri_raw            = mod_openssl_handle_uri_raw;
    p->handle_request_env        = mod_openssl_handle_request_env;
    p->handle_request_reset      = mod_openssl_handle_request_reset;
    p->handle_trigger            = mod_openssl_handle_trigger;

    return 0;
}


static int
mod_openssl_ssl_conf_proto_val (server *srv, const buffer *b, int max)
{
    if (NULL == b) /* default: min TLSv1.3, max TLSv1.3 */
        return TLS1_3_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        return max
          ? TLS1_3_VERSION
          : TLS1_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.0")))
        return TLS1_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.1")))
        return TLS1_1_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        return TLS1_2_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        return TLS1_3_VERSION;
    else {
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1.2")))
            log_error(srv->errh, __FILE__, __LINE__,
                      "SSL: ssl.openssl.ssl-conf-cmd %s %s ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
        else
            log_error(srv->errh, __FILE__, __LINE__,
                      "SSL: ssl.openssl.ssl-conf-cmd %s %s invalid; ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
    }
    return TLS1_3_VERSION;
}


static int
mod_openssl_ssl_conf_cmd (server *srv, plugin_config_socket *s)
{
    /* reference:
     * https://www.openssl.org/docs/manmaster/man3/SSL_CONF_cmd.html */
    int rc = 0;
    buffer *cipherstring = NULL;
    buffer *ciphersuites = NULL;
    buffer *minb = NULL;
    buffer *maxb = NULL;
    buffer *curves = NULL;

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        data_string *ds = (data_string *)s->ssl_conf_cmd->data[i];
        if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("CipherString")))
            cipherstring = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Ciphersuites")))
            ciphersuites = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Curves"))
              || buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Groups")))
            curves = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("DHParameters"))){
            if (!buffer_is_blank(&ds->value)) {
                if (!mod_openssl_ssl_conf_dhparameters(srv, s, &ds->value))
                    rc = -1;
            }
        }
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MaxProtocol")))
            maxb = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MinProtocol")))
            minb = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Protocol"))) {
            /* openssl config for Protocol=... is complex and deprecated */
            log_error(srv->errh, __FILE__, __LINE__,
                      "SSL: ssl.openssl.ssl-conf-cmd %s ignored; "
                      "use MinProtocol=... and MaxProtocol=... instead",
                      ds->key.ptr);
        }
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Options"))) {
            for (char *v = ds->value.ptr, *e; *v; v = e) {
                while (*v == ' ' || *v == '\t' || *v == ',') ++v;
                int flag = 1;
                if (*v == '-') {
                    flag = 0;
                    ++v;
                }
                else if (*v == '+')
                    ++v;
                for (e = v; light_isalpha(*e); ++e) ;
                switch ((int)(e-v)) {
                  case 11:
                    if (buffer_eq_icase_ssn(v, "Compression", 11)) {
                        /* (force disabled, the default, if HTTP/2 enabled) */
                        if (srv->srvconf.h2proto)
                            flag = 0;
                        if (flag)
                            SSL_CTX_clear_options(s->ssl_ctx,
                                                  SSL_OP_NO_COMPRESSION);
                        else
                            SSL_CTX_set_options(s->ssl_ctx,
                                                SSL_OP_NO_COMPRESSION);
                        continue;
                    }
                    break;
                  case 13:
                    if (buffer_eq_icase_ssn(v, "SessionTicket", 13)) {
                        if (flag)
                            SSL_CTX_clear_options(s->ssl_ctx,
                                                  SSL_OP_NO_TICKET);
                        else
                            SSL_CTX_set_options(s->ssl_ctx,
                                                SSL_OP_NO_TICKET);
                        continue;
                    }
                    break;
                  case 16:
                    if (buffer_eq_icase_ssn(v, "ServerPreference", 16)) {
                        if (flag)
                            SSL_CTX_set_options(s->ssl_ctx,
                                               SSL_OP_CIPHER_SERVER_PREFERENCE);
                        else
                            SSL_CTX_clear_options(s->ssl_ctx,
                                               SSL_OP_CIPHER_SERVER_PREFERENCE);
                        s->ssl_honor_cipher_order = flag;
                        continue;
                    }
                    break;
                  default:
                    break;
                }
                /* warn if not explicitly handled or ignored above */
                if (!flag) --v;
                log_error(srv->errh, __FILE__, __LINE__,
                          "SSL: ssl.openssl.ssl-conf-cmd Options %.*s "
                          "ignored", (int)(e-v), v);
            }
        }
      #if 0
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("..."))) {
        }
      #endif
        else {
            /* warn if not explicitly handled or ignored above */
            log_error(srv->errh, __FILE__, __LINE__,
                      "SSL: ssl.openssl.ssl-conf-cmd %s ignored",
                      ds->key.ptr);
        }

    }

    if (minb) {
        int n = mod_openssl_ssl_conf_proto_val(srv, minb, 0);
        if (!SSL_CTX_set_min_proto_version(s->ssl_ctx, n))
            rc = -1;
    }

    if (maxb) {
        int x = mod_openssl_ssl_conf_proto_val(srv, maxb, 1);
        if (!SSL_CTX_set_max_proto_version(s->ssl_ctx, x))
            rc = -1;
    }

    if (ciphersuites && !buffer_is_blank(ciphersuites)) {
      #if 0
        /* SSL_CTX_set_ciphersuites() not implemented in BoringSSL */
        if (SSL_CTX_set_ciphersuites(s->ssl_ctx, ciphersuites->ptr) != 1) {
            elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_set_ciphersuites");
            rc = -1;
        }
      #endif
    }

    if (cipherstring && !buffer_is_blank(cipherstring)) {
        /* Disable support for low encryption ciphers */
        buffer_append_string_len(cipherstring,
                                 CONST_STR_LEN(":!aNULL:!eNULL:!EXP"));
        if (SSL_CTX_set_cipher_list(s->ssl_ctx, cipherstring->ptr) != 1) {
            elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_set_cipher_list");
            rc = -1;
        }

        if (s->ssl_honor_cipher_order)
            SSL_CTX_set_options(s->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    if (curves && !buffer_is_blank(curves)) {
        if (!mod_openssl_ssl_conf_curves(srv, s, curves))
            rc = -1;
    }

    return rc;
}
