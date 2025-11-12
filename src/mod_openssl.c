/*
 * mod_openssl - openssl support for lighttpd
 *
 * Fully-rewritten from original
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
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
#include "first.h"

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-time.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*(not needed)*/
/* correction; needed for:
 *   SSL_load_client_CA_file()
 *   X509_STORE_load_locations()
 */
/*#define OPENSSL_NO_STDIO*/

#ifndef HAVE_KRB5
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#endif

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
#include <openssl/rand.h>
#include <openssl/tls1.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
#endif
#ifdef AWSLC_API_VERSION /* alt: OPENSSL_IS_AWSLC */
/* AWS-LC derived from BoringSSL, but AWSLC_API_VERSION has different meaning.
 * Reuse BORINGSSL_API_VERSION for (presently) small num of API version checks*/
#ifndef BORINGSSL_API_VERSION
#define BORINGSSL_API_VERSION 19
#endif
#endif
#ifdef BORINGSSL_API_VERSION
#include <openssl/hmac.h>
/* BoringSSL purports to have some OCSP support */
#undef OPENSSL_NO_OCSP
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#endif

/* check defines from <openssl/ssl.h> for experimental ECH support */
#if !defined(SSL_OP_ECH_GREASE) && !defined(SSL_R_ECH_REJECTED)
#define OPENSSL_NO_ECH
#endif

#ifndef OPENSSL_NO_ECH
/*#define LIGHTTPD_OPENSSL_ECH_DEBUG*/ /*(ECH developer debug trace)*/
#if defined(BORINGSSL_API_VERSION)
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
#else
#include <openssl/ech.h>
#endif
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/store.h>
#endif

#include "base.h"
#include "ck.h"
#include "fdevent.h"
#include "http_date.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "plugin.h"
#include "sock_addr.h"

#ifdef BORINGSSL_API_VERSION
#include "base64.h"
#endif

typedef struct mod_openssl_kp {
    EVP_PKEY *ssl_pemfile_pkey;
    X509 *ssl_pemfile_x509;
    STACK_OF(X509) *ssl_pemfile_chain;
    buffer *ssl_stapling_der;
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
    STACK_OF(X509_NAME) *names;
    X509_STORE *store;
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
    STACK_OF(X509_NAME) *ssl_ca_dn_file;
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
    STACK_OF(X509_NAME) *ssl_ca_dn_file;
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
  #if OPENSSL_VERSION_NUMBER < 0x10002000 || defined(LIBRESSL_VERSION_NUMBER)
    array *cafiles;
  #endif
    array *ech_only_hosts;
    const char *ssl_stek_file;
} plugin_data;

static int ssl_is_init;
#ifdef SSL_OP_ENABLE_KTLS /* openssl 3.0.0 */
static int ktls_enable;
#endif
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[mod_openssl_plugin_data->id]; */
static plugin_data *mod_openssl_plugin_data;
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
    return kp;
}


__attribute_cold__
static void
mod_openssl_kp_free (mod_openssl_kp *kp)
{
    EVP_PKEY_free(kp->ssl_pemfile_pkey);
    X509_free(kp->ssl_pemfile_x509);
    sk_X509_pop_free(kp->ssl_pemfile_chain, X509_free);
    buffer_free(kp->ssl_stapling_der);
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




static int
mod_openssl_SSL_CTX_use_cert_and_key (SSL_CTX *ssl_ctx, plugin_cert *pc, mod_openssl_kp *kp)
{
    /* note: caller is responsible for refcnt on pc->kp;
     * openssl keeps its own internal refcnt on objects */
    UNUSED(pc); /*(used below if openssl < 1.0.2)*/

  #if OPENSSL_VERSION_NUMBER >= 0x10101000 \
   && !defined(LIBRESSL_VERSION_NUMBER) \
   && !defined(BORINGSSL_API_VERSION)

    return SSL_CTX_use_cert_and_key(ssl_ctx,
                                    kp->ssl_pemfile_x509,
                                    kp->ssl_pemfile_pkey,
                                    kp->ssl_pemfile_chain,
                                    1);

  #else

   #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
    && (!defined(LIBRESSL_VERSION_NUMBER) \
        || LIBRESSL_VERSION_NUMBER >= 0x3000000fL)
    if (1 != SSL_CTX_use_certificate(ssl_ctx, kp->ssl_pemfile_x509))
        return 0;
    if (kp->ssl_pemfile_chain)
        SSL_CTX_set1_chain(ssl_ctx, kp->ssl_pemfile_chain);
   #else
    if (1 != SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                                pc->ssl_pemfile->ptr))
        return 0;
   #endif

    if (1 != SSL_CTX_use_PrivateKey(ssl_ctx, kp->ssl_pemfile_pkey))
        return 0;

    return SSL_CTX_check_private_key(ssl_ctx);

  #endif
}


static int
mod_openssl_SSL_use_cert_and_key (SSL *ssl, plugin_cert *pc, mod_openssl_kp *kp)
{
    /* note: caller is responsible for refcnt on pc->kp;
     * openssl keeps its own internal refcnt on objects */
    UNUSED(pc); /*(used below if openssl < 1.0.2)*/

  #if OPENSSL_VERSION_NUMBER >= 0x10101000 \
   && !defined(LIBRESSL_VERSION_NUMBER) \
   && !defined(BORINGSSL_API_VERSION)

    return SSL_use_cert_and_key(ssl,
                                kp->ssl_pemfile_x509,
                                kp->ssl_pemfile_pkey,
                                kp->ssl_pemfile_chain,
                                1);

  #else

    if (1 != SSL_use_certificate(ssl, kp->ssl_pemfile_x509))
        return 0;
   #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
    && (!defined(LIBRESSL_VERSION_NUMBER) \
        || LIBRESSL_VERSION_NUMBER >= 0x3000000fL)
    if (kp->ssl_pemfile_chain)
        SSL_set1_chain(ssl, kp->ssl_pemfile_chain);
   #endif

    if (1 != SSL_use_PrivateKey(ssl, kp->ssl_pemfile_pkey))
        return 0;

    return SSL_check_private_key(ssl);

  #endif
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
  #if OPENSSL_VERSION_NUMBER < 0x10101000L \
   || defined(BORINGSSL_API_VERSION) \
   || defined(LIBRESSL_VERSION_NUMBER)
  #define RAND_priv_bytes(x,sz) RAND_bytes((x),(sz))
  #endif
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


#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* based on reference implementation from openssl 1.1.1g man page
 *   man SSL_CTX_set_tlsext_ticket_key_cb
 * but mod_openssl code uses EVP_aes_256_cbc() instead of EVP_aes_128_cbc()
 */
static int
ssl_tlsext_ticket_key_cb (SSL *s, unsigned char key_name[16],
                          unsigned char iv[EVP_MAX_IV_LENGTH],
                          EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
/* based on reference implementation from openssl 3.0.0 man page
 *   man SSL_CTX_set_tlsext_ticket_key_cb
 */
static int
ssl_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16],
                         unsigned char *iv, EVP_CIPHER_CTX *ctx,
                         EVP_MAC_CTX *hctx, int enc)
#endif
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
      #if OPENSSL_VERSION_NUMBER < 0x30000000L
        HMAC_Init_ex(hctx, k->tick_hmac_key, sizeof(k->tick_hmac_key),
                     EVP_sha256(), NULL);
      #else
        OSSL_PARAM params[] = {
          OSSL_PARAM_DEFN(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING,
                          k->tick_hmac_key, sizeof(k->tick_hmac_key)),
          OSSL_PARAM_DEFN(OSSL_MAC_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING,
                          "sha256", sizeof("sha256")),
          OSSL_PARAM_END
        };
        EVP_MAC_CTX_set_params(hctx, params);
      #endif
        return 1;
    }
    else { /* retrieve session */
        int refresh;
        tlsext_ticket_key_t *k = tlsext_ticket_key_find(key_name, &refresh);
        if (NULL == k)
            return 0;
      #if OPENSSL_VERSION_NUMBER < 0x30000000L
        HMAC_Init_ex(hctx, k->tick_hmac_key, sizeof(k->tick_hmac_key),
                     EVP_sha256(), NULL);
      #else
        OSSL_PARAM params[] = {
          OSSL_PARAM_DEFN(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING,
                          k->tick_hmac_key, sizeof(k->tick_hmac_key)),
          OSSL_PARAM_DEFN(OSSL_MAC_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING,
                          "sha256", sizeof("sha256")),
          OSSL_PARAM_END
        };
        EVP_MAC_CTX_set_params(hctx, params);
      #endif
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


#ifndef OPENSSL_NO_OCSP
#ifndef BORINGSSL_API_VERSION /* BoringSSL suggests using different API */
static int
ssl_tlsext_status_cb(SSL *ssl, void *arg)
{
  #ifdef SSL_get_tlsext_status_type
    if (TLSEXT_STATUSTYPE_ocsp != SSL_get_tlsext_status_type(ssl))
        return SSL_TLSEXT_ERR_NOACK; /* ignore if not client OCSP request */
  #endif

    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    if (NULL == hctx->kp) return SSL_TLSEXT_ERR_NOACK;/*should not happen*/
    buffer *ssl_stapling = hctx->kp->ssl_stapling_der;
    if (NULL == ssl_stapling) return SSL_TLSEXT_ERR_NOACK;
    UNUSED(arg);

    int len = (int)buffer_clen(ssl_stapling);

    /* OpenSSL and LibreSSL require copy (BoringSSL, too, if using compat API)*/
    uint8_t *ocsp_resp = OPENSSL_malloc(len);
    if (NULL == ocsp_resp)
        return SSL_TLSEXT_ERR_NOACK; /* ignore OCSP request if error occurs */
    memcpy(ocsp_resp, ssl_stapling->ptr, len);

    /* (openssl library keeps refcnts on its objects) */
    mod_openssl_kp_rel(hctx->kp);
    hctx->kp = NULL;

    if (!SSL_set_tlsext_status_ocsp_resp(ssl, ocsp_resp, len)) {
        elogf(hctx->r->conf.errh, __FILE__, __LINE__,
          "failed to set OCSP response for TLS server name %s",
          hctx->r->uri.authority.ptr);
        OPENSSL_free(ocsp_resp);
        return SSL_TLSEXT_ERR_NOACK; /* ignore OCSP request if error occurs */
        /*return SSL_TLSEXT_ERR_ALERT_FATAL;*/
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif
#endif


#ifndef OPENSSL_NO_ECH

#ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
#if !defined(BORINGSSL_API_VERSION)
static void ech_key_status_trace (server * const srv, OSSL_ECHSTORE * const es)
{
    int numkeys = 0;
    int ksrv = OSSL_ECHSTORE_num_keys(es, &numkeys);
    if (ksrv != 1)
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: OSSL_ECHSTORE_num_keys failed (%d)", ksrv);
    else
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: OSSL_ECHSTORE_num_keys number of keys loaded %d",
          numkeys);
}
#endif
#endif

__attribute_pure__
static const buffer *
mod_openssl_refresh_ech_key_is_ech_only(plugin_ssl_ctx * const s, const char * const h, size_t hlen)
{
    /* (similar to mod_openssl_ech_only(), but without hctx) */
    const array * const ech_only_hosts =
      mod_openssl_plugin_data->ech_only_hosts;
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

#define PEM_BEGIN_PKEY      "-----BEGIN PRIVATE KEY-----"
#define PEM_END_PKEY        "-----END PRIVATE KEY-----"
#define PEM_BEGIN_ECHCONFIG "-----BEGIN ECHCONFIG-----"
#define PEM_END_ECHCONFIG   "-----END ECHCONFIG-----"

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

  #if defined(BORINGSSL_API_VERSION)

    SSL_ECH_KEYS *keys = SSL_ECH_KEYS_new();
    if (keys == NULL) {
        array_free_data(&a);
        return 0;
    }

    int rc = 1;
    for (uint32_t i = 0; i < a.used; ++i) {
        buffer * const n = &a.sorted[i]->key;
        buffer_append_path_len(kp, BUF_PTR_LEN(n)); /* *.ech */

        int rv = 0;
        off_t dlen = 64*1024;/*(arbitrary limit: 64 KB file; expect < 1 KB)*/
        char *data = fdevent_load_file(kp->ptr, &dlen, srv->errh, malloc, free);
        EVP_HPKE_KEY key;
        EVP_HPKE_KEY_zero(&key);
        buffer * const tb = srv->tmp_buf;
        buffer_clear(tb);
        do {
            if (NULL == data) break;

            char *b, *e;
            uint32_t len;
            b = strstr(data, PEM_BEGIN_PKEY);
            if (NULL == b) break;
            b += sizeof(PEM_BEGIN_PKEY)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_PKEY);
            if (NULL == e) break;
            len = (uint32_t)(e - b);

            buffer_clear(tb);
            if (NULL == buffer_append_base64_decode(tb,b,len,BASE64_STANDARD))
                break;

            const uint8_t *x = (uint8_t *)tb->ptr;
            EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL,&x,(long)buffer_clen(tb));
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

            size_t out_len = buffer_clen(tb); /*(large enough)*/
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

            b = strstr(data, PEM_BEGIN_ECHCONFIG);
            if (NULL == b) break;
            b += sizeof(PEM_BEGIN_ECHCONFIG)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_ECHCONFIG);
            if (NULL == e) break;
            len = (uint32_t)(e - b);

            buffer_clear(tb);
            if (NULL == buffer_append_base64_decode(tb,b,len,BASE64_STANDARD))
                break;

            /* OpenSSL tool 'openssl ech' ECHConfig begins with 2-byte len;
             * BoringSSL 'tool/bssl generate-ech' ECHConfig does not */
            if (buffer_clen(tb) > 2
                && (uint32_t)((tb->ptr[0]<<4)|tb->ptr[1]) == buffer_clen(tb)-2){
                memmove(tb->ptr, tb->ptr+2, buffer_clen(tb)-2);
                buffer_truncate(tb, buffer_clen(tb)-2);
            }

            const int is_retry_config = ((data_integer *)a.sorted[i])->value;
            rv = SSL_ECH_KEYS_add(keys, is_retry_config,
                                  (uint8_t *)BUF_PTR_LEN(tb), &key);
        } while (0);
        ck_memzero(tb->ptr, buffer_clen(tb));
        EVP_HPKE_KEY_cleanup(&key);
        if (dlen) ck_memzero(data, dlen);
        free(data);

        if (0 == rv) {
            elog(srv->errh, __FILE__, __LINE__, kp->ptr);
            rc = 0;
        }

        buffer_truncate(kp, dirlen);
    }

    if (1 != SSL_CTX_set1_ech_keys(s->ssl_ctx, keys))
        rc = 0;
    SSL_ECH_KEYS_free(keys);

  #else  /* !BORINGSSL_API_VERSION */

    OSSL_ECHSTORE * const es = OSSL_ECHSTORE_new(NULL, NULL);
    if (es == NULL) {
        array_free_data(&a);
        return 0;
    }

    /* load all echconfig files matching *.ech */
    int rc = 1;
    for (uint32_t i = 0; i < a.used; ++i) {
        buffer * const n = &a.sorted[i]->key;
        buffer_append_path_len(kp, BUF_PTR_LEN(n)); /* *.ech */

        BIO *in = BIO_new_file(kp->ptr, "r");
        const int is_retry_config = ((data_integer *)a.sorted[i])->value;
        if (in != NULL
            && 1 == OSSL_ECHSTORE_read_pem(es, in, is_retry_config)) {
          #ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: OSSL_ECHSTORE_read_pem() worked for %s", kp->ptr);
          #endif
        }
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: OSSL_ECHSTORE_read_pem() failed for %s", kp->ptr);
            rc = 0;
        }
        BIO_free_all(in);

        buffer_truncate(kp, dirlen);
    }

    if (1 != SSL_CTX_set1_echstore(s->ssl_ctx, es))
        rc = 0;
   #ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
    else
        ech_key_status_trace(srv, es);
   #endif
    OSSL_ECHSTORE_free(es);

  #endif /* !BORINGSSL_API_VERSION */

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


#ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
#if !defined(BORINGSSL_API_VERSION)

__attribute_const__
static const char * ech_status_str (int status)
{
  #define s(x) #x
    switch (status) {
      case SSL_ECH_STATUS_BACKEND:   return s(SSL_ECH_STATUS_BACKEND);
      case SSL_ECH_STATUS_GREASE_ECH:return s(SSL_ECH_STATUS_GREASE_ECH);
      case SSL_ECH_STATUS_GREASE:    return s(SSL_ECH_STATUS_GREASE);
      case SSL_ECH_STATUS_SUCCESS:   return s(SSL_ECH_STATUS_SUCCESS);
      case SSL_ECH_STATUS_FAILED:    return s(SSL_ECH_STATUS_FAILED);
      case SSL_ECH_STATUS_BAD_CALL:  return s(SSL_ECH_STATUS_BAD_CALL);
      case SSL_ECH_STATUS_NOT_TRIED: return s(SSL_ECH_STATUS_NOT_TRIED);
      case SSL_ECH_STATUS_BAD_NAME:  return s(SSL_ECH_STATUS_BAD_NAME);
      case SSL_ECH_STATUS_NOT_CONFIGURED:
                                     return s(SSL_ECH_STATUS_NOT_CONFIGURED);
      case SSL_ECH_STATUS_FAILED_ECH:return s(SSL_ECH_STATUS_FAILED_ECH);
      case SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:
                                     return
                                       s(SL_ECH_STATUS_FAILED_ECH_BAD_NAME);
      default:                       return NULL;
    }
  #undef s
}

static void ech_status_trace(request_st *r, SSL *ssl)
{
    char *sni_ech = NULL;
    char *sni_clr = NULL;
    int status = SSL_ech_get1_status(ssl, &sni_ech, &sni_clr);
    const char *str = ech_status_str(status);
    const char *ech = sni_ech ? sni_ech : "";
    const char *clr = sni_clr ? sni_clr : "";
    if (str)
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "ech_status: %s sni_clr: %s sni_ech: %s", str, clr, ech);
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "ech_status: %d sni_clr: %s sni_ech: %s", status, clr, ech);
    OPENSSL_free(sni_ech);
    OPENSSL_free(sni_clr);
}

static unsigned int
mod_openssl_ech_cb (SSL * const ssl, const char * const str)
{
    /*(callback is run after successful ECH extension decryption)*/
    UNUSED(ssl);
    UNUSED(str);
  #ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
    handler_ctx * const hctx = (handler_ctx *) SSL_get_app_data(ssl);
    ech_status_trace(hctx->r, ssl);
  #endif
    return 1;
}

#endif /* !BORING_API_VERSION */
#endif /* LIGHTTPD_OPENSSL_ECH_DEBUG */


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
  #if defined(BORINGSSL_API_VERSION)
    switch (SSL_ech_accepted(hctx->ssl))
  #else
    switch (SSL_ech_get1_status(hctx->ssl, &sni_ech, &sni_clr))
  #endif
    {
      case SSL_ECH_STATUS_SUCCESS:
        /* require that request :authority (Host) match SNI in ECH to avoid one
         * ECH-provided host testing for existence of another ECH-only host.
         * 'sni_ech' is assumed normalized since ECH decryption succeeded. */
       {
      #if defined(BORINGSSL_API_VERSION)
        const char *ech =
          SSL_get_servername(hctx->ssl, TLSEXT_NAMETYPE_host_name);
      #else
        const char *ech = sni_ech;
      #endif
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
    return (mod_openssl_plugin_data = ck_calloc(1, sizeof(plugin_data)));
}


static int mod_openssl_init_once_openssl (server *srv)
{
    if (ssl_is_init) return 1;

  #if OPENSSL_VERSION_NUMBER >= 0x10100000L \
   && (!defined(LIBRESSL_VERSION_NUMBER) \
       || LIBRESSL_VERSION_NUMBER >= 0x2070000fL)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
                    |OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                       |OPENSSL_INIT_ADD_ALL_DIGESTS
                       |OPENSSL_INIT_LOAD_CONFIG, NULL);
  #else
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
  #endif
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

  #if OPENSSL_VERSION_NUMBER >= 0x10100000L \
   && !defined(LIBRESSL_VERSION_NUMBER)
    /*(OpenSSL libraries handle thread init and deinit)
     * https://github.com/openssl/openssl/pull/1048 */
  #else
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
   #if OPENSSL_VERSION_NUMBER >= 0x10000000L
    ERR_remove_thread_state(NULL);
   #else
    ERR_remove_state(0);
   #endif
    EVP_cleanup();
  #endif

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
  #if OPENSSL_VERSION_NUMBER < 0x10002000 || defined(LIBRESSL_VERSION_NUMBER)
    array_free(p->cafiles);
  #endif
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
                    sk_X509_NAME_pop_free(cacerts->names, X509_NAME_free);
                    X509_STORE_free(cacerts->store);
                    free(cacerts);
                }
                break;
              case 3: /* ssl.ca-dn-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    sk_X509_NAME_pop_free(cpv->v.v, X509_NAME_free);
                break;
              default:
                break;
            }
        }
    }
}


#ifdef SSL_OP_ENABLE_KTLS /* openssl 3.0.0 */

#ifdef __linux__
#include <sys/utsname.h>/* uname() */
#include "sys-unistd.h" /* read() close() getuid() */
__attribute_cold__
static int
mod_tls_linux_has_ktls (void)
{
    /* file in special proc filesystem returns 0 size to stat(),
     * so unable to use fdevent_load_file() */
    static const char file[] = "/proc/sys/net/ipv4/tcp_available_ulp";
    char buf[1024];
    int fd = fdevent_open_cloexec(file, 1, O_RDONLY, 0);
    if (-1 == fd) return -1; /*(/proc not mounted?)*/
    ssize_t rd = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (-1 == rd) return -1;
    int has_ktls = 0;
    if (rd > 0) {
        buf[rd] = '\0';
        char *p = buf;
        has_ktls =
          (0 == strncmp(p, "tls", 3) ? (p+=3)
           : (p = strstr(p, " tls")) ? (p+=4) : NULL)
          && (*p == ' ' || *p == '\n' || *p == '\0');
    }
    return has_ktls; /* false if kernel tls module not loaded */
}

__attribute_cold__
static int
mod_tls_linux_modprobe_tls (void)
{
    if (0 == getuid()) {
          char *argv[3];
          *(const char **)&argv[0] = "/usr/sbin/modprobe";
          *(const char **)&argv[1] = "tls";
          *(const char **)&argv[2] = NULL;
          pid_t pid = /*(send input and output to /dev/null)*/
            fdevent_fork_execve(argv[0], argv, NULL, -1, -1, STDOUT_FILENO, -1);
          if (pid > 0)
            fdevent_waitpid(pid, NULL, 0);
          return mod_tls_linux_has_ktls();
    }
    return 0;
}
#endif /* __linux__ */

#ifdef __FreeBSD__
#include <sys/sysctl.h> /* sysctlbyname() */
#endif

__attribute_cold__
static int
mod_tls_check_kernel_ktls (void)
{
    int has_ktls = 0;

   #ifdef __linux__
    struct utsname uts;
    if (0 == uname(&uts)) {
        /* check two or more digit linux major kernel ver or >= kernel 4.13 */
        /* (avoid #include <stdio.h> for scanf("%d.%d.%d"); limit stdio.h use)*/
        const char * const v = uts.release;
        int rv = v[1] != '.' || v[0]-'0' > 4
              || (v[0]-'0' == 4 && v[3] != '.' /*(last 4.x.x was 4.20.x)*/
                  && (v[2]-'0' > 1 || (v[2]-'0' == 1 && v[3]-'0' >= 3)));
        if (rv && 0 == (rv = mod_tls_linux_has_ktls()))
            rv = mod_tls_linux_modprobe_tls();
        has_ktls = rv;
    }
   #endif
   #ifdef __FreeBSD__
    size_t ktls_sz = sizeof(has_ktls);
    if (0 != sysctlbyname("kern.ipc.tls.enable",
                          &has_ktls, &ktls_sz, NULL, 0)) {
      #if 0 /*(not present on kernels < FreeBSD 13 unless backported)*/
        log_perror(srv->errh, __FILE__, __LINE__,
          "sysctl(\"kern.ipc.tls.enable\")");
      #endif
        has_ktls = -1;
    }
   #endif

    /* has_ktls = 1:enabled; 0:disabled; -1:unable to determine */
    return has_ktls;
}

__attribute_cold__
static void
mod_openssl_check_ktls (void)
{
    int rv = mod_tls_check_kernel_ktls();

    /* disable ktls if ktls not available or if unable to determine */
    ktls_enable = (rv > 0);
}

#endif /* SSL_OP_ENABLE_KTLS */


/* use memory from openssl secure heap for temporary buffers, returned storage
 * (pemfile might contain a private key in addition to certificate chain)
 * Interfaces similar to those constructed in include/openssl/pem.h for
 * PEM_read_bio_X509(), except this is named PEM_read_bio_X509_secmem().
 * Similar for PEM_read_bio_X509_AUX_secmem().
 *
 * Supporting routine PEM_ASN1_read_bio_secmem() modified from openssl
 * crypto/pem/pem_oth.c:PEM_ASN1_read_bio():
 *   uses PEM_bytes_read_bio_secmem() instead of PEM_bytes_read_bio()
 *   uses OPENSSL_secure_clear_free() instead of OPENSSL_free()
 *
 * 'man PEM_bytes_read_bio_secmem()' and see NOTES section for more info
 * PEM_bytes_read_bio_secmem() openssl 1.1.1 or later
 * OPENSSL_secure_clear_free() openssl 1.1.0g or later
 * As this comment is being written, only openssl 1.1.1 is actively maintained.
 * Earlier vers of openssl no longer receive security patches from openssl.org.
 */
static void *
PEM_ASN1_read_bio_secmem(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                         pem_password_cb *cb, void *u)
{
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len = 0;
    char *ret = NULL;

  #if OPENSSL_VERSION_NUMBER >= 0x10101000L \
   && !defined(BORINGSSL_API_VERSION) \
   && !defined(LIBRESSL_VERSION_NUMBER)
    if (!PEM_bytes_read_bio_secmem(&data, &len, NULL, name, bp, cb, u))
  #else
    if (!PEM_bytes_read_bio(&data, &len, NULL, name, bp, cb, u))
  #endif
        return NULL;
    p = data;
    ret = d2i(x, &p, len);
  #ifndef BORINGSSL_API_VERSION /* missing PEMerr() macro */
    if (ret == NULL)
      #if OPENSSL_VERSION_NUMBER < 0x30000000L
        PEMerr(PEM_F_PEM_ASN1_READ_BIO, ERR_R_ASN1_LIB);
      #else
        ERR_raise(ERR_LIB_PEM, ERR_R_ASN1_LIB);
      #endif
  #endif
    /* boringssl provides OPENSSL_secure_clear_free() in commit
     * 8a1542fc41b43bdcd67cd341c1d332d2e05e2340 (not yet in a release)
     * (note: boringssl already calls OPENSSL_cleanse() in OPENSSL_free()) */
  #if OPENSSL_VERSION_NUMBER >= 0x10101000L \
   && !defined(BORINGSSL_API_VERSION) \
   && !defined(LIBRESSL_VERSION_NUMBER)
    OPENSSL_secure_clear_free(data, len);
  #else
    OPENSSL_cleanse(data, len);
    OPENSSL_free(data);
  #endif
    return ret;
}


static X509 *
PEM_read_bio_X509_secmem(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read_bio_secmem((d2i_of_void *)d2i_X509,
                                    PEM_STRING_X509,
                                    bp, (void **)x, cb, u);
}


static X509 *
PEM_read_bio_X509_AUX_secmem(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read_bio_secmem((d2i_of_void *)d2i_X509_AUX,
                                    PEM_STRING_X509_TRUSTED,
                                    bp, (void **)x, cb, u);
}


static int
mod_openssl_load_X509_sk (const char *file, log_error_st *errh, STACK_OF(X509) **chain, BIO *in)
{
    STACK_OF(X509) *chain_sk = NULL;
    for (X509 *ca; (ca = PEM_read_bio_X509_secmem(in,NULL,NULL,NULL)); ) {
        if (NULL == chain_sk) /*(allocate only if it will not be empty)*/
            chain_sk = sk_X509_new_null();
        if (!chain_sk || !sk_X509_push(chain_sk, ca)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: couldn't read X509 certificates from '%s'", file);
            if (chain_sk) sk_X509_pop_free(chain_sk, X509_free);
            X509_free(ca);
            return 0;
        }
    }
    *chain = chain_sk;
    return 1;
}


static int
mod_openssl_load_X509_STORE (const char *file, log_error_st *errh, X509_STORE **chain, BIO *in)
{
    X509_STORE *chain_store = NULL;
    for (X509 *ca; (ca = PEM_read_bio_X509(in,NULL,NULL,NULL)); X509_free(ca)) {
        if (NULL == chain_store) /*(allocate only if it will not be empty)*/
            chain_store = X509_STORE_new();
        if (!chain_store || !X509_STORE_add_cert(chain_store, ca)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: couldn't read X509 certificates from '%s'", file);
            if (chain_store) X509_STORE_free(chain_store);
            X509_free(ca);
            return 0;
        }
    }
    *chain = chain_store;
    return 1;
}


static plugin_cacerts *
mod_openssl_load_cacerts (const buffer *ssl_ca_file, log_error_st *errh)
{
    const char *file = ssl_ca_file->ptr;
    BIO *in = BIO_new(BIO_s_file());
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new(BIO_s_file()) failed");
        return NULL;
    }

    if (BIO_read_filename(in, file) <= 0) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_read_filename('%s') failed", file);
        BIO_free(in);
        return NULL;
    }

    X509_STORE *chain_store = NULL;
    if (!mod_openssl_load_X509_STORE(file, errh, &chain_store, in)) {
        BIO_free(in);
        return NULL;
    }

    BIO_free(in);

    if (NULL == chain_store) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: ssl.verifyclient.ca-file is empty %s", file);
        return NULL;
    }

    plugin_cacerts *cacerts = ck_malloc(sizeof(plugin_cacerts));

    /* (would be more efficient to walk the X509_STORE and build the list,
     *  but this works for now and matches how ssl.ca-dn-file is handled) */
    cacerts->names = SSL_load_client_CA_file(file);
    if (NULL == cacerts->names) {
        X509_STORE_free(chain_store);
        free(cacerts);
        return NULL;
    }

    cacerts->store = chain_store;
    cacerts->crl_file = NULL;
    cacerts->crl_loadts = 0;
    return cacerts;
}


static int
mod_openssl_load_cacrls (X509_STORE *store, const char *ssl_ca_crl_file, server *srv)
{
  #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (1 != X509_STORE_load_file(store, ssl_ca_crl_file))
  #else
    if (1 != X509_STORE_load_locations(store, ssl_ca_crl_file, NULL))
  #endif
    {
        elog(srv->errh, __FILE__, __LINE__, ssl_ca_crl_file);
        return 0;
    }
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    return 1;
}


#if OPENSSL_VERSION_NUMBER < 0x10002000 \
 || defined(LIBRESSL_VERSION_NUMBER)
static int
mod_openssl_load_verify_locn (SSL_CTX *ssl_ctx, const buffer *b, server *srv)
{
    const char *fn = b->ptr;
    if (1 == SSL_CTX_load_verify_locations(ssl_ctx, fn, NULL))
        return 1;

    elog(srv->errh, __FILE__, __LINE__, fn);
    return 0;
}


static int
mod_openssl_load_ca_files (SSL_CTX *ssl_ctx, plugin_data *p, server *srv)
{
    /* load all ssl.ca-files specified in the config into each SSL_CTX */

    for (uint32_t i = 0, used = p->cafiles->used; i < used; ++i) {
        const buffer *b = &((data_string *)p->cafiles->data[i])->value;
        if (!mod_openssl_load_verify_locn(ssl_ctx, b, srv))
            return 0;
    }
    return 1;
}
#endif


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
    plugin_data * const p = mod_openssl_plugin_data;
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

/* https://wiki.openssl.org/index.php/Manual:SSL_CTX_set_verify(3)#EXAMPLES */
static int
verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    X509 *err_cert;
    int err, depth;
    SSL *ssl;
    handler_ctx *hctx;

    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    /*
     * Retrieve the pointer to the SSL of the connection currently treated
     * and the application specific data stored into the SSL object.
     */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    hctx = (handler_ctx *) SSL_get_app_data(ssl);

    /*
     * Catch a too long certificate chain. The depth limit set using
     * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
     * that whenever the "depth>verify_depth" condition is met, we
     * have violated the limit and want to log this error condition.
     * We must do it here, because the CHAIN_TOO_LONG error would not
     * be found explicitly; only errors introduced by cutting off the
     * additional certificates would be logged.
     */
    if (depth > hctx->conf.ssl_verifyclient_depth) {
        preverify_ok = 0;
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }

    if (preverify_ok && 0 == depth && NULL != hctx->conf.ssl_ca_dn_file) {
        /* verify that client cert is issued by CA in ssl.ca-dn-file
         * if both ssl.ca-dn-file and ssl.ca-file were configured */
        STACK_OF(X509_NAME) * const cert_names = hctx->conf.ssl_ca_dn_file;
        X509_NAME *issuer;
      #if OPENSSL_VERSION_NUMBER >= 0x10002000L
        err_cert = X509_STORE_CTX_get_current_cert(ctx);
      #else
        err_cert = ctx->current_cert;
      #endif
        if (NULL == err_cert) return !hctx->conf.ssl_verifyclient_enforce;
        issuer = X509_get_issuer_name(err_cert);
      #if 0 /*(?desirable/undesirable to have cert_names sorted?)*/
        if (-1 != sk_X509_NAME_find(cert_names, issuer))
            return preverify_ok; /* match */
      #else
        for (int i = 0, len = sk_X509_NAME_num(cert_names); i < len; ++i) {
            if (0 == X509_NAME_cmp(sk_X509_NAME_value(cert_names, i), issuer))
                return preverify_ok; /* match */
        }
      #endif

        preverify_ok = 0;
        err = X509_V_ERR_CERT_REJECTED;
        X509_STORE_CTX_set_error(ctx, err);
    }

    if (preverify_ok) {
        return preverify_ok;
    }

  #if OPENSSL_VERSION_NUMBER >= 0x10002000L
    err_cert = X509_STORE_CTX_get_current_cert(ctx);
  #else
    err_cert = ctx->current_cert;
  #endif
    if (NULL == err_cert) return !hctx->conf.ssl_verifyclient_enforce;
    safer_X509_NAME_oneline(X509_get_subject_name(err_cert),buf,sizeof(buf));
    log_error_st *errh = hctx->r->conf.errh;
    log_error(errh, __FILE__, __LINE__,
      "SSL: addr:%s verify error:num=%d:%s:depth=%d:subject=%s",
      hctx->con->dst_addr_buf.ptr,
      err, X509_verify_cert_error_string(err), depth, buf);

    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                          err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        safer_X509_NAME_oneline(X509_get_issuer_name(err_cert),buf,sizeof(buf));
        log_error(errh, __FILE__, __LINE__,
          "SSL: addr:%s issuer=%s", hctx->con->dst_addr_buf.ptr, buf);
    }

    return !hctx->conf.ssl_verifyclient_enforce;
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

  #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
   && (!defined(LIBRESSL_VERSION_NUMBER) \
       || LIBRESSL_VERSION_NUMBER >= 0x3000000fL)
    if (hctx->kp->ssl_pemfile_chain) {
    }
   #if !defined(BORINGSSL_API_VERSION) \
    && !defined(LIBRESSL_VERSION_NUMBER)
    /* (missing SSL_set1_chain_cert_store() and SSL_build_cert_chain()) */
    else if (hctx->conf.ssl_ca_file && !hctx->kp->self_issued) {
        /* preserve legacy behavior whereby openssl will reuse CAs trusted for
         * certificate verification (set by SSL_CTX_load_verify_locations() in
         * SSL_CTX) in order to build certificate chain for server certificate
         * sent to client */
        if (1 != SSL_use_certificate(ssl, hctx->kp->ssl_pemfile_x509)) {
            elogf(hctx->r->conf.errh, __FILE__, __LINE__,
              "failed to set certificate for TLS server name %s",
              hctx->r->uri.authority.ptr);
            return 0;
        }

        SSL_set1_chain_cert_store(ssl, hctx->conf.ssl_ca_file->store);

        if (1 != SSL_build_cert_chain(ssl,
                                        SSL_BUILD_CHAIN_FLAG_NO_ROOT
                                      | SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR
                                      | SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR)) {
            elogf(hctx->r->conf.errh, __FILE__, __LINE__,
              "building cert chain for TLS server name %s",
              hctx->r->uri.authority.ptr);
            return 0;
        }
        else { /* copy chain for future reuse */
            STACK_OF(X509) *chain = NULL;
            SSL_get0_chain_certs(ssl, &chain);
            hctx->kp->ssl_pemfile_chain = X509_chain_up_ref(chain);
            SSL_set1_chain_cert_store(ssl, NULL);
        }
    }
   #endif
  #endif

    if (1 != mod_openssl_SSL_use_cert_and_key(ssl, pc, hctx->kp)) {
        elogf(hctx->r->conf.errh, __FILE__, __LINE__,
          "failed to set cert for TLS server name %s",
          hctx->r->uri.authority.ptr);
        return 0;
    }
  }

  #ifndef OPENSSL_NO_OCSP
  #ifdef BORINGSSL_API_VERSION
    /* BoringSSL suggests API different than SSL_CTX_set_tlsext_status_cb() */
    buffer *ocsp_resp = hctx->kp->ssl_stapling_der;
    if (NULL != ocsp_resp
        && !SSL_set_ocsp_response(ssl, (uint8_t *)BUF_PTR_LEN(ocsp_resp))) {
        elogf(hctx->r->conf.errh, __FILE__, __LINE__,
          "failed to set OCSP response for TLS server name %s",
          hctx->r->uri.authority.ptr);
        return 0;
    }
  #endif
  #endif

    /* (openssl library keeps refcnts on its objects) */
    /* retain hctx->kp if needed for OCSP staping response (tlsext_status_cb) */
  #if !defined(OPENSSL_NO_OCSP) && !defined(BORINGSSL_API_VERSION)
    if (NULL == hctx->kp->ssl_stapling_der)
  #endif
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
      #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
       && !defined(LIBRESSL_VERSION_NUMBER)
        SSL_set1_verify_cert_store(ssl, hctx->conf.ssl_ca_file->store);
      #endif
        /* WTH openssl?  SSL_set_client_CA_list() calls set0_CA_list(),
         * but there is no set1_CA_list() to simply up the reference count
         * (without needing to duplicate the list) */
        STACK_OF(X509_NAME) * const cert_names = hctx->conf.ssl_ca_dn_file
          ? hctx->conf.ssl_ca_dn_file
          : hctx->conf.ssl_ca_file->names;
        SSL_set_client_CA_list(ssl, SSL_dup_CA_list(cert_names));
        int mode = SSL_VERIFY_PEER;
        if (hctx->conf.ssl_verifyclient_enforce)
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_set_verify(ssl, mode, verify_callback);
        SSL_set_verify_depth(ssl, hctx->conf.ssl_verifyclient_depth + 1);
    }
    else {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
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
      #if defined(BORINGSSL_API_VERSION)
        int rc = SSL_ech_accepted(hctx->ssl);
      #else
        char *sni_ech = NULL;
        char *sni_clr = NULL;
        int rc = SSL_ech_get1_status(hctx->ssl, &sni_ech, &sni_clr);
        OPENSSL_free(sni_ech);
        OPENSSL_free(sni_clr);
      #endif
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

  #if OPENSSL_VERSION_NUMBER >= 0x10002000L \
   && !defined(LIBRESSL_VERSION_NUMBER)
    return SSL_TLSEXT_ERR_OK;
  #else
    return (mod_openssl_cert_cb(hctx->ssl, NULL) == 1)
      ? SSL_TLSEXT_ERR_OK
      : SSL_TLSEXT_ERR_ALERT_FATAL;
  #endif
}

#ifdef SSL_CLIENT_HELLO_SUCCESS
static int
mod_openssl_client_hello_cb (SSL *ssl, int *al, void *srv)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    buffer_copy_string_len(&hctx->r->uri.scheme, CONST_STR_LEN("https"));
    UNUSED(srv);

    const unsigned char *name;
    size_t len, slen;
  #ifdef TLSEXT_TYPE_ech
    /* code currently inactive; see top of file #undef SSL_CLIENT_HELLO_SUCCESS.
     * Were the openssl ECH callback (set with SSL_CTX_ech_set_callback()) to
     * become something other than what it currently is (mainly informational),
     * then we might reconsider using it.  An alternative idea is to leverage
     * the cert_cb (always called during client hello processing and set with
     * SSL_CTX_set_cert_cb()) to access outcome of ECH or SNI immediately prior
     * to server certificate selection.  Prior to existence of cert_cb, the use
     * of servername_callback (set with SSL_CTX_set_tlsext_servername_callback)
     * was needed to handle SNI, but might now be folded into cert_cb. */
   #if 0
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ech, &name, &len)) {
        return SSL_CLIENT_HELLO_SUCCESS; /* defer to later ECH processing */
    }
   #endif
  #endif
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &name, &len)) {
        return SSL_CLIENT_HELLO_SUCCESS; /* client did not provide SNI */
    }

    /* expecting single element in the server_name extension; parse first one */
    if (len > 5
        && (size_t)((name[0] << 8) + name[1]) == len-2
        && name[2] == TLSEXT_TYPE_server_name
        && (slen = (name[3] << 8) + name[4]) <= len-5) { /*(first)*/
        int read_ahead = hctx->conf.ssl_read_ahead;
        int rc = mod_openssl_SNI(hctx, (const char *)name+5, slen);
        if (!read_ahead && hctx->conf.ssl_read_ahead)
            SSL_set_read_ahead(ssl, hctx->conf.ssl_read_ahead);
        if (rc == SSL_TLSEXT_ERR_OK)
            return SSL_CLIENT_HELLO_SUCCESS;
    }

    *al = TLS1_AD_UNRECOGNIZED_NAME;
    return SSL_CLIENT_HELLO_ERROR;
}
#else
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
    size_t len = strlen(servername);
    int read_ahead = hctx->conf.ssl_read_ahead;
    int rc = mod_openssl_SNI(hctx, servername, len);
    if (!read_ahead && hctx->conf.ssl_read_ahead)
        SSL_set_read_ahead(ssl, hctx->conf.ssl_read_ahead);
    return rc;
}
#endif
#endif


#if OPENSSL_VERSION_NUMBER < 0x10101000L \
 || !(defined(_LP64) || defined(__LP64__) || defined(_WIN64)) \
 || defined(BORINGSSL_API_VERSION) \
 ||(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3060000fL)
static unix_time64_t
mod_openssl_asn1_time_to_posix (const ASN1_TIME *asn1time);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L \
 && !defined(BORINGSSL_API_VERSION) \
 && !defined(LIBRESSL_VERSION_NUMBER)
#define X509_get0_notBefore X509_get_notBefore
#define X509_get0_notAfter  X509_get_notAfter
#endif

static int
mod_openssl_cert_is_active (const X509 *crt)
{
    const ASN1_TIME *notBefore = X509_get0_notBefore(crt);
    const ASN1_TIME *notAfter  = X509_get0_notAfter(crt);
  #if OPENSSL_VERSION_NUMBER < 0x10101000L \
   || !(defined(_LP64) || defined(__LP64__) || defined(_WIN64)) \
   || defined(BORINGSSL_API_VERSION) \
   ||(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3060000fL)
    const unix_time64_t before = mod_openssl_asn1_time_to_posix(notBefore);
    const unix_time64_t after  = mod_openssl_asn1_time_to_posix(notAfter);
    const unix_time64_t now = log_epoch_secs;
    return (0 <= before && before <= now && now <= after);
  #else /*(-2 is an error from ASN1_TIME_cmp_time_t(); test cmp for -1, 0, 1)*/
    const unix_time64_t now = log_epoch_secs;
    const int before_cmp = ASN1_TIME_cmp_time_t(notBefore, (time_t)now);
    const int after_cmp  = ASN1_TIME_cmp_time_t(notAfter,  (time_t)now);
    return ((before_cmp == -1 || before_cmp == 0) && 0 <= after_cmp);
  #endif
}


static X509 *
mod_openssl_load_pem_file (const char *file, log_error_st *errh, STACK_OF(X509) **chain)
{
    *chain = NULL;

    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(file, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;

    BIO *in = BIO_new_mem_buf(data, (int)dlen);
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new/BIO_read_filename('%s') failed", file);
        if (dlen) ck_memzero(data, dlen);
        free(data);
        return NULL;
    }

    int is_pem = (NULL != strstr(data, "-----"));
    X509 *x = is_pem
      ? PEM_read_bio_X509_AUX_secmem(in, NULL, NULL, NULL)
      : d2i_X509_bio(in, NULL);
    if (NULL == x) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: couldn't read X509 certificate from '%s'", file);
    }
    else if (is_pem && !mod_openssl_load_X509_sk(file, errh, chain, in)) {
        X509_free(x);
        x = NULL;
    }
    else if (!mod_openssl_cert_is_active(x) && log_epoch_secs > 300) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: inactive/expired X509 certificate '%s'", file);
    }

    BIO_free(in);
    if (dlen) ck_memzero(data, dlen);
    free(data);
    return x;
}


static EVP_PKEY *
mod_openssl_evp_pkey_load_pem_file (const char *file, log_error_st *errh)
{
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(file, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;
    EVP_PKEY *x = NULL;
    BIO *in = BIO_new_mem_buf(data, (int)dlen);
    if (NULL != in) {
        x = (NULL != strstr(data, "-----"))
          ? PEM_read_bio_PrivateKey(in, NULL, NULL, NULL)
          : d2i_PrivateKey_bio(in, NULL);
        BIO_free(in);
    }
    if (dlen) ck_memzero(data, dlen);
    free(data);

    if (NULL == in)
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new/BIO_read_filename('%s') failed", file);
    else if (NULL == x)
        log_error(errh, __FILE__, __LINE__,
          "SSL: couldn't read private key from '%s'", file);

    return x;
}


#if OPENSSL_VERSION_NUMBER >= 0x10002000 && !defined(LIBRESSL_VERSION_NUMBER)
/* LibreSSL does not support SSL_set1_verify_cert_store() at this time */

__attribute_noinline__
static int
mod_openssl_reload_crl_file (server *srv, plugin_cacerts *cacerts, const unix_time64_t cur_ts)
{
  #if OPENSSL_VERSION_NUMBER < 0x10100000
    /* fall through to perform initial load, but skip reload for 1.0.2 */
    /*(X509_STORE_get0_objects(), X509_OBJECT_get0_X509() available in 1.1.0)*/
    if (cacerts->store)
        return 1;
  #endif

    /* CRLs can be updated at any time, though expected on/before Next Update */
    /* For BoringSSL, SSL_CTX_set_cert_store() is called in network_init_ssl()
     * to support auto-chaining.  Since only CRLs are updated here, there are
     * no modifications needed there; the SSL_CTX will keep reference to
     * original ref-counted X509_STORE for cert auto-chaining.  (Or, we could
     * add code to resolve all certificate chains at startup.) */
    X509_STORE * const new_store = X509_STORE_new();
    if (NULL == new_store)
        return 0;
    X509_STORE * const store = cacerts->store;
    int rc = 1;
  #if OPENSSL_VERSION_NUMBER >= 0x10100000
    /* duplicate X509_STORE with X509 objects and skip CRLs */
    /* (modelled off X509_STORE_get1_all_certs()) */
    /*X509_STORE_lock(store);*/
    STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
    for (int i = 0, num = sk_X509_OBJECT_num(objs); i < num && rc; ++i) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
        if (cert != NULL)
            rc = X509_STORE_add_cert(new_store, cert);
    }
    /*X509_STORE_unlock(store);*/
  #endif

    if (rc) {
        rc = mod_openssl_load_cacrls(new_store, cacerts->crl_file, srv);
        if (rc) {
            cacerts->crl_loadts = cur_ts;
            cacerts->store = new_store;
        }
    }
    /* XXX: not thread-safe if another thread has pointer to store and is about
     * to perform client certificate verification */
    X509_STORE_free(rc ? store : new_store);
    return rc;
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

#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000 && !LIBRESSL_VERSION_NUMBER */


#ifndef OPENSSL_NO_OCSP

static buffer *
mod_openssl_load_stapling_file (const char *file, log_error_st *errh, buffer *b)
{
    /* load stapling .der into buffer *b only if successful
     *
     * Note: for some TLS libs, the OCSP stapling response is not copied when
     * assigned to a session (and is reasonable since not changed frequently)
     * - BoringSSL SSL_set_ocsp_response()
     * - WolfSSL SSL_set_tlsext_status_ocsp_resp() (differs from OpenSSL API)
     * Therefore, there is a potential race condition if the OCSP response is
     * assigned to the session during the handshake and the Server Hello is
     * partially sent, AND (unlikely, if possible at all), the TLS library is
     * in the middle of reading this OSCP response buffer.  If the OCSP response
     * is replaced due to an updated ssl.stapling-file (checked periodically),
     * AND the buffer is resized, this would be a problem.  Resizing the buffer
     * is unlikely since updated OSCP response for same certificate are
     * typically the same size with the signature and dates refreshed.
     */

    /* load raw .der file */
    off_t dlen = 1*1024*1024;/*(arbitrary limit: 1 MB file; expect < 1 KB)*/
    char *data = fdevent_load_file(file, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;

  #if defined(BORINGSSL_API_VERSION)

    if (NULL == b)
        b = buffer_init();
    else if (b->ptr)
        free(b->ptr);
    b->ptr  = data;
    b->used = (uint32_t)dlen;
    b->size = (uint32_t)dlen+1;
    return b;

  #else

    BIO *in = BIO_new_mem_buf(data, (int)dlen);
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new/BIO_read_filename('%s') failed", file);
        free(data);
        return NULL;
    }

    OCSP_RESPONSE *x = d2i_OCSP_RESPONSE_bio(in, NULL);
    BIO_free(in);
    free(data);
    if (NULL == x) {
        elogf(errh, __FILE__, __LINE__,
          "OCSP stapling file read error: %s", file);
        return NULL;
    }

    unsigned char *rspder = NULL;
    int rspderlen = i2d_OCSP_RESPONSE(x, &rspder);

    if (rspderlen > 0) {
        if (NULL == b) b = buffer_init();
        buffer_copy_string_len(b, (char *)rspder, (uint32_t)rspderlen);
    }

    OPENSSL_free(rspder);
    OCSP_RESPONSE_free(x);
    return rspderlen ? b : NULL;

  #endif
}

#endif /* OPENSSL_NO_OCSP */


static unix_time64_t
mod_openssl_asn1_time_to_posix (const ASN1_TIME *asn1time)
{
  #if defined(BORINGSSL_API_VERSION) && BORINGSSL_API_VERSION >= 19

    int64_t t;
    return ASN1_TIME_to_posix(asn1time, &t) ? (unix_time64_t)t : -1;

  #elif defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER>=0x2050100fL

    struct tm x;
   #if LIBRESSL_VERSION_NUMBER >= 0x3050000fL
    if (!ASN1_TIME_to_tm(asn1time, &x))
        return -1;
   #else /* LIBRESSL_VERSION_NUMBER >= 0x2050100fL */
    if (-1 == ASN1_time_parse(asn1time->data, asn1time->length, &x, 0))
        return -1;
   #endif
    time_t t = timegm(&x);
    return (t != (time_t)-1) ? TIME64_CAST(t) : t;

  #elif (defined(LIBRESSL_VERSION_NUMBER) \
         && LIBRESSL_VERSION_NUMBER < 0x3050000fL) \
     || (!defined(LIBRESSL_VERSION_NUMBER) \
         && OPENSSL_VERSION_NUMBER < 0x10002000L)
    /* LibreSSL was forked from OpenSSL 1.0.1; does not have ASN1_TIME_diff */

    /*(Note: all certificate times are expected to use UTC)*/
    /*(Note: does not strictly validate string contains appropriate digits)*/
    /*(Note: incorrectly assumes GMT if 'Z' or offset not provided)*/
    /*(Note: incorrectly ignores if local timezone might be in DST)*/

    if (NULL == asn1time || NULL == asn1time->data) return -1;
    const char *s = (const char *)asn1time->data;
    size_t len = strlen(s);
    struct tm x;
    x.tm_isdst = 0;
    x.tm_yday = 0;
    x.tm_wday = 0;
    switch (asn1time->type) {
      case V_ASN1_UTCTIME:         /* 2-digit year */
        if (len < 8) return -1;
        len -= 8;
        x.tm_year = (s[0]-'0')*10 + (s[1]-'0');
        x.tm_year += (x.tm_year < 50 ? 2000 : 1900);
        s += 2;
        break;
      case V_ASN1_GENERALIZEDTIME: /* 4-digit year */
        if (len < 10) return -1;
        len -= 10;
        x.tm_year = (s[0]-'0')*1000+(s[1]-'0')*100+(s[2]-'0')*10+(s[3]-'0');
        s += 4;
        break;
      default:
        return -1;
    }
    x.tm_mon  = (s[0]-'0')*10 + (s[1]-'0');
    x.tm_mday = (s[2]-'0')*10 + (s[3]-'0');
    x.tm_hour = (s[4]-'0')*10 + (s[5]-'0');
    x.tm_min  = 0;
    x.tm_sec  = 0;
    s += 6;
    if (len >= 2 && s[0] != '+' && s[0] != '-' && s[0] != 'Z') {
        len -= 2;
        x.tm_min = (s[0]-'0')*10 + (s[1]-'0');
        s += 2;
        if (len >= 2 && s[0] != '+' && s[0] != '-' && s[0] != 'Z') {
            len -= 2;
            x.tm_sec = (s[0]-'0')*10 + (s[1]-'0');
            s += 2;
            if (len && s[0] == '.') {
                /*(ignore .fff fractional seconds;
                 * should be up to 3 digits but we ignore more)*/
                do { ++s; --len; } while (*s >= '0' && *s <= '9');
            }
        }
    }
    int offset = 0;
    if ((*s == '-' || *s == '+') && len != 5) {
        offset = ((s[1]-'0')*10 + (s[2]-'0')) * 3600
               + ((s[3]-'0')*10 + (s[4]-'0')) * 60;
        if (*s == '-') offset = -offset;
    }
    else if (s[0] != '\0' && (s[0] != 'Z' || s[1] != '\0'))
        return -1;

    if (x.tm_year == 9999 && x.tm_mon == 12 && x.tm_mday == 31
        && x.tm_hour == 23 && x.tm_min == 59 && x.tm_sec == 59 && s[0] == 'Z')
        return -1; // 99991231235959Z RFC 5280

    x.tm_year-= 1900;
    x.tm_mon -= 1;
    time_t t = timegm(&x);
    return (t != (time_t)-1) ? TIME64_CAST(t) + offset : t;

  #else

   #if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(BORINGSSL_API_VERSION)

    struct tm x;
    if (!ASN1_TIME_to_tm(asn1time, &x))
        return -1;
    time_t t = timegm(&x);
    return (t != (time_t)-1) ? TIME64_CAST(t) : t;

   #else

    /* Note: this does not check for integer overflow of time_t! */
    int day, sec;
    return ASN1_TIME_diff(&day, &sec, NULL, asn1time)
      ? log_epoch_secs + day*86400 + sec
      : -1;

   #endif

  #endif
}


#ifndef OPENSSL_NO_OCSP

static unix_time64_t
mod_openssl_ocsp_next_update (buffer *der)
{
  #if defined(BORINGSSL_API_VERSION)
    UNUSED(der);
    return -1; /*(not implemented)*/
  #else
    const unsigned char *p = (unsigned char *)der->ptr; /*(p gets modified)*/
    OCSP_RESPONSE *ocsp = d2i_OCSP_RESPONSE(NULL, &p, buffer_clen(der));
    if (NULL == ocsp) return -1;
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(ocsp);
    if (NULL == bs) {
        OCSP_RESPONSE_free(ocsp);
        return -1;
    }

    /* XXX: should save and evaluate cert status returned by these calls */
    ASN1_TIME *nextupd = NULL;
    OCSP_single_get0_status(OCSP_resp_get0(bs, 0), NULL, NULL, NULL, &nextupd);
    unix_time64_t t = nextupd
      ? mod_openssl_asn1_time_to_posix(nextupd)
      : (time_t)-1;

    /* Note: trust external process which creates ssl.stapling-file to verify
     *       (as well as to validate certificate status)
     * future: verify OCSP response here to double-check */

    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(ocsp);

    return t;
  #endif
}


__attribute_cold__
static void
mod_openssl_expire_stapling_file (server *srv, plugin_cert *pc)
{
    mod_openssl_kp * const kp = pc->kp;
    if (NULL == kp->ssl_stapling_der) /*(previously discarded or never loaded)*/
        return;

    /* discard expired OCSP stapling response */
    buffer_free(kp->ssl_stapling_der);
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
    mod_openssl_kp * const kp = pc->kp;
    buffer *b = mod_openssl_load_stapling_file(pc->ssl_stapling_file->ptr,
                                               srv->errh, kp->ssl_stapling_der);
    if (!b) return 0;

    kp->ssl_stapling_der = b; /*(unchanged unless orig was NULL)*/
    kp->ssl_stapling_loadts = cur_ts;
    kp->ssl_stapling_nextts = mod_openssl_ocsp_next_update(b);
    if (kp->ssl_stapling_nextts == (time_t)-1) {
        /* "Next Update" might not be provided by OCSP responder
         * Use 3600 sec (1 hour) in that case. */
        /* retry in 1 hour if unable to determine Next Update */
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


static int
mod_openssl_crt_must_staple (const X509 *crt)
{
  #if OPENSSL_VERSION_NUMBER < 0x10100000L \
   || defined(BORINGSSL_API_VERSION) \
   || defined(LIBRESSL_VERSION_NUMBER)
    /*(not currently supported in BoringSSL or LibreSSL)*/
    UNUSED(crt);
    return 0;
  #else
    /* openssl/x509v3.h:typedef STACK_OF(ASN1_INTEGER) TLS_FEATURE; */

    TLS_FEATURE *tlsf = X509_get_ext_d2i(crt, NID_tlsfeature, NULL, NULL);
    if (NULL == tlsf) return 0;

    int rc = 0;

    for (int i = 0; i < sk_ASN1_INTEGER_num(tlsf); ++i) {
        ASN1_INTEGER *ai = sk_ASN1_INTEGER_value(tlsf, i);
        long tlsextid = ASN1_INTEGER_get(ai);
        if (tlsextid == 5) { /* 5 = OCSP Must-Staple */
            rc = 1;
            break;
        }
    }

    sk_ASN1_INTEGER_pop_free(tlsf, ASN1_INTEGER_free);
    return rc; /* 1 if OCSP Must-Staple found; 0 if not */
  #endif
}

#endif /* OPENSSL_NO_OCSP */


__attribute_noinline__
static plugin_cert *
network_openssl_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey, const buffer *ssl_stapling_file)
{
    if (!mod_openssl_init_once_openssl(srv)) return NULL;

    STACK_OF(X509) *ssl_pemfile_chain = NULL;
    X509 *ssl_pemfile_x509 =
      mod_openssl_load_pem_file(pemfile->ptr, srv->errh, &ssl_pemfile_chain);
    if (NULL == ssl_pemfile_x509)
        return NULL;

    EVP_PKEY *ssl_pemfile_pkey =
      mod_openssl_evp_pkey_load_pem_file(privkey->ptr, srv->errh);
    if (NULL == ssl_pemfile_pkey) {
        X509_free(ssl_pemfile_x509);
        sk_X509_pop_free(ssl_pemfile_chain, X509_free);
        return NULL;
    }

    if (!X509_check_private_key(ssl_pemfile_x509, ssl_pemfile_pkey)) {
        elogf(srv->errh, __FILE__, __LINE__, "SSL:"
          "Private key does not match the certificate public key %s %s",
          pemfile->ptr, privkey->ptr);
        EVP_PKEY_free(ssl_pemfile_pkey);
        X509_free(ssl_pemfile_x509);
        sk_X509_pop_free(ssl_pemfile_chain, X509_free);
        return NULL;
    }

    plugin_cert *pc = ck_malloc(sizeof(plugin_cert));
    mod_openssl_kp * const kp = pc->kp = mod_openssl_kp_init();
    kp->ssl_pemfile_pkey = ssl_pemfile_pkey;
    kp->ssl_pemfile_x509 = ssl_pemfile_x509;
    kp->ssl_pemfile_chain= ssl_pemfile_chain;
    pc->ssl_pemfile = pemfile;
    pc->ssl_privkey = privkey;
    pc->ssl_stapling_file= ssl_stapling_file;
    pc->pkey_ts = log_epoch_secs;
  #ifndef OPENSSL_NO_OCSP
    kp->must_staple = mod_openssl_crt_must_staple(ssl_pemfile_x509);
  #else
    kp->must_staple = 0;
  #endif
    kp->self_issued =
      (0 == X509_NAME_cmp(X509_get_subject_name(ssl_pemfile_x509),
                          X509_get_issuer_name(ssl_pemfile_x509)));

    if (pc->ssl_stapling_file) {
      #ifndef OPENSSL_NO_OCSP
        if (!mod_openssl_reload_stapling_file(srv, pc, log_epoch_secs)) {
            /* continue without OCSP response if there is an error */
        }
      #else
        log_error(srv->errh, __FILE__, __LINE__, "SSL:"
          "OCSP stapling not supported; ignoring %s",
          pc->ssl_stapling_file->ptr);
      #endif
    }
    else if (kp->must_staple) {
        log_error(srv->errh, __FILE__, __LINE__,
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
    X509 *ssl_pemfile_x509 = NULL;
    STACK_OF(X509) *ssl_pemfile_chain = NULL;
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
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
        ssl_pemfile_x509 =
          mod_openssl_load_pem_file(b->ptr, errh, &ssl_pemfile_chain);
        if (NULL == ssl_pemfile_x509) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        buffer_truncate(b, len); /*(remove ".crt.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        ssl_pemfile_pkey = mod_openssl_evp_pkey_load_pem_file(b->ptr, errh);
        if (NULL == ssl_pemfile_pkey) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

      #if 0 /* redundant with below? */
        if (!X509_check_private_key(ssl_pemfile_x509, ssl_pemfile_pkey)) {
            elogf(errh, __FILE__, __LINE__,
               "Private key does not match acme-tls/1 "
               "certificate public key %s", b->ptr);
            break;
        }
      #endif

        /* first set certificate!
         * setting private key checks whether certificate matches it */
        if (1 != SSL_use_certificate(ssl, ssl_pemfile_x509)) {
            elogf(errh, __FILE__, __LINE__,
              "failed to set acme-tls/1 certificate for TLS server name %s",
              name->ptr);
            break;
        }

        if (ssl_pemfile_chain) {
            SSL_set0_chain(ssl, ssl_pemfile_chain);
            ssl_pemfile_chain = NULL;
        }

        if (1 != SSL_use_PrivateKey(ssl, ssl_pemfile_pkey)) {
            elogf(errh, __FILE__, __LINE__,
              "failed to set acme-tls/1 private key for TLS server name %s",
              name->ptr);
            break;
        }

        hctx->conf.ssl_verifyclient_enforce = 0;
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        rc = SSL_TLSEXT_ERR_OK;
    } while (0);

    if (ssl_pemfile_pkey) EVP_PKEY_free(ssl_pemfile_pkey);
    if (ssl_pemfile_x509) X509_free(ssl_pemfile_x509);
    if (ssl_pemfile_chain)
        sk_X509_pop_free(ssl_pemfile_chain, X509_free);

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

  #if OPENSSL_VERSION_NUMBER < 0x10100000L
    return SSL_TLSEXT_ERR_NOACK;
  #else
    return hctx->r->handler_module /*(e.g. mod_sockproxy)*/
      ? SSL_TLSEXT_ERR_NOACK
      : SSL_TLSEXT_ERR_ALERT_FATAL;
  #endif
}

#endif /* TLSEXT_TYPE_application_layer_protocol_negotiation */

#endif /* OPENSSL_NO_TLSEXT */


#if defined(BORINGSSL_API_VERSION) \
 || defined(LIBRESSL_VERSION_NUMBER)
static int
mod_openssl_ssl_conf_cmd (server *srv, plugin_config_socket *s);
#endif


static int
network_openssl_ssl_conf_cmd (server *srv, plugin_config_socket *s)
{
  #ifdef SSL_CONF_FLAG_CMDLINE

    int rc = 0;
    const data_string *ds;
    SSL_CONF_CTX * const cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_ssl_ctx(cctx, s->ssl_ctx);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE
                               | SSL_CONF_FLAG_SERVER
                               | SSL_CONF_FLAG_SHOW_ERRORS
                               | SSL_CONF_FLAG_CERTIFICATE);

    /* always disable null and export ciphers */
    ds = (const data_string *)
      array_get_element_klen(s->ssl_conf_cmd,
                             CONST_STR_LEN("CipherString"));
    if (NULL != ds) {
        buffer *cipher_string =
          array_get_buf_ptr(s->ssl_conf_cmd, CONST_STR_LEN("CipherString"));
        if (buffer_is_blank(cipher_string))
            buffer_append_string_len(cipher_string, CONST_STR_LEN("HIGH"));
        buffer_append_string_len(cipher_string,
                                 CONST_STR_LEN(":!aNULL:!eNULL:!EXP"));
    }

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        ds = (data_string *)s->ssl_conf_cmd->data[i];
        /* ("SecurityLevel" is lighttpd extension to SSL_CONF_cmd() syntax)
         * SSL_CTX_set_security_level() is specific to OpenSSL >= 1.1.0 */
        if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("SecurityLevel"))) {
          #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            int level = atoi(ds->value.ptr);
            if (level >= 0) SSL_CTX_set_security_level(s->ssl_ctx, level);
          #endif
            continue;
        }
      #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("DHParameters")))
            SSL_CTX_set_dh_auto(s->ssl_ctx, 0);
      #endif
        ERR_clear_error();
        if (SSL_CONF_cmd(cctx, ds->key.ptr, ds->value.ptr) <= 0) {
            elogf(srv->errh, __FILE__, __LINE__,
              "SSL_CONF_cmd %s %s", ds->key.ptr, ds->value.ptr);
            rc = -1;
            break;
        }
    }

    if (0 == rc && 1 != SSL_CONF_CTX_finish(cctx)) {
        elog(srv->errh, __FILE__, __LINE__, "SSL_CONF_CTX_finish()");
        rc = -1;
    }

    SSL_CONF_CTX_free(cctx);
    return rc;

  #elif defined(BORINGSSL_API_VERSION) \
     || defined(LIBRESSL_VERSION_NUMBER)

    return mod_openssl_ssl_conf_cmd(srv, s);

  #else

    UNUSED(s);
    log_error(srv->errh, __FILE__, __LINE__,
      "SSL: ssl.openssl.ssl-conf-cmd not available; ignored");
    return 0;

  #endif
}


#if OPENSSL_VERSION_NUMBER < 0x30000000L
#ifndef OPENSSL_NO_DH
#if !defined(BORINGSSL_API_VERSION) && !defined(AWSLC_API_VERSION)
#if OPENSSL_VERSION_NUMBER < 0x10100000L \
 || (defined(LIBRESSL_VERSION_NUMBER) \
     && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
#define DH_set0_pqg(dh, dh_p, NULL, dh_g) \
        ((dh)->p = (dh_p), (dh)->g = (dh_g), (dh_p) != NULL && (dh_g) != NULL)
#endif
/* https://tools.ietf.org/html/rfc7919#appendix-A.1
 * A.1.  ffdhe2048
 *
 * https://ssl-config.mozilla.org/ffdhe2048.txt
 * C code generated with: openssl dhparam -C -in ffdhe2048.txt
 */
static DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAD, 0xF8,
        0x54, 0x58, 0xA2, 0xBB, 0x4A, 0x9A, 0xAF, 0xDC, 0x56, 0x20,
        0x27, 0x3D, 0x3C, 0xF1, 0xD8, 0xB9, 0xC5, 0x83, 0xCE, 0x2D,
        0x36, 0x95, 0xA9, 0xE1, 0x36, 0x41, 0x14, 0x64, 0x33, 0xFB,
        0xCC, 0x93, 0x9D, 0xCE, 0x24, 0x9B, 0x3E, 0xF9, 0x7D, 0x2F,
        0xE3, 0x63, 0x63, 0x0C, 0x75, 0xD8, 0xF6, 0x81, 0xB2, 0x02,
        0xAE, 0xC4, 0x61, 0x7A, 0xD3, 0xDF, 0x1E, 0xD5, 0xD5, 0xFD,
        0x65, 0x61, 0x24, 0x33, 0xF5, 0x1F, 0x5F, 0x06, 0x6E, 0xD0,
        0x85, 0x63, 0x65, 0x55, 0x3D, 0xED, 0x1A, 0xF3, 0xB5, 0x57,
        0x13, 0x5E, 0x7F, 0x57, 0xC9, 0x35, 0x98, 0x4F, 0x0C, 0x70,
        0xE0, 0xE6, 0x8B, 0x77, 0xE2, 0xA6, 0x89, 0xDA, 0xF3, 0xEF,
        0xE8, 0x72, 0x1D, 0xF1, 0x58, 0xA1, 0x36, 0xAD, 0xE7, 0x35,
        0x30, 0xAC, 0xCA, 0x4F, 0x48, 0x3A, 0x79, 0x7A, 0xBC, 0x0A,
        0xB1, 0x82, 0xB3, 0x24, 0xFB, 0x61, 0xD1, 0x08, 0xA9, 0x4B,
        0xB2, 0xC8, 0xE3, 0xFB, 0xB9, 0x6A, 0xDA, 0xB7, 0x60, 0xD7,
        0xF4, 0x68, 0x1D, 0x4F, 0x42, 0xA3, 0xDE, 0x39, 0x4D, 0xF4,
        0xAE, 0x56, 0xED, 0xE7, 0x63, 0x72, 0xBB, 0x19, 0x0B, 0x07,
        0xA7, 0xC8, 0xEE, 0x0A, 0x6D, 0x70, 0x9E, 0x02, 0xFC, 0xE1,
        0xCD, 0xF7, 0xE2, 0xEC, 0xC0, 0x34, 0x04, 0xCD, 0x28, 0x34,
        0x2F, 0x61, 0x91, 0x72, 0xFE, 0x9C, 0xE9, 0x85, 0x83, 0xFF,
        0x8E, 0x4F, 0x12, 0x32, 0xEE, 0xF2, 0x81, 0x83, 0xC3, 0xFE,
        0x3B, 0x1B, 0x4C, 0x6F, 0xAD, 0x73, 0x3B, 0xB5, 0xFC, 0xBC,
        0x2E, 0xC2, 0x20, 0x05, 0xC5, 0x8E, 0xF1, 0x83, 0x7D, 0x16,
        0x83, 0xB2, 0xC6, 0xF3, 0x4A, 0x26, 0xC1, 0xB2, 0xEF, 0xFA,
        0x88, 0x6B, 0x42, 0x38, 0x61, 0x28, 0x5C, 0x97, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}
#endif /* !BORINGSSL_API_VERSION && !AWSLC_API_VERSION */
#endif /* !OPENSSL_NO_DH */
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */


static int
mod_openssl_ssl_conf_dhparameters(server *srv, plugin_config_socket *s, const buffer *dhparameters)
{
  #ifdef OPENSSL_NO_DH
    if (dhparameters) {
        UNUSED(s);
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: openssl compiled without DH support, "
          "can't load parameters from %s", dhparameters->ptr);
    }
  #elif defined(BORINGSSL_API_VERSION) || defined(AWSLC_API_VERSION)
    if (dhparameters) {
        UNUSED(s);
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: BoringSSL/AWS-LC does not support FFDH cipher suites; "
          "skipping loading parameters from %s", dhparameters->ptr);
    }
  #else
   #if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH *dh;
    /* Support for Diffie-Hellman key exchange */
    if (dhparameters) {
        /* DH parameters from file */
        BIO *bio;
        bio = BIO_new_file((char *) dhparameters->ptr, "r");
        if (bio == NULL) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unable to open file %s", dhparameters->ptr);
            return 0;
        }
        dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (dh == NULL) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: PEM_read_bio_DHparams failed %s", dhparameters->ptr);
            return 0;
        }
        SSL_CTX_set_tmp_dh(s->ssl_ctx, dh);
        DH_free(dh);
    }
    else {
        dh = get_dh2048();
        if (dh == NULL) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: get_dh2048() failed");
            return 0;
        }
        SSL_CTX_set_tmp_dh(s->ssl_ctx, dh);
        DH_free(dh);
    }
   #else
    /* OSSL_STORE_open() available in openssl 1.1.1, but might
     * not be present in alt TLS libs (libressl or boringssl) */
    EVP_PKEY *dhpkey = NULL;
    if (dhparameters) {
        OSSL_STORE_CTX *ctx = NULL;
        ctx = OSSL_STORE_open(dhparameters->ptr, NULL, NULL, NULL, NULL);
        if (NULL != ctx) {
            if (OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PARAMS)) {
                while (!OSSL_STORE_eof(ctx)) {
                    OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
                    if (info) {
                        dhpkey = OSSL_STORE_INFO_get1_PARAMS(info);
                        OSSL_STORE_INFO_free(info);
                    }
                    break;
                }
            }
            OSSL_STORE_close(ctx);
        }
        if (!dhpkey || !EVP_PKEY_is_a(dhpkey, "DH")
            || !SSL_CTX_set0_tmp_dh_pkey(s->ssl_ctx, dhpkey)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "Unable to load DH params from %s", dhparameters->ptr);
            EVP_PKEY_free(dhpkey);
            dhpkey = NULL;
        } /*(else dhpkey ownership transferred upon success)*/
    }
    if (NULL == dhpkey)
        SSL_CTX_set_dh_auto(s->ssl_ctx, 1);
   #endif
    SSL_CTX_set_options(s->ssl_ctx, SSL_OP_SINGLE_DH_USE);
  #endif

    return 1;
}


static int
mod_openssl_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *ssl_ec_curve)
{
  #if OPENSSL_VERSION_NUMBER >= 0x0090800fL
  #ifndef OPENSSL_NO_ECDH
  #if defined(BORINGSSL_API_VERSION) \
   || (defined(LIBRESSL_VERSION_NUMBER) \
       && LIBRESSL_VERSION_NUMBER >= 0x2050100fL)
    /* boringssl eccurves_default[] (now kDefaultGroups[])
     * has been the equivalent of "X25519:secp256r1:secp384r1" since 2016
     * (previously with secp521r1 appended for Android)
     * (and before that the equivalent of "secp256r1:secp384r1:secp521r1"
     *  since mid 2014) */
    /* libressl eccurves_default[] (now ecgroups_server_default[])
     * has been the equivalent of "X25519:secp256r1:secp384r1"
     * since libressl v2.5.1 (Feb 2017) which added SSL_CTX_set1_groups_list()*/
    if (NULL == ssl_ec_curve || buffer_is_blank(ssl_ec_curve))
        return 1;
  #endif

  #if (defined(BORINGSSL_API_VERSION) && BORINGSSL_API_VERSION >= 3) \
   || (defined(LIBRESSL_VERSION_NUMBER) \
       && LIBRESSL_VERSION_NUMBER >= 0x2050100fL) \
   || OPENSSL_VERSION_NUMBER >= 0x10100000L
    const char *groups = ssl_ec_curve && !buffer_is_blank(ssl_ec_curve)
      ? ssl_ec_curve->ptr
      :
       #if defined(BORINGSSL_API_VERSION) || defined(LIBRESSL_VERSION_NUMBER)
        /* libressl recognizes X448, but does not appear to implement X448 */
        /* boringssl include/openssl/evp.h contains comment:
         * > EVP_PKEY_X448 is defined for OpenSSL compatibility, but we do not
         * > support X448 and attempts to create keys will fail.
         */
        "X25519:P-256:P-384";
       #else
        /* openssl recognizes and implements X448 */
        "X25519:P-256:P-384:X448";
       #endif

   #if (defined(BORINGSSL_API_VERSION) && BORINGSSL_API_VERSION >= 19) \
    || (defined(LIBRESSL_VERSION_NUMBER) \
        && LIBRESSL_VERSION_NUMBER >= 0x2050100fL) \
    || OPENSSL_VERSION_NUMBER >= 0x10101000L
    int rc = SSL_CTX_set1_groups_list(s->ssl_ctx, groups);
   #elif (defined(BORINGSSL_API_VERSION) && BORINGSSL_API_VERSION >= 3) \
      || OPENSSL_VERSION_NUMBER >= 0x10100000L
    int rc = SSL_CTX_set1_curves_list(s->ssl_ctx, groups);
   #endif
    if (1 != rc) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: Unable to config groups %s", groups);
        return 0;
    }
  #else
    /* Support for Elliptic-Curve Diffie-Hellman key exchange */
    /* OpenSSL only supports the "named curves" from RFC 4492, section 5.1.1. */
    const char *curve = ssl_ec_curve ? ssl_ec_curve->ptr : "prime256v1";
    int nid = 0;
    if (ssl_ec_curve) {
        /* OpenSSL only supports the "named curves"
         * from RFC 4492, section 5.1.1. */
        nid = OBJ_sn2nid((char *) curve);
        if (nid == 0) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unknown curve name %s", curve);
            return 0;
        }
    }
    else {
      #if OPENSSL_VERSION_NUMBER < 0x10002000
        /* Default curve */
        nid = OBJ_sn2nid("prime256v1");
      #elif OPENSSL_VERSION_NUMBER < 0x10100000L \
         || defined(LIBRESSL_VERSION_NUMBER)
        if (!SSL_CTX_set_ecdh_auto(s->ssl_ctx, 1)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: SSL_CTX_set_ecdh_auto() failed");
        }
      #endif
    }
    if (nid) {
      #if OPENSSL_VERSION_NUMBER < 0x30000000L
        EC_KEY *ecdh;
        ecdh = EC_KEY_new_by_curve_name(nid);
        if (ecdh == NULL) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unable to create curve %s", curve);
            return 0;
        }
        SSL_CTX_set_tmp_ecdh(s->ssl_ctx, ecdh);
        EC_KEY_free(ecdh);
      #else
        /* SSL_CTX_set1_groups() available in openssl 1.1.1, but might
         * not be present in alt TLS libs (libressl or boringssl) */
        if (1 != SSL_CTX_set1_groups(s->ssl_ctx, &nid, 1)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unable to config curve %s", curve);
            return 0;
        }
      #endif
        SSL_CTX_set_options(s->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
    }
  #endif
  #endif
  #endif
    UNUSED(srv);
    UNUSED(s);
    UNUSED(ssl_ec_curve);

    return 1;
}


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
      #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        uint64_t ssloptions =
      #elif defined(BORINGSSL_API_VERSION)
        uint32_t ssloptions =
      #else
        long ssloptions =
      #endif
                          SSL_OP_ALL
                        | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                        | SSL_OP_NO_COMPRESSION;

      #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        s->ssl_ctx = SSL_CTX_new(TLS_server_method());
      #else
        s->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
      #endif
        if (NULL == s->ssl_ctx) {
            elog(srv->errh, __FILE__, __LINE__, "SSL_CTX_new");
            return -1;
        }

      #ifdef SSL_OP_NO_RENEGOTIATION /* openssl 1.1.0 */
        ssloptions |= SSL_OP_NO_RENEGOTIATION;
      #endif
      #ifdef SSL_OP_ENABLE_KTLS /* openssl 3.0.0 */
        if (ktls_enable)
            ssloptions |= SSL_OP_ENABLE_KTLS;
      #ifdef SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE
        ssloptions |= SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE;
      #endif
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
       #if OPENSSL_VERSION_NUMBER < 0x30000000L
        SSL_CTX_set_tlsext_ticket_key_cb(s->ssl_ctx, ssl_tlsext_ticket_key_cb);
       #else  /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
        SSL_CTX_set_tlsext_ticket_key_evp_cb(s->ssl_ctx,
                                             ssl_tlsext_ticket_key_cb);
       #endif
      #endif

      #ifndef OPENSSL_NO_OCSP
      #ifndef BORINGSSL_API_VERSION /* BoringSSL suggests using different API */
        SSL_CTX_set_tlsext_status_cb(s->ssl_ctx, ssl_tlsext_status_cb);
      #endif
      #endif

      #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
       && !defined(LIBRESSL_VERSION_NUMBER)

        SSL_CTX_set_cert_cb(s->ssl_ctx, mod_openssl_cert_cb, NULL);
        UNUSED(p);

       #if defined(BORINGSSL_API_VERSION) /* BoringSSL limitation */
        /* set cert store for auto-chaining
         * BoringSSL does not support SSL_set1_chain_cert_store() in cert_cb */
        if (s->ssl_ca_file && s->ssl_ca_file->store) {
            if (!X509_STORE_up_ref(s->ssl_ca_file->store))
                return -1;
            SSL_CTX_set_cert_store(s->ssl_ctx, s->ssl_ca_file->store);
        }
       #endif

      #else /* OPENSSL_VERSION_NUMBER < 0x10002000 */

        /* load all ssl.ca-files specified in the config into each SSL_CTX
         * This might be a bit excessive, but are all trusted CAs;
         * load on-demand in mod_openssl_cert_cb() for openssl >= 1.0.2 */
        if (!mod_openssl_load_ca_files(s->ssl_ctx, p, srv))
            return -1;

        if (s->ssl_verifyclient) {
            if (NULL == s->ssl_ca_file) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: You specified ssl.verifyclient.activate "
                  "but no ssl.verifyclient.ca-file");
                return -1;
            }
            /* WTH openssl?  SSL_CTX_set_client_CA_list() calls set0_CA_list(),
             * but there is no set1_CA_list() to simply up the reference count
             * (without needing to duplicate the list) */
            STACK_OF(X509_NAME) * const cert_names = s->ssl_ca_dn_file
              ? s->ssl_ca_dn_file
              : s->ssl_ca_file->names;
            SSL_CTX_set_client_CA_list(s->ssl_ctx, SSL_dup_CA_list(cert_names));
            int mode = SSL_VERIFY_PEER;
            if (s->ssl_verifyclient_enforce) {
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            SSL_CTX_set_verify(s->ssl_ctx, mode, verify_callback);
            SSL_CTX_set_verify_depth(s->ssl_ctx, s->ssl_verifyclient_depth + 1);
            if (s->ssl_ca_crl_file && !buffer_is_blank(s->ssl_ca_crl_file)) {
                X509_STORE *store = SSL_CTX_get_cert_store(s->ssl_ctx);
                if (!mod_openssl_load_cacrls(store,s->ssl_ca_crl_file->ptr,srv))
                    return -1;
            }
        }

        /* only for OPENSSL_VERSION_NUMBER < 0x10002000
         * due to openssl SSL_CTX and SSL cert selection with ECDSA and RSA */

        if (1 != mod_openssl_SSL_CTX_use_cert_and_key(s->ssl_ctx,
                                                      s->pc, s->pc->kp)) {
            elogf(srv->errh, __FILE__, __LINE__, "%s %s",
              s->pc->ssl_pemfile->ptr, s->pc->ssl_privkey->ptr);
            return -1;
        }

      #endif /* OPENSSL_VERSION_NUMBER < 0x10002000 */

       #if defined(BORINGSSL_API_VERSION)
       #define SSL_CTX_set_default_read_ahead(ctx,m) \
               SSL_CTX_set_read_ahead(ctx,m)
       #endif
        SSL_CTX_set_default_read_ahead(s->ssl_ctx, s->ssl_read_ahead);
        SSL_CTX_set_mode(s->ssl_ctx, SSL_CTX_get_mode(s->ssl_ctx)
                                   | SSL_MODE_ENABLE_PARTIAL_WRITE
                                   | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
                                   | SSL_MODE_RELEASE_BUFFERS);

      #ifndef OPENSSL_NO_TLSEXT
       #ifdef SSL_CLIENT_HELLO_SUCCESS
        SSL_CTX_set_client_hello_cb(s->ssl_ctx,mod_openssl_client_hello_cb,srv);
       #else
        if (!SSL_CTX_set_tlsext_servername_callback(
               s->ssl_ctx, network_ssl_servername_callback) ||
            !SSL_CTX_set_tlsext_servername_arg(s->ssl_ctx, srv)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: failed to initialize TLS servername callback, "
              "openssl library does not support TLS servername extension");
            return -1;
        }
       #endif

       #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        SSL_CTX_set_alpn_select_cb(s->ssl_ctx,mod_openssl_alpn_select_cb,NULL);
       #endif
      #endif

      #if OPENSSL_VERSION_NUMBER >= 0x10100000L \
       || defined(BORINGSSL_API_VERSION) \
       || defined(LIBRESSL_VERSION_NUMBER)
       #ifdef TLS1_3_VERSION
        if (!SSL_CTX_set_min_proto_version(s->ssl_ctx, TLS1_3_VERSION))
       #else
        if (!SSL_CTX_set_min_proto_version(s->ssl_ctx, TLS1_2_VERSION))
       #endif
            return -1;
      #endif

      #ifndef OPENSSL_NO_ECH
        if (s->ech_opts) {
          #if defined(LIGHTTPD_OPENSSL_ECH_DEBUG)
          #if !defined(BORINGSSL_API_VERSION)
            SSL_CTX_ech_set_callback(s->ssl_ctx, mod_openssl_ech_cb);
          #endif
          #endif
          #if defined(SSL_OP_ECH_TRIALDECRYPT)
            /* enable SSL_OP_ECH_TRIALDECRYPT by default unless disabled;
             * prefer "Options" => "ECHTrialDecrypt"
             * in lighttpd ssl.openssl.ssl-conf-cmd */
            if (config_plugin_value_tobool(
                  array_get_element_klen(s->ech_opts,
                                         CONST_STR_LEN("trial-decrypt")), 1)) {
                SSL_CTX_set_options(s->ssl_ctx, SSL_OP_ECH_TRIALDECRYPT);
            }
          #endif
        }
      #endif

        if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
            if (0 != network_openssl_ssl_conf_cmd(srv, s)) return -1;
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

      #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
       && !defined(LIBRESSL_VERSION_NUMBER)
        mod_openssl_refresh_crl_files(srv, p, log_epoch_secs);
      #endif
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
  #if OPENSSL_VERSION_NUMBER < 0x10002000 || defined(LIBRESSL_VERSION_NUMBER)
    p->cafiles = array_init(0);
  #endif
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
        const buffer *ssl_ca_file = NULL;
        const buffer *ssl_ca_dn_file = NULL;
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
                ssl_ca_file = cpv->v.b;
                cpv->v.v = mod_openssl_load_cacerts(ssl_ca_file, srv->errh);
                if (NULL != cpv->v.v) {
                    cpv->vtype = T_CONFIG_LOCAL;
                    cacerts = (plugin_cacerts *)cpv->v.v;
                }
                else {
                    elog(srv->errh, __FILE__, __LINE__, ssl_ca_file->ptr);
                    return HANDLER_ERROR;
                }
                break;
              case 16:/* ssl.verifyclient.ca-dn-file */
                cpv->k_id = 3;
                __attribute_fallthrough__
              case 3: /* ssl.ca-dn-file */
                if (buffer_is_blank(cpv->v.b)) break;
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                ssl_ca_dn_file = cpv->v.b;
                cpv->v.v = SSL_load_client_CA_file(ssl_ca_dn_file->ptr);
                if (NULL != cpv->v.v) {
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                else {
                    elog(srv->errh, __FILE__, __LINE__, ssl_ca_dn_file->ptr);
                    return HANDLER_ERROR;
                }
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

      #if OPENSSL_VERSION_NUMBER < 0x10002000 /* p->cafiles for legacy only */ \
       || defined(LIBRESSL_VERSION_NUMBER)
        /* load all ssl.ca-files into a single chain */
        /*(certificate load order might matter)*/
        if (ssl_ca_dn_file)
            array_insert_value(p->cafiles, BUF_PTR_LEN(ssl_ca_dn_file));
        if (ssl_ca_file)
            array_insert_value(p->cafiles, BUF_PTR_LEN(ssl_ca_file));
        UNUSED(cacerts);
        UNUSED(ssl_ca_crl_file);
        UNUSED(default_ssl_ca_crl_file);
      #else
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
      #endif

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

  #if OPENSSL_VERSION_NUMBER < 0x30000000L \
   && !defined(BORINGSSL_API_VERSION) \
   && !defined(LIBRESSL_VERSION_NUMBER)
  if (log_epoch_secs >= 1792728000) /* 23 Oct 2026 */
    log_error(srv->errh, __FILE__, __LINE__, "SSL:"
      "openssl library version is outdated and has reached end-of-life.  "
      "As of 22 Oct 2026, only openssl 3.5 and later continue to receive "
      "security patches from openssl.org");
  else
    log_error(srv->errh, __FILE__, __LINE__, "SSL:"
      "openssl library version is outdated and has reached end-of-life.  "
      "As of 11 Sep 2023, only openssl 3.0 and later continue to receive "
      "security patches from openssl.org");
  #endif

  #ifdef SSL_OP_ENABLE_KTLS /* openssl 3.0.0 */
    mod_openssl_check_ktls();
  #endif

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
    handler_ctx * const hctx = con->plugin_ctx[mod_openssl_plugin_data->id];

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


#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int
connection_write_cq_ssl_ktls (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[mod_openssl_plugin_data->id];

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_openssl_close_notify(hctx);

    /* not done: scan cq for FILE_CHUNK within first max_bytes rather than
     * only using SSL_sendfile() if the first chunk is FILE_CHUNK.
     * Checking first chunk for FILE_CHUNK means that initial response headers
     * and beginning of file will be read into memory before subsequent writes
     * use SSL_sendfile().  TBD: possible to be further optimized? */

    for (chunk *c; (c = cq->first) && c->type == FILE_CHUNK; ) {
        off_t len = c->file.length - c->offset;
        if (len > max_bytes) len = max_bytes;
        if (0 == len) break; /*(FILE_CHUNK or max_bytes should not be 0)*/
        if (-1 == c->file.fd && 0 != chunk_open_file_chunk(c, hctx->errh))
            return -1;

      #if defined(__FreeBSD__) && defined(SF_NODISKIO)

        int flags = !c->file.busy ? SF_NODISKIO : 0;
       #ifdef SF_FLAGS
        flags = SF_FLAGS(32, flags);
       #endif
        ossl_ssize_t wr =
          SSL_sendfile(hctx->ssl, c->file.fd, c->offset, (size_t)len, flags);
        if (wr < 0) {
            c->file.busy = (errno == EBUSY);
          #if OPENSSL_VERSION_NUMBER < 0x30400000L /* && >= 0x30000000L */
            unsigned long err = ERR_peek_error();
            if (err && ERR_GET_LIB(err) != ERR_LIB_SYS
                && ERR_GET_REASON(err) == SSL_R_UNINITIALIZED) {
                int errnum = errno;
                if (errnum) {
                    err = ERR_get_error(); /* pop (invalid) error from queue */
                    ERR_raise_data(ERR_LIB_SYS,errnum,"ktls_sendfile failure");
                }
            }
          #endif
            return mod_openssl_write_err(hctx, (int)wr);
        }
        c->file.busy = 0;

      #else

        ossl_ssize_t wr =
          SSL_sendfile(hctx->ssl, c->file.fd, c->offset, (size_t)len, 0);
        if (wr < 0) {
          #if OPENSSL_VERSION_NUMBER < 0x30400000L /* && >= 0x30000000L */
            unsigned long err = ERR_peek_error();
            if (err && ERR_GET_LIB(err) != ERR_LIB_SYS
                && ERR_GET_REASON(err) == SSL_R_UNINITIALIZED) {
                int errnum = errno;
                if (errnum) {
                    err = ERR_get_error(); /* pop (invalid) error from queue */
                    ERR_raise_data(ERR_LIB_SYS,errnum,"ktls_sendfile failure");
                }
            }
          #endif
            return mod_openssl_write_err(hctx, (int)wr);
        }

      #endif

        chunkqueue_mark_written(cq, wr);
        max_bytes -= wr;

        if (wr < len) return 0; /* try again later */
    }

    return connection_write_cq_ssl(con, cq, max_bytes);
}
#endif


static int
connection_read_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[mod_openssl_plugin_data->id];
    int len;
    char *mem = NULL;
    size_t mem_len = 0;

    UNUSED(max_bytes);

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_openssl_close_notify(hctx);

    ERR_clear_error();
    do {
        len = SSL_pending(hctx->ssl);
        mem_len = len < 2048 ? 2048 : (size_t)len;
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

      #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        /* ideally should be done only once, after handshake completes,
         * so check each time for HTTP/2 so that we do not re-enable */
        if (hctx->r->http_version < HTTP_VERSION_2
            && BIO_get_ktls_send(SSL_get_wbio(hctx->ssl)) > 0)
            con->network_write = connection_write_cq_ssl_ktls;
      #endif
      #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        if (hctx->alpn) {
            if (hctx->alpn == MOD_OPENSSL_ALPN_H2) {
                if (0 != mod_openssl_alpn_h2_policy(hctx))
                    return -1;
              #if OPENSSL_VERSION_NUMBER >= 0x30000000L
                /*(not expecting FILE_CHUNKs in write_queue with h2,
                 * so skip ktls and SSL_sendfile; reset to default)*/
                con->network_write = connection_write_cq_ssl;
              #endif
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
    } while (len > 0
             && (hctx->conf.ssl_read_ahead || SSL_pending(hctx->ssl) > 0));

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
             * (unless hctx->conf.ssl_read_ahead is set)
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
                } while (ret > 0 && (hctx->conf.ssl_read_ahead||(ssl_r-=ret)));
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
    X509 *xs;
    X509_NAME *xn;
    buffer *vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_VERIFY"));

    long vr = SSL_get_verify_result(hctx->ssl);
    if (vr != X509_V_OK) {
        buffer_copy_string_len(vb, CONST_STR_LEN("FAILED:"));
        https_add_ssl_client_verify_err(vb, vr);
        return;
    }
  #if OPENSSL_VERSION_NUMBER < 0x30000000L
    else if (!(xs = SSL_get_peer_certificate(hctx->ssl)))
  #else
    else if (!(xs = SSL_get0_peer_certificate(hctx->ssl)))
  #endif
    {
        buffer_copy_string_len(vb, CONST_STR_LEN("NONE"));
        return;
    } else {
        buffer_copy_string_len(vb, CONST_STR_LEN("SUCCESS"));
    }

    xn = X509_get_subject_name(xs);
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
        BIO *bio;
        if (NULL != (bio = BIO_new(BIO_s_mem()))) {
            PEM_write_bio_X509(bio, xs);
            const int n = BIO_pending(bio);

            vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_CERT"));
            buffer_extend(vb, (uint32_t)n);
            BIO_read(bio, vb->ptr, n);
            BIO_free(bio);
        }
    }
  #if OPENSSL_VERSION_NUMBER < 0x30000000L
    X509_free(xs);
  #endif
}


#ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
#if !defined(BORINGSSL_API_VERSION)
static void
http_cgi_ssl_ech(request_st * const r, SSL * const ssl)
{
    /* add to environment ECH status, inner SNI, and outer SNI */
    char *sni_ech = NULL;
    char *sni_clr = NULL;
    int status = SSL_ech_get1_status(ssl, &sni_ech, &sni_clr);
    const char *str = ech_status_str(status);
    if (str == NULL) str = "ECH status unknown"; /*(alt: format status to str)*/
    http_header_env_set(r, CONST_STR_LEN("SSL_ECH_STATUS"), str, strlen(str));
    const char *clr = sni_clr ? sni_clr : "NONE";
    http_header_env_set(r, CONST_STR_LEN("SSL_ECH_OUTER_SNI"),clr,strlen(clr));
    const char *ech = sni_ech ? sni_ech : "NONE";
    http_header_env_set(r, CONST_STR_LEN("SSL_ECH_INNER_SNI"),ech,strlen(ech));
    OPENSSL_free(sni_ech);
    OPENSSL_free(sni_clr);
}
#endif
#endif


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

  #ifdef LIGHTTPD_OPENSSL_ECH_DEBUG
  #if !defined(BORINGSSL_API_VERSION)
    http_cgi_ssl_ech(r, hctx->ssl);
  #endif
  #endif
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


#if OPENSSL_VERSION_NUMBER >= 0x10002000 && !defined(LIBRESSL_VERSION_NUMBER)

static void
mod_openssl_refresh_plugin_ssl_ctx (server * const srv, plugin_ssl_ctx * const s)
{
    if (NULL == s->kp || NULL == s->pc || s->kp == s->pc->kp) return;
    mod_openssl_kp_rel(s->kp);
    s->kp = mod_openssl_kp_acq(s->pc);

  #if 0 /* disabled due to openssl quirks selecting incorrect certificate */
    if (1 != mod_openssl_SSL_CTX_use_cert_and_key(s->ssl_ctx, s->pc, s->kp)) {
        elogf(srv->errh, __FILE__, __LINE__, "%s %s",
          s->pc->ssl_pemfile->ptr, s->pc->ssl_privkey->ptr);
        /* no recovery until admin fixes input files */
    }
  #else
    UNUSED(mod_openssl_SSL_CTX_use_cert_and_key);
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

#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000 && !LIBRESSL_VERSION_NUMBER */


TRIGGER_FUNC(mod_openssl_handle_trigger) {
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/
    UNUSED(srv);
    UNUSED(p);

  #ifdef TLSEXT_TYPE_session_ticket
    mod_openssl_session_ticket_key_check(p, cur_ts);
  #endif

  #if OPENSSL_VERSION_NUMBER >= 0x10002000 && !defined(LIBRESSL_VERSION_NUMBER)
    /* enable with SSL_CTX_set_cert_cb() which runs unconditionally;
     * not enabled for older openssl or for LibreSSL since refcnt not incr if
     * SNI not present (when SSL_CTX_set_cert_cb() is not supported and used) */
    /*if (!(cur_ts & 0x3ff))*/ /*(once each 1024 sec (~17 min))*/
        if (feature_refresh_certs)
            mod_openssl_refresh_certs(srv, p);
  #else
    UNUSED(feature_refresh_certs);
  #endif

  #ifndef OPENSSL_NO_OCSP
    mod_openssl_refresh_stapling_files(srv, p, cur_ts);
  #endif

  #ifdef TLSEXT_TYPE_ech
    mod_openssl_refresh_ech_keys(srv, p, cur_ts);
  #endif

  #if OPENSSL_VERSION_NUMBER >= 0x10002000 && !defined(LIBRESSL_VERSION_NUMBER)
    if (feature_refresh_crls)
        mod_openssl_refresh_crl_files(srv, p, cur_ts);
  #else
    UNUSED(feature_refresh_crls);
  #endif

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_openssl_plugin_init (plugin *p);
int mod_openssl_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "openssl";
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


#if defined(BORINGSSL_API_VERSION) \
 || defined(LIBRESSL_VERSION_NUMBER)

static int
mod_openssl_ssl_conf_proto_val (server *srv, const buffer *b, int max)
{
    if (NULL == b) /* default: min TLSv1.3 (if supported), max TLSv1.3 */
      #ifdef TLS1_3_VERSION
        return TLS1_3_VERSION;
      #else
        return TLS1_2_VERSION;
      #endif
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        return max
          ?
           #ifdef TLS1_3_VERSION
            TLS1_3_VERSION
           #else
            TLS1_2_VERSION
           #endif
          : TLS1_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.0")))
        return TLS1_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.1")))
        return TLS1_1_VERSION;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        return TLS1_2_VERSION;
  #ifdef TLS1_3_VERSION
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        return TLS1_3_VERSION;
  #endif
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
  #ifdef TLS1_3_VERSION
    return TLS1_3_VERSION;
  #else
    return TLS1_2_VERSION;
  #endif
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
                 #ifdef SSL_OP_ENABLE_KTLS
                  case 4:
                    if (buffer_eq_icase_ssn(v, "KTLS", 4)) {
                        if (flag)
                            SSL_CTX_set_options(s->ssl_ctx,
                                                SSL_OP_ENABLE_KTLS);
                        else
                            SSL_CTX_clear_options(s->ssl_ctx,
                                                  SSL_OP_ENABLE_KTLS);
                        continue;
                    }
                    break;
                 #endif
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
      #if defined(LIBRESSL_VERSION_NUMBER) && defined(LIBRESSL_HAS_TLS1_3)
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

#endif /* BORINGSSL_API_VERSION || LIBRESSL_VERSION_NUMBER */
