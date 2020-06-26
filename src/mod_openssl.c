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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*(not needed)*/
#define OPENSSL_NO_STDIO

#ifndef USE_OPENSSL_KERBEROS
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#endif

#include "sys-crypto.h"

#ifdef BORINGSSL_API_VERSION
#undef OPENSSL_NO_STDIO /* for X509_STORE_load_locations() */
#endif

#ifdef WOLFSSL_OPTIONS_H
/* WolfSSL defines OPENSSL_VERSION_NUMBER 0x10001040L for OPENSSL_ALL
 * or HAVE_LIGHTY.  WolfSSL does not provide many interfaces added in
 * OpenSSL 1.0.2, including SSL_CTX_set_cert_cb(), so it is curious that
 * WolFSSL defines OPENSSL_VERSION_NUMBER 0x10100000L for WOLFSSL_APACHE_HTTPD*/
#ifndef OPENSSL_ALL
#define OPENSSL_ALL
#endif
#include <wolfssl/ssl.h>
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
#ifdef BORINGSSL_API_VERSION
/* BoringSSL purports to have some OCSP support */
#undef OPENSSL_NO_OCSP
#endif

#if ! defined OPENSSL_NO_TLSEXT && ! defined SSL_CTRL_SET_TLSEXT_HOSTNAME
#define OPENSSL_NO_TLSEXT
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#endif

#ifdef WOLFSSL_VERSION
#ifdef HAVE_ALPN
#undef OPENSSL_NO_TLSEXT
#else
#define OPENSSL_NO_TLSEXT
#endif
#ifdef HAVE_SESSION_TICKET
#define TLSEXT_TYPE_session_ticket
#endif
static char global_err_buf[WOLFSSL_MAX_ERROR_SZ];
#undef ERR_error_string
#define ERR_error_string(e,b) \
        (wolfSSL_ERR_error_string_n((e),global_err_buf,WOLFSSL_MAX_ERROR_SZ), \
         global_err_buf)
#define OPENSSL_NO_POSIX_IO /* WolfSSL does not provide BIO_new_fd(); use alt */
#include "safe_memclear.h"  /* WolfSSL does not provide OPENSSL_cleanse() */
#define OPENSSL_cleanse(x,sz) safe_memclear((x),(sz))
#define SSL_set_read_ahead(x,y) ((void)(y)) /*WolfSSL no SSL_set_read_ahead()*/
#endif

#include "base.h"
#include "fdevent.h"
#include "http_header.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    EVP_PKEY *ssl_pemfile_pkey;
    X509 *ssl_pemfile_x509;
    STACK_OF(X509) *ssl_pemfile_chain;
    buffer *ssl_stapling;
    const buffer *ssl_pemfile;
    const buffer *ssl_privkey;
    const buffer *ssl_stapling_file;
    time_t ssl_stapling_loadts;
    time_t ssl_stapling_nextts;
    char must_staple;
} plugin_cert;

typedef struct {
    SSL_CTX *ssl_ctx;
} plugin_ssl_ctx;

typedef struct {
    STACK_OF(X509_NAME) *names;
    X509_STORE *certs;
} plugin_cacerts;

typedef struct {
    SSL_CTX *ssl_ctx; /* output from network_init_ssl() */

    /*(used only during startup; not patched)*/
    unsigned char ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned char ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    unsigned char ssl_empty_fragments; /* whether to not set SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
    unsigned char ssl_use_sslv2;
    unsigned char ssl_use_sslv3;
    const buffer *ssl_cipher_list;
    const buffer *ssl_dh_file;
    const buffer *ssl_ec_curve;
    array *ssl_conf_cmd;

    /*(copied from plugin_data for socket ssl_ctx config)*/
    const plugin_cert *pc;
    const plugin_cacerts *ssl_ca_file;
    STACK_OF(X509_NAME) *ssl_ca_dn_file;
    const buffer *ssl_ca_crl_file;
    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;
    unsigned char ssl_read_ahead;
    unsigned char ssl_disable_client_renegotiation;
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
    unsigned char ssl_disable_client_renegotiation;
    const buffer *ssl_verifyclient_username;
    const buffer *ssl_acme_tls_1;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_ssl_ctx *ssl_ctxs;
    plugin_config defaults;
    server *srv;
    array *cafiles;
    const char *ssl_stek_file;
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = r->plugin_ctx[plugin_data_singleton->id]; */
static plugin_data *plugin_data_singleton;
#define LOCAL_SEND_BUFSIZE (16 * 1024)
static char *local_send_buffer;

typedef struct {
    SSL *ssl;
    request_st *r;
    connection *con;
    short renegotiations; /* count of SSL_CB_HANDSHAKE_START */
    short close_notify;
    unsigned short request_env_patched;
    unsigned short alpn;
    plugin_config conf;
    buffer *tmp_buf;
} handler_ctx;


static handler_ctx *
handler_ctx_init (void)
{
    handler_ctx *hctx = calloc(1, sizeof(*hctx));
    force_assert(hctx);
    return hctx;
}


static void
handler_ctx_free (handler_ctx *hctx)
{
    if (hctx->ssl) SSL_free(hctx->ssl);
    free(hctx);
}


#ifdef TLSEXT_TYPE_session_ticket
/* ssl/ssl_local.h */
#define TLSEXT_KEYNAME_LENGTH  16
#define TLSEXT_TICK_KEY_LENGTH 32

/* openssl has a huge number of interfaces, but not the most useful;
 * construct our own session ticket encryption key structure */
typedef struct tlsext_ticket_key_st {
    time_t active_ts; /* tickets not issued w/ key until activation timestamp */
    time_t expire_ts; /* key not valid after expiration timestamp */
    unsigned char tick_key_name[TLSEXT_KEYNAME_LENGTH];
    unsigned char tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    unsigned char tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
} tlsext_ticket_key_t;

static tlsext_ticket_key_t session_ticket_keys[4];
static time_t stek_rotate_ts;


static int
mod_openssl_session_ticket_key_generate (time_t active_ts, time_t expire_ts)
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
    const time_t cur_ts = log_epoch_secs;
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
    const time_t cur_ts = log_epoch_secs;
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
tlsext_ticket_wipe_expired (const time_t cur_ts)
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
 * but openssl code uses EVP_aes_256_cbc() instead of EVP_aes_128_cbc()
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
    int fd = fdevent_open_cloexec(fn, 1, O_RDONLY, 0);
    if (fd < 0)
        return 0;

    ssize_t rd = read(fd, buf, sizeof(buf));
    close(fd);

    int rc = 0; /*(will retry on next check interval upon any error)*/
    if (rd == sizeof(buf) && buf[0] == 0) { /*(format version 0)*/
        session_ticket_keys[3].active_ts = buf[1];
        session_ticket_keys[3].expire_ts = buf[2];
        memcpy(&session_ticket_keys[3].tick_key_name, buf+3, 80);
        rc = 1;
    }

    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}


static void
mod_openssl_session_ticket_key_check (const plugin_data *p, const time_t cur_ts)
{
    int rotate = 0;
    if (p->ssl_stek_file) {
        struct stat st;
        if (0 == stat(p->ssl_stek_file, &st) && st.st_mtime > stek_rotate_ts)
            rotate = mod_openssl_session_ticket_key_file(p->ssl_stek_file);
        tlsext_ticket_wipe_expired(cur_ts);
    }
    else if (cur_ts - 28800 >= stek_rotate_ts)     /*(8 hours)*/
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
    buffer *ssl_stapling = hctx->conf.pc->ssl_stapling;
    if (NULL == ssl_stapling) return SSL_TLSEXT_ERR_NOACK;
    UNUSED(arg);

    int len = (int)buffer_string_length(ssl_stapling);

  #ifdef WOLFSSL_VERSION /* WolfSSL does not require copy */
    uint8_t *ocsp_resp = (uint8_t *)ssl_stapling->ptr;
  #else
    /* OpenSSL and LibreSSL require copy (BoringSSL, too, if using compat API)*/
    uint8_t *ocsp_resp = OPENSSL_malloc(len);
    if (NULL == ocsp_resp)
        return SSL_TLSEXT_ERR_NOACK; /* ignore OCSP request if error occurs */
    memcpy(ocsp_resp, ssl_stapling->ptr, len);
  #endif

    if (!SSL_set_tlsext_status_ocsp_resp(ssl, ocsp_resp, len)) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set OCSP response for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
      #ifndef WOLFSSL_VERSION /* WolfSSL does not require copy */
        OPENSSL_free(ocsp_resp);
      #endif
        return SSL_TLSEXT_ERR_NOACK; /* ignore OCSP request if error occurs */
        /*return SSL_TLSEXT_ERR_ALERT_FATAL;*/
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif
#endif


INIT_FUNC(mod_openssl_init)
{
    plugin_data_singleton = (plugin_data *)calloc(1, sizeof(plugin_data));
  #ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
  #endif
    return plugin_data_singleton;
}


static int mod_openssl_init_once_openssl (server *srv)
{
    if (ssl_is_init) return 1;

  #if OPENSSL_VERSION_NUMBER >= 0x10100000L \
   && !defined(LIBRESSL_VERSION_NUMBER) \
   && !defined(WOLFSSL_VERSION)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
                    |OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                       |OPENSSL_INIT_ADD_ALL_DIGESTS
                       |OPENSSL_INIT_LOAD_CONFIG, NULL);
  #elif defined(WOLFSSL_VERSION)
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: wolfSSL_Init() failed");
        return 0;
    }
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

    local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
    force_assert(NULL != local_send_buffer);

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
   && !defined(LIBRESSL_VERSION_NUMBER) \
   && !defined(WOLFSSL_VERSION)
    /*(OpenSSL libraries handle thread init and deinit)
     * https://github.com/openssl/openssl/pull/1048 */
  #elif defined(WOLFSSL_VERSION)
    if (wolfSSL_Cleanup() != WOLFSSL_SUCCESS) {
        log_error(plugin_data_singleton->srv->errh, __FILE__, __LINE__,
          "SSL: wolfSSL_Cleanup() failed");
    }
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
mod_openssl_free_config (server *srv, plugin_data * const p)
{
    array_free(p->cafiles);

    if (NULL != p->ssl_ctxs) {
        SSL_CTX * const ssl_ctx_global_scope = p->ssl_ctxs->ssl_ctx;
        /* free ssl_ctx from $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs + i;
            if (s->ssl_ctx && s->ssl_ctx != ssl_ctx_global_scope)
                SSL_CTX_free(s->ssl_ctx);
        }
        /* free ssl_ctx from global scope */
        if (ssl_ctx_global_scope)
            SSL_CTX_free(ssl_ctx_global_scope);
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
                    EVP_PKEY_free(pc->ssl_pemfile_pkey);
                    X509_free(pc->ssl_pemfile_x509);
                    sk_X509_pop_free(pc->ssl_pemfile_chain, X509_free);
                    buffer_free(pc->ssl_stapling);
                }
                break;
              case 2: /* ssl.ca-file */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_cacerts *cacerts = cpv->v.v;
                    sk_X509_NAME_pop_free(cacerts->names, X509_NAME_free);
                    X509_STORE_free(cacerts->certs);
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


/* openssl BIO_s_file() employs system stdio
 * system stdio buffers reads and does not guarantee to clear buffer memory
 * 'man PEM_bytes_read_bio_secmem()' and see NOTES section for more info
 */

#ifdef OPENSSL_NO_POSIX_IO

#include <stdio.h>
static BIO *
BIO_new_rdonly_file (const char *file)
{

    BIO *in = BIO_new(BIO_s_file());
    if (NULL == in)
        return NULL;

    if (BIO_read_filename(in, file) <= 0) {
        BIO_free(in);
        return NULL;
    }

    /* set I/O stream unbuffered (best-effort; not fatal)
     * system stdio buffers reads and does not guarantee to clear buffer memory.
     * Alternative: provide buffer (e.g. 8k) and clear after use (in caller) */
    FILE *fp = NULL;
    if (BIO_get_fp(in, &fp))
        setvbuf(fp, NULL, _IONBF, 0);

    return in;
}

#else  /* !OPENSSL_NO_POSIX_IO */

#include <fcntl.h>
static BIO *
BIO_new_rdonly_file (const char *file)
{
    /* unbuffered fd; not using system stdio */
    int fd = fdevent_open_cloexec(file, 1, O_RDONLY, 0);
    if (fd < 0)
        return NULL;

    BIO *in = BIO_new_fd(fd, BIO_CLOSE);
    if (NULL == in) {
        close(fd);
        return NULL;
    }

    return in;
}

#endif /* !OPENSSL_NO_POSIX_IO */


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
 * PEM_bytes_read_bio_secmem() openssl 1.1.1 or later
 * OPENSSL_secure_clear_free() openssl 1.1.0g or later
 * As this comment is being written, only openssl 1.1.1 is actively maintained.
 * Earlier vers of openssl no longer receive security patches from openssl.org.
 */
#ifndef WOLFSSL_VERSION /* WolfSSL limitation; does not wipe temp mem used */
static void *
PEM_ASN1_read_bio_secmem(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                         pem_password_cb *cb, void *u)
{
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len = 0;
    char *ret = NULL;

  #if OPENSSL_VERSION_NUMBER >= 0x10101000L \
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
        PEMerr(PEM_F_PEM_ASN1_READ_BIO, ERR_R_ASN1_LIB);
  #endif
  #if OPENSSL_VERSION_NUMBER >= 0x10101000L \
   && !defined(LIBRESSL_VERSION_NUMBER)
    OPENSSL_secure_clear_free(data, len);
  #else
    OPENSSL_cleanse(data, len);
    OPENSSL_free(data);
  #endif
    return ret;
}
#endif


static X509 *
PEM_read_bio_X509_secmem(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
  #ifdef WOLFSSL_VERSION /* WolfSSL limitation; does not wipe temp mem used */
    return wolfSSL_PEM_read_bio_X509(bp, x, cb, u);
  #else
    return PEM_ASN1_read_bio_secmem((d2i_of_void *)d2i_X509,
                                    PEM_STRING_X509,
                                    bp, (void **)x, cb, u);
  #endif
}


static X509 *
PEM_read_bio_X509_AUX_secmem(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
  #ifdef WOLFSSL_VERSION /* WolfSSL limitation; does not wipe temp mem used */
    return wolfSSL_PEM_read_bio_X509_AUX(bp, x, cb, u);
  #else
    return PEM_ASN1_read_bio_secmem((d2i_of_void *)d2i_X509_AUX,
                                    PEM_STRING_X509_TRUSTED,
                                    bp, (void **)x, cb, u);
  #endif
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
          "SSL: ssl.ca-file is empty %s", file);
        return NULL;
    }

    plugin_cacerts *cacerts = malloc(sizeof(plugin_cacerts));
    force_assert(cacerts);

    /* (would be more efficient to walk the X509_STORE and build the list,
     *  but this works for now and matches how ssl.ca-dn-file is handled) */
    cacerts->names = SSL_load_client_CA_file(file);
    if (NULL == cacerts->names) {
        X509_STORE_free(chain_store);
        free(cacerts);
        return NULL;
    }

    cacerts->certs = chain_store;
    return cacerts;
}


static int
mod_openssl_load_cacrls (X509_STORE *store, const buffer *ssl_ca_crl_file, server *srv)
{
    if (1 != X509_STORE_load_locations(store, ssl_ca_crl_file->ptr, NULL)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: %s %s", ERR_error_string(ERR_get_error(), NULL),
          ssl_ca_crl_file->ptr);
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

    log_error(srv->errh, __FILE__, __LINE__,
      "SSL: %s %s", ERR_error_string(ERR_get_error(), NULL), fn);
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
        pconf->ssl_disable_client_renegotiation = (0 != cpv->v.u);
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
    plugin_data * const p = plugin_data_singleton;
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
        int len = X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE);
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
      #ifdef WOLFSSL_VERSION
        SSL *ssl_nonconst;
        *(const SSL **)&ssl_nonconst = ssl;
        if (wolfSSL_GetVersion(ssl_nonconst) >= WOLFSSL_TLSV1_3)
      #else
        if (SSL_version(ssl) >= TLS1_3_VERSION)
      #endif
        {
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
      "SSL: verify error:num=%d:%s:depth=%d:subject=%s",
      err, X509_verify_cert_error_string(err), depth, buf);

    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                          err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        safer_X509_NAME_oneline(X509_get_issuer_name(err_cert),buf,sizeof(buf));
        log_error(errh, __FILE__, __LINE__, "SSL: issuer=%s", buf);
    }

    return !hctx->conf.ssl_verifyclient_enforce;
}

static int
mod_openssl_cert_cb (SSL *ssl, void *arg)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    plugin_cert *pc = hctx->conf.pc;
    UNUSED(arg);

    if (NULL == pc->ssl_pemfile_x509 || NULL == pc->ssl_pemfile_pkey) {
        /* x509/pkey available <=> pemfile was set <=> pemfile got patched:
         * so this should never happen, unless you nest $SERVER["socket"] */
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: no certificate/private key for TLS server name %s",
          hctx->r->uri.authority.ptr);
        return 0;
    }

    /* first set certificate!
     * setting private key checks whether certificate matches it */
    if (1 != SSL_use_certificate(ssl, pc->ssl_pemfile_x509)) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set certificate for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

  #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
   && !defined(LIBRESSL_VERSION_NUMBER)
    if (pc->ssl_pemfile_chain)
        SSL_set1_chain(ssl, pc->ssl_pemfile_chain);
   #ifndef BORINGSSL_API_VERSION /* BoringSSL limitation */
    else if (hctx->conf.ssl_ca_file) {
        /* preserve legacy behavior whereby openssl will reuse CAs trusted for
         * certificate verification (set by SSL_CTX_load_verify_locations() in
         * SSL_CTX) in order to build certificate chain for server certificate
         * sent to client */
        SSL_set1_chain_cert_store(ssl, hctx->conf.ssl_ca_file->certs);

        if (1 != SSL_build_cert_chain(ssl,
                                        SSL_BUILD_CHAIN_FLAG_NO_ROOT
                                      | SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR
                                      | SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR)) {
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
              "SSL: building cert chain for TLS server name %s: %s",
              hctx->r->uri.authority.ptr,
              ERR_error_string(ERR_get_error(), NULL));
            return 0;
        }
        else { /* copy chain for future reuse */
            STACK_OF(X509) *chain = NULL;
            SSL_get0_chain_certs(ssl, &chain);
            pc->ssl_pemfile_chain = X509_chain_up_ref(chain);
            SSL_set1_chain_cert_store(ssl, NULL);
        }
    }
   #endif
  #endif

    if (1 != SSL_use_PrivateKey(ssl, pc->ssl_pemfile_pkey)) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set private key for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

  #ifndef OPENSSL_NO_OCSP
  #ifdef BORINGSSL_API_VERSION
    /* BoringSSL suggests API different than SSL_CTX_set_tlsext_status_cb() */
    buffer *ocsp_resp = pc->ssl_stapling;
    if (NULL != ocsp_resp
        && !SSL_set_ocsp_response(ssl, (uint8_t *)CONST_BUF_LEN(ocsp_resp))) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set OCSP response for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }
  #endif
  #endif

    if (hctx->conf.ssl_verifyclient) {
        if (NULL == hctx->conf.ssl_ca_file) {
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
              "SSL: can't verify client without ssl.ca-file "
              "for TLS server name %s", hctx->r->uri.authority.ptr);
            return 0;
        }
      #if OPENSSL_VERSION_NUMBER >= 0x10002000 \
       && !defined(LIBRESSL_VERSION_NUMBER)
        SSL_set1_verify_cert_store(ssl, hctx->conf.ssl_ca_file->certs);
      #endif
        /* WTH openssl?  SSL_set_client_CA_list() calls set0_CA_list(),
         * but there is no set1_CA_list() to simply up the reference count
         * (without needing to duplicate the list) */
      #ifndef WOLFSSL_VERSION /* WolfSSL limitation */
        /* WolfSSL does not support setting per-session CA list;
         * limitation is to per-CTX CA list, and is not changed after SNI */
        STACK_OF(X509_NAME) * const cert_names = hctx->conf.ssl_ca_dn_file
          ? hctx->conf.ssl_ca_dn_file
          : hctx->conf.ssl_ca_file->names;
        SSL_set_client_CA_list(ssl, SSL_dup_CA_list(cert_names));
      #endif
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
                  "SSL: SNI name too long %.*s", (int)len, servername);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* use SNI to patch mod_openssl config and then reset COMP_HTTP_HOST */
    buffer_copy_string_len(&r->uri.authority, servername, len);
    buffer_to_lower(&r->uri.authority);
  #if 0
    /*(r->uri.authority used below for configuration before request read;
     * revisit for h2)*/
    if (0 != http_request_host_policy(&r->uri.authority,
                                      r->conf.http_parseopts, 443))
        return SSL_TLSEXT_ERR_ALERT_FATAL;
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
    buffer_copy_string(&hctx->r->uri.scheme, "https");
    UNUSED(srv);

    const unsigned char *name;
    size_t len, slen;
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
    buffer_copy_string(&hctx->r->uri.scheme, "https");
    UNUSED(al);
    UNUSED(srv);

  #ifdef WOLFSSL_VERSION
    const char *servername;
    size_t len = (size_t)
      wolfSSL_SNI_GetRequest(ssl, WOLFSSL_SNI_HOST_NAME, (void **)&servername);
    if (0 == len)
        return SSL_TLSEXT_ERR_NOACK; /* client did not provide SNI */
  #else
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (NULL == servername)
        return SSL_TLSEXT_ERR_NOACK; /* client did not provide SNI */
    size_t len = strlen(servername);
  #endif
    int read_ahead = hctx->conf.ssl_read_ahead;
    int rc = mod_openssl_SNI(hctx, servername, len);
    if (!read_ahead && hctx->conf.ssl_read_ahead)
        SSL_set_read_ahead(ssl, hctx->conf.ssl_read_ahead);
    return rc;
}
#endif
#endif


static X509 *
mod_openssl_load_pem_file (const char *file, log_error_st *errh, STACK_OF(X509) **chain)
{
    *chain = NULL;

    BIO *in = BIO_new_rdonly_file(file);
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new/BIO_read_filename('%s') failed", file);
        return NULL;
    }

    X509 *x = PEM_read_bio_X509_AUX_secmem(in, NULL, NULL, NULL);
    if (NULL == x) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: couldn't read X509 certificate from '%s'", file);
    }
    else if (!mod_openssl_load_X509_sk(file, errh, chain, in)) {
        X509_free(x);
        x = NULL;
    }

    BIO_free(in);
    return x;
}


static EVP_PKEY *
mod_openssl_evp_pkey_load_pem_file (const char *file, log_error_st *errh)
{
    BIO *in = BIO_new_rdonly_file(file);
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new/BIO_read_filename('%s') failed", file);
        return NULL;
    }

    EVP_PKEY *x = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    if (NULL == x)
        log_error(errh, __FILE__, __LINE__,
          "SSL: couldn't read private key from '%s'", file);

    return x;
}


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

  #ifdef BORINGSSL_API_VERSION

    /* load raw .der file */
    /* (similar to mod_gnutls.c:mod_gnutls_load_file(), but some differences) */
    int fd = -1;
    uint32_t sz = 0;
    char *buf = NULL;
    do {
        fd = fdevent_open_cloexec(file,1,O_RDONLY,0); /*(1: follows symlinks)*/
        if (fd < 0) break;

        struct stat st;
        if (0 != fstat(fd, &st)) break;
        if (st.st_size == 0) break;
        if (st.st_size >= UINT32_MAX) { /*(file too large for buffer uint32_t)*/
            errno = EOVERFLOW;
            break;
        }

        sz = (uint32_t)st.st_size;
        buf = malloc(sz+1); /*(+1 trailing '\0')*/
        if (NULL == buf) break;

        ssize_t rd = 0;
        unsigned int off = 0;
        do {
            rd = read(fd, buf+off, sz-off);
        } while (rd > 0 ? (off += (unsigned int)rd) != sz : errno == EINTR);
        if (off != sz) { /*(file truncated?)*/
            if (rd >= 0) errno = EIO;
            break;
        }

        if (NULL == b) b = buffer_init();
        buffer_copy_string_len(b, buf, sz);
        memset(buf, 0, sz);
        free(buf);
        close(fd);
        return b;
    } while (0);
    int errnum = errno;
    log_perror(errh, __FILE__, __LINE__, "%s() %s", __func__, file);
    if (fd >= 0) close(fd);
    if (buf) {
        memset(buf, 0, sz);
        free(buf);
    }
    errno = errnum;
    return NULL;;

  #else

    BIO *in = BIO_new_rdonly_file(file);
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new/BIO_read_filename('%s') failed", file);
        return NULL;
    }

    OCSP_RESPONSE *x = d2i_OCSP_RESPONSE_bio(in, NULL);
    BIO_free(in);
    if (NULL == x) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: OCSP stapling file read error: %s %s",
          ERR_error_string(ERR_get_error(), NULL), file);
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


#ifndef BORINGSSL_API_VERSION
static time_t
mod_openssl_asn1_time_to_posix (ASN1_TIME *asn1time)
{
  #ifdef LIBRESSL_VERSION_NUMBER
    /* LibreSSL was forked from OpenSSL 1.0.1; does not have ASN1_TIME_diff */

    /*(Note: all certificate times are expected to use UTC)*/
    /*(Note: does not strictly validate string contains appropriate digits)*/
    /*(Note: incorrectly assumes GMT if 'Z' or offset not provided)*/
    /*(Note: incorrectly ignores if local timezone might be in DST)*/

    if (NULL == asn1time || NULL == asn1time->data) return (time_t)-1;
    const char *s = (const char *)asn1time->data;
    size_t len = strlen(s);
    struct tm x;
    x.tm_isdst = 0;
    x.tm_yday = 0;
    x.tm_wday = 0;
    switch (asn1time->type) {
      case V_ASN1_UTCTIME:         /* 2-digit year */
        if (len < 8) return (time_t)-1;
        len -= 8;
        x.tm_year = (s[0]-'0')*10 + (s[1]-'0');
        x.tm_year += (x.tm_year < 50 ? 2000 : 1900);
        s += 2;
        break;
      case V_ASN1_GENERALIZEDTIME: /* 4-digit year */
        if (len < 10) return (time_t)-1;
        len -= 10;
        x.tm_year = (s[0]-'0')*1000+(s[1]-'0')*100+(s[2]-'0')*10+(s[3]-'0');
        s += 4;
        break;
      default:
        return (time_t)-1;
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
        return (time_t)-1;

    if (x.tm_year == 9999 && x.tm_mon == 12 && x.tm_mday == 31
        && x.tm_hour == 23 && x.tm_min == 59 && x.tm_sec == 59 && s[0] == 'Z')
        return (time_t)-1; // 99991231235959Z RFC 5280

   #if 0
    #if defined(_WIN32) && !defined(__CYGWIN__)
    #define timegm(x) _mkgmtime(x)
    #endif
    /* timegm() might not be available, and mktime() is sensitive to TZ */
    x.tm_year-= 1900;
    x.tm_mon -= 1;
    time_t t = timegm(&d);
    return (t != (time_t)-1) ? t + offset : t;
   #else
    int y = x.tm_year;
    int m = x.tm_mon;
    int d = x.tm_mday;
    /* days_from_civil() http://howardhinnant.github.io/date_algorithms.html */
    y -= m <= 2;
    int era = y / 400;
    int yoe = y - era * 400;                                   // [0, 399]
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;  // [0, 365]
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           // [0, 146096]
    int days_since_1970 = era * 146097 + doe - 719468;
    return 60*(60*(24L*days_since_1970+x.tm_hour)+x.tm_min)+x.tm_sec+offset;
   #endif

  #else

    /* Note: this does not check for integer overflow of time_t! */
    int day, sec;
    return ASN1_TIME_diff(&day, &sec, NULL, asn1time)
      ? log_epoch_secs + day*86400 + sec
      : (time_t)-1;

  #endif
}
#endif


static time_t
mod_openssl_ocsp_next_update (plugin_cert *pc)
{
  #ifdef BORINGSSL_API_VERSION
    UNUSED(pc);
    return (time_t)-1; /*(not implemented)*/
  #else
    buffer *der = pc->ssl_stapling;
    const unsigned char *p = (unsigned char *)der->ptr; /*(p gets modified)*/
    OCSP_RESPONSE *ocsp = d2i_OCSP_RESPONSE(NULL,&p,buffer_string_length(der));
    if (NULL == ocsp) return (time_t)-1;
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(ocsp);
    if (NULL == bs) {
        OCSP_RESPONSE_free(ocsp);
        return (time_t)-1;
    }

    /* XXX: should save and evaluate cert status returned by these calls */
    ASN1_TIME *nextupd = NULL;
   #ifdef WOLFSSL_VERSION /* WolfSSL limitation */
    /* WolfSSL does not provide OCSP_resp_get0() OCSP_single_get0_status() */
    OCSP_CERTID *id = (NULL != pc->ssl_pemfile_chain)
      ? OCSP_cert_to_id(NULL, pc->ssl_pemfile_x509,
                        sk_X509_value(pc->ssl_pemfile_chain, 0))
      : NULL;
    if (id == NULL) {
        OCSP_BASICRESP_free(bs);
        OCSP_RESPONSE_free(ocsp);
        return (time_t)-1;
    }
    OCSP_resp_find_status(bs, id, NULL, NULL, NULL, NULL, &nextupd);
    OCSP_CERTID_free(id);
   #else
    OCSP_single_get0_status(OCSP_resp_get0(bs, 0), NULL, NULL, NULL, &nextupd);
   #endif
    time_t t = nextupd ? mod_openssl_asn1_time_to_posix(nextupd) : (time_t)-1;

    /* Note: trust external process which creates ssl.stapling-file to verify
     *       (as well as to validate certificate status)
     * future: verify OCSP response here to double-check */

    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(ocsp);

    return t;
  #endif
}


static int
mod_openssl_reload_stapling_file (server *srv, plugin_cert *pc, const time_t cur_ts)
{
    buffer *b = mod_openssl_load_stapling_file(pc->ssl_stapling_file->ptr,
                                               srv->errh, pc->ssl_stapling);
    if (!b) return 0;

    pc->ssl_stapling = b; /*(unchanged unless orig was NULL)*/
    pc->ssl_stapling_loadts = cur_ts;
    pc->ssl_stapling_nextts = mod_openssl_ocsp_next_update(pc);
    if (pc->ssl_stapling_nextts == (time_t)-1) {
        /* "Next Update" might not be provided by OCSP responder
         * Use 3600 sec (1 hour) in that case. */
        /* retry in 1 hour if unable to determine Next Update */
        pc->ssl_stapling_nextts = cur_ts + 3600;
        pc->ssl_stapling_loadts = 0;
    }

    return 1;
}


static int
mod_openssl_refresh_stapling_file (server *srv, plugin_cert *pc, const time_t cur_ts)
{
    if (pc->ssl_stapling && pc->ssl_stapling_nextts - 256 > cur_ts)
        return 1; /* skip check for refresh unless close to expire */
    struct stat st;
    if (0 != stat(pc->ssl_stapling_file->ptr, &st)
        || st.st_mtime <= pc->ssl_stapling_loadts) {
        if (pc->ssl_stapling_nextts < cur_ts) {
            /* discard expired OCSP stapling response */
            buffer_free(pc->ssl_stapling);
            pc->ssl_stapling = NULL;
            if (pc->must_staple) {
                log_error(srv->errh, __FILE__, __LINE__,
                          "certificate marked OCSP Must-Staple, "
                          "but OCSP response expired from ssl.stapling-file %s",
                          pc->ssl_stapling_file->ptr);
            }
        }
        return 1;
    }
    return mod_openssl_reload_stapling_file(srv, pc, cur_ts);
}


static void
mod_openssl_refresh_stapling_files (server *srv, const plugin_data *p, const time_t cur_ts)
{
    /* future: might construct array of (plugin_cert *) at startup
     *         to avoid the need to search for them here */
    for (int i = 0, used = p->nconfig; i < used; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; cpv->k_id != -1; ++cpv) {
            if (cpv->k_id != 0) continue; /* k_id == 0 for ssl.pemfile */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            plugin_cert *pc = cpv->v.v;
            if (!buffer_string_is_empty(pc->ssl_stapling_file))
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
        log_error(srv->errh, __FILE__, __LINE__, "SSL:"
          "Private key does not match the certificate public key, "
          "reason: %s %s %s", ERR_error_string(ERR_get_error(), NULL),
          pemfile->ptr, privkey->ptr);
        EVP_PKEY_free(ssl_pemfile_pkey);
        X509_free(ssl_pemfile_x509);
        sk_X509_pop_free(ssl_pemfile_chain, X509_free);
        return NULL;
    }

    plugin_cert *pc = malloc(sizeof(plugin_cert));
    force_assert(pc);
    pc->ssl_pemfile_pkey = ssl_pemfile_pkey;
    pc->ssl_pemfile_x509 = ssl_pemfile_x509;
    pc->ssl_pemfile_chain= ssl_pemfile_chain;
    pc->ssl_pemfile = pemfile;
    pc->ssl_privkey = privkey;
    pc->ssl_stapling     = NULL;
    pc->ssl_stapling_file= ssl_stapling_file;
    pc->ssl_stapling_loadts = 0;
    pc->ssl_stapling_nextts = 0;
  #ifndef OPENSSL_NO_OCSP
    pc->must_staple = mod_openssl_crt_must_staple(ssl_pemfile_x509);
  #else
    pc->must_staple = 0;
  #endif

    if (!buffer_string_is_empty(pc->ssl_stapling_file)) {
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
    else if (pc->must_staple) {
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate %s marked OCSP Must-Staple, "
                  "but ssl.stapling-file not provided", pemfile->ptr);
    }

    return pc;
}


#ifndef OPENSSL_NO_TLSEXT

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
mod_openssl_acme_tls_1 (SSL *ssl, handler_ctx *hctx)
{
    buffer * const b = hctx->tmp_buf;
    const buffer * const name = &hctx->r->uri.authority;
    log_error_st * const errh = hctx->r->conf.errh;
    X509 *ssl_pemfile_x509 = NULL;
    STACK_OF(X509) *ssl_pemfile_chain = NULL;
    EVP_PKEY *ssl_pemfile_pkey = NULL;
    size_t len;
    int rc = SSL_TLSEXT_ERR_ALERT_FATAL;

    /* check if acme-tls/1 protocol is enabled (path to dir of cert(s) is set)*/
    if (buffer_string_is_empty(hctx->conf.ssl_acme_tls_1))
        return SSL_TLSEXT_ERR_NOACK; /*(reuse value here for not-configured)*/
    buffer_copy_buffer(b, hctx->conf.ssl_acme_tls_1);
    buffer_append_slash(b);

    /* check if SNI set server name (required for acme-tls/1 protocol)
     * and perform simple path checks for no '/'
     * and no leading '.' (e.g. ignore "." or ".." or anything beginning '.') */
    if (buffer_string_is_empty(name))   return rc;
    if (NULL != strchr(name->ptr, '/')) return rc;
    if (name->ptr[0] == '.')            return rc;
  #if 0
    if (0 != http_request_host_policy(name,hctx->r->conf.http_parseopts,443))
        return rc;
  #endif
    buffer_append_string_buffer(b, name);
    len = buffer_string_length(b);

    do {
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
        ssl_pemfile_x509 =
          mod_openssl_load_pem_file(b->ptr, errh, &ssl_pemfile_chain);
        if (NULL == ssl_pemfile_x509) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        buffer_string_set_length(b, len); /*(remove ".crt.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        ssl_pemfile_pkey = mod_openssl_evp_pkey_load_pem_file(b->ptr, errh);
        if (NULL == ssl_pemfile_pkey) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

      #if 0 /* redundant with below? */
        if (!X509_check_private_key(ssl_pemfile_x509, ssl_pemfile_pkey)) {
            log_error(errh, __FILE__, __LINE__,
               "SSL: Private key does not match acme-tls/1 "
               "certificate public key, reason: %s %s"
               ERR_error_string(ERR_get_error(), NULL), b->ptr);
            break;
        }
      #endif

        /* first set certificate!
         * setting private key checks whether certificate matches it */
        if (1 != SSL_use_certificate(ssl, ssl_pemfile_x509)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: failed to set acme-tls/1 certificate for TLS server "
              "name %s: %s", name->ptr, ERR_error_string(ERR_get_error(),NULL));
            break;
        }

        if (ssl_pemfile_chain) {
          #ifndef WOLFSSL_VERSION /* WolfSSL limitation */
            /* WolfSSL does not support setting per-session chain;
             * limitation is to per-CTX chain, and so chain is not provided for
             * "acme-tls/1" (might be non-issue; chain might not be present) */
            SSL_set0_chain(ssl, ssl_pemfile_chain);
            ssl_pemfile_chain = NULL;
          #endif
        }

        if (1 != SSL_use_PrivateKey(ssl, ssl_pemfile_pkey)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: failed to set acme-tls/1 private key for TLS server "
              "name %s: %s", name->ptr, ERR_error_string(ERR_get_error(),NULL));
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

    return rc;
}

enum {
  MOD_OPENSSL_ALPN_HTTP11      = 1
 ,MOD_OPENSSL_ALPN_HTTP10      = 2
 ,MOD_OPENSSL_ALPN_H2          = 3
 ,MOD_OPENSSL_ALPN_ACME_TLS_1  = 4
};

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
         #if 0
          case 2:  /* "h2" */
            if (in[i] == 'h' && in[i+1] == '2') {
                proto = MOD_OPENSSL_ALPN_H2;
                break;
            }
            continue;
         #endif
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
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  #endif
}

#endif /* TLSEXT_TYPE_application_layer_protocol_negotiation */

#endif /* OPENSSL_NO_TLSEXT */


#if defined(BORINGSSL_API_VERSION) \
 || defined(LIBRESSL_VERSION_NUMBER) \
 || defined(WOLFSSL_VERSION)
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
        buffer_append_string_len(cipher_string,
                                 CONST_STR_LEN(":!aNULL:!eNULL:!EXP"));
    }

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        ds = (data_string *)s->ssl_conf_cmd->data[i];
        ERR_clear_error();
        if (SSL_CONF_cmd(cctx, ds->key.ptr, ds->value.ptr) <= 0) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: SSL_CONF_cmd %s %s: %s", ds->key.ptr, ds->value.ptr,
              ERR_error_string(ERR_get_error(), NULL));
            rc = -1;
            break;
        }
    }

    if (0 == rc && 1 != SSL_CONF_CTX_finish(cctx)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: SSL_CONF_CTX_finish(): %s",
          ERR_error_string(ERR_get_error(), NULL));
        rc = -1;
    }

    SSL_CONF_CTX_free(cctx);
    return rc;

  #elif defined(BORINGSSL_API_VERSION) \
     || defined(LIBRESSL_VERSION_NUMBER) \
     || defined(WOLFSSL_VERSION)

    return mod_openssl_ssl_conf_cmd(srv, s);

  #else

    UNUSED(s);
    log_error(srv->errh, __FILE__, __LINE__,
      "SSL: ssl.openssl.ssl-conf-cmd not available; ignored");
    return 0;

  #endif
}


#ifndef OPENSSL_NO_DH
#if OPENSSL_VERSION_NUMBER < 0x10100000L \
 || defined(LIBRESSL_VERSION_NUMBER)
#define DH_set0_pqg(dh, dh_p, NULL, dh_g) \
        ((dh)->p = (dh_p), (dh)->g = (dh_g), (dh_p) != NULL && (dh_g != NULL))
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
#endif


static int
mod_openssl_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *ssl_ec_curve)
{
  #if OPENSSL_VERSION_NUMBER >= 0x0090800fL
  #ifndef OPENSSL_NO_ECDH
    int nid = 0;
    /* Support for Elliptic-Curve Diffie-Hellman key exchange */
    if (!buffer_string_is_empty(ssl_ec_curve)) {
        /* OpenSSL only supports the "named curves"
         * from RFC 4492, section 5.1.1. */
        nid = OBJ_sn2nid((char *) ssl_ec_curve->ptr);
        if (nid == 0) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unknown curve name %s", ssl_ec_curve->ptr);
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
        EC_KEY *ecdh;
        ecdh = EC_KEY_new_by_curve_name(nid);
        if (ecdh == NULL) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unable to create curve %s", ssl_ec_curve->ptr);
            return 0;
        }
        SSL_CTX_set_tmp_ecdh(s->ssl_ctx, ecdh);
        SSL_CTX_set_options(s->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
        EC_KEY_free(ecdh);
    }
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
        long ssloptions = SSL_OP_ALL
                        | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                        | SSL_OP_NO_COMPRESSION;

      #if OPENSSL_VERSION_NUMBER >= 0x10100000L \
       || defined(WOLFSSL_VERSION)
        s->ssl_ctx = (!s->ssl_use_sslv2 && !s->ssl_use_sslv3)
          ? SSL_CTX_new(TLS_server_method())
          : SSL_CTX_new(SSLv23_server_method());
      #else
        s->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
      #endif
        if (NULL == s->ssl_ctx) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

      #ifdef SSL_OP_NO_RENEGOTIATION /* openssl 1.1.0 */
        if (s->ssl_disable_client_renegotiation)
            ssloptions |= SSL_OP_NO_RENEGOTIATION;
      #endif

        /* completely useless identifier;
         * required for client cert verification to work with sessions */
        if (0 == SSL_CTX_set_session_id_context(
                   s->ssl_ctx,(const unsigned char*)CONST_STR_LEN("lighttpd"))){
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: failed to set session context: %s",
              ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

        /* disable session cache; session tickets are preferred */
        SSL_CTX_set_session_cache_mode(s->ssl_ctx, SSL_SESS_CACHE_OFF
                                                 | SSL_SESS_CACHE_NO_AUTO_CLEAR
                                                 | SSL_SESS_CACHE_NO_INTERNAL);

        if (s->ssl_empty_fragments) {
          #ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
            ssloptions &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
          #else
            ssloptions &= ~0x00000800L; /* hardcode constant */
            log_error(srv->errh, __FILE__, __LINE__,
              "WARNING: SSL: 'insert empty fragments' not supported by the "
              "openssl version used to compile lighttpd with");
          #endif
        }

        SSL_CTX_set_options(s->ssl_ctx, ssloptions);
        SSL_CTX_set_info_callback(s->ssl_ctx, ssl_info_callback);

      #ifndef HAVE_WOLFSSL_SSL_H /*(wolfSSL does not support SSLv2)*/
        if (!s->ssl_use_sslv2 && 0 != SSL_OP_NO_SSLv2) {
            /* disable SSLv2 */
            if ((SSL_OP_NO_SSLv2
                 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv2))
                != SSL_OP_NO_SSLv2) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }
      #endif

        if (!s->ssl_use_sslv3 && 0 != SSL_OP_NO_SSLv3) {
            /* disable SSLv3 */
            if ((SSL_OP_NO_SSLv3
                 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv3))
                != SSL_OP_NO_SSLv3) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }

        if (!buffer_string_is_empty(s->ssl_cipher_list)) {
            /* Disable support for low encryption ciphers */
            if (SSL_CTX_set_cipher_list(s->ssl_ctx,s->ssl_cipher_list->ptr)!=1){
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
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

      #ifndef OPENSSL_NO_DH
      {
        DH *dh;
        /* Support for Diffie-Hellman key exchange */
        if (!buffer_string_is_empty(s->ssl_dh_file)) {
            /* DH parameters from file */
            BIO *bio;
            bio = BIO_new_file((char *) s->ssl_dh_file->ptr, "r");
            if (bio == NULL) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: Unable to open file %s", s->ssl_dh_file->ptr);
                return -1;
            }
            dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
            BIO_free(bio);
            if (dh == NULL) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: PEM_read_bio_DHparams failed %s", s->ssl_dh_file->ptr);
                return -1;
            }
        } else {
            dh = get_dh2048();
            if (dh == NULL) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: get_dh2048() failed");
                return -1;
            }
        }
        SSL_CTX_set_tmp_dh(s->ssl_ctx,dh);
        SSL_CTX_set_options(s->ssl_ctx,SSL_OP_SINGLE_DH_USE);
        DH_free(dh);
      }
      #else
        if (!buffer_string_is_empty(s->ssl_dh_file)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: openssl compiled without DH support, "
              "can't load parameters from %s", s->ssl_dh_file->ptr);
        }
      #endif

        if (!mod_openssl_ssl_conf_curves(srv, s, s->ssl_ec_curve))
            return -1;

      #ifdef TLSEXT_TYPE_session_ticket
        SSL_CTX_set_tlsext_ticket_key_cb(s->ssl_ctx, ssl_tlsext_ticket_key_cb);
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
        if (s->ssl_ca_file && s->ssl_ca_file->certs) {
            if (!X509_STORE_up_ref(s->ssl_ca_file->certs))
                return -1;
            SSL_CTX_set_cert_store(s->ssl_ctx, s->ssl_ca_file->certs);
        }
       #endif

      #else /* OPENSSL_VERSION_NUMBER < 0x10002000 */

        /* load all ssl.ca-files specified in the config into each SSL_CTX
         * XXX: This might be a bit excessive, but are all trusted CAs
         *      TODO: prefer to load on-demand in mod_openssl_cert_cb()
         *            for openssl >= 1.0.2 */
        if (!mod_openssl_load_ca_files(s->ssl_ctx, p, srv))
            return -1;

        if (s->ssl_verifyclient) {
            if (NULL == s->ssl_ca_file) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: You specified ssl.verifyclient.activate "
                  "but no ssl.ca-file");
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
            if (!buffer_string_is_empty(s->ssl_ca_crl_file)) {
                X509_STORE *store = SSL_CTX_get_cert_store(s->ssl_ctx);
                if (!mod_openssl_load_cacrls(store, s->ssl_ca_crl_file, srv))
                    return -1;
            }
        }

        if (1 != SSL_CTX_use_certificate_chain_file(s->ssl_ctx,
                                                    s->pc->ssl_pemfile->ptr)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s %s", ERR_error_string(ERR_get_error(), NULL),
              s->pc->ssl_pemfile->ptr);
            return -1;
        }

        if (1 != SSL_CTX_use_PrivateKey(s->ssl_ctx, s->pc->ssl_pemfile_pkey)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s %s %s", ERR_error_string(ERR_get_error(), NULL),
              s->pc->ssl_pemfile->ptr, s->pc->ssl_privkey->ptr);
            return -1;
        }

        if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Private key does not match the certificate public key, "
              "reason: %s %s %s", ERR_error_string(ERR_get_error(), NULL),
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
       || defined(LIBRESSL_VERSION_NUMBER) \
       || defined(WOLFSSL_VERSION)
        if (!s->ssl_use_sslv3 && !s->ssl_use_sslv2
            && !SSL_CTX_set_min_proto_version(s->ssl_ctx, TLS1_2_VERSION))
            return -1;
      #endif

        if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
            if (0 != network_openssl_ssl_conf_cmd(srv, s)) return -1;
        }

        return 0;
}


static int
mod_openssl_set_defaults_sockets(server *srv, plugin_data *p)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.engine"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.cipher-list"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.honor-cipher-order"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.dh-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ec-curve"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.openssl.ssl-conf-cmd"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.pemfile"), /* included to process global scope */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.empty-fragments"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.use-sslv2"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.use-sslv3"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.stek-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };
  #ifdef WOLFSSL_VERSION /* WolfSSL does not have mapping for "HIGH" */
    /* cipher list is (current) output of "openssl ciphers HIGH" */
    static const buffer default_ssl_cipher_list = { CONST_STR_LEN("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:ECDHE-ECDSA-ARIA256-GCM-SHA384:ECDHE-ARIA256-GCM-SHA384:DHE-DSS-ARIA256-GCM-SHA384:DHE-RSA-ARIA256-GCM-SHA384:ADH-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:ECDHE-ECDSA-ARIA128-GCM-SHA256:ECDHE-ARIA128-GCM-SHA256:DHE-DSS-ARIA128-GCM-SHA256:DHE-RSA-ARIA128-GCM-SHA256:ADH-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:DHE-RSA-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA256:ADH-AES256-SHA256:ADH-CAMELLIA256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA256:ADH-AES128-SHA256:ADH-CAMELLIA128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:AECDH-AES256-SHA:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:AECDH-AES128-SHA:ADH-AES128-SHA:ADH-CAMELLIA128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:DHE-PSK-AES256-CCM8:DHE-PSK-AES256-CCM:RSA-PSK-ARIA256-GCM-SHA384:DHE-PSK-ARIA256-GCM-SHA384:AES256-GCM-SHA384:AES256-CCM8:AES256-CCM:ARIA256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:PSK-AES256-CCM8:PSK-AES256-CCM:PSK-ARIA256-GCM-SHA384:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-CCM8:DHE-PSK-AES128-CCM:RSA-PSK-ARIA128-GCM-SHA256:DHE-PSK-ARIA128-GCM-SHA256:AES128-GCM-SHA256:AES128-CCM8:AES128-CCM:ARIA128-GCM-SHA256:PSK-AES128-GCM-SHA256:PSK-AES128-CCM8:PSK-AES128-CCM:PSK-ARIA128-GCM-SHA256:AES256-SHA256:CAMELLIA256-SHA256:AES128-SHA256:CAMELLIA128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:ECDHE-PSK-CAMELLIA256-SHA384:RSA-PSK-CAMELLIA256-SHA384:DHE-PSK-CAMELLIA256-SHA384:AES256-SHA:CAMELLIA256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:PSK-CAMELLIA256-SHA384:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:ECDHE-PSK-CAMELLIA128-SHA256:RSA-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA128-SHA256:AES128-SHA:CAMELLIA128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA:PSK-CAMELLIA128-SHA256"), 0 };
  #else
    static const buffer default_ssl_cipher_list = { CONST_STR_LEN("HIGH"), 0 };
  #endif

    p->ssl_ctxs = calloc(srv->config_context->used, sizeof(plugin_ssl_ctx));
    force_assert(p->ssl_ctxs);

    int rc = HANDLER_GO_ON;
    plugin_data_base srvplug;
    memset(&srvplug, 0, sizeof(srvplug));
    plugin_data_base * const ps = &srvplug;
    if (!config_plugin_values_init(srv, ps, cpk, "mod_openssl"))
        return HANDLER_ERROR;

    plugin_config_socket defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.ssl_honor_cipher_order = 1;
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

        /*(preserve prior behavior; not inherited)*/
        /*(forcing inheritance might break existing configs where SSL is enabled
         * by default in the global scope, but not $SERVER["socket"]=="*:80") */
        conf.ssl_enabled = 0;

        config_plugin_value_t *cpv = ps->cvlist + ps->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            /* ignore ssl.pemfile (k_id=6); included to process global scope */
            if (!is_socket_scope && cpv->k_id != 6) {
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
                conf.ssl_cipher_list = cpv->v.b;
                break;
              case 2: /* ssl.honor-cipher-order */
                conf.ssl_honor_cipher_order = (0 != cpv->v.u);
                break;
              case 3: /* ssl.dh-file */
                conf.ssl_dh_file = cpv->v.b;
                break;
              case 4: /* ssl.ec-curve */
                conf.ssl_ec_curve = cpv->v.b;
                break;
              case 5: /* ssl.openssl.ssl-conf-cmd */
                *(const array **)&conf.ssl_conf_cmd = cpv->v.a;
                break;
              case 6: /* ssl.pemfile */
                /* ignore here; included to process global scope when
                 * ssl.pemfile is set, but ssl.engine is not "enable" */
                break;
              case 7: /* ssl.empty-fragments */
                conf.ssl_empty_fragments = (0 != cpv->v.u);
                log_error(srv->errh, __FILE__, __LINE__, "SSL: "
                  "ssl.empty-fragments is deprecated and will soon be "
                  "removed.  If needed, use: ssl.openssl.ssl-conf-cmd = "
                  "(\"Options\" => \"EmptyFragments\")");
                log_error(srv->errh, __FILE__, __LINE__, "SSL: "
                  "ssl.empty-fragments is a "
                  "counter-measure against a SSL 3.0/TLS 1.0 protocol "
                  "vulnerability affecting CBC ciphers, which cannot be handled"
                  " by some broken (Microsoft) SSL implementations.");
                break;
              case 8: /* ssl.use-sslv2 */
                conf.ssl_use_sslv2 = (0 != cpv->v.u);
                log_error(srv->errh, __FILE__, __LINE__, "SSL: "
                  "ssl.use-sslv2 is deprecated and will soon be removed.  "
                  "Many modern TLS libraries no longer support SSLv2.");
                break;
              case 9: /* ssl.use-sslv3 */
                conf.ssl_use_sslv3 = (0 != cpv->v.u);
                log_error(srv->errh, __FILE__, __LINE__, "SSL: "
                  "ssl.use-sslv3 is deprecated and will soon be removed.  "
                  "Many modern TLS libraries no longer support SSLv3.  "
                  "If needed, use: "
                  "ssl.openssl.ssl-conf-cmd = (\"MinProtocol\" => \"SSLv3\")");
                break;
              case 10:/* ssl.stek-file */
                if (!buffer_is_empty(cpv->v.b))
                    p->ssl_stek_file = cpv->v.b->ptr;
                break;
              default:/* should not happen */
                break;
            }
        }
        if (HANDLER_GO_ON != rc) break;
        if (0 == i) memcpy(&defaults, &conf, sizeof(conf));

        if (0 != i && !conf.ssl_enabled) continue;

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
                    conf.ssl_disable_client_renegotiation = (0 != cpv->v.u);
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
                if (count_not_engine) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "ssl.pemfile has to be set in same $SERVER[\"socket\"] scope "
                      "as other ssl.* directives, unless only ssl.engine is set, "
                      "inheriting ssl.* from global scope");
                    rc = HANDLER_ERROR;
                    continue;
                }
                plugin_ssl_ctx * const s = p->ssl_ctxs + sidx;
                *s = *p->ssl_ctxs;/*(copy struct of ssl_ctx from global scope)*/
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
            plugin_ssl_ctx * const s = p->ssl_ctxs + sidx;
            s->ssl_ctx = conf.ssl_ctx;
        }
        else {
            SSL_CTX_free(conf.ssl_ctx);
            rc = HANDLER_ERROR;
        }
    }

  #ifdef TLSEXT_TYPE_session_ticket
    if (rc == HANDLER_GO_ON && ssl_is_init)
        mod_openssl_session_ticket_key_check(p, log_epoch_secs);
  #endif

    free(srvplug.cvlist);
    return rc;
}


SETDEFAULTS_FUNC(mod_openssl_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.pemfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.privkey"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-file"),
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
        T_CONFIG_BOOL,
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
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    p->srv = srv;
    p->cafiles = array_init(0);
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
        X509_STORE *ca_store = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (!buffer_string_is_empty(cpv->v.b)) pemfile = cpv;
                break;
              case 1: /* ssl.privkey */
                if (!buffer_string_is_empty(cpv->v.b)) privkey = cpv;
                break;
              case 2: /* ssl.ca-file */
                if (buffer_string_is_empty(cpv->v.b)) break;
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                ssl_ca_file = cpv->v.b;
                cpv->v.v = mod_openssl_load_cacerts(ssl_ca_file, srv->errh);
                if (NULL != cpv->v.v) {
                    cpv->vtype = T_CONFIG_LOCAL;
                    ca_store = ((plugin_cacerts *)cpv->v.v)->certs;
                }
                else {
                    log_error(srv->errh, __FILE__, __LINE__, "SSL: %s %s",
                      ERR_error_string(ERR_get_error(), NULL),
                      ssl_ca_file->ptr);
                    return HANDLER_ERROR;
                }
                break;
              case 3: /* ssl.ca-dn-file */
                if (buffer_string_is_empty(cpv->v.b)) break;
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                ssl_ca_dn_file = cpv->v.b;
                cpv->v.v = SSL_load_client_CA_file(ssl_ca_dn_file->ptr);
                if (NULL != cpv->v.v) {
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                else {
                    log_error(srv->errh, __FILE__, __LINE__, "SSL: %s %s",
                      ERR_error_string(ERR_get_error(), NULL),
                      ssl_ca_dn_file->ptr);
                    return HANDLER_ERROR;
                }
                break;
              case 4: /* ssl.ca-crl-file */
                if (buffer_string_is_empty(cpv->v.b)) break;
                ssl_ca_crl_file = cpv->v.b;
                if (0 == i) default_ssl_ca_crl_file = cpv->v.b;
                break;
              case 5: /* ssl.read-ahead */
              case 6: /* ssl.disable-client-renegotiation */
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
              case 11:/* ssl.verifyclient.exportcert */
              case 12:/* ssl.acme-tls-1 */
                break;
              case 13:/* ssl.stapling-file */
                ssl_stapling_file = cpv->v.b;
                break;
              case 14:/* debug.log-ssl-noise */
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
            array_insert_value(p->cafiles, CONST_BUF_LEN(ssl_ca_dn_file));
        if (ssl_ca_file)
            array_insert_value(p->cafiles, CONST_BUF_LEN(ssl_ca_file));
        UNUSED(ca_store);
        UNUSED(ssl_ca_crl_file);
        UNUSED(default_ssl_ca_crl_file);
      #else
        if (NULL == ca_store && ssl_ca_crl_file && i != 0) {
            log_error(srv->errh, __FILE__, __LINE__,
              "ssl.ca-crl-file (%s) ignored unless issued with ssl.ca-file",
              ssl_ca_crl_file->ptr);
        }
        else if (ca_store && (ssl_ca_crl_file || default_ssl_ca_crl_file)) {
            /* prior behavior in lighttpd allowed ssl.ca-crl-file only in global
             * scope or $SERVER["socket"], so this inheritence from global scope
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
            if (!mod_openssl_load_cacrls(ca_store, ssl_ca_crl_file, srv))
                return HANDLER_ERROR;
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
    p->defaults.ssl_disable_client_renegotiation = 1;
    p->defaults.ssl_read_ahead = 0;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_openssl_merge_config(&p->defaults, cpv);
    }

    return mod_openssl_set_defaults_sockets(srv, p);
}


static int
load_next_chunk (request_st * const r, chunkqueue * const cq, off_t max_bytes,
                 const char ** const data, size_t * const data_len)
{
    chunk *c = cq->first;

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

    force_assert(NULL != c);

    switch (c->type) {
    case MEM_CHUNK:
        *data = NULL;
        *data_len = 0;
        do {
            size_t have;

            force_assert(c->offset >= 0
                         && c->offset <= (off_t)buffer_string_length(c->mem));

            have = buffer_string_length(c->mem) - c->offset;

            /* copy small mem chunks into single large buffer before SSL_write()
             * to reduce number times write() called underneath SSL_write() and
             * potentially reduce number of packets generated if TCP_NODELAY */
            if (*data_len) {
                size_t space = LOCAL_SEND_BUFSIZE - *data_len;
                if (have > space)
                    have = space;
                if (have > (size_t)max_bytes - *data_len)
                    have = (size_t)max_bytes - *data_len;
                if (*data != local_send_buffer) {
                    memcpy(local_send_buffer, *data, *data_len);
                    *data = local_send_buffer;
                }
                memcpy(local_send_buffer+*data_len,c->mem->ptr+c->offset,have);
                *data_len += have;
                continue;
            }

            if ((off_t) have > max_bytes) have = max_bytes;

            *data = c->mem->ptr + c->offset;
            *data_len = have;
        } while ((c = c->next) && c->type == MEM_CHUNK
                 && *data_len < LOCAL_SEND_BUFSIZE
                 && (off_t) *data_len < max_bytes);
        return 0;

    case FILE_CHUNK:
        if (0 != chunkqueue_open_file_chunk(cq, r->conf.errh)) return -1;

        {
            off_t offset, toSend;

            force_assert(c->offset >= 0 && c->offset <= c->file.length);
            offset = c->file.start + c->offset;
            toSend = c->file.length - c->offset;

            if (toSend > LOCAL_SEND_BUFSIZE) toSend = LOCAL_SEND_BUFSIZE;
            if (toSend > max_bytes) toSend = max_bytes;

            if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
                log_perror(r->conf.errh, __FILE__, __LINE__, "lseek");
                return -1;
            }
            if (-1 == (toSend = read(c->file.fd, local_send_buffer, toSend))) {
                log_perror(r->conf.errh, __FILE__, __LINE__, "read");
                return -1;
            }

            *data = local_send_buffer;
            *data_len = toSend;
        }
        return 0;
    }

    return -1;
}


static int
mod_openssl_close_notify(handler_ctx *hctx);


static int
connection_write_cq_ssl (connection *con, chunkqueue *cq, off_t max_bytes)
{
    request_st * const r = &con->request;
    handler_ctx *hctx = r->plugin_ctx[plugin_data_singleton->id];
    SSL *ssl = hctx->ssl;

    if (0 != hctx->close_notify) return mod_openssl_close_notify(hctx);

    chunkqueue_remove_finished_chunks(cq);

    while (max_bytes > 0 && NULL != cq->first) {
        const char *data;
        size_t data_len;
        int wr;

        if (0 != load_next_chunk(r, cq, max_bytes, &data, &data_len)) return -1;

        /**
         * SSL_write man-page
         *
         * WARNING
         *        When an SSL_write() operation has to be repeated because of
         *        SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be
         *        repeated with the same arguments.
         */

        ERR_clear_error();
        wr = SSL_write(ssl, data, data_len);

        if (hctx->renegotiations > 1
            && hctx->conf.ssl_disable_client_renegotiation) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }

        if (wr <= 0) {
            int ssl_r;
            unsigned long err;

            switch ((ssl_r = SSL_get_error(ssl, wr))) {
            case SSL_ERROR_WANT_READ:
                con->is_readable = -1;
                return 0; /* try again later */
            case SSL_ERROR_WANT_WRITE:
                con->is_writable = -1;
                return 0; /* try again later */
            case SSL_ERROR_SYSCALL:
                /* perhaps we have error waiting in our error-queue */
                if (0 != (err = ERR_get_error())) {
                    do {
                        log_error(r->conf.errh, __FILE__, __LINE__,
                          "SSL: %d %d %s",ssl_r,wr,ERR_error_string(err,NULL));
                    } while((err = ERR_get_error()));
                } else if (wr == -1) {
                    /* no, but we have errno */
                    switch(errno) {
                    case EPIPE:
                    case ECONNRESET:
                        return -2;
                    default:
                        log_perror(r->conf.errh, __FILE__, __LINE__,
                          "SSL: %d %d", ssl_r, wr);
                        break;
                    }
                } else {
                    /* neither error-queue nor errno ? */
                    log_perror(r->conf.errh, __FILE__, __LINE__,
                      "SSL (error): %d %d", ssl_r, wr);
                }
                break;

            case SSL_ERROR_ZERO_RETURN:
                /* clean shutdown on the remote side */

                if (wr == 0) return -2;

                /* fall through */
            default:
                while((err = ERR_get_error())) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "SSL: %d %d %s", ssl_r, wr, ERR_error_string(err, NULL));
                }
                break;
            }
            return -1;
        }

        chunkqueue_mark_written(cq, wr);
        max_bytes -= wr;

        if ((size_t) wr < data_len) break; /* try again later */
    }

    return 0;
}


static int
connection_read_cq_ssl (connection *con, chunkqueue *cq, off_t max_bytes)
{
    request_st * const r = &con->request;
    handler_ctx *hctx = r->plugin_ctx[plugin_data_singleton->id];
    int len;
    char *mem = NULL;
    size_t mem_len = 0;

    UNUSED(max_bytes);

    if (0 != hctx->close_notify) return mod_openssl_close_notify(hctx);

    ERR_clear_error();
    do {
        len = SSL_pending(hctx->ssl);
        mem_len = len < 2048 ? 2048 : (size_t)len;
        chunk * const ckpt = cq->last;
        mem = chunkqueue_get_memory(cq, &mem_len);

        len = SSL_read(hctx->ssl, mem, mem_len);
        if (len > 0) {
            chunkqueue_use_memory(cq, ckpt, len);
            con->bytes_read += len;
        } else {
            chunkqueue_use_memory(cq, ckpt, 0);
        }

        if (hctx->renegotiations > 1
            && hctx->conf.ssl_disable_client_renegotiation) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }

      #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        if (hctx->alpn) {
            if (hctx->alpn == MOD_OPENSSL_ALPN_ACME_TLS_1) {
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
        int oerrno = errno;
        int rc, ssl_err;
        switch ((rc = SSL_get_error(hctx->ssl, len))) {
        case SSL_ERROR_WANT_WRITE:
            con->is_writable = -1;
            /* fall through */
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
            while((ssl_err = ERR_get_error())) {
                /* get all errors from the error-queue */
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "SSL: %d %s", rc, ERR_error_string(ssl_err, NULL));
            }

            switch(oerrno) {
            case ECONNRESET:
                if (!hctx->conf.ssl_log_noise) break;
                /* fall through */
            default:
                /* (oerrno should be something like ECONNABORTED not 0
                 *  if client disconnected before anything was sent
                 *  (e.g. TCP connection probe), but it does not appear
                 *  that openssl provides such notification, not even
                 *  something like SSL_R_SSL_HANDSHAKE_FAILURE) */
                if (0==oerrno && 0==cq->bytes_in && !hctx->conf.ssl_log_noise)
                    break;

                log_error(r->conf.errh, __FILE__, __LINE__,
                  "SSL: %d %d %d %s", len, rc, oerrno, strerror(oerrno));
                break;
            }

            break;
        case SSL_ERROR_ZERO_RETURN:
            /* clean shutdown on the remote side */

            if (rc == 0) {
                /* FIXME: later */
            }

            /* fall through */
        default:
            while((ssl_err = ERR_get_error())) {
                switch (ERR_GET_REASON(ssl_err)) {
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
                /* get all errors from the error-queue */
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "SSL: %d %s", rc, ERR_error_string(ssl_err, NULL));
            }
            break;
        }
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
    server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    plugin_data *p = p_d;
    handler_ctx * const hctx = handler_ctx_init();
    request_st * const r = &con->request;
    hctx->r = r;
    hctx->con = con;
    hctx->tmp_buf = con->srv->tmp_buf;
    r->plugin_ctx[p->id] = hctx;

    plugin_ssl_ctx * const s = p->ssl_ctxs + srv_sock->sidx;
    hctx->ssl = SSL_new(s->ssl_ctx);
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
        log_error(r->conf.errh, __FILE__, __LINE__,
          "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
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
    request_st * const r = &con->request;
    plugin_data *p = p_d;
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

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
        unsigned long err;
        log_error_st *errh;

        if (1 == hctx->close_notify) return -2;

        ERR_clear_error();
        switch ((ret = SSL_shutdown(hctx->ssl))) {
        case 1:
            mod_openssl_detach(hctx);
            return -2;
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
            switch ((ret = SSL_shutdown(hctx->ssl))) {
            case 1:
                mod_openssl_detach(hctx);
                return -2;
            case 0:
                hctx->close_notify = -1;
                return 0;
            default:
                break;
            }

            /* fall through */
        default:

            if (!SSL_is_init_finished(hctx->ssl)) {
                mod_openssl_detach(hctx);
                return -2;
            }

            switch ((ssl_r = SSL_get_error(hctx->ssl, ret))) {
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
                hctx->close_notify = -1;
                return 0; /* try again later */
            case SSL_ERROR_SYSCALL:
                /* perhaps we have error waiting in our error-queue */
                errh = hctx->r->conf.errh;
                if (0 != (err = ERR_get_error())) {
                    do {
                        log_error(errh, __FILE__, __LINE__,
                          "SSL: %d %d %s",ssl_r,ret,ERR_error_string(err,NULL));
                    } while((err = ERR_get_error()));
                } else if (errno != 0) {
                    /*ssl bug (see lighttpd ticket #2213): sometimes errno==0*/
                    switch(errno) {
                    case EPIPE:
                    case ECONNRESET:
                        break;
                    default:
                        log_perror(errh, __FILE__, __LINE__,
                          "SSL (error): %d %d", ssl_r, ret);
                        break;
                    }
                }

                break;
            default:
                errh = hctx->r->conf.errh;
                while((err = ERR_get_error())) {
                    log_error(errh, __FILE__, __LINE__,
                      "SSL: %d %d %s", ssl_r, ret, ERR_error_string(err, NULL));
                }

                break;
            }
        }
        ERR_clear_error();
        hctx->close_notify = -1;
        return ret;
}


CONNECTION_FUNC(mod_openssl_handle_con_close)
{
    request_st * const r = &con->request;
    plugin_data *p = p_d;
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL != hctx) {
        handler_ctx_free(hctx);
        r->plugin_ctx[p->id] = NULL;
    }

    return HANDLER_GO_ON;
}


static void
https_add_ssl_client_entries (request_st * const r, handler_ctx * const hctx)
{
    buffer * const tb = r->tmp_buf;
    X509 *xs;
    X509_NAME *xn;
    int i, nentries;

    long vr = SSL_get_verify_result(hctx->ssl);
    if (vr != X509_V_OK) {
        char errstr[256];
        ERR_error_string_n(vr, errstr, sizeof(errstr));
        buffer_copy_string_len(tb, CONST_STR_LEN("FAILED:"));
        buffer_append_string(tb, errstr);
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_BUF_LEN(tb));
        return;
    } else if (!(xs = SSL_get_peer_certificate(hctx->ssl))) {
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_STR_LEN("NONE"));
        return;
    } else {
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_STR_LEN("SUCCESS"));
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
    buffer_copy_string_len(tb, CONST_STR_LEN("SSL_CLIENT_S_DN_"));
    for (i = 0, nentries = X509_NAME_entry_count(xn); i < nentries; ++i) {
        int xobjnid;
        const char * xobjsn;
        X509_NAME_ENTRY *xe;

        if (!(xe = X509_NAME_get_entry(xn, i))) {
            continue;
        }
        xobjnid = OBJ_obj2nid((ASN1_OBJECT*)X509_NAME_ENTRY_get_object(xe));
        xobjsn = OBJ_nid2sn(xobjnid);
        if (xobjsn) {
            buffer_string_set_length(tb, sizeof("SSL_CLIENT_S_DN_")-1);
            buffer_append_string(tb, xobjsn);
            http_header_env_set(r,
                                CONST_BUF_LEN(tb),
                                (const char*)X509_NAME_ENTRY_get_data(xe)->data,
                                X509_NAME_ENTRY_get_data(xe)->length);
        }
    }

    {
      #ifdef WOLFSSL_VERSION
        byte buf[64];
        int bsz = (int)sizeof(buf);
        if (wolfSSL_X509_get_serial_number(xs, buf, &bsz) == WOLFSSL_SUCCESS) {
            char serialHex[128+1];
            li_tohex_uc(serialHex, sizeof(serialHex), (char *)buf, (size_t)bsz);
            http_header_env_set(r,
                                CONST_STR_LEN("SSL_CLIENT_M_SERIAL"),
                                serialHex, strlen(serialHex));
        }
      #else
        ASN1_INTEGER *xsn = X509_get_serialNumber(xs);
        BIGNUM *serialBN = ASN1_INTEGER_to_BN(xsn, NULL);
        char *serialHex = BN_bn2hex(serialBN);
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_M_SERIAL"),
                            serialHex, strlen(serialHex));
        OPENSSL_free(serialHex);
        BN_free(serialBN);
      #endif
    }

    if (!buffer_string_is_empty(hctx->conf.ssl_verifyclient_username)) {
        /* pick one of the exported values as "REMOTE_USER", for example
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_UID"
         * or
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_emailAddress"
         */
        const buffer *varname = hctx->conf.ssl_verifyclient_username;
        const buffer *vb = http_header_env_get(r, CONST_BUF_LEN(varname));
        if (vb) { /* same as http_auth.c:http_auth_setenv() */
            http_header_env_set(r,
                                CONST_STR_LEN("REMOTE_USER"),
                                CONST_BUF_LEN(vb));
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

            buffer_string_prepare_copy(tb, n);
            BIO_read(bio, tb->ptr, n);
            BIO_free(bio);
            buffer_commit(tb, n);
            http_header_env_set(r,
                                CONST_STR_LEN("SSL_CLIENT_CERT"),
                                CONST_BUF_LEN(tb));
        }
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
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    if (hctx->request_env_patched) return HANDLER_GO_ON;
    hctx->request_env_patched = 1;

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
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    mod_openssl_patch_config(r, &hctx->conf);
    if (hctx->conf.ssl_verifyclient) {
        mod_openssl_handle_request_env(r, p);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_openssl_handle_request_reset)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = r->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    hctx->request_env_patched = 0;
    return HANDLER_GO_ON;
}


TRIGGER_FUNC(mod_openssl_handle_trigger) {
    const plugin_data * const p = p_d;
    const time_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/
    UNUSED(srv);
    UNUSED(p);

  #ifdef TLSEXT_TYPE_session_ticket
    mod_openssl_session_ticket_key_check(p, cur_ts);
  #endif

  #ifndef OPENSSL_NO_OCSP
    mod_openssl_refresh_stapling_files(srv, p, cur_ts);
  #endif

    return HANDLER_GO_ON;
}


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
    p->connection_reset          = mod_openssl_handle_request_reset;
    p->handle_trigger            = mod_openssl_handle_trigger;

    return 0;
}


#if defined(BORINGSSL_API_VERSION) \
 || defined(LIBRESSL_VERSION_NUMBER) \
 || defined(WOLFSSL_VERSION)

static int
mod_openssl_ssl_conf_proto_val (server *srv, plugin_config_socket *s, const buffer *b, int max)
{
    if (NULL == b) /* default: min TLSv1.2, max TLSv1.3 */
      #ifdef TLS1_3_VERSION
        return max ? TLS1_3_VERSION : TLS1_2_VERSION;
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
          : (s->ssl_use_sslv3 ? SSL3_VERSION : TLS1_VERSION);
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("SSLv3")))
        return SSL3_VERSION;
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
    return max ? TLS1_3_VERSION : TLS1_2_VERSION;
  #else
    return TLS1_2_VERSION;
  #endif
}


static int
mod_openssl_ssl_conf_cmd (server *srv, plugin_config_socket *s)
{
    /* reference:
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_CONF_cmd.html */
    int rc = 0;
    buffer *cipherstring = NULL;
    /*buffer *ciphersuites = NULL;*/
    buffer *minb = NULL;
    buffer *maxb = NULL;
    buffer *curves = NULL;

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        data_string *ds = (data_string *)s->ssl_conf_cmd->data[i];
        if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("CipherString")))
            cipherstring = &ds->value;
      #if 0
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Ciphersuites")))
            ciphersuites = &ds->value;
      #endif
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Curves"))
              || buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Groups")))
            curves = &ds->value;
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
                for (e = v; light_isalpha(*e); ++e) ;
                switch ((int)(e-v)) {
                  case 11:
                    if (buffer_eq_icase_ssn(v, "Compression", 11)) {
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
        /*(wolfSSL_CTX_SetMinVersion() alt uses enums with different values)*/
        int n = mod_openssl_ssl_conf_proto_val(srv, s, minb, 0);
        if (!SSL_CTX_set_min_proto_version(s->ssl_ctx, n))
            rc = -1;
    }

    if (maxb) {
      #ifndef WOLFSSL_VERSION /*WolfSSL max ver is set at WolfSSL compile-time*/
        int x = mod_openssl_ssl_conf_proto_val(srv, s, maxb, 1);
        if (!SSL_CTX_set_max_proto_version(s->ssl_ctx, x))
            rc = -1;
      #endif
    }

    if (cipherstring) {
        /* Disable support for low encryption ciphers */
        buffer_append_string_len(cipherstring,
                                 CONST_STR_LEN(":!aNULL:!eNULL:!EXP"));
        if (SSL_CTX_set_cipher_list(s->ssl_ctx, s->ssl_cipher_list->ptr) != 1) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
            rc = -1;
        }

        if (s->ssl_honor_cipher_order)
            SSL_CTX_set_options(s->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    if (curves) {
        if (!mod_openssl_ssl_conf_curves(srv, s, curves))
            rc = -1;
    }

    return rc;
}

#endif /* BORINGSSL_API_VERSION || LIBRESSL_VERSION_NUMBER || WOLFSSL_VERSION */
