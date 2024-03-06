/*
 * mod_wolfssl - wolfSSL support for lighttpd
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
/*
 * Note: If session tickets are -not- disabled with
 *     ssl.openssl.ssl-conf-cmd = ("Options" => "-SessionTicket")
 *   mod_wolfssl rotates server ticket encryption key (STEK) every 8 hours
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

/*
 * Note: mod_wolfssl.c is forked from mod_openssl.c
 * Many internal symbol names in mod_wolfssl.c retain the mod_openssl_* prefix
 * (wolfSSL provides an OpenSSL compatibility layer)
 */

/* wolfSSL needs to be built with ./configure --enable-lighty for lighttpd.
 * Doing so defines OPENSSL_EXTRA and HAVE_LIGHTY in <wolfssl/options.h>, and
 * these defines are necessary for wolfSSL headers to expose sufficient openssl
 * compatibility layer for wolfSSL to be able to provide an openssl substitute
 * for use by lighttpd */

/* workaround fragile code in wolfssl/wolfcrypto/types.h */
#if !defined(SIZEOF_LONG) || !defined(SIZEOF_LONG_LONG)
#undef SIZEOF_LONG
#undef SIZEOF_LONG_LONG
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#ifdef HAVE_OCSP
#include <wolfssl/ocsp.h>
#endif

static char global_err_buf[WOLFSSL_MAX_ERROR_SZ];
#undef ERR_error_string
#define ERR_error_string(e,b) \
        (wolfSSL_ERR_error_string_n((e),global_err_buf,WOLFSSL_MAX_ERROR_SZ), \
         global_err_buf)

#if 0 /* symbols and definitions requires WolfSSL built with -DOPENSSL_EXTRA */
#define SSL_TLSEXT_ERR_OK               0
#define SSL_TLSEXT_ERR_ALERT_FATAL      alert_fatal
#define SSL_TLSEXT_ERR_NOACK            alert_warning

WOLFSSL_API void wolfSSL_set_verify_depth(WOLFSSL *ssl,int depth);

WOLFSSL_API void wolfSSL_X509_NAME_free(WOLFSSL_X509_NAME* name);
WOLFSSL_API int wolfSSL_X509_NAME_cmp(const WOLFSSL_X509_NAME* x, const WOLFSSL_X509_NAME* y);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_X509_NAME_dup(WOLFSSL_X509_NAME*);
WOLFSSL_API char* wolfSSL_X509_get_name_oneline(WOLFSSL_X509_NAME*, char*, int);

WOLFSSL_API const char* wolfSSL_OBJ_nid2sn(int n);
WOLFSSL_API int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);
WOLFSSL_API WOLFSSL_ASN1_OBJECT * wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY *ne);
WOLFSSL_API WOLFSSL_X509_NAME_ENTRY *wolfSSL_X509_NAME_get_entry(WOLFSSL_X509_NAME *name, int loc);
#endif

#if LIBWOLFSSL_VERSION_HEX < 0x04005000
#if !defined(OPENSSL_ALL) || LIBWOLFSSL_VERSION_HEX < 0x04002000
/*(invalid; but centralize making these calls no-ops)*/
#define wolfSSL_sk_X509_NAME_num(a)          0
#define wolfSSL_sk_X509_NAME_push(a, b)      0
#define wolfSSL_sk_X509_NAME_pop_free(a, b)  do { } while (0)
#define wolfSSL_sk_X509_NAME_free(a)         do { } while (0)
#define wolfSSL_X509_get_subject_name(ca) \
        ((WOLFSSL_X509_NAME *)1) /* ! NULL */
#define wolfSSL_sk_X509_NAME_new(a) \
        ((WOLF_STACK_OF(WOLFSSL_X509_NAME) *)1) /* ! NULL */
#endif
#endif

#if LIBWOLFSSL_VERSION_HEX < 0x04006000 || defined(WOLFSSL_NO_FORCE_ZERO)
#define wolfSSL_OPENSSL_cleanse(x,sz) ck_memzero((x),(sz))
#endif

#if LIBWOLFSSL_VERSION_HEX < 0x04002000 /*(exact version needed not checked)*/
#ifndef STACK_OF
#define STACK_OF(x) WOLFSSL_STACK
#endif
#endif

#include "base.h"
#include "ck.h"
#include "fdevent.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    buffer *ssl_pemfile_pkey;
    buffer *ssl_pemfile_x509;
    buffer **ssl_pemfile_chain;
    buffer *ssl_stapling;
    const buffer *ssl_pemfile;
    const buffer *ssl_privkey;
    const buffer *ssl_stapling_file;
    unix_time64_t ssl_stapling_loadts;
    unix_time64_t ssl_stapling_nextts;
    char must_staple;
} plugin_cert;

typedef struct {
    WOLFSSL_CTX *ssl_ctx;
} plugin_ssl_ctx;

typedef struct {
    STACK_OF(X509_NAME) *names;
    X509_STORE *certs;
} plugin_cacerts;

typedef struct {
    WOLFSSL_CTX *ssl_ctx; /* output from network_init_ssl() */

    /*(used only during startup; not patched)*/
    unsigned char ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned char ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    const buffer *ssl_cipher_list;
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
    plugin_ssl_ctx *ssl_ctxs;
    plugin_config defaults;
    server *srv;
    array *cafiles;
    const char *ssl_stek_file;
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id]; */
static plugin_data *plugin_data_singleton;
#define LOCAL_SEND_BUFSIZE (16 * 1024)
static char *local_send_buffer;

typedef struct {
    WOLFSSL *ssl;
    request_st *r;
    connection *con;
    short renegotiations; /* count of SSL_CB_HANDSHAKE_START */
    short close_notify;
    unsigned short alpn;
    plugin_config conf;
    buffer *tmp_buf;
    log_error_st *errh;
} handler_ctx;


static handler_ctx *
handler_ctx_init (void)
{
    return ck_calloc(1, sizeof(handler_ctx));
}


static void
handler_ctx_free (handler_ctx *hctx)
{
    if (hctx->ssl) SSL_free(hctx->ssl);
    free(hctx);
}


#ifdef HAVE_SESSION_TICKET
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

    wolfSSL_OPENSSL_cleanse(session_ticket_keys+3, sizeof(tlsext_ticket_key_t));
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
            wolfSSL_OPENSSL_cleanse(session_ticket_keys+i,
                                    sizeof(tlsext_ticket_key_t));
    }
}


/* based on reference implementation from openssl 1.1.1g man page
 *   man SSL_CTX_set_tlsext_ticket_key_cb
 * but openssl code uses EVP_aes_256_cbc() instead of EVP_aes_128_cbc()
 */
#ifndef EVP_MAX_IV_LENGTH
#define EVP_MAX_IV_LENGTH 16
#endif
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

    wolfSSL_OPENSSL_cleanse(buf, sizeof(buf));
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

#endif /* HAVE_SESSION_TICKET */


#ifdef HAVE_OCSP
static int
ssl_tlsext_status_cb(SSL *ssl, void *arg)
{
  #ifdef SSL_get_tlsext_status_type
    if (TLSEXT_STATUSTYPE_ocsp != SSL_get_tlsext_status_type(ssl))
        return SSL_TLSEXT_ERR_NOACK; /* ignore if not client OCSP request */
  #endif

    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    if (NULL == hctx->conf.pc) return SSL_TLSEXT_ERR_NOACK;/*should not happen*/
    buffer *ssl_stapling = hctx->conf.pc->ssl_stapling;
    if (NULL == ssl_stapling) return SSL_TLSEXT_ERR_NOACK;
    UNUSED(arg);

    int len = (int)buffer_clen(ssl_stapling);

    /* wolfSSL caller is going to XFREE() */
    uint8_t *ocsp_resp = XMALLOC(len, NULL, DYNAMIC_TYPE_OPENSSL);
    if (NULL == ocsp_resp)
        return SSL_TLSEXT_ERR_NOACK; /* ignore OCSP request if error occurs */
    memcpy(ocsp_resp, ssl_stapling->ptr, (uint32_t)len);

    if (!SSL_set_tlsext_status_ocsp_resp(ssl, ocsp_resp, len)) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set OCSP response for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
        return SSL_TLSEXT_ERR_NOACK; /* ignore OCSP request if error occurs */
        /*return SSL_TLSEXT_ERR_ALERT_FATAL;*/
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif


INIT_FUNC(mod_openssl_init)
{
    plugin_data_singleton = (plugin_data *)ck_calloc(1, sizeof(plugin_data));
  #ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
  #endif
    return plugin_data_singleton;
}


static int mod_openssl_init_once_openssl (server *srv)
{
    if (ssl_is_init) return 1;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: wolfSSL_Init() failed");
        return 0;
    }
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

  #ifdef HAVE_SESSION_TICKET
    wolfSSL_OPENSSL_cleanse(session_ticket_keys, sizeof(session_ticket_keys));
    stek_rotate_ts = 0;
  #endif

    if (wolfSSL_Cleanup() != WOLFSSL_SUCCESS) {
        log_error(plugin_data_singleton->srv->errh, __FILE__, __LINE__,
          "SSL: wolfSSL_Cleanup() failed");
    }

    free(local_send_buffer);
    ssl_is_init = 0;
}


static void
mod_wolfssl_free_der_certs (buffer **certs)
{
    if (NULL == certs) return;
    for (int i = 0; NULL != certs[i]; ++i)
        buffer_free(certs[i]);
    free(certs);
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
                    wolfSSL_OPENSSL_cleanse(pc->ssl_pemfile_pkey->ptr,
                                            pc->ssl_pemfile_pkey->size);
                    buffer_free(pc->ssl_pemfile_pkey);
                    /*buffer_free(pc->ssl_pemfile_x509);*//*(part of chain)*/
                    mod_wolfssl_free_der_certs(pc->ssl_pemfile_chain);
                    buffer_free(pc->ssl_stapling);
                    free(pc);
                }
                break;
              case 2: /* ssl.ca-file */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_cacerts *cacerts = cpv->v.v;
                    wolfSSL_sk_X509_NAME_pop_free(cacerts->names,
                                                  X509_NAME_free);
                    wolfSSL_X509_STORE_free(cacerts->certs);
                    free(cacerts);
                }
                break;
              case 3: /* ssl.ca-dn-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    wolfSSL_sk_X509_NAME_pop_free(cpv->v.v, X509_NAME_free);
                break;
              default:
                break;
            }
        }
    }
}


#if LIBWOLFSSL_VERSION_HEX >= 0x04002000
static int
mod_wolfssl_cert_is_active (const buffer *b)
{
    WOLFSSL_X509 *crt =
      wolfSSL_X509_load_certificate_buffer((const unsigned char *)b->ptr,
                                           (int)buffer_clen(b),
                                           WOLFSSL_FILETYPE_ASN1);
    if (NULL == crt) return 0;
    const WOLFSSL_ASN1_TIME *notBefore = wolfSSL_X509_get_notBefore(crt);
    const WOLFSSL_ASN1_TIME *notAfter  = wolfSSL_X509_get_notAfter(crt);
    time_t now = (time_t)log_epoch_secs;
    /*(wolfSSL_X509_cmp_time() might return 0 (WOLFSSL_FAILURE) on failure
     * to convert WOLFSSL_ASN1_TIME to struct tm; should not happen but WTH?
     * Also might return -337 (GETTIME_ERROR))*/
    const int before_cmp = wolfSSL_X509_cmp_time(notBefore, &now);
    const int after_cmp  = wolfSSL_X509_cmp_time(notAfter,  &now);
    wolfSSL_X509_free(crt);
    return ((before_cmp == -1 || before_cmp == 0) && 0 <= after_cmp);
}
#endif


/* WolfSSL OpenSSL compat API does not wipe temp mem used; write our own */
/* (pemfile might contain private key)*/
/* code here is based on similar code in mod_nss */
#include "base64.h"

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


static buffer *
mod_wolfssl_load_pem_file (const char *fn, log_error_st *errh, buffer ***chain)
{
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;

    buffer **certs = NULL;
    int rc = -1;
    do {
        int count = 0;
        char *b = data;
        for (; (b = strstr(b, PEM_BEGIN_CERT)); b += sizeof(PEM_BEGIN_CERT)-1)
            ++count;
        b = data;
        for (; (b = strstr(b, PEM_BEGIN_TRUSTED_CERT));
                b += sizeof(PEM_BEGIN_TRUSTED_CERT)-1)
            ++count;
        if (0 == count) {
            rc = 0;
            if (NULL == strstr(data, "-----")) {
                /* does not look like PEM, treat as DER format */
                certs = ck_malloc(2 * sizeof(buffer *));
                certs[0] = buffer_init();
                certs[1] = NULL;
                buffer_copy_string_len(certs[0], data, dlen);
            }
            break;
        }

        certs = ck_malloc((count+1) * sizeof(buffer *));
        certs[count] = NULL;
        for (int i = 0; i < count; ++i)
            certs[i] = buffer_init();

        buffer *der;
        int i = 0;
        for (char *e = data; (b = strstr(e, PEM_BEGIN_CERT)); ++i) {
            b += sizeof(PEM_BEGIN_CERT)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_CERT);
            if (NULL == e) break;
            uint32_t len = (uint32_t)(e - b);
            e += sizeof(PEM_END_CERT)-1;
            if (i >= count) break; /*(should not happen)*/
            der = certs[i];
            if (NULL == buffer_append_base64_decode(der,b,len,BASE64_STANDARD))
                break;
        }
        for (char *e = data; (b = strstr(e, PEM_BEGIN_TRUSTED_CERT)); ++i) {
            b += sizeof(PEM_BEGIN_TRUSTED_CERT)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_TRUSTED_CERT);
            if (NULL == e) break;
            uint32_t len = (uint32_t)(e - b);
            e += sizeof(PEM_END_TRUSTED_CERT)-1;
            if (i >= count) break; /*(should not happen)*/
            der = certs[i];
            if (NULL == buffer_append_base64_decode(der,b,len,BASE64_STANDARD))
                break;
        }
        if (i == count)
            rc = 0;
        else
            errno = EIO;
    } while (0);

    if (dlen) ck_memzero(data, dlen);
    free(data);

    if (rc < 0) {
        log_perror(errh, __FILE__, __LINE__, "error loading %s", fn);
        mod_wolfssl_free_der_certs(certs);
        certs = NULL;
    }

  #if LIBWOLFSSL_VERSION_HEX >= 0x04002000
    if (certs && !mod_wolfssl_cert_is_active(certs[0]))
        log_error(errh, __FILE__, __LINE__,
          "SSL: inactive/expired X509 certificate '%s'", fn);
  #endif

    *chain = certs;
    return certs ? certs[0] : NULL;
}


static buffer *
mod_wolfssl_evp_pkey_load_pem_file (const char *fn, log_error_st *errh)
{
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, errh, malloc, free);
    if (NULL == data) return NULL;

    buffer *pkey = NULL;
    int rc = -1;
    do {
        /*(expecting single private key in file, so first match)*/
        char *b, *e;
        if ((b = strstr(data, PEM_BEGIN_PKEY))
            && (e = strstr(b, PEM_END_PKEY)))
            b += sizeof(PEM_BEGIN_PKEY)-1;
        else if ((b = strstr(data, PEM_BEGIN_EC_PKEY))
                 && (e = strstr(b, PEM_END_EC_PKEY)))
            b += sizeof(PEM_BEGIN_EC_PKEY)-1;
        else if ((b = strstr(data, PEM_BEGIN_RSA_PKEY))
                 && (e = strstr(b, PEM_END_RSA_PKEY)))
            b += sizeof(PEM_BEGIN_RSA_PKEY)-1;
        else if ((b = strstr(data, PEM_BEGIN_DSA_PKEY))
                 && (e = strstr(b, PEM_END_DSA_PKEY)))
            b += sizeof(PEM_BEGIN_DSA_PKEY)-1;
        else if ((b = strstr(data, PEM_BEGIN_ANY_PKEY))
                 && (e = strstr(b, PEM_END_ANY_PKEY)))
            b += sizeof(PEM_BEGIN_ANY_PKEY)-1;
        else if (NULL == strstr(data, "-----")) {
            /* does not look like PEM, treat as DER format */
            pkey = buffer_init();
            buffer_copy_string_len(pkey, data, dlen);
            rc = 0;
            break;
        }
        else
            break;
        if (*b == '\r') ++b;
        if (*b == '\n') ++b;

        pkey = buffer_init();
        size_t len = (size_t)(e - b);
        if (NULL == buffer_append_base64_decode(pkey, b, len, BASE64_STANDARD))
            break;
        rc = 0;
    } while (0);

    if (dlen) ck_memzero(data, dlen);
    free(data);

    if (rc < 0) {
        log_error(errh, __FILE__, __LINE__, "%s() %s", __func__, fn);
        if (pkey) {
            wolfSSL_OPENSSL_cleanse(pkey->ptr, pkey->size);
            buffer_free(pkey);
        }
        return NULL;
    }

    return pkey;
}


static int
mod_wolfssl_CTX_use_certificate_chain_file (WOLFSSL_CTX *ssl_ctx, const char *fn, log_error_st *errh)
{
    /* (While it should be possible to parse DERs from (buffer **)
     *  s->pc->ssl_pemfile_chain, it is simpler to re-read file and use the
     *  built-in wolfSSL_CTX_use_certificate_chain_buffer() interface) */
    off_t dlen = 4*1024*1024;/*(arbitrary limit: 4 MB file; expect < 1 KB)*/
    char *data = fdevent_load_file(fn, &dlen, errh, malloc, free);
    if (NULL == data) return -1;

    int rc = (NULL != strstr(data, "-----"))
      ? wolfSSL_CTX_use_certificate_chain_buffer(ssl_ctx, (unsigned char *)data,
                                                 (long)dlen)
      : wolfSSL_CTX_use_certificate_chain_buffer_format(ssl_ctx,
                                                        (unsigned char *)data,
                                                        (long)dlen,
                                                        WOLFSSL_FILETYPE_ASN1);

    if (dlen) ck_memzero(data, dlen);
    free(data);

    if (rc == WOLFSSL_SUCCESS)
        return 1;

    log_error(errh, __FILE__, __LINE__,
      "SSL: %s %s", ERR_error_string(rc, NULL), fn);
    return 0;
}


static STACK_OF(X509_NAME) *
mod_wolfssl_load_client_CA_file (const buffer *ssl_ca_file, log_error_st *errh)
{
    /* similar to wolfSSL_load_client_CA_file(), plus some processing */
    buffer **certs = NULL;
    if (NULL == mod_wolfssl_load_pem_file(ssl_ca_file->ptr, errh, &certs)) {
      #if defined(__clang_analyzer__) || defined(__COVERITY__)
        mod_wolfssl_free_der_certs(certs); /*unnecessary; quiet clang analyzer*/
      #endif
        return NULL;
    }

    WOLF_STACK_OF(WOLFSSL_X509_NAME) *canames = wolfSSL_sk_X509_NAME_new(NULL);
    if (NULL == canames) {
        mod_wolfssl_free_der_certs(certs);
        return NULL;
    }

    /* wolfSSL_sk_X509_NAME_push prior to version 4.8.0 returned 0 on success.
     * The return value was changed to WOLFSSL_SUCCESS (not 0) from 4.8.0. */
    const int x = wolfSSL_lib_version_hex() < 0x04008000 ? 0 : WOLFSSL_SUCCESS;
    for (int i = 0; NULL != certs[i]; ++i) {
        WOLFSSL_X509 *ca =
          wolfSSL_X509_load_certificate_buffer((unsigned char *)certs[i]->ptr,
                                               (int)buffer_clen(certs[i]),
                                               WOLFSSL_FILETYPE_ASN1);
        WOLFSSL_X509_NAME *subj = NULL;
        if (NULL == ca
            || NULL == (subj = wolfSSL_X509_get_subject_name(ca))
            || x != wolfSSL_sk_X509_NAME_push(canames,
                                              wolfSSL_X509_NAME_dup(subj))) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: couldn't read X509 certificates from '%s'",
              ssl_ca_file->ptr);
            if (subj) wolfSSL_X509_NAME_free(subj);
            if (ca) wolfSSL_X509_free(ca);
            wolfSSL_sk_X509_NAME_free(canames);
            mod_wolfssl_free_der_certs(certs);
            return NULL;
        }

        wolfSSL_X509_free(ca);
    }

    mod_wolfssl_free_der_certs(certs);
    return canames;
}


static plugin_cacerts *
mod_wolfssl_load_cacerts (const buffer *ssl_ca_file, log_error_st *errh)
{
    /* similar to mod_wolfSSL_load_client_CA_file(), plus some processing */
    /* similar to wolfSSL_load_client_CA_file(), plus some processing */
    buffer **certs = NULL;
    if (NULL == mod_wolfssl_load_pem_file(ssl_ca_file->ptr, errh, &certs)) {
      #if defined(__clang_analyzer__) || defined(__COVERITY__)
        mod_wolfssl_free_der_certs(certs); /*unnecessary; quiet clang analyzer*/
      #endif
        return NULL;
    }

    WOLFSSL_X509_STORE *castore = wolfSSL_X509_STORE_new();
    if (NULL == castore) {
        mod_wolfssl_free_der_certs(certs);
        return NULL;
    }

    WOLF_STACK_OF(WOLFSSL_X509_NAME) *canames = wolfSSL_sk_X509_NAME_new(NULL);
    if (NULL == canames) {
        wolfSSL_X509_STORE_free(castore);
        mod_wolfssl_free_der_certs(certs);
        return NULL;
    }

    /* wolfSSL_sk_X509_NAME_push prior to version 4.8.0 returned 0 on success.
     * The return value was changed to WOLFSSL_SUCCESS (not 0) from 4.8.0. */
    const int x = wolfSSL_lib_version_hex() < 0x04008000 ? 0 : WOLFSSL_SUCCESS;
    for (int i = 0; NULL != certs[i]; ++i) {
        WOLFSSL_X509 *ca =
          wolfSSL_X509_load_certificate_buffer((unsigned char *)certs[i]->ptr,
                                               (int)buffer_clen(certs[i]),
                                               WOLFSSL_FILETYPE_ASN1);
        WOLFSSL_X509_NAME *subj = NULL;
        if (NULL == ca || !wolfSSL_X509_STORE_add_cert(castore, ca)
            || NULL == (subj = wolfSSL_X509_get_subject_name(ca))
            || x != wolfSSL_sk_X509_NAME_push(canames,
                                              wolfSSL_X509_NAME_dup(subj))) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: couldn't read X509 certificates from '%s'",
              ssl_ca_file->ptr);
            if (subj) wolfSSL_X509_NAME_free(subj);
            if (ca) wolfSSL_X509_free(ca);
            wolfSSL_sk_X509_NAME_free(canames);
            wolfSSL_X509_STORE_free(castore);
            mod_wolfssl_free_der_certs(certs);
            return NULL;
        }

        wolfSSL_X509_free(ca);
    }

    mod_wolfssl_free_der_certs(certs);

    plugin_cacerts *cacerts = ck_malloc(sizeof(plugin_cacerts));
    cacerts->names = canames;
    cacerts->certs = castore;
    return cacerts;
}


static int
mod_wolfssl_load_cacrls (WOLFSSL_CTX *ssl_ctx, const buffer *ssl_ca_crl_file, server *srv)
{
  #ifdef HAVE_CRL /* <wolfssl/options.h> */
    int rc = wolfSSL_CTX_EnableCRL(ssl_ctx,
                                   WOLFSSL_CRL_CHECK | WOLFSSL_CRL_CHECKALL);
    if (rc != WOLFSSL_SUCCESS) return 0;

    const char *fn = ssl_ca_crl_file->ptr;
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, srv->errh, malloc, free);
    if (NULL == data) return 0;

    rc = wolfSSL_CTX_LoadCRLBuffer(ssl_ctx, (byte *)data, (long)dlen,
                                   WOLFSSL_FILETYPE_PEM);

    if (dlen) ck_memzero(data, dlen);
    free(data);

    if (rc == WOLFSSL_SUCCESS)
        return 1;

    log_error(srv->errh, __FILE__, __LINE__,
      "SSL: %s %s", ERR_error_string(rc, NULL), fn);
    return 0;
  #else
    UNUSED(ssl_ctx);
    log_error(srv->errh, __FILE__, __LINE__,
      "WolfSSL not built with CRL support; ignoring %s", ssl_ca_crl_file->ptr);
    return WOLFSSL_FAILURE;
  #endif
}


static int
mod_wolfssl_load_verify_locn (SSL_CTX *ssl_ctx, const buffer *b, server *srv)
{
    const char *fn = b->ptr;
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, srv->errh, malloc, free);
    if (NULL == data) return 0;

    int rc = wolfSSL_CTX_load_verify_buffer(ssl_ctx, (unsigned char *)data,
                                            (long)dlen, WOLFSSL_FILETYPE_PEM);

    if (dlen) ck_memzero(data, dlen);
    free(data);

    if (rc == WOLFSSL_SUCCESS)
        return 1;

    log_error(srv->errh, __FILE__, __LINE__,
      "SSL: %s %s", ERR_error_string(rc, NULL), fn);
    return 0;
}


static int
mod_wolfssl_load_ca_files (SSL_CTX *ssl_ctx, plugin_data *p, server *srv)
{
    /* load all ssl.ca-files specified in the config into each SSL_CTX */

    for (uint32_t i = 0, used = p->cafiles->used; i < used; ++i) {
        const buffer *b = &((data_string *)p->cafiles->data[i])->value;
        if (!mod_wolfssl_load_verify_locn(ssl_ctx, b, srv))
            return 0;
    }
    return 1;
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
  #if LIBWOLFSSL_VERSION_HEX < 0x04004000
    UNUSED(name);
    UNUSED(sz);
  #else
    if (wolfSSL_X509_get_name_oneline(name, buf, (int)sz))
        return (int)strlen(buf);
    else
  #endif
    {
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
    /* https://github.com/openssl/openssl/issues/5721
     * "TLSv1.3 unexpected InfoCallback after handshake completed" */
    if (0 != (where & SSL_CB_HANDSHAKE_DONE)) {
        /* SSL_version() is valid after initial handshake completed */
        SSL *ssl_nonconst;
        *(const SSL **)&ssl_nonconst = ssl;
        if (wolfSSL_GetVersion(ssl_nonconst) >= WOLFSSL_TLSV1_3) {
            /* https://wiki.openssl.org/index.php/TLS1.3
             * "Renegotiation is not possible in a TLSv1.3 connection" */
            handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
            hctx->renegotiations = -1;
        }
    }
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
     * wolfSSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
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
        err_cert = ctx->current_cert;/*wolfSSL_X509_STORE_CTX_get_current_cert*/
        if (NULL == err_cert) return !hctx->conf.ssl_verifyclient_enforce;
        issuer = X509_get_issuer_name(err_cert);
      #if 0 /*(?desirable/undesirable to have cert_names sorted?)*/
        if (-1 != sk_X509_NAME_find(cert_names, issuer))
            return preverify_ok; /* match */
      #else
        for (int i=0, len=wolfSSL_sk_X509_NAME_num(cert_names); i < len; ++i) {
            if (0 == wolfSSL_X509_NAME_cmp(sk_X509_NAME_value(cert_names, i),
                                           issuer))
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

    err_cert = ctx->current_cert; /*wolfSSL_X509_STORE_CTX_get_current_cert()*/
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

    if (!pc || NULL == pc->ssl_pemfile_x509 || NULL == pc->ssl_pemfile_pkey) {
        /* x509/pkey available <=> pemfile was set <=> pemfile got patched:
         * so this should never happen, unless you nest $SERVER["socket"] */
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: no certificate/private key for TLS server name \"%s\".  "
          "$SERVER[\"socket\"] should not be nested in other conditions.",
          hctx->r->uri.authority.ptr);
        return 0;
    }

    /* first set certificate!
     * setting private key checks whether certificate matches it */
    buffer *cert = pc->ssl_pemfile_x509;
    if (1 != wolfSSL_use_certificate_ASN1(ssl, (unsigned char *)cert->ptr,
                                          (int)buffer_clen(cert))) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set certificate for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    buffer *pkey = pc->ssl_pemfile_pkey;
    if (1 != wolfSSL_use_PrivateKey_buffer(ssl, (unsigned char *)pkey->ptr,
                                           (int)buffer_clen(pkey),
                                           WOLFSSL_FILETYPE_ASN1)) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SSL: failed to set private key for TLS server name %s: %s",
          hctx->r->uri.authority.ptr, ERR_error_string(ERR_get_error(), NULL));
        return 0;
    }

    if (hctx->conf.ssl_verifyclient) {
        if (NULL == hctx->conf.ssl_ca_file) {
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
              "SSL: can't verify client without ssl.verifyclient.ca-file "
              "for TLS server name %s", hctx->r->uri.authority.ptr);
            return 0;
        }
        /* WolfSSL does not support setting per-session CA list;
         * limitation is to per-CTX CA list, and is not changed after SNI */
        int mode = SSL_VERIFY_PEER;
        if (hctx->conf.ssl_verifyclient_enforce)
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        wolfSSL_set_verify(ssl, mode, verify_callback);
        wolfSSL_set_verify_depth(ssl, hctx->conf.ssl_verifyclient_depth + 1);
    }
    else {
        wolfSSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    return 1;
}

#ifdef HAVE_TLS_EXTENSIONS

enum {
  MOD_OPENSSL_ALPN_HTTP11      = 1
 ,MOD_OPENSSL_ALPN_HTTP10      = 2
 ,MOD_OPENSSL_ALPN_H2          = 3
 ,MOD_OPENSSL_ALPN_ACME_TLS_1  = 4
};

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
    buffer_copy_string_len_lc(&r->uri.authority, servername, len);
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

    return (mod_openssl_cert_cb(hctx->ssl, NULL) == 1)
      ? SSL_TLSEXT_ERR_OK
      : SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int
network_ssl_servername_callback (SSL *ssl, int *al, void *srv)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
  #ifdef HAVE_ALPN
  #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    /*(do not repeat if acme-tls/1 creds have been set
     * and still in handshake (hctx->alpn not unset yet))*/
    if (hctx->alpn == MOD_OPENSSL_ALPN_ACME_TLS_1)
        return SSL_TLSEXT_ERR_OK; /*(wolfSSL might call twice in client hello)*/
  #endif
  #endif
    if (hctx->r->conditional_is_valid & (1 << COMP_HTTP_HOST))/*(already done)*/
        return SSL_TLSEXT_ERR_OK; /*(wolfSSL might call twice in client hello)*/
    buffer_copy_string_len(&hctx->r->uri.scheme, CONST_STR_LEN("https"));
    UNUSED(al);
    UNUSED(srv);

    const char *servername;
    size_t len = (size_t)
    #ifdef HAVE_SNI
      wolfSSL_SNI_GetRequest(ssl, WOLFSSL_SNI_HOST_NAME, (void **)&servername);
    #else
      0;
    #endif
    if (0 == len)
        return SSL_TLSEXT_ERR_NOACK; /* client did not provide SNI */
  #if 0  /* WolfSSL does not provide per-session SSL_set_read_ahead() */
    int read_ahead = hctx->conf.ssl_read_ahead;
    int rc = mod_openssl_SNI(hctx, servername, len);
    if (!read_ahead && hctx->conf.ssl_read_ahead)
        SSL_set_read_ahead(ssl, hctx->conf.ssl_read_ahead);
    return rc;
  #else
    return mod_openssl_SNI(hctx, servername, len);
  #endif
}

#endif /* HAVE_TLS_EXTENSIONS */


#ifdef HAVE_OCSP

#define OCSP_RESPONSE             OcspResponse
#define OCSP_RESPONSE_free        wolfSSL_OCSP_RESPONSE_free
#define d2i_OCSP_RESPONSE_bio     wolfSSL_d2i_OCSP_RESPONSE_bio
#define d2i_OCSP_RESPONSE         wolfSSL_d2i_OCSP_RESPONSE
#define i2d_OCSP_RESPONSE         wolfSSL_i2d_OCSP_RESPONSE
#define OCSP_response_get1_basic  wolfSSL_OCSP_response_get1_basic
#define OCSP_single_get0_status   wolfSSL_OCSP_single_get0_status
#define OCSP_resp_get0            wolfSSL_OCSP_resp_get0
#define OCSP_BASICRESP            WOLFSSL_OCSP_BASICRESP
#define OCSP_BASICRESP_free       wolfSSL_OCSP_BASICRESP_free

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

    if (NULL == b)
        b = buffer_init();
    else if (b->ptr)
        free(b->ptr);
    b->ptr  = data;
    b->used = (uint32_t)dlen;
    b->size = (uint32_t)dlen+1;
    return b;
}


static unix_time64_t
mod_openssl_asn1_time_to_posix (const ASN1_TIME *asn1time)
{
  #if LIBWOLFSSL_VERSION_HEX >= 0x05000000 /*(stub func filled in v5.0.0)*/
    /* Note: up to at least wolfSSL 4.5.0 (current version as this is written)
     * wolfSSL_ASN1_TIME_diff() is a stub function which always returns 0 */
    /* prefer wolfSSL_ASN1_TIME_to_tm() instead of wolfSSL_ASN1_TIME_diff() */
    struct tm x;
    if (!wolfSSL_ASN1_TIME_to_tm(asn1time, &x))
        return -1;
    time_t t = timegm(&x);
    return (t != -1) ? TIME64_CAST(t) : t;
  #else
    UNUSED(asn1time);
    return -1;
  #endif
}


static unix_time64_t
mod_openssl_ocsp_next_update (plugin_cert *pc)
{
  #if LIBWOLFSSL_VERSION_HEX < 0x05000000
    UNUSED(pc);
    (void)mod_openssl_asn1_time_to_posix(NULL);
    return -1; /*(not implemented)*/
  #else
    buffer *der = pc->ssl_stapling;
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
   #if LIBWOLFSSL_VERSION_HEX < 0x04006000
    /* WolfSSL does not provide OCSP_resp_get0() OCSP_single_get0_status() */
    /* (inactive code path; alternative path followed in #if above for WolfSSL)
     * (chain not currently available in mod_openssl when used with WolfSSL)
     * (For WolfSSL, pc->ssl_pemfile_chain might not be filled in with actual
     *  chain, but is used to store (buffer **) of DER decoded from PEM certs
     *  read from ssl.pemfile, which may be a single cert, pc->ssl_pemfile_x509.
     *  The chain is not calculated or filled in if single cert, and neither are
     *  (X509 *), though (X509 *) could be temporarily created to calculated
     *  (OCSP_CERTID *), which additionally could be calculated once at startup)
     */
    OCSP_CERTID *id = (NULL != pc->ssl_pemfile_chain)
      ? OCSP_cert_to_id(NULL, pc->ssl_pemfile_x509,
                        sk_X509_value(pc->ssl_pemfile_chain, 0))
      : NULL;
    if (id == NULL) {
        OCSP_BASICRESP_free(bs);
        OCSP_RESPONSE_free(ocsp);
        return -1;
    }
    OCSP_resp_find_status(bs, id, NULL, NULL, NULL, NULL, &nextupd);
    OCSP_CERTID_free(id);
   #else
    OCSP_single_get0_status(OCSP_resp_get0(bs, 0), NULL, NULL, NULL, &nextupd);
   #endif
    unix_time64_t t = nextupd ? mod_openssl_asn1_time_to_posix(nextupd) : -1;

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
    if (NULL == pc->ssl_stapling) /*(previously discarded or never loaded)*/
        return;

    /* discard expired OCSP stapling response */
    buffer_free(pc->ssl_stapling);
    pc->ssl_stapling = NULL;
    if (pc->must_staple)
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate marked OCSP Must-Staple, "
                  "but OCSP response expired from ssl.stapling-file %s",
                  pc->ssl_stapling_file->ptr);
}


static int
mod_openssl_reload_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    buffer *b = mod_openssl_load_stapling_file(pc->ssl_stapling_file->ptr,
                                               srv->errh, pc->ssl_stapling);
    if (!b) return 0;

    pc->ssl_stapling = b; /*(unchanged unless orig was NULL)*/
    pc->ssl_stapling_loadts = cur_ts;
    pc->ssl_stapling_nextts = mod_openssl_ocsp_next_update(pc);
    if (pc->ssl_stapling_nextts == -1) {
        /* "Next Update" might not be provided by OCSP responder
         * Use 3600 sec (1 hour) in that case. */
        /* retry in 1 hour if unable to determine Next Update */
        pc->ssl_stapling_nextts = cur_ts + 3600;
        pc->ssl_stapling_loadts = 0;
    }
    else if (pc->ssl_stapling_nextts < cur_ts) {
        mod_openssl_expire_stapling_file(srv, pc);
        return 0;
    }

    return 1;
}


static int
mod_openssl_refresh_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    if (pc->ssl_stapling && pc->ssl_stapling_nextts > cur_ts + 256)
        return 1; /* skip check for refresh unless close to expire */
    struct stat st;
    if (0 != stat(pc->ssl_stapling_file->ptr, &st)
        || TIME64_CAST(st.st_mtime) <= pc->ssl_stapling_loadts) {
        if (pc->ssl_stapling && pc->ssl_stapling_nextts < cur_ts)
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
mod_openssl_crt_must_staple (const WOLFSSL_X509 *crt)
{
  #if LIBWOLFSSL_VERSION_HEX < 0x05000000 /*(stub func filled in v5.0.0)*/
    /* wolfSSL_ASN1_INTEGER_get() is a stub func < v5.0.0; always returns 0 */
    UNUSED(crt);
    return 0;
  #else
    STACK_OF(ASN1_OBJECT) * const tlsf = (STACK_OF(ASN1_OBJECT)*)
      wolfSSL_X509_get_ext_d2i(crt, NID_tlsfeature, NULL, NULL);
    if (NULL == tlsf) return 0;

    int rc = 0;

    /* wolfSSL_sk_ASN1_INTEGER_num() not implemented */
    /* wolfSSL_sk_ASN1_INTEGER_value() not implemented */
    /* wolfSSL_sk_ASN1_INTEGER_pop_free() not implemented */
    #define wolfSSL_sk_ASN1_INTEGER_num(sk) wolfSSL_sk_num(sk)
    #define wolfSSL_sk_ASN1_INTEGER_value(sk, i) wolfSSL_sk_value(sk, i)
    #define wolfSSL_sk_ASN1_INTEGER_pop_free(sk, fn) wolfSSL_sk_pop_free(sk, fn)

    for (int i = 0; i < wolfSSL_sk_ASN1_INTEGER_num(tlsf); ++i) {
        WOLFSSL_ASN1_INTEGER *ai = wolfSSL_sk_ASN1_INTEGER_value(tlsf, i);
        long tlsextid = wolfSSL_ASN1_INTEGER_get(ai);
        if (tlsextid == 5) { /* 5 = OCSP Must-Staple */
            rc = 1;
            break;
        }
    }

    wolfSSL_sk_ASN1_INTEGER_pop_free(tlsf, (wolfSSL_sk_freefunc)
                                           wolfSSL_ASN1_INTEGER_free);
    return rc; /* 1 if OCSP Must-Staple found; 0 if not */
  #endif
}

#endif /* HAVE_OCSP */


static plugin_cert *
network_openssl_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey, const buffer *ssl_stapling_file)
{
    if (!mod_openssl_init_once_openssl(srv)) return NULL;

    buffer **ssl_pemfile_chain = NULL;
    buffer *ssl_pemfile_x509 =
      mod_wolfssl_load_pem_file(pemfile->ptr, srv->errh, &ssl_pemfile_chain);
    if (NULL == ssl_pemfile_x509) {
      #if defined(__clang_analyzer__) || defined(__COVERITY__)
        mod_wolfssl_free_der_certs(ssl_pemfile_chain); /*unnecessary*/
      #endif
        return NULL;
    }

    buffer *ssl_pemfile_pkey =
      mod_wolfssl_evp_pkey_load_pem_file(privkey->ptr, srv->errh);
    if (NULL == ssl_pemfile_pkey) {
        /*buffer_free(ssl_pemfile_x509);*//*(part of chain)*/
        mod_wolfssl_free_der_certs(ssl_pemfile_chain);
        return NULL;
    }

    /* wolfSSL_X509_check_private_key() is a stub func (not implemented) in
     * WolfSSL prior to v4.6.0, and still no-op #ifdef NO_CHECK_PRIVATE_KEY */

    plugin_cert *pc = ck_malloc(sizeof(plugin_cert));
    pc->ssl_pemfile_pkey = ssl_pemfile_pkey;
    pc->ssl_pemfile_x509 = ssl_pemfile_x509;
    pc->ssl_pemfile_chain= ssl_pemfile_chain;
    pc->ssl_pemfile = pemfile;
    pc->ssl_privkey = privkey;
    pc->ssl_stapling     = NULL;
    pc->ssl_stapling_file= ssl_stapling_file;
    pc->ssl_stapling_loadts = 0;
    pc->ssl_stapling_nextts = 0;
  #ifdef HAVE_OCSP
    WOLFSSL_X509 *crt =
      wolfSSL_X509_load_certificate_buffer((const unsigned char *)
                                             ssl_pemfile_x509->ptr,
                                           (int)buffer_clen(ssl_pemfile_x509),
                                           WOLFSSL_FILETYPE_ASN1);
    pc->must_staple = mod_openssl_crt_must_staple(crt);
    wolfSSL_X509_free(crt);
  #else
    pc->must_staple = 0;
  #endif

    if (pc->ssl_stapling_file) {
      #ifdef HAVE_OCSP
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

  #if 0
  #if LIBWOLFSSL_VERSION_HEX >= 0x05000000 /*(stub func filled in v5.0.0)*/
    pc->notAfter = /*(see mod_wolfssl_cert_is_active to get X509 crt from buf)*/
      mod_openssl_asn1_time_to_posix(wolfSSL_X509_get_notAfter(crt));
  #endif
  #endif

    return pc;
}


#ifdef HAVE_TLS_EXTENSIONS

#ifdef HAVE_ALPN
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
mod_openssl_acme_tls_1 (SSL *ssl, handler_ctx *hctx)
{
    buffer * const b = hctx->tmp_buf;
    const buffer * const name = &hctx->r->uri.authority;
    log_error_st * const errh = hctx->r->conf.errh;
    buffer *ssl_pemfile_x509 = NULL;
    buffer *ssl_pemfile_pkey = NULL;
    buffer **ssl_pemfile_chain = NULL;
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
    buffer_copy_path_len2(b, BUF_PTR_LEN(hctx->conf.ssl_acme_tls_1),
                             BUF_PTR_LEN(name));
    len = buffer_clen(b);

    do {
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
        ssl_pemfile_x509 =
          mod_wolfssl_load_pem_file(b->ptr, errh, &ssl_pemfile_chain);
        if (NULL == ssl_pemfile_x509) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        buffer_truncate(b, len); /*(remove ".crt.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        ssl_pemfile_pkey = mod_wolfssl_evp_pkey_load_pem_file(b->ptr, errh);
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
        buffer *cert = ssl_pemfile_x509;
        if (1 != wolfSSL_use_certificate_ASN1(ssl, (unsigned char *)cert->ptr,
                                              (int)buffer_clen(cert))){
            log_error(errh, __FILE__, __LINE__,
              "SSL: failed to set acme-tls/1 certificate for TLS server "
              "name %s: %s", name->ptr, ERR_error_string(ERR_get_error(),NULL));
            break;
        }

        if (ssl_pemfile_chain) {
            /* WolfSSL limitation */
            /* WolfSSL does not support setting per-session chain;
             * limitation is to per-CTX chain, and so chain is not provided for
             * "acme-tls/1" (might be non-issue; chain might not be present) */
        }

        buffer *pkey = ssl_pemfile_pkey;
        if (1 != wolfSSL_use_PrivateKey_buffer(ssl, (unsigned char *)pkey->ptr,
                                               (int)buffer_clen(pkey),
                                               WOLFSSL_FILETYPE_ASN1)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: failed to set acme-tls/1 private key for TLS server "
              "name %s: %s", name->ptr, ERR_error_string(ERR_get_error(),NULL));
            break;
        }

        hctx->conf.ssl_verifyclient_enforce = 0;
        wolfSSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        rc = SSL_TLSEXT_ERR_OK;
    } while (0);

    if (ssl_pemfile_pkey) {
        wolfSSL_OPENSSL_cleanse(b->ptr, b->size);
        buffer_free(ssl_pemfile_pkey);
    }
    /*if (ssl_pemfile_x509) buffer_free(ssl_pemfile_x509);*//*(part of chain)*/
    mod_wolfssl_free_der_certs(ssl_pemfile_chain);

    return rc;
}

static int
mod_openssl_alpn_h2_policy (handler_ctx * const hctx)
{
    /*(currently called after handshake has completed)*/
  #if 0 /* SNI omitted by client when connecting to IP instead of to name */
    if (buffer_is_blank(&hctx->r->uri.authority)) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: error ALPN h2 without SNI");
        return -1;
    }
  #endif
    if (wolfSSL_version(hctx->ssl) < TLS1_2_VERSION) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: error ALPN h2 requires TLSv1.2 or later");
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

    return SSL_TLSEXT_ERR_NOACK;
}

#endif /* TLSEXT_TYPE_application_layer_protocol_negotiation */
#endif /* HAVE_ALPN */

#endif /* HAVE_TLS_EXTENSIONS */


static int
mod_openssl_ssl_conf_cmd (server *srv, plugin_config_socket *s);


#ifndef NO_DH
#include <wolfssl/openssl/dh.h>
/* wolfSSL provides wolfSSL_DH_set0_pqg() for
 * Apache w/ OPENSSL_VERSION_NUMBER >= 0x10100000L
 * but does not provide most other openssl 1.1.0+ interfaces
 * and get_dh2048() might not be necessary if wolfSSL defines
 * HAVE_TLS_EXTENSIONS HAVE_DH_DEFAULT_PARAMS HAVE_FFDHE HAVE_SUPPORTED_CURVES*/
#ifndef DH_set0_pqg /*(added in wolfssl v5.0.0)*/
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
#endif


static int
mod_openssl_ssl_conf_dhparameters(server *srv, plugin_config_socket *s, const buffer *dhparameters)
{
  #ifndef NO_DH
    DH *dh;
    /* Support for Diffie-Hellman key exchange */
    if (dhparameters) {
        const char *fn = dhparameters->ptr;
        off_t dlen = 1*1024*1024;/*(arbitrary limit: 1 MB; expect < 1 KB)*/
        char *data = fdevent_load_file(fn, &dlen, srv->errh, malloc, free);
        int rc = (NULL != data) ? 0 : -1;
        if (0 == rc)
            wolfSSL_CTX_SetTmpDH_buffer(s->ssl_ctx, (unsigned char *)data,
                                        (long)dlen, WOLFSSL_FILETYPE_PEM);
        if (dlen) ck_memzero(data, dlen);
        free(data);
        if (rc < 0) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unable to read DH params from file %s",
              dhparameters->ptr);
            return 0;
        }
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
    SSL_CTX_set_options(s->ssl_ctx, SSL_OP_SINGLE_DH_USE);
  #else
    if (dhparameters) {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: wolfssl compiled without DH support, "
          "can't load parameters from %s", dhparameters->ptr);
    }
  #endif

    return 1;
}


static int
mod_openssl_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *ssl_ec_curve)
{
    /* Support for Elliptic-Curve Diffie-Hellman key exchange */
    /* OpenSSL only supports the "named curves" from RFC 4492, section 5.1.1. */
    const char *curve = ssl_ec_curve ? ssl_ec_curve->ptr : "prime256v1";
    int nid = wolfSSL_OBJ_sn2nid(curve);
    if (nid) {
        EC_KEY * const ecdh = EC_KEY_new_by_curve_name(nid);
        if (ecdh == NULL) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Unable to create curve %s", curve);
            return 0;
        }
        wolfSSL_SSL_CTX_set_tmp_ecdh(s->ssl_ctx, ecdh);
        SSL_CTX_set_options(s->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
        EC_KEY_free(ecdh);
        return 1;
    }
    else {
        log_error(srv->errh, __FILE__, __LINE__,
          "SSL: Unknown curve name %s", curve);
        return 0;
    }
}


static int
network_init_ssl (server *srv, plugin_config_socket *s, plugin_data *p)
{
    /* load SSL certificates */

      #ifndef SSL_OP_NO_COMPRESSION
      #define SSL_OP_NO_COMPRESSION 0
      #endif
        long ssloptions = SSL_OP_ALL
                        | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                        | SSL_OP_NO_COMPRESSION;

      #if LIBWOLFSSL_VERSION_HEX >= 0x04002000
        s->ssl_ctx = SSL_CTX_new(TLS_server_method());
      #else
        s->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
      #endif
        if (NULL == s->ssl_ctx) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

      #ifdef SSL_OP_NO_RENEGOTIATION /* openssl 1.1.0 */
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

      #if !defined(NO_SESSION_CACHE)
        const int disable_sess_cache =
          !config_feature_bool(srv, "ssl.session-cache", 0);
        if (disable_sess_cache)
            /* disable session cache; session tickets are preferred */
            SSL_CTX_set_session_cache_mode(s->ssl_ctx,
                                             SSL_SESS_CACHE_OFF
                                           | SSL_SESS_CACHE_NO_AUTO_CLEAR
                                           | SSL_SESS_CACHE_NO_INTERNAL);
      #endif

        SSL_CTX_set_options(s->ssl_ctx, ssloptions);
        SSL_CTX_set_info_callback(s->ssl_ctx, ssl_info_callback);

        /*(wolfSSL does not support SSLv2)*/

        if (0 != SSL_OP_NO_SSLv3) {
            /* disable SSLv3 */
            if ((SSL_OP_NO_SSLv3
                 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv3))
                != SSL_OP_NO_SSLv3) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }

        if (s->ssl_cipher_list) {
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

        if (!mod_openssl_ssl_conf_dhparameters(srv, s, NULL))
            return -1;

      #ifdef HAVE_SESSION_TICKET
        wolfSSL_CTX_set_tlsext_ticket_key_cb(s->ssl_ctx, ssl_tlsext_ticket_key_cb);
      #endif

      #ifdef HAVE_OCSP
        wolfSSL_CTX_set_tlsext_status_cb(s->ssl_ctx, ssl_tlsext_status_cb);
      #endif

        /* load all ssl.ca-files specified in the config into each SSL_CTX
         * XXX: This might be a bit excessive, but are all trusted CAs
         *      TODO: prefer to load on-demand in mod_openssl_cert_cb()
         *            for openssl >= 1.0.2 */
        if (!mod_wolfssl_load_ca_files(s->ssl_ctx, p, srv))
            return -1;

        if (s->ssl_verifyclient) {
            if (NULL == s->ssl_ca_file) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: You specified ssl.verifyclient.activate "
                  "but no ssl.verifyclient.ca-file");
                return -1;
            }
          #ifndef OPENSSL_ALL
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: You specified ssl.verifyclient.activate "
                  "but wolfssl library built without necessary support");
                return -1;
          #else
            /* Before wolfssl 4.6.0, wolfSSL_dup_CA_list() is a stub function
             * which returns NULL, so DN names in cert request are not set here.
             * (A patch has been submitted to WolfSSL add is part of 4.6.0)
             * https://github.com/wolfSSL/wolfssl/pull/3098 */
            STACK_OF(X509_NAME) * const cert_names = s->ssl_ca_dn_file
              ? s->ssl_ca_dn_file
              : s->ssl_ca_file->names;
            wolfSSL_CTX_set_client_CA_list(s->ssl_ctx,
                                           wolfSSL_dup_CA_list(cert_names));
            int mode = SSL_VERIFY_PEER;
            if (s->ssl_verifyclient_enforce) {
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            wolfSSL_CTX_set_verify(s->ssl_ctx, mode, verify_callback);
            wolfSSL_CTX_set_verify_depth(s->ssl_ctx,
                                         s->ssl_verifyclient_depth + 1);
          #endif
            if (s->ssl_ca_crl_file) {
                if (!mod_wolfssl_load_cacrls(s->ssl_ctx,s->ssl_ca_crl_file,srv))
                    return -1;
            }
        }

        if (1 != mod_wolfssl_CTX_use_certificate_chain_file(
                   s->ssl_ctx, s->pc->ssl_pemfile->ptr, srv->errh))
            return -1;

        buffer *k = s->pc->ssl_pemfile_pkey;
        if (1 != wolfSSL_CTX_use_PrivateKey_buffer(s->ssl_ctx,
                                                   (unsigned char *)k->ptr,
                                                   (int)buffer_clen(k),
                                                   WOLFSSL_FILETYPE_ASN1)) {
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

        SSL_CTX_set_default_read_ahead(s->ssl_ctx, s->ssl_read_ahead);
        wolfSSL_CTX_set_mode(s->ssl_ctx,
                             SSL_MODE_ENABLE_PARTIAL_WRITE);
        wolfSSL_CTX_set_mode(s->ssl_ctx, /*(wolfSSL default mode)*/
                             WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
      #ifdef wolfSSL_SSL_MODE_RELEASE_BUFFERS
        wolfSSL_CTX_set_mode(s->ssl_ctx, /*(not currently implemented)*/
                             wolfSSL_SSL_MODE_RELEASE_BUFFERS);
      #endif

      #ifdef HAVE_TLS_EXTENSIONS
        /*(wolfSSL preprocessor defines are obnoxious)*/
        /*(code should be HAVE_SNI, but is hidden by OPENSSL_ALL
         * even though the comment in wolfssl code on the #endif
         * says (OPENSSL_ALL
         *       || (OPENSSL_EXTRA
         *           && (HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_LIGHTY)))
         * and sniRecvCb sniRecvCbArg are hidden by *different* set of defines
         * in wolfssl/internal.h)
         * Note: wolfSSL SNI callbacks members not present unless wolfSSL is
         * built OPENSSL_ALL or some additional combination of preprocessor
         * defines.  The following should work with more recent wolfSSL versions
         * (and HAVE_LIGHTY is not sufficient in wolfssl <= 4.5.0) */
       #if defined(OPENSSL_ALL) \
        || (defined(OPENSSL_EXTRA) \
            && (defined(HAVE_STUNNEL) \
                || defined(WOLFSSL_NGINX) \
                || defined(WOLFSSL_HAPROXY)))
       #else
       #undef HAVE_SNI
       #endif
       #ifdef HAVE_SNI
        wolfSSL_CTX_set_servername_callback(
            s->ssl_ctx, network_ssl_servername_callback);
        wolfSSL_CTX_set_servername_arg(s->ssl_ctx, srv);
       #else
        log_warn(srv->errh, __FILE__, __LINE__,
          "SSL: WARNING: SNI callbacks *crippled* in wolfSSL library build");
        UNUSED(network_ssl_servername_callback);
       #endif

       #ifdef HAVE_ALPN
       #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
        SSL_CTX_set_alpn_select_cb(s->ssl_ctx,mod_openssl_alpn_select_cb,NULL);
       #endif
       #endif
      #endif

        if (wolfSSL_CTX_SetMinVersion(s->ssl_ctx, WOLFSSL_TLSV1_2)
               != WOLFSSL_SUCCESS)
            return -1;

        if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
            if (0 != mod_openssl_ssl_conf_cmd(srv, s)) return -1;
        }

        return 0;
}


/* expanded from:
 * $ openssl ciphers 'EECDH+AESGCM:CHACHA20:!PSK:!DHE'
 */
#define LIGHTTPD_DEFAULT_CIPHER_LIST \
"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"


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
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };
    static const buffer default_ssl_cipher_list =
      { CONST_STR_LEN(LIGHTTPD_DEFAULT_CIPHER_LIST), 0 };

    p->ssl_ctxs = ck_calloc(srv->config_context->used, sizeof(plugin_ssl_ctx));

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
                    if (!buffer_is_blank(cpv->v.b))
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
                    || (conf.ssl_enabled && NULL == p->ssl_ctxs[0].ssl_ctx)) {
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

  #ifdef HAVE_SESSION_TICKET
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
                cpv->v.v = mod_wolfssl_load_cacerts(ssl_ca_file, srv->errh);
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
              case 16:/* ssl.verifyclient.ca-dn-file */
                cpv->k_id = 3;
                __attribute_fallthrough__
              case 3: /* ssl.ca-dn-file */
                if (buffer_is_blank(cpv->v.b)) break;
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                ssl_ca_dn_file = cpv->v.b;
               #ifndef OPENSSL_ALL
                {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "SSL: You specified %s but wolfssl library built without "
                      "necessary support", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
               #endif
                cpv->v.v = mod_wolfssl_load_client_CA_file(ssl_ca_dn_file,
                                                           srv->errh);
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
              default:/* should not happen */
                break;
            }
        }

        /* p->cafiles for legacy only */
        /* load all ssl.ca-files into a single chain */
        /*(certificate load order might matter)*/
        if (ssl_ca_dn_file)
            array_insert_value(p->cafiles, BUF_PTR_LEN(ssl_ca_dn_file));
        if (ssl_ca_file)
            array_insert_value(p->cafiles, BUF_PTR_LEN(ssl_ca_file));
        UNUSED(ca_store);
        UNUSED(ssl_ca_crl_file);
        UNUSED(default_ssl_ca_crl_file);

        if (pemfile) {
          #ifndef HAVE_TLS_EXTENSIONS
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

    return mod_openssl_set_defaults_sockets(srv, p);
}


__attribute_cold__
static int
mod_wolfssl_write_err (SSL * const ssl, int wr, connection * const con,
                       log_error_st * const errh)
{
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
                log_error(errh, __FILE__, __LINE__,
                  "SSL: %d %d %s",ssl_r,wr,ERR_error_string(err,NULL));
            } while((err = ERR_get_error()));
        }
        else if (wr == -1) {
            /* no, but we have errno */
            switch(errno) {
              case EAGAIN:
              case EINTR:
             #if defined(__FreeBSD__) && defined(SF_NODISKIO)
              case EBUSY:
             #endif
                return 0; /* try again later */
              case EPIPE:
              case ECONNRESET:
                return -2;
              default:
                log_perror(errh, __FILE__, __LINE__,
                  "SSL: %d %d", ssl_r, wr);
                break;
            }
        }
        else {
            /* neither error-queue nor errno ? */
            log_perror(errh, __FILE__, __LINE__,
              "SSL (error): %d %d", ssl_r, wr);
        }
        break;

      case SSL_ERROR_ZERO_RETURN:
        /* clean shutdown on the remote side */
        if (wr == 0) return -2;

        __attribute_fallthrough__
      default:
        while((err = ERR_get_error()))
            log_error(errh, __FILE__, __LINE__,
              "SSL: %d %d %s", ssl_r, wr, ERR_error_string(err, NULL));
        break;
    }

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
    handler_ctx * const hctx = con->plugin_ctx[plugin_data_singleton->id];
    SSL * const ssl = hctx->ssl;
    log_error_st * const errh = hctx->errh;

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_openssl_close_notify(hctx);

    while (max_bytes > 0 && !chunkqueue_is_empty(cq)) {
        char *data = local_send_buffer;
        uint32_t data_len = LOCAL_SEND_BUFSIZE < max_bytes
          ? LOCAL_SEND_BUFSIZE
          : (uint32_t)max_bytes;
        int wr;

        if (0 != chunkqueue_peek_data(cq, &data, &data_len, errh, 1)) return -1;
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
        wr = SSL_write(ssl, data, data_len);

        if (__builtin_expect( (hctx->renegotiations > 1), 0)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }

        if (wr <= 0)
            return mod_wolfssl_write_err(ssl, wr, con, errh);

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
    handler_ctx * const hctx = con->plugin_ctx[plugin_data_singleton->id];
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
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }

      #ifdef HAVE_ALPN
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
      #endif
    } while (len > 0
             && (hctx->conf.ssl_read_ahead || SSL_pending(hctx->ssl) > 0));

    if (len < 0) {
        int oerrno = errno;
        int rc, ssl_err;
        switch ((rc = SSL_get_error(hctx->ssl, len))) {
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
            while((ssl_err = ERR_get_error())) {
                /* get all errors from the error-queue */
                log_error(hctx->errh, __FILE__, __LINE__,
                  "SSL: %d %s", rc, ERR_error_string(ssl_err, NULL));
            }

            switch(oerrno) {
            case ECONNRESET:
                if (!hctx->conf.ssl_log_noise) break;
                __attribute_fallthrough__
            default:
                /* (oerrno should be something like ECONNABORTED not 0
                 *  if client disconnected before anything was sent
                 *  (e.g. TCP connection probe), but it does not appear
                 *  that openssl provides such notification, not even
                 *  something like SSL_R_SSL_HANDSHAKE_FAILURE) */
                if (0==oerrno && 0==cq->bytes_in && !hctx->conf.ssl_log_noise)
                    break;

                errno = oerrno; /*(for log_perror())*/
                log_perror(hctx->errh, __FILE__, __LINE__,
                  "SSL: %d %d %d", len, rc, oerrno);
                break;
            }

            break;
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
                log_error(hctx->errh, __FILE__, __LINE__,
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
    const server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    plugin_data *p = p_d;
    handler_ctx * const hctx = handler_ctx_init();
    request_st * const r = &con->request;
    hctx->r = r;
    hctx->con = con;
    hctx->tmp_buf = con->srv->tmp_buf;
    hctx->errh = r->conf.errh;
    con->plugin_ctx[p->id] = hctx;
    buffer_blank(&r->uri.authority);

    plugin_ssl_ctx *s = p->ssl_ctxs + srv_sock->sidx;
    if (NULL == s->ssl_ctx) s = p->ssl_ctxs; /*(inherit from global scope)*/
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
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
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

            __attribute_fallthrough__
        default:

            if (!SSL_is_init_finished(hctx->ssl)) {
                mod_openssl_detach(hctx);
                return -2;
            }

            switch ((ssl_r = SSL_get_error(hctx->ssl, ret))) {
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_ZERO_RETURN: /*(unexpected here)*/
                hctx->close_notify = -1;
                return 0; /* try again later */
            case SSL_ERROR_SYSCALL:
                if (0 == ERR_peek_error()) {
                    switch(errno) {
                    case 0: /*ssl bug (see lighttpd ticket #2213)*/
                    case EPIPE:
                    case ECONNRESET:
                        mod_openssl_detach(hctx);
                        return -2;
                    default:
                        log_perror(hctx->r->conf.errh, __FILE__, __LINE__,
                          "SSL (error): %d %d", ssl_r, ret);
                        break;
                    }
                    break;
                }
                __attribute_fallthrough__
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
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL != hctx) {
        con->plugin_ctx[p->id] = NULL;
        handler_ctx_free(hctx);
    }

    return HANDLER_GO_ON;
}


#ifndef OBJ_nid2sn
#define OBJ_nid2sn  wolfSSL_OBJ_nid2sn
#endif
#ifndef OBJ_obj2nid
#define OBJ_obj2nid wolfSSL_OBJ_obj2nid
#endif
#include <wolfssl/wolfcrypt/asn_public.h>


static void
https_add_ssl_client_subject (request_st * const r, X509_NAME *xn)
{
    const size_t prelen = sizeof("SSL_CLIENT_S_DN_")-1;
    char key[64] = "SSL_CLIENT_S_DN_";
    for (int i = 0, nentries = X509_NAME_entry_count(xn); i < nentries; ++i) {
        int xobjnid;
        const char * xobjsn;
        X509_NAME_ENTRY *xe;

        if (!(xe = wolfSSL_X509_NAME_get_entry(xn, i))) {
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
    } else if (!(xs = SSL_get_peer_certificate(hctx->ssl))) {
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
        byte buf[64];
        int bsz = (int)sizeof(buf);
        if (wolfSSL_X509_get_serial_number(xs, buf, &bsz) == WOLFSSL_SUCCESS) {
            buffer_append_string_encoded_hex_uc(
              http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_M_SERIAL")),
              (char *)buf, (size_t)bsz);
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
        int dersz, pemsz;
        const unsigned char *der = wolfSSL_X509_get_der(xs, &dersz);
        pemsz = der ? wc_DerToPemEx(der, dersz, NULL, 0, NULL, CERT_TYPE) : 0;
        if (pemsz > 0) {
            vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_CERT"));
            if (0 == wc_DerToPemEx(der, dersz,
                                   (byte *)buffer_string_prepare_copy(vb,pemsz),
                                   pemsz, NULL, CERT_TYPE))
                buffer_commit(vb, (uint32_t)pemsz);
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
        s = SSL_CIPHER_get_name(cipher);
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER"), s, strlen(s));
        /*(wolfSSL preprocessor defines are obnoxious)*/
      #if defined(OPENSSL_ALL) \
       || (defined(OPENSSL_EXTRA) \
           && (defined(HAVE_STUNNEL)    || \
               defined(WOLFSSL_NGINX)   || defined(HAVE_LIGHTY) || \
               defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_OPENSSH)))
        int usekeysize, algkeysize = 0;
        char buf[LI_ITOSTRING_LENGTH];
        usekeysize = wolfSSL_CIPHER_get_bits(cipher, &algkeysize);
        if (0 == algkeysize) algkeysize = usekeysize;
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, li_itostrn(buf, sizeof(buf), usekeysize));
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                            buf, li_itostrn(buf, sizeof(buf), algkeysize));
      #endif
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


TRIGGER_FUNC(mod_openssl_handle_trigger) {
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/
    UNUSED(srv);
    UNUSED(p);

  #ifdef HAVE_SESSION_TICKET
    mod_openssl_session_ticket_key_check(p, cur_ts);
  #endif

  #ifdef HAVE_OCSP
    mod_openssl_refresh_stapling_files(srv, p, cur_ts);
  #endif

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_wolfssl_plugin_init (plugin *p);
int mod_wolfssl_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "wolfssl";
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
    if (NULL == b) /* default: min TLSv1.2, max TLSv1.3 */
        return max ? WOLFSSL_TLSV1_3 : WOLFSSL_TLSV1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        return max ? WOLFSSL_TLSV1_3 : WOLFSSL_TLSV1;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.0")))
        return WOLFSSL_TLSV1;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.1")))
        return WOLFSSL_TLSV1_1;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        return WOLFSSL_TLSV1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        return WOLFSSL_TLSV1_3;
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
    return max ? WOLFSSL_TLSV1_3 : WOLFSSL_TLSV1_2;
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
                      #ifdef HAVE_SESSION_TICKET
                        if (flag)
                            SSL_CTX_clear_options(s->ssl_ctx,
                                                  SSL_OP_NO_TICKET);
                        else
                            SSL_CTX_set_options(s->ssl_ctx,
                                                SSL_OP_NO_TICKET);
                      #endif
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
        if (wolfSSL_CTX_SetMinVersion(s->ssl_ctx, n) != WOLFSSL_SUCCESS)
            rc = -1;
    }

    if (maxb) {
        /* WolfSSL max ver is set at WolfSSL compile-time */
      #if LIBWOLFSSL_VERSION_HEX >= 0x04002000
        /*(could use SSL_OP_NO_* before 4.2.0)*/
        /*(wolfSSL_CTX_set_max_proto_version() 4.6.0 uses different defines)*/
        int n = mod_openssl_ssl_conf_proto_val(srv, maxb, 1);
        switch (n) {
          case WOLFSSL_SSLV3:
            wolfSSL_CTX_set_options(s->ssl_ctx, WOLFSSL_OP_NO_TLSv1);
            __attribute_fallthrough__
          case WOLFSSL_TLSV1:
            wolfSSL_CTX_set_options(s->ssl_ctx, WOLFSSL_OP_NO_TLSv1_1);
            __attribute_fallthrough__
          case WOLFSSL_TLSV1_1:
            wolfSSL_CTX_set_options(s->ssl_ctx, WOLFSSL_OP_NO_TLSv1_2);
            __attribute_fallthrough__
          case WOLFSSL_TLSV1_2:
            wolfSSL_CTX_set_options(s->ssl_ctx, WOLFSSL_OP_NO_TLSv1_3);
            __attribute_fallthrough__
          case WOLFSSL_TLSV1_3:
          default:
            break;
        }
      #endif
    }

    if (cipherstring && !buffer_is_blank(cipherstring)) {
        /* Disable support for low encryption ciphers */
        buffer_append_string_len(cipherstring,
                                 CONST_STR_LEN(":!aNULL:!eNULL:!EXP"));
        if (SSL_CTX_set_cipher_list(s->ssl_ctx, cipherstring->ptr) != 1) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
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
