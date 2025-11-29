/*
 * mod_mbedtls - mbedTLS support for lighttpd
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
/*
 * reference:
 * https://tls.mbed.org/high-level-design
 * https://tls.mbed.org/tech-updates/blog/mbedtls-2.0-defaults-best-practices
 * mbedTLS header files (mbedtls/ssl.h and others) are extremely well-documented
 * https://tls.mbed.org/api/  (generated from mbedTLS headers and code)
 *
 * mbedTLS limitations:
 * - mbedTLS does not currently support OCSP
 *   https://tls.mbed.org/discussions/feature-request/ocsp-stapling
 *   TLS/DTLS: OCSP Stapling support #880
 *   https://github.com/ARMmbed/mbedtls/issues/880
 *   Add support for writing OCSP requests and parsing OCSP responses #1197
 *   https://github.com/ARMmbed/mbedtls/issues/1197
 *
 * future possible enhancements to lighttpd mod_mbedtls:
 * - session cache (though session tickets are implemented)
 *     sample code in mbedtls:programs/ssl/ssl_server2.c
 *     (and do not enable unless server.feature-flags ssl.session-cache enabled)
 *
 * Note: If session tickets are -not- disabled with
 *     ssl.openssl.ssl-conf-cmd = ("Options" => "-SessionTicket")
 *   mbedtls rotates the session ticket key according to 2x timeout set with
 *   mbedtls_ssl_ticket_setup() (currently 43200 s, so 24 hour ticket lifetime)
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
 *   restart lighttpd at least every 12 hours if session tickets are enabled and
 *   multiple lighttpd workers are configured.  Since that is likely disruptive,
 *   if multiple lighttpd workers are configured, ssl.stek-file should be
 *   defined and the file maintained externally.
 */
#include "first.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>      /* vsnprintf() */
#include <string.h>

#include <mbedtls/version.h>
/*(compatibility while waiting for future mbedtls 3.x interfaces)*/
#if MBEDTLS_VERSION_NUMBER < 0x03020000 /* mbedtls 3.02.0 */
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include <mbedtls/psa_util.h>
/*(compatibility while waiting for future mbedtls 4.x interfaces)*/
#if MBEDTLS_VERSION_NUMBER >= 0x04000000 /* mbedtls 4.0.0 */
/* mbedtls_ecp_curve_info mbedtls_ecp_curve_list() */
typedef struct mbedtls_ecp_curve_info {
    mbedtls_ecp_group_id grp_id;    /*!< An internal identifier. */
    uint16_t tls_id;                /*!< The TLS NamedCurve identifier. */
    uint16_t bit_size;              /*!< The curve size in bits. */
    const char *name;               /*!< A human-friendly name. */
} mbedtls_ecp_curve_info;
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_list(void);
#include <mbedtls/pk.h>
typedef enum {
    MBEDTLS_PK_NONE = MBEDTLS_PK_SIGALG_NONE,
    MBEDTLS_PK_RSA = MBEDTLS_PK_SIGALG_RSA_PKCS1V15,
    MBEDTLS_PK_RSASSA_PSS = MBEDTLS_PK_SIGALG_RSA_PSS,
    MBEDTLS_PK_ECDSA = MBEDTLS_PK_SIGALG_ECDSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_OPAQUE,
} mbedtls_pk_type_t;
#endif
#else
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#endif
#include <mbedtls/debug.h>
#if defined(MBEDTLS_DHM_C)
#include <mbedtls/dhm.h>
#endif
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/ssl.h>
#if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
#include <mbedtls/ssl_internal.h> /* struct mbedtls_ssl_transform */
#endif
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform_util.h> /* mbedtls_platform_zeroize() */

#if MBEDTLS_VERSION_NUMBER >= 0x02040000 /* mbedtls 2.04.0 */
#include <mbedtls/net_sockets.h>
#else
#include <mbedtls/net.h>
#endif

#if defined(MBEDTLS_SSL_TICKET_C)
#include <mbedtls/ssl_ticket.h>
#endif

#ifndef MBEDTLS_X509_CRT_PARSE_C
#error "lighttpd requires that mbedtls be built with MBEDTLS_X509_CRT_PARSE_C"
#endif

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(x) x
#endif

#include "base.h"
#include "ck.h"
#include "fdevent.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "plugin.h"

typedef struct mod_mbedtls_x509_crl {
    mbedtls_x509_crl crl;
    int refcnt;
    struct mod_mbedtls_x509_crl *next;
} mod_mbedtls_x509_crl;

typedef struct {
    mod_mbedtls_x509_crl *ca_crl;
    const char *crl_file;
    unix_time64_t crl_loadts;
} plugin_crl;

typedef struct mod_mbedtls_kp {
    mbedtls_pk_context pk; /* parsed private key structure */
    mbedtls_x509_crt crt;  /* parsed public key structure */
    int refcnt;
    int8_t need_chain;
    struct mod_mbedtls_kp *next;
} mod_mbedtls_kp;

typedef struct {
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    mod_mbedtls_kp *kp; /* parsed public/private key structures */
    const buffer *ssl_pemfile;
    const buffer *ssl_privkey;
    unix_time64_t pkey_ts;
} plugin_cert;

typedef struct {
    mbedtls_ssl_config *ssl_ctx;        /* context shared between mbedtls_ssl_CONTEXT structures */
    int *ciphersuites;
    void *curves;
    plugin_cert *pc;
    mod_mbedtls_kp *kp;
    mbedtls_x509_crt *ssl_ca_file;
} plugin_ssl_ctx;

typedef struct {
    mbedtls_ssl_config *ssl_ctx;        /* output from network_init_ssl() */
    int *ciphersuites;                  /* output from network_init_ssl() */
    void *curves;                       /* output from network_init_ssl() */

    /*(used only during startup; not patched)*/
    unsigned char ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned char ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    const buffer *ssl_cipher_list;
    const buffer *ssl_acme_tls_1;
    array *ssl_conf_cmd;

    /*(copied from plugin_data for socket ssl_ctx config)*/
    plugin_cert *pc;
    mbedtls_x509_crt *ssl_ca_file;
    unsigned char ssl_session_ticket;
    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;
} plugin_config_socket; /*(used at startup during configuration)*/

typedef struct {
    /* SNI per host: w/ COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    plugin_cert *pc;
    mbedtls_x509_crt *ssl_ca_file;
    mbedtls_x509_crt *ssl_ca_dn_file;
    plugin_crl *ssl_ca_crl_file;

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
  #if !defined(MBEDTLS_USE_PSA_CRYPTO)
    /* NIST counter-mode deterministic random byte generator */
    mbedtls_ctr_drbg_context ctr_drbg;
    /* entropy collection and state management */
    mbedtls_entropy_context entropy;
  #endif
  #if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_ticket_context ticket_ctx;
    const char *ssl_stek_file;
  #endif
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[mod_mbedtls_plugin_data->id]; */
static plugin_data *mod_mbedtls_plugin_data;
#ifdef MBEDTLS_SSL_OUT_CONTENT_LEN
#define LOCAL_SEND_BUFSIZE MBEDTLS_SSL_OUT_CONTENT_LEN
#else
#define LOCAL_SEND_BUFSIZE MBEDTLS_SSL_MAX_CONTENT_LEN
#endif
static char *local_send_buffer;
static int feature_refresh_certs;
static int feature_refresh_crls;

typedef struct {
    mbedtls_ssl_context ssl;      /* mbedtls request/connection context */
    request_st *r;
    connection *con;
    int8_t close_notify;
    unsigned short alpn;
    int handshake_done;
    size_t pending_write;
    plugin_config conf;
    log_error_st *errh;
    mbedtls_ssl_config *ssl_ctx;
    /*plugin_cert *pc;*/
    mod_mbedtls_kp *kp;
    mod_mbedtls_x509_crl *crl;
} handler_ctx;


__attribute_cold__
static mod_mbedtls_kp *
mod_mbedtls_kp_init (void)
{
    mod_mbedtls_kp * const kp = ck_malloc(sizeof(*kp));
    kp->refcnt = 1;
    kp->need_chain = 0;
    kp->next = NULL;
    mbedtls_pk_init(&kp->pk);   /* init private key context */
    mbedtls_x509_crt_init(&kp->crt); /* init cert structure */
    return kp;
}


__attribute_cold__
static void
mod_mbedtls_kp_free (mod_mbedtls_kp *kp)
{
    mbedtls_pk_free(&kp->pk);
    mbedtls_x509_crt_free(&kp->crt);
    free(kp);
}


static mod_mbedtls_kp *
mod_mbedtls_kp_acq (plugin_cert *pc)
{
    mod_mbedtls_kp *kp = pc->kp;
    ++kp->refcnt;
    return kp;
}


static void
mod_mbedtls_kp_rel (mod_mbedtls_kp *kp)
{
    if (--kp->refcnt < 0)
        mod_mbedtls_kp_free(kp); /* immed free for acme-tls/1 */
}


__attribute_cold__
static mod_mbedtls_x509_crl *
mod_mbedtls_x509_crl_init (void)
{
    mod_mbedtls_x509_crl *ca_crl = ck_malloc(sizeof(*ca_crl));
    ca_crl->refcnt = 1;
    ca_crl->next = NULL;
    mbedtls_x509_crl_init(&ca_crl->crl);
    return ca_crl;
}


__attribute_cold__
static void
mod_mbedtls_x509_crl_free (mod_mbedtls_x509_crl *ca_crl)
{
    mbedtls_x509_crl_free(&ca_crl->crl);
    free(ca_crl);
}


static mod_mbedtls_x509_crl *
mod_mbedtls_x509_crl_acq (plugin_crl *ssl_ca_crl)
{
    mod_mbedtls_x509_crl *ca_crl = ssl_ca_crl->ca_crl;
    if (ca_crl)
        ++ca_crl->refcnt;
    return ca_crl;
}


static void
mod_mbedtls_x509_crl_rel (mod_mbedtls_x509_crl *ca_crl)
{
    --ca_crl->refcnt;
}


static handler_ctx *
handler_ctx_init (void)
{
    return ck_calloc(1, sizeof(handler_ctx));
}


static void
handler_ctx_free (handler_ctx *hctx)
{
    mbedtls_ssl_free(&hctx->ssl);
    if (hctx->kp)
        mod_mbedtls_kp_rel(hctx->kp);
    if (hctx->crl)
        mod_mbedtls_x509_crl_rel(hctx->crl);
    free(hctx);
}


#ifdef MBEDTLS_ERROR_C
__attribute_cold__
static void elog(log_error_st * const errh,
                 const char * const file, const int line,
                 const int rc, const char * const msg)
{
    /* error logging convenience function that decodes mbedtls result codes */
    char buf[256];
    mbedtls_strerror(rc, buf, sizeof(buf));
    log_error(errh, file, line, "MTLS: %s: %s (-0x%04x)", msg, buf, -rc);
}
#else
#define elog(errh, file, line, rc, msg) \
    log_error((errh), (file), (line), "MTLS: %s: (-0x%04x)", (msg), -(rc))
#endif


__attribute_cold__
__attribute_format__((__printf__, 5, 6))
static void elogf(log_error_st * const errh,
                  const char * const file, const int line,
                  const int rc, const char * const fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    elog(errh, file, line, rc, msg);
}


#ifdef MBEDTLS_SSL_SESSION_TICKETS

#define TLSEXT_KEYNAME_LENGTH  16
#define TLSEXT_TICK_KEY_LENGTH 32

/* construct our own session ticket encryption key structure
 * to store keys that are not yet active
 * (mirror from mod_openssl, even though not all bits are used here) */
typedef struct tlsext_ticket_key_st {
    unix_time64_t active_ts; /* tickets not issued w/ key until activation ts*/
    unix_time64_t expire_ts; /* key not valid after expiration timestamp */
    unsigned char tick_key_name[TLSEXT_KEYNAME_LENGTH];
    unsigned char tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    unsigned char tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
} tlsext_ticket_key_t;

static tlsext_ticket_key_t session_ticket_keys[1]; /* temp store until active */
static unix_time64_t stek_rotate_ts;


static int
mod_mbedtls_session_ticket_key_file (const char *fn)
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
        session_ticket_keys[0].active_ts = TIME64_CAST(buf[1]);
        session_ticket_keys[0].expire_ts = TIME64_CAST(buf[2]);
      #ifndef __COVERITY__
        memcpy(&session_ticket_keys[0].tick_key_name, buf+3, 80);
      #else
        memcpy(&session_ticket_keys[0].tick_key_name,
               buf+3, TLSEXT_KEYNAME_LENGTH);
        memcpy(&session_ticket_keys[0].tick_hmac_key,
               buf+7, TLSEXT_TICK_KEY_LENGTH);
        memcpy(&session_ticket_keys[0].tick_aes_key,
               buf+15, TLSEXT_TICK_KEY_LENGTH);
      #endif
        rc = 1;
    }

    mbedtls_platform_zeroize(buf, sizeof(buf));
    return rc;
}


static void
mod_mbedtls_session_ticket_key_check (plugin_data *p, const unix_time64_t cur_ts)
{
    if (NULL == p->ssl_stek_file) return;

    struct stat st;
    if (0 == stat(p->ssl_stek_file, &st)
        && TIME64_CAST(st.st_mtime) > stek_rotate_ts
        && mod_mbedtls_session_ticket_key_file(p->ssl_stek_file)) {
        stek_rotate_ts = cur_ts;
    }

    tlsext_ticket_key_t *stek = session_ticket_keys;
    if (stek->active_ts != 0 && stek->active_ts - 63 <= cur_ts) {
      #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
        int rc = mbedtls_ssl_ticket_rotate(&p->ticket_ctx,
                   stek->tick_key_name, sizeof(stek->tick_key_name),
                   stek->tick_aes_key, sizeof(stek->tick_aes_key),
                   (uint32_t)(stek->expire_ts - stek->active_ts));
        if (0 != rc)
            elog(p->srv->errh, __FILE__,__LINE__, rc,
                 "session ticket encryption key rotation failed");
      #else /*(mbedtls_allow_private_access at top of file for [3.0.0,3.2.0))*/
        /* expect to get newer ssl.stek-file prior to mbedtls detecting
         * expiration and internally generating a new key.  If not, then
         * lifetime may be up to 2x specified lifetime until overwritten
         * by mbedtls, but original key will be overwritten and discarded */
        mbedtls_ssl_ticket_context *ctx = &p->ticket_ctx;
        ctx->ticket_lifetime = stek->expire_ts - stek->active_ts;
        ctx->active = 1 - ctx->active;
        mbedtls_ssl_ticket_key *key = ctx->keys + ctx->active;
        /* set generation_time to cur_ts instead of stek->active_ts
         * since ctx->active was updated */
        key->generation_time = (uint32_t)cur_ts;
        memcpy(key->name, stek->tick_key_name, sizeof(key->name));
        /* With GCM and CCM, same context can encrypt & decrypt */
        int rc = mbedtls_cipher_setkey(&key->ctx, stek->tick_aes_key,
                                       mbedtls_cipher_get_key_bitlen(&key->ctx),
                                       MBEDTLS_ENCRYPT);
        if (0 != rc) { /* expire key immediately if error occurs */
            key->generation_time = cur_ts > (unix_time64_t)ctx->ticket_lifetime
              ? cur_ts - ctx->ticket_lifetime - 1
              : 0;
            ctx->active = 1 - ctx->active;
        }
      #endif
        mbedtls_platform_zeroize(stek, sizeof(tlsext_ticket_key_t));
    }
}

#endif /* MBEDTLS_SSL_SESSION_TICKETS */


INIT_FUNC(mod_mbedtls_init)
{
    return (mod_mbedtls_plugin_data = ck_calloc(1, sizeof(plugin_data)));
}


static int mod_mbedtls_init_once_mbedtls (server *srv)
{
    if (ssl_is_init) return 1;
    ssl_is_init = 1;

  #if !defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_SESSION_TICKETS)
    plugin_data * const p = mod_mbedtls_plugin_data;
  #endif
  #if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: %s: (-0x%04x)", "psa_crypto_init()", ps);
        return 0;
    }
  #else
    mbedtls_ctr_drbg_init(&p->ctr_drbg); /* init empty NSIT random num gen */
    mbedtls_entropy_init(&p->entropy);   /* init empty entropy collection struct
                                               .. could add sources here too */

    int rc =                                      /* init RNG */
      mbedtls_ctr_drbg_seed(&p->ctr_drbg,         /* random number generator */
                            mbedtls_entropy_func, /* default entropy func */
                            &p->entropy,          /* entropy context */
                            NULL, 0);             /* no personalization data */
    if (0 != rc) {
        elog(srv->errh, __FILE__,__LINE__, rc,
             "Init of random number generator failed");
        return 0;
    }
  #endif
  #if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_ticket_init(&p->ticket_ctx);
  #endif

    local_send_buffer = ck_malloc(LOCAL_SEND_BUFSIZE);
    return 1;
}


static void mod_mbedtls_free_mbedtls (void)
{
    if (!ssl_is_init) return;

  #ifdef MBEDTLS_SSL_SESSION_TICKETS
    mbedtls_platform_zeroize(session_ticket_keys, sizeof(session_ticket_keys));
    stek_rotate_ts = 0;
  #endif

  #if !defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_SESSION_TICKETS)
    plugin_data * const p = mod_mbedtls_plugin_data;
  #endif
  #if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_psa_crypto_free();
  #else
    mbedtls_ctr_drbg_free(&p->ctr_drbg);
    mbedtls_entropy_free(&p->entropy);
  #endif
  #if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_ticket_free(&p->ticket_ctx);
  #endif

    free(local_send_buffer);
    ssl_is_init = 0;
}


static void
mod_mbedtls_free_plugin_ssl_ctx (plugin_ssl_ctx * const s)
{
    mbedtls_ssl_config_free(s->ssl_ctx);
    free(s->ciphersuites);
    free(s->curves);
    if (s->kp)
        mod_mbedtls_kp_rel(s->kp);
    free(s);
}


static void
mod_mbedtls_free_config (server *srv, plugin_data * const p)
{
    if (NULL != p->ssl_ctxs) {
        /* free ssl_ctx from $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[i];
            if (s && s != p->ssl_ctxs[0])
                mod_mbedtls_free_plugin_ssl_ctx(s);
        }
        /* free ssl_ctx from global scope */
        if (p->ssl_ctxs[0])
            mod_mbedtls_free_plugin_ssl_ctx(p->ssl_ctxs[0]);
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
                    mod_mbedtls_kp *kp = pc->kp;
                    while (kp) {
                        mod_mbedtls_kp *o = kp;
                        kp = kp->next;
                        mod_mbedtls_kp_free(o);
                    }
                    free(pc);
                }
                break;
              case 2: /* ssl.ca-file */
              case 3: /* ssl.ca-dn-file */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    mbedtls_x509_crt *cacert = cpv->v.v;
                    mbedtls_x509_crt_free(cacert);
                    free(cacert);
                }
                break;
              case 4: /* ssl.ca-crl-file */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_crl *ssl_ca_crl = cpv->v.v;
                    mod_mbedtls_x509_crl *ca_crl = ssl_ca_crl->ca_crl;
                    while (ca_crl) {
                        mod_mbedtls_x509_crl *o = ca_crl;
                        ca_crl = ca_crl->next;
                        mbedtls_x509_crl_free(&o->crl);
                        free(o);
                    }
                    free(ssl_ca_crl);
                }
                break;
              default:
                break;
            }
        }
    }
}


FREE_FUNC(mod_mbedtls_free)
{
    plugin_data *p = p_d;
    if (NULL == p->srv) return;
    mod_mbedtls_free_config(p->srv, p);
    mod_mbedtls_free_mbedtls();
}


static void
mod_mbedtls_merge_config_cpv (plugin_config * const pconf, const config_plugin_value_t * const cpv)
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
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ssl_ca_crl_file = cpv->v.v;
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
      case 13:/* debug.log-ssl-noise */
        pconf->ssl_log_noise = (unsigned char)cpv->v.shrt;
        break;
     #if 0    /*(cpk->k_id remapped in mod_mbedtls_set_defaults())*/
      case 14:/* ssl.verifyclient.ca-file */
      case 15:/* ssl.verifyclient.ca-dn-file */
      case 16:/* ssl.verifyclient.ca-crl-file */
        break;
     #endif
      default:/* should not happen */
        return;
    }
}


static void
mod_mbedtls_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv)
{
    do {
        mod_mbedtls_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_mbedtls_patch_config (request_st * const r, plugin_config * const pconf)
{
    plugin_data * const p = mod_mbedtls_plugin_data;
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_mbedtls_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


__attribute_pure__
static int
mod_mbedtls_crt_is_self_issued (const mbedtls_x509_crt * const crt)
{
    const mbedtls_x509_buf * const issuer  = &crt->issuer_raw;
    const mbedtls_x509_buf * const subject = &crt->subject_raw;
    return subject->len == issuer->len
        && 0 == memcmp(issuer->p, subject->p, subject->len);
}


__attribute_cold__
static int
mod_mbedtls_construct_crt_chain (mbedtls_x509_crt *leaf, mbedtls_x509_crt *store, log_error_st *errh)
{
    /* Historically, openssl will use the cert chain in (SSL_CTX *) if a cert
     * does not have a chain configured in (SSL *).  While similar behavior
     * could be achieved with mbedtls_x509_crt_parse_file(crt, ssl_ca_file->ptr)
     * instead attempt to do better and build a proper, ordered cert chain. */

    if (leaf->next) return 0; /*(presume chain has already been provided)*/
    if (store == NULL) return 0;/*(unable to proceed; chain may be incomplete)*/

    /* attempt to construct certificate chain from certificate store */
    for (mbedtls_x509_crt *crt = leaf; crt; ) {
        const mbedtls_x509_buf * const issuer = &crt->issuer_raw;

        /*(walk entire store in case certs are not properly sorted)*/
        for (crt = store; crt; crt = crt->next) {
            /* The raw issuer/subject data (DER) is used for quick comparison */
            /* (see comments in mod_mbedtls_verify_cb())*/
            const mbedtls_x509_buf * const subject = &crt->subject_raw;
            if (issuer->len != subject->len
                || 0 != memcmp(subject->p, issuer->p, issuer->len)) continue;

            /* root cert is end condition; omit from chain of intermediates */
            if (mod_mbedtls_crt_is_self_issued(crt))
                return 0;

            int rc =
          #if MBEDTLS_VERSION_NUMBER >= 0x02110000 /* mbedtls 2.17.0 */
              /* save memory by eliding copy of already-loaded raw DER */
              mbedtls_x509_crt_parse_der_nocopy(leaf, crt->raw.p, crt->raw.len);
          #else
              mbedtls_x509_crt_parse_der(leaf, crt->raw.p, crt->raw.len);
          #endif
            if (0 != rc) { /*(failure not unexpected since already parsed)*/
                elog(errh, __FILE__, __LINE__, rc, "cert copy failed");
                return rc;
            }
            break;
        }
    }

    return 0; /*(no error, though cert chain may or may not be complete)*/
}


static int
mod_mbedtls_verify_cb (void *arg, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    handler_ctx * const hctx = (handler_ctx *)arg;

    if (depth > hctx->conf.ssl_verifyclient_depth) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
                  "MTLS: addr:%s client cert chain too long",
                  hctx->con->dst_addr_buf.ptr);
        *flags |= MBEDTLS_X509_BADCERT_OTHER; /* cert chain too long */
    }
    else if (0 == depth && NULL != hctx->conf.ssl_ca_dn_file) {
        /* verify that client cert is issued by CA in ssl.ca-dn-file
         * if both ssl.ca-dn-file and ssl.ca-file were configured */
        /* The raw issuer/subject data (DER) is used for quick comparison. */
        const size_t len = crt->issuer_raw.len;
        mbedtls_x509_crt *chain = hctx->conf.ssl_ca_dn_file;
        do {
          #if 0 /* x509_name_cmp() is not a public func in mbedtls */
            if (0 == x509_name_cmp(&crt->issuer, &chain->subject))
                break;
          #else
            if (len == chain->subject_raw.len
                && 0 == memcmp(chain->subject_raw.p, crt->issuer_raw.p, len))
                break;
          #endif
        } while ((chain = chain->next));

        if (NULL == chain)
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    }
    if (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
                  "MTLS: addr:%s client cert not trusted",
                  hctx->con->dst_addr_buf.ptr);
    }

    return 0;
}


enum {
  MOD_MBEDTLS_ALPN_HTTP11      = 1
 ,MOD_MBEDTLS_ALPN_HTTP10      = 2
 ,MOD_MBEDTLS_ALPN_H2          = 3
 ,MOD_MBEDTLS_ALPN_ACME_TLS_1  = 4
};

#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
#ifdef MBEDTLS_SSL_ALPN

static int
mod_mbedtls_acme_tls_1 (handler_ctx *hctx);

#endif
#endif


#if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
#define MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO
#define MBEDTLS_ERR_SSL_DECODE_ERROR      MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO
#endif


#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
static int
mod_mbedtls_SNI (void *arg, mbedtls_ssl_context *ssl, const unsigned char *servername, size_t len)
{
    handler_ctx * const hctx = (handler_ctx *) arg;
    request_st * const r = hctx->r;
    buffer_copy_string_len(&r->uri.scheme, CONST_STR_LEN("https"));

    if (len >= 1024) { /*(expecting < 256; TLSEXT_MAXLEN_host_name is 255)*/
        log_error(r->conf.errh, __FILE__, __LINE__,
          "MTLS: addr:%s SNI name too long (%zu) %.*s...",
          hctx->con->dst_addr_buf.ptr, len, 1024, servername);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    /* use SNI to patch mod_mbedtls config and then reset COMP_HTTP_HOST */
    buffer_copy_string_len_lc(&r->uri.authority, (const char *)servername, len);
  #if 0
    /*(r->uri.authority used below for configuration before request read;
     * revisit for h2)*/
    if (0 != http_request_host_policy(&r->uri.authority,
                                      r->conf.http_parseopts, 443))
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
  #endif

    const buffer * const ssl_pemfile = hctx->conf.pc->ssl_pemfile;

    r->conditional_is_valid |= (1 << COMP_HTTP_SCHEME)
                            |  (1 << COMP_HTTP_HOST);

    mod_mbedtls_patch_config(r, &hctx->conf);
    /* reset COMP_HTTP_HOST so that conditions re-run after request hdrs read */
    /*(done in configfile-glue.c:config_cond_cache_reset() after request hdrs read)*/
    /*config_cond_cache_reset_item(r, COMP_HTTP_HOST);*/
    /*buffer_clear(&r->uri.authority);*/

  #ifdef MBEDTLS_SSL_ALPN
    /* TLS-ALPN-01 (ALPN "acme-tls/1") requires SNI */
    if (hctx->alpn == MOD_MBEDTLS_ALPN_ACME_TLS_1)
        return mod_mbedtls_acme_tls_1(hctx);
  #endif

    /*(future: if threaded, take mutex in (plugin_cert *)
     * around access to x509, pkey, OCSP stapling)*/
    /*hctx->pc = hctx->conf.pc;*/
    hctx->kp = mod_mbedtls_kp_acq(hctx->conf.pc);

    /*(compare strings as ssl.pemfile might repeat same file in lighttpd.conf
     * and mod_mbedtls does not attempt to de-dup)*/
    if (!buffer_is_equal(hctx->conf.pc->ssl_pemfile, ssl_pemfile)) {
        /* if needed, attempt to construct certificate chain for server cert */
        mod_mbedtls_kp * const kp = hctx->kp;
        if (kp->need_chain) {
            kp->need_chain = 0; /*(attempt once to complete chain)*/
            mbedtls_x509_crt *ssl_cred = &kp->crt;
            mbedtls_x509_crt *store = hctx->conf.ssl_ca_file;
            if (0 != mod_mbedtls_construct_crt_chain(ssl_cred, store,
                                                     r->conf.errh))
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        /* reconfigure to use SNI-specific cert */
        int rc = mbedtls_ssl_set_hs_own_cert(ssl, &kp->crt, &kp->pk);
        if (0 != rc) {
            elogf(r->conf.errh, __FILE__, __LINE__, rc,
                  "failed to set SNI certificate for TLS server name %s",
                  r->uri.authority.ptr);
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }

    return 0;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */


static int
mod_mbedtls_conf_verify (handler_ctx *hctx)
{
    if (NULL == hctx->conf.ssl_ca_file) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "MTLS: can't verify client without ssl.verifyclient.ca-file "
          "for TLS server name %s",
          hctx->r->uri.authority.ptr);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (hctx->crl == NULL)
        hctx->crl = mod_mbedtls_x509_crl_acq(hctx->conf.ssl_ca_crl_file);
    mbedtls_ssl_context * const ssl = &hctx->ssl;
  #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
    int mode = (hctx->conf.ssl_verifyclient_enforce)
      ? MBEDTLS_SSL_VERIFY_REQUIRED
      : MBEDTLS_SSL_VERIFY_OPTIONAL;
    mbedtls_ssl_set_hs_authmode(ssl, mode);
    mbedtls_x509_crl *ca_crl = hctx->crl ? &hctx->crl->crl : NULL;
    mbedtls_ssl_set_hs_ca_chain(ssl, hctx->conf.ssl_ca_file, ca_crl);
    if (hctx->conf.ssl_ca_dn_file)
        mbedtls_ssl_set_hs_dn_hints(ssl, hctx->conf.ssl_ca_dn_file);
  #else
    /* send ssl_ca_dn_file (if set) in client certificate request
     * (later changed to ssl_ca_file before client certificate verification) */
    mbedtls_x509_crt *ca_certs = hctx->conf.ssl_ca_dn_file
                               ? hctx->conf.ssl_ca_dn_file
                               : hctx->conf.ssl_ca_file;
    mbedtls_x509_crl *ca_crl = hctx->crl ? &hctx->crl->crl : NULL;
    mbedtls_ssl_set_hs_ca_chain(ssl, ca_certs, ca_crl);
  #endif
  #if MBEDTLS_VERSION_NUMBER >= 0x02120000 /* mbedtls 2.18.0 */
    mbedtls_ssl_set_verify(ssl, mod_mbedtls_verify_cb, hctx);
  #else
    /* overwrite callback with hctx each time we enter here, before handshake
     * (Some callbacks are on mbedtls_ssl_config, not mbedtls_ssl_context)
     * (Not thread-safe if config (mbedtls_ssl_config *ssl_ctx) is shared)
     * (XXX: there is probably a better way to do this...) */
    mbedtls_ssl_conf_verify(hctx->ssl_ctx, mod_mbedtls_verify_cb, hctx);
  #endif
    return 0;
}


/* mbedTLS interfaces are generally excellent.  mbedTLS convenience interfaces
 * to read CRLs, X509 certs, and private keys are uniformly paranoid about
 * clearing memory.  At the moment, stdio routines fopen(), fread(), fclose()
 * are used for portability, but without setvbuf(stream, NULL, _IOLBF, 0),
 * again for portability, since setvbuf() is not necessarily available.  Since
 * stdio buffers by default, use our own funcs to read files without buffering.
 * mbedtls_pk_load_file() includes trailing '\0' in size when contents in PEM
 * format, so do the same with the value returned from fdevent_load_file().
 */


static int
mod_mbedtls_x509_crl_parse (mbedtls_x509_crl *chain, const char *fn)
{
    int rc = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, NULL, malloc, free);
    if (NULL == data) return rc;

    rc = mbedtls_x509_crl_parse(chain, (unsigned char *)data, (size_t)dlen+1);

    if (dlen) ck_memzero(data, (size_t)dlen);
    free(data);

    return rc;
}


static mod_mbedtls_x509_crl *
mod_mbedtls_x509_crl_parse_file (const char *fn, log_error_st *errh)
{
    mod_mbedtls_x509_crl *ca_crl = mod_mbedtls_x509_crl_init();
    int rc = mod_mbedtls_x509_crl_parse(&ca_crl->crl, fn);
    if (0 != rc) {
        elogf(errh, __FILE__, __LINE__, rc,
          "CRL file read failed (%s)", fn);
        mod_mbedtls_x509_crl_free(ca_crl);
        ca_crl = NULL;
    }
    return ca_crl;
}


__attribute_noinline__
static void
mod_mbedtls_reload_crl_file (server * const srv, plugin_crl *ssl_ca_crl)
{
    /* CRLs can be updated at any time, though expected on/before Next Update */
    mod_mbedtls_x509_crl *ca_crl =
      mod_mbedtls_x509_crl_parse_file(ssl_ca_crl->crl_file, srv->errh);
    if (NULL == ca_crl)
        return; /* ignore if crl error; keep using existing crl */

    /*(future: if threaded, only one thread should update crls)*/

    mod_mbedtls_x509_crl *ca_crl_prior = ca_crl->next = ssl_ca_crl->ca_crl;
    ssl_ca_crl->ca_crl = ca_crl;
    ssl_ca_crl->crl_loadts = log_epoch_secs;
    if (ca_crl_prior)
        mod_mbedtls_x509_crl_rel(ca_crl_prior);
}


static void
mod_mbedtls_refresh_crl_file (server * const srv, plugin_crl *ssl_ca_crl)
{
    if (ssl_ca_crl->ca_crl) {
        for (mod_mbedtls_x509_crl **crlp = &ssl_ca_crl->ca_crl->next; *crlp; ) {
            mod_mbedtls_x509_crl *ca_crl = *crlp;
            if (ca_crl->refcnt)
                crlp = &ca_crl->next;
            else {
                *crlp = ca_crl->next;
                mod_mbedtls_x509_crl_free(ca_crl);
            }
        }
    }

    struct stat st;
    if (0 != stat(ssl_ca_crl->crl_file, &st)
        || (TIME64_CAST(st.st_mtime) <= ssl_ca_crl->crl_loadts
            && ssl_ca_crl->crl_loadts != (unix_time64_t)-1))
        return;
    mod_mbedtls_reload_crl_file(srv, ssl_ca_crl);
}


static void
mod_mbedtls_refresh_crl_files (server *srv, plugin_data * const p)
{
    /* future: might construct array of (plugin_crl *) at startup
     *         to avoid the need to search for them here */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    if (NULL == p->cvlist) return;
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->k_id != 4) continue; /* k_id == 4 for ssl.ca-crl-file */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            mod_mbedtls_refresh_crl_file(srv, cpv->v.v);
        }
    }
}


static int
mod_mbedtls_cert_is_active (const mbedtls_x509_crt *crt)
{
    return (   !mbedtls_x509_time_is_future(&crt->valid_from)
            && !mbedtls_x509_time_is_past(&crt->valid_to));
}


#if MBEDTLS_VERSION_NUMBER >= 0x02170000 /* mbedtls 2.23.0 */

static int
mod_mbedtls_x509_crt_ext_cb (void *p_ctx,
                             mbedtls_x509_crt const *crt,
                             mbedtls_x509_buf const *oid,
                             int critical,
                             const unsigned char *p,
                             const unsigned char *end)
{
    UNUSED(p_ctx);
    if (!mod_mbedtls_cert_is_active(crt))
        return MBEDTLS_ERR_X509_INVALID_DATE;
    /* id-pe-acmeIdentifier 1.3.6.1.5.5.7.1.31 */
    static const unsigned char acmeIdentifier[] = MBEDTLS_OID_PKIX "\x01\x1f";
    if (0 == MBEDTLS_OID_CMP(acmeIdentifier, oid)) {
        if (!critical) /* required by RFC 8737 */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS
                 + MBEDTLS_ERR_ASN1_INVALID_DATA;
        /*(mbedtls_asn1_get_tag() should take first param as
         * (const unsigned char **) so safe to cast away const)*/
        unsigned char *q;
        *(const unsigned char **)&q = p;
        size_t len;
        int rc = mbedtls_asn1_get_tag(&q, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING
                                     |MBEDTLS_ASN1_PRIMITIVE);
        if (0 != rc)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + rc;
        if (q + len != end)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS
                 + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        if (len != 32) /* must be OCTET STRING (SIZE (32)) */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS
                 + MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        return 0;
    }
    return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
}

static int
mod_mbedtls_x509_crt_parse_acme (mbedtls_x509_crt *chain, const char *fn)
{
    /* similar to mod_mbedtls_x509_crt_parse_file(), but read single cert
     * and special case to handle id-pe-acmeIdentifier OID */
    /* https://github.com/ARMmbed/mbedtls/issues/3241 */
    int rc = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, NULL, malloc, free);
    if (NULL == data) return rc;

    mbedtls_pem_context pem;
    mbedtls_pem_init(&pem);

    size_t use_len;
    rc = mbedtls_pem_read_buffer(&pem,
                                 "-----BEGIN CERTIFICATE-----",
                                 "-----END CERTIFICATE-----",
                                 (unsigned char *)data, NULL, 0, &use_len);
    if (0 == rc) {
        mbedtls_x509_crt_ext_cb_t cb = mod_mbedtls_x509_crt_ext_cb;
      #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
        size_t buflen;
        const unsigned char *buf = mbedtls_pem_get_buffer(&pem, &buflen);
      #else
        const unsigned char *buf = pem.MBEDTLS_PRIVATE(buf);
        size_t buflen = pem.MBEDTLS_PRIVATE(buflen);
      #endif
        rc = mbedtls_x509_crt_parse_der_with_ext_cb(chain,buf,buflen,1,cb,NULL);
    }

    mbedtls_pem_free(&pem);

    if (dlen) ck_memzero(data, (size_t)dlen);
    free(data);

    return rc;
}

#endif


__attribute_noinline__
static int
mod_mbedtls_x509_crt_parse_file (mbedtls_x509_crt *chain, const char *fn)
{
    int rc = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, NULL, malloc, free);
    if (NULL == data) return rc;

    rc = mbedtls_x509_crt_parse(chain, (unsigned char *)data, (size_t)dlen+1);

    if (dlen) ck_memzero(data, (size_t)dlen);
    free(data);

    return rc;
}


__attribute_noinline__
static int
mod_mbedtls_pk_parse_keyfile (mbedtls_pk_context *ctx, const char *fn, const char *pwd)
{
    int rc = MBEDTLS_ERR_PK_FILE_IO_ERROR;
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, NULL, malloc, free);
    if (NULL == data) return rc;

  #if MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.0.0 */ \
   && MBEDTLS_VERSION_NUMBER <  0x04000000 /* mbedtls 4.0.0 */
   #if defined(MBEDTLS_USE_PSA_CRYPTO)
    rc = mbedtls_pk_parse_key(ctx, (unsigned char *)data, (size_t)dlen+1,
                              (const unsigned char *)pwd,
                              pwd ? strlen(pwd) : 0,
                              mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
   #else
    plugin_data * const p = mod_mbedtls_plugin_data;
    rc = mbedtls_pk_parse_key(ctx, (unsigned char *)data, (size_t)dlen+1,
                              (const unsigned char *)pwd,
                              pwd ? strlen(pwd) : 0,
                              mbedtls_ctr_drbg_random, &p->ctr_drbg);
   #endif
  #else
    rc = mbedtls_pk_parse_key(ctx, (unsigned char *)data, (size_t)dlen+1,
                              (const unsigned char *)pwd,
                              pwd ? strlen(pwd) : 0);
  #endif

    if (dlen) ck_memzero(data, (size_t)dlen);
    free(data);

    return rc;
}


__attribute_noinline__
static void *
network_mbedtls_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey)
{
  #if MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.0.0 */
    if (!mod_mbedtls_init_once_mbedtls(srv))
        return NULL;
  #endif

    mod_mbedtls_kp * const kp = mod_mbedtls_kp_init();
    int rc;

    rc = mod_mbedtls_x509_crt_parse_file(&kp->crt, pemfile->ptr);
    if (0 != rc) {
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "PEM file cert read failed (%s)", pemfile->ptr);
        mod_mbedtls_kp_free(kp);
        return NULL;
    }
    else if (!mod_mbedtls_cert_is_active(&kp->crt) && log_epoch_secs > 300) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: inactive/expired X509 certificate '%s'", pemfile->ptr);
    }

    kp->need_chain = (kp->crt.next == NULL
                      && !mod_mbedtls_crt_is_self_issued(&kp->crt));

    rc = mod_mbedtls_pk_parse_keyfile(&kp->pk, privkey->ptr, NULL);
    if (0 != rc) {
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "PEM file private key read failed %s", privkey->ptr);
        mod_mbedtls_kp_free(kp);
        return NULL;
    }

  #if MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.0.0 */ \
   && MBEDTLS_VERSION_NUMBER <  0x04000000 /* mbedtls 4.0.0 */
   #if defined(MBEDTLS_USE_PSA_CRYPTO)
    rc = mbedtls_pk_check_pair(&kp->crt.pk, &kp->pk,
                               mbedtls_psa_get_random,MBEDTLS_PSA_RANDOM_STATE);
   #else
    plugin_data * const p = mod_mbedtls_plugin_data;
    rc = mbedtls_pk_check_pair(&kp->crt.pk, &kp->pk,
                               mbedtls_ctr_drbg_random, &p->ctr_drbg);
   #endif
  #else
    rc = mbedtls_pk_check_pair(&kp->crt.pk, &kp->pk);
  #endif
    if (0 != rc) {
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "PEM cert and private key did not verify (%s) (%s)",
              pemfile->ptr, privkey->ptr);
        mod_mbedtls_kp_free(kp);
        return NULL;
    }

    plugin_cert *pc = ck_malloc(sizeof(plugin_cert));
    pc->kp = kp;
    pc->ssl_pemfile = pemfile;
    pc->ssl_privkey = privkey;
    pc->pkey_ts = log_epoch_secs;

  #if 0
    /* needed at top of file for portable timegm(): #include "sys-time.h" */
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    mbedtls_x509_time *notAfter = &kp->crt->valid_to;
    tm.tm_sec   = notAfter->sec;
    tm.tm_min   = notAfter->min;
    tm.tm_hour  = notAfter->hour;
    tm.tm_mday  = notAfter->day;
    tm.tm_mon   = notAfter->mon;
    tm.tm_year  = notAfter->year;
    pc->notAfter = TIME64_CAST(timegm(&tm));
  #endif

    return pc;
}


#ifdef MBEDTLS_SSL_ALPN

#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
static int
mod_mbedtls_acme_tls_1 (handler_ctx *hctx)
{
    const buffer * const name = &hctx->r->uri.authority;
    log_error_st * const errh = hctx->r->conf.errh;
    size_t len;
    int rc = MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;

    /* check if acme-tls/1 protocol is enabled (path to dir of cert(s) is set)*/
    if (!hctx->conf.ssl_acme_tls_1)
        return 0; /*(should not happen)*/

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

    mod_mbedtls_kp * const kp = mod_mbedtls_kp_init();
    kp->refcnt = 0; /*(special-case for single-use and immed free in kp_free)*/
    do {
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
      #if MBEDTLS_VERSION_NUMBER >= 0x02170000 /* mbedtls 2.23.0 */
        rc = mod_mbedtls_x509_crt_parse_acme(&kp->crt, b->ptr);
      #else /*(will fail; unable to handle id-pe-acmeIdentifier OID)*/
        rc = mod_mbedtls_x509_crt_parse_file(&kp->crt, b->ptr);
      #endif
        if (0 != rc) {
            elogf(errh, __FILE__, __LINE__, rc,
                  "Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        buffer_truncate(b, len); /*(remove ".crt.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        rc = mod_mbedtls_pk_parse_keyfile(&kp->pk, b->ptr, NULL);
        if (0 != rc) {
            elogf(errh, __FILE__, __LINE__, rc,
                  "Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        rc = mbedtls_ssl_set_hs_own_cert(&hctx->ssl, &kp->crt, &kp->pk);
        if (0 != rc) {
            elogf(errh, __FILE__, __LINE__, rc,
                  "failed to set acme-tls/1 certificate for TLS server "
                  "name %s", name->ptr);
            break;
        }

        /*hctx->pc = NULL;*/
        hctx->kp = kp;

    } while (0);

    if (0 != rc)
        mod_mbedtls_kp_free(kp);
    buffer_free(b);
    return rc;
}
#endif


static int
mod_mbedtls_alpn_h2_policy (handler_ctx * const hctx)
{
    /*(currently called after handshake has completed)*/
  #if 0 /* SNI omitted by client when connecting to IP instead of to name */
    if (buffer_is_blank(&hctx->r->uri.authority)) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "MTLS: addr:%s error ALPN h2 without SNI",
          hctx->con->dst_addr_buf.ptr);
        return -1;
    }
  #endif
  #if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
    if (hctx->ssl.major_ver == MBEDTLS_SSL_MAJOR_VERSION_3
        && hctx->ssl.minor_ver < MBEDTLS_SSL_MINOR_VERSION_3) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "MTLS: addr:%s error ALPN h2 requires TLSv1.2 or later",
          hctx->con->dst_addr_buf.ptr);
        return -1;
    }
  #else /*(mbedTLS 3.0.0 dropped support for TLSv1.1 and earlier)*/
    UNUSED(hctx);
  #endif

    return 0;
}


static int
mod_mbedtls_alpn_selected (handler_ctx * const hctx, const char * const in)
{
    const int n = (int)strlen(in);
    const int i = 0;
    unsigned short proto;

    switch (n) {
      case 2:  /* "h2" */
        if (in[i] == 'h' && in[i+1] == '2') {
            proto = MOD_MBEDTLS_ALPN_H2;
            if (hctx->r->handler_module == NULL)/*(e.g. not mod_sockproxy)*/
                hctx->r->http_version = HTTP_VERSION_2;
            break;
        }
        return 0;
      case 8:  /* "http/1.1" "http/1.0" */
        if (0 == memcmp(in+i, "http/1.", 7)) {
            if (in[i+7] == '1') {
                proto = MOD_MBEDTLS_ALPN_HTTP11;
                break;
            }
            if (in[i+7] == '0') {
                proto = MOD_MBEDTLS_ALPN_HTTP10;
                break;
            }
        }
        return 0;
      case 10: /* "acme-tls/1" */
        if (0 == memcmp(in+i, "acme-tls/1", 10)) {
            proto = MOD_MBEDTLS_ALPN_ACME_TLS_1;
            break;
        }
        return 0;
      default:
        return 0;
    }

    hctx->alpn = proto;
    return 0;
}


#if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
static int
mod_mbedtls_alpn_select_cb (handler_ctx *hctx, const unsigned char *in, const unsigned int inlen)
{
    /*(skip first two bytes which should match inlen-2)*/
    for (unsigned int i = 2, n; i < inlen; i += n) {
        n = in[i++];
        if (i+n > inlen || 0 == n) break;
        switch (n) {
          case 2:  /* "h2" */
            if (in[i] == 'h' && in[i+1] == '2') {
                if (!hctx->r->conf.h2proto) continue;
                hctx->alpn = MOD_MBEDTLS_ALPN_H2;
                if (hctx->r->handler_module == NULL)/*(e.g. not mod_sockproxy)*/
                    hctx->r->http_version = HTTP_VERSION_2;
                return 0;
            }
            continue;
          case 8:  /* "http/1.1" "http/1.0" */
            if (0 == memcmp(in+i, "http/1.", 7)) {
                if (in[i+7] == '1') {
                    hctx->alpn = MOD_MBEDTLS_ALPN_HTTP11;
                    return 0;
                }
                if (in[i+7] == '0') {
                    hctx->alpn = MOD_MBEDTLS_ALPN_HTTP10;
                    return 0;
                }
            }
            continue;
          case 10: /* "acme-tls/1" */
            if (0 == memcmp(in+i, "acme-tls/1", 10)) {
                hctx->alpn = MOD_MBEDTLS_ALPN_ACME_TLS_1;
                return 0;
            }
            continue;
          default:
            continue;
        }
    }

    return 0;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */ /* mbedtls 3.00.0 */

#endif /* MBEDTLS_SSL_ALPN */


#if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
static int
mod_mbedtls_cert_cb (mbedtls_ssl_context * const ssl)
{
    handler_ctx * const hctx = mbedtls_ssl_get_user_data_p(ssl);
    int rc = 0;

  #ifdef MBEDTLS_SSL_ALPN
    const char *alpn = mbedtls_ssl_get_alpn_protocol(&hctx->ssl);
    if (NULL != alpn) {
        rc = mod_mbedtls_alpn_selected(hctx, alpn);
        if (0 != rc) return rc;
    }
  #endif

  #ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
    size_t len;
    const unsigned char *servername = mbedtls_ssl_get_hs_sni(ssl, &len);
    if (servername) {
        rc = mod_mbedtls_SNI(hctx, ssl, servername, len);
        if (0 != rc) return rc;
    } /*(else no SNI)*/
   #if 0 /*"acme-tls/1" required SNI; use default cert; let cert challenge fail*/
    else if (hctx->alpn == MOD_MBEDTLS_ALPN_ACME_TLS_1)
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
   #endif
    else
  #endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
    {
        /*(future: if threaded, take mutex in (plugin_cert *)
         * around access to x509, pkey, OCSP stapling)*/
        /*hctx->pc = hctx->conf.pc;*/
        hctx->kp = mod_mbedtls_kp_acq(hctx->conf.pc);
    }

    if (hctx->conf.ssl_verifyclient
        && hctx->alpn != MOD_MBEDTLS_ALPN_ACME_TLS_1) { /*(not "acme-tls/1")*/
        rc = mod_mbedtls_conf_verify(hctx);
        if (0 != rc) return rc;
    }

    return rc;
}
#endif


static int
mod_mbedtls_ssl_conf_ciphersuites (server *srv, plugin_config_socket *s, buffer *ciphersuites, const buffer *cipherstring);


static int
mod_mbedtls_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist);


static int
mod_mbedtls_ssl_conf_dhparameters(server *srv, plugin_config_socket *s, const buffer *dhparameters);


static void
mod_mbedtls_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *b, int max);


static int
mod_mbedtls_ssl_conf_cmd (server *srv, plugin_config_socket *s)
{
    /* reference:
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_CONF_cmd.html */
    int rc = 0;
    buffer *cipherstring = NULL;
    buffer *ciphersuites = NULL;

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        data_string *ds = (data_string *)s->ssl_conf_cmd->data[i];
        if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("CipherString")))
            cipherstring = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Ciphersuites")))
            ciphersuites = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Curves"))
              || buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Groups"))) {
            if (!mod_mbedtls_ssl_conf_curves(srv, s, &ds->value))
                rc = -1;
        }
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("DHParameters"))){
            if (!buffer_is_blank(&ds->value)) {
                if (!mod_mbedtls_ssl_conf_dhparameters(srv, s, &ds->value))
                    rc = -1;
            }
        }
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MaxProtocol")))
            mod_mbedtls_ssl_conf_proto(srv, s, &ds->value, 1); /* max */
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MinProtocol")))
            mod_mbedtls_ssl_conf_proto(srv, s, &ds->value, 0); /* min */
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Protocol"))) {
            /* openssl config for Protocol=... is complex and deprecated */
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s ignored; "
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
                        /* mbedtls defaults to no record compression unless
                         * mbedtls is built with MBEDTLS_ZLIB_SUPPORT, which
                         * is deprecated and slated for removal*/
                        if (!flag) continue;
                    }
                    break;
                  case 13:
                    if (buffer_eq_icase_ssn(v, "SessionTicket", 13)) {
                        s->ssl_session_ticket = flag;
                        continue;
                    }
                    break;
                  case 16:
                    if (buffer_eq_icase_ssn(v, "ServerPreference", 16)) {
                        /* Note: before mbedTLS 3.0.0, the server uses its own
                         * preferences over the preference of the client unless
                         * MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE defined! */
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
                          "MTLS: ssl.openssl.ssl-conf-cmd Options %.*s ignored",
                          (int)(e-v), v);
            }
        }
      #if 0
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("..."))) {
        }
      #endif
        else {
            /* warn if not explicitly handled or ignored above */
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s ignored",
                      ds->key.ptr);
        }
    }

    if (!mod_mbedtls_ssl_conf_ciphersuites(srv, s, ciphersuites, cipherstring))
        rc = -1;

    return rc;
}


static int
network_init_ssl (server *srv, plugin_config_socket *s, plugin_data *p)
{
    int rc;

    s->ssl_ctx = ck_malloc(sizeof(mbedtls_ssl_config));
    mbedtls_ssl_config_init(s->ssl_ctx);

 #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    /* set the RNG in the ssl config context, using the default random func */
  #if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_ssl_conf_rng(s->ssl_ctx,
                         mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
  #else
    mbedtls_ssl_conf_rng(s->ssl_ctx, mbedtls_ctr_drbg_random, &p->ctr_drbg);
  #endif
 #endif

    /* mbedtls defaults to disable client renegotiation
     * mbedtls defaults to no record compression unless mbedtls is built
     *   with MBEDTLS_ZLIB_SUPPORT, which is deprecated and slated for removal
     * MBEDTLS_SSL_PRESET_SUITEB is stricter than MBEDTLS_SSL_PRESET_DEFAULT
     * (and is attempted to be supported in mod_mbedtls_ssl_conf_ciphersuites())
     * explanation: https://github.com/ARMmbed/mbedtls/issues/1591
     * reference: RFC 6460 */
    rc = mbedtls_ssl_config_defaults(s->ssl_ctx,
                                     MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (0 != rc) {
        elog(srv->errh, __FILE__,__LINE__, rc,
             "Init of ssl config context defaults failed");
        return -1;
    }

    if (s->ssl_cipher_list) {
        if (!mod_mbedtls_ssl_conf_ciphersuites(srv,s,NULL,s->ssl_cipher_list))
            return -1;
    }

    /* if needed, attempt to construct certificate chain for server cert */
    /* network_init_ssl() caller performs mod_mbedtls_kp_acq(conf.pc) */
    mod_mbedtls_kp * const kp = s->pc->kp;
    if (kp->need_chain) {
        kp->need_chain = 0; /*(attempt once to complete chain)*/
        if (0 != mod_mbedtls_construct_crt_chain(&kp->crt,
                                                 s->ssl_ca_file, srv->errh))
            return -1;
    }

    rc = mbedtls_ssl_conf_own_cert(s->ssl_ctx, &kp->crt, &kp->pk);
    if (0 != rc) {
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "PEM cert and private key did not verify (%s) (%s)",
              s->pc->ssl_pemfile->ptr, s->pc->ssl_privkey->ptr);
        return -1;
    }

  #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
    mbedtls_ssl_conf_cert_cb(s->ssl_ctx, mod_mbedtls_cert_cb);
  #endif

  #ifdef MBEDTLS_SSL_ALPN
    /* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
    static const char *alpn_protos_http_acme[] = {
      "h2"
     ,"http/1.1"
     ,"http/1.0"
     ,"acme-tls/1"
     ,NULL
    };
    static const char *alpn_protos_http[] = {
      "h2"
     ,"http/1.1"
     ,"http/1.0"
     ,NULL
    };
    const char **alpn_protos = (s->ssl_acme_tls_1)
      ? alpn_protos_http_acme
      : alpn_protos_http;
    if (!srv->srvconf.h2proto) ++alpn_protos;
    rc = mbedtls_ssl_conf_alpn_protocols(s->ssl_ctx, alpn_protos);
    if (0 != rc) {
        elog(srv->errh, __FILE__, __LINE__, rc, "error setting ALPN protocols");
        return -1;
    }
  #endif

    mod_mbedtls_ssl_conf_proto(srv, s, NULL, 0); /* min */

    if (!mod_mbedtls_ssl_conf_curves(srv, s, NULL))
        return -1;

    if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
        if (0 != mod_mbedtls_ssl_conf_cmd(srv, s)) return -1;
    }

 #if MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.00.0 */
    int order = s->ssl_honor_cipher_order
      ? MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_SERVER
      : MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_CLIENT;
    mbedtls_ssl_conf_preference_order(s->ssl_ctx, order);
 #else
    /* server preference is used (default) unless mbedtls is built with
     * MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE defined (not default) */
 #endif

  #if defined(MBEDTLS_SSL_SESSION_TICKETS)
    if (s->ssl_session_ticket            /*(.ticket_lifetime is private)*/
        && !*(unsigned char *)&p->ticket_ctx) { /*init once*/
      #if defined(MBEDTLS_USE_PSA_CRYPTO)
        rc = mbedtls_ssl_ticket_setup(&p->ticket_ctx,
          #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                                      mbedtls_psa_get_random,
                                      MBEDTLS_PSA_RANDOM_STATE,
                                      MBEDTLS_CIPHER_AES_256_GCM,
          #else
                                      PSA_ALG_CATEGORY_AEAD,
                                      PSA_KEY_TYPE_AES,
                                      256,
          #endif
                                      43200); /* ticket timeout: 12 hours */
      #else
        rc = mbedtls_ssl_ticket_setup(&p->ticket_ctx, mbedtls_ctr_drbg_random,
                                      &p->ctr_drbg, MBEDTLS_CIPHER_AES_256_GCM,
                                      43200); /* ticket timeout: 12 hours */
      #endif
        if (0 != rc) {
            elog(srv->errh,__FILE__,__LINE__,rc,"mbedtls_ssl_ticket_setup()");
            return -1;
        }
    }

   #if defined(MBEDTLS_SSL_TICKET_C)
    if (s->ssl_session_ticket)
        mbedtls_ssl_conf_session_tickets_cb(s->ssl_ctx,
                                            mbedtls_ssl_ticket_write,
                                            mbedtls_ssl_ticket_parse,
                                            &p->ticket_ctx);
   #endif
  #endif /* MBEDTLS_SSL_SESSION_TICKETS */

    return 0;
}


#define LIGHTTPD_DEFAULT_CIPHER_LIST \
"EECDH+AESGCM:CHACHA20:!PSK:!DHE"

/*"TLS1-3-AES-256-GCM-SHA384:TLS1-3-CHACHA20-POLY1305-SHA256:TLS1-3-AES-128-GCM-SHA256:TLS1-3-AES-128-CCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"*/


static int
mod_mbedtls_set_defaults_sockets(server *srv, plugin_data *p)
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

    p->ssl_ctxs = ck_calloc(srv->config_context->used,sizeof(plugin_ssl_ctx *));

    int rc = HANDLER_GO_ON;
    plugin_data_base srvplug;
    memset(&srvplug, 0, sizeof(srvplug));
    plugin_data_base * const ps = &srvplug;
    if (!config_plugin_values_init(srv, ps, cpk, "mod_mbedtls"))
        return HANDLER_ERROR;

    plugin_config_socket defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.ssl_session_ticket     = 1; /* enabled by default */
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
                  "MTLS: %s is valid only in global scope or "
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
               #ifdef MBEDTLS_SSL_SESSION_TICKETS
                if (!buffer_is_blank(cpv->v.b))
                    p->ssl_stek_file = cpv->v.b->ptr;
               #else
                log_error(srv->errh, __FILE__, __LINE__, "MTLS: "
                  "ssl.stek-file ignored; mbedtls library not built with "
                  "support for SSL session tickets");
               #endif
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

        conf.ssl_verifyclient         = p->defaults.ssl_verifyclient;
        conf.ssl_verifyclient_enforce = p->defaults.ssl_verifyclient_enforce;
        conf.ssl_verifyclient_depth   = p->defaults.ssl_verifyclient_depth;
        conf.ssl_acme_tls_1           = p->defaults.ssl_acme_tls_1;

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
                  case 7: /* ssl.verifyclient.activate */
                    conf.ssl_verifyclient = (0 != cpv->v.u);
                    break;
                  case 8: /* ssl.verifyclient.enforce */
                    conf.ssl_verifyclient_enforce = (0 != cpv->v.u);
                    break;
                  case 9: /* ssl.verifyclient.depth */
                    conf.ssl_verifyclient_depth = (unsigned char)cpv->v.shrt;
                    break;
                  case 12:/* ssl.acme-tls-1 */
                    conf.ssl_acme_tls_1 = cpv->v.b;
                    break;
                 #if 0    /*(cpk->k_id remapped in mod_mbedtls_set_defaults())*/
                  case 14:/* ssl.verifyclient.ca-file */
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
                      "MTLS: ssl.pemfile has to be set in same "
                      "$SERVER[\"socket\"] scope as other ssl.* directives, "
                      "unless only ssl.engine is set, inheriting ssl.* from "
                      "global scope");
                    rc = HANDLER_ERROR;
                    continue;
                }
                p->ssl_ctxs[sidx] = p->ssl_ctxs[0]; /*(copy global scope)*/
                continue;
            }
            /* PEM file is required */
            log_error(srv->errh, __FILE__, __LINE__,
              "MTLS: ssl.pemfile has to be set when ssl.engine = \"enable\"");
            rc = HANDLER_ERROR;
            continue;
        }

        /* (initialize once if module enabled) */
        if (!mod_mbedtls_init_once_mbedtls(srv)) {
            rc = HANDLER_ERROR;
            break;
        }

        /* configure ssl_ctx for socket */

        /*conf.ssl_ctx = NULL;*//*(filled by network_init_ssl() even on error)*/
        if (0 == network_init_ssl(srv, &conf, p)) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[sidx] =
              ck_calloc(1, sizeof(plugin_ssl_ctx));
            s->ssl_ctx            = conf.ssl_ctx;
            s->ciphersuites       = conf.ciphersuites;
            s->curves             = conf.curves;
            s->pc                 = conf.pc;
            s->kp                 = mod_mbedtls_kp_acq(conf.pc);
            s->ssl_ca_file        = conf.ssl_ca_file;/* refresh w/ need_chain */
        }
        else {
            mbedtls_ssl_config_free(conf.ssl_ctx);
            free(conf.ciphersuites);
            free(conf.curves);
            rc = HANDLER_ERROR;
        }
    }

    free(srvplug.cvlist);

    if (rc == HANDLER_GO_ON && ssl_is_init) {
      #ifdef MBEDTLS_SSL_SESSION_TICKETS
        mod_mbedtls_session_ticket_key_check(p, log_epoch_secs);
      #endif
        mod_mbedtls_refresh_crl_files(srv, p);
    }

    return rc;
}


SETDEFAULTS_FUNC(mod_mbedtls_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.pemfile"), /* expect pos 0 for refresh certs */
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
     ,{ CONST_STR_LEN("ssl.ca-crl-file"), /* expect pos 4 for refresh crl */
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
    if (!config_plugin_values_init(srv, p, cpk, "mod_mbedtls"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        config_plugin_value_t *pemfile = NULL;
        config_plugin_value_t *privkey = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (!buffer_is_blank(cpv->v.b)) pemfile = cpv;
                break;
              case 1: /* ssl.privkey */
                if (!buffer_is_blank(cpv->v.b)) privkey = cpv;
                break;
              case 14:/* ssl.verifyclient.ca-file */
                if (cpv->k_id == 14) cpv->k_id = 2;
                __attribute_fallthrough__
              case 15:/* ssl.verifyclient.ca-dn-file */
                if (cpv->k_id == 15) cpv->k_id = 3;
                __attribute_fallthrough__
              case 2: /* ssl.ca-file */
              case 3: /* ssl.ca-dn-file */
               #if MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.0.0 */
                if (!mod_mbedtls_init_once_mbedtls(srv)) return HANDLER_ERROR;
               #endif /* else defer; not necessary for pemfile parsing */
                if (!buffer_is_blank(cpv->v.b)) {
                    mbedtls_x509_crt *cacert = ck_calloc(1, sizeof(*cacert));
                    mbedtls_x509_crt_init(cacert);
                    int rc =
                      mod_mbedtls_x509_crt_parse_file(cacert, cpv->v.b->ptr);
                    if (0 == rc) {
                        cpv->vtype = T_CONFIG_LOCAL;
                        cpv->v.v = cacert;
                    }
                    else {
                        elogf(srv->errh, __FILE__, __LINE__, rc,
                              "%s = %s", cpk[cpv->k_id].k, cpv->v.b->ptr);
                        mbedtls_x509_crt_free(cacert);
                        free(cacert);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 16:/* ssl.verifyclient.ca-crl-file */
                cpv->k_id = 4;
                __attribute_fallthrough__
              case 4: /* ssl.ca-crl-file */
                if (!buffer_is_blank(cpv->v.b)) {
                    plugin_crl *ssl_ca_crl = ck_malloc(sizeof(*ssl_ca_crl));
                    ssl_ca_crl->ca_crl = NULL;
                    ssl_ca_crl->crl_file = cpv->v.b->ptr;
                    ssl_ca_crl->crl_loadts = (unix_time64_t)-1;
                    cpv->vtype = T_CONFIG_LOCAL;
                    cpv->v.v = ssl_ca_crl;
                }
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
                      "MTLS: %s is absurdly large (%hu); limiting to 255",
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
              case 13:/* debug.log-ssl-noise */
             #if 0    /*(handled further above)*/
              case 14:/* ssl.verifyclient.ca-file */
              case 15:/* ssl.verifyclient.ca-dn-file */
              case 16:/* ssl.verifyclient.ca-crl-file */
             #endif
                break;
              default:/* should not happen */
                break;
            }
        }

        if (pemfile) {
            if (NULL == privkey) privkey = pemfile;
            pemfile->v.v =
              network_mbedtls_load_pemfile(srv, pemfile->v.b, privkey->v.b);
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
            mod_mbedtls_merge_config(&p->defaults, cpv);
    }

  #ifndef MBEDTLS_ERROR_C
    log_error(srv->errh, __FILE__, __LINE__,
              "MTLS: No error strings available. "
              "Compile mbedtls with MBEDTLS_ERROR_C to enable.");
  #endif

    feature_refresh_certs = config_feature_bool(srv, "ssl.refresh-certs", 0);
    feature_refresh_crls  = config_feature_bool(srv, "ssl.refresh-crls",  0);

    return mod_mbedtls_set_defaults_sockets(srv, p);
}


    /* local_send_buffer is a static buffer of size (LOCAL_SEND_BUFSIZE)
     *
     * buffer is allocated once, is NOT realloced (note: not thread-safe)
     * */

            /* copy small mem chunks into single large buffer
             * before mbedtls_ssl_write() to reduce number times
             * write() called underneath mbedtls_ssl_write() and
             * potentially reduce number of packets generated if TCP_NODELAY */


__attribute_cold__
static int
mod_mbedtls_ssl_write_err(connection *con, handler_ctx *hctx, int wr, size_t wr_len)
{
    switch (wr) {
      case MBEDTLS_ERR_SSL_WANT_READ:
        con->is_readable = -1;
        break; /* try again later */
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        con->is_writable = -1;
       #if MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.00.0 */
        hctx->pending_write = wr_len; /* partial write; save attempted wr_len */
       #endif
        break; /* try again later */
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
        break; /* try again later */
      case MBEDTLS_ERR_NET_CONN_RESET:
        if (hctx->conf.ssl_log_noise)
            elogf(hctx->r->conf.errh, __FILE__, __LINE__, wr,
              "addr:%s peer closed connection", con->dst_addr_buf.ptr);
        return -1;
      default:
        elogf(hctx->r->conf.errh, __FILE__, __LINE__, wr,
          "addr:%s %s()", con->dst_addr_buf.ptr, __func__);
        return -1;
    }

  #if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
    if (0 != hctx->ssl.out_left)  /* partial write; save attempted wr_len */
        hctx->pending_write = wr_len;
  #endif

    return 0; /* try again later */
}


static int
mod_mbedtls_close_notify(handler_ctx *hctx);


static int
connection_write_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[mod_mbedtls_plugin_data->id];
    mbedtls_ssl_context * const ssl = &hctx->ssl;

    if (hctx->pending_write) {
        int wr = (int)hctx->pending_write;
      #if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
        if (0 != ssl->out_left)
      #endif
        {
            /*(would prefer mbedtls_ssl_flush_output() from ssl_internal.h)*/
            size_t data_len = hctx->pending_write;
            wr = mbedtls_ssl_write(ssl, NULL, data_len);
            if (wr <= 0)
                return mod_mbedtls_ssl_write_err(con, hctx, wr, data_len);
            max_bytes -= wr;
        }
        hctx->pending_write = 0;
        chunkqueue_mark_written(cq, wr);
    }

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_mbedtls_close_notify(hctx);

    const int lim = mbedtls_ssl_get_max_out_record_payload(ssl);
    if (lim < 0) return mod_mbedtls_ssl_write_err(con, hctx, lim, 0);

    log_error_st * const errh = hctx->errh;
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

        /* yield if read less than requested
         * (if starting cqlen was less than requested read amount, then
         *  chunkqueue should be empty now, so no need to calculate that)
         * max_bytes will end up negative at bottom of block and loop exit */
        if (data_len < ( LOCAL_SEND_BUFSIZE < max_bytes
                       ? LOCAL_SEND_BUFSIZE
                       : (uint32_t)max_bytes))
            max_bytes = 0; /* try again later; trigger loop exit on next iter */

        /* mbedtls_ssl_write() copies the data, up to max record size, but if
         * (temporarily) unable to write the entire record, it is documented
         * that the caller must call mbedtls_ssl_write() again, later, with the
         * same arguments.  This appears to be because mbedtls_ssl_context does
         * not keep track of the original size of the caller data that
         * mbedtls_ssl_write() attempted to write (and may have transformed to
         * a different size).  The func may return MBEDTLS_ERR_SSL_WANT_READ or
         * MBEDTLS_ERR_SSL_WANT_WRITE to indicate that the caller should wait
         * for the fd to be readable/writable before calling the func again,
         * which is why those (temporary) errors are returned instead of telling
         * the caller that the data was successfully copied.  When the record is
         * written successfully, the return value is supposed to indicate the
         * number of (originally submitted) bytes written, but since that value
         * is unknown (not saved), the caller's len parameter is reflected back,
         * which is why the caller must call the func again with the same args.
         * Additionally, to be accurate, the size must fit into a record which
         * is why we restrict ourselves to sending max out record payload each
         * iteration.
         */

        int wr_total = 0;
        do {
            size_t wr_len = (data_len > (size_t)lim) ? (size_t)lim : data_len;
            wr = mbedtls_ssl_write(ssl, (const unsigned char *)data, wr_len);
            if (wr <= 0) {
                if (wr_total) chunkqueue_mark_written(cq, wr_total);
                return mod_mbedtls_ssl_write_err(con, hctx, wr, wr_len);
            }
            wr_total += wr;
            data += wr;
        } while ((data_len -= wr));
        chunkqueue_mark_written(cq, wr_total);
        max_bytes -= wr_total;
    }

    return 0;
}


#if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
#elif MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.00.0 */
#define handshake_state(ssl) (ssl)->MBEDTLS_PRIVATE(state)
#else /* MBEDTLS_VERSION_NUMBER < 0x03000000 */ /* mbedtls 3.00.0 */
#define handshake_state(ssl) (ssl)->state
#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
#ifdef MBEDTLS_SSL_ALPN
static int ssl_parse_client_hello( mbedtls_ssl_context *ssl, handler_ctx *hctx );
#endif
#endif
#endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */ /* mbedtls 3.00.0 */


static int
mod_mbedtls_ssl_handshake (handler_ctx *hctx)
{
    int rc = 0;

 #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */

    rc = mbedtls_ssl_handshake(&hctx->ssl);

 #else

    /* overwrite callback with hctx each time we enter here, before handshake
     * (Some callbacks are on mbedtls_ssl_config, not mbedtls_ssl_context)
     * (Not thread-safe if config (mbedtls_ssl_config *ssl_ctx) is shared)
     * (XXX: there is probably a better way to do this...) */
  #ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
    mbedtls_ssl_conf_sni(hctx->ssl_ctx, mod_mbedtls_SNI, hctx);
  #endif

    if (handshake_state(&hctx->ssl) < MBEDTLS_SSL_SERVER_HELLO) {
        while (handshake_state(&hctx->ssl) != MBEDTLS_SSL_SERVER_HELLO
            && handshake_state(&hctx->ssl) != MBEDTLS_SSL_HANDSHAKE_OVER) {
          /* disable in mbedtls 3.0+ until alternative callbacks are available
           * https://github.com/ARMmbed/mbedtls/issues/5430 */
          #if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
          #ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
          #ifdef MBEDTLS_SSL_ALPN
            /* parse client_hello for ALPN extension prior to mbedtls handshake
             * in order to perform certificate selection in mod_mbedtls_SNI() */
            if (hctx->conf.ssl_acme_tls_1) {
                rc = ssl_parse_client_hello(&hctx->ssl, hctx);
                if (0 != rc) break;
            }
          #endif
          #endif
          #endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */ /* mbedtls 3.00.0 */
            rc = mbedtls_ssl_handshake_step(&hctx->ssl);
            if (0 != rc) break;
        }
        if (0 == rc
            && handshake_state(&hctx->ssl) == MBEDTLS_SSL_SERVER_HELLO) {
          #ifdef MBEDTLS_SSL_ALPN
            const char *alpn = mbedtls_ssl_get_alpn_protocol(&hctx->ssl);
            if (NULL != alpn)
                rc = mod_mbedtls_alpn_selected(hctx, alpn);
          #endif
        }
    }

    if (0 == rc && hctx->conf.ssl_verifyclient  /*(after SNI and ALPN)*/
        && handshake_state(&hctx->ssl) >= MBEDTLS_SSL_SERVER_HELLO
        && handshake_state(&hctx->ssl) <= MBEDTLS_SSL_SERVER_HELLO_DONE
        && hctx->alpn != MOD_MBEDTLS_ALPN_ACME_TLS_1) { /*(not "acme-tls/1")*/
        int mode = (hctx->conf.ssl_verifyclient_enforce)
          ? MBEDTLS_SSL_VERIFY_REQUIRED
          : MBEDTLS_SSL_VERIFY_OPTIONAL;
        mbedtls_ssl_set_hs_authmode(&hctx->ssl, mode);
        while (handshake_state(&hctx->ssl) != MBEDTLS_SSL_CERTIFICATE_REQUEST
            && handshake_state(&hctx->ssl) != MBEDTLS_SSL_HANDSHAKE_OVER) {
            rc = mbedtls_ssl_handshake_step(&hctx->ssl);
            if (0 != rc) break;
        }
        if (0 == rc
            && handshake_state(&hctx->ssl) == MBEDTLS_SSL_CERTIFICATE_REQUEST) {
            rc = mod_mbedtls_conf_verify(hctx);
            if (0 == rc)
                rc = mbedtls_ssl_handshake_step(&hctx->ssl);
            /* reconfigure CA trust chain after sending client certificate
             * request (if ssl_ca_dn_file is set), before client certificate
             * verification (MBEDTLS_SSL_CERTIFICATE_VERIFY) */
            if (0 == rc && hctx->conf.ssl_ca_dn_file
                && handshake_state(&hctx->ssl)==MBEDTLS_SSL_SERVER_HELLO_DONE) {
                if (hctx->crl == NULL)
                    hctx->crl =
                      mod_mbedtls_x509_crl_acq(hctx->conf.ssl_ca_crl_file);
                mbedtls_x509_crt *ca_certs = hctx->conf.ssl_ca_file;
                mbedtls_x509_crl *ca_crl = hctx->crl ? &hctx->crl->crl : NULL;
                mbedtls_ssl_set_hs_ca_chain(&hctx->ssl, ca_certs, ca_crl);
            }
        }
    }

    if (0 == rc && handshake_state(&hctx->ssl) != MBEDTLS_SSL_HANDSHAKE_OVER) {
        rc = mbedtls_ssl_handshake(&hctx->ssl);
    }

 #endif

    switch (rc) {
      case 0:
        hctx->handshake_done = 1;
       #ifdef MBEDTLS_SSL_ALPN
        if (hctx->alpn == MOD_MBEDTLS_ALPN_H2) {
            if (0 != mod_mbedtls_alpn_h2_policy(hctx))
                return -1;
        }
        else if (hctx->alpn == MOD_MBEDTLS_ALPN_ACME_TLS_1) {
            /* Once TLS handshake is complete, return -1 to result in
             * CON_STATE_ERROR so that socket connection is quickly closed */
            return -1;
        }
        hctx->alpn = 0;
       #endif
        return 1; /* continue reading */
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        hctx->con->is_writable = -1;
        __attribute_fallthrough__
      case MBEDTLS_ERR_SSL_WANT_READ:
        hctx->con->is_readable = 0;
        return 0;
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
        return 0;
      case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
        return -1;
      case MBEDTLS_ERR_NET_CONN_RESET:
      case MBEDTLS_ERR_SSL_CONN_EOF:
        if (!hctx->conf.ssl_log_noise) return -1;
        __attribute_fallthrough__
      default:
        elogf(hctx->r->conf.errh, __FILE__, __LINE__, rc,
          "addr:%s %s()", hctx->con->dst_addr_buf.ptr, __func__);
        return -1;
    }
}


static int
connection_read_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[mod_mbedtls_plugin_data->id];
    int len;
    char *mem = NULL;
    size_t mem_len = 0;

    UNUSED(max_bytes);

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_mbedtls_close_notify(hctx);

    if (!hctx->handshake_done) {
        int rc = mod_mbedtls_ssl_handshake(hctx);
        if (1 != rc) return rc; /* !hctx->handshake_done; not done, or error */
    }

    do {
        len = mbedtls_ssl_get_bytes_avail(&hctx->ssl);
        mem_len = len < 2048 ? 2048 : (size_t)len;
        chunk * const ckpt = cq->last;
        mem = chunkqueue_get_memory(cq, &mem_len);

        len = mbedtls_ssl_read(&hctx->ssl, (unsigned char *)mem, mem_len);
        chunkqueue_use_memory(cq, ckpt, len > 0 ? len : 0);
    } while (len > 0
             && mbedtls_ssl_check_pending(&hctx->ssl));

    if (len < 0) {
        int rc = len;
        request_st * const r = &con->request;
        switch (rc) {
          case MBEDTLS_ERR_SSL_WANT_WRITE:
            con->is_writable = -1;
            __attribute_fallthrough__
          case MBEDTLS_ERR_SSL_WANT_READ:
            con->is_readable = 0;
            return 0;
          case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
          case MBEDTLS_ERR_SSL_CONN_EOF:
            /* XXX: future: save state to avoid future read after response? */
            con->is_readable = 0;
            r->keep_alive = 0;
            return -2;
          case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
          case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
            return 0;
          case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            return -1;
          case MBEDTLS_ERR_NET_CONN_RESET:
            if (!hctx->conf.ssl_log_noise) return -1;
            __attribute_fallthrough__
          default:
            elogf(hctx->r->conf.errh, __FILE__, __LINE__, rc,
              "addr:%s mod_mbedtls_ssl_read_err()",hctx->con->dst_addr_buf.ptr);
            return -1;
        }
    } else if (len == 0) {
        con->is_readable = 0;
        /* the other end closed the connection -> KEEP-ALIVE */

        return -2;
    } else {
        return 0;
    }
}


static void
mod_mbedtls_debug_cb(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    if (level < (intptr_t)ctx) /* level */
        log_error(NULL, file, line, "MTLS: %s", str);
}


CONNECTION_FUNC(mod_mbedtls_handle_con_accept)
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

    hctx->ssl_ctx = p->ssl_ctxs[srv_sock->sidx]
                  ? p->ssl_ctxs[srv_sock->sidx]->ssl_ctx
                  : p->ssl_ctxs[0] ? p->ssl_ctxs[0]->ssl_ctx : NULL;
    mbedtls_ssl_init(&hctx->ssl);
    int rc = hctx->ssl_ctx  /*(not NULL if properly configured)*/
      ? mbedtls_ssl_setup(&hctx->ssl, hctx->ssl_ctx)
      : MBEDTLS_ERR_SSL_INTERNAL_ERROR; /*(should not happen)*/
    if (0 == rc) {
        con->network_read = connection_read_cq_ssl;
        con->network_write = connection_write_cq_ssl;
        con->proto_default_port = 443; /* "https" */
        mod_mbedtls_patch_config(r, &hctx->conf);
    }
    else {
        elog(r->conf.errh, __FILE__, __LINE__, rc, "ssl_setup() failed");
        return HANDLER_ERROR;
    }

  #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
    mbedtls_ssl_set_user_data_p(&hctx->ssl, hctx);
  #endif

    mbedtls_ssl_set_bio(&hctx->ssl, (mbedtls_net_context *)&con->fd,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    /* (mbedtls_ssl_config *) is shared across multiple connections, which may
     * overlap, and so this debug setting is not reset upon connection close.
     * Once enabled, debug hook will remain so for this mbedtls_ssl_config */
    if (hctx->conf.ssl_log_noise) {/* volume level for debug message callback */
      #ifdef MBEDTLS_DEBUG_C
      #if MBEDTLS_VERSION_NUMBER >= 0x02000000 /* mbedtls 2.0.0 */
        mbedtls_debug_set_threshold(hctx->conf.ssl_log_noise);
      #endif
      #endif
        mbedtls_ssl_conf_dbg(hctx->ssl_ctx, mod_mbedtls_debug_cb,
                             (void *)(intptr_t)hctx->conf.ssl_log_noise);
    }

    return HANDLER_GO_ON;
}


static void
mod_mbedtls_detach(handler_ctx *hctx)
{
    /* step aside from further SSL processing
     * (used after handle_connection_shut_wr hook) */
    /* future: might restore prior network_read and network_write fn ptrs */
    hctx->con->is_ssl_sock = 0;
    /* if called after handle_connection_shut_wr hook, shutdown SHUT_WR */
    if (-1 == hctx->close_notify) shutdown(hctx->con->fd, SHUT_WR);
    hctx->close_notify = 1;
}


CONNECTION_FUNC(mod_mbedtls_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx || 1 == hctx->close_notify) return HANDLER_GO_ON;

    hctx->close_notify = -2;
    if (hctx->handshake_done) {
        mod_mbedtls_close_notify(hctx);
    }
    else {
        mod_mbedtls_detach(hctx);
    }

    return HANDLER_GO_ON;
}


static int
mod_mbedtls_close_notify (handler_ctx *hctx)
{
    if (1 == hctx->close_notify) return -2;

    int rc = mbedtls_ssl_close_notify(&hctx->ssl);
    switch (rc) {
      case 0:
        mod_mbedtls_detach(hctx);
        return -2;
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        return 0;
      default:
        elogf(hctx->r->conf.errh, __FILE__, __LINE__, rc,
          "addr:%s mbedtls_ssl_close_notify()",
          hctx->con->dst_addr_buf.ptr);
        __attribute_fallthrough__
      case MBEDTLS_ERR_NET_CONN_RESET:
        mbedtls_ssl_session_reset(&hctx->ssl);
        mod_mbedtls_detach(hctx);
        return -1;
    }
}


CONNECTION_FUNC(mod_mbedtls_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL != hctx) {
        con->plugin_ctx[p->id] = NULL;
        if (1 != hctx->close_notify)
            mod_mbedtls_close_notify(hctx); /*(one final try)*/
        handler_ctx_free(hctx);
    }

    return HANDLER_GO_ON;
}


#if defined(MBEDTLS_PEM_WRITE_C)
__attribute_noinline__
static void
https_add_ssl_client_cert (request_st * const r, const mbedtls_x509_crt * const peer)
{
    #define PEM_BEGIN_CRT "-----BEGIN CERTIFICATE-----\n"
    #define PEM_END_CRT   "-----END CERTIFICATE-----\n"
    unsigned char buf[4096];
    size_t olen;
    if (0 == mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
                                      peer->raw.p, peer->raw.len,
                                      buf, sizeof(buf), &olen))
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_CERT"),
                            (char *)buf, olen);
}
#endif


static void
https_add_ssl_client_subject (request_st * const r, const mbedtls_x509_name *name)
{
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */

    /* add components of client Subject DN */
    /* code block is similar to mbedtls_x509_dn_gets() */
    /* code block specialized for creating env vars of Subject DN components
     * and splits multi-valued RDNs into separate env vars for attribute=value*/
    size_t n = 0;
    const size_t prelen = sizeof("SSL_CLIENT_S_DN_")-1;
    char key[64] = "SSL_CLIENT_S_DN_";
    char buf[512]; /* MBEDTLS_X509_MAX_DN_NAME_SIZE is (256) */

    for (; name != NULL; name = name->next) {
        if (!name->oid.p)
            continue;
        const char *short_name = NULL;
      #if MBEDTLS_VERSION_NUMBER >= 0x04000000 /* mbedtls 4.0.0 */
       #if 0 /* OID interfaces in library/x509_oid.h are not public */
        if (0 != mbedtls_x509_oid_get_attr_short_name(&name->oid, &short_name))
       #endif
            continue;
      #else
        if (0 != mbedtls_oid_get_attr_short_name(&name->oid, &short_name))
            continue;
      #endif
        const size_t len = strlen(short_name);
        if (prelen+len >= sizeof(key)) continue;
        memcpy(key+prelen, short_name, len); /*(not '\0'-terminated)*/

        if (n+2+len+1+name->val.len > sizeof(buf)) continue;
        buf[n++] = ','; /*(", " at beginning is skipped outside loop below)*/
        buf[n++] = ' ';
        memcpy(buf+n, short_name, len);
        n += len;
        buf[n++] = '=';

        for (size_t i = 0; i < name->val.len; ++i) {
            unsigned char c = name->val.p[i];
            buf[n+i] = (c >= 32 && c != 127) ? c : '?';
        }

        http_header_env_set(r, key, prelen+len, buf+n, name->val.len);
        n += name->val.len;
    }

    /* mbedtls_x509_dn_gets() is not used to construct DN because that func does
     * not support non-ASCII UTF-8.  This func allows non-ASCII UTF-8 but does
     * not check for need to backslash-encode special chars.  This func
     * *assumes* a trusted and validated cert which does contain any chars which
     * need to be backslash-encoded in the stringified DN, even if such chars
     * are allowed in ASN.1 DN.  Above, CTLs are encoded as '?' above, even
     * though some are allowed if backslash-encoded.  Multi-valued RDNs are not
     * combined with '+' above, as name->next_merged is private in mbedtls 3.0.0
     */
    if (n > 2)
        http_header_env_set(r, CONST_STR_LEN("SSL_CLIENT_S_DN"), buf+2, n-2);

  #else  /* MBEDTLS_VERSION_NUMBER >= 0x04000000 *//* mbedtls 4.0.0 */

    const size_t prelen = sizeof("SSL_CLIENT_S_DN_")-1;
    char key[64] = "SSL_CLIENT_S_DN_";
    char buf[512]; /* MBEDTLS_X509_MAX_DN_NAME_SIZE is (256) */

    int tot = mbedtls_x509_dn_gets(buf, sizeof(buf), name);
    if (tot <= 0)
        return;

    for (char *v, *sep, *p = buf; (v = strchr(p, '=')); p = sep+2) {
        sep = strstr(p, ", ");
        if (sep == NULL)
            sep = buf+tot;

        const uint32_t len = (uint32_t)(v - p);
        if (prelen+len >= sizeof(key)) continue;
        memcpy(key+prelen, p, len); /*(not '\0'-terminated)*/

        /* XXX: different from code for mbedtls < 4.x above
         * - non-ASCII UTF-8 is escaped in resulting string
         * - multi-valued RDNs (separated by '+') are not parsed out below */
        const uint32_t n = (uint32_t)(sep - ++v);
        for (uint32_t i = 0; i < n; ++i) {
            unsigned char c = ((unsigned char *)v)[i];
            if (c < 32 || c == 127) v[i] = '?';
        }

        http_header_env_set(r, key, prelen+len, v, n);

        if (sep == buf+tot)
            break;
    }

    http_header_env_set(r, CONST_STR_LEN("SSL_CLIENT_S_DN"),
                        buf, (uint32_t)tot);

  #endif /* MBEDTLS_VERSION_NUMBER >= 0x04000000 *//* mbedtls 4.0.0 */
}


__attribute_cold__
static void
https_add_ssl_client_verify_err (buffer * const b, uint32_t status)
{
  #ifndef MBEDTLS_X509_REMOVE_INFO
    /* get failure string and translate newline to ':', removing last one */
    char buf[512];
    int n = mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", status);
    if (n > 0) {
        for (char *nl = buf; NULL != (nl = strchr(nl, '\n')); ++nl)
            nl[0] = ('\0' == nl[1] ? (--n, '\0') : ':');
        buffer_append_string_len(b, buf, n);
    }
  #else
    UNUSED(b);
    UNUSED(status);
  #endif
}


__attribute_noinline__
static void
https_add_ssl_client_entries (request_st * const r, handler_ctx * const hctx)
{
    /* Note: starting with mbedtls-2.17.0, peer cert is not available here if
     * MBEDTLS_SSL_KEEP_PEER_CERTIFICATE *is not* defined at compile time,
     * though default behavior is to have it defined.  However, since earlier
     * versions do keep the cert, but not set this define, attempt to retrieve
     * the peer cert and check for NULL before using it. */
    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&hctx->ssl);
    buffer *vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_VERIFY"));

    uint32_t rc = (NULL != crt)
      ? mbedtls_ssl_get_verify_result(&hctx->ssl)
      : 0xFFFFFFFF;
    if (0xFFFFFFFF == rc) { /*(e.g. no cert, or verify result not available)*/
        buffer_copy_string_len(vb, CONST_STR_LEN("NONE"));
        return;
    }
    else if (0 != rc) {
        buffer_copy_string_len(vb, CONST_STR_LEN("FAILED:"));
        https_add_ssl_client_verify_err(vb, rc);
        return;
    }
    else {
        buffer_copy_string_len(vb, CONST_STR_LEN("SUCCESS"));
    }

    https_add_ssl_client_subject(r, &crt->subject);

    /* mbedtls_x509_serial_gets() (inefficiently) formats to hex separated by
     * colons, but would differ from behavior of other lighttpd TLS modules */
  #ifdef __COVERITY__
    ck_assert(crt->serial.len); /*(otherwise, invalid crt returned above)*/
  #endif
    size_t i = 0; /* skip leading 0's per Distinguished Encoding Rules (DER) */
    while (i < crt->serial.len && crt->serial.p[i] == 0) ++i;
    if (i == crt->serial.len) --i;
    buffer_append_string_encoded_hex_uc(
      http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_M_SERIAL")),
      (char *)crt->serial.p+i, crt->serial.len-i);

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

  #if defined(MBEDTLS_PEM_WRITE_C)
    /* if (NULL != crt) (e.g. not PSK-based ciphersuite) */
    if (hctx->conf.ssl_verifyclient_export_cert)
        https_add_ssl_client_cert(r, crt);
  #endif
}


#if MBEDTLS_VERSION_NUMBER < 0x03020000 /* mbedtls 3.02.0 */
#define mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl) \
        (ssl)->MBEDTLS_PRIVATE(session)->MBEDTLS_PRIVATE(ciphersuite)
#define mbedtls_ssl_ciphersuite_get_name(info) \
        (info)->MBEDTLS_PRIVATE(name)
#endif

static void
http_cgi_ssl_env (request_st * const r, handler_ctx * const hctx)
{
    const char *s;

    s = mbedtls_ssl_get_version(&hctx->ssl);
    http_header_env_set(r, CONST_STR_LEN("SSL_PROTOCOL"), s, strlen(s));

    const int ciphersuite_id =
      mbedtls_ssl_get_ciphersuite_id_from_ssl(&hctx->ssl);
    const mbedtls_ssl_ciphersuite_t * const ciphersuite_info =
      mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);
    if (__builtin_expect( (NULL == ciphersuite_info), 0)) return;

    s = mbedtls_ssl_ciphersuite_get_name(ciphersuite_info);
    http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER"), s, strlen(s));

    {
        /* SSL_CIPHER_ALGKEYSIZE - Number of cipher bits (possible) */
        /* SSL_CIPHER_USEKEYSIZE - Number of cipher bits (actually used) */
      #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
        size_t algkeysize =
          mbedtls_ssl_ciphersuite_get_cipher_key_bitlen(ciphersuite_info);
        unsigned int usekeysize = algkeysize; /*(equivalent in modern ciphers)*/
      #elif MBEDTLS_VERSION_NUMBER >= 0x03000000 /* mbedtls 3.00.0 */
       #ifdef MBEDTLS_CIPHER_C
        /*(messy transition; ssl->transform is hidden in ssl_internal.h)*/
        const mbedtls_cipher_info_t * const cipher_info =
          mbedtls_cipher_info_from_type(
            ciphersuite_info->MBEDTLS_PRIVATE(cipher));
        if (__builtin_expect( (NULL == cipher_info), 0)) return;
        unsigned int algkeysize = cipher_info->MBEDTLS_PRIVATE(key_bitlen);
       #else
        if (1) return;
       #endif
        unsigned int usekeysize = algkeysize; /*(equivalent in modern ciphers)*/
      #else
        /* XXX: is usekeysize correct? XXX: reaching into ssl_internal.h here */
        unsigned int usekeysize =
          hctx->ssl.transform->cipher_ctx_enc.key_bitlen;
       #ifdef MBEDTLS_CIPHER_C
        unsigned int algkeysize =
          hctx->ssl.transform->cipher_ctx_enc.cipher_info->key_bitlen;
       #else
        unsigned int algkeysize = usekeysize;
       #endif
      #endif
        char buf[LI_ITOSTRING_LENGTH];
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                            buf, li_utostrn(buf, sizeof(buf), algkeysize));
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, li_utostrn(buf, sizeof(buf), usekeysize));
    }
}


REQUEST_FUNC(mod_mbedtls_handle_request_env)
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


REQUEST_FUNC(mod_mbedtls_handle_uri_raw)
{
    /* mod_mbedtls must be loaded prior to mod_auth
     * if mod_mbedtls is configured to set REMOTE_USER based on client cert */
    /* mod_mbedtls must be loaded after mod_extforward
     * if mod_mbedtls config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward, *unless* PROXY protocol
     * is enabled with extforward.hap-PROXY = "enable", in which case the
     * reverse is true: mod_extforward must be loaded after mod_mbedtls */
    plugin_data *p = p_d;
    handler_ctx *hctx = r->con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    mod_mbedtls_patch_config(r, &hctx->conf);
    if (hctx->conf.ssl_verifyclient) {
        mod_mbedtls_handle_request_env(r, p);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_mbedtls_handle_request_reset)
{
    plugin_data *p = p_d;
    r->plugin_ctx[p->id] = NULL; /* simple flag for request_env_patched */
    return HANDLER_GO_ON;
}


#if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */

static void
mod_mbedtls_refresh_plugin_ssl_ctx (server * const srv, plugin_ssl_ctx * const s)
{
    if (NULL == s->kp || NULL == s->pc || s->kp == s->pc->kp) return;
    mod_mbedtls_kp_rel(s->kp);
    mod_mbedtls_kp * const kp = s->kp = mod_mbedtls_kp_acq(s->pc);
    if (kp->need_chain) {
        kp->need_chain = 0; /*(attempt once to complete chain)*/
        if (0 != mod_mbedtls_construct_crt_chain(&kp->crt,
                                                 s->ssl_ca_file, srv->errh)) {
            /*(ignore error on cert refresh; admins should provide full chain)*/
        }
    }
    int rc = mbedtls_ssl_conf_own_cert(s->ssl_ctx, &kp->crt, &kp->pk);
    if (0 != rc)
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "PEM cert and private key did not verify (%s) (%s)",
              s->pc->ssl_pemfile->ptr, s->pc->ssl_privkey->ptr);
}


__attribute_cold__
static int
mod_mbedtls_refresh_plugin_cert_fail (server * const srv, plugin_cert * const pc)
{
    log_perror(srv->errh, __FILE__, __LINE__,
               "MTLS: unable to check/refresh cert key; "
               "continuing to use already-loaded %s",
               pc->ssl_privkey->ptr);
    return 0;
}


static int
mod_mbedtls_refresh_plugin_cert (server * const srv, plugin_cert * const pc)
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
    for (mod_mbedtls_kp **kpp = &pc->kp->next; *kpp; ) {
        mod_mbedtls_kp *kp = *kpp;
        if (kp->refcnt)
            kpp = &kp->next;
        else {
            *kpp = kp->next;
            mod_mbedtls_kp_free(kp);
        }
    }

    /* Note: check last modification timestamp only on privkey file, so when
     * 'mv' updated files into place from generation location, script should
     * update privkey last, after pem file (and OCSP stapling file) */
    struct stat st;
    if (0 != stat(pc->ssl_privkey->ptr, &st))
        return mod_mbedtls_refresh_plugin_cert_fail(srv, pc);
        /* ignore if stat() error; keep using existing crt/pk */
    if (TIME64_CAST(st.st_mtime) <= pc->pkey_ts)
        return 0; /* mtime match; no change */

    plugin_cert *npc =
      network_mbedtls_load_pemfile(srv, pc->ssl_pemfile, pc->ssl_privkey);
    if (NULL == npc)
        return mod_mbedtls_refresh_plugin_cert_fail(srv, pc);
        /* ignore if crt/pk error; keep using existing crt/pk */

    /*(future: if threaded, only one thread should update pcs)*/

    mod_mbedtls_kp * const kp = pc->kp;
    mod_mbedtls_kp * const nkp = npc->kp;
    nkp->next = kp;
    pc->pkey_ts = npc->pkey_ts;
    pc->kp = nkp;
    mod_mbedtls_kp_rel(kp);

    free(npc);
    return 1;
}


static void
mod_mbedtls_refresh_certs (server *srv, plugin_data * const p)
{
    if (NULL == p->cvlist) return;
    int newpcs = 0;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->k_id != 0) continue; /* k_id == 0 for ssl.pemfile */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            newpcs |= mod_mbedtls_refresh_plugin_cert(srv, cpv->v.v);
        }
    }

    if (newpcs && NULL != p->ssl_ctxs) {
        if (p->ssl_ctxs[0])
            mod_mbedtls_refresh_plugin_ssl_ctx(srv, p->ssl_ctxs[0]);
        /* refresh $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs[i];
            if (s && s != p->ssl_ctxs[0])
                mod_mbedtls_refresh_plugin_ssl_ctx(srv, s);
        }
    }
}

#endif /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */


TRIGGER_FUNC(mod_mbedtls_handle_trigger) {
    plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/

  #ifdef MBEDTLS_SSL_SESSION_TICKETS
    mod_mbedtls_session_ticket_key_check(p, cur_ts);
  #endif

  #if MBEDTLS_VERSION_NUMBER >= 0x03020000 /* mbedtls 3.02.0 */
    /* enable with mbedtls_ssl_conf_cert_cb() which runs unconditionally;
     * not enabled for mbedtls 2.x since refcnt not incr if SNI not present */
    /*if (!(cur_ts & 0x3ff))*/ /*(once each 1024 sec (~17 min))*/
        if (feature_refresh_certs)
            mod_mbedtls_refresh_certs(srv, p);
  #else
    UNUSED(feature_refresh_certs);
  #endif

    if (feature_refresh_crls)
        mod_mbedtls_refresh_crl_files(srv, p);

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_mbedtls_plugin_init (plugin *p);
int mod_mbedtls_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "mbedtls";
    p->init         = mod_mbedtls_init;
    p->cleanup      = mod_mbedtls_free;
    p->priv_defaults= mod_mbedtls_set_defaults;

    p->handle_connection_accept  = mod_mbedtls_handle_con_accept;
    p->handle_connection_shut_wr = mod_mbedtls_handle_con_shut_wr;
    p->handle_connection_close   = mod_mbedtls_handle_con_close;
    p->handle_uri_raw            = mod_mbedtls_handle_uri_raw;
    p->handle_request_env        = mod_mbedtls_handle_request_env;
    p->handle_request_reset      = mod_mbedtls_handle_request_reset;
    p->handle_trigger            = mod_mbedtls_handle_trigger;

    return 0;
}


/* cipher suites (taken from mbedtls/ssl_ciphersuites.[ch]) */

static const int suite_CHACHAPOLY_ephemeral[] = {
    /* Chacha-Poly ephemeral suites */
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  #endif
};

static const int suite_AES_256_ephemeral[] = {
    /* All AES-256 ephemeral suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8
  #endif
};

static const int suite_CAMELLIA_256_ephemeral[] = {
    /* All CAMELLIA-256 ephemeral suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
  #endif
};

static const int suite_ARIA_256_ephemeral[] = {
    /* All ARIA-256 ephemeral suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
  #endif
};

static const int suite_AES_128_ephemeral[] = {
    /* All AES-128 ephemeral suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8
  #endif
};

static const int suite_CAMELLIA_128_ephemeral[] = {
    /* All CAMELLIA-128 ephemeral suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
  #endif
};

static const int suite_ARIA_128_ephemeral[] = {
    /* All ARIA-128 ephemeral suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
  #endif
};

static const int suite_PSK_ephemeral[] = {
    /* The PSK ephemeral suites */
    MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,

    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
   ,MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
  #endif
};

#if 0
static const int suite_ECJPAKE[] = {
    /* The ECJPAKE suite */
    MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8
};
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
static const int suite_AES_256[] = {
    /* All AES-256 suites */
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
   ,MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8
  #endif
};
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
static const int suite_CAMELLIA_256[] = {
    /* All CAMELLIA-256 suites */
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
  #endif
};
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
static const int suite_ARIA_256[] = {
    /* All ARIA-256 suites */
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384
  #endif
};
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
static const int suite_AES_128[] = {
    /* All AES-128 suites */
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
   ,MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8
  #endif
};
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
static const int suite_CAMELLIA_128[] = {
    /* All CAMELLIA-128 suites */
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
  #endif
};
#endif

#if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
static const int suite_ARIA_128[] = {
    /* All ARIA-128 suites */
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
   ,MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256
  #endif
};
#endif

#ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
static const int suite_RSA_PSK[] = {
    /* The RSA PSK suites */
    MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,

    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
};
#endif

static const int suite_PSK[] = {
    /* The PSK suites */
    MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384,

    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256
};

#ifdef MBEDTLS_SSL_PROTO_TLS1
static const int suite_3DES[] = {
    /* 3DES suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
  #endif
    MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA
};
#endif

#ifdef MBEDTLS_SSL_PROTO_TLS1
static const int suite_RC4[] = {
    /* RC4 suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA,
    MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,
    MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA,
  #endif
    MBEDTLS_TLS_PSK_WITH_RC4_128_SHA
};
#endif

#ifdef MBEDTLS_SSL_PROTO_SSL3
static const int suite_weak[] = {
    /* Weak suites */
    MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA
};
#endif

static const int suite_null[] = {
    /* NULL suites */
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA,
    MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256,
    MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA,
  #endif

  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_NULL_SHA256,
    MBEDTLS_TLS_RSA_WITH_NULL_SHA,
    MBEDTLS_TLS_RSA_WITH_NULL_MD5,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA,
  #endif
    MBEDTLS_TLS_PSK_WITH_NULL_SHA384,
    MBEDTLS_TLS_PSK_WITH_NULL_SHA256,
    MBEDTLS_TLS_PSK_WITH_NULL_SHA
};

/* TLSv1.2 cipher list (supported in mbedtls)
 * marked with minimum version MBEDTLS_SSL_MINOR_VERSION_3 in
 *   ciphersuite_definitions[] and then sorted by ciphersuite_preference[]
 *   from mbedtls library/ssl_ciphersuites.c */
static const int suite_TLSv12[] = {
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8,
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256
};

#ifdef MBEDTLS_SSL_PROTO_TLS1
/* TLSv1.0 cipher list (supported in mbedtls)
 * marked with minimum version MBEDTLS_SSL_MINOR_VERSION_1 in
 *   ciphersuite_definitions[] and then sorted by ciphersuite_preference[]
 *   from mbedtls library/ssl_ciphersuites.c */
/* XXX: intentionally not including overlapping eNULL ciphers */
static const int suite_TLSv10[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA
  #endif
};
#endif

/* HIGH cipher list (mapped from openssl list to mbedtls) */
static const int suite_HIGH[] = {
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  #endif
    MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
  #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
    MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256,
  #endif
  #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
  #endif
    MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384,
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
    MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256,
};


/* true if RC4 or weak or NULL cipher suite
 *   (These ciphersuites are excluded from openssl "DEFAULT")
 * This is a subset of ciphers excluded for mod_openssl "!aNULL:!eNULL:!EXP" */
static int
mod_mbedtls_ssl_is_weak_ciphersuite (int id)
{
  #ifdef MBEDTLS_SSL_PROTO_TLS1
    for (uint32_t i = 0; i < sizeof(suite_RC4)/sizeof(suite_RC4[0]); ++i) {
        if (id == suite_RC4[i]) return 1;
    }
  #endif
  #ifdef MBEDTLS_SSL_PROTO_SSL3
    for (uint32_t i = 0; i < sizeof(suite_weak)/sizeof(suite_weak[0]); ++i) {
        if (id == suite_weak[i]) return 1;
    }
  #endif
    for (uint32_t i = 0; i < sizeof(suite_null)/sizeof(suite_null[0]); ++i) {
        if (id == suite_null[i]) return 1;
    }
    return 0;
}


static int
mod_mbedtls_ssl_DEFAULT_ciphersuite (server *srv, int *ids, int nids, int idsz)
{
    /* obtain default ciphersuite list and filter out weak or NULL */
    const int *dids = mbedtls_ssl_list_ciphersuites();
    int i = 0;
    while (dids[i] != 0) ++i;

    if (i >= idsz - (nids + 1)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: error: too many ciphersuites during list expand");
        return -1;
    }

    for (i = 0; dids[i] != 0; ++i) {
        if (!mod_mbedtls_ssl_is_weak_ciphersuite(dids[i]))
            ids[++nids] = dids[i];
    }

    return nids;
}


static int
mod_mbedtls_ssl_append_ciphersuite (server *srv, int *ids, int nids, int idsz, const int *x, int xsz)
{
    if (xsz >= idsz - (nids + 1)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: error: too many ciphersuites during list expand");
        return -1;
    }

    for (int i = 0; i < xsz; ++i)
        ids[++nids] = x[i];

    return nids;
}


static int
mod_mbedtls_ssl_conf_ciphersuites (server *srv, plugin_config_socket *s, buffer *ciphersuites, const buffer *cipherstring)
{
    /* reference: https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
     * Attempt to parse *some* keywords from Ciphersuites and CipherString
     * !!! openssl uses a *different* naming scheme than does mbedTLS !!!
     * Since Ciphersuites in openssl takes only TLSv1.3 suites, and mbedTLS
     * does not currently support TLSv1.3, mapping of those names is not
     * currently provided.  Note that CipherString does allow cipher suites to
     * be listed, and this code does not currently attempt to provide mapping */

    char n[128]; /*(most ciphersuite names are about 40 chars)*/
    int ids[512];
    int nids = -1;
    const int idsz = (int)(sizeof(ids)/sizeof(*ids)-1);
    int crt_profile_default = 0;

    if (ciphersuites) {
        buffer *b = ciphersuites;
        buffer_to_upper(b); /*(ciphersuites are all uppercase (currently))*/
        for (const char *e, *p = b->ptr; p; p = e ? e+1 : NULL) {
            e = strchr(p, ':');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            if (len >= sizeof(n)) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: skipped ciphersuite; too long: %.*s",
                  (int)len, p);
                continue;
            }
            memcpy(n, p, len);
            n[len] = '\0';

            int id = mbedtls_ssl_get_ciphersuite_id(n);
            if (0 == id) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: skipped ciphersuite; not recognized: %.*s",
                  (int)len, n);
                continue;
            }

            /* allow any ciphersuite if explicitly listed, even weak or eNULL */
          #if 0
            if (mod_mbedtls_ssl_is_weak_ciphersuite(id)) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: skipped ciphersuite; weak or NULL suite: %.*s",
                  (int)len, n);
                continue;
            }
          #endif

            if (nids >= idsz) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: skipped ciphersuite; too many listed: %.*s",
                  (int)len, n);
                continue;
            }

            ids[++nids] = id;
        }
    }

    /* XXX: openssl config for CipherString=... is excessively complex.
     * If there is a need to enable specific ciphersuites, then that
     * can be accomplished with mod_mbedtls by specifying the list in
     * Ciphersuites=... in the ssl.openssl.ssl-conf-cmd directive.
     * (Alternatively, build mbedtls with specific set of cipher suites
     *  or modify mod_mbedtls code to specify the precise list).
     *
     * The tokens parsed here are a quick attempt to handle a few cases
     *
     * XXX: not done: could make a list of ciphers with bitflag of attributes
     *      to make future combining easier */
    if (cipherstring && !buffer_is_blank(cipherstring)) {
        const buffer *b = cipherstring;
        const char *e = b->ptr;

        /* XXX: not done: no checking for duplication of ciphersuites
         * even if tokens overlap or are repeated */

        /* XXX: not done: might walk string and build up exclude list of !xxxxx
         * ciphersuites and walk string again, excluding as result list built */

        /* manually handle first token, since one-offs apply */
        /* (openssl syntax NOT fully supported) */
        int default_suite = 0;
        #define strncmp_const(s,cs) strncmp((s),(cs),sizeof(cs)-1)
        if (0 == strncmp_const(e, "!ALL") || 0 == strncmp_const(e, "-ALL")) {
            /* "!ALL" excluding all ciphers does not make sense; ignore */
            e += sizeof("!ALL")-1; /* same as sizeof("-ALL")-1 */
        }
        else if (0 == strncmp_const(e, "!DEFAULT")
              || 0 == strncmp_const(e, "-DEFAULT")) {
            /* "!DEFAULT" excluding default ciphers is empty list; no effect */
            e += sizeof("!DEFAULT")-1; /* same as sizeof("-DEFAULT")-1 */
        }
        else if (0 == strncmp_const(e, "DEFAULT")) {
            e += sizeof("DEFAULT")-1;
            default_suite = 1;
        }
        else if (0 == /* effectively the same as "DEFAULT" */
                 strncmp_const(e, "ALL:!COMPLEMENTOFDEFAULT:!eNULL")) {
            e += sizeof("ALL:!COMPLEMENTOFDEFAULT:!eNULL")-1;
            default_suite = 1;
        }
        else if (0 == strncmp_const(e, "SUITEB128")
              || 0 == strncmp_const(e, "SUITEB128ONLY")
              || 0 == strncmp_const(e, "SUITEB192")) {
            default_suite = 0;
            crt_profile_default = -1;
            mbedtls_ssl_conf_cert_profile(s->ssl_ctx,
                                          &mbedtls_x509_crt_profile_suiteb);
            /* re-initialize mbedtls_ssl_config defaults */
          #if MBEDTLS_VERSION_NUMBER < 0x03020000 /* mbedtls 3.02.0 */
            mbedtls_mpi_free(&s->ssl_ctx->MBEDTLS_PRIVATE(dhm_P));
            mbedtls_mpi_free(&s->ssl_ctx->MBEDTLS_PRIVATE(dhm_G));
          #endif
            int rc = mbedtls_ssl_config_defaults(s->ssl_ctx,
                                                 MBEDTLS_SSL_IS_SERVER,
                                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                                 MBEDTLS_SSL_PRESET_SUITEB);
            if (0 != rc) {
                elog(srv->errh, __FILE__,__LINE__, rc,
                     "Init of ssl config context SUITEB defaults failed");
                return 0;
            }
            if (0 == strncmp_const(e, "SUITEB192")) {
                static const int ssl_preset_suiteb192[] = {
                    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    0
                };
                static const mbedtls_x509_crt_profile crt_profile_suiteb192 = {
                    /* Only SHA-384 */
                    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ),
                    /* Only ECDSA */
                    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECDSA ) |
                    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECKEY ),
                  #if defined(MBEDTLS_ECP_C)
                    /* Only NIST P-384 */
                    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP384R1 ),
                  #else
                    0,
                  #endif
                    3072,
                };
                mbedtls_ssl_conf_ciphersuites(s->ssl_ctx, ssl_preset_suiteb192);
                mbedtls_ssl_conf_cert_profile(s->ssl_ctx,
                                              &crt_profile_suiteb192);
              #if defined(MBEDTLS_DHM_C)
                mbedtls_ssl_conf_dhm_min_bitlen(s->ssl_ctx, 3072);
              #endif
            }
            e += (0 == strncmp_const(e, "SUITEB128ONLY"))
                 ? sizeof("SUITEB128ONLY")-1
                 : sizeof("SUITEB128")-1;
            if (*e)
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: ignoring cipher string after SUITEB: %s", e);
            return 1;
        }
        else if (0 == strncmp_const(e,
                  "EECDH+AESGCM:CHACHA20:!PSK:!DHE")) {
            e += sizeof(
                  "EECDH+AESGCM:CHACHA20:!PSK:!DHE")-1;
          #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
            if (nids + 10 >= idsz)
          #else
            if (nids + 6 >= idsz)
          #endif
            {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: error: too many ciphersuites during list expand");
                return 0;
            }
          #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
            ids[++nids] = MBEDTLS_TLS1_3_AES_256_GCM_SHA384;
            ids[++nids] = MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256;
            ids[++nids] = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;
            ids[++nids] = MBEDTLS_TLS1_3_AES_128_CCM_SHA256;
          #endif
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
            ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
            ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
            ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
        }
        else if (0 == strncmp_const(e,
                  "ECDHE+AESGCM:ECDHE+AES256:CHACHA20:!SHA1:!SHA256:!SHA384")
              || 0 == strncmp_const(e,
                  "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")) {
            e += sizeof(
                  "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")-1;
          #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
            if (nids + 13 >= idsz)
          #else
            if (nids + 9 >= idsz)
          #endif
            {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: error: too many ciphersuites during list expand");
                return 0;
            }
          #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
            ids[++nids] = MBEDTLS_TLS1_3_AES_256_GCM_SHA384;
            ids[++nids] = MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256;
            ids[++nids] = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;
            ids[++nids] = MBEDTLS_TLS1_3_AES_128_CCM_SHA256;
          #endif
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
            ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
            ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM;
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
            ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
            ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
          #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
            ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
          #endif
        }

        if (e != b->ptr && *e != ':' && *e != '\0') {
            log_error(srv->errh, __FILE__, __LINE__,
              "MTLS: error: missing support for cipher list: %s", b->ptr);
            return 0;
        }

        if (default_suite) {
            crt_profile_default = 1;
            nids =
              mod_mbedtls_ssl_DEFAULT_ciphersuite(srv, ids, nids, idsz);
            if (-1 == nids) return 0;
        }

        /* not handled: "ALL" is "DEFAULT" and "RC4" */
        /* not handled: "COMPLEMENTOFALL" is "eNULL" */

        int rc = 1;
        if (e == b->ptr || *e == '\0') --e; /*initial condition for loop below*/
        do {
            const char * const p = e+1;
            e = strchr(p, ':');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            if (0 == len) continue;
            if (len >= sizeof(n)) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: skipped ciphersuite; too long: %.*s",
                  (int)len, p);
                continue;
            }
            char c = (*p == '!' || *p == '-' || *p == '+') ? *p : 0;
            size_t nlen = c ? len-1 : len;
            memcpy(n, c ? p+1 : p, nlen);
            n[nlen] = '\0';

            /* not handled: !xxxxx -xxxxx and most +xxxxx */
            if (c) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: error: missing support for cipher list: %s", b->ptr);
            }

            /* ignore @STRENGTH sorting and ignore @SECLEVEL=n */
            char *a = strchr(n, '@');
            if (a) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: ignored %s in %.*s", a, (int)len, p);
                *a = '\0';
                nlen = (size_t)(a - n);
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("TLSv1.2"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_TLSv12,
                         (int)(sizeof(suite_TLSv12)/sizeof(*suite_TLSv12)));
                if (-1 == nids) return 0;
                continue;
            }

          #ifdef MBEDTLS_SSL_PROTO_TLS1
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("TLSv1.0"))) {
                crt_profile_default = 1;
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_TLSv10,
                         (int)(sizeof(suite_TLSv10)/sizeof(*suite_TLSv10)));
                if (-1 == nids) return 0;
                continue;
            }
          #endif

            /* handle popular recommendations
             *   ssl.cipher-list = "EECDH+AESGCM:EDH+AESGCM"
             *   ssl.cipher-list = "AES256+EECDH:AES256+EDH"
             * which uses AES hardware acceleration built into popular CPUs */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("ECDHE+AESGCM"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("EECDH+AESGCM"))) {
              #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
                if (nids + 6 >= idsz)
              #else
                if (nids + 4 >= idsz)
              #endif
                {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: error: too many ciphersuites during list expand");
                    return 0;
                }
              #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
                ids[++nids] = MBEDTLS_TLS1_3_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS1_3_AES_128_GCM_SHA256;
              #endif
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
                ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
                continue;
            }
          #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("DHE+AESGCM"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("EDH+AESGCM"))) {
                if (nids + 2 >= idsz) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: error: too many ciphersuites during list expand");
                    return 0;
                }
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
                continue;
            }
          #endif
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES256+EECDH"))) {
              #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
                if (nids + 9 >= idsz)
              #else
                if (nids + 8 >= idsz)
              #endif
                {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: error: too many ciphersuites during list expand");
                    return 0;
                }
              #if defined(MBEDTLS_SSL_PROTO_TLS1_3)
                ids[++nids] = MBEDTLS_TLS1_3_AES_256_GCM_SHA384;
              #endif
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM;
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
                ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
                ids[++nids] = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
                ids[++nids] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
                continue;
            }
          #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES256+EDH"))) {
                if (nids + 5 >= idsz) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: error: too many ciphersuites during list expand");
                    return 0;
                }
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM;
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
                ids[++nids] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8;
                continue;
            }
          #endif

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("HIGH"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_HIGH,
                         (int)(sizeof(suite_HIGH)/sizeof(*suite_HIGH)));
                if (-1 == nids) return 0;
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES256"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_AES_256_ephemeral,
                         (int)(sizeof(suite_AES_256_ephemeral)
                              /sizeof(*suite_AES_256_ephemeral)));
                if (-1 == nids) return 0;
              #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_AES_256,
                         (int)(sizeof(suite_AES_256)/sizeof(*suite_AES_256)));
                if (-1 == nids) return 0;
              #endif
                /* XXX: not done: AES256 PSK suites */
                if (nlen == sizeof("AES256")-1) continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES128"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_AES_128_ephemeral,
                         (int)(sizeof(suite_AES_128_ephemeral)
                              /sizeof(*suite_AES_128_ephemeral)));
                if (-1 == nids) return 0;
              #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_AES_128,
                         (int)(sizeof(suite_AES_128)/sizeof(*suite_AES_128)));
                if (-1 == nids) return 0;
              #endif
                /* XXX: not done: AES128 PSK suites */
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA256"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_CAMELLIA_256_ephemeral,
                         (int)(sizeof(suite_CAMELLIA_256_ephemeral)
                              /sizeof(*suite_CAMELLIA_256_ephemeral)));
                if (-1 == nids) return 0;
              #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_CAMELLIA_256,
                         (int)(sizeof(suite_CAMELLIA_256)
                              /sizeof(*suite_CAMELLIA_256)));
                if (-1 == nids) return 0;
              #endif
                /* XXX: not done: CAMELLIA256 PSK suites */
                if (nlen == sizeof("CAMELLIA256")-1) continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA128"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_CAMELLIA_128_ephemeral,
                         (int)(sizeof(suite_CAMELLIA_128_ephemeral)
                              /sizeof(*suite_CAMELLIA_128_ephemeral)));
                if (-1 == nids) return 0;
              #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_CAMELLIA_128,
                         (int)(sizeof(suite_CAMELLIA_128)
                              /sizeof(*suite_CAMELLIA_128)));
                if (-1 == nids) return 0;
              #endif
                /* XXX: not done: CAMELLIA128 PSK suites */
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("ARIA256"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("ARIA"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_ARIA_256_ephemeral,
                         (int)(sizeof(suite_ARIA_256_ephemeral)
                              /sizeof(*suite_ARIA_256_ephemeral)));
                if (-1 == nids) return 0;
              #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_ARIA_256,
                         (int)(sizeof(suite_ARIA_256)/sizeof(*suite_ARIA_256)));
                if (-1 == nids) return 0;
              #endif
                /* XXX: not done: ARIA256 PSK suites */
                if (nlen == sizeof("ARIA256")-1) continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("ARIA128"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("ARIA"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_ARIA_128_ephemeral,
                         (int)(sizeof(suite_ARIA_128_ephemeral)
                              /sizeof(*suite_ARIA_128_ephemeral)));
                if (-1 == nids) return 0;
              #if MBEDTLS_VERSION_NUMBER < 0x04000000 /* mbedtls 4.0.0 */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_ARIA_128,
                         (int)(sizeof(suite_ARIA_128)/sizeof(*suite_ARIA_128)));
                if (-1 == nids) return 0;
              #endif
                /* XXX: not done: ARIA128 PSK suites */
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CHACHA20"))) {
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_CHACHAPOLY_ephemeral,
                         (int)(sizeof(suite_CHACHAPOLY_ephemeral)
                              /sizeof(*suite_CHACHAPOLY_ephemeral)));
                if (-1 == nids) return 0;
                /* XXX: not done: CHACHA20 PSK suites */
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("PSK"))) {
                /* XXX: intentionally not including overlapping eNULL ciphers */
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_PSK_ephemeral,
                         (int)(sizeof(suite_PSK_ephemeral)
                              /sizeof(*suite_PSK_ephemeral)));
                if (-1 == nids) return 0;
              #ifdef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_RSA_PSK,
                         (int)(sizeof(suite_RSA_PSK)/sizeof(*suite_RSA_PSK)));
                if (-1 == nids) return 0;
              #endif
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_PSK,
                         (int)(sizeof(suite_PSK)/sizeof(*suite_PSK)));
                if (-1 == nids) return 0;
                continue;
            }

          #ifdef MBEDTLS_SSL_PROTO_TLS1
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("3DES"))) {
                crt_profile_default = 1;
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_3DES,
                         (int)(sizeof(suite_3DES)/sizeof(*suite_3DES)));
                if (-1 == nids) return 0;
                continue;
            }
          #endif

          #ifdef MBEDTLS_SSL_PROTO_TLS1
            /* not recommended, but permitted if explicitly requested */
            /* "RC4" is same as openssl "COMPLEMENTOFALL" */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("RC4"))) {
                crt_profile_default = 1;
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_RC4,
                         (int)(sizeof(suite_RC4)/sizeof(*suite_RC4)));
                if (-1 == nids) return 0;
                continue;
            }
          #endif

            /* not recommended, but permitted if explicitly requested */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("NULL"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("eNULL"))) {
                crt_profile_default = 1;
                nids = mod_mbedtls_ssl_append_ciphersuite(srv, ids, nids, idsz,
                         suite_null,
                         (int)(sizeof(suite_null)/sizeof(*suite_null)));
                if (-1 == nids) return 0;
                continue;
            }

            const mbedtls_ssl_ciphersuite_t *info =
              mbedtls_ssl_ciphersuite_from_string(n);
            if (info) {
                if (nids + 1 >= idsz) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: error: too many ciphersuites during list expand");
                    return 0;
                }
                /* WTH?  why private and no accessor func? */
                ids[++nids] = info->MBEDTLS_PRIVATE(id);
                continue;
            }

            {
                log_error(srv->errh, __FILE__, __LINE__,
                  "MTLS: error: missing support for cipher list: %.*s",
                  (int)len, p);
                rc = 0;
                continue;
            }
        } while (e);
        if (0 == rc) return 0;
    }

    if (-1 == nids) {
        /* Do not set a default if ssl.cipher-list was set (and we are
         * are processing ssl.openssl.ssl-conf-cmd, not ssl.cipher-list) */
        if (cipherstring != s->ssl_cipher_list && s->ssl_cipher_list)
            return 1;

        /* obtain default ciphersuite list and filter out RC4, weak, and NULL */
        nids =
          mod_mbedtls_ssl_DEFAULT_ciphersuite(srv, ids, nids,
                                              sizeof(ids)/sizeof(*ids));
        if (-1 == nids) return 0;
    }

    if (nids >= idsz) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: error: too many ciphersuites during list expand");
        return 0;
    }
    ids[++nids] = 0; /* terminate list */
    ++nids;

    if (0 == crt_profile_default)
        mbedtls_ssl_conf_cert_profile(s->ssl_ctx,
                                      &mbedtls_x509_crt_profile_next);
    else if (1 == crt_profile_default)
        mbedtls_ssl_conf_cert_profile(s->ssl_ctx,
                                      &mbedtls_x509_crt_profile_default);
    /* else if (-1 == crt_profile_default) *//*(cert_profile set further up)*/

    /* ciphersuites list must be persistent for lifetime of mbedtls_ssl_config*/
    free(s->ciphersuites);
    s->ciphersuites = ck_malloc(nids * sizeof(int));
    memcpy(s->ciphersuites, ids, nids * sizeof(int));

    mbedtls_ssl_conf_ciphersuites(s->ssl_ctx, s->ciphersuites);
    return 1;
}


#if MBEDTLS_VERSION_NUMBER < 0x03010000 /* mbedtls 3.01.0 */
static int
mod_mbedtls_ssl_append_curve (server *srv, mbedtls_ecp_group_id *ids, int nids, int idsz, const mbedtls_ecp_group_id id)
{
    if (1 >= idsz - (nids + 1)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: error: too many curves during list expand");
        return -1;
    }
    ids[++nids] = id;
    return nids;
}


static int
mod_mbedtls_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist)
{
    mbedtls_ecp_group_id ids[512];
    int nids = -1;
    const int idsz = (int)(sizeof(ids)/sizeof(*ids)-1);
    const mbedtls_ecp_curve_info * const curve_info = mbedtls_ecp_curve_list();

    const char *groups = curvelist && !buffer_is_blank(curvelist)
      ? curvelist->ptr
      :
       #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        "x25519"
       #endif
       #if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        ":"
        #endif
        "secp256r1"
       #endif
       #if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) \
         || defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        ":"
        #endif
        "secp384r1"
       #endif
       #if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) \
         || defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)  \
         || defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        ":"
        #endif
        "x448"
       #endif
        ;
    for (const char *e; groups; groups = e ? e+1 : NULL) {
        const char * const n = groups;
        e = strchr(n, ':');
        size_t len = e ? (size_t)(e - n) : strlen(n);
        /* similar to mbedtls_ecp_curve_info_from_name() */
        const mbedtls_ecp_curve_info *info;
        for (info = curve_info; info->grp_id != MBEDTLS_ECP_DP_NONE; ++info) {
            if (0 == strncmp(info->name, n, len) && info->name[len] == '\0')
                break;
        }
        if (info->grp_id == MBEDTLS_ECP_DP_NONE) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: unrecognized curve: %.*s; ignored", (int)len, n);
            continue;
        }

        nids = mod_mbedtls_ssl_append_curve(srv, ids, nids, idsz, info->grp_id);
        if (-1 == nids) return 0;
    }

    /* XXX: mod_openssl configures "prime256v1" if curve list not specified,
     * but mbedtls provides a list of supported curves if not explicitly set */
    if (-1 == nids) return 1; /* empty list; no-op */

    ids[++nids] = MBEDTLS_ECP_DP_NONE; /* terminate list */
    ++nids;

    /* curves list must be persistent for lifetime of mbedtls_ssl_config */
    if (s->curves) free(s->curves);
    s->curves = ck_malloc(nids * sizeof(mbedtls_ecp_group_id));
    memcpy(s->curves, ids, nids * sizeof(mbedtls_ecp_group_id));

    mbedtls_ssl_conf_curves(s->ssl_ctx, s->curves);
    return 1;
}
#else
static int
mod_mbedtls_ssl_append_curve (server *srv, uint16_t *ids, int nids, int idsz, const uint16_t id)
{
    if (1 >= idsz - (nids + 1)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "MTLS: error: too many curves during list expand");
        return -1;
    }
    ids[++nids] = id;
    return nids;
}


static int
mod_mbedtls_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist)
{
    uint16_t ids[512];
    int nids = -1;
    const int idsz = (int)(sizeof(ids)/sizeof(*ids)-1);
    const mbedtls_ecp_curve_info * const curve_info = mbedtls_ecp_curve_list();

    const char *groups = curvelist && !buffer_is_blank(curvelist)
      ? curvelist->ptr
      :
       #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        "x25519"
       #endif
       #if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        ":"
        #endif
        "secp256r1"
       #endif
       #if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) \
         || defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        ":"
        #endif
        "secp384r1"
       #endif
       #if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        #if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) \
         || defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)  \
         || defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        ":"
        #endif
        "x448"
       #endif
        ;
    for (const char *e; groups; groups = e ? e+1 : NULL) {
        const char * const n = groups;
        e = strchr(n, ':');
        size_t len = e ? (size_t)(e - n) : strlen(n);
        /* similar to mbedtls_ecp_curve_info_from_name() */
        const mbedtls_ecp_curve_info *info;
        for (info = curve_info; info->tls_id != 0; ++info) {
            if (0 == strncmp(info->name, n, len) && info->name[len] == '\0')
                break;
        }
        if (info->tls_id == 0) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: unrecognized curve: %.*s; ignored", (int)len, n);
            continue;
        }

        nids = mod_mbedtls_ssl_append_curve(srv, ids, nids, idsz, info->tls_id);
        if (-1 == nids) return 0;
    }

    /* XXX: mod_openssl configures "prime256v1" if curve list not specified,
     * but mbedtls provides a list of supported curves if not explicitly set */
    if (-1 == nids) return 1; /* empty list; no-op */

    ids[++nids] = 0; /* terminate list */
    ++nids;

    /* curves list must be persistent for lifetime of mbedtls_ssl_config */
    if (s->curves) free(s->curves);
    s->curves = ck_malloc(nids * sizeof(uint16_t));
    memcpy(s->curves, ids, nids * sizeof(uint16_t));

    mbedtls_ssl_conf_groups(s->ssl_ctx, s->curves);
    return 1;
}
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03010000 */ /* mbedtls 3.01.0 */


static int
mod_mbedtls_ssl_conf_dhparameters(server *srv, plugin_config_socket *s, const buffer *dhparameters)
{
  #if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);
    int rc = mbedtls_dhm_parse_dhmfile(&dhm, dhparameters->ptr);
    if (0 != rc)
        elogf(srv->errh, __FILE__,__LINE__, rc,
             "mbedtls_dhm_parse_dhmfile() %s", dhparameters->ptr);
    else {
        rc = mbedtls_ssl_conf_dh_param_ctx(s->ssl_ctx, &dhm);
        if (0 != rc)
            elogf(srv->errh, __FILE__,__LINE__, rc,
                 "mbedtls_ssl_conf_dh_param_ctx() %s", dhparameters->ptr);
    }
    mbedtls_dhm_free(&dhm);
    return (0 == rc);
  #else
    UNUSED(srv);
    UNUSED(s);
    UNUSED(dhparameters);
    return 1;
  #endif
}


#if MBEDTLS_VERSION_NUMBER < 0x03020000 /* mbedtls 3.02.0 */
static void
mod_mbedtls_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *b, int max)
{
    /* note: mbedtls does not support TLSv1.3 well on the server-side
     * until well into the mbedtls 3.x branch: e.g. mbedtls 3.6.1 */
    int v = MBEDTLS_SSL_MINOR_VERSION_3; /* default: TLS v1.2 */
    if (NULL == b) /* default: min TLSv1.2, max TLSv1.3 */
      #ifdef MBEDTLS_SSL_MINOR_VERSION_4
        v = max ? MBEDTLS_SSL_MINOR_VERSION_4 : MBEDTLS_SSL_MINOR_VERSION_3;
      #else
        v = MBEDTLS_SSL_MINOR_VERSION_3;
      #endif
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        v = max
          ?
           #ifdef MBEDTLS_SSL_MINOR_VERSION_4
            MBEDTLS_SSL_MINOR_VERSION_4  /* TLS v1.3 */
           #else
            MBEDTLS_SSL_MINOR_VERSION_3  /* TLS v1.2 */
           #endif
          :
           #if defined(MBEDTLS_SSL_MINOR_VERSION_1)
            MBEDTLS_SSL_MINOR_VERSION_1  /* TLS v1.0 */
           #elif defined(MBEDTLS_SSL_MINOR_VERSION_2)
            MBEDTLS_SSL_MINOR_VERSION_2  /* TLS v1.1 */
           #else
            MBEDTLS_SSL_MINOR_VERSION_3  /* TLS v1.2 */
           #endif
            ;
  #ifdef MBEDTLS_SSL_MINOR_VERSION_1
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.0")))
        v = MBEDTLS_SSL_MINOR_VERSION_1; /* TLS v1.0 */
  #endif
  #ifdef MBEDTLS_SSL_MINOR_VERSION_2
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.1")))
        v = MBEDTLS_SSL_MINOR_VERSION_2; /* TLS v1.1 */
  #endif
  #ifdef MBEDTLS_SSL_MINOR_VERSION_3
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        v = MBEDTLS_SSL_MINOR_VERSION_3; /* TLS v1.2 */
  #endif
  #ifdef MBEDTLS_SSL_MINOR_VERSION_4
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        v = MBEDTLS_SSL_MINOR_VERSION_4; /* TLS v1.3 */
  #endif
    else {
      #ifndef MBEDTLS_SSL_MINOR_VERSION_4
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s TLSv1.3 not supported "
                      "by mod_mbedtls; using TLSv1.2",
                      max ? "MaxProtocol" : "MinProtocol");
        else
      #endif
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1"))
                 || buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1.2"))) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s %s ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
            return;
        }
        else {
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s %s invalid; ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
            return;
        }
    }

    max
      ? mbedtls_ssl_conf_max_version(s->ssl_ctx,MBEDTLS_SSL_MAJOR_VERSION_3,v)
      : mbedtls_ssl_conf_min_version(s->ssl_ctx,MBEDTLS_SSL_MAJOR_VERSION_3,v);
}
#else /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */ /* mbedtls 3.02.0 */
static void
mod_mbedtls_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *b, int max)
{
  #ifndef MBEDTLS_SSL_PROTO_TLS1_3 /* use TLSv1.2 if TLSv1.3 not avail */
  #define MBEDTLS_SSL_VERSION_TLS1_3 MBEDTLS_SSL_VERSION_TLS1_2
  #endif
  #if MBEDTLS_VERSION_NUMBER >= 0x03060100 /* mbedtls 3.6.1 */
    /* note: mbedtls does not support TLSv1.3 well on the server-side
     * until well into the mbedtls 3.x branch: e.g. mbedtls 3.6.1 */
    int v = MBEDTLS_SSL_VERSION_TLS1_3; /* default: TLS v1.3 */
    if (NULL == b) /* default: min TLSv1.3, max TLSv1.3 */
        v = MBEDTLS_SSL_VERSION_TLS1_3;
  #else
    int v = MBEDTLS_SSL_VERSION_TLS1_2; /* default: TLS v1.2 */
    if (NULL == b) /* default: min TLSv1.2, max TLSv1.3 */
        v = max ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2;
  #endif
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        v = max ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        v = MBEDTLS_SSL_VERSION_TLS1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        v = MBEDTLS_SSL_VERSION_TLS1_3;
    else {
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1.2"))) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s %s ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
            return;
        }
        else {
            log_error(srv->errh, __FILE__, __LINE__,
                      "MTLS: ssl.openssl.ssl-conf-cmd %s %s invalid; ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
            return;
        }
    }
  #ifndef MBEDTLS_SSL_PROTO_TLS1_3
  #undef MBEDTLS_SSL_VERSION_TLS1_3
  #endif

    max
      ? mbedtls_ssl_conf_max_tls_version(s->ssl_ctx, v)
      : mbedtls_ssl_conf_min_tls_version(s->ssl_ctx, v);
}
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */ /* mbedtls 3.02.0 */

#if MBEDTLS_VERSION_NUMBER < 0x03000000 /* mbedtls 3.00.0 */
#ifdef MBEDTLS_SSL_SERVER_NAME_INDICATION
#ifdef MBEDTLS_SSL_ALPN
/*
 * XXX: forked from mbedtls
 *
 * ssl_parse_client_hello() is forked and modified from mbedtls
 *   library/ssl_srv.c:ssl_parse_client_hello()
 * due to limitations in mbedtls hooks.  Other than fetching input, ssl is not
 * modified here so that it can be reprocessed during handshake.
 *
 * It would be beneficial to have a callback after parsing client hello and all
 * extensions, and before certificate selection.  (SNI extension might occur
 * prior to ALPN extension, and a different certificate may be needed by
 * ALPN "acme-tls/1".)  Alternatively, mbedtls could provide an API to clear
 * &ssl->handshake->sni_key_cert, rather than forcing ssl_append_key_cert() with
 * no other option.
 */
static int ssl_parse_client_hello( mbedtls_ssl_context *ssl, handler_ctx *hctx )
{
    int ret;
    size_t msg_len;
    unsigned char *buf;

    /*
     * If renegotiating, then the input was read with mbedtls_ssl_read_record(),
     * otherwise read it ourselves manually in order to support SSLv2
     * ClientHello, which doesn't use the same record layer format.
     */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ssl->renego_status == MBEDTLS_SSL_INITIAL_HANDSHAKE )
#endif
    {
        if( ( ret = mbedtls_ssl_fetch_input( ssl, 5 ) ) != 0 )
        {
            /* No alert on a read error. */
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
            return( ret );
        }
    }

    buf = ssl->in_hdr;

    /*
     * TLS Client Hello
     *
     * Record layer:
     *     0  .   0   message type
     *     1  .   2   protocol version
     *     3  .   11  DTLS: epoch + record sequence number
     *     3  .   4   message length
     */
    if( buf[0] != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    /*(not supported in lighttpd for now)*/
    /*(mbedtls_ssl_in_hdr_len() and mbedtls_ssl_hs_hdr_len() are in
     * mbedtls/ssl_internal.h but simple enough to repeat here) */
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    msg_len = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE )
    {
        /* Set by mbedtls_ssl_read_record() */
        msg_len = ssl->in_hslen;
    }
    else
#endif
    {
        if( msg_len > MBEDTLS_SSL_IN_CONTENT_LEN )
        {
            return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        }

        if( ( ret = mbedtls_ssl_fetch_input( ssl,
                       5 /*mbedtls_ssl_in_hdr_len( ssl )*/ + msg_len ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
            return( ret );
        }
    }

    buf = ssl->in_msg;

    /*
     * Handshake layer:
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   DTLS only: message seqence number
     *     6  .   8   DTLS only: fragment offset
     *     9  .  11   DTLS only: fragment length
     */
    if( msg_len < 4 /*mbedtls_ssl_hs_hdr_len( ssl )*/ )
    {
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    if( buf[0] != MBEDTLS_SSL_HS_CLIENT_HELLO )
    {
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    /* We don't support fragmentation of ClientHello (yet?) */
    if( buf[1] != 0 ||
        msg_len != 4u /*mbedtls_ssl_hs_hdr_len( ssl )*/ + ( ( buf[2] << 8 ) | buf[3] ) )
    {
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    buf += 4; /* mbedtls_ssl_hs_hdr_len( ssl ); */
    msg_len -= 4; /* mbedtls_ssl_hs_hdr_len( ssl ); */

    /*
     * ClientHello layer:
     *     0  .   1   protocol version
     *     2  .  33   random bytes (starting with 4 bytes of Unix time)
     *    34  .  35   session id length (1 byte)
     *    35  . 34+x  session id
     *   35+x . 35+x  DTLS only: cookie length (1 byte)
     *   36+x .  ..   DTLS only: cookie
     *    ..  .  ..   ciphersuite list length (2 bytes)
     *    ..  .  ..   ciphersuite list
     *    ..  .  ..   compression alg. list length (1 byte)
     *    ..  .  ..   compression alg. list
     *    ..  .  ..   extensions length (2 bytes, optional)
     *    ..  .  ..   extensions (optional)
     */

    /*
     * Minimal length (with everything empty and extensions omitted) is
     * 2 + 32 + 1 + 2 + 1 = 38 bytes. Check that first, so that we can
     * read at least up to session id length without worrying.
     */
    if( msg_len < 38 )
    {
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /*
     * Check and save the protocol version
     */
    int major_ver, minor_ver;
    mbedtls_ssl_read_version( &major_ver, &minor_ver,
                      ssl->conf->transport, buf );

    /*
     * Check the session ID length and save session ID
     */
    const size_t sess_len = buf[34];

    if( sess_len > sizeof( ssl->session_negotiate->id ) ||
        sess_len + 34 + 2 > msg_len ) /* 2 for cipherlist length field */
    {
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /*
     * Check the cookie length and content
     */
    const size_t ciph_offset = 35 + sess_len;

    const size_t ciph_len = ( buf[ciph_offset + 0] << 8 )
                          | ( buf[ciph_offset + 1]      );

    if( ciph_len < 2 ||
        ciph_len + 2 + ciph_offset + 1 > msg_len || /* 1 for comp. alg. len */
        ( ciph_len % 2 ) != 0 )
    {
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /*
     * Check the compression algorithms length and pick one
     */
    const size_t comp_offset = ciph_offset + 2 + ciph_len;

    const size_t comp_len = buf[comp_offset];

    if( comp_len < 1 ||
        comp_len > 16 ||
        comp_len + comp_offset + 1 > msg_len )
    {
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* Do not parse the extensions if the protocol is SSLv3 */
#if defined(MBEDTLS_SSL_PROTO_SSL3)
    if( ( major_ver != 3 ) || ( minor_ver != 0 ) )
    {
#endif
        /*
         * Check the extension length
         */
        const size_t ext_offset = comp_offset + 1 + comp_len;
        size_t ext_len;
        if( msg_len > ext_offset )
        {
            if( msg_len < ext_offset + 2 )
            {
                return( MBEDTLS_ERR_SSL_DECODE_ERROR );
            }

            ext_len = ( buf[ext_offset + 0] << 8 )
                    | ( buf[ext_offset + 1]      );

            if( msg_len != ext_offset + 2 + ext_len )
            {
                return( MBEDTLS_ERR_SSL_DECODE_ERROR );
            }
        }
        else
            ext_len = 0;

        unsigned char *ext = buf + ext_offset + 2;

        while( ext_len != 0 )
        {
            unsigned int ext_id;
            unsigned int ext_size;
            if ( ext_len < 4 ) {
                return( MBEDTLS_ERR_SSL_DECODE_ERROR );
            }
            ext_id   = ( ( ext[0] <<  8 ) | ( ext[1] ) );
            ext_size = ( ( ext[2] <<  8 ) | ( ext[3] ) );

            if( ext_size + 4 > ext_len )
            {
                return( MBEDTLS_ERR_SSL_DECODE_ERROR );
            }
            switch( ext_id )
            {
#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found alpn extension" ) );

                /*(lighttpd-specific)*/
                ret = mod_mbedtls_alpn_select_cb(hctx, ext + 4, ext_size);
                if( ret != 0 )
                    return( ret );
                break;
#endif /* MBEDTLS_SSL_ALPN */

            default:
                break;
            }

            ext_len -= 4 + ext_size;
            ext += 4 + ext_size;
        }
#if defined(MBEDTLS_SSL_PROTO_SSL3)
    }
#endif

    return( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* MBEDTLS_VERSION_NUMBER < 0x03000000 */ /* mbedtls 3.00.0 */
