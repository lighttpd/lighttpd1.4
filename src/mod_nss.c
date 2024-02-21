/*
 * mod_nss - Network Security Services (NSS) support for lighttpd
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * Portions supporting mod_nss_ssl_conf_ciphersuites() (see end of file)
 *   Copyright 2001-2004 The Apache Software Foundation
 */
/*
 * NSS docs: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS
 *
 * NSS documentation is seriously lacking and man pages exist only for apps;
 * be prepared to slog through organic piles of NSS library code
 *
 * Note: If session tickets are -not- disabled with
 *     ssl.openssl.ssl-conf-cmd = ("Options" => "-SessionTicket")
 *   NSS never rotates server ticket encryption key (STEK) while running.
 *   Therefore, if session tickets are enabled, lighttpd server should be
 *   restarted (by an external job) at least every 24 hours.  Restarting
 *   lighttpd generates a new key that is shared by lighttpd workers.  There
 *   is no mechanism implemented in lighttpd mod_nss to share STEK between
 *   independent lighttpd servers.  ssl.stek-file is not used in mod_nss.
 *
 *   NSS provides SSL_SetSessionTicketKeyPair(pubKey, privKey) to set RSA keys.
 *   However, to match behavior of other lighttpd TLS modules, it seems we want
 *   to set the private struct ssl_self_encrypt_keys in lib/ssl/sslsnce.c
 *   instead of the private struct ssl_self_encrypt_key_pair.
 *   sslSelfEncryptKeys ssl_self_encrypt_keys contains:
 *     PRUint8 keyName[SELF_ENCRYPT_KEY_NAME_LEN];
 *     PK11SymKey *encKey;
 *     PK11SymKey *macKey;
 *   (see lib/ssl/sslsnce.c:GenerateSelfEncryptKeys())
 *   PK11SymKey *masterSecret in ssl3CipherSpec in ssl3State in sslSessionID
 *     is private in lib/ssl/ssl3con.c
 *
 *   Update: NSS developer explains:
 *   "The way that we currently operate is to tie the session key encryption to
 *    the server public key. Which only works if you have an RSA key configured"
 *   https://bugzilla.mozilla.org/show_bug.cgi?id=1673254
 *
 * not implemented:
 * - session ticket rotation (see comments above)
 * - OCSP Must Staple detection
 * - ssl.verifyclient.depth
 * - ssl.openssl.ssl-conf-cmd Ciphersuite
 *
 * future:
 * - consider SSL_AlertReceivedCallback() to set SSLAlertCallback
 *   in order to (optionally) log alerts, and to abort connection if fatal alert
 * - consider using experimental API for cipher suite choice in lib/ssl/sslexp.h
 *   SSL_CipherSuiteOrderGet
 *   SSL_CipherSuiteOrderSet
 * - detect CLOSE_NOTIFY from client
 * - feature options
 *   - SSL_ENABLE_FALSE_START
 *   - SSL_ENABLE_DELEGATED_CREDENTIALS
 *   - SSL_ENABLE_0RTT_DATA
 *   - SSL_SUPPRESS_END_OF_EARLY_DATA
 * - crypto option using FreeBL
 *   "A core element of NSS is FreeBL, a base library providing hash functions,
 *    big number calculations, and cryptographic algorithms."
 *   "Softoken is an NSS module that exposes most FreeBL functionality as a
 *    PKCS#11 module."
 *   "PR_GetRandomNoise - Produces a random value for use as a seed value for
 *    another random number generator."
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

#ifdef __has_include
#if __has_include(<nspr4/nspr.h>)
#define NSS_NSPR_INCLUDE_PREFIX_VER
#else
#if __has_include(<nspr/nspr.h>)
#define NSS_NSPR_INCLUDE_PREFIX
#endif
#endif
#if __has_include(<nss3/nss.h>)
#define NSS_INCLUDE_PREFIX_VER
#else
#if __has_include(<nss/nss.h>)
#define NSS_INCLUDE_PREFIX
#endif
#endif
#endif

#ifdef NSS_NSPR_INCLUDE_PREFIX_VER
#include <nspr4/nspr.h>
#include <nspr4/private/pprio.h> /* see mod_nss_io_ctor() comments */
#else
#ifdef NSS_NSPR_INCLUDE_PREFIX
#include <nspr/nspr.h>
#include <nspr/private/pprio.h> /* see mod_nss_io_ctor() comments */
#else
#include <nspr.h>
#include <private/pprio.h> /* see mod_nss_io_ctor() comments */
#endif
#endif

#ifdef NSS_INCLUDE_PREFIX_VER
#include <nss3/nss.h>
#include <nss3/nssb64.h>
#include <nss3/keyhi.h>
#include <nss3/pk11pub.h>
#include <nss3/secder.h>
#include <nss3/secerr.h>
#include <nss3/ssl.h>
#include <nss3/sslproto.h>
#else
#ifdef NSS_INCLUDE_PREFIX
#include <nss/nss.h>
#include <nss/nssb64.h>
#include <nss/keyhi.h>
#include <nss/pk11pub.h>
#include <nss/secder.h>
#include <nss/secerr.h>
#include <nss/ssl.h>
#include <nss/sslproto.h>
#else
#include <nss.h>
#include <nssb64.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <secder.h>
#include <secerr.h>
#include <ssl.h>
#include <sslproto.h>
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
    char must_staple;
    CERTCertificate *ssl_pemfile_x509;
    SECKEYPrivateKey *ssl_pemfile_pkey;
    SSLExtraServerCertData ssl_credex;
    const buffer *ssl_stapling_file;
    unix_time64_t ssl_stapling_loadts;
    unix_time64_t ssl_stapling_nextts;
    SECItemArray OCSPResponses;
    SECItem OCSPResponse;
} plugin_cert;

typedef struct {
    PRFileDesc *model;
    SSLVersionRange protos;
    PRBool ssl_compression;
    int8_t ssl_session_ticket;
} plugin_ssl_ctx;

typedef struct {
    plugin_cert *pc;

    /*(used only during startup; not patched)*/
    unsigned char ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned char ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    const buffer *ssl_cipher_list;
    array *ssl_conf_cmd;

    /*(copied from plugin_data for socket ssl_ctx config)*/
    unsigned char ssl_session_ticket;
    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;

    PRFileDesc *model;
    SSLVersionRange protos;
    PRBool ssl_compression;
} plugin_config_socket; /*(used at startup during configuration)*/

typedef struct {
    /* SNI per host: w/ COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    plugin_cert *pc;
    CERTCertList *ssl_ca_file;
    CERTCertList *ssl_ca_dn_file;

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
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id]; */
static plugin_data *plugin_data_singleton;
#define LOCAL_SEND_BUFSIZE 16384 /* DEFAULT_MAX_RECORD_SIZE */
static char *local_send_buffer;

typedef struct {
    PRFileDesc *ssl;
    request_st *r;
    connection *con;
    int8_t close_notify;
    uint8_t alpn;
    int8_t ssl_session_ticket;
    int handshake;
    size_t pending_write;
    plugin_config conf;
    int verify_status;
    buffer *tmp_buf;
    log_error_st *errh;
} handler_ctx;


static handler_ctx *
handler_ctx_init (void)
{
    return ck_calloc(1, sizeof(handler_ctx));
}


static void mod_nss_io_dtor (PRFileDesc *ssl);

static void
handler_ctx_free (handler_ctx *hctx)
{
    mod_nss_io_dtor(hctx->ssl);
    free(hctx);
}


__attribute_cold__
static void elog(log_error_st * const errh,
                 const char * const file, const int line,
                 const char * const msg)
{
    /* error logging convenience function that decodes NSS result codes */
    const PRErrorCode rc = PR_GetError();
    const char *s = PR_ErrorToName(rc);
    log_error(errh, file, line, "NSS: %s: (%s) %s",
              msg, s ? s : "", PR_ErrorToString(rc, 0));
}


__attribute_cold__
__attribute_format__((__printf__, 4, 5))
static void elogf(log_error_st * const errh,
                  const char * const file, const int line,
                  const char * const fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    elog(errh, file, line, msg);
}


static PRFileDesc *
mod_nss_io_ctor (int fd, PRFileDesc *model, log_error_st *errh)
{
    /* WTH? Why not a public PR_ImportTCPSocket() interface from NSPR?
     * (and PR_GetInheritedFD() is not a great replacement interface to
     *  fudge NSPR_INHERIT_FDS in environment for each connection)
     *
     * #include <nspr4/private/pprio.h>
     * Use internal routines to set up PRFileDesc.  Perform actions underlying
     * PR_ImportTCPSocket() to avoid excess work done by PR_ImportTCPSocket(),
     * which includes closing the fd if there is a failure.  Could pass 0 as fd
     * to PR_AllocFileDesc() to avoid NSPR setting O_NONBLOCK since already set.
     * Instead, employ simpler PR_CreateSocketPollFd() and change methods table,
     * which handles _PR_ImplicitInitialization() (PR_AllocFileDesc() does not).
     * (WTH?: PR_AllocFileDesc() has limit fd < FD_SETSIZE when XP_UNIX defined)
     * Note: since bypassing PR_ImportTCPSocket() this might not work on Windows
     * which expects prfd->secret->af to be set to AF_INET.
     */
  #if defined(_WIN32) && !defined(__CYGWIN__)
    PRFileDesc *prfd = PR_ImportTCPSocket(fd);
    if (NULL == prfd) {
        elog(errh, __FILE__, __LINE__, "PR_ImportTCPSocket()");
        return NULL;
    }
  #else
    /*PRFileDesc *prfd = PR_AllocFileDesc(0, PR_GetTCPMethods());*/
    PRFileDesc *prfd = PR_CreateSocketPollFd(fd);
    if (NULL == prfd) {
        elog(errh, __FILE__, __LINE__, "PR_CreateSocketPollFd()");
        return NULL;
    }
    /*PR_ChangeFileDescNativeHandle(prfd, fd);*/
    prfd->methods = PR_GetTCPMethods();
    /*prfd->dtor    = PR_FreeFileDesc();*/ /* PR_FreeFileDesc() is private */
  #endif

    /* set prfd->secret->nonblocking flag */
    PRSocketOptionData data;
    data.option = PR_SockOpt_Nonblocking;
    data.value.non_blocking = PR_TRUE;
    if (PR_SetSocketOption(prfd, &data) != PR_SUCCESS) {
        elog(errh, __FILE__, __LINE__, "PR_SocketSetSocketOption()");
        PR_DestroySocketPollFd(prfd); /* PR_FreeFileDesc() is private */
        return NULL;
    }

    PRFileDesc *ssl = SSL_ImportFD(model, prfd);
    if (NULL == ssl) {
        elog(errh, __FILE__, __LINE__, "SSL_ImportFD()");
        PR_DestroySocketPollFd(prfd); /* PR_FreeFileDesc() is private */
        return NULL;
    }

    return ssl;
}


static void
mod_nss_io_detach (PRFileDesc *ssl)
{
  #if 0 /* PR_PopIOLayer() forbids pop of PR_NSPR_IO_LAYER */
    PRFileDesc *prfd = PR_PopIOLayer(ssl, PR_NSPR_IO_LAYER);
    if (prfd) {
        PR_ChangeFileDescNativeHandle(prfd, -1);
        PR_DestroySocketPollFd(prfd); /* PR_FreeFileDesc() is private */
    }
  #else
    /*(results in close(-1) and EBADF from PR_Close() in mod_nss_io_dtor())*/
    PRFileDesc *prfd = PR_GetIdentitiesLayer(ssl, PR_NSPR_IO_LAYER);
    if (prfd)
        PR_ChangeFileDescNativeHandle(prfd, -1);
  #endif
}


static void
mod_nss_io_dtor (PRFileDesc *ssl)
{
    if (NULL == ssl) return;
    mod_nss_io_detach(ssl);
    PR_Close(ssl);
}


static int
mod_nss_load_file (const char * const fn, SECItem * const d, log_error_st *errh)
{
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, errh, PORT_Alloc, PORT_Free);
    if (NULL == data) return -1;
    d->type = siBuffer;
    d->data = (unsigned char *)data;
    d->len  = (unsigned int)dlen;
    return 0;
}


static void
mod_nss_secitem_wipe (SECItem * const d)
{
    /* safer than SECITEM_ZfreeItem() */
    if (NULL == d) return;
    if (d->data) {
        if (d->len) ck_memzero(d->data, d->len); /*safer than PORT_Memset()*/
        PORT_Free(d->data); /* ck_memzero() is safer than PORT_ZFree() */
        d->data = NULL;
    }
    d->len = 0;
}


INIT_FUNC(mod_nss_init)
{
    plugin_data_singleton = (plugin_data *)ck_calloc(1, sizeof(plugin_data));
    return plugin_data_singleton;
}


static int mod_nss_init_once_nss (void)
{
    if (ssl_is_init) return 1;
    ssl_is_init = 1;

    /*PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);*//*implicit on first use*/

    if (!NSS_IsInitialized() && NSS_NoDB_Init(NULL) < 0)
        return 0;

    if (SSL_OptionSetDefault(SSL_ENABLE_SSL2, PR_FALSE) < 0)
        return 0;
    if (SSL_OptionSetDefault(SSL_ENABLE_SSL3, PR_FALSE) < 0)
        return 0;
    /* XXX: lighttpd is single threaded and so SSL_NO_LOCKS is desirable,
     *      but NSS crashes if SSL_NO_LOCKS option is set to PR_TRUE.
     *      (Crash in SSL3_SendAlert() call to PR_GetMonitorEntryCount()
     *       with NULL ptr to monitor (mon))
     *      NSS lib/ssl/sslimpl.h macros such as ssl_HaveSSL3HandshakeLock(ss),
     *      plus some other .c files use macros without first checking if
     *      (!ss->opt.noLocks): PZ_InMonitor() PZ_InMonitor() PZ_InMonitor() */
    /*if (SSL_OptionSetDefault(SSL_NO_LOCKS, PR_TRUE) < 0)*/
    if (SSL_OptionSetDefault(SSL_NO_LOCKS, PR_FALSE) < 0)
        return 0;
    if (SSL_OptionSetDefault(SSL_NO_CACHE, PR_TRUE) < 0)
        return 0;
    if (SSL_OptionSetDefault(SSL_ENABLE_SESSION_TICKETS, PR_TRUE) < 0)
        return 0;
    if (SSL_OptionSetDefault(SSL_ENABLE_ALPN, PR_TRUE) < 0)
        return 0;
    if (SSL_OptionSetDefault(SSL_ENABLE_RENEGOTIATION,
                             SSL_RENEGOTIATE_NEVER) < 0)
        return 0;

    if (NSS_SetDomesticPolicy() < 0)
        return 0;

    local_send_buffer = ck_malloc(LOCAL_SEND_BUFSIZE);
    return 1;
}


static void mod_nss_free_nss (void)
{
    if (!ssl_is_init) return;

    NSS_Shutdown();

    free(local_send_buffer);
    ssl_is_init = 0;
}


static int
mod_nss_cert_is_active (const CERTCertificate *crt)
{
    PRTime notBefore, notAfter;
    SECStatus rc = CERT_GetCertTimes(crt, &notBefore, &notAfter);
    const unix_time64_t now = log_epoch_secs;
    return (rc == SECSuccess
            && notBefore/1000000 <= now && now <= notAfter/1000000);
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


static CERTCertificateList *
mod_nss_load_pem_file (const char *fn, log_error_st *errh)
{
    if (!mod_nss_init_once_nss()) return NULL;

    SECItem f;
    int rc = mod_nss_load_file(fn, &f, errh);
    if (rc < 0) return NULL;

    rc = -1;
    CERTCertificateList *chain = NULL;
    do {
        int count = 0;
        char *b = (char *)f.data;
        for (; (b = strstr(b, PEM_BEGIN_CERT)); b += sizeof(PEM_BEGIN_CERT)-1)
            ++count;
        b = (char *)f.data;
        for (; (b = strstr(b, PEM_BEGIN_TRUSTED_CERT));
                b += sizeof(PEM_BEGIN_TRUSTED_CERT)-1)
            ++count;
        if (0 == count) {
            if (NULL != strstr((char *)f.data, "-----")) {
                rc = 0;
                break;
            }
            /*(fall through and treat as DER)*/
        }

        PLArenaPool *arena = PORT_NewArena(4096);
        if (NULL == arena)
            break;

        chain = (CERTCertificateList *)
          PORT_ArenaAlloc(arena, sizeof(CERTCertificateList));
        if (NULL == chain) {
            PORT_FreeArena(arena, PR_FALSE);
            break;
        }

        chain->arena = arena;
        chain->len = count ? count : 1;
        chain->certs = (SECItem *)PORT_ArenaZAlloc(arena,
                                                   chain->len*sizeof(SECItem));
        if (NULL == chain->certs)
            break;

        if (0 == count) {
            /* treat as DER */
            if (NULL == SECITEM_AllocItem(arena, chain->certs+0, f.len)) {
                PORT_SetError(SEC_ERROR_IO);
                break;
            }
            memcpy(chain->certs[0].data, f.data, (chain->certs[0].len = f.len));
            rc = 0;
            break;
        }

        int i = 0;
        for (char *e = (char *)f.data; (b = strstr(e, PEM_BEGIN_CERT)); ++i) {
            b += sizeof(PEM_BEGIN_CERT)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_CERT);
            if (NULL == e) break;
            uint32_t len = (uint32_t)(e - b);
            e += sizeof(PEM_END_CERT)-1;
            if (NULL == NSSBase64_DecodeBuffer(arena, chain->certs+i, b, len))
                break;
        }
        for (char *e=(char *)f.data; (b=strstr(e,PEM_BEGIN_TRUSTED_CERT)); ++i){
            b += sizeof(PEM_BEGIN_TRUSTED_CERT)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_TRUSTED_CERT);
            if (NULL == e) break;
            uint32_t len = (uint32_t)(e - b);
            e += sizeof(PEM_END_TRUSTED_CERT)-1;
            if (NULL == NSSBase64_DecodeBuffer(arena, chain->certs+i, b, len))
                break;
        }
        if (i == count)
            rc = 0;
        else
            PORT_SetError(SEC_ERROR_IO);
    } while (0);

    mod_nss_secitem_wipe(&f);

    if (rc < 0) {
        elogf(errh, __FILE__, __LINE__, "error loading %s", fn);
        if (chain)
            CERT_DestroyCertificateList(chain);
        return NULL;
    }

    return chain;
}


static CERTCertificate *
mod_nss_load_pem_crts (const char *fn, log_error_st *errh, CERTCertificateList **pchain)
{
    *pchain = mod_nss_load_pem_file(fn, errh);
    if (NULL == *pchain) return NULL;

    CERTCertificate *cert = CERT_NewTempCertificate(NULL, (*pchain)->certs+0,
                                                    NULL, PR_FALSE, PR_TRUE);
    if (NULL == cert) {
        CERT_DestroyCertificateList(*pchain);
        *pchain = NULL;
    }
    else if (!mod_nss_cert_is_active(cert)) {
        log_error(errh, __FILE__, __LINE__,
          "NSS: inactive/expired X509 certificate '%s'", fn);
    }

    return cert;
}

static CERTCertList *
mod_nss_cert_list (CERTCertificateList *crts)
{
    SECStatus rc = SECFailure;
    CERTCertificate *cert = NULL;
    CERTCertList *clist = CERT_NewCertList();
    if (NULL != clist) {
        for (int i = 0; i < crts->len; ++i) {
            cert = CERT_NewTempCertificate(NULL, crts->certs+i,
                                           NULL, PR_FALSE, PR_TRUE);
            if (NULL == cert) break;
            rc = CERT_AddCertToListTail(clist, cert);
            if (rc < 0) break;
        }
    }

    if (rc < 0 || NULL == cert) {
        if (cert) CERT_DestroyCertificate(cert);
        if (clist) CERT_DestroyCertList(clist);
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    return clist;
}


static CERTCertList *
mod_nss_load_config_crts (const char *fn, log_error_st *errh)
{
    CERTCertificateList *crts = mod_nss_load_pem_file(fn, errh);
    if (NULL == crts) return NULL;

    CERTCertList *clist = NULL;
    SECStatus rc =
      CERT_ImportCAChainTrusted(crts->certs,crts->len,certUsageUserCertImport);
    if (rc == SECSuccess)
        clist = mod_nss_cert_list(crts);
    else {
        elogf(errh, __FILE__, __LINE__, "CERT_ImportCAChainTrusted() %s", fn);
        CERT_DestroyCertificateList(crts);
        return NULL;
    }

    CERT_DestroyCertificateList(crts);
    return clist;
}


static CERTCertList *
mod_nss_load_config_dncrts (const char *fn, log_error_st *errh)
{
    CERTCertificateList *crts = mod_nss_load_pem_file(fn, errh);
    if (NULL == crts) return NULL;

    CERTCertList *clist = mod_nss_cert_list(crts);

    CERT_DestroyCertificateList(crts);
    return clist;
}


static void
mod_nss_free_config_crls (CERTCertificateList *crls)
{
    if (NULL == crls) return;
    CERTCertDBHandle * const dbhandle = CERT_GetDefaultCertDB();
    for (int i = 0; i < crls->len; ++i)
        CERT_UncacheCRL(dbhandle, crls->certs+i);
    CERT_DestroyCertificateList(crls);
}


static CERTCertificateList *
mod_nss_load_config_crls (const char *fn, log_error_st *errh)
{
    /*(similar start to other mod_nss_load_config_*())*/
    if (!mod_nss_init_once_nss()) return NULL;

    SECItem f;
    int rc = mod_nss_load_file(fn, &f, errh);
    if (rc < 0) return NULL;

    rc = -1;
    CERTCertificateList *chain = NULL;
    CERTCertDBHandle * const dbhandle = CERT_GetDefaultCertDB();
    do {
        int count = 0;
        char *b = (char *)f.data;
        for (; (b = strstr(b, PEM_BEGIN_X509_CRL));
                b += sizeof(PEM_BEGIN_X509_CRL)-1)
            ++count;
        if (0 == count) {
            rc = 0;
            break;
        }

        PLArenaPool *arena = PORT_NewArena(4096);
        if (NULL == arena)
            break;

        chain = (CERTCertificateList *)
          PORT_ArenaAlloc(arena, sizeof(CERTCertificateList));
        if (NULL == chain) {
            PORT_FreeArena(arena, PR_FALSE);
            break;
        }

        chain->arena = arena;
        chain->len = count;
        chain->certs = (SECItem *)PORT_ArenaAlloc(arena, count*sizeof(SECItem));
        if (NULL == chain->certs)
            break;

        int i = 0;
        for (char *e = (char *)f.data; (b = strstr(e,PEM_BEGIN_X509_CRL)); ++i){
            b += sizeof(PEM_BEGIN_X509_CRL)-1;
            if (*b == '\r') ++b;
            if (*b == '\n') ++b;
            e = strstr(b, PEM_END_X509_CRL);
            if (NULL == e) break;
            uint32_t len = (uint32_t)(e - b);
            e += sizeof(PEM_END_X509_CRL)-1;
            chain->certs[i].type = 0;
            chain->certs[i].data = NULL;
            chain->certs[i].len  = 0;
            if (NULL == NSSBase64_DecodeBuffer(arena, chain->certs+i, b, len))
                break;
            /* using ephemeral db, so cache CRL instead of CERT_ImportCRL() */
            if (CERT_CacheCRL(dbhandle, chain->certs+i) < 0)
                break;
        }
        if (i == count)
            rc = 0;
        else
            PORT_SetError(SEC_ERROR_IO);
    } while (0);

    mod_nss_secitem_wipe(&f);

    if (rc < 0) {
        elogf(errh, __FILE__, __LINE__, "error loading %s", fn);
        if (chain)
            CERT_DestroyCertificateList(chain);
        return NULL;
    }

    return chain;
}


static SECItem *
mod_nss_cert_get_publicValue (SECKEYPublicKey *pubKey)
{
    /*(lib/pkcs12/p12d.c:sec_pkcs12_get_public_value_and_type() private)*/
    /*(lib/pk11wrap/pk11akey.c:pk11_MakeIDFromPublicKey() private, hashes)*/
    /*(lib/crmf/crmfcont.c:crmf_get_public_value() public but incomplete)*/
    switch (pubKey->keyType) {
      case dsaKey: return &pubKey->u.dsa.publicValue;
      case dhKey:  return &pubKey->u.dh.publicValue;
      case rsaKey: return &pubKey->u.rsa.modulus;
      case ecKey:  return &pubKey->u.ec.publicValue;
      default:     return NULL;
    }
}


static SECKEYPrivateKey *
mod_nss_load_config_pkey (const char *fn, CERTCertificate *cert, log_error_st *errh)
{
    /* NSS does not provide convenient mechanisms to read PEM or DER private key
     * instead expecting PKCS12-format, which is not the convention used by many
     * other TLS modules */

    /*(similar start to other mod_nss_load_config_*())*/
    if (!mod_nss_init_once_nss()) return NULL;

    SECItem f;
    int rc = mod_nss_load_file(fn, &f, errh);
    if (rc < 0) return NULL;

    SECItem der = { 0, NULL, 0 };
    PK11SlotInfo *slot = NULL;
    SECKEYPrivateKey *pkey = NULL;
    SECStatus src = SECFailure;
    do {
        /*(expecting single private key in file, so first match)*/
        char *b, *e;
        if ((b = strstr((char *)f.data, PEM_BEGIN_PKEY))
            && (e = strstr(b, PEM_END_PKEY)))
            b += sizeof(PEM_BEGIN_PKEY)-1;
        else if ((b = strstr((char *)f.data, PEM_BEGIN_EC_PKEY))
                 && (e = strstr(b, PEM_END_EC_PKEY)))
            b += sizeof(PEM_BEGIN_EC_PKEY)-1;
        else if ((b = strstr((char *)f.data, PEM_BEGIN_RSA_PKEY))
                 && (e = strstr(b, PEM_END_RSA_PKEY)))
            b += sizeof(PEM_BEGIN_RSA_PKEY)-1;
        else if ((b = strstr((char *)f.data, PEM_BEGIN_DSA_PKEY))
                 && (e = strstr(b, PEM_END_DSA_PKEY)))
            b += sizeof(PEM_BEGIN_DSA_PKEY)-1;
        else if ((b = strstr((char *)f.data, PEM_BEGIN_ANY_PKEY))
                 && (e = strstr(b, PEM_END_ANY_PKEY)))
            b += sizeof(PEM_BEGIN_ANY_PKEY)-1;
        else if (NULL == strstr((char *)f.data, "-----")) {
            der = f; /*(copy struct)*/
            f.type = 0;
            f.data = NULL;
            f.len = 0;
            b = (char *)der.data;
        }
        else
            break;
        if (*b == '\r') ++b;
        if (*b == '\n') ++b;

        if (NULL == der.data
            && NULL == NSSBase64_DecodeBuffer(NULL, &der, b, (uint32_t)(e - b)))
            break;

        slot = PK11_GetInternalKeySlot();
        if (NULL == slot) break;

        SECItem nickname = { 0, NULL, strlen(fn) };
        *(const unsigned char **)&nickname.data = (unsigned char *)fn;
        unsigned int keyUsage = KU_ALL;  /* XXX: limit to fewer flags? */
        PRBool isPerm = PR_FALSE;
        PRBool isPrivate = PR_TRUE;
        SECKEYPublicKey *pubKey = CERT_ExtractPublicKey(cert);
        SECItem *pubValue = mod_nss_cert_get_publicValue(pubKey);
        src =
          PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &der, &nickname,
                                                   pubValue, isPerm, isPrivate,
                                                   keyUsage, &pkey, NULL);
        /* nickname attribute has reference taken to data;
         * data must persist longer than SECKEYPrivateKey */
        /* (pubValue data is of decoded type SEC_ASN1_INTEGER and is copied) */
        SECKEY_DestroyPublicKey(pubKey);
    } while (0);

    if (slot) PK11_FreeSlot(slot);
    if (der.data) {
        mod_nss_secitem_wipe(&der);
        PORT_Free(der.data);
    }
    mod_nss_secitem_wipe(&f);

    if (src < 0) {
        elogf(errh, __FILE__, __LINE__,
              "PK11_ImportDERPrivateKeyInfoAndReturnKey() %s", fn);
        return NULL;
    }

    return pkey;
}


static void
mod_nss_free_config (server *srv, plugin_data * const p)
{
    if (NULL != p->ssl_ctxs) {
        PRFileDesc *global_model = p->ssl_ctxs->model;
        /* free from $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs + i;
            if (s->model && s->model != global_model)
                PR_Close(s->model);
        }
        /* free from global scope */
        if (global_model)
            PR_Close(global_model);
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
                    CERT_DestroyCertificate(pc->ssl_pemfile_x509);
                    SECKEY_DestroyPrivateKey(pc->ssl_pemfile_pkey);
                    CERTCertificateList *certChain;
                    *(const CERTCertificateList **)&certChain =
                      pc->ssl_credex.certChain;
                    CERT_DestroyCertificateList(certChain);
                    PORT_Free(pc->OCSPResponse.data);
                    //CERT_Destroy...(pc->ssl_credex.signedCertTimestamps);
                    //CERT_Destroy...(pc->ssl_credex.delegCred);
                    //CERT_Destroy...(pc->ssl_credex.delegCredPrivKey);
                    free(pc);
                }
                break;
              case 2: /* ssl.ca-file */
              case 3: /* ssl.ca-dn-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    CERT_DestroyCertList(cpv->v.v);
                break;
              case 4: /* ssl.ca-crl-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    mod_nss_free_config_crls(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}


FREE_FUNC(mod_nss_free)
{
    plugin_data *p = p_d;
    if (NULL == p->srv) return;
    mod_nss_free_config(p->srv, p);
    mod_nss_free_nss();
}


static void
mod_nss_merge_config_cpv (plugin_config * const pconf, const config_plugin_value_t * const cpv)
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
        pconf->ssl_log_noise = (unsigned char)cpv->v.shrt;
        break;
     #if 0    /*(cpk->k_id remapped in mod_nss_set_defaults())*/
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
mod_nss_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv)
{
    do {
        mod_nss_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_nss_patch_config (request_st * const r, plugin_config * const pconf)
{
    plugin_data * const p = plugin_data_singleton;
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_nss_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


static SECStatus
mod_nss_verify_cb (void *arg, PRFileDesc *ssl, PRBool checkSig, PRBool isServer)
{
    handler_ctx * const hctx = arg;
    if (!hctx->conf.ssl_verifyclient) return SECSuccess;

    /* Notes
     * trusted CAs in ssl.ca-file were loaded into default cert db at startup
     * OCSP checking (querying OCSP Responder) is disabled by default
     *   CERT_EnableOCSPChecking()
     *   CERT_DisableOCSPChecking()
     * cert_VerifyCertWithFlags() is not public,
     *   so unable to use CERT_VERIFYCERT_SKIP_OCSP
     * hctx->verify_status is set here; not setting SSL_BadCertHook()
     * XXX: not implemented (yet) here: hctx->conf.ssl_verifyclient_depth)
     */

    CERTCertificate *peer = NULL;

  #if 0
    peer = SSL_PeerCertificate(ssl);
    if (NULL == peer)
        return (PORT_GetError() == SSL_ERROR_NO_CERTIFICATE)
          ? SECSuccess
          : SECFailure;

    if (CERT_VerifyCert(CERT_GetDefaultCertDB(), peer, PR_TRUE,
                        certUsageSSLClient, (PRInt64)log_epoch_secs * 1000000,
                        SSL_RevealPinArg(ssl), NULL) < 0)
  #else
    if (SSL_AuthCertificate((void *)CERT_GetDefaultCertDB(),
                            ssl, checkSig, isServer) < 0)
  #endif
    {
        hctx->verify_status = PORT_GetError();
        if (0 == hctx->verify_status)
            hctx->verify_status = SEC_ERROR_UNTRUSTED_CERT;
    }

    if (hctx->verify_status == 0 && hctx->conf.ssl_ca_dn_file) {
        /* verify that client cert is issued by CA in ssl.ca-dn-file
         * if both ssl.ca-dn-file and ssl.ca-file were configured */
        if (NULL == peer) peer = SSL_PeerCertificate(ssl);
        if (peer) {
            CERTCertList * const certList = hctx->conf.ssl_ca_dn_file;
            SECItem * const derIssuer = &peer->derIssuer;
            CERTCertListNode *node = CERT_LIST_HEAD(certList);
            for (; !CERT_LIST_END(node, certList); node = CERT_LIST_NEXT(node)){
                SECItem * const derSubject = &node->cert->derSubject;
                if (SECITEM_CompareItem(derIssuer, derSubject) == SECEqual)
                    break;
            }
            if (CERT_LIST_END(node, certList))
                hctx->verify_status = SEC_ERROR_UNTRUSTED_CERT;
        }
    }

    if (peer) CERT_DestroyCertificate(peer);

    if (hctx->verify_status != 0 && hctx->conf.ssl_verifyclient_enforce) {
        PORT_SetError(SEC_ERROR_UNTRUSTED_CERT);
        return SECFailure;
    }

    return SECSuccess;
}


__attribute_cold__
static void
mod_nss_expire_stapling_file (server *srv, plugin_cert *pc)
{
    /* discard expired OCSP stapling response */
    pc->ssl_credex.stapledOCSPResponses = NULL;
    if (pc->must_staple)
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate marked OCSP Must-Staple, "
                  "but OCSP response expired from ssl.stapling-file %s",
                  pc->ssl_stapling_file->ptr);
}


static int
mod_nss_reload_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    SECItem f;
    int rc = mod_nss_load_file(pc->ssl_stapling_file->ptr, &f, srv->errh);
    if (rc < 0) return rc;

    /* NSS has the ability to include multiple OCSP responses for
     * certificate chain as allowed in TLSv1.3, but that is not utilized here.
     * If implemented, it will probably operate on a new directive,
     *   e.g. ssl.stapling-pemfile
     */

    /*   Note that the credentials structure should be read-only when in
     *   use, thus when reloading, either the credentials structure must not
     *   be in use by any sessions, or a new credentials structure should be
     *   allocated for new sessions.
     * XXX: lighttpd is not threaded, so this is probably not an issue (?)
     */

    PORT_Free(pc->OCSPResponse.data);
    pc->OCSPResponse.data   = f.data;
    pc->OCSPResponse.len    = f.len;
    pc->OCSPResponses.items = &pc->OCSPResponse;
    pc->OCSPResponses.len   = 1;
    pc->ssl_credex.stapledOCSPResponses = &pc->OCSPResponses;

    /* NSS does not expose CERTOCSPSingleResponse member nextUpdate
     * to allow getting (PRTime) of nextUpdate from the OCSP response.
     * (PRTime is (PRInt64) of microseconds since epoch)
     * e.g. DER_GeneralizedTimeToTime(&nextUpdate, single->nextUpdate);
     * XXX: *not* implementing our own ASN.1 DER decoder for OCSP response
     * ssl.stapling-file will be reloaded hourly
     */
    unix_time64_t nextupd = -1;

    pc->ssl_stapling_loadts = cur_ts;
    pc->ssl_stapling_nextts = nextupd;
    if (pc->ssl_stapling_nextts == -1) {
        /* "Next Update" might not be provided by OCSP responder
         * Use 3600 sec (1 hour) in that case. */
        /* retry in 1 hour if unable to determine Next Update */
        pc->ssl_stapling_nextts = cur_ts + 3600;
        pc->ssl_stapling_loadts = 0;
    }
    else if (pc->ssl_stapling_nextts < cur_ts)
        mod_nss_expire_stapling_file(srv, pc);

    return 0;
}


static int
mod_nss_refresh_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    if (pc->ssl_stapling_nextts > cur_ts + 256)
        return 0; /* skip check for refresh unless close to expire */
    struct stat st;
    if (0 != stat(pc->ssl_stapling_file->ptr, &st)
        || TIME64_CAST(st.st_mtime) <= pc->ssl_stapling_loadts) {
        if (pc->ssl_stapling_nextts < cur_ts)
            mod_nss_expire_stapling_file(srv, pc);
        return 0;
    }
    return mod_nss_reload_stapling_file(srv, pc, cur_ts);
}


static void
mod_nss_refresh_stapling_files (server *srv, const plugin_data *p, const unix_time64_t cur_ts)
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
                mod_nss_refresh_stapling_file(srv, pc, cur_ts);
        }
    }
}


static int
mod_nss_crt_must_staple (CERTCertificate *crt)
{
    /* Look for TLS features X.509 extension with value 5
     * RFC 7633 https://tools.ietf.org/html/rfc7633#appendix-A
     * 5 = OCSP Must-Staple (security mechanism)
     *
     * id-pe-tlsfeature 1.3.6.1.5.5.7.1.24
     * 1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05
     */

    int rc;

    /* XXX: not implemented */
    UNUSED(crt);
    rc = 0;

    return rc; /* 1 if OCSP Must-Staple found; 0 if not */
}


static void *
network_nss_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey, const buffer *ssl_stapling_file)
{
    CERTCertificateList *ssl_pemfile_chain;
    CERTCertificate *ssl_pemfile_x509 =
      mod_nss_load_pem_crts(pemfile->ptr, srv->errh, &ssl_pemfile_chain);
    if (NULL == ssl_pemfile_x509)
        return NULL;

    SECKEYPrivateKey *pkey =
      mod_nss_load_config_pkey(privkey->ptr, ssl_pemfile_x509, srv->errh);
    if (NULL == pkey) {
        CERT_DestroyCertificate(ssl_pemfile_x509);
        if (ssl_pemfile_chain) CERT_DestroyCertificateList(ssl_pemfile_chain);
        return NULL;
    }

    if (NULL == ssl_pemfile_chain)
        ssl_pemfile_chain = CERT_CertChainFromCert(ssl_pemfile_x509,
                                                   certUsageSSLServer,
                                                   PR_FALSE);

    plugin_cert *pc = ck_calloc(1, sizeof(plugin_cert));
    pc->ssl_pemfile_pkey = pkey;
    pc->ssl_pemfile_x509 = ssl_pemfile_x509;
    pc->ssl_credex.certChain = ssl_pemfile_chain;
    pc->ssl_stapling_file= ssl_stapling_file;
    pc->ssl_stapling_loadts = 0;
    pc->ssl_stapling_nextts = 0;
    pc->OCSPResponse.type   = 0;
    pc->OCSPResponse.data   = NULL;
    pc->OCSPResponse.len    = 0;
    pc->OCSPResponses.items = NULL;
    pc->OCSPResponses.len   = 0;
    pc->must_staple = mod_nss_crt_must_staple(ssl_pemfile_x509);

    if (pc->ssl_stapling_file) {
        if (mod_nss_reload_stapling_file(srv, pc, log_epoch_secs) < 0) {
            /* continue without OCSP response if there is an error */
        }
    }
    else if (pc->must_staple) {
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate %s marked OCSP Must-Staple, "
                  "but ssl.stapling-file not provided", pemfile->ptr);
    }

  #if 0
    PRTime notBefore, notAfter;
    SECStatus rc = CERT_GetCertTimes(crt, &notBefore, &notAfter);
    pc->notAfter = (rc == SECSuccess) ? notAfter/1000000 : 0;
  #endif

    return pc;
}


static int
mod_nss_acme_tls_1 (handler_ctx *hctx)
{
    buffer * const b = hctx->tmp_buf;
    const buffer * const name = &hctx->r->uri.authority;
    log_error_st * const errh = hctx->r->conf.errh;

    /* check if acme-tls/1 protocol is enabled (path to dir of cert(s) is set)*/
    if (!hctx->conf.ssl_acme_tls_1)
        return SECFailure; /*(should not happen)*/

    /* check if SNI set server name (required for acme-tls/1 protocol)
     * and perform simple path checks for no '/'
     * and no leading '.' (e.g. ignore "." or ".." or anything beginning '.') */
    if (buffer_is_blank(name))          return SECFailure;
    if (NULL != strchr(name->ptr, '/')) return SECFailure;
    if (name->ptr[0] == '.')            return SECFailure;
  #if 0
    if (0 != http_request_host_policy(name, hctx->r->conf.http_parseopts, 443))
        return SECFailure;
  #endif
    buffer_copy_path_len2(b, BUF_PTR_LEN(hctx->conf.ssl_acme_tls_1),
                             BUF_PTR_LEN(name));

    /* cert and key load is similar to network_nss_load_pemfile() */

    uint32_t len = buffer_clen(b);
    buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));

    CERTCertificateList *ssl_pemfile_chain;
    CERTCertificate *ssl_pemfile_x509 =
      mod_nss_load_pem_crts(b->ptr, errh, &ssl_pemfile_chain);
    if (NULL == ssl_pemfile_x509)
        return SECFailure;

    buffer_truncate(b, len);
    buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));

    SECKEYPrivateKey *pkey =
      mod_nss_load_config_pkey(b->ptr, ssl_pemfile_x509, errh);
    if (NULL == pkey) {
        CERT_DestroyCertificate(ssl_pemfile_x509);
        if (ssl_pemfile_chain) CERT_DestroyCertificateList(ssl_pemfile_chain);
        return SECFailure;
    }

    /* use NSS deprecated functions to unconfigure an already-configured cert.
     * This is because SSL_ConfigServerCert() will replace an existing cert
     * of the same type, but not if an existing cert is of a different type */
    if (hctx->conf.pc) {
        SSLKEAType certType =
          NSS_FindCertKEAType(hctx->conf.pc->ssl_pemfile_x509);
        SSL_ConfigSecureServerWithCertChain(hctx->ssl,NULL,NULL,NULL,certType);
    }

    unsigned int dlen = 0;
    SSLExtraServerCertData *data = NULL;
    SSLExtraServerCertData d;
    if (ssl_pemfile_chain) {
        data = &d;
        dlen = sizeof(d);
        memset(&d, 0, sizeof(d));
        d.certChain = ssl_pemfile_chain;
    }
    SECStatus rc =
      SSL_ConfigServerCert(hctx->ssl, ssl_pemfile_x509, pkey, data, dlen);

    CERT_DestroyCertificate(ssl_pemfile_x509);
    SECKEY_DestroyPrivateKey(pkey);
    if (ssl_pemfile_chain) CERT_DestroyCertificateList(ssl_pemfile_chain);

    if (hctx->conf.ssl_verifyclient) {
        /*(disable client certificate verification for "acme-tls/1")*/
        hctx->conf.ssl_verifyclient = 0;
        SSL_OptionSet(hctx->ssl, SSL_REQUEST_CERTIFICATE, PR_FALSE);
        SSL_OptionSet(hctx->ssl, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
    }

    return rc;
}


static int
mod_nss_alpn_h2_policy (handler_ctx * const hctx)
{
    UNUSED(hctx);
    /*(currently called after handshake has completed)*/
  #if 0 /* SNI omitted by client when connecting to IP instead of to name */
    if (buffer_is_blank(&hctx->r->uri.authority)) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: error ALPN h2 without SNI");
        return -1;
    }
  #endif
  #if 0
    /* sanity check; lighttpd defaults to using TLSv1.2 or better */
    /* modified from http_cgi_ssl_env(); expensive, so commented out */
    /* (quite a bit of work just to get protocol version)
     * (could not find better NSS interface) */
    SSLChannelInfo inf;
    if (SSL_GetChannelInfo(ssl, &inf, sizeof(inf)) < 0
        || inf.protocolVersion < SSL_LIBRARY_VERSION_TLS_1_2) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: error ALPN h2 requires TLSv1.2 or later");
        return -1;
    }
  #endif

    return 0;
}


enum {
  MOD_NSS_ALPN_HTTP11      = 1
 ,MOD_NSS_ALPN_HTTP10      = 2
 ,MOD_NSS_ALPN_H2          = 3
 ,MOD_NSS_ALPN_ACME_TLS_1  = 4
};


static SECStatus
mod_nss_alpn_select_cb (void *arg, PRFileDesc *ssl,
                        const unsigned char *protos, unsigned int protosLen,
                        unsigned char *protoOut, unsigned int *protoOutLen,
                        unsigned int protoMaxOut)
{
    /* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
    static const SECItem alpn[] = {
      { 0, (unsigned char *)CONST_STR_LEN("h2") }
     ,{ 0, (unsigned char *)CONST_STR_LEN("http/1.1") }
     ,{ 0, (unsigned char *)CONST_STR_LEN("http/1.0") }
     ,{ 0, (unsigned char *)CONST_STR_LEN("acme-tls/1") }
    };
    UNUSED(ssl);
    /* reference: lib/ssl/sslsock.c:ssl_NextProtoNegoCallback() */
    for (unsigned int i = 0; i < protosLen; i += 1 + protos[i]) {
        for (unsigned int j = 0; j < sizeof(alpn)/sizeof(*alpn); ++j) {
            if (protos[i] == alpn[j].len && i+1+protos[i] <= protosLen
                && 0 == PORT_Memcmp(protos+i+1, alpn[j].data, alpn[j].len)) {

                if (protoMaxOut < alpn[j].len) {
                    PORT_SetError(SEC_ERROR_OUTPUT_LEN);
                    return SECFailure;
                }

                handler_ctx *hctx = arg;
                switch (j) { /*(must match SECItem alpn[] above)*/
                  case 0:
                    if (!hctx->r->conf.h2proto) continue;
                    hctx->alpn = MOD_NSS_ALPN_H2;
                    if (hctx->r->handler_module == NULL)/*(not mod_sockproxy)*/
                        hctx->r->http_version = HTTP_VERSION_2;
                    break;
                  case 1:
                    hctx->alpn = MOD_NSS_ALPN_HTTP11;
                    break;
                  case 2:
                    hctx->alpn = MOD_NSS_ALPN_HTTP10;
                    break;
                  case 3:
                    if (!hctx->conf.ssl_acme_tls_1)
                        continue;
                    hctx->alpn = MOD_NSS_ALPN_ACME_TLS_1;
                    break;
                  default:
                    break;
                }

                memcpy(protoOut, alpn[j].data, alpn[j].len);
                *protoOutLen = alpn[j].len;

                return SECSuccess;
            }
        }
    }
    return SECSuccess;
}


static PRInt32
mod_nss_SNI (PRFileDesc *ssl, const SECItem *srvNameArr, PRUint32 srvNameArrSize,
             void *arg)
{
    if (0 == srvNameArrSize) /* should not happen */
        return SSL_SNI_CURRENT_CONFIG_IS_USED;

    handler_ctx * const hctx = (handler_ctx *)arg;
    request_st * const r = hctx->r;
    buffer_copy_string_len(&r->uri.scheme, CONST_STR_LEN("https"));
    PRUint32 i = 0; /* index into srvNameArr; always take first element */
    const SECItem *sn = srvNameArr+i;

    if (sn->len >= 1024) { /*(expecting < 256; TLSEXT_MAXLEN_host_name is 255)*/
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "NSS: SNI name too long %.*s", (int)sn->len,(char *)sn->data);
        return SSL_SNI_SEND_ALERT;
    }

    /* use SNI to patch mod_nss config and then reset COMP_HTTP_HOST */
    buffer_copy_string_len_lc(&r->uri.authority,(const char *)sn->data,sn->len);
  #if 0
    /*(r->uri.authority used below for configuration before request read;
     * revisit for h2)*/
    if (0 != http_request_host_policy(&r->uri.authority,
                                      r->conf.http_parseopts, 443))
        return SSL_SNI_SEND_ALERT;
  #endif

    r->conditional_is_valid |= (1 << COMP_HTTP_SCHEME)
                            |  (1 << COMP_HTTP_HOST);

    plugin_cert *pc = hctx->conf.pc;

    mod_nss_patch_config(r, &hctx->conf);
    /* reset COMP_HTTP_HOST so that conditions re-run after request hdrs read */
    /*(done in configfile-glue.c:config_cond_cache_reset() after request hdrs read)*/
    /*config_cond_cache_reset_item(r, COMP_HTTP_HOST);*/
    /*buffer_clear(&r->uri.authority);*/

    /* XXX: it appears that ALPN callback is called before SNI callback in NSS,
     * so handle acme-tls/1 here, prior to and instead of setting cert below */
    if (hctx->alpn == MOD_NSS_ALPN_ACME_TLS_1) {
        if (0 == mod_nss_acme_tls_1(hctx))
            return (PRInt32)i;
        else {
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
                      "failed to set acme-tls/1 certificate for TLS"
                      " server name %s", hctx->r->uri.authority.ptr);
            return SSL_SNI_SEND_ALERT;
        }
    }

    if (pc == hctx->conf.pc)
        return SSL_SNI_CURRENT_CONFIG_IS_USED;

    /* use NSS deprecated functions to unconfigure an already-configured cert.
     * This is because SSL_ConfigServerCert() will replace an existing cert
     * of the same type, but not if an existing cert is of a different type */
    SSLKEAType certType =
      NSS_FindCertKEAType(hctx->conf.pc->ssl_pemfile_x509);
    SSL_ConfigSecureServerWithCertChain(ssl, NULL, NULL, NULL, certType);
    SECStatus rc =
      SSL_ConfigServerCert(ssl, hctx->conf.pc->ssl_pemfile_x509,
                           hctx->conf.pc->ssl_pemfile_pkey,
                           &hctx->conf.pc->ssl_credex,
                           sizeof(hctx->conf.pc->ssl_credex));
    if (rc < 0) {
        elogf(r->conf.errh, __FILE__, __LINE__,
              "failed to set SNI certificate for TLS server name %s",
              r->uri.authority.ptr);
        return SSL_SNI_SEND_ALERT;
    }

    if (hctx->conf.ssl_verifyclient) {
        /*(XXX: technically do not need to redo if it has not changed)*/
        if (SSL_AuthCertificateHook(ssl, mod_nss_verify_cb, hctx) < 0) {
            elog(r->conf.errh, __FILE__, __LINE__, "SSL_AuthCertificateHook");
            return SSL_SNI_SEND_ALERT;
        }
        CERTCertList * const certList = hctx->conf.ssl_ca_dn_file
                                      ? hctx->conf.ssl_ca_dn_file
                                      : hctx->conf.ssl_ca_file;
        if (NULL == certList)
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
              "NSS: can't verify client without ssl.verifyclient.ca-file "
              "for TLS server name %s",
              hctx->r->uri.authority.ptr); /*(might not be set yet if no SNI)*/
        if (certList && SSL_SetTrustAnchors(ssl, certList) < 0) {
            elog(r->conf.errh, __FILE__, __LINE__, "SSL_SetTrustAnchors");
            return SSL_SNI_SEND_ALERT;
        }
        SSL_OptionSet(ssl, SSL_REQUEST_CERTIFICATE, PR_TRUE);
        SSL_OptionSet(ssl, SSL_REQUIRE_CERTIFICATE,
                           hctx->conf.ssl_verifyclient_enforce
                             ? SSL_REQUIRE_ALWAYS
                             : SSL_REQUIRE_NEVER);
    }
    else {
        SSL_OptionSet(ssl, SSL_REQUEST_CERTIFICATE, PR_FALSE);
        SSL_OptionSet(ssl, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
    }

    return (PRInt32)i;
}


static int
mod_nss_ssl_conf_ciphersuites (server *srv, plugin_config_socket *s, buffer *ciphersuites, const buffer *cipherstring);


static int
mod_nss_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist);


static void
mod_nss_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *minb, const buffer *maxb);


static int
mod_nss_ssl_conf_cmd (server *srv, plugin_config_socket *s)
{
    /* reference:
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_CONF_cmd.html */
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
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MaxProtocol")))
            maxb = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MinProtocol")))
            minb = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Protocol"))) {
            /* openssl config for Protocol=... is complex and deprecated */
            log_error(srv->errh, __FILE__, __LINE__,
                      "NSS: ssl.openssl.ssl-conf-cmd %s ignored; "
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
                        s->ssl_compression = flag;
                        continue;
                    }
                    break;
                  case 13:
                    if (buffer_eq_icase_ssn(v, "SessionTicket", 13)) {
                        /*(translates to "%NO_TICKETS" priority str if !flag)*/
                        s->ssl_session_ticket = flag;
                        continue;
                    }
                    break;
                  case 16:
                    if (buffer_eq_icase_ssn(v, "ServerPreference", 16)) {
                        /*(translates to "%SERVER_PRECEDENCE" priority string)*/
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
                          "NSS: ssl.openssl.ssl-conf-cmd Options %.*s "
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
                      "NSS: ssl.openssl.ssl-conf-cmd %s ignored",
                      ds->key.ptr);
        }
    }

    if (minb || maxb) /*(if at least one was set)*/
        mod_nss_ssl_conf_proto(srv, s, minb, maxb);

    if (!mod_nss_ssl_conf_ciphersuites(srv, s, ciphersuites, cipherstring))
        rc = -1;

    if (curves && !buffer_is_blank(curves)) {
        if (!mod_nss_ssl_conf_curves(srv, s, curves))
            rc = -1;
    }

    return rc;
}


static int
network_init_ssl (server *srv, plugin_config_socket *s, plugin_data *p)
{
    UNUSED(p);

    const int disable_sess_cache =
      !config_feature_bool(srv, "ssl.session-cache", 0);
    if (!disable_sess_cache) /* undo disable from mod_nss_init_once_nss() */
        SSL_OptionSetDefault(SSL_NO_CACHE, PR_FALSE);

    /* use PR_CreateSocketPollFd() for dummy;
     * PR_CreateIOLayerStub() was resulting in crashes
     * when SSL_ImportFD() attempted ssl_DefGetpeername() */
    s->model = PR_CreateSocketPollFd(-1);
    if (NULL == s->model) return -1;
    s->model->methods = PR_GetTCPMethods();
    PRFileDesc *model = SSL_ImportFD(NULL, s->model);
    if (NULL == model) return -1;
    s->model = model;

    if (s->ssl_cipher_list) {
        if (!mod_nss_ssl_conf_ciphersuites(srv,s,NULL,s->ssl_cipher_list))
            return -1;
    }

    mod_nss_ssl_conf_proto(srv, s, NULL, NULL); /* set default range */

    if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
        if (0 != mod_nss_ssl_conf_cmd(srv, s)) return -1;
    }

    /* future: add additional configuration of s->model here
     *         rather than in mod_nss_handle_con_accept() */

    if (SSL_OptionSet(model, SSL_SECURITY, PR_TRUE) < 0) {
        elog(srv->errh, __FILE__, __LINE__, "SSL_SECURITY");
        return -1;
    }

    if (SSL_VersionRangeSet(model, &s->protos)) {
        elog(srv->errh, __FILE__, __LINE__, "SSL_VersionRangeSet()");
        return -1;
    }

    if (s->protos.min == SSL_LIBRARY_VERSION_2
        && SSL_OptionSet(model, SSL_ENABLE_SSL2, PR_TRUE) < 0) {
        elog(srv->errh, __FILE__, __LINE__, "SSL_ENABLE_SSL2");
        return -1;
    }

    if (s->protos.min == SSL_LIBRARY_VERSION_3_0
        && SSL_OptionSet(model, SSL_ENABLE_SSL3, PR_TRUE) < 0) {
        elog(srv->errh, __FILE__, __LINE__, "SSL_ENABLE_SSL3");
        return -1;
    }

    if (!s->ssl_session_ticket
        && SSL_OptionSet(model, SSL_ENABLE_SESSION_TICKETS, PR_FALSE) < 0) {
        elog(srv->errh, __FILE__, __LINE__, "!SSL_ENABLE_SESSION_TICKETS");
        return -1;
    }

    if (SSL_OptionSet(model, SSL_ENABLE_DEFLATE, s->ssl_compression) < 0) {
        elog(srv->errh, __FILE__, __LINE__, "SSL_ENABLE_DEFLATE");
        return HANDLER_ERROR;
    }

    SSL_OptionSet(model, SSL_REQUEST_CERTIFICATE, PR_FALSE);
    SSL_OptionSet(model, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);

    SECStatus rc =
      SSL_ConfigServerCert(model, s->pc->ssl_pemfile_x509,
                           s->pc->ssl_pemfile_pkey,
                           &s->pc->ssl_credex,
                           sizeof(s->pc->ssl_credex));
    if (rc < 0) {
        elogf(srv->errh, __FILE__, __LINE__,
              "failed to set default certificate for socket");
        return -1;
    }

    return 0;
}


#define LIGHTTPD_DEFAULT_CIPHER_LIST \
"EECDH+AESGCM:CHACHA20:!DH"


static int
mod_nss_set_defaults_sockets(server *srv, plugin_data *p)
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
    if (!config_plugin_values_init(srv, ps, cpk, "mod_nss"))
        return HANDLER_ERROR;

    plugin_config_socket defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.ssl_session_ticket     = 1; /* enabled by default */
    defaults.ssl_compression        = 0; /* disable for security */
    defaults.ssl_cipher_list        = &default_ssl_cipher_list;

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
                  "NSS: %s is valid only in global scope or "
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
                log_error(srv->errh, __FILE__, __LINE__, "NSS: "
                  "ssl.stek-file is not supported in mod_nss; ignoring.");
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
        conf.ssl_verifyclient         = p->defaults.ssl_verifyclient;
        conf.ssl_verifyclient_enforce = p->defaults.ssl_verifyclient_enforce;
        conf.ssl_verifyclient_depth   = p->defaults.ssl_verifyclient_depth;

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
                if (count_not_engine
                    || (conf.ssl_enabled && NULL == p->ssl_ctxs[0].model)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "NSS: ssl.pemfile has to be set in same "
                      "$SERVER[\"socket\"] scope as other ssl.* directives, "
                      "unless only ssl.engine is set, inheriting ssl.* from "
                      "global scope");
                    rc = HANDLER_ERROR;
                    continue;
                }
                plugin_ssl_ctx * const s = p->ssl_ctxs + sidx;
                *s = *p->ssl_ctxs;/*(copy struct of ssl_ctx from global scope)*/
                continue;
            }
            /* PEM file is required */
            log_error(srv->errh, __FILE__, __LINE__,
              "NSS: ssl.pemfile has to be set when ssl.engine = \"enable\"");
            rc = HANDLER_ERROR;
            continue;
        }

        /* (initialize once if module enabled) */
        if (!mod_nss_init_once_nss()) {
            rc = HANDLER_ERROR;
            break;
        }

        /* configure ssl_ctx for socket */

        /*conf.ssl_ctx = NULL;*//*(filled by network_init_ssl() even on error)*/
        if (0 == network_init_ssl(srv, &conf, p)) {
            plugin_ssl_ctx * const s = p->ssl_ctxs + sidx;
            s->model              = conf.model;
            s->protos             = conf.protos;
            s->ssl_compression    = conf.ssl_compression;
            s->ssl_session_ticket = conf.ssl_session_ticket;
        }
        else {
            if (conf.model) PR_Close(conf.model);
            rc = HANDLER_ERROR;
        }
    }

    free(srvplug.cvlist);
    return rc;
}


SETDEFAULTS_FUNC(mod_nss_set_defaults)
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
    if (!config_plugin_values_init(srv, p, cpk, "mod_nss"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        config_plugin_value_t *pemfile = NULL;
        config_plugin_value_t *privkey = NULL;
        const buffer *ssl_stapling_file = NULL;
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
                if (!buffer_is_blank(cpv->v.b)) {
                    CERTCertList *d =
                      mod_nss_load_config_crts(cpv->v.b->ptr, srv->errh);
                    if (d != NULL) {
                        cpv->vtype = T_CONFIG_LOCAL;
                        cpv->v.v = d;
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__,
                                  "%s = %s", cpk[cpv->k_id].k, cpv->v.b->ptr);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 16:/* ssl.verifyclient.ca-dn-file */
                cpv->k_id = 3;
                __attribute_fallthrough__
              case 3: /* ssl.ca-dn-file */
                if (!buffer_is_blank(cpv->v.b)) {
                    CERTCertList *d =
                      mod_nss_load_config_dncrts(cpv->v.b->ptr, srv->errh);
                    if (d != NULL) {
                        cpv->vtype = T_CONFIG_LOCAL;
                        cpv->v.v = d;
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__,
                                  "%s = %s", cpk[cpv->k_id].k, cpv->v.b->ptr);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 17:/* ssl.verifyclient.ca-crl-file */
                cpv->k_id = 4;
                __attribute_fallthrough__
              case 4: /* ssl.ca-crl-file */
                if (!buffer_is_blank(cpv->v.b)) {
                    CERTCertificateList *d =
                      mod_nss_load_config_crls(cpv->v.b->ptr, srv->errh);
                    if (d != NULL) {
                        cpv->vtype = T_CONFIG_LOCAL;
                        cpv->v.v = d;
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__,
                                  "%s = %s", cpk[cpv->k_id].k, cpv->v.b->ptr);
                        return HANDLER_ERROR;
                    }
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
                      "NSS: %s is absurdly large (%hu); limiting to 255",
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

        if (pemfile) {
            if (NULL == privkey) privkey = pemfile;
            pemfile->v.v =
              network_nss_load_pemfile(srv, pemfile->v.b, privkey->v.b,
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
            mod_nss_merge_config(&p->defaults, cpv);
    }

    return mod_nss_set_defaults_sockets(srv, p);
}


    /* local_send_buffer is a static buffer of size (LOCAL_SEND_BUFSIZE)
     *
     * buffer is allocated once, is NOT realloced (note: not thread-safe)
     * */

            /* copy small mem chunks into single large buffer
             * before PR_Write() to reduce number times write() called
             * underneath PR_Write() and potentially reduce number of packets
             * generated if TCP_NODELAY */


__attribute_cold__
static int
mod_nss_write_err(connection *con, handler_ctx *hctx, size_t wr_len)
{
    switch (PR_GetError()) {
      case PR_WOULD_BLOCK_ERROR:
      case PR_PENDING_INTERRUPT_ERROR:
        con->is_writable = -1;
        /* XXX: not handled: protocol might be blocked waiting on read */
        /*if (0) con->is_readable = -1;*/
        break; /* try again later */
      case PR_CONNECT_RESET_ERROR:
        if (!hctx->conf.ssl_log_noise) return -1;
        __attribute_fallthrough__
      default:
        elog(hctx->r->conf.errh, __FILE__, __LINE__, __func__);
        return -1;
    }

    /* partial write; save attempted wr_len */
    hctx->pending_write = wr_len;

    return 0; /* try again later */
}


__attribute_cold__
static int
mod_nss_read_err(connection *con, handler_ctx *hctx)
{
    switch (PR_GetError()) {
      case PR_WOULD_BLOCK_ERROR:
      case PR_PENDING_INTERRUPT_ERROR:
        /* XXX: not handled: protocol might be blocked waiting on write */
        /*if (0) con->is_writable = -1;*/
        con->is_readable = 0;
        return 0;
      case PR_CONNECT_ABORTED_ERROR:
      case PR_CONNECT_RESET_ERROR:
      case PR_END_OF_FILE_ERROR:
        if (!hctx->conf.ssl_log_noise) return -1;
        __attribute_fallthrough__
      default:
        elog(hctx->errh, __FILE__, __LINE__, __func__);
        return -1;
    }
}


static int
mod_nss_close_notify(handler_ctx *hctx);


static int
connection_write_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[plugin_data_singleton->id];
    PRFileDesc * const ssl = hctx->ssl;
    log_error_st * const errh = hctx->errh;

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_nss_close_notify(hctx);

    /* future: for efficiency/performance might consider using NSS
     *   PR_Writev() PR_TransmitFile() PR_SendFile()
     */

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

        /*(if partial write occurred, expect that subsequent writes will have
         * at least that much data available from chunkqueue_peek_data(), which
         * is what should happen, but is not checked here)*/
        size_t lim = hctx->pending_write;
        if (lim && data_len > lim) data_len = lim;
        hctx->pending_write = 0;

        /*
         * XXX: above comments modified from mod_mbedtls; should be verified
         */

        int wr_total = 0;
        do {
            size_t wr_len = data_len;
            wr = PR_Write(ssl, data, (PRInt32)wr_len);
            if (wr <= 0) {
                if (wr_total) chunkqueue_mark_written(cq, wr_total);
                return mod_nss_write_err(con, hctx, wr_len);
            }
            wr_total += wr;
            data += wr;
        } while ((data_len -= wr));
        chunkqueue_mark_written(cq, wr_total);
        max_bytes -= wr_total;
    }

    return 0;
}


static void
mod_nss_SSLHandshakeCallback (PRFileDesc *fd, void *arg)
{
    UNUSED(fd);
    handler_ctx *hctx = arg;
    hctx->handshake = 1;
}


static int
connection_read_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[plugin_data_singleton->id];

    UNUSED(max_bytes);

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_nss_close_notify(hctx);

    PRFileDesc * const ssl = hctx->ssl;
    ssize_t len;
    char *mem = NULL;
    size_t mem_len = 0;
    do {
        int pend = SSL_DataPending(ssl);
        if (pend < 0) {
            len = pend;
            break;
        }
        mem_len = pend < 2048 ? 2048 : (uint32_t)pend;
        chunk * const ckpt = cq->last;
        mem = chunkqueue_get_memory(cq, &mem_len);

        len = PR_Read(ssl, mem, (PRInt32)mem_len);
        chunkqueue_use_memory(cq, ckpt, len > 0 ? len : 0);
    } while (len > 0);

    if (hctx->alpn && hctx->handshake) {
        if (hctx->alpn == MOD_NSS_ALPN_H2) {
            if (0 != mod_nss_alpn_h2_policy(hctx))
                return -1;
        }
        else if (hctx->alpn == MOD_NSS_ALPN_ACME_TLS_1) {
            /* Once TLS handshake is complete, return -1 to result in
             * CON_STATE_ERROR so that socket connection is quickly closed */
            return -1;
        }
        hctx->alpn = 0;
    }

    if (len < 0) {
        return mod_nss_read_err(con, hctx);
    } else if (len == 0) {
        con->is_readable = 0;
        /* the other end closed the connection -> KEEP-ALIVE */

        return -2;
  #ifndef __COVERITY__
    } else {
        return 0;
  #endif
    }
}


CONNECTION_FUNC(mod_nss_handle_con_accept)
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
    if (NULL == s->model) s = p->ssl_ctxs; /*(inherit from global scope)*/
    hctx->ssl_session_ticket = s->ssl_session_ticket;

    con->network_read = connection_read_cq_ssl;
    con->network_write = connection_write_cq_ssl;
    con->proto_default_port = 443; /* "https" */
    mod_nss_patch_config(r, &hctx->conf);

    hctx->ssl = mod_nss_io_ctor(con->fd, s->model, r->conf.errh);
    if (NULL == hctx->ssl)
        return HANDLER_ERROR;

    /* future: move more config from here to config model in network_init_ssl().
     * Callbacks need to be set here to be able to set callback arg to hctx */

    if (SSL_ResetHandshake(hctx->ssl, PR_TRUE) < 0) {
        elog(r->conf.errh, __FILE__, __LINE__, "SSL_ResetHandshake()");
        return HANDLER_ERROR;
    }

    if (SSL_HandshakeCallback(hctx->ssl, mod_nss_SSLHandshakeCallback, hctx)<0){
        elog(r->conf.errh, __FILE__, __LINE__, "SSL_HandshakeCallback()");
        return HANDLER_ERROR;
    }

    if (SSL_SNISocketConfigHook(hctx->ssl, mod_nss_SNI, hctx) < 0) {
        elog(r->conf.errh, __FILE__, __LINE__, "SSL_SNISocketConfigHook()");
        return HANDLER_ERROR;
    }

    if (SSL_SetNextProtoCallback(hctx->ssl, mod_nss_alpn_select_cb, hctx) < 0) {
        elog(r->conf.errh, __FILE__, __LINE__, "SSL_SetNextProtoCallback()");
        return HANDLER_ERROR;
    }

    hctx->verify_status = -1;
    if (hctx->conf.ssl_verifyclient) {
        if (SSL_AuthCertificateHook(hctx->ssl, mod_nss_verify_cb, hctx) < 0) {
            elog(r->conf.errh, __FILE__, __LINE__, "SSL_AuthCertificateHook()");
            return HANDLER_ERROR;
        }
        CERTCertList * const certList = hctx->conf.ssl_ca_dn_file
                                      ? hctx->conf.ssl_ca_dn_file
                                      : hctx->conf.ssl_ca_file;
        if (NULL == certList) {
            log_error(hctx->r->conf.errh, __FILE__, __LINE__,
              "NSS: can't verify client without ssl.verifyclient.ca-file "
              "for TLS server name %s",
              hctx->r->uri.authority.ptr); /*(might not be set yet if no SNI)*/
            return hctx->conf.ssl_verifyclient_enforce
              ? HANDLER_ERROR
              : HANDLER_GO_ON;
        }
        if (SSL_SetTrustAnchors(hctx->ssl, certList) < 0) {
            elog(r->conf.errh, __FILE__, __LINE__, "SSL_SetTrustAnchors()");
            return HANDLER_ERROR;
        }
        SSL_OptionSet(hctx->ssl, SSL_REQUEST_CERTIFICATE, PR_TRUE);
        SSL_OptionSet(hctx->ssl, SSL_REQUIRE_CERTIFICATE,
                                 hctx->conf.ssl_verifyclient_enforce
                                   ? SSL_REQUIRE_ALWAYS
                                   : SSL_REQUIRE_NEVER);
    }
    else {
        SSL_OptionSet(hctx->ssl, SSL_REQUEST_CERTIFICATE, PR_FALSE);
        SSL_OptionSet(hctx->ssl, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
    }

    return HANDLER_GO_ON;
}


static void
mod_nss_detach(handler_ctx *hctx)
{
    /* step aside from further SSL processing
     * (note: additional data might be buffered/discarded by this layer)
     * (used after handle_connection_shut_wr hook) */
    /* future: might restore prior network_read and network_write fn ptrs */
    mod_nss_io_detach(hctx->ssl);
    hctx->con->is_ssl_sock = 0;
    /* if called after handle_connection_shut_wr hook, shutdown SHUT_WR */
    if (-1 == hctx->close_notify) shutdown(hctx->con->fd, SHUT_WR);
    hctx->close_notify = 1;
}


CONNECTION_FUNC(mod_nss_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    hctx->close_notify = -2;
    if (hctx->handshake) {
        mod_nss_close_notify(hctx);
    }
    else {
        mod_nss_detach(hctx);
    }

    return HANDLER_GO_ON;
}


static int
mod_nss_close_notify (handler_ctx *hctx)
{
    if (1 == hctx->close_notify) return -2;

    /* note: this sends close_notify TLS alert and calls shutdown() on fd */
    switch (PR_Shutdown(hctx->ssl, PR_SHUTDOWN_SEND)) {
      case PR_SUCCESS:
        mod_nss_detach(hctx);
        return -2;
      case PR_FAILURE:
      default:
        if (PR_GetError() != PR_NOT_CONNECTED_ERROR)
            elog(hctx->r->conf.errh, __FILE__, __LINE__, "PR_Shutdown()");
        mod_nss_detach(hctx);
        return -1;
    }
}


CONNECTION_FUNC(mod_nss_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL != hctx) {
        con->plugin_ctx[p->id] = NULL;
        if (1 != hctx->close_notify)
            mod_nss_close_notify(hctx); /*(one final try)*/
        handler_ctx_free(hctx);
    }

    return HANDLER_GO_ON;
}


__attribute_noinline__
static void
https_add_ssl_client_cert (request_st * const r, CERTCertificate *peer)
{
    char *pem = NSSBase64_EncodeItem(NULL, NULL, 0, &peer->derCert);
    if (NULL == pem) return;
    uint32_t len = 0;
    for (uint32_t i = 0; pem[i]; ++i) {
        if (pem[i] != '\r') pem[len++] = pem[i]; /*(translate \r\n to \n)*/
    }
    buffer_append_str3(
      http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_CERT")),
      CONST_STR_LEN(PEM_BEGIN_CERT"\n"),
      pem, len,
      CONST_STR_LEN("\n"PEM_END_CERT"\n"));
    PORT_Free(pem);
}


static void
https_add_ssl_client_subject (request_st * const r, CERTName * const subj)
{
    /* add components of client Subject DN */
    /* not complete list; NSS does not expose enough of lib/certdb/alg1485.c
     * for friendly names, though we could consider using CERT_GetOidString()
     * and CERT_RFC1485_EscapeAndQuote() */
    static const
      struct { const char *tag; uint32_t tlen; char *(*fn)(const CERTName *); }
      comp[] = {
        { CONST_STR_LEN("CN"),           CERT_GetCommonName },
        { CONST_STR_LEN("ST"),           CERT_GetStateName },
        { CONST_STR_LEN("O"),            CERT_GetOrgName },
        { CONST_STR_LEN("OU"),           CERT_GetOrgUnitName },
        { CONST_STR_LEN("C"),            CERT_GetCountryName },
        { CONST_STR_LEN("L"),            CERT_GetLocalityName },
        { CONST_STR_LEN("UID"),          CERT_GetCertUid },
        { CONST_STR_LEN("emailAddress"), CERT_GetCertEmailAddress },
        { CONST_STR_LEN("DC"),           CERT_GetDomainComponentName },
      };
    const size_t prelen = sizeof("SSL_CLIENT_S_DN_")-1;
    char key[64] = "SSL_CLIENT_S_DN_";
    for (uint32_t i = 0; i < sizeof(comp)/sizeof(*comp); ++i) {
        char *s = comp[i].fn(subj);
        if (NULL == s) continue;

        unsigned int n;
        unsigned char c;
        for (n = 0; (c = ((unsigned char *)s)[n]); ++n) {
            if (c < 32 || c == 127) s[n] = '?';
        }

        /*if (prelen+comp[i].tlen >= sizeof(key)) continue;*//*(not possible)*/
        memcpy(key+prelen, comp[i].tag, comp[i].tlen); /*(not '\0'-terminated)*/
        http_header_env_set(r, key, prelen+comp[i].tlen, s, n);

        PR_Free(s);
    }
}


__attribute_cold__
static void
https_add_ssl_client_verify_err (buffer * const b, unsigned int status)
{
    const char *s = PR_ErrorToName(status);
    if (s)
        buffer_append_string_len(b, s, strlen(s));
    buffer_append_char(b, ':');
    s = PR_ErrorToString(status, PR_LANGUAGE_I_DEFAULT);
    buffer_append_string_len(b, s, strlen(s));
}


__attribute_noinline__
static void
https_add_ssl_client_entries (request_st * const r, handler_ctx * const hctx)
{
    PRFileDesc *ssl = hctx->ssl;
    CERTCertificate *crt = NULL;
    buffer *vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_VERIFY"));

    if (hctx->verify_status != -1)
        crt = SSL_PeerCertificate(ssl);
    if (NULL == crt) { /* || hctx->verify_status == -1) */
        /*(e.g. no cert, or verify result not available)*/
        buffer_copy_string_len(vb, CONST_STR_LEN("NONE"));
        return;
    }
    else if (0 != hctx->verify_status) {
        buffer_copy_string_len(vb, CONST_STR_LEN("FAILED:"));
        https_add_ssl_client_verify_err(vb, hctx->verify_status);
        CERT_DestroyCertificate(crt);
        return;
    }
    else {
        buffer_copy_string_len(vb, CONST_STR_LEN("SUCCESS"));
    }

    char *s = CERT_NameToAsciiInvertible(&crt->subject, CERT_N2A_STRICT);
    if (s) {
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_S_DN"),
                            s, strlen(s));
        PR_Free(s);
    }

    https_add_ssl_client_subject(r, &crt->subject);

    s = (char *)crt->serialNumber.data;
    size_t i = 0; /* skip leading 0's per Distinguished Encoding Rules (DER) */
    while (i < crt->serialNumber.len && s[i] == 0) ++i;
    if (i == crt->serialNumber.len) --i;
    buffer_append_string_encoded_hex_uc(
      http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_M_SERIAL")),
      s+i, crt->serialNumber.len-i);

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

    if (hctx->conf.ssl_verifyclient_export_cert)
        https_add_ssl_client_cert(r, crt);

    CERT_DestroyCertificate(crt);
}


static void
http_cgi_ssl_env (request_st * const r, handler_ctx * const hctx)
{
    PRFileDesc *ssl = hctx->ssl;

    /* (quite a bit of work just to get protocol version)
     * (could not find better NSS interface) */
    SSLChannelInfo inf;
    if (SSL_GetChannelInfo(ssl, &inf, sizeof(inf)) < 0)
        inf.protocolVersion = 0;

    size_t n;
    const char *s = NULL;
    switch (inf.protocolVersion) {
      case SSL_LIBRARY_VERSION_TLS_1_3: s="TLSv1.3";n=sizeof("TLSv1.3")-1;break;
      case SSL_LIBRARY_VERSION_TLS_1_2: s="TLSv1.2";n=sizeof("TLSv1.2")-1;break;
      case SSL_LIBRARY_VERSION_TLS_1_1: s="TLSv1.1";n=sizeof("TLSv1.1")-1;break;
      case SSL_LIBRARY_VERSION_TLS_1_0: s="TLSv1.0";n=sizeof("TLSv1.0")-1;break;
      default: break;
    }
    if (s) http_header_env_set(r, CONST_STR_LEN("SSL_PROTOCOL"), s, n);

    char *cipher;
    int algkeysize;
    int usekeysize;
    if (SSL_SecurityStatus(ssl, NULL, &cipher, &algkeysize, &usekeysize,
                           NULL, NULL) < 0)
        return;

    if (cipher) {
        n = strlen(cipher);
        http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER"), cipher, n);
        PR_Free(cipher);
    }

    /* SSL_CIPHER_ALGKEYSIZE - Number of cipher bits (possible) */
    /* SSL_CIPHER_USEKEYSIZE - Number of cipher bits (actually used) */
    char buf[LI_ITOSTRING_LENGTH];
    http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                        buf, li_utostrn(buf, sizeof(buf), usekeysize));
    http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                        buf, li_utostrn(buf, sizeof(buf), algkeysize));
}


REQUEST_FUNC(mod_nss_handle_request_env)
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


REQUEST_FUNC(mod_nss_handle_uri_raw)
{
    /* mod_nss must be loaded prior to mod_auth
     * if mod_nss is configured to set REMOTE_USER based on client cert */
    /* mod_nss must be loaded after mod_extforward
     * if mod_nss config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward, *unless* PROXY protocol
     * is enabled with extforward.hap-PROXY = "enable", in which case the
     * reverse is true: mod_extforward must be loaded after mod_nss */
    plugin_data *p = p_d;
    handler_ctx *hctx = r->con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    mod_nss_patch_config(r, &hctx->conf);
    if (hctx->conf.ssl_verifyclient) {
        mod_nss_handle_request_env(r, p);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_nss_handle_request_reset)
{
    plugin_data *p = p_d;
    r->plugin_ctx[p->id] = NULL; /* simple flag for request_env_patched */
    return HANDLER_GO_ON;
}


TRIGGER_FUNC(mod_nss_handle_trigger) {
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/

    mod_nss_refresh_stapling_files(srv, p, cur_ts);

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_nss_plugin_init (plugin *p);
int mod_nss_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "nss";
    p->init         = mod_nss_init;
    p->cleanup      = mod_nss_free;
    p->priv_defaults= mod_nss_set_defaults;

    p->handle_connection_accept  = mod_nss_handle_con_accept;
    p->handle_connection_shut_wr = mod_nss_handle_con_shut_wr;
    p->handle_connection_close   = mod_nss_handle_con_close;
    p->handle_uri_raw            = mod_nss_handle_uri_raw;
    p->handle_request_env        = mod_nss_handle_request_env;
    p->handle_request_reset      = mod_nss_handle_request_reset;
    p->handle_trigger            = mod_nss_handle_trigger;

    return 0;
}


static int
mod_nss_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist)
{
    log_error(srv->errh, __FILE__, __LINE__,
              "NSS: ignoring Curves/Groups; not implemented (%s)",
              curvelist->ptr);
    UNUSED(s);
    UNUSED(curvelist);

    /* XXX: TODO: see ssl/sslt.h enum SSLNamedGroup */

    return 1;
}


static PRUint16
mod_nss_ssl_conf_proto_val (server *srv, const buffer *b, int max)
{
    /* use of SSL v3 should be avoided, and SSL v2 is not supported here */
    if (NULL == b) /* default: min TLSv1.2, max TLSv1.3 */
        return max ? SSL_LIBRARY_VERSION_TLS_1_3 : SSL_LIBRARY_VERSION_TLS_1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        return max ? SSL_LIBRARY_VERSION_TLS_1_3 : SSL_LIBRARY_VERSION_TLS_1_0;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.0")))
        return SSL_LIBRARY_VERSION_TLS_1_0;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.1")))
        return SSL_LIBRARY_VERSION_TLS_1_1;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        return SSL_LIBRARY_VERSION_TLS_1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        return SSL_LIBRARY_VERSION_TLS_1_3;
    else {
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1.2")))
            log_error(srv->errh, __FILE__, __LINE__,
                      "NSS: ssl.openssl.ssl-conf-cmd %s %s ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
        else
            log_error(srv->errh, __FILE__, __LINE__,
                      "NSS: ssl.openssl.ssl-conf-cmd %s %s invalid; ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
    }
    return max ? SSL_LIBRARY_VERSION_TLS_1_3 : SSL_LIBRARY_VERSION_TLS_1_2;
}


static void
mod_nss_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *minb, const buffer *maxb)
{
    s->protos.min = mod_nss_ssl_conf_proto_val(srv, minb, 0);
    s->protos.max = mod_nss_ssl_conf_proto_val(srv, maxb, 1);
    /* XXX: could check values against SSL_VersionRangeGetSupported() */
}


/**
 * Apache mod_nss
 * https://pagure.io/mod_nss.git
 *
 * (with minor modifications to compile in lighttpd)
 */

#define ap_log_error(APLOG_MARK, APLOG_INFO, rc, errh, ...) \
        log_error(errh, __FILE__, __LINE__, __VA_ARGS__)
typedef log_error_st server_rec;


/*
 * mod_nss/nss_engine_cipher.h
 */

/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Cipher definitions
 */
typedef struct
{
    const char *name;            /* The mod_nss cipher name */
    PRInt32 num;                 /* The cipher id */
    const char *openssl_name;    /* The OpenSSL cipher name */
    PRInt32 attr;                /* cipher attributes: algorithms, etc */
    PRInt32 version;             /* protocol version valid for this cipher */
    PRInt32 strength;            /* LOW, MEDIUM, HIGH */
    PRInt32 bits;                /* bits of strength */
    PRInt32 alg_bits;            /* bits of the algorithm */
    const char *alias;           /* Other names, usually typos. Right now a
                                    single string but could be CSV */
} cipher_properties;

/* OpenSSL-compatible cipher attributes */
#define SSL_kRSA	0x00000001L
#define SSL_aRSA	0x00000002L
#define SSL_aDSS	0x00000004L
#define SSL_DSS		SSL_aDSS
#define SSL_eNULL	0x00000008L
#define SSL_DES		0x00000010L
#define SSL_3DES	0x00000020L
#define SSL_RC4		0x00000040L
#define SSL_RC2		0x00000080L
#define SSL_MD5		0x00000200L
#define SSL_SHA1	0x00000400L
#define SSL_SHA		SSL_SHA1
#define SSL_RSA		(SSL_kRSA)
#define SSL_kEDH	0x00000800L
#define SSL_EDH		(SSL_kDHE)
#define SSL_aNULL	0x00001000L
#define SSL_kECDHE	0x00002000L
#define SSL_AECDH	0x00004000L
#define SSL_aECDSA	0x00008000L
#define SSL_kECDHr	0x00010000L
#define SSL_kEECDH	0x00020000L
#define SSL_ECDH	(SSL_kECDHE|SSL_kECDHr|SSL_kEECDH)
#define SSL_EECDH	(SSL_kEECDH)
#define SSL_ADH		(SSL_kEDH)
#define SSL_kDHE	0x00040000L
#define SSL_DHE		(SSL_kDHE)

/* cipher strength */
#define SSL_STRONG_NONE   0x00000001L
#define SSL_NULL          0x00000002L
#define SSL_EXPORT40      0x00000004L
#define SSL_EXPORT56      0x00000008L
#define SSL_LOW           0x00000010L
#define SSL_MEDIUM        0x00000020L
#define SSL_HIGH          0x00000040L

#define SSL_CHACHA20POLY1305   0x00080000L
#define SSL_AES128             0x00400000L
#define SSL_AES256             0x00800000L
#define SSL_CAMELLIA128        0x01000000L
#define SSL_CAMELLIA256        0x02000000L
#define SSL_AES128GCM          0x04000000L
#define SSL_AES256GCM          0x08000000L
#define SSL_SHA256             0x10000000L
#define SSL_SHA384             0x20000000L
#define SSL_AEAD               0x40000000L

#define SSL_AES           (SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM)
#define SSL_CAMELLIA      (SSL_CAMELLIA128|SSL_CAMELLIA256)

/* Protocols */
#define SSLV2              0x00000001L
#define SSLV3              0x00000002L
#define TLSV1              SSLV3
#define TLSV1_2            0x00000004L
#define TLSV1_3            0x00000008L

#if 0
/* the table itself is defined in nss_engine_cipher.c */
#if 0
#ifdef NSS_ENABLE_ECC
# ifdef ENABLE_SHA384
#  define ciphernum 54
# else
#  define ciphernum 49
# endif
#else
#define ciphernum 20
#endif
#endif

extern int ciphernum;

/* function prototypes */
int nss_parse_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum]);
int countciphers(PRBool cipher_state[ciphernum], int version);
#endif

/* I chose an arbitrary cipher to test the existence for to handle older
 * versions of NSS, at least back to 3.15.1
 */
#ifndef TLS_NULL_WITH_NULL_NULL
#define TLS_NULL_WITH_NULL_NULL                SSL_NULL_WITH_NULL_NULL
#define TLS_RSA_WITH_NULL_MD5                  SSL_RSA_WITH_NULL_MD5
#define TLS_RSA_WITH_NULL_SHA                  SSL_RSA_WITH_NULL_SHA
#define TLS_RSA_EXPORT_WITH_RC4_40_MD5         SSL_RSA_EXPORT_WITH_RC4_40_MD5
#define TLS_RSA_WITH_RC4_128_MD5               SSL_RSA_WITH_RC4_128_MD5
#define TLS_RSA_WITH_RC4_128_SHA               SSL_RSA_WITH_RC4_128_SHA
#define TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
#define TLS_RSA_WITH_IDEA_CBC_SHA              SSL_RSA_WITH_IDEA_CBC_SHA
#define TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      SSL_RSA_EXPORT_WITH_DES40_CBC_SHA
#define TLS_RSA_WITH_DES_CBC_SHA               SSL_RSA_WITH_DES_CBC_SHA
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA          SSL_RSA_WITH_3DES_EDE_CBC_SHA
#endif


/*
 * mod_nss/nss_engine_cipher.c
 */

/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef NSS_INCLUDE_PREFIX_VER
#include <nss3/sslproto.h>
#else
#ifdef NSS_INCLUDE_PREFIX
#include <nss/sslproto.h>
#else
#include <sslproto.h>
#endif
#endif

/* Cipher actions */
#define PERMANENTLY_DISABLE_CIPHER   -1 /* !CIPHER */
#define SUBTRACT_CIPHER               0 /* -CIPHER */
#define ENABLE_CIPHER                 1 /* CIPHER */
#define REORDER_CIPHER                2 /* +CIPHER */

///* ciphernum is defined in nss_engine_cipher.h */
static const cipher_properties ciphers_def[] =
{
    {"rsa_null_md5", TLS_RSA_WITH_NULL_MD5, "NULL-MD5", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_MD5, SSLV3, SSL_STRONG_NONE, 0, 0, NULL},
    {"rsa_null_sha", TLS_RSA_WITH_NULL_SHA, "NULL-SHA", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA1, SSLV3, SSL_STRONG_NONE, 0, 0, NULL},
    {"rsa_rc4_40_md5", TLS_RSA_EXPORT_WITH_RC4_40_MD5, "EXP-RC4-MD5", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSLV3, SSL_EXPORT40, 40, 128, NULL},
    {"rsa_rc4_128_md5", TLS_RSA_WITH_RC4_128_MD5, "RC4-MD5", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSLV3, SSL_MEDIUM, 128, 128, NULL},
    {"rsa_rc4_128_sha", TLS_RSA_WITH_RC4_128_SHA, "RC4-SHA", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, SSLV3, SSL_MEDIUM, 128, 128, NULL},
    {"rsa_rc2_40_md5", TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, "EXP-RC2-CBC-MD5", SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5, SSLV3, SSL_EXPORT40, 40, 128, NULL},
    /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA not implemented 0x0008 */
    {"rsa_des_sha", TLS_RSA_WITH_DES_CBC_SHA, "DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56, NULL},
    {"rsa_3des_sha", TLS_RSA_WITH_3DES_EDE_CBC_SHA, "DES-CBC3-SHA", SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSLV3, SSL_MEDIUM, 168, 168, NULL},
//#ifdef ENABLE_SERVER_DHE
    {"dhe_rsa_des_sha", TLS_DHE_RSA_WITH_DES_CBC_SHA, "EDH-RSA-DES-CBC-SHA", SSL_kDHE|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56, NULL},
//#endif
    {"rsa_aes_128_sha", TLS_RSA_WITH_AES_128_CBC_SHA, "AES128-SHA", SSL_kRSA|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"rsa_aes_256_sha", TLS_RSA_WITH_AES_256_CBC_SHA, "AES256-SHA", SSL_kRSA|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"null_sha_256", TLS_RSA_WITH_NULL_SHA256, "NULL-SHA256", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA256, TLSV1_2, SSL_STRONG_NONE, 0, 0, NULL},
    {"aes_128_sha_256", TLS_RSA_WITH_AES_128_CBC_SHA256, "AES128-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128, NULL},
    {"aes_256_sha_256", TLS_RSA_WITH_AES_256_CBC_SHA256, "AES256-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES256|SSL_SHA256, TLSV1_2, SSL_HIGH, 256, 256, NULL},
    {"camellia_128_sha", TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, "CAMELLIA128-SHA", SSL_kRSA|SSL_aRSA|SSL_CAMELLIA128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, "camelia_128_sha"},
    {"rsa_des_56_sha", TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, "EXP1024-DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, TLSV1, SSL_EXPORT56, 56, 56, NULL},
    {"rsa_rc4_56_sha", TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, "EXP1024-RC4-SHA", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_EXPORT56, 56, 128, NULL},
    {"camellia_256_sha", TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, "CAMELLIA256-SHA", SSL_kRSA|SSL_aRSA|SSL_CAMELLIA256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, "camelia_256_sha"},
//#ifdef ENABLE_GCM
    {"rsa_aes_128_gcm_sha_256", TLS_RSA_WITH_AES_128_GCM_SHA256, "AES128-GCM-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128, NULL},
//#endif
//#ifdef ENABLE_SHA384
    {"rsa_aes_256_gcm_sha_384", TLS_RSA_WITH_AES_256_GCM_SHA384, "AES256-GCM-SHA384", SSL_kRSA|SSL_aRSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
//#endif
    {"fips_3des_sha", SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, "FIPS-DES-CBC3-SHA", SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSLV3, SSL_MEDIUM, 112, 168, NULL},
    {"fips_des_sha", SSL_RSA_FIPS_WITH_DES_CBC_SHA, "FIPS-DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56, NULL},
//#ifdef ENABLE_SERVER_DHE
    {"dhe_rsa_3des_sha", TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, "DHE-RSA-DES-CBC3-SHA", SSL_kDHE|SSL_aRSA|SSL_3DES|SSL_SHA1, TLSV1, SSL_MEDIUM, 112, 168, NULL},
    {"dhe_rsa_aes_128_sha", TLS_DHE_RSA_WITH_AES_128_CBC_SHA, "DHE-RSA-AES128-SHA", SSL_kDHE|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"dhe_rsa_aes_256_sha", TLS_DHE_RSA_WITH_AES_256_CBC_SHA, "DHE-RSA-AES256-SHA", SSL_kDHE|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"dhe_rsa_camellia_128_sha", TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, "DHE-RSA-CAMELLIA128-SHA", SSL_kDHE|SSL_aRSA|SSL_CAMELLIA128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"dhe_rsa_camellia_256_sha", TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, "DHE-RSA-CAMELLIA256-SHA", SSL_kDHE|SSL_aRSA|SSL_CAMELLIA256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"dhe_rsa_aes_128_sha_256", TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, "DHE-RSA-AES128-SHA256", SSL_kDHE|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128, "dhe_rsa_aes_128_sha256"},
    {"dhe_rsa_aes_256_sha_256", TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, "DHE-RSA-AES256-SHA256", SSL_kDHE|SSL_aRSA|SSL_AES256|SSL_SHA256, TLSV1_2, SSL_HIGH, 256, 256, "dhe_rsa_aes_256_sha256"},
//#ifdef ENABLE_GCM
    {"dhe_rsa_aes_128_gcm_sha_256", TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, "DHE-RSA-AES128-GCM-SHA256", SSL_kDHE|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128, NULL},
//#endif
//#ifdef ENABLE_SHA384
    {"dhe_rsa_aes_256_gcm_sha_384", TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, "DHE-RSA-AES256-GCM-SHA384", SSL_kDHE|SSL_aRSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
//#endif
//#endif /* ENABLE_SERVER_DHE */
//#ifdef NSS_ENABLE_ECC
    {"ecdh_ecdsa_null_sha", TLS_ECDH_ECDSA_WITH_NULL_SHA, "ECDH-ECDSA-NULL-SHA", SSL_kECDHE|SSL_AECDH|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0, NULL},
    {"ecdh_ecdsa_rc4_128_sha", TLS_ECDH_ECDSA_WITH_RC4_128_SHA, "ECDH-ECDSA-RC4-SHA", SSL_kECDHE|SSL_AECDH|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128, NULL},
    {"ecdh_ecdsa_3des_sha", TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, "ECDH-ECDSA-DES-CBC3-SHA", SSL_kECDHE|SSL_AECDH|SSL_3DES|SSL_SHA1, TLSV1, SSL_MEDIUM, 112, 168, NULL},
    {"ecdh_ecdsa_aes_128_sha", TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, "ECDH-ECDSA-AES128-SHA", SSL_kECDHE|SSL_AECDH|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"ecdh_ecdsa_aes_256_sha", TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, "ECDH-ECDSA-AES256-SHA", SSL_kECDHE|SSL_AECDH|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_ecdsa_null_sha", TLS_ECDHE_ECDSA_WITH_NULL_SHA, "ECDHE-ECDSA-NULL-SHA", SSL_kEECDH|SSL_aECDSA|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0, NULL},
    {"ecdhe_ecdsa_rc4_128_sha", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "ECDHE-ECDSA-RC4-SHA", SSL_kEECDH|SSL_aECDSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128, NULL},
    {"ecdhe_ecdsa_3des_sha", TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, "ECDHE-ECDSA-DES-CBC3-SHA", SSL_kEECDH|SSL_aECDSA|SSL_3DES|SSL_SHA1, TLSV1, SSL_MEDIUM, 112, 168, NULL},
    {"ecdhe_ecdsa_aes_128_sha", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "ECDHE-ECDSA-AES128-SHA", SSL_kEECDH|SSL_aECDSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"ecdhe_ecdsa_aes_256_sha", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ECDHE-ECDSA-AES256-SHA", SSL_kEECDH|SSL_aECDSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"ecdh_rsa_null_sha", TLS_ECDH_RSA_WITH_NULL_SHA, "ECDH-RSA-NULL-SHA", SSL_kECDHr|SSL_AECDH|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0, NULL},
    {"ecdh_rsa_128_sha", TLS_ECDH_RSA_WITH_RC4_128_SHA, "ECDH-RSA-RC4-SHA", SSL_kECDHr|SSL_AECDH|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128, NULL},
    {"ecdh_rsa_3des_sha", TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, "ECDH-RSA-DES-CBC3-SHA", SSL_kECDHr|SSL_AECDH|SSL_3DES|SSL_SHA1, TLSV1, SSL_MEDIUM, 112, 168, NULL},
    {"ecdh_rsa_aes_128_sha", TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, "ECDH-RSA-AES128-SHA", SSL_kECDHr|SSL_AECDH|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"ecdh_rsa_aes_256_sha", TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, "ECDH-RSA-AES256-SHA", SSL_kECDHr|SSL_AECDH|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_rsa_null", TLS_ECDHE_RSA_WITH_NULL_SHA, "ECDHE-RSA-NULL-SHA", SSL_kEECDH|SSL_aRSA|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0, NULL},
    {"ecdhe_rsa_rc4_128_sha", TLS_ECDHE_RSA_WITH_RC4_128_SHA, "ECDHE-RSA-RC4-SHA", SSL_kEECDH|SSL_aRSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128, NULL},
    {"ecdhe_rsa_3des_sha", TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "ECDHE-RSA-DES-CBC3-SHA", SSL_kEECDH|SSL_aRSA|SSL_3DES|SSL_SHA1, TLSV1, SSL_MEDIUM, 112, 168, NULL},
    {"ecdhe_rsa_aes_128_sha", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "ECDHE-RSA-AES128-SHA", SSL_kEECDH|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"ecdhe_rsa_aes_256_sha", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "ECDHE-RSA-AES256-SHA", SSL_kEECDH|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"ecdh_anon_null_sha", TLS_ECDH_anon_WITH_NULL_SHA, "AECDH-NULL-SHA", SSL_kEECDH|SSL_aNULL|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0, NULL},
    {"ecdh_anon_rc4_128sha", TLS_ECDH_anon_WITH_RC4_128_SHA, "AECDH-RC4-SHA", SSL_kEECDH|SSL_aNULL|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128, NULL},
    {"ecdh_anon_3des_sha", TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, "AECDH-DES-CBC3-SHA", SSL_kEECDH|SSL_aNULL|SSL_3DES|SSL_SHA1, TLSV1, SSL_MEDIUM, 112, 168, NULL},
    {"ecdh_anon_aes_128_sha", TLS_ECDH_anon_WITH_AES_128_CBC_SHA, "AECDH-AES128-SHA", SSL_kEECDH|SSL_aNULL|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128, NULL},
    {"ecdh_anon_aes_256_sha", TLS_ECDH_anon_WITH_AES_256_CBC_SHA, "AECDH-AES256-SHA", SSL_kEECDH|SSL_aNULL|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_ecdsa_aes_128_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", SSL_kEECDH|SSL_aECDSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128, NULL},
    {"ecdhe_rsa_aes_128_sha_256", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "ECDHE-RSA-AES128-SHA256", SSL_kEECDH|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128, NULL},
//#ifdef ENABLE_GCM
    {"ecdhe_ecdsa_aes_128_gcm_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256", SSL_kEECDH|SSL_aECDSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128, NULL},
//#endif
//#ifdef ENABLE_SHA384
    {"ecdhe_ecdsa_aes_256_sha_384", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "ECDHE-ECDSA-AES256-SHA384", SSL_kEECDH|SSL_aECDSA|SSL_AES256|SSL_SHA384, TLSV1_2, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_rsa_aes_256_sha_384", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "ECDHE-RSA-AES256-SHA384", SSL_kEECDH|SSL_aRSA|SSL_AES256|SSL_SHA384, TLSV1_2, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_ecdsa_aes_256_gcm_sha_384", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384", SSL_kEECDH|SSL_aECDSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_rsa_aes_256_gcm_sha_384", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM-SHA384", SSL_kEECDH|SSL_aRSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
//#endif
//#ifdef ENABLE_GCM
    {"ecdhe_rsa_aes_128_gcm_sha_256", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256", SSL_kEECDH|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128, NULL},
//#endif
    /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 is not implemented */
    /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 is not implemented */
    /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 is not implemented */
    /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 is not implemented */
//#endif
//#ifdef ENABLE_CHACHA20
    {"ecdhe_rsa_chacha20_poly1305_sha_256", TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-RSA-CHACHA20-POLY1305", SSL_kEECDH|SSL_aRSA|SSL_CHACHA20POLY1305|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
    {"ecdhe_ecdsa_chacha20_poly1305_sha_256", TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-ECDSA-CHACHA20-POLY1305", SSL_kEECDH|SSL_aECDSA|SSL_CHACHA20POLY1305|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
    {"dhe_rsa_chacha20_poly1305_sha_256", TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "DHE-RSA-CHACHA20-POLY1305", SSL_kDHE|SSL_aRSA|SSL_CHACHA20POLY1305|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256, NULL},
//#endif
//#ifdef NSS_SUPPORTS_TLS_1_3
  #ifdef TLS_AES_128_GCM_SHA256
    /* Special TLS 1.3 cipher suites that really just specify AEAD
     * TLS 1.3 ciphers don't specify key exchange and authentication.
     */
    {"aes_128_gcm_sha_256", TLS_AES_128_GCM_SHA256, "TLS-AES-128-GCM-SHA256", SSL_AES128GCM|SSL_AEAD, TLSV1_3, SSL_HIGH, 128, 128, NULL},
    {"aes_256_gcm_sha_384", TLS_AES_256_GCM_SHA384, "TLS-AES-256-GCM-SHA384", SSL_AES256GCM|SSL_AEAD, TLSV1_3, SSL_HIGH, 256, 256, NULL},
    {"chacha20_poly1305_sha_256", TLS_CHACHA20_POLY1305_SHA256, "TLS-CHACHA20-POLY1305_SHA256", SSL_CHACHA20POLY1305|SSL_AEAD, TLSV1_3, SSL_HIGH, 256, 256, NULL},
  #endif
//#endif
};

#define CIPHERNUM sizeof(ciphers_def) / sizeof(cipher_properties)
//static const int ciphernum = CIPHERNUM;
#define ciphernum ((int)(CIPHERNUM))

/* Some ciphers are optionally enabled in OpenSSL. For safety sake assume
 * they are not available.
 */
static const int skip_ciphers = 4;
static const int ciphers_not_in_openssl[] = {
    SSL_RSA_FIPS_WITH_DES_CBC_SHA,
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
};

static int parse_nss_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum]);
static int parse_openssl_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum]);

static
int countciphers(PRBool cipher_state[ciphernum], int version) {
    int ciphercount = 0;
    int i = 0;

    for (i = 0; i < ciphernum; i++)
    {
        if ((cipher_state[i] == PR_TRUE) &&
            (ciphers_def[i].version & version)) {
            ciphercount++;
        }
    }

    return ciphercount;
}


static
int nss_parse_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    UNUSED(s);
    int rv = 0;

    /* If the string has a colon we use the OpenSSL style. If it has a
     * comma then NSS. If it has neither we try both. */
    if (strchr(ciphers, ':')) {
        rv = parse_openssl_ciphers(s, ciphers, cipher_list);
    } else if (strchr(ciphers, ',')) {
        rv = parse_nss_ciphers(s, ciphers, cipher_list);
    } else {
        rv = parse_openssl_ciphers(s, ciphers, cipher_list);
        if (rv == 0 && 0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2|TLSV1_3)) {
            rv = parse_nss_ciphers(s, ciphers, cipher_list);
        }
    }
    if (0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2|TLSV1_3)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "no cipher match");
    }

    return rv;
}


/* Given a set of ciphers perform a given action on the indexed value.
 *
 * This is needed because the + action doesn't do anything in the NSS
 * context. In OpenSSL it will re-order the cipher list.
 */
static void set_cipher_value(PRBool cipher_list[ciphernum], int index, int action)
{
    int i;

    if (action == REORDER_CIPHER)
        /* NSS doesn't allow ordering so do nothing */
        return;

    for (i = 0; i < skip_ciphers; i++) {
        if (ciphers_def[index].num == ciphers_not_in_openssl[i]) {
            cipher_list[index] = PERMANENTLY_DISABLE_CIPHER;
            return;
        }
    }

    if (cipher_list[index] != PERMANENTLY_DISABLE_CIPHER)
        cipher_list[index] = action;
}


static int parse_openssl_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    UNUSED(s);
    char * cipher;
    int i, action;
    PRBool merge = PR_FALSE;
    PRBool found = PR_FALSE;
    PRBool first = PR_TRUE;

    cipher = ciphers;
    while (ciphers && (strlen(ciphers)))
    {
        while ((*cipher) && (isspace(*(uint8_t *)cipher)))
            ++cipher;

        action = ENABLE_CIPHER; /* default to enable */
        switch(*cipher)
        {
            case '+':
                /* Cipher ordering is not supported in NSS */
                action = REORDER_CIPHER;
                cipher++;
                break;
            case '-':
                action = SUBTRACT_CIPHER;
                cipher++;
                break;
            case '!':
                action = PERMANENTLY_DISABLE_CIPHER;
                cipher++;
                break;
            default:
                /* Add the cipher */
                break;
        }

        if ((ciphers = strchr(cipher, ':'))) {
            *ciphers++ = '\0';
            merge = PR_FALSE;
            found = PR_FALSE;
        }

        if (!strcmp(cipher, "ALL")) {
            found = PR_TRUE;
            for (i=0; i<ciphernum; i++) {
                if (!(ciphers_def[i].attr & SSL_eNULL))
                    set_cipher_value(cipher_list, i, action);
            }
        } else if (!strcmp(cipher, "COMPLEMENTOFALL")) {
            found = PR_TRUE;
            for (i=0; i<ciphernum; i++) {
                if ((ciphers_def[i].attr & SSL_eNULL))
                    set_cipher_value(cipher_list, i, action);
            }
        } else if (!strcmp(cipher, "DEFAULT")) {
            /* In OpenSSL the default cipher list is
             *    ALL:!aNULL:!eNULL:!SSLv2
             * So we need to disable all the NULL ciphers too.
             */
            int mask = SSL_aNULL | SSL_eNULL;
            found = PR_TRUE;
            for (i=0; i < ciphernum; i++) {
                if (cipher_list[i] != PERMANENTLY_DISABLE_CIPHER)
                    SSL_CipherPrefGetDefault(ciphers_def[i].num,
                                             &cipher_list[i]);
                if (PR_TRUE == first) {
                    if (ciphers_def[i].attr & mask) {
                        set_cipher_value(cipher_list, i,
                                         PERMANENTLY_DISABLE_CIPHER);
                    }
                }
            }
        } else if (!strcmp(cipher, "COMPLEMENTOFDEFAULT")) {
            found = PR_TRUE;
            /* no-op. In OpenSSL this is the ADH ciphers */
        } else if (!strcmp(cipher, "@STRENGTH")) {
            /* No cipher ordering in NSS */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "Cipher ordering is not supported in NSS");
            return -1;
        } else {
            int amask = 0;
            int amaskaction = 0;
            int mask = 0;
            int strength = 0;
            int protocol = 0;
            char *c;
            PRBool candidate_list[ciphernum];
            PRBool temp_list[ciphernum];

            for (i = 0; i < ciphernum; i++) {
                candidate_list[i] = 1;
            }

            c = cipher;
            while (c && (strlen(c))) {
                amask = 0;
                amaskaction = 0;
                mask = 0;
                strength = 0;
                protocol = 0;
                for (i = 0; i < ciphernum; i++) {
                    temp_list[i] = 0;
                }

                if ((c = strchr(cipher, '+'))) {
                    *c++ = '\0';
                }

                if (!strcmp(cipher, "RSA")) {
                    mask |= SSL_RSA;
                } else if (!strcmp(cipher, "kRSA")) {
                    mask |= SSL_kRSA;
                } else if (!strcmp(cipher, "aRSA")) {
                    mask |= SSL_aRSA;
                } else if (!strcmp(cipher, "EDH")) {
                    /* Normally this is kEDH:-ADH but since we don't
                     * support ADH this is sufficient.
                     */
                    mask |= SSL_kEDH;
                } else if (!strcmp(cipher, "DH")) {
                    /* non-ephemeral DH. The ciphers are defined
                     * but not implemented in OpenSSL so manage
                     * this here.
                     */
                    mask |= SSL_kDHE;
#if 0
                } else if (!strcmp(cipher, "ADH")) {
                    mask |= SSL_ADH;
#endif
                } else if (!strcmp(cipher, "ECDH")) {
                    mask |= SSL_ECDH;
                } else if (!strcmp(cipher, "EECDH")) {
                    mask |= SSL_kEECDH;
                    amask = SSL_aNULL;
                    amaskaction = 1; /* filter anonymous out */
                } else if (!strcmp(cipher, "AECDH")) {
                    mask |= SSL_kEECDH;
                    amask = SSL_aNULL; /* require anonymous */
                    amaskaction = 0; /* keep these */
                } else if (!strcmp(cipher, "kECDH")) {
                    mask |= SSL_kECDHE | SSL_kECDHr;
                } else if (!strcmp(cipher, "kECDHE")) {
                    mask |= SSL_kECDHE;
                } else if (!strcmp(cipher, "kECDHr")) {
                    mask |= SSL_kECDHr;
                } else if (!strcmp(cipher, "kEECDH")) {
                    mask |= SSL_kEECDH;
                } else if (!strcmp(cipher, "AECDH")) {
                    mask |= SSL_AECDH;
                } else if (!strcmp(cipher, "ECDSA")) {
                    mask |= SSL_aECDSA;
                } else if (!strcmp(cipher, "aECDSA")) {
                    mask |= SSL_aECDSA;
                } else if ((!strcmp(cipher, "NULL")) || (!strcmp(cipher, "eNULL"))) {
                    mask |= SSL_eNULL;
                } else if (!strcmp(cipher, "aNULL")) {
                    mask |= SSL_aNULL;
                } else if (!strcmp(cipher, "AES")) {
                    mask |= SSL_AES;
                } else if (!strcmp(cipher, "AESGCM")) {
                    mask |= SSL_AES128GCM|SSL_AES256GCM;
                } else if (!strcmp(cipher, "AES128")) {
                    mask |= SSL_AES128|SSL_AES128GCM;
                } else if (!strcmp(cipher, "AES256")) {
                    mask |= SSL_AES256|SSL_AES256GCM;
                } else if (!strcmp(cipher, "CHACHA20")) {
                    mask |= SSL_CHACHA20POLY1305;
                } else if (!strcmp(cipher, "CAMELLIA")) {
                    mask |= SSL_CAMELLIA128|SSL_CAMELLIA256;
                } else if (!strcmp(cipher, "CAMELLIA128")) {
                    mask |= SSL_CAMELLIA128;
                } else if (!strcmp(cipher, "CAMELLIA256")) {
                    mask |= SSL_CAMELLIA256;
                } else if (!strcmp(cipher, "3DES")) {
                    mask |= SSL_3DES;
                } else if (!strcmp(cipher, "DES")) {
                    mask |= SSL_DES;
                } else if (!strcmp(cipher, "RC4")) {
                    mask |= SSL_RC4;
                } else if (!strcmp(cipher, "RC2")) {
                    mask |= SSL_RC2;
                } else if (!strcmp(cipher, "MD5")) {
                    mask |= SSL_MD5;
                } else if ((!strcmp(cipher, "SHA")) || (!strcmp(cipher, "SHA1"))) {
                    mask |= SSL_SHA1;
                } else if (!strcmp(cipher, "SHA256")) {
                    mask |= SSL_SHA256;
                } else if (!strcmp(cipher, "SHA384")) {
                    mask |= SSL_SHA384;
                } else if (!strcmp(cipher, "SSLv2")) {
                    /* no-op */
                } else if (!strcmp(cipher, "SSLv3")) {
                    protocol |= SSLV3;
                } else if (!strcmp(cipher, "TLSv1")) {
                    protocol |= TLSV1;
                } else if (!strcmp(cipher, "TLSv1.2")) {
                    protocol |= TLSV1_2;
                } else if (!strcmp(cipher, "TLSv1.3")) {
                    protocol |= TLSV1_3;
                } else if (!strcmp(cipher, "HIGH")) {
                    strength |= SSL_HIGH;
                } else if (!strcmp(cipher, "MEDIUM")) {
                    strength |= SSL_MEDIUM;
                } else if (!strcmp(cipher, "LOW")) {
                    strength |= SSL_LOW;
                } else if ((!strcmp(cipher, "EXPORT")) || (!strcmp(cipher, "EXP"))) {
                    strength |= SSL_EXPORT40|SSL_EXPORT56;
                } else if (!strcmp(cipher, "EXPORT40")) {
                    strength |= SSL_EXPORT40;
                } else if (!strcmp(cipher, "EXPORT56")) {
                    strength |= SSL_EXPORT56;
                }

                if (c)
                    cipher = c;

                /* If we have a mask, apply it. If not then perhaps they
                 * provided a specific cipher to enable.
                 */
                if (mask || strength || protocol) {
                    merge = PR_TRUE;
                    found = PR_TRUE;
                    for (i=0; i<ciphernum; i++) {
                        if (((ciphers_def[i].attr & mask) ||
                         (ciphers_def[i].strength & strength) ||
                         (ciphers_def[i].version & protocol)) &&
                         (cipher_list[i] != PERMANENTLY_DISABLE_CIPHER)) {
                            if (amask != 0) {
                                PRBool match = PR_FALSE;
                                if (ciphers_def[i].attr & amask) {
                                    match = PR_TRUE;
                                }
                                if (amaskaction && match)
                                    continue;
                                if (!amaskaction && !match)
                                    continue;
                            }
#if 0
                            /* Enable the NULL ciphers only if explicity
                             * requested */
                            if (ciphers_def[i].attr & SSL_eNULL) {
                                if (mask & SSL_eNULL)
                                    temp_list[i] = 1;
                            } else
#endif
                                temp_list[i] = 1;
                            }
                    }
                    /* Merge the temp list into the candidate list */
                    for (i=0; i<ciphernum; i++) {
                        if (!(candidate_list[i] & temp_list[i])) {
                            candidate_list[i] = 0;
                        }
                    }
                } else if (!strcmp(cipher, "FIPS")) {
                        SSLCipherSuiteInfo suite;
                    for (i=0; i<ciphernum;i++) {
                        if (SSL_GetCipherSuiteInfo(ciphers_def[i].num,
                            &suite, sizeof suite) == SECSuccess) {
                            if (suite.isFIPS)
                                set_cipher_value(cipher_list, i, action);
                        }
                    }
                } else {
                    for (i=0; i<ciphernum; i++) {
                        if (!strcmp(ciphers_def[i].openssl_name, cipher))
                            set_cipher_value(cipher_list, i, action);
                    }
                }
            } /* while */
            if (PR_TRUE == merge) {
                first = PR_FALSE;
                /* Merge the candidate list into the cipher list */
                for (i=0; i<ciphernum; i++) {
                    if (candidate_list[i])
                        set_cipher_value(cipher_list, i, action);
                }
                merge = PR_FALSE;
                found = PR_FALSE;
            }
        }

        if (ciphers)
            cipher = ciphers;

    }
    if (found && 0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2|TLSV1_3))
        return 1; /* no matching ciphers */
    return 0;
}


static int parse_nss_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    UNUSED(s);
    char * cipher;
    PRBool found;
    int i, active;

    cipher = ciphers;

    while (ciphers && (strlen(ciphers)))
    {
        while ((*cipher) && (isspace(*(uint8_t *)cipher)))
           ++cipher;

        switch(*cipher++)
        {
            case '+':
                active = PR_TRUE;
                break;
            case '-':
                active = PR_FALSE;
                break;
            default:
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                             "invalid cipher string %s. Format is +cipher1,-cipher2...", cipher - 1);
            return -1;
        }

        if ((ciphers = strchr(cipher, ','))) {
            *ciphers++ = '\0';
        }

        found = PR_FALSE;

        for (i = 0; i < ciphernum; i++)
        {
            if (!strcasecmp(cipher, ciphers_def[i].name))
            {
                cipher_list[i] = active;
                found = PR_TRUE;
                break;
            } else if ((ciphers_def[i].alias != NULL) &&
                (!strcasecmp(cipher, ciphers_def[i].alias)))
            {
                cipher_list[i] = active;
                found = PR_TRUE;
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                             "Deprecated cipher name %s, use %s instead.",
                             cipher, ciphers_def[i].name);
                break;
            }
        }

        if (found == PR_FALSE) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "Unknown cipher %s\n", cipher);
        }

        if (ciphers) {
            cipher = ciphers;
        }
    }

    return 0;
}


static int
mod_nss_ssl_conf_ciphersuites (server *srv, plugin_config_socket *s, buffer *ciphersuites, const buffer *cipherstring)
{
    if (ciphersuites)
        /* XXX: not implemented;
         *      could manually add support for short list of TLSv1.3 suites */
        log_error(srv->errh, __FILE__, __LINE__,
                  "Ciphersuite support not implemented for %s",
                  ciphersuites->ptr);

    if (!cipherstring || buffer_is_blank(cipherstring))
        return 1; /* nothing to do */

    /*
     * Apache mod_nss
     * https://pagure.io/mod_nss.git
     *
     * modified from mod_nss/nss_engine_init.c:nss_init_ctx_cipher_suite()
     */

    PRBool cipher_state[ciphernum];

    /* Disable all NSS supported cipher suites. This is to prevent any new
     * NSS cipher suites from getting automatically and unintentionally
     * enabled as a result of the NSS_SetDomesticPolicy() call. This way,
     * only the ciphers explicitly specified in the server configuration can
     * ever be enabled.
     */
    for (int i = 0; i < SSL_NumImplementedCiphers; ++i)
        SSL_CipherPrefSet(s->model, SSL_ImplementedCiphers[i], SSL_NOT_ALLOWED);

    /* initialize all known ciphers to false */
    for (int i = 0; i < ciphernum; ++i)
        cipher_state[i] = PR_FALSE;

    char *ciphers = strdup(cipherstring->ptr);/*(string modified during parse)*/
    if (NULL == ciphers) return 0;

    int rc = nss_parse_ciphers(srv->errh, ciphers, cipher_state);
    free(ciphers);
    if (-1 == rc) return 0;

    if (s->protos.min && s->protos.min <= SSL_LIBRARY_VERSION_3_0
        && countciphers(cipher_state, SSLV3) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, srv->errh,
          "NSSCipherSuite: SSL3 is enabled but no SSL3 ciphers are enabled.");
        return 0;
    }

    if (s->protos.max >= SSL_LIBRARY_VERSION_TLS_1_0
        && countciphers(cipher_state, TLSV1|TLSV1_2|TLSV1_3) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, srv->errh,
          "NSSCipherSuite: TLS is enabled but no TLS ciphers are enabled.");
        return 0;
    }

    /* Finally actually enable the selected ciphers */
    for (int i = 0; i < ciphernum; ++i)
        SSL_CipherPrefSet(s->model, ciphers_def[i].num,
                          cipher_state[i] == ENABLE_CIPHER
                            ? SSL_ALLOWED
                            : SSL_NOT_ALLOWED);

    return 1;
}
