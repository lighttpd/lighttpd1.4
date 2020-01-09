#include "first.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef USE_OPENSSL_KERBEROS
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#endif

#include "sys-crypto.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif

#if ! defined OPENSSL_NO_TLSEXT && ! defined SSL_CTRL_SET_TLSEXT_HOSTNAME
#define OPENSSL_NO_TLSEXT
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#endif

#include "base.h"
#include "http_header.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    EVP_PKEY *ssl_pemfile_pkey;
    X509 *ssl_pemfile_x509;
    const buffer *ssl_pemfile;
    const buffer *ssl_privkey;
} plugin_cert;

typedef struct {
    SSL_CTX *ssl_ctx;
    EVP_PKEY *ssl_pemfile_pkey;
} plugin_ssl_ctx;

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
    EVP_PKEY *ssl_pemfile_pkey;
    X509 *ssl_pemfile_x509;
    const buffer *ssl_pemfile;
    const buffer *ssl_privkey;
    STACK_OF(X509_NAME) *ssl_ca_file;
    STACK_OF(X509_NAME) *ssl_ca_dn_file;
    const buffer *ssl_ca_crl_file;
    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;
    unsigned char ssl_read_ahead;
} plugin_config_socket; /*(used at startup during configuration)*/

typedef struct {
    /* SNI per host: w/ COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    EVP_PKEY *ssl_pemfile_pkey;
    X509 *ssl_pemfile_x509;
    const buffer *ssl_pemfile;
    STACK_OF(X509_NAME) *ssl_ca_file;
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
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id]; */
static plugin_data *plugin_data_singleton;
#define LOCAL_SEND_BUFSIZE (16 * 1024)
static char *local_send_buffer;

typedef struct {
    SSL *ssl;
    connection *con;
    short renegotiations; /* count of SSL_CB_HANDSHAKE_START */
    short close_notify;
    unsigned short request_env_patched;
    unsigned short alpn;
    plugin_config conf;
    server *srv;
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
   && !defined(LIBRESSL_VERSION_NUMBER)
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

    local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
    force_assert(NULL != local_send_buffer);

    return 1;
}


static void mod_openssl_free_openssl (void)
{
    if (!ssl_is_init) return;

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
                }
                break;
              case 2: /* ssl.ca-file */
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
    /* load all ssl.ca-files specified in the config
     * into each SSL_CTX to be prepared for SNI */

    for (uint32_t i = 0, used = p->cafiles->used; i < used; ++i) {
        const buffer *b = &((data_string *)p->cafiles->data[i])->value;
        if (!mod_openssl_load_verify_locn(ssl_ctx, b, srv))
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
        if (cpv->vtype == T_CONFIG_LOCAL) {
            plugin_cert *pc = cpv->v.v;
            pconf->ssl_pemfile_pkey = pc->ssl_pemfile_pkey;
            pconf->ssl_pemfile_x509 = pc->ssl_pemfile_x509;
            pconf->ssl_pemfile      = pc->ssl_pemfile;
        }
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
      case 13:/* debug.log-ssl-noise */
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
mod_openssl_patch_config (connection * const con, plugin_config * const pconf)
{
    plugin_data * const p = plugin_data_singleton;
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
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

    if (preverify_ok && 0 == depth
        && NULL != hctx->conf.ssl_ca_dn_file
        && NULL != hctx->conf.ssl_ca_file) {
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
    log_error_st *errh = hctx->con->conf.errh;
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

#ifndef OPENSSL_NO_TLSEXT
static int
mod_openssl_SNI (SSL *ssl, handler_ctx *hctx, const char *servername, size_t len)
{
    connection * const con = hctx->con;
    if (len >= 1024) { /*(expecting < 256; TLSEXT_MAXLEN_host_name is 255)*/
        log_error(con->conf.errh, __FILE__, __LINE__,
                  "SSL: SNI name too long %.*s", (int)len, servername);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* use SNI to patch mod_openssl config and then reset COMP_HTTP_HOST */
    buffer_copy_string_len(con->uri.authority, servername, len);
    buffer_to_lower(con->uri.authority);
  #if 0
    /*(con->uri.authority used below for configuration before request read;
     * revisit for h2)*/
    if (0 != http_request_host_policy(con->uri.authority,
                                      con->conf.http_parseopts, 443))
        return SSL_TLSEXT_ERR_ALERT_FATAL;
  #endif

    const buffer * const ssl_pemfile = hctx->conf.ssl_pemfile;

    con->request.conditional_is_valid |= (1 << COMP_HTTP_SCHEME)
                                      |  (1 << COMP_HTTP_HOST);
    mod_openssl_patch_config(con, &hctx->conf);
    /* reset COMP_HTTP_HOST so that conditions re-run after request hdrs read */
    /*(done in response.c:config_cond_cache_reset() after request hdrs read)*/
    /*config_cond_cache_reset_item(con, COMP_HTTP_HOST);*/
    /*buffer_clear(con->uri.authority);*/

    if (!buffer_is_equal(hctx->conf.ssl_pemfile, ssl_pemfile)) {
        /* reconfigure to use SNI-specific cert if SNI-specific cert provided */

        if (NULL == hctx->conf.ssl_pemfile_x509
            || NULL == hctx->conf.ssl_pemfile_pkey) {
            /* x509/pkey available <=> pemfile was set <=> pemfile got patched:
             * so this should never happen, unless you nest $SERVER["socket"] */
            log_error(con->conf.errh, __FILE__, __LINE__,
              "SSL: no certificate/private key for TLS server name %s",
              con->uri.authority->ptr);
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        /* first set certificate!
         * setting private key checks whether certificate matches it */
        if (1 != SSL_use_certificate(ssl, hctx->conf.ssl_pemfile_x509)) {
            log_error(con->conf.errh, __FILE__, __LINE__,
              "SSL: failed to set certificate for TLS server name %s: %s",
              con->uri.authority->ptr, ERR_error_string(ERR_get_error(), NULL));
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        if (1 != SSL_use_PrivateKey(ssl, hctx->conf.ssl_pemfile_pkey)) {
            log_error(con->conf.errh, __FILE__, __LINE__,
              "SSL: failed to set private key for TLS server name %s: %s",
              con->uri.authority->ptr, ERR_error_string(ERR_get_error(), NULL));
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    if (hctx->conf.ssl_verifyclient) {
        int mode;
        STACK_OF(X509_NAME) * const cert_names = hctx->conf.ssl_ca_dn_file
          ? hctx->conf.ssl_ca_dn_file
          : hctx->conf.ssl_ca_file;
        if (NULL == cert_names) {
            log_error(con->conf.errh, __FILE__, __LINE__,
              "SSL: can't verify client without ssl.ca-file "
              "or ssl.ca-dn-file for TLS server name %s: %s",
              con->uri.authority->ptr, ERR_error_string(ERR_get_error(), NULL));
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        SSL_set_client_CA_list(ssl, SSL_dup_CA_list(cert_names));
        /* forcing verification here is really not that useful
         * -- a client could just connect without SNI */
        mode = SSL_VERIFY_PEER;
        if (hctx->conf.ssl_verifyclient_enforce) {
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        SSL_set_verify(ssl, mode, verify_callback);
        SSL_set_verify_depth(ssl, hctx->conf.ssl_verifyclient_depth + 1);
    } else {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    return SSL_TLSEXT_ERR_OK;
}

#ifdef SSL_CLIENT_HELLO_SUCCESS
static int
mod_openssl_client_hello_cb (SSL *ssl, int *al, void *srv)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    buffer_copy_string(hctx->con->uri.scheme, "https");
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
        int rc = mod_openssl_SNI(ssl, hctx, (const char *)name+5, slen);
        if (rc == SSL_TLSEXT_ERR_OK)
            return SSL_CLIENT_HELLO_SUCCESS;
    }

    *al = TLS1_AD_UNRECOGNIZED_NAME;
    return SSL_CLIENT_HELLO_ERROR;
}
#else
static int
network_ssl_servername_callback (SSL *ssl, int *al, server *srv)
{
    handler_ctx *hctx = (handler_ctx *) SSL_get_app_data(ssl);
    buffer_copy_string(hctx->con->uri.scheme, "https");
    UNUSED(al);
    UNUSED(srv);

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    return (NULL != servername)
      ? mod_openssl_SNI(ssl, hctx, servername, strlen(servername))
      : SSL_TLSEXT_ERR_NOACK; /* client did not provide SNI */
}
#endif
#endif


static X509 *
x509_load_pem_file (const char *file, log_error_st *errh)
{
    BIO *in;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file());
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new(BIO_s_file()) failed");
        goto error;
    }

    if (BIO_read_filename(in,file) <= 0) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_read_filename('%s') failed", file);
        goto error;
    }

    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (NULL == x) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: couldn't read X509 certificate from '%s'", file);
        goto error;
    }

    BIO_free(in);
    return x;

error:
    if (NULL != in) BIO_free(in);
    return NULL;
}


static EVP_PKEY *
evp_pkey_load_pem_file (const char *file, log_error_st *errh)
{
    BIO *in;
    EVP_PKEY *x = NULL;

    in = BIO_new(BIO_s_file());
    if (NULL == in) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_new(BIO_s_file()) failed");
        goto error;
    }

    if (BIO_read_filename(in,file) <= 0) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: BIO_read_filename('%s') failed", file);
        goto error;
    }

    x = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (NULL == x) {
        log_error(errh, __FILE__, __LINE__,
          "SSL: couldn't read private key from '%s'", file);
        goto error;
    }

    BIO_free(in);
    return x;

error:
    if (NULL != in) BIO_free(in);
    return NULL;
}


static void *
network_openssl_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey)
{
    if (!mod_openssl_init_once_openssl(srv)) return NULL;

    X509 *ssl_pemfile_x509 = x509_load_pem_file(pemfile->ptr, srv->errh);
    if (NULL == ssl_pemfile_x509)
        return NULL;

    EVP_PKEY *ssl_pemfile_pkey = evp_pkey_load_pem_file(privkey->ptr, srv->errh);
    if (NULL == ssl_pemfile_pkey) {
        X509_free(ssl_pemfile_x509);
        return NULL;
    }

    if (!X509_check_private_key(ssl_pemfile_x509, ssl_pemfile_pkey)) {
        log_error(srv->errh, __FILE__, __LINE__, "SSL:"
          "Private key does not match the certificate public key, "
          "reason: %s %s %s", ERR_error_string(ERR_get_error(), NULL),
          pemfile->ptr, privkey->ptr);
        EVP_PKEY_free(ssl_pemfile_pkey);
        X509_free(ssl_pemfile_x509);
        return NULL;
    }

    plugin_cert *pc = malloc(sizeof(plugin_cert));
    force_assert(pc);
    pc->ssl_pemfile_pkey = ssl_pemfile_pkey;
    pc->ssl_pemfile_x509 = ssl_pemfile_x509;
    pc->ssl_pemfile = pemfile;
    pc->ssl_privkey = privkey;
    return pc;
}


#ifndef OPENSSL_NO_TLSEXT

#if OPENSSL_VERSION_NUMBER >= 0x10002000

static int
mod_openssl_acme_tls_1 (SSL *ssl, handler_ctx *hctx)
{
    buffer * const b = hctx->srv->tmp_buf;
    buffer *name = hctx->con->uri.authority;
    log_error_st *errh = hctx->con->conf.errh;
    X509 *ssl_pemfile_x509 = NULL;
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
    if (0 != http_request_host_policy(name,hctx->con->conf.http_parseopts,443))
        return rc;
  #endif
    buffer_append_string_buffer(b, name);
    len = buffer_string_length(b);

    do {
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
        ssl_pemfile_x509 = x509_load_pem_file(b->ptr, errh);
        if (NULL == ssl_pemfile_x509) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: Failed to load acme-tls/1 pemfile: %s", b->ptr);
            break;
        }

        buffer_string_set_length(b, len); /*(remove ".crt.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        ssl_pemfile_pkey = evp_pkey_load_pem_file(b->ptr, errh);
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

        if (1 != SSL_use_PrivateKey(ssl, ssl_pemfile_pkey)) {
            log_error(errh, __FILE__, __LINE__,
              "SSL: failed to set acme-tls/1 private key for TLS server "
              "name %s: %s", name->ptr, ERR_error_string(ERR_get_error(),NULL));
            break;
        }

        rc = SSL_TLSEXT_ERR_OK;
    } while (0);

    if (ssl_pemfile_pkey) EVP_PKEY_free(ssl_pemfile_pkey);
    if (ssl_pemfile_x509) X509_free(ssl_pemfile_x509);

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

#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000 */

#endif /* OPENSSL_NO_TLSEXT */


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

  #else

    UNUSED(s);
    log_error(srv->errh, __FILE__, __LINE__,
      "SSL: ssl.openssl.ssl-conf-cmd not available; ignored");
    return 0;

  #endif
}


static int
network_init_ssl (server *srv, plugin_config_socket *s, plugin_data *p)
{
  #ifndef OPENSSL_NO_DH
   /* 1024-bit MODP Group with 160-bit prime order subgroup (RFC5114)
    * -----BEGIN DH PARAMETERS-----
    * MIIBDAKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
    * mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
    * +qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
    * w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
    * sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
    * jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5QICAKA=
    * -----END DH PARAMETERS-----
    */

    static const unsigned char dh1024_p[]={
        0xB1,0x0B,0x8F,0x96,0xA0,0x80,0xE0,0x1D,0xDE,0x92,0xDE,0x5E,
        0xAE,0x5D,0x54,0xEC,0x52,0xC9,0x9F,0xBC,0xFB,0x06,0xA3,0xC6,
        0x9A,0x6A,0x9D,0xCA,0x52,0xD2,0x3B,0x61,0x60,0x73,0xE2,0x86,
        0x75,0xA2,0x3D,0x18,0x98,0x38,0xEF,0x1E,0x2E,0xE6,0x52,0xC0,
        0x13,0xEC,0xB4,0xAE,0xA9,0x06,0x11,0x23,0x24,0x97,0x5C,0x3C,
        0xD4,0x9B,0x83,0xBF,0xAC,0xCB,0xDD,0x7D,0x90,0xC4,0xBD,0x70,
        0x98,0x48,0x8E,0x9C,0x21,0x9A,0x73,0x72,0x4E,0xFF,0xD6,0xFA,
        0xE5,0x64,0x47,0x38,0xFA,0xA3,0x1A,0x4F,0xF5,0x5B,0xCC,0xC0,
        0xA1,0x51,0xAF,0x5F,0x0D,0xC8,0xB4,0xBD,0x45,0xBF,0x37,0xDF,
        0x36,0x5C,0x1A,0x65,0xE6,0x8C,0xFD,0xA7,0x6D,0x4D,0xA7,0x08,
        0xDF,0x1F,0xB2,0xBC,0x2E,0x4A,0x43,0x71,
    };

    static const unsigned char dh1024_g[]={
        0xA4,0xD1,0xCB,0xD5,0xC3,0xFD,0x34,0x12,0x67,0x65,0xA4,0x42,
        0xEF,0xB9,0x99,0x05,0xF8,0x10,0x4D,0xD2,0x58,0xAC,0x50,0x7F,
        0xD6,0x40,0x6C,0xFF,0x14,0x26,0x6D,0x31,0x26,0x6F,0xEA,0x1E,
        0x5C,0x41,0x56,0x4B,0x77,0x7E,0x69,0x0F,0x55,0x04,0xF2,0x13,
        0x16,0x02,0x17,0xB4,0xB0,0x1B,0x88,0x6A,0x5E,0x91,0x54,0x7F,
        0x9E,0x27,0x49,0xF4,0xD7,0xFB,0xD7,0xD3,0xB9,0xA9,0x2E,0xE1,
        0x90,0x9D,0x0D,0x22,0x63,0xF8,0x0A,0x76,0xA6,0xA2,0x4C,0x08,
        0x7A,0x09,0x1F,0x53,0x1D,0xBF,0x0A,0x01,0x69,0xB6,0xA2,0x8A,
        0xD6,0x62,0xA4,0xD1,0x8E,0x73,0xAF,0xA3,0x2D,0x77,0x9D,0x59,
        0x18,0xD0,0x8B,0xC8,0x85,0x8F,0x4D,0xCE,0xF9,0x7C,0x2A,0x24,
        0x85,0x5E,0x6E,0xEB,0x22,0xB3,0xB2,0xE5,
    };
  #endif

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

      #if OPENSSL_VERSION_NUMBER >= 0x10100000L
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

        /* completely useless identifier;
         * required for client cert verification to work with sessions */
        if (0 == SSL_CTX_set_session_id_context(
                   s->ssl_ctx,(const unsigned char*)CONST_STR_LEN("lighttpd"))){
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: failed to set session context: %s",
              ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

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
            BIGNUM *dh_p, *dh_g;
            /* Default DH parameters from RFC5114 */
            dh = DH_new();
            if (dh == NULL) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: DH_new () failed");
                return -1;
            }
            dh_p = BN_bin2bn(dh1024_p,sizeof(dh1024_p), NULL);
            dh_g = BN_bin2bn(dh1024_g,sizeof(dh1024_g), NULL);
            if ((dh_p == NULL) || (dh_g == NULL)) {
                DH_free(dh);
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: BN_bin2bn () failed");
                return -1;
            }
          #if OPENSSL_VERSION_NUMBER < 0x10100000L \
           || defined(LIBRESSL_VERSION_NUMBER)
            dh->p = dh_p;
            dh->g = dh_g;
            dh->length = 160;
          #else
            DH_set0_pqg(dh, dh_p, NULL, dh_g);
            DH_set_length(dh, 160);
          #endif
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

      #if OPENSSL_VERSION_NUMBER >= 0x0090800fL
      #ifndef OPENSSL_NO_ECDH
      {
        int nid = 0;
        /* Support for Elliptic-Curve Diffie-Hellman key exchange */
        if (!buffer_string_is_empty(s->ssl_ec_curve)) {
            /* OpenSSL only supports the "named curves"
             * from RFC 4492, section 5.1.1. */
            nid = OBJ_sn2nid((char *) s->ssl_ec_curve->ptr);
            if (nid == 0) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: Unknown curve name %s", s->ssl_ec_curve->ptr);
                return -1;
            }
        } else {
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
                  "SSL: Unable to create curve %s", s->ssl_ec_curve->ptr);
                return -1;
            }
            SSL_CTX_set_tmp_ecdh(s->ssl_ctx,ecdh);
            SSL_CTX_set_options(s->ssl_ctx,SSL_OP_SINGLE_ECDH_USE);
            EC_KEY_free(ecdh);
        }
      }
      #endif
      #endif

        /* load all ssl.ca-files specified in the config into each SSL_CTX
         * to be prepared for SNI */
        if (!mod_openssl_load_ca_files(s->ssl_ctx, p, srv))
            return -1;

        if (s->ssl_verifyclient) {
            STACK_OF(X509_NAME) * const cert_names = s->ssl_ca_dn_file
              ? s->ssl_ca_dn_file
              : s->ssl_ca_file;
            if (NULL == cert_names) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: You specified ssl.verifyclient.activate "
                  "but no ssl.ca-file or ssl.ca-dn-file");
                return -1;
            }
            SSL_CTX_set_client_CA_list(s->ssl_ctx, SSL_dup_CA_list(cert_names));
            int mode = SSL_VERIFY_PEER;
            if (s->ssl_verifyclient_enforce) {
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            SSL_CTX_set_verify(s->ssl_ctx, mode, verify_callback);
            SSL_CTX_set_verify_depth(s->ssl_ctx, s->ssl_verifyclient_depth + 1);
            if (!buffer_string_is_empty(s->ssl_ca_crl_file)) {
                X509_STORE *store = SSL_CTX_get_cert_store(s->ssl_ctx);
                if (1 != X509_STORE_load_locations(store, s->ssl_ca_crl_file->ptr, NULL)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "SSL: %s %s", ERR_error_string(ERR_get_error(), NULL),
                      s->ssl_ca_crl_file->ptr);
                    return -1;
                }
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            }
        }

        if (1 != SSL_CTX_use_certificate_chain_file(s->ssl_ctx,
                                                    s->ssl_pemfile->ptr)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s %s", ERR_error_string(ERR_get_error(), NULL),
              s->ssl_pemfile->ptr);
            return -1;
        }

        if (1 != SSL_CTX_use_PrivateKey(s->ssl_ctx, s->ssl_pemfile_pkey)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: %s %s %s", ERR_error_string(ERR_get_error(), NULL),
              s->ssl_pemfile->ptr, s->ssl_privkey->ptr);
            return -1;
        }

        if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
            log_error(srv->errh, __FILE__, __LINE__,
              "SSL: Private key does not match the certificate public key, "
              "reason: %s %s %s", ERR_error_string(ERR_get_error(), NULL),
              s->ssl_pemfile->ptr, s->ssl_privkey->ptr);
            return -1;
        }
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

       #if OPENSSL_VERSION_NUMBER >= 0x10002000
        SSL_CTX_set_alpn_select_cb(s->ssl_ctx,mod_openssl_alpn_select_cb,NULL);
       #endif
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
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };
    static const buffer default_ssl_cipher_list = { CONST_STR_LEN("HIGH"), 0 };

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
        config_get_config_cond_info(srv,(uint32_t)ps->cvlist[i].k_id,&cfginfo);
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
                break;
              case 8: /* ssl.use-sslv2 */
                conf.ssl_use_sslv2 = (0 != cpv->v.u);
                break;
              case 9: /* ssl.use-sslv3 */
                conf.ssl_use_sslv3 = (0 != cpv->v.u);
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

        /*conf.ssl_pemfile_pkey       = p->defaults.ssl_pemfile_pkey;*/
        /*conf.ssl_pemfile_x509       = p->defaults.ssl_pemfile_x509;*/
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
                    if (cpv->vtype == T_CONFIG_LOCAL) {
                        plugin_cert *pc = cpv->v.v;
                        conf.ssl_pemfile_pkey = pc->ssl_pemfile_pkey;
                        conf.ssl_pemfile_x509 = pc->ssl_pemfile_x509;
                        conf.ssl_pemfile      = pc->ssl_pemfile;
                        conf.ssl_privkey      = pc->ssl_privkey;
                    }
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

        if (NULL == conf.ssl_pemfile_x509) {
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
            /*(used to match and avoid work changing keys
             * during SNI when pkey has not changed)*/
            s->ssl_pemfile_pkey = conf.ssl_pemfile_pkey;
        }
        else {
            SSL_CTX_free(conf.ssl_ctx);
            rc = HANDLER_ERROR;
        }
    }

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

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        config_plugin_value_t *pemfile = NULL;
        config_plugin_value_t *privkey = NULL;
        const buffer *ssl_ca_file = NULL;
        const buffer *ssl_ca_dn_file = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (!buffer_string_is_empty(cpv->v.b)) pemfile = cpv;
                break;
              case 1: /* ssl.privkey */
                if (!buffer_string_is_empty(cpv->v.b)) privkey = cpv;
                break;
              case 2: /* ssl.ca-file */
              case 3: /* ssl.ca-dn-file */
                if (!mod_openssl_init_once_openssl(srv)) return HANDLER_ERROR;
                if (!buffer_string_is_empty(cpv->v.b)) {
                    const char * const fn = cpv->v.b->ptr;
                    if (cpv->k_id == 2)
                        ssl_ca_file = cpv->v.b;
                    else
                        ssl_ca_dn_file = cpv->v.b;
                    cpv->v.v = SSL_load_client_CA_file(fn);
                    if (NULL != cpv->v.v) {
                        cpv->vtype = T_CONFIG_LOCAL;
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__, "SSL: %s %s",
                          ERR_error_string(ERR_get_error(), NULL), fn);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 4: /* ssl.ca-crl-file */
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
              case 13:/* debug.log-ssl-noise */
                break;
              default:/* should not happen */
                break;
            }
        }

        /* load all ssl.ca-files into a single chain to be prepared for SNI */
        /*(certificate load order might matter)*/
        if (ssl_ca_dn_file)
            array_insert_value(p->cafiles, CONST_BUF_LEN(ssl_ca_dn_file));
        if (ssl_ca_file)
            array_insert_value(p->cafiles, CONST_BUF_LEN(ssl_ca_file));

        if (pemfile) {
          #ifdef OPENSSL_NO_TLSEXT
            config_cond_info cfginfo;
            uint32_t j = (uint32_t)p->cvlist[i].k_id;
            config_get_config_cond_info(srv, j, &cfginfo);
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
              network_openssl_load_pemfile(srv, pemfile->v.b, privkey->v.b);
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
load_next_chunk (connection *con, chunkqueue *cq, off_t max_bytes,
                 const char **data, size_t *data_len)
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
        if (0 != chunkqueue_open_file_chunk(cq, con->conf.errh)) return -1;

        {
            off_t offset, toSend;

            force_assert(c->offset >= 0 && c->offset <= c->file.length);
            offset = c->file.start + c->offset;
            toSend = c->file.length - c->offset;

            if (toSend > LOCAL_SEND_BUFSIZE) toSend = LOCAL_SEND_BUFSIZE;
            if (toSend > max_bytes) toSend = max_bytes;

            if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
                log_perror(con->conf.errh, __FILE__, __LINE__, "lseek");
                return -1;
            }
            if (-1 == (toSend = read(c->file.fd, local_send_buffer, toSend))) {
                log_perror(con->conf.errh, __FILE__, __LINE__, "read");
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
    handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id];
    SSL *ssl = hctx->ssl;

    if (0 != hctx->close_notify) return mod_openssl_close_notify(hctx);

    chunkqueue_remove_finished_chunks(cq);

    while (max_bytes > 0 && NULL != cq->first) {
        const char *data;
        size_t data_len;
        int wr;

        if (0 != load_next_chunk(con,cq,max_bytes,&data,&data_len)) return -1;

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
            log_error(con->conf.errh, __FILE__, __LINE__,
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
                        log_error(con->conf.errh, __FILE__, __LINE__,
                          "SSL: %d %d %s",ssl_r,wr,ERR_error_string(err,NULL));
                    } while((err = ERR_get_error()));
                } else if (wr == -1) {
                    /* no, but we have errno */
                    switch(errno) {
                    case EPIPE:
                    case ECONNRESET:
                        return -2;
                    default:
                        log_perror(con->conf.errh, __FILE__, __LINE__,
                          "SSL: %d %d", ssl_r, wr);
                        break;
                    }
                } else {
                    /* neither error-queue nor errno ? */
                    log_perror(con->conf.errh, __FILE__, __LINE__,
                      "SSL (error): %d %d", ssl_r, wr);
                }
                break;

            case SSL_ERROR_ZERO_RETURN:
                /* clean shutdown on the remote side */

                if (wr == 0) return -2;

                /* fall through */
            default:
                while((err = ERR_get_error())) {
                    log_error(con->conf.errh, __FILE__, __LINE__,
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
    handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id];
    int len;
    char *mem = NULL;
    size_t mem_len = 0;

    /*(code transform assumption; minimize diff)*/
    force_assert(cq == con->read_queue);
    UNUSED(max_bytes);

    if (0 != hctx->close_notify) return mod_openssl_close_notify(hctx);

    ERR_clear_error();
    do {
        len = SSL_pending(hctx->ssl);
        mem_len = len < 2048 ? 2048 : (size_t)len;
        chunk * const ckpt = con->read_queue->last;
        mem = chunkqueue_get_memory(con->read_queue, &mem_len);

        len = SSL_read(hctx->ssl, mem, mem_len);
        if (len > 0) {
            chunkqueue_use_memory(con->read_queue, ckpt, len);
            con->bytes_read += len;
        } else {
            chunkqueue_use_memory(con->read_queue, ckpt, 0);
        }

        if (hctx->renegotiations > 1
            && hctx->conf.ssl_disable_client_renegotiation) {
            log_error(con->conf.errh, __FILE__, __LINE__,
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }

      #if OPENSSL_VERSION_NUMBER >= 0x10002000
        if (hctx->alpn) {
            if (hctx->alpn == MOD_OPENSSL_ALPN_ACME_TLS_1) {
                chunkqueue_reset(con->read_queue);
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
                log_error(con->conf.errh, __FILE__, __LINE__,
                  "SSL: %d %s", rc, ERR_error_string(ssl_err, NULL));
            }

            switch(oerrno) {
            default:
                /* (oerrno should be something like ECONNABORTED not 0
                 *  if client disconnected before anything was sent
                 *  (e.g. TCP connection probe), but it does not appear
                 *  that openssl provides such notification, not even
                 *  something like SSL_R_SSL_HANDSHAKE_FAILURE) */
                if (0==oerrno && 0==cq->bytes_in && !hctx->conf.ssl_log_noise)
                    break;

                log_error(con->conf.errh, __FILE__, __LINE__,
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
                log_error(con->conf.errh, __FILE__, __LINE__,
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
    hctx->con = con;
    hctx->srv = con->srv;
    con->plugin_ctx[p->id] = hctx;

    plugin_ssl_ctx * const s = p->ssl_ctxs + srv_sock->sidx;
    hctx->conf.ssl_pemfile_pkey = s->ssl_pemfile_pkey;
    hctx->ssl = SSL_new(s->ssl_ctx);
    if (NULL != hctx->ssl
        && SSL_set_app_data(hctx->ssl, hctx)
        && SSL_set_fd(hctx->ssl, con->fd)) {
        SSL_set_accept_state(hctx->ssl);
        con->network_read = connection_read_cq_ssl;
        con->network_write = connection_write_cq_ssl;
        con->proto_default_port = 443; /* "https" */
        mod_openssl_patch_config(con, &hctx->conf);
        return HANDLER_GO_ON;
    }
    else {
        log_error(con->conf.errh, __FILE__, __LINE__,
          "SSL: %s", ERR_error_string(ERR_get_error(), NULL));
        return HANDLER_ERROR;
    }
}


static void
mod_openssl_detach(handler_ctx *hctx)
{
    /* step aside from futher SSL processing
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
                errh = hctx->con->conf.errh;
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
                errh = hctx->con->conf.errh;
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
        handler_ctx_free(hctx);
        con->plugin_ctx[p->id] = NULL;
    }

    return HANDLER_GO_ON;
}


static void
https_add_ssl_client_entries (connection *con, handler_ctx *hctx)
{
    buffer * const tb = con->srv->tmp_buf;
    X509 *xs;
    X509_NAME *xn;
    int i, nentries;

    long vr = SSL_get_verify_result(hctx->ssl);
    if (vr != X509_V_OK) {
        char errstr[256];
        ERR_error_string_n(vr, errstr, sizeof(errstr));
        buffer_copy_string_len(tb, CONST_STR_LEN("FAILED:"));
        buffer_append_string(tb, errstr);
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_BUF_LEN(tb));
        return;
    } else if (!(xs = SSL_get_peer_certificate(hctx->ssl))) {
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_STR_LEN("NONE"));
        return;
    } else {
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_STR_LEN("SUCCESS"));
    }

    xn = X509_get_subject_name(xs);
    {
        char buf[256];
        int len = safer_X509_NAME_oneline(xn, buf, sizeof(buf));
        if (len > 0) {
            if (len >= (int)sizeof(buf)) len = (int)sizeof(buf)-1;
            http_header_env_set(con,
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
            http_header_env_set(con,
                                CONST_BUF_LEN(tb),
                                (const char*)X509_NAME_ENTRY_get_data(xe)->data,
                                X509_NAME_ENTRY_get_data(xe)->length);
        }
    }

    {
        ASN1_INTEGER *xsn = X509_get_serialNumber(xs);
        BIGNUM *serialBN = ASN1_INTEGER_to_BN(xsn, NULL);
        char *serialHex = BN_bn2hex(serialBN);
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CLIENT_M_SERIAL"),
                            serialHex, strlen(serialHex));
        OPENSSL_free(serialHex);
        BN_free(serialBN);
    }

    if (!buffer_string_is_empty(hctx->conf.ssl_verifyclient_username)) {
        /* pick one of the exported values as "REMOTE_USER", for example
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_UID"
         * or
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_emailAddress"
         */
        const buffer *varname = hctx->conf.ssl_verifyclient_username;
        const buffer *vb = http_header_env_get(con, CONST_BUF_LEN(varname));
        if (vb) { /* same as http_auth.c:http_auth_setenv() */
            http_header_env_set(con,
                                CONST_STR_LEN("REMOTE_USER"),
                                CONST_BUF_LEN(vb));
            http_header_env_set(con,
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
            http_header_env_set(con,
                                CONST_STR_LEN("SSL_CLIENT_CERT"),
                                CONST_BUF_LEN(tb));
        }
    }
    X509_free(xs);
}


static void
http_cgi_ssl_env (connection *con, handler_ctx *hctx)
{
    const char *s;
    const SSL_CIPHER *cipher;

    s = SSL_get_version(hctx->ssl);
    http_header_env_set(con, CONST_STR_LEN("SSL_PROTOCOL"), s, strlen(s));

    if ((cipher = SSL_get_current_cipher(hctx->ssl))) {
        int usekeysize, algkeysize;
        char buf[LI_ITOSTRING_LENGTH];
        s = SSL_CIPHER_get_name(cipher);
        http_header_env_set(con, CONST_STR_LEN("SSL_CIPHER"), s, strlen(s));
        usekeysize = SSL_CIPHER_get_bits(cipher, &algkeysize);
        http_header_env_set(con, CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, li_itostrn(buf, sizeof(buf), usekeysize));
        http_header_env_set(con, CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                            buf, li_itostrn(buf, sizeof(buf), algkeysize));
    }
}


CONNECTION_FUNC(mod_openssl_handle_request_env)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    if (hctx->request_env_patched) return HANDLER_GO_ON;
    hctx->request_env_patched = 1;

    http_cgi_ssl_env(con, hctx);
    if (hctx->conf.ssl_verifyclient) {
        https_add_ssl_client_entries(con, hctx);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_uri_raw)
{
    /* mod_openssl must be loaded prior to mod_auth
     * if mod_openssl is configured to set REMOTE_USER based on client cert */
    /* mod_openssl must be loaded after mod_extforward
     * if mod_openssl config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward, *unless* PROXY protocol
     * is enabled with extforward.hap-PROXY = "enable", in which case the
     * reverse is true: mod_extforward must be loaded after mod_openssl */
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    mod_openssl_patch_config(con, &hctx->conf);
    if (hctx->conf.ssl_verifyclient) {
        mod_openssl_handle_request_env(con, p);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_request_reset)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    hctx->request_env_patched = 0;
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

    return 0;
}
