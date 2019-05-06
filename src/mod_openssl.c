#include "first.h"

#include <errno.h>
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
    SSL_CTX *ssl_ctx; /* not patched */
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    EVP_PKEY *ssl_pemfile_pkey;
    X509 *ssl_pemfile_x509;
    STACK_OF(X509_NAME) *ssl_ca_file_cert_names;

    unsigned short ssl_verifyclient;
    unsigned short ssl_verifyclient_enforce;
    unsigned short ssl_verifyclient_depth;
    unsigned short ssl_verifyclient_export_cert;
    buffer *ssl_verifyclient_username;

    unsigned short ssl_disable_client_renegotiation;
    unsigned short ssl_read_ahead;
    unsigned short ssl_log_noise;

    /*(used only during startup; not patched)*/
    unsigned short ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned short ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    unsigned short ssl_empty_fragments; /* whether to not set SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
    unsigned short ssl_use_sslv2;
    unsigned short ssl_use_sslv3;
    buffer *ssl_pemfile;
    buffer *ssl_privkey;
    buffer *ssl_ca_file;
    buffer *ssl_ca_crl_file;
    buffer *ssl_ca_dn_file;
    buffer *ssl_cipher_list;
    buffer *ssl_dh_file;
    buffer *ssl_ec_curve;
    array *ssl_conf_cmd;
    buffer *ssl_acme_tls_1;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
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


FREE_FUNC(mod_openssl_free)
{
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            plugin_config *s = p->config_storage[i];
            int copy;
            if (NULL == s) continue;
            copy = s->ssl_enabled && buffer_string_is_empty(s->ssl_pemfile);
            buffer_free(s->ssl_pemfile);
            buffer_free(s->ssl_privkey);
            buffer_free(s->ssl_ca_file);
            buffer_free(s->ssl_ca_crl_file);
            buffer_free(s->ssl_ca_dn_file);
            buffer_free(s->ssl_cipher_list);
            buffer_free(s->ssl_dh_file);
            buffer_free(s->ssl_ec_curve);
            buffer_free(s->ssl_verifyclient_username);
            array_free(s->ssl_conf_cmd);
            buffer_free(s->ssl_acme_tls_1);

            if (copy) continue;
            SSL_CTX_free(s->ssl_ctx);
            EVP_PKEY_free(s->ssl_pemfile_pkey);
            X509_free(s->ssl_pemfile_x509);
            if (NULL != s->ssl_ca_file_cert_names)
                sk_X509_NAME_pop_free(s->ssl_ca_file_cert_names,X509_NAME_free);
        }
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;

            free(s);
        }
        free(p->config_storage);
    }

    if (ssl_is_init) {
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
    }

    free(p);

    return HANDLER_GO_ON;
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
    server *srv;

    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    /*
     * Retrieve the pointer to the SSL of the connection currently treated
     * and the application specific data stored into the SSL object.
     */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    hctx = (handler_ctx *) SSL_get_app_data(ssl);
    srv = hctx->srv;

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
        && !buffer_string_is_empty(hctx->conf.ssl_ca_dn_file)
        && !buffer_string_is_empty(hctx->conf.ssl_ca_file)) {
        /* verify that client cert is issued by CA in ssl.ca-dn-file
         * if both ssl.ca-dn-file and ssl.ca-file were configured */
        STACK_OF(X509_NAME) * const names = hctx->conf.ssl_ca_file_cert_names;
        X509_NAME *issuer;
      #if OPENSSL_VERSION_NUMBER >= 0x10002000L
        err_cert = X509_STORE_CTX_get_current_cert(ctx);
      #else
        err_cert = ctx->current_cert;
      #endif
        if (NULL == err_cert) return !hctx->conf.ssl_verifyclient_enforce;
        issuer = X509_get_issuer_name(err_cert);
      #if 0 /*(?desirable/undesirable to have ssl_ca_file_cert_names sorted?)*/
        if (-1 != sk_X509_NAME_find(names, issuer))
            return preverify_ok; /* match */
      #else
        for (int i = 0, len = sk_X509_NAME_num(names); i < len; ++i) {
            if (0 == X509_NAME_cmp(sk_X509_NAME_value(names, i), issuer))
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
    log_error_write(srv, __FILE__, __LINE__, "SDSSSDSS",
                        "SSL: verify error:num=", err, ":",
                        X509_verify_cert_error_string(err), ":depth=", depth,
                        ":subject=", buf);

    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                          err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        safer_X509_NAME_oneline(X509_get_issuer_name(err_cert),buf,sizeof(buf));
        log_error_write(srv, __FILE__, __LINE__, "SS", "SSL: issuer=", buf);
    }

    return !hctx->conf.ssl_verifyclient_enforce;
}

#ifndef OPENSSL_NO_TLSEXT
static int mod_openssl_patch_connection (server *srv, connection *con, handler_ctx *hctx);

static int
mod_openssl_SNI (SSL *ssl, server *srv, handler_ctx *hctx, const char *servername, size_t len)
{
    if (len >= 1024) { /*(expecting < 256; TLSEXT_MAXLEN_host_name is 255)*/
        log_error(srv->errh, __FILE__, __LINE__,
                  "SSL: SNI name too long %.*s", (int)len, servername);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* use SNI to patch mod_openssl config and then reset COMP_HTTP_HOST */
    connection * const con = hctx->con;
    buffer_copy_string_len(con->uri.authority, servername, len);
    buffer_to_lower(con->uri.authority);
  #if 0
    /*(con->uri.authority used below for configuration before request read;
     * revisit for h2)*/
    if (0 != http_request_host_policy(con, con->uri.authority, con->uri.scheme))
        return SSL_TLSEXT_ERR_ALERT_FATAL;
  #endif

    con->conditional_is_valid[COMP_HTTP_SCHEME] = 1;
    con->conditional_is_valid[COMP_HTTP_HOST] = 1;
    mod_openssl_patch_connection(srv, con, hctx);
    /* reset COMP_HTTP_HOST so that conditions re-run after request hdrs read */
    /*(done in response.c:config_cond_cache_reset() after request hdrs read)*/
    /*config_cond_cache_reset_item(con, COMP_HTTP_HOST);*/
    /*buffer_clear(con->uri.authority);*/

    if (NULL == hctx->conf.ssl_pemfile_x509
        || NULL == hctx->conf.ssl_pemfile_pkey) {
        /* x509/pkey available <=> pemfile was set <=> pemfile got patched:
         * so this should never happen, unless you nest $SERVER["socket"] */
        log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                        "no certificate/private key for TLS server name",
                        con->uri.authority);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* first set certificate!
     * setting private key checks whether certificate matches it */
    if (1 != SSL_use_certificate(ssl, hctx->conf.ssl_pemfile_x509)) {
        log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
                        "failed to set certificate for TLS server name",
                        con->uri.authority,
                        ERR_error_string(ERR_get_error(), NULL));
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (1 != SSL_use_PrivateKey(ssl, hctx->conf.ssl_pemfile_pkey)) {
        log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
                        "failed to set private key for TLS server name",
                        con->uri.authority,
                        ERR_error_string(ERR_get_error(), NULL));
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (hctx->conf.ssl_verifyclient) {
        int mode;
        if (NULL == hctx->conf.ssl_ca_file_cert_names) {
            log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
                            "can't verify client without ssl.ca-file "
                            "or ssl.ca-dn-file for TLS server name",
                            con->uri.authority,
                            ERR_error_string(ERR_get_error(), NULL));
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        SSL_set_client_CA_list(
          ssl, SSL_dup_CA_list(hctx->conf.ssl_ca_file_cert_names));
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
        int rc = mod_openssl_SNI(ssl, srv, hctx, (const char *)name+5, slen);
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

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    return (NULL != servername)
      ? mod_openssl_SNI(ssl, srv, hctx, servername, strlen(servername))
      : SSL_TLSEXT_ERR_NOACK; /* client did not provide SNI */
}
#endif
#endif


static X509 *
x509_load_pem_file (server *srv, const char *file)
{
    BIO *in;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file());
    if (NULL == in) {
        log_error_write(srv, __FILE__, __LINE__, "S",
                        "SSL: BIO_new(BIO_s_file()) failed");
        goto error;
    }

    if (BIO_read_filename(in,file) <= 0) {
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "SSL: BIO_read_filename('", file,"') failed");
        goto error;
    }

    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (NULL == x) {
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "SSL: couldn't read X509 certificate from '", file,"'");
        goto error;
    }

    BIO_free(in);
    return x;

error:
    if (NULL != in) BIO_free(in);
    return NULL;
}


static EVP_PKEY *
evp_pkey_load_pem_file (server *srv, const char *file)
{
    BIO *in;
    EVP_PKEY *x = NULL;

    in = BIO_new(BIO_s_file());
    if (NULL == in) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "SSL: BIO_new(BIO_s_file()) failed");
        goto error;
    }

    if (BIO_read_filename(in,file) <= 0) {
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "SSL: BIO_read_filename('", file,"') failed");
        goto error;
    }

    x = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (NULL == x) {
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "SSL: couldn't read private key from '", file,"'");
        goto error;
    }

    BIO_free(in);
    return x;

error:
    if (NULL != in) BIO_free(in);
    return NULL;
}


static int
network_openssl_load_pemfile (server *srv, plugin_config *s, size_t ndx)
{
  #ifdef OPENSSL_NO_TLSEXT
    data_config *dc = (data_config *)srv->config_context->data[ndx];
    if ((ndx > 0 && (COMP_SERVER_SOCKET != dc->comp
                     || dc->cond != CONFIG_COND_EQ)) || !s->ssl_enabled) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                        "ssl.pemfile only works in SSL socket binding context "
                        "as openssl version does not support TLS extensions");
        return -1;
    }
  #else
    UNUSED(ndx);
  #endif

    s->ssl_pemfile_x509 = x509_load_pem_file(srv, s->ssl_pemfile->ptr);
    if (NULL == s->ssl_pemfile_x509) return -1;
    s->ssl_pemfile_pkey = !buffer_string_is_empty(s->ssl_privkey)
      ? evp_pkey_load_pem_file(srv, s->ssl_privkey->ptr)
      : evp_pkey_load_pem_file(srv, s->ssl_pemfile->ptr);
    if (NULL == s->ssl_pemfile_pkey) return -1;

    if (!X509_check_private_key(s->ssl_pemfile_x509, s->ssl_pemfile_pkey)) {
        log_error_write(srv, __FILE__, __LINE__, "sssbb", "SSL:",
                        "Private key does not match the certificate public key,"
                        " reason:", ERR_error_string(ERR_get_error(), NULL),
                        s->ssl_pemfile, s->ssl_privkey);
        return -1;
    }

    return 0;
}


#ifndef OPENSSL_NO_TLSEXT

#if OPENSSL_VERSION_NUMBER >= 0x10002000

static int
mod_openssl_acme_tls_1 (SSL *ssl, handler_ctx *hctx)
{
    server *srv = hctx->srv;
    buffer *b = srv->tmp_buf;
    buffer *name = hctx->con->uri.authority;
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
    if (0 != http_request_host_policy(hctx->con, name, hctx->con->uri.scheme))
        return rc;
  #endif
    buffer_append_string_buffer(b, name);
    len = buffer_string_length(b);

    do {
        buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
        ssl_pemfile_x509 = x509_load_pem_file(srv, b->ptr);
        if (NULL == ssl_pemfile_x509) {
            log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                            "Failed to load acme-tls/1 pemfile:", b);
            break;
        }

        buffer_string_set_length(b, len); /*(remove ".crt.pem")*/
        buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));
        ssl_pemfile_pkey = evp_pkey_load_pem_file(srv, b->ptr);
        if (NULL == ssl_pemfile_pkey) {
            log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                            "Failed to load acme-tls/1 pemfile:", b);
            break;
        }

      #if 0 /* redundant with below? */
        if (!X509_check_private_key(ssl_pemfile_x509, ssl_pemfile_pkey)) {
            log_error_write(srv, __FILE__, __LINE__, "sssb", "SSL:",
               "Private key does not match acme-tls/1 certificate public key,"
               " reason:" ERR_error_string(ERR_get_error(), NULL), b);
            break;
        }
      #endif

        /* first set certificate!
         * setting private key checks whether certificate matches it */
        if (1 != SSL_use_certificate(ssl, ssl_pemfile_x509)) {
            log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
              "failed to set acme-tls/1 certificate for TLS server name",
              name, ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        if (1 != SSL_use_PrivateKey(ssl, ssl_pemfile_pkey)) {
            log_error_write(srv, __FILE__, __LINE__, "ssb:s", "SSL:",
              "failed to set acme-tls/1 private key for TLS server name",
              name, ERR_error_string(ERR_get_error(), NULL));
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
        if (i+n > inlen) break;
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
network_openssl_ssl_conf_cmd (server *srv, plugin_config *s)
{
  #ifdef SSL_CONF_FLAG_CMDLINE

    int rc = 0;
    data_string *ds;
    SSL_CONF_CTX * const cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_ssl_ctx(cctx, s->ssl_ctx);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE
                               | SSL_CONF_FLAG_SERVER
                               | SSL_CONF_FLAG_SHOW_ERRORS
                               | SSL_CONF_FLAG_CERTIFICATE);

    /* always disable null and export ciphers */
    ds = (data_string *)
      array_get_element_klen(s->ssl_conf_cmd,
                             CONST_STR_LEN("CipherString"));
    if (NULL != ds) {
        buffer_append_string_len(ds->value,
                                 CONST_STR_LEN(":!aNULL:!eNULL:!EXP"));
    }

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        ds = (data_string *)s->ssl_conf_cmd->data[i];
        ERR_clear_error();
        if (SSL_CONF_cmd(cctx, ds->key->ptr, ds->value->ptr) <= 0) {
            log_error_write(srv, __FILE__, __LINE__, "ssbbss", "SSL:",
                            "SSL_CONF_cmd", ds->key, ds->value, ":",
                            ERR_error_string(ERR_get_error(), NULL));
            rc = -1;
            break;
        }
    }

    if (0 == rc && 1 != SSL_CONF_CTX_finish(cctx)) {
        log_error_write(srv, __FILE__, __LINE__, "sss", "SSL:",
                        "SSL_CONF_CTX_finish():",
                        ERR_error_string(ERR_get_error(), NULL));
        rc = -1;
    }

    SSL_CONF_CTX_free(cctx);
    return rc;

  #else

    UNUSED(s);
    log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                    "ssl.openssl.ssl-conf-cmd not available; ignored");
    return 0;

  #endif
}


static int
network_init_ssl (server *srv, void *p_d)
{
    plugin_data *p = p_d;

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
    for (size_t i = 0; i < srv->config_context->used; ++i) {
        plugin_config *s = p->config_storage[i];
      #ifndef SSL_OP_NO_COMPRESSION
      #define SSL_OP_NO_COMPRESSION 0
      #endif
      #ifndef SSL_MODE_RELEASE_BUFFERS    /* OpenSSL >= 1.0.0 */
      #define SSL_MODE_RELEASE_BUFFERS 0
      #endif
        long ssloptions = SSL_OP_ALL
                        | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                        | SSL_OP_NO_COMPRESSION;

        if (s->ssl_enabled) {
            if (buffer_string_is_empty(s->ssl_pemfile)) {
                /* inherit ssl settings from global scope
                 * (if only ssl.engine = "enable" and no other ssl.* settings)*/
                if (0 != i && p->config_storage[0]->ssl_enabled) {
                    s->ssl_ctx = p->config_storage[0]->ssl_ctx;
                    continue;
                }
                /* PEM file is require */
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "ssl.pemfile has to be set "
                                "when ssl.engine = \"enable\"");
                return -1;
            }
        }

        if (buffer_string_is_empty(s->ssl_pemfile)
            && buffer_string_is_empty(s->ssl_ca_dn_file)
            && buffer_string_is_empty(s->ssl_ca_file)) continue;

        if (ssl_is_init == 0) {
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
                log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                                "not enough entropy in the pool");
                return -1;
            }

            local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
            force_assert(NULL != local_send_buffer);
        }

        if (!buffer_string_is_empty(s->ssl_pemfile)) {
          #ifdef OPENSSL_NO_TLSEXT
            data_config *dc = (data_config *)srv->config_context->data[i];
            if (COMP_HTTP_HOST == dc->comp) {
                log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                                "can't use ssl.pemfile with $HTTP[\"host\"], "
                                "openssl version does not support TLS "
                                "extensions");
                return -1;
            }
          #endif
            if (network_openssl_load_pemfile(srv, s, i)) return -1;
        }


        if (!buffer_string_is_empty(s->ssl_ca_dn_file)) {
            s->ssl_ca_file_cert_names =
              SSL_load_client_CA_file(s->ssl_ca_dn_file->ptr);
            if (NULL == s->ssl_ca_file_cert_names) {
                log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                                ERR_error_string(ERR_get_error(), NULL),
                                s->ssl_ca_dn_file);
            }
        }

        if (NULL == s->ssl_ca_file_cert_names
            && !buffer_string_is_empty(s->ssl_ca_file)) {
            s->ssl_ca_file_cert_names =
              SSL_load_client_CA_file(s->ssl_ca_file->ptr);
            if (NULL == s->ssl_ca_file_cert_names) {
                log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                                ERR_error_string(ERR_get_error(), NULL),
                                s->ssl_ca_file);
            }
        }

        if (buffer_string_is_empty(s->ssl_pemfile) || !s->ssl_enabled) continue;

      #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        s->ssl_ctx = (!s->ssl_use_sslv2 && !s->ssl_use_sslv3)
          ? SSL_CTX_new(TLS_server_method())
          : SSL_CTX_new(SSLv23_server_method());
      #else
        s->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
      #endif
        if (NULL == s->ssl_ctx) {
            log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                            ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

        /* completely useless identifier;
         * required for client cert verification to work with sessions */
        if (0 == SSL_CTX_set_session_id_context(
                   s->ssl_ctx,(const unsigned char*)CONST_STR_LEN("lighttpd"))){
            log_error_write(srv, __FILE__, __LINE__, "ss:s", "SSL:",
                            "failed to set session context",
                            ERR_error_string(ERR_get_error(), NULL));
            return -1;
        }

        if (s->ssl_empty_fragments) {
          #ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
            ssloptions &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
          #else
            ssloptions &= ~0x00000800L; /* hardcode constant */
            log_error_write(srv, __FILE__, __LINE__, "ss", "WARNING: SSL:",
                            "'insert empty fragments' not supported by the "
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
                log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                                ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }
      #endif

        if (!s->ssl_use_sslv3 && 0 != SSL_OP_NO_SSLv3) {
            /* disable SSLv3 */
            if ((SSL_OP_NO_SSLv3
                 & SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv3))
                != SSL_OP_NO_SSLv3) {
                log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                                ERR_error_string(ERR_get_error(), NULL));
                return -1;
            }
        }

        if (!buffer_string_is_empty(s->ssl_cipher_list)) {
            /* Disable support for low encryption ciphers */
            if (SSL_CTX_set_cipher_list(s->ssl_ctx,s->ssl_cipher_list->ptr)!=1){
                log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                                ERR_error_string(ERR_get_error(), NULL));
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
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "SSL: Unable to open file",
                                s->ssl_dh_file->ptr);
                return -1;
            }
            dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
            BIO_free(bio);
            if (dh == NULL) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "SSL: PEM_read_bio_DHparams failed",
                                s->ssl_dh_file->ptr);
                return -1;
            }
        } else {
            BIGNUM *dh_p, *dh_g;
            /* Default DH parameters from RFC5114 */
            dh = DH_new();
            if (dh == NULL) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "SSL: DH_new () failed");
                return -1;
            }
            dh_p = BN_bin2bn(dh1024_p,sizeof(dh1024_p), NULL);
            dh_g = BN_bin2bn(dh1024_g,sizeof(dh1024_g), NULL);
            if ((dh_p == NULL) || (dh_g == NULL)) {
                DH_free(dh);
                log_error_write(srv, __FILE__, __LINE__, "s",
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
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "SSL: openssl compiled without DH support, "
                            "can't load parameters from", s->ssl_dh_file->ptr);
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
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "SSL: Unknown curve name",
                                s->ssl_ec_curve->ptr);
                return -1;
            }
        } else {
          #if OPENSSL_VERSION_NUMBER < 0x10002000
            /* Default curve */
            nid = OBJ_sn2nid("prime256v1");
          #elif OPENSSL_VERSION_NUMBER < 0x10100000L \
             || defined(LIBRESSL_VERSION_NUMBER)
            if (!SSL_CTX_set_ecdh_auto(s->ssl_ctx, 1)) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "SSL: SSL_CTX_set_ecdh_auto() failed");
            }
          #endif
        }
        if (nid) {
            EC_KEY *ecdh;
            ecdh = EC_KEY_new_by_curve_name(nid);
            if (ecdh == NULL) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "SSL: Unable to create curve",
                                s->ssl_ec_curve->ptr);
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
        for (size_t j = 0; j < srv->config_context->used; ++j) {
            plugin_config *s1 = p->config_storage[j];

            if (!buffer_string_is_empty(s1->ssl_ca_dn_file)) {
                if (1 != SSL_CTX_load_verify_locations(
                           s->ssl_ctx, s1->ssl_ca_dn_file->ptr, NULL)) {
                    log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                                    ERR_error_string(ERR_get_error(), NULL),
                                    s1->ssl_ca_dn_file);
                    return -1;
                }
            }
            if (!buffer_string_is_empty(s1->ssl_ca_file)) {
                if (1 != SSL_CTX_load_verify_locations(
                           s->ssl_ctx, s1->ssl_ca_file->ptr, NULL)) {
                    log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                                    ERR_error_string(ERR_get_error(), NULL),
                                    s1->ssl_ca_file);
                    return -1;
                }
            }
        }

        if (s->ssl_verifyclient) {
            int mode;
            if (NULL == s->ssl_ca_file_cert_names) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "SSL: You specified ssl.verifyclient.activate "
                                "but no ssl.ca-file or ssl.ca-dn-file");
                return -1;
            }
            SSL_CTX_set_client_CA_list(
              s->ssl_ctx, SSL_dup_CA_list(s->ssl_ca_file_cert_names));
            mode = SSL_VERIFY_PEER;
            if (s->ssl_verifyclient_enforce) {
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            SSL_CTX_set_verify(s->ssl_ctx, mode, verify_callback);
            SSL_CTX_set_verify_depth(s->ssl_ctx, s->ssl_verifyclient_depth + 1);
            if (!buffer_string_is_empty(s->ssl_ca_crl_file)) {
                X509_STORE *store = SSL_CTX_get_cert_store(s->ssl_ctx);
                if (1 != X509_STORE_load_locations(store, s->ssl_ca_crl_file->ptr, NULL)) {
                    log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                    ERR_error_string(ERR_get_error(), NULL), s->ssl_ca_crl_file);
                    return -1;
                }
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            }
        }

        if (1 != SSL_CTX_use_certificate_chain_file(s->ssl_ctx,
                                                    s->ssl_pemfile->ptr)) {
            log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
                            ERR_error_string(ERR_get_error(), NULL),
                            s->ssl_pemfile);
            return -1;
        }

        if (1 != SSL_CTX_use_PrivateKey(s->ssl_ctx, s->ssl_pemfile_pkey)) {
            log_error_write(srv, __FILE__, __LINE__, "ssbb", "SSL:",
                            ERR_error_string(ERR_get_error(), NULL),
                            s->ssl_pemfile, s->ssl_privkey);
            return -1;
        }

        if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
            log_error_write(srv, __FILE__, __LINE__, "sssbb", "SSL:",
                            "Private key does not match the certificate public "
                            "key, reason:",
                            ERR_error_string(ERR_get_error(), NULL),
                            s->ssl_pemfile, s->ssl_privkey);
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
            log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                            "failed to initialize TLS servername callback, "
                            "openssl library does not support TLS servername "
                            "extension");
            return -1;
        }
       #endif

       #if OPENSSL_VERSION_NUMBER >= 0x10002000
        SSL_CTX_set_alpn_select_cb(s->ssl_ctx,mod_openssl_alpn_select_cb,NULL);
       #endif
      #endif

        if (s->ssl_conf_cmd->used) {
            if (0 != network_openssl_ssl_conf_cmd(srv, s)) return -1;
        }
    }

    return 0;
}


SETDEFAULTS_FUNC(mod_openssl_set_defaults)
{
    plugin_data *p = p_d;
    config_values_t cv[] = {
        { "debug.log-ssl-noise",               NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
        { "ssl.engine",                        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { "ssl.pemfile",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 2 */
        { "ssl.ca-file",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 3 */
        { "ssl.dh-file",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 4 */
        { "ssl.ec-curve",                      NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 5 */
        { "ssl.cipher-list",                   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 6 */
        { "ssl.honor-cipher-order",            NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 7 */
        { "ssl.empty-fragments",               NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 8 */
        { "ssl.disable-client-renegotiation",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 9 */
        { "ssl.read-ahead",                    NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 10 */
        { "ssl.verifyclient.activate",         NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 11 */
        { "ssl.verifyclient.enforce",          NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 12 */
        { "ssl.verifyclient.depth",            NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 13 */
        { "ssl.verifyclient.username",         NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 14 */
        { "ssl.verifyclient.exportcert",       NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 15 */
        { "ssl.use-sslv2",                     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 16 */
        { "ssl.use-sslv3",                     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 17 */
        { "ssl.ca-crl-file",                   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 18 */
        { "ssl.ca-dn-file",                    NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 19 */
        { "ssl.openssl.ssl-conf-cmd",          NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_CONNECTION }, /* 20 */
        { "ssl.acme-tls-1",                    NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 21 */
        { "ssl.privkey",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 22 */
        { NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

    for (size_t i = 0; i < srv->config_context->used; i++) {
        data_config const* config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));

        s->ssl_enabled   = 0;
        s->ssl_pemfile   = buffer_init();
        s->ssl_privkey   = buffer_init();
        s->ssl_ca_file   = buffer_init();
        s->ssl_ca_crl_file = buffer_init();
        s->ssl_ca_dn_file = buffer_init();
        s->ssl_cipher_list = buffer_init();
        s->ssl_dh_file   = buffer_init();
        s->ssl_ec_curve  = buffer_init();
        s->ssl_honor_cipher_order = 1;
        s->ssl_empty_fragments = 0;
        s->ssl_use_sslv2 = 0;
        s->ssl_use_sslv3 = 0;
        s->ssl_verifyclient = 0;
        s->ssl_verifyclient_enforce = 1;
        s->ssl_verifyclient_username = buffer_init();
        s->ssl_verifyclient_depth = 9;
        s->ssl_verifyclient_export_cert = 0;
        s->ssl_disable_client_renegotiation = 1;
        s->ssl_read_ahead = (0 == i)
          ? 0
          : p->config_storage[0]->ssl_read_ahead;
        if (0 == i)
            buffer_copy_string_len(s->ssl_cipher_list, CONST_STR_LEN("HIGH"));
        if (0 != i) {
            buffer *b;
            b = p->config_storage[0]->ssl_ca_crl_file;
            if (!buffer_string_is_empty(b))
                buffer_copy_buffer(s->ssl_ca_crl_file, b);
            b = p->config_storage[0]->ssl_ca_dn_file;
            if (!buffer_string_is_empty(b))
                buffer_copy_buffer(s->ssl_ca_dn_file, b);
            b = p->config_storage[0]->ssl_cipher_list;
            if (!buffer_string_is_empty(b))
                buffer_copy_buffer(s->ssl_cipher_list, b);
        }
        s->ssl_conf_cmd = (0 == i)
          ? array_init()
          : array_init_array(p->config_storage[0]->ssl_conf_cmd);
        s->ssl_acme_tls_1 = buffer_init();

        cv[0].destination = &(s->ssl_log_noise);
        cv[1].destination = &(s->ssl_enabled);
        cv[2].destination = s->ssl_pemfile;
        cv[3].destination = s->ssl_ca_file;
        cv[4].destination = s->ssl_dh_file;
        cv[5].destination = s->ssl_ec_curve;
        cv[6].destination = s->ssl_cipher_list;
        cv[7].destination = &(s->ssl_honor_cipher_order);
        cv[8].destination = &(s->ssl_empty_fragments);
        cv[9].destination = &(s->ssl_disable_client_renegotiation);
        cv[10].destination = &(s->ssl_read_ahead);
        cv[11].destination = &(s->ssl_verifyclient);
        cv[12].destination = &(s->ssl_verifyclient_enforce);
        cv[13].destination = &(s->ssl_verifyclient_depth);
        cv[14].destination = s->ssl_verifyclient_username;
        cv[15].destination = &(s->ssl_verifyclient_export_cert);
        cv[16].destination = &(s->ssl_use_sslv2);
        cv[17].destination = &(s->ssl_use_sslv3);
        cv[18].destination = s->ssl_ca_crl_file;
        cv[19].destination = s->ssl_ca_dn_file;
        cv[20].destination = s->ssl_conf_cmd;
        cv[21].destination = s->ssl_acme_tls_1;
        cv[22].destination = s->ssl_privkey;

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (0 != i && s->ssl_enabled && buffer_string_is_empty(s->ssl_pemfile)){
            /* inherit ssl settings from global scope (in network_init_ssl())
             * (if only ssl.engine = "enable" and no other ssl.* settings)*/
            for (size_t j = 0; j < config->value->used; ++j) {
                buffer *k = config->value->data[j]->key;
                if (0 == strncmp(k->ptr, "ssl.", sizeof("ssl.")-1)
                    && !buffer_is_equal_string(k, CONST_STR_LEN("ssl.engine"))){
                    log_error_write(srv, __FILE__, __LINE__, "sb",
                                    "ssl.pemfile has to be set in same scope "
                                    "as other ssl.* directives, unless only "
                                    "ssl.engine is set, inheriting ssl.* from "
                                    "global scope", k);
                    return HANDLER_ERROR;
                }
            }
        }

        if (0 != i && s->ssl_enabled && config->comp != COMP_SERVER_SOCKET) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "ssl.engine is valid only in global scope "
                            "or $SERVER[\"socket\"] condition");
        }

        if (!array_is_kvstring(s->ssl_conf_cmd)) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "ssl.openssl.ssl-conf-cmd must be array "
                            "of \"key\" => \"value\" strings");
        }
    }

    if (0 != network_init_ssl(srv, p)) return HANDLER_ERROR;

    return HANDLER_GO_ON;
}


#define PATCH(x) \
    hctx->conf.x = s->x;
static int
mod_openssl_patch_connection (server *srv, connection *con, handler_ctx *hctx)
{
    plugin_config *s = plugin_data_singleton->config_storage[0];

    /*PATCH(ssl_enabled);*//*(not patched)*/
    /*PATCH(ssl_pemfile);*//*(not patched)*/
    /*PATCH(ssl_privkey);*//*(not patched)*/
    PATCH(ssl_pemfile_x509);
    PATCH(ssl_pemfile_pkey);
    PATCH(ssl_ca_file);
    /*PATCH(ssl_ca_crl_file);*//*(not patched)*/
    PATCH(ssl_ca_dn_file);
    PATCH(ssl_ca_file_cert_names);
    /*PATCH(ssl_cipher_list);*//*(not patched)*/
    /*PATCH(ssl_dh_file);*//*(not patched)*/
    /*PATCH(ssl_ec_curve);*//*(not patched)*/
    /*PATCH(ssl_honor_cipher_order);*//*(not patched)*/
    /*PATCH(ssl_empty_fragments);*//*(not patched)*/
    /*PATCH(ssl_use_sslv2);*//*(not patched)*/
    /*PATCH(ssl_use_sslv3);*//*(not patched)*/
    /*PATCH(ssl_conf_cmd);*//*(not patched)*/

    PATCH(ssl_verifyclient);
    PATCH(ssl_verifyclient_enforce);
    PATCH(ssl_verifyclient_depth);
    PATCH(ssl_verifyclient_username);
    PATCH(ssl_verifyclient_export_cert);
    PATCH(ssl_disable_client_renegotiation);
    PATCH(ssl_read_ahead);
    PATCH(ssl_acme_tls_1);

    PATCH(ssl_log_noise);

    /* skip the first, the global context */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = plugin_data_singleton->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.pemfile"))) {
                /*PATCH(ssl_pemfile);*//*(not patched)*/
                /*PATCH(ssl_privkey);*//*(not patched)*/
                PATCH(ssl_pemfile_x509);
                PATCH(ssl_pemfile_pkey);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.ca-file"))) {
                PATCH(ssl_ca_file);
                PATCH(ssl_ca_file_cert_names);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.ca-dn-file"))) {
                PATCH(ssl_ca_dn_file);
                PATCH(ssl_ca_file_cert_names);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.verifyclient.activate"))) {
                PATCH(ssl_verifyclient);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.verifyclient.enforce"))) {
                PATCH(ssl_verifyclient_enforce);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.verifyclient.depth"))) {
                PATCH(ssl_verifyclient_depth);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.verifyclient.username"))) {
                PATCH(ssl_verifyclient_username);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.verifyclient.exportcert"))) {
                PATCH(ssl_verifyclient_export_cert);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.disable-client-renegotiation"))) {
                PATCH(ssl_disable_client_renegotiation);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.read-ahead"))) {
                PATCH(ssl_read_ahead);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.acme-tls-1"))) {
                PATCH(ssl_acme_tls_1);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-ssl-noise"))) {
                PATCH(ssl_log_noise);
          #if 0 /*(not patched)*/
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.ca-crl-file"))) {
                PATCH(ssl_ca_crl_file);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.honor-cipher-order"))) {
                PATCH(ssl_honor_cipher_order);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.empty-fragments"))) {
                PATCH(ssl_empty_fragments);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.use-sslv2"))) {
                PATCH(ssl_use_sslv2);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.use-sslv3"))) {
                PATCH(ssl_use_sslv3);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.cipher-list"))) {
                PATCH(ssl_cipher_list);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.dh-file"))) {
                PATCH(ssl_dh_file);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.ec-curve"))) {
                PATCH(ssl_ec_curve);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.engine"))) {
                PATCH(ssl_enabled);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("ssl.openssl.ssl-conf-cmd"))) {
                PATCH(ssl_conf_cmd);
          #endif
            }
        }
    }

    return 0;
}
#undef PATCH


static int
load_next_chunk (server *srv, chunkqueue *cq, off_t max_bytes,
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
        if (0 != chunkqueue_open_file_chunk(srv, cq)) return -1;

        {
            off_t offset, toSend;

            force_assert(c->offset >= 0 && c->offset <= c->file.length);
            offset = c->file.start + c->offset;
            toSend = c->file.length - c->offset;

            if (toSend > LOCAL_SEND_BUFSIZE) toSend = LOCAL_SEND_BUFSIZE;
            if (toSend > max_bytes) toSend = max_bytes;

            if (-1 == lseek(c->file.fd, offset, SEEK_SET)) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "lseek: ", strerror(errno));
                return -1;
            }
            if (-1 == (toSend = read(c->file.fd, local_send_buffer, toSend))) {
                log_error_write(srv, __FILE__, __LINE__, "ss",
                                "read: ", strerror(errno));
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
mod_openssl_close_notify(server *srv, handler_ctx *hctx);


static int
connection_write_cq_ssl (server *srv, connection *con,
                         chunkqueue *cq, off_t max_bytes)
{
    handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id];
    SSL *ssl = hctx->ssl;

    if (0 != hctx->close_notify) return mod_openssl_close_notify(srv, hctx);

    chunkqueue_remove_finished_chunks(cq);

    while (max_bytes > 0 && NULL != cq->first) {
        const char *data;
        size_t data_len;
        int r;

        if (0 != load_next_chunk(srv,cq,max_bytes,&data,&data_len)) return -1;

        /**
         * SSL_write man-page
         *
         * WARNING
         *        When an SSL_write() operation has to be repeated because of
         *        SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be
         *        repeated with the same arguments.
         */

        ERR_clear_error();
        r = SSL_write(ssl, data, data_len);

        if (hctx->renegotiations > 1
            && hctx->conf.ssl_disable_client_renegotiation) {
            log_error_write(srv, __FILE__, __LINE__, "s",
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }

        if (r <= 0) {
            int ssl_r;
            unsigned long err;

            switch ((ssl_r = SSL_get_error(ssl, r))) {
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
                        log_error_write(srv, __FILE__, __LINE__, "sdds",
                                        "SSL:", ssl_r, r,
                                        ERR_error_string(err, NULL));
                    } while((err = ERR_get_error()));
                } else if (r == -1) {
                    /* no, but we have errno */
                    switch(errno) {
                    case EPIPE:
                    case ECONNRESET:
                        return -2;
                    default:
                        log_error_write(srv, __FILE__, __LINE__, "sddds",
                                        "SSL:", ssl_r, r, errno,
                                        strerror(errno));
                        break;
                    }
                } else {
                    /* neither error-queue nor errno ? */
                    log_error_write(srv, __FILE__, __LINE__, "sddds",
                                    "SSL (error):", ssl_r, r, errno,
                                    strerror(errno));
                }
                break;

            case SSL_ERROR_ZERO_RETURN:
                /* clean shutdown on the remote side */

                if (r == 0) return -2;

                /* fall through */
            default:
                while((err = ERR_get_error())) {
                    log_error_write(srv, __FILE__, __LINE__, "sdds",
                                    "SSL:", ssl_r, r,
                                    ERR_error_string(err, NULL));
                }
                break;
            }
            return -1;
        }

        chunkqueue_mark_written(cq, r);
        max_bytes -= r;

        if ((size_t) r < data_len) break; /* try again later */
    }

    return 0;
}


static int
connection_read_cq_ssl (server *srv, connection *con,
                        chunkqueue *cq, off_t max_bytes)
{
    handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id];
    int r, ssl_err, len;
    char *mem = NULL;
    size_t mem_len = 0;

    /*(code transform assumption; minimize diff)*/
    force_assert(cq == con->read_queue);
    UNUSED(max_bytes);

    if (0 != hctx->close_notify) return mod_openssl_close_notify(srv, hctx);

    ERR_clear_error();
    do {
        len = SSL_pending(hctx->ssl);
        mem_len = len < 2048 ? 2048 : (size_t)len;
        mem = chunkqueue_get_memory(con->read_queue, &mem_len);
#if 0
        /* overwrite everything with 0 */
        memset(mem, 0, mem_len);
#endif

        len = SSL_read(hctx->ssl, mem, mem_len);
        if (len > 0) {
            chunkqueue_use_memory(con->read_queue, len);
            con->bytes_read += len;
        } else {
            chunkqueue_use_memory(con->read_queue, 0);
        }

        if (hctx->renegotiations > 1
            && hctx->conf.ssl_disable_client_renegotiation) {
            log_error_write(srv, __FILE__, __LINE__, "s",
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
        switch ((r = SSL_get_error(hctx->ssl, len))) {
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
                log_error_write(srv, __FILE__, __LINE__, "sds", "SSL:",
                        r, ERR_error_string(ssl_err, NULL));
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

                log_error_write(srv, __FILE__, __LINE__, "sddds", "SSL:",
                        len, r, oerrno,
                        strerror(oerrno));
                break;
            }

            break;
        case SSL_ERROR_ZERO_RETURN:
            /* clean shutdown on the remote side */

            if (r == 0) {
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
                log_error_write(srv, __FILE__, __LINE__, "sds", "SSL:",
                                r, ERR_error_string(ssl_err, NULL));
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
    plugin_data *p = p_d;
    handler_ctx *hctx;
    server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    hctx = handler_ctx_init();
    hctx->con = con;
    hctx->srv = srv;
    con->plugin_ctx[p->id] = hctx;
    mod_openssl_patch_connection(srv, con, hctx);

    /* connect fd to SSL */
    hctx->ssl = SSL_new(p->config_storage[srv_sock->sidx]->ssl_ctx);
    if (NULL == hctx->ssl) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                        ERR_error_string(ERR_get_error(), NULL));
        return HANDLER_ERROR;
    }

    buffer_copy_string_len(con->proto, CONST_STR_LEN("https"));
    con->network_read = connection_read_cq_ssl;
    con->network_write = connection_write_cq_ssl;
    SSL_set_app_data(hctx->ssl, hctx);
    SSL_set_accept_state(hctx->ssl);

    if (1 != (SSL_set_fd(hctx->ssl, con->fd))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                        ERR_error_string(ERR_get_error(), NULL));
        return HANDLER_ERROR;
    }

    return HANDLER_GO_ON;
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
        mod_openssl_close_notify(srv, hctx);
    }
    else {
        mod_openssl_detach(hctx);
    }

    return HANDLER_GO_ON;
}


static int
mod_openssl_close_notify(server *srv, handler_ctx *hctx)
{
        int ret, ssl_r;
        unsigned long err;

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
                if (0 != (err = ERR_get_error())) {
                    do {
                        log_error_write(srv, __FILE__, __LINE__, "sdds",
                                        "SSL:", ssl_r, ret,
                                        ERR_error_string(err, NULL));
                    } while((err = ERR_get_error()));
                } else if (errno != 0) {
                    /*ssl bug (see lighttpd ticket #2213): sometimes errno==0*/
                    switch(errno) {
                    case EPIPE:
                    case ECONNRESET:
                        break;
                    default:
                        log_error_write(srv, __FILE__, __LINE__, "sddds",
                                        "SSL (error):", ssl_r, ret, errno,
                                        strerror(errno));
                        break;
                    }
                }

                break;
            default:
                while((err = ERR_get_error())) {
                    log_error_write(srv, __FILE__, __LINE__, "sdds",
                                    "SSL:", ssl_r, ret,
                                    ERR_error_string(err, NULL));
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

    UNUSED(srv);
    return HANDLER_GO_ON;
}


static void
https_add_ssl_client_entries (server *srv, connection *con, handler_ctx *hctx)
{
    X509 *xs;
    X509_NAME *xn;
    int i, nentries;

    long vr = SSL_get_verify_result(hctx->ssl);
    if (vr != X509_V_OK) {
        char errstr[256];
        ERR_error_string_n(vr, errstr, sizeof(errstr));
        buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("FAILED:"));
        buffer_append_string(srv->tmp_buf, errstr);
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_BUF_LEN(srv->tmp_buf));
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
    buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("SSL_CLIENT_S_DN_"));
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
            buffer_string_set_length(srv->tmp_buf,sizeof("SSL_CLIENT_S_DN_")-1);
            buffer_append_string(srv->tmp_buf, xobjsn);
            http_header_env_set(con,
                                CONST_BUF_LEN(srv->tmp_buf),
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
        buffer *varname = hctx->conf.ssl_verifyclient_username;
        buffer *vb = http_header_env_get(con, CONST_BUF_LEN(varname));
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
            buffer *cert = srv->tmp_buf;
            int n;

            PEM_write_bio_X509(bio, xs);
            n = BIO_pending(bio);

            buffer_string_prepare_copy(cert, n);
            BIO_read(bio, cert->ptr, n);
            BIO_free(bio);
            buffer_commit(cert, n);
            http_header_env_set(con,
                                CONST_STR_LEN("SSL_CLIENT_CERT"),
                                CONST_BUF_LEN(cert));
        }
    }
    X509_free(xs);
}


static void
http_cgi_ssl_env (server *srv, connection *con, handler_ctx *hctx)
{
    const char *s;
    const SSL_CIPHER *cipher;
    UNUSED(srv);

    s = SSL_get_version(hctx->ssl);
    http_header_env_set(con,
                        CONST_STR_LEN("SSL_PROTOCOL"),
                        s, strlen(s));

    if ((cipher = SSL_get_current_cipher(hctx->ssl))) {
        int usekeysize, algkeysize;
        char buf[LI_ITOSTRING_LENGTH];
        s = SSL_CIPHER_get_name(cipher);
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CIPHER"),
                            s, strlen(s));
        usekeysize = SSL_CIPHER_get_bits(cipher, &algkeysize);
        li_itostrn(buf, sizeof(buf), usekeysize);
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, strlen(buf));
        li_itostrn(buf, sizeof(buf), algkeysize);
        http_header_env_set(con,
                            CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                            buf, strlen(buf));
    }
}


CONNECTION_FUNC(mod_openssl_handle_request_env)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    if (hctx->request_env_patched) return HANDLER_GO_ON;
    hctx->request_env_patched = 1;

    http_cgi_ssl_env(srv, con, hctx);
    if (hctx->conf.ssl_verifyclient) {
        https_add_ssl_client_entries(srv, con, hctx);
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

    mod_openssl_patch_connection(srv, con, hctx);
    if (hctx->conf.ssl_verifyclient) {
        mod_openssl_handle_request_env(srv, con, p);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_request_reset)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    hctx->request_env_patched = 0;

    UNUSED(srv);
    return HANDLER_GO_ON;
}


int mod_openssl_plugin_init (plugin *p);
int mod_openssl_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = buffer_init_string("openssl");
    p->init         = mod_openssl_init;
    p->cleanup      = mod_openssl_free;
    p->priv_defaults= mod_openssl_set_defaults;

    p->handle_connection_accept  = mod_openssl_handle_con_accept;
    p->handle_connection_shut_wr = mod_openssl_handle_con_shut_wr;
    p->handle_connection_close   = mod_openssl_handle_con_close;
    p->handle_uri_raw            = mod_openssl_handle_uri_raw;
    p->handle_request_env        = mod_openssl_handle_request_env;
    p->connection_reset          = mod_openssl_handle_request_reset;

    p->data         = NULL;

    return 0;
}
