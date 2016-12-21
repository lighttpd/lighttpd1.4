#include "first.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifndef USE_OPENSSL_KERBEROS
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#endif

#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "base.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    int dummy;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

typedef struct {
    SSL *ssl;
    buffer *tlsext_server_name;
    unsigned int renegotiations; /* count of SSL_CB_HANDSHAKE_START */
    int request_env_patched;
    plugin_config conf;
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
    buffer_free(hctx->tlsext_server_name);
    free(hctx);
}


INIT_FUNC(mod_openssl_init)
{
    return calloc(1, sizeof(plugin_data));
}


FREE_FUNC(mod_openssl_free)
{
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            specific_config *s = srv->config_storage[i];
            buffer_free(s->ssl_pemfile);
            buffer_free(s->ssl_ca_file);
            buffer_free(s->ssl_cipher_list);
            buffer_free(s->ssl_dh_file);
            buffer_free(s->ssl_ec_curve);
            buffer_free(s->ssl_verifyclient_username);
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

    free(p);

    if (srv->ssl_is_init) {
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
    }

    return HANDLER_GO_ON;
}


SETDEFAULTS_FUNC(mod_openssl_set_defaults)
{
    UNUSED(srv);
    UNUSED(p_d);
    return HANDLER_GO_ON;
}


#define PATCH(x) \
    p->conf.x = s->x;
static int
mod_openssl_patch_connection (server *srv, connection *con, handler_ctx *p)
{
    UNUSED(srv);
    UNUSED(con);
    UNUSED(p);
    return 0;
}
#undef PATCH


static int
load_next_chunk (server *srv, chunkqueue *cq, off_t max_bytes,
                 const char **data, size_t *data_len)
{
    chunk * const c = cq->first;

#define LOCAL_SEND_BUFSIZE (64 * 1024)
    /* this is a 64k sendbuffer
     *
     * it has to stay at the same location all the time to satisfy the needs
     * of SSL_write to pass the SAME parameter in case of a _WANT_WRITE
     *
     * buffer is allocated once, is NOT realloced and is NOT freed at shutdown
     * -> we expect a 64k block to 'leak' in valgrind
     * */
    static char *local_send_buffer = NULL;

    force_assert(NULL != c);

    switch (c->type) {
    case MEM_CHUNK:
        {
            size_t have;

            force_assert(c->offset >= 0
                         && c->offset <= (off_t)buffer_string_length(c->mem));

            have = buffer_string_length(c->mem) - c->offset;
            if ((off_t) have > max_bytes) have = max_bytes;

            *data = c->mem->ptr + c->offset;
            *data_len = have;
        }
        return 0;

    case FILE_CHUNK:
        if (NULL == local_send_buffer) {
            local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
            force_assert(NULL != local_send_buffer);
        }

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
connection_write_cq_ssl (server *srv, connection *con,
                         chunkqueue *cq, off_t max_bytes)
{
    /* the remote side closed the connection before without shutdown request
     * - IE
     * - wget
     * if keep-alive is disabled */
    SSL *ssl = con->ssl;

    if (con->keep_alive == 0) {
        SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
    }

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

        if (con->renegotiations > 1
            && con->conf.ssl_disable_client_renegotiation) {
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
    int r, ssl_err, len;
    char *mem = NULL;
    size_t mem_len = 0;

    /*(code transform assumption; minimize diff)*/
    force_assert(cq == con->read_queue);
    UNUSED(max_bytes);

    ERR_clear_error();
    do {
        chunkqueue_get_memory(con->read_queue, &mem, &mem_len, 0,
                              SSL_pending(con->ssl));
#if 0
        /* overwrite everything with 0 */
        memset(mem, 0, mem_len);
#endif

        len = SSL_read(con->ssl, mem, mem_len);
        if (len > 0) {
            chunkqueue_use_memory(con->read_queue, len);
            con->bytes_read += len;
        } else {
            chunkqueue_use_memory(con->read_queue, 0);
        }

        if (con->renegotiations > 1
            && con->conf.ssl_disable_client_renegotiation) {
            log_error_write(srv, __FILE__, __LINE__, "s",
              "SSL: renegotiation initiated by client, killing connection");
            return -1;
        }
    } while (len > 0 &&(con.conf->ssl_read_ahead || SSL_pending(con->ssl) > 0));

    if (len < 0) {
        int oerrno = errno;
        switch ((r = SSL_get_error(con->ssl, len))) {
        case SSL_ERROR_WANT_WRITE:
            con->is_writable = -1;
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

            /* fall thourgh */
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
                    if (!con->conf.log_ssl_noise) continue;
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
    con->plugin_ctx[p->id] = hctx;
    mod_openssl_patch_connection(srv, con, hctx);

    /* connect fd to SSL */
    con->ssl = SSL_new(srv->config_storage[srv_sock->sidx]->ssl_ctx);
    if (NULL == con->ssl) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                        ERR_error_string(ERR_get_error(), NULL));
        return HANDLER_ERROR;
    }

    con->network_read = connection_read_cq_ssl;
    con->network_write = connection_write_cq_ssl;
    con->renegotiations = 0;
    SSL_set_app_data(con->ssl, con);
    SSL_set_accept_state(con->ssl);

    if (1 != (SSL_set_fd(con->ssl, con->fd))) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
                        ERR_error_string(ERR_get_error(), NULL));
        return HANDLER_ERROR;
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    if (SSL_is_init_finished(con->ssl)) {
        int ret, ssl_r;
        unsigned long err;
        ERR_clear_error();
        switch ((ret = SSL_shutdown(con->ssl))) {
        case 1:
            /* ok */
            break;
        case 0:
            /* wait for fd-event
             *
             * FIXME: wait for fdevent and call SSL_shutdown again
             *
             */
            ERR_clear_error();
            if (-1 != (ret = SSL_shutdown(con->ssl))) break;

            /* fall through */
        default:

            switch ((ssl_r = SSL_get_error(con->ssl, ret))) {
            case SSL_ERROR_ZERO_RETURN:
                break;
            case SSL_ERROR_WANT_WRITE:
                /*con->is_writable=-1;*//*(no effect; shutdown() called below)*/
            case SSL_ERROR_WANT_READ:
                break;
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
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    if (con->ssl) SSL_free(con->ssl);
    con->ssl = NULL;
    handler_ctx_free(hctx);

    UNUSED(srv);
    return HANDLER_GO_ON;
}


static void
https_add_ssl_client_entries (server *srv, connection *con)
{
    X509 *xs;
    X509_NAME *xn;
    int i, nentries;

    long vr = SSL_get_verify_result(con->ssl);
    if (vr != X509_V_OK) {
        char errstr[256];
        ERR_error_string_n(vr, errstr, sizeof(errstr));
        buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("FAILED:"));
        buffer_append_string(srv->tmp_buf, errstr);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_BUF_LEN(srv->tmp_buf));
        return;
    } else if (!(xs = SSL_get_peer_certificate(con->ssl))) {
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_STR_LEN("NONE"));
        return;
    } else {
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CLIENT_VERIFY"),
                            CONST_STR_LEN("SUCCESS"));
    }

    buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("SSL_CLIENT_S_DN_"));
    xn = X509_get_subject_name(xs);
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
            array_set_key_value(con->environment,
                                CONST_BUF_LEN(srv->tmp_buf),
                                (const char*)X509_NAME_ENTRY_get_data(xe)->data,
                                X509_NAME_ENTRY_get_data(xe)->length);
        }
    }

    {
        ASN1_INTEGER *xsn = X509_get_serialNumber(xs);
        BIGNUM *serialBN = ASN1_INTEGER_to_BN(xsn, NULL);
        char *serialHex = BN_bn2hex(serialBN);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CLIENT_M_SERIAL"),
                            serialHex, strlen(serialHex));
        OPENSSL_free(serialHex);
        BN_free(serialBN);
    }

    if (!buffer_string_is_empty(con->conf.ssl_verifyclient_username)) {
        /* pick one of the exported values as "REMOTE_USER", for example
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_UID"
         * or
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_emailAddress"
         */
        data_string *ds = (data_string *)
          array_get_element(con->environment,
                            con->conf.ssl_verifyclient_username->ptr);
        if (ds) { /* same as http_auth.c:http_auth_setenv() */
            array_set_key_value(con->environment,
                                CONST_STR_LEN("REMOTE_USER"),
                                CONST_BUF_LEN(ds->value));
            array_set_key_value(con->environment,
                                CONST_STR_LEN("AUTH_TYPE"),
                                CONST_STR_LEN("SSL_CLIENT_VERIFY"));
        }
    }

    if (con->conf.ssl_verifyclient_export_cert) {
        BIO *bio;
        if (NULL != (bio = BIO_new(BIO_s_mem()))) {
            data_string *envds;
            int n;

            PEM_write_bio_X509(bio, xs);
            n = BIO_pending(bio);

            envds = (data_string *)
              array_get_unused_element(con->environment, TYPE_STRING);
            if (NULL == envds) {
                envds = data_string_init();
            }

            buffer_copy_string_len(envds->key,CONST_STR_LEN("SSL_CLIENT_CERT"));
            buffer_string_prepare_copy(envds->value, n);
            BIO_read(bio, envds->value->ptr, n);
            BIO_free(bio);
            buffer_commit(envds->value, n);
            array_replace(con->environment, (data_unset *)envds);
        }
    }
    X509_free(xs);
}


static void
http_cgi_ssl_env (connection *con)
{
    const char *s;
    const SSL_CIPHER *cipher;

    if (!con->ssl) return;

    s = SSL_get_version(con->ssl);
    array_set_key_value(con->environment,
                        CONST_STR_LEN("SSL_PROTOCOL"),
                        s, strlen(s));

    if ((cipher = SSL_get_current_cipher(con->ssl))) {
        int usekeysize, algkeysize;
        char buf[LI_ITOSTRING_LENGTH];
        s = SSL_CIPHER_get_name(cipher);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CIPHER"),
                            s, strlen(s));
        usekeysize = SSL_CIPHER_get_bits(cipher, &algkeysize);
        li_itostrn(buf, sizeof(buf), usekeysize);
        array_set_key_value(con->environment,
                            CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                            buf, strlen(buf));
        li_itostrn(buf, sizeof(buf), algkeysize);
        array_set_key_value(con->environment,
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

    http_cgi_ssl_env(con);
    if (con->conf.ssl_verifyclient) {
        https_add_ssl_client_entries(srv, con);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_uri_raw)
{
    /* mod_openssl must be loaded prior to mod_auth
     * if mod_openssl is configured to set REMOTE_USER based on client cert */
    /* mod_openssl must be loaded after mod_extforward
     * if mod_openssl config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward */
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    if (con->conf.ssl_verifyclient) {
        mod_openssl_handle_request_env(srv, con, p);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_request_reset)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    /*
     * XXX: preserve (for now) lighttpd historical behavior which resets
     * tlsext_server_name after each request, meaning SNI is valid only for
     * initial request, prior to reading request headers.  Probably should
     * instead validate that Host header (or authority in request line)
     * matches SNI server name for all requests on the connection on which
     * SNI extension has been provided.
     */
    buffer_reset(hctx->tlsext_server_name);
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
    p->set_defaults = mod_openssl_set_defaults;

    p->handle_connection_accept  = mod_openssl_handle_con_accept;
    p->handle_connection_shut_wr = mod_openssl_handle_con_shut_wr;
    p->handle_connection_close   = mod_openssl_handle_con_close;
    p->handle_uri_raw            = mod_openssl_handle_uri_raw;
    p->handle_request_env        = mod_openssl_handle_request_env;
    p->connection_reset          = mod_openssl_handle_request_reset;

    p->data         = NULL;

    return 0;
}
