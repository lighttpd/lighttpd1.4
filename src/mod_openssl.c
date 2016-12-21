#include "first.h"

#include <errno.h>
#include <string.h>

#ifndef USE_OPENSSL_KERBEROS
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#endif

#include <openssl/ssl.h>
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
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;

            free(s);
        }
        free(p->config_storage);
    }

    free(p);

    UNUSED(srv);
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


CONNECTION_FUNC(mod_openssl_handle_con_accept)
{
    server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    {
        plugin_data *p = p_d;
        handler_ctx *hctx = handler_ctx_init();
        con->plugin_ctx[p->id] = hctx;
        mod_openssl_patch_connection(srv, con, hctx);
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    UNUSED(srv);
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    handler_ctx_free(hctx);

    UNUSED(srv);
    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_openssl_handle_request_env)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    if (hctx->request_env_patched) return HANDLER_GO_ON;
    hctx->request_env_patched = 1;

    UNUSED(srv);
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
