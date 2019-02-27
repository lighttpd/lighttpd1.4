/*
 * mod_wstunnel originally based off https://github.com/nori0428/mod_websocket
 * Portions of this module Copyright(c) 2017, Glenn Strauss, All rights reserved
 * Portions of this module Copyright(c) 2010, Norio Kobota, All rights reserved.
 */

/*
 * Copyright(c) 2010, Norio Kobota, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the 'incremental' nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/* NOTES:
 *
 * mod_wstunnel has been largely rewritten from Norio Kobota mod_websocket.
 *
 * highlighted differences from Norio Kobota mod_websocket
 * - re-coded to use lighttpd 1.4.46 buffer, chunkqueue, and gw_backend APIs
 * - websocket.server "ext" value is no longer regex;
 *   operates similar to mod_proxy for either path prefix or extension match
 * - validation of "origins" value is no longer regex; operates as suffix match
 *   (admin could use lighttpd.conf regex on "Origin" or "Sec-WebSocket-Origin"
 *    and reject non-matches with mod_access if such regex validation required)
 * - websocket transparent proxy mode removed; functionality is now in mod_proxy
 *   Backend server which responds to Connection: upgrade and Upgrade: websocket
 *   should check "Origin" and/or "Sec-WebSocket-Origin".  lighttpd.conf could
 *   additionally be configured to check
 *     $REQUEST_HEADER["Sec-WebSocket-Origin"] !~ "..."
 *   with regex, and mod_access used to reject non-matches, if desired.
 * - connections to backend no longer block, but only first address returned
 *   by getaddrinfo() is used; lighttpd does not cycle through all addresses
 *   returned by DNS resolution.  Note: DNS resolution occurs once at startup.
 * - directives renamed from websocket.* to wstunnel.*
 * - directive websocket.ping_interval replaced with wstunnel.ping-interval
 *     (note the '_' changed to '-')
 * - directive websocket.timeout should be replaced with server.max-read-idle
 * - attribute "type" is an independent directive wstunnel.frame-type
 *     (default is "text" unless "binary" is specified)
 * - attribute "origins" is an independent directive wstunnel.origins
 * - attribute "proto" removed; mod_proxy can proxy to backend websocket server
 * - attribute "subproto" should be replaced with mod_setenv directive
 *     setenv.set-response-header = ( "Sec-WebSocket-Protocol" => "..." )
 *     if header is required
 *
 * not reviewed:
 * - websocket protocol compliance has not been reviewed
 *     e.g. when to send 1000 Normal Closure and when to send 1001 Going Away
 * - websocket protocol sanity checking has not been reviewed
 *
 * References:
 *   https://en.wikipedia.org/wiki/WebSocket
 *   https://tools.ietf.org/html/rfc6455
 *   https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-00
 */
#include "first.h"

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "gw_backend.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"
#include "http_header.h"
#include "joblist.h"
#include "log.h"

#define MOD_WEBSOCKET_LOG_NONE  0
#define MOD_WEBSOCKET_LOG_ERR   1
#define MOD_WEBSOCKET_LOG_WARN  2
#define MOD_WEBSOCKET_LOG_INFO  3
#define MOD_WEBSOCKET_LOG_DEBUG 4

#define DEBUG_LOG(level, format, ...)                                        \
  if (hctx->gw.conf.debug >= (level)) {                                      \
      log_error_write(hctx->srv, __FILE__, __LINE__, (format), __VA_ARGS__); \
  }

typedef struct {
    gw_plugin_config gw;
    buffer *frame_type;
    array *origins;
    unsigned short int ping_interval;
} plugin_config;

typedef struct plugin_data {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

typedef enum {
    MOD_WEBSOCKET_FRAME_STATE_INIT,

    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
    MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH,
    MOD_WEBSOCKET_FRAME_STATE_READ_MASK,
    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

    MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD
} mod_wstunnel_frame_state_t;

typedef enum {
    MOD_WEBSOCKET_FRAME_TYPE_TEXT,
    MOD_WEBSOCKET_FRAME_TYPE_BIN,
    MOD_WEBSOCKET_FRAME_TYPE_CLOSE,

    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
    MOD_WEBSOCKET_FRAME_TYPE_PING,
    MOD_WEBSOCKET_FRAME_TYPE_PONG
    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_wstunnel_frame_type_t;

typedef struct {
    uint64_t siz;

    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
    int siz_cnt;
    int mask_cnt;
    #define MOD_WEBSOCKET_MASK_CNT 4
    unsigned char mask[MOD_WEBSOCKET_MASK_CNT];
    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_wstunnel_frame_control_t;

typedef struct {
    mod_wstunnel_frame_state_t state;
    mod_wstunnel_frame_control_t ctl;
    mod_wstunnel_frame_type_t type, type_before, type_backend;
    buffer *payload;
} mod_wstunnel_frame_t;

typedef struct {
    gw_handler_ctx gw;
    mod_wstunnel_frame_t frame;

    int hybivers;
    time_t ping_ts;
    int subproto;

    server *srv;  /*(for mod_wstunnel module-specific DEBUG_LOG() macro)*/
    plugin_config conf;
} handler_ctx;

/* prototypes */
static handler_t mod_wstunnel_handshake_create_response(handler_ctx *);
static int mod_wstunnel_frame_send(handler_ctx *, mod_wstunnel_frame_type_t, const char *, size_t);
static int mod_wstunnel_frame_recv(handler_ctx *);
#define _MOD_WEBSOCKET_SPEC_IETF_00_
#define _MOD_WEBSOCKET_SPEC_RFC_6455_

INIT_FUNC(mod_wstunnel_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_wstunnel_free) {
    plugin_data *p = p_d;
    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;
            buffer_free(s->frame_type);
            array_free(s->origins);
            /*assert(0 == offsetof(s->gw));*/
            gw_plugin_config_free(&s->gw);
            /*free(s);*//*free'd by gw_plugin_config_free()*/
        }
        free(p->config_storage);
    }
    free(p);
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_wstunnel_set_defaults) {
    plugin_data *p = p_d;
    data_unset *du;
    config_values_t cv[] = {
        { "wstunnel.server",        NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
        { "wstunnel.debug",         NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
        { "wstunnel.balance",       NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },
        { "wstunnel.map-extensions",NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
        { "wstunnel.frame-type",    NULL, T_CONFIG_STRING,T_CONFIG_SCOPE_CONNECTION },
        { "wstunnel.origins",       NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
        { "wstunnel.ping-interval", NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },
        { NULL,                     NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));
    force_assert(p->config_storage);
    for (size_t i = 0; i < srv->config_context->used; ++i) {
        array *ca = ((data_config *)(srv->config_context->data[i]))->value;
        plugin_config *s = calloc(1, sizeof(plugin_config));
        force_assert(s);

        s->gw.debug = 0; /* MOD_WEBSOCKET_LOG_NONE */
        s->gw.ext_mapping = array_init();
        s->frame_type = buffer_init();
        s->origins = array_init();
        s->ping_interval = 0; /* do not send ping */

        cv[0].destination = NULL; /* T_CONFIG_LOCAL */
        cv[1].destination = &(s->gw.debug);
        cv[2].destination = NULL; /* T_CONFIG_LOCAL */
        cv[3].destination = s->gw.ext_mapping;
        cv[4].destination = s->frame_type;
        cv[5].destination = s->origins;
        cv[6].destination = &(s->ping_interval);

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, ca, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        du = array_get_element(ca, "wstunnel.server");
        if (!gw_set_defaults_backend(srv, (gw_plugin_data *)p, du, i, 0)) {
            return HANDLER_ERROR;
        }

        du = array_get_element(ca, "wstunnel.balance");
        if (!gw_set_defaults_balance(srv, &s->gw, du)) {
            return HANDLER_ERROR;
        }

        /* disable check-local for all exts (default enabled) */
        if (s->gw.exts) { /*(check after gw_set_defaults_backend())*/
            for (size_t j = 0; j < s->gw.exts->used; ++j) {
                gw_extension *ex = s->gw.exts->exts[j];
                for (size_t n = 0; n < ex->used; ++n) {
                    ex->hosts[n]->check_local = 0;
                }
            }
        }

        /* error if "mode" = "authorizer"; wstunnel can not act as authorizer */
        /*(check after gw_set_defaults_backend())*/
        if (s->gw.exts_auth && s->gw.exts_auth->used) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "wstunnel.server must not define any hosts "
                            "with attribute \"mode\" = \"authorizer\"");
            return HANDLER_ERROR;
        }

        /*(default frame-type to "text" unless "binary" is specified)*/
        if (!buffer_is_empty(s->frame_type)
            && !buffer_is_equal_caseless_string(s->frame_type,
                                                CONST_STR_LEN("binary"))) {
            buffer_clear(s->frame_type);
        }

        if (!array_is_vlist(s->origins)) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "unexpected value for wstunnel.origins; expected wstunnel.origins = ( \"...\", \"...\" )");
            return HANDLER_ERROR;
        }
        for (size_t j = 0; j < s->origins->used; ++j) {
            if (buffer_string_is_empty(((data_string *)s->origins->data[j])->value)) {
                log_error_write(srv, __FILE__, __LINE__, "s",
                                "unexpected empty string in wstunnel.origins");
                return HANDLER_ERROR;
            }
        }
    }

    /*assert(0 == offsetof(s->gw));*/
    return HANDLER_GO_ON;
}

static handler_t wstunnel_create_env(server *srv, gw_handler_ctx *gwhctx) {
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    connection *con = hctx->gw.remote_conn;
    handler_t rc;
    if (0 == con->request.content_length) {
        http_response_upgrade_read_body_unknown(srv, con);
        chunkqueue_append_chunkqueue(con->request_content_queue,
                                     con->read_queue);
    }
    rc = mod_wstunnel_handshake_create_response(hctx);
    if (rc != HANDLER_GO_ON) return rc;

    con->http_status = 101; /* Switching Protocols */
    con->file_started = 1;

    hctx->ping_ts = srv->cur_ts;
    gw_set_transparent(srv, &hctx->gw);

    return HANDLER_GO_ON;
}

static handler_t wstunnel_stdin_append(server *srv, gw_handler_ctx *gwhctx) {
    /* prepare websocket frames to backend */
    /* (caller should verify con->request_content_queue) */
    /*assert(!chunkqueue_is_empty(con->request_content_queue));*/
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    if (0 == mod_wstunnel_frame_recv(hctx))
        return HANDLER_GO_ON;
    else {
        /*(error)*/
        /* future: might differentiate client close request from client error,
         *         and then send 1000 or 1001 */
        connection *con = hctx->gw.remote_conn;
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds",
                  "disconnected from client ( fd =", con->fd, ")");
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sds",
                  "send close response to client ( fd =", con->fd, ")");
        mod_wstunnel_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, CONST_STR_LEN("1000")); /* 1000 Normal Closure */
        gw_connection_reset(srv, con, hctx->gw.plugin_data);
        return HANDLER_FINISHED;
    }
}

static handler_t wstunnel_recv_parse(server *srv, connection *con, http_response_opts *opts, buffer *b, size_t n) {
    handler_ctx *hctx = (handler_ctx *)opts->pdata;
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "recv data from backend ( fd =", hctx->gw.fd, "), size =", n);
    if (0 == n) return HANDLER_FINISHED;
    if (mod_wstunnel_frame_send(hctx,hctx->frame.type_backend,b->ptr,n) < 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "fail to send data to client");
        return HANDLER_ERROR;
    }
    buffer_clear(b);
    UNUSED(srv);
    UNUSED(con);
    return HANDLER_GO_ON;
}

#define PATCH(x)    p->conf.x    = s->x
#define PATCH_GW(x) p->conf.gw.x = s->gw.x
static void mod_wstunnel_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH_GW(exts);
    PATCH_GW(exts_auth);
    PATCH_GW(exts_resp);
    PATCH_GW(debug);
    PATCH_GW(balance);
    PATCH_GW(ext_mapping);
    PATCH(frame_type);
    PATCH(origins);
    PATCH(ping_interval);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) {
            continue;
        }
        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.server"))) {
                PATCH_GW(exts);
                /*(wstunnel can not act as authorizer,
                 * but p->conf.exts_auth must not be NULL)*/
                PATCH_GW(exts_auth);
                PATCH_GW(exts_resp);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.debug"))) {
                PATCH_GW(debug);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.balance"))) {
                PATCH_GW(balance);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.map-extensions"))) {
                PATCH_GW(ext_mapping);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.frame-type"))) {
                PATCH(frame_type);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.origins"))) {
                PATCH(origins);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("wstunnel.ping-interval"))) {
                PATCH(ping_interval);
            }
        }
    }
}
#undef PATCH_GW
#undef PATCH

static int header_contains_token (buffer *b, const char *m, size_t mlen)
{
    for (char *s = b->ptr; s; s = strchr(s, ',')) {
        while (*s == ' ' || *s == '\t' || *s == ',') ++s;
        if (0 == strncasecmp(s, m, mlen)) {
            s += mlen;
            if (*s == '\0' || *s == ' ' || *s == '\t' || *s == ',' || *s == ';')
                return 1;
        }
    }
    return 0;
}

static int wstunnel_is_allowed_origin(connection *con, handler_ctx *hctx) {
    /* If allowed origins is set (and not empty list), fail closed if no match.
     * Note that origin provided in request header has not been normalized, so
     * change in case or other non-normal forms might not match allowed list */
    const array * const allowed_origins = hctx->conf.origins;
    buffer *origin = NULL;
    size_t olen;

    if (0 == allowed_origins->used) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s", "allowed origins not specified");
        return 1;
    }

    /* "Origin" header is preferred
     * ("Sec-WebSocket-Origin" is from older drafts of websocket spec) */
    origin = http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Origin"));
    if (NULL == origin) {
        origin =
          http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Origin"));
    }
    olen = buffer_string_length(origin);
    if (0 == olen) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "Origin header is invalid");
        con->http_status = 400; /* Bad Request */
        return 0;
    }

    for (size_t i = 0; i < allowed_origins->used; ++i) {
        buffer *b = ((data_string *)allowed_origins->data[i])->value;
        size_t blen = buffer_string_length(b);
        if ((olen > blen ? origin->ptr[olen-blen-1] == '.' : olen == blen)
            && buffer_is_equal_right_len(origin, b, blen)) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "bsb",
                      origin, "matches allowed origin:", b);
            return 1;
        }
    }
    DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "bs",
              origin, "does not match any allowed origins");
    con->http_status = 403; /* Forbidden */
    return 0;
}

static int wstunnel_check_request(connection *con, handler_ctx *hctx) {
    const buffer * const vers =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Version"));
    const long hybivers = (NULL != vers) ? strtol(vers->ptr, NULL, 10) : 0;
    if (hybivers < 0 || hybivers > INT_MAX) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "invalid Sec-WebSocket-Version");
        con->http_status = 400; /* Bad Request */
        return -1;
    }

    /*(redundant since HTTP/1.1 required in mod_wstunnel_check_extension())*/
    if (buffer_is_empty(con->request.http_host)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "Host header does not exist");
        con->http_status = 400; /* Bad Request */
        return -1;
    }

    if (!wstunnel_is_allowed_origin(con, hctx)) {
        return -1;
    }

    return (int)hybivers;
}

static void wstunnel_backend_error(gw_handler_ctx *gwhctx) {
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    if (hctx->gw.state == GW_STATE_WRITE || hctx->gw.state == GW_STATE_READ) {
        mod_wstunnel_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, CONST_STR_LEN("1001")); /* 1001 Going Away */
    }
}

static void wstunnel_handler_ctx_free(void *gwhctx) {
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    chunk_buffer_release(hctx->frame.payload);
}

static handler_t wstunnel_handler_setup (server *srv, connection *con, plugin_data *p) {
    handler_ctx *hctx = con->plugin_ctx[p->id];
    int binary;
    int hybivers;
    hctx->srv = srv; /*(for mod_wstunnel module-specific DEBUG_LOG() macro)*/
    hctx->conf = p->conf; /*(copies struct)*/
    hybivers = wstunnel_check_request(con, hctx);
    if (hybivers < 0) return HANDLER_FINISHED;
    hctx->hybivers = hybivers;
    if (0 == hybivers) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,"s","WebSocket Version = hybi-00");
    }
    else {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO,"sd","WebSocket Version =",hybivers);
    }

    hctx->gw.opts.backend     = BACKEND_PROXY; /*(act proxy-like; not used)*/
    hctx->gw.opts.pdata       = hctx;
    hctx->gw.opts.parse       = wstunnel_recv_parse;
    hctx->gw.stdin_append     = wstunnel_stdin_append;
    hctx->gw.create_env       = wstunnel_create_env;
    hctx->gw.handler_ctx_free = wstunnel_handler_ctx_free;
    hctx->gw.backend_error    = wstunnel_backend_error;
    hctx->gw.response         = chunk_buffer_acquire();

    hctx->frame.state         = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx->frame.ctl.siz       = 0;
    hctx->frame.payload       = chunk_buffer_acquire();

    binary = !buffer_is_empty(hctx->conf.frame_type); /*("binary")*/
    if (!binary) {
        buffer *vb =
          http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Protocol"));
        if (NULL != vb) {
            for (const char *s = vb->ptr; *s; ++s) {
                while (*s==' '||*s=='\t'||*s=='\r'||*s=='\n') ++s;
                if (0 == strncasecmp(s, "binary", sizeof("binary")-1)) {
                    s += sizeof("binary")-1;
                    while (*s==' '||*s=='\t'||*s=='\r'||*s=='\n') ++s;
                    if (*s==','||*s=='\0') {
                        hctx->subproto = 1;
                        binary = 1;
                        break;
                    }
                }
                else if (0 == strncasecmp(s, "base64", sizeof("base64")-1)) {
                    s += sizeof("base64")-1;
                    while (*s==' '||*s=='\t'||*s=='\r'||*s=='\n') ++s;
                    if (*s==','||*s=='\0') {
                        hctx->subproto = -1;
                        break;
                    }
                }
                s = strchr(s, ',');
                if (NULL == s) break;
            }
        }
    }

    if (binary) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s",
                  "will recv binary data from backend");
        hctx->frame.type         = MOD_WEBSOCKET_FRAME_TYPE_BIN;
        hctx->frame.type_before  = MOD_WEBSOCKET_FRAME_TYPE_BIN;
        hctx->frame.type_backend = MOD_WEBSOCKET_FRAME_TYPE_BIN;
    }
    else {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "s",
                  "will recv text data from backend");
        hctx->frame.type         = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
        hctx->frame.type_before  = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
        hctx->frame.type_backend = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
    }

    return HANDLER_GO_ON;
}

static handler_t mod_wstunnel_check_extension(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;
    buffer *vb;
    handler_t rc;

    if (con->mode != DIRECT)
        return HANDLER_GO_ON;
    if (con->request.http_method != HTTP_METHOD_GET)
        return HANDLER_GO_ON;
    if (con->request.http_version != HTTP_VERSION_1_1)
        return HANDLER_GO_ON;

    /*
     * Connection: upgrade, keep-alive, ...
     * Upgrade: WebSocket, ...
     */
    vb = http_header_request_get(con, HTTP_HEADER_UPGRADE, CONST_STR_LEN("Upgrade"));
    if (NULL == vb
        || !header_contains_token(vb, CONST_STR_LEN("websocket")))
        return HANDLER_GO_ON;
    vb = http_header_request_get(con, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"));
    if (NULL == vb
        || !header_contains_token(vb, CONST_STR_LEN("upgrade")))
        return HANDLER_GO_ON;

    mod_wstunnel_patch_connection(srv, con, p);
    if (NULL == p->conf.gw.exts) return HANDLER_GO_ON;

    rc = gw_check_extension(srv,con,(gw_plugin_data *)p,1,sizeof(handler_ctx));
    return (HANDLER_GO_ON == rc && con->mode == p->id)
      ? wstunnel_handler_setup(srv, con, p)
      : rc;
}

TRIGGER_FUNC(mod_wstunnel_handle_trigger) {
    const plugin_data * const p = p_d;
    const time_t cur_ts = srv->cur_ts + 1;

    gw_handle_trigger(srv, p_d);

    for (size_t i = 0; i < srv->conns->used; ++i) {
        connection *con = srv->conns->ptr[i];
        handler_ctx *hctx = con->plugin_ctx[p->id];
        if (NULL == hctx || con->mode != p->id)
            continue;

        if (hctx->gw.state != GW_STATE_WRITE && hctx->gw.state != GW_STATE_READ)
            continue;

        if (cur_ts - con->read_idle_ts > con->conf.max_read_idle) {
            DEBUG_LOG(MOD_WEBSOCKET_LOG_INFO, "sds",
                      "timeout client ( fd =", con->fd, ")");
            mod_wstunnel_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, NULL, 0);
            gw_connection_reset(srv, con, p_d);
            joblist_append(srv, con);
            /* avoid server.c closing connection with error due to max_read_idle
             * (might instead run joblist after plugins_call_handle_trigger())*/
            con->read_idle_ts = cur_ts;
            continue;
        }

        if (0 != hctx->hybivers
            && hctx->conf.ping_interval > 0
            && (time_t)hctx->conf.ping_interval + hctx->ping_ts < cur_ts) {
            hctx->ping_ts = cur_ts;
            mod_wstunnel_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_PING, CONST_STR_LEN("ping"));
            joblist_append(srv, con);
            continue;
        }
    }

    return HANDLER_GO_ON;
}

int mod_wstunnel_plugin_init(plugin *p);
int mod_wstunnel_plugin_init(plugin *p) {
    p->version           = LIGHTTPD_VERSION_ID;
    p->name              = buffer_init_string("wstunnel");
    p->init              = mod_wstunnel_init;
    p->cleanup           = mod_wstunnel_free;
    p->set_defaults      = mod_wstunnel_set_defaults;
    p->connection_reset  = gw_connection_reset;
    p->handle_uri_clean  = mod_wstunnel_check_extension;
    p->handle_subrequest = gw_handle_subrequest;
    p->handle_trigger    = mod_wstunnel_handle_trigger;
    p->handle_waitpid    = gw_handle_waitpid_cb;
    p->data              = NULL;
    return 0;
}




/*
 * modified from Norio Kobota mod_websocket_handshake.c
 */

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_

#include "sys-endian.h" /* lighttpd */
#include "md5.h"        /* lighttpd */

static int get_key3(connection *con, char *buf) {
    /* 8 bytes should have been sent with request
     * for draft-ietf-hybi-thewebsocketprotocol-00 */
    chunkqueue *cq = con->request_content_queue;
    size_t bytes = 8;
    /*(caller should ensure bytes available prior to calling this routine)*/
    /*assert(chunkqueue_length(cq) >= 8);*/
    for (chunk *c = cq->first; NULL != c; c = c->next) {
        /*(chunk_remaining_length() on MEM_CHUNK)*/
        size_t n = (size_t)(buffer_string_length(c->mem) - c->offset);
        /*(expecting 8 bytes to be in memory directly after headers)*/
        if (c->type != MEM_CHUNK) break; /* FILE_CHUNK not handled here */
        if (n > bytes) n = bytes;
        memcpy(buf, c->mem->ptr+c->offset, n);
        buf += n;
        if (0 == (bytes -= n)) break;
    }
    if (0 != bytes) return -1;
    chunkqueue_mark_written(cq, 8);
    return 0;
}

static int get_key_number(uint32_t *ret, const buffer *b) {
    const char * const s = b->ptr;
    size_t j = 0;
    unsigned long n;
    uint32_t sp = 0;
    char tmp[10 + 1]; /* #define UINT32_MAX_STRLEN 10 */

    for (size_t i = 0, used = buffer_string_length(b); i < used; ++i) {
        if (light_isdigit(s[i])) {
            tmp[j] = s[i];
            if (++j >= sizeof(tmp)) return -1;
        }
        else if (s[i] == ' ') ++sp; /* count num spaces */
    }
    tmp[j] = '\0';
    n = strtoul(tmp, NULL, 10);
    if (n > UINT32_MAX || 0 == sp) return -1;
    *ret = (uint32_t)n / sp;
    return 0;
}

static int create_MD5_sum(connection *con) {
    uint32_t buf[4]; /* MD5 binary hash len */
    li_MD5_CTX ctx;

    const buffer *key1 =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Key1"));
    const buffer *key2 =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Key2"));

    if (NULL == key1 || get_key_number(buf+0, key1) < 0 ||
        NULL == key2 || get_key_number(buf+1, key2) < 0 ||
        get_key3(con, (char *)(buf+2)) < 0) {
        return -1;
    }
  #ifdef __BIG_ENDIAN__
  #define ws_htole32(s,u)\
    (s)[0]=((u)>>24);    \
    (s)[1]=((u)>>16);    \
    (s)[2]=((u)>>8);     \
    (s)[3]=((u))
    ws_htole32((unsigned char *)(buf+0), buf[0]);
    ws_htole32((unsigned char *)(buf+1), buf[1]);
  #endif
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, buf, sizeof(buf));
    li_MD5_Final((unsigned char *)buf, &ctx); /*(overwrite buf[] with result)*/
    chunkqueue_append_mem(con->write_queue, (char *)buf, sizeof(buf));
    return 0;
}

static int create_response_ietf_00(handler_ctx *hctx) {
    connection *con = hctx->gw.remote_conn;
    buffer *value = hctx->srv->tmp_buf;

    /* "Origin" header is preferred
     * ("Sec-WebSocket-Origin" is from older drafts of websocket spec) */
    buffer *origin = http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Origin"));
    if (NULL == origin) {
        origin =
          http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Origin"));
    }
    if (NULL == origin) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "Origin header is invalid");
        return -1;
    }
    if (buffer_is_empty(con->request.http_host)) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "Host header does not exist");
        return -1;
    }

    /* calc MD5 sum from keys */
    if (create_MD5_sum(con) < 0) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "Sec-WebSocket-Key is invalid");
        return -1;
    }

    http_header_response_set(con, HTTP_HEADER_UPGRADE,
                             CONST_STR_LEN("Upgrade"),
                             CONST_STR_LEN("websocket"));
  #if 0 /*(added later in http_response_write_header())*/
    http_header_response_append(con, HTTP_HEADER_CONNECTION,
                                CONST_STR_LEN("Connection"),
                                CONST_STR_LEN("upgrade"));
  #endif
  #if 0 /*(Sec-WebSocket-Origin header is not required for hybi-00)*/
    /* Note: it is insecure to simply reflect back origin provided by client
     * (if admin did not configure restricted list of valid origins)
     * (see wstunnel_check_request()) */
    http_header_response_set(con, HTTP_HEADER_OTHER,
                             CONST_STR_LEN("Sec-WebSocket-Origin"),
                             CONST_BUF_LEN(origin));
  #endif

    if (buffer_is_equal_string(con->uri.scheme, CONST_STR_LEN("https")))
        buffer_copy_string_len(value, CONST_STR_LEN("wss://"));
    else
        buffer_copy_string_len(value, CONST_STR_LEN("ws://"));
    buffer_append_string_buffer(value, con->request.http_host);
    buffer_append_string_buffer(value, con->uri.path);
    http_header_response_set(con, HTTP_HEADER_OTHER,
                             CONST_STR_LEN("Sec-WebSocket-Location"),
                             CONST_BUF_LEN(value));

    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */


#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_

#include "algo_sha1.h"  /* lighttpd */
#include "base64.h"     /* lighttpd */

static int create_response_rfc_6455(handler_ctx *hctx) {
    connection *con = hctx->gw.remote_conn;
    SHA_CTX sha;
    unsigned char sha_digest[SHA_DIGEST_LENGTH];

    buffer *value =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Key"));
    if (NULL == value) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "Sec-WebSocket-Key is invalid");
        return -1;
    }

    /* get SHA1 hash of key */
    /* refer: RFC-6455 Sec.1.3 Opening Handshake */
    SHA1_Init(&sha);
    SHA1_Update(&sha, (const unsigned char *)CONST_BUF_LEN(value));
    SHA1_Update(&sha, (const unsigned char *)CONST_STR_LEN("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
    SHA1_Final(sha_digest, &sha);

    http_header_response_set(con, HTTP_HEADER_UPGRADE,
                             CONST_STR_LEN("Upgrade"),
                             CONST_STR_LEN("websocket"));
  #if 0 /*(added later in http_response_write_header())*/
    http_header_response_append(con, HTTP_HEADER_CONNECTION,
                                CONST_STR_LEN("Connection"),
                                CONST_STR_LEN("upgrade"));
  #endif

    value = hctx->srv->tmp_buf;
    buffer_clear(value);
    buffer_append_base64_encode(value, sha_digest, SHA_DIGEST_LENGTH, BASE64_STANDARD);
    http_header_response_set(con, HTTP_HEADER_OTHER,
                             CONST_STR_LEN("Sec-WebSocket-Accept"),
                             CONST_BUF_LEN(value));

    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_BIN)
        http_header_response_set(con, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Sec-WebSocket-Protocol"),
                                 CONST_STR_LEN("binary"));
    else if (-1 == hctx->subproto)
        http_header_response_set(con, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Sec-WebSocket-Protocol"),
                                 CONST_STR_LEN("base64"));

    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */


handler_t mod_wstunnel_handshake_create_response(handler_ctx *hctx) {
    connection *con = hctx->gw.remote_conn;
  #ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->hybivers >= 8) {
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "send handshake response");
        if (0 != create_response_rfc_6455(hctx)) {
            con->http_status = 400; /* Bad Request */
            return HANDLER_ERROR;
        }
        return HANDLER_GO_ON;
    }
  #endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (hctx->hybivers == 0) {
      #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
        /* 8 bytes should have been sent with request
         * for draft-ietf-hybi-thewebsocketprotocol-00 */
        chunkqueue *cq = con->request_content_queue;
        if (chunkqueue_length(cq) < 8)
            return HANDLER_WAIT_FOR_EVENT;
      #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */

        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "send handshake response");
        if (0 != create_response_ietf_00(hctx)) {
            con->http_status = 400; /* Bad Request */
            return HANDLER_ERROR;
        }
        return HANDLER_GO_ON;
    }
  #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */

    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "not supported WebSocket Version");
    con->http_status = 503; /* Service Unavailable */
    return HANDLER_ERROR;
}




/*
 * modified from Norio Kobota mod_websocket_frame.c
 */

#include "base64.h"     /* lighttpd */
#include "http_chunk.h" /* lighttpd */

#define MOD_WEBSOCKET_BUFMAX (0x0fffff)

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_

#include <stdlib.h>
static int send_ietf_00(handler_ctx *hctx, mod_wstunnel_frame_type_t type, const char *payload, size_t siz) {
    static const char head =  0; /* 0x00 */
    static const char tail = ~0; /* 0xff */
    server *srv = hctx->srv;
    connection *con = hctx->gw.remote_conn;
    char *mem;
    size_t len;

    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        if (0 == siz) return 0;
        http_chunk_append_mem(srv, con, &head, 1);
        http_chunk_append_mem(srv, con, payload, siz);
        http_chunk_append_mem(srv, con, &tail, 1);
        len = siz+2;
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        if (0 == siz) return 0;
        http_chunk_append_mem(srv, con, &head, 1);
        len = 4*(siz/3)+4+1;
        /* avoid accumulating too much data in memory; send to tmpfile */
        mem = malloc(len);
        force_assert(mem);
        len=li_to_base64(mem,len,(unsigned char *)payload,siz,BASE64_STANDARD);
        http_chunk_append_mem(srv, con, mem, len);
        free(mem);
        http_chunk_append_mem(srv, con, &tail, 1);
        len += 2;
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
        http_chunk_append_mem(srv, con, &tail, 1);
        http_chunk_append_mem(srv, con, &head, 1);
        len = 2;
        break;
    default:
        DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "invalid frame type");
        return -1;
    }
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "send data to client ( fd =", con->fd, "), frame size =", len);
    return 0;
}

static int recv_ietf_00(handler_ctx *hctx) {
    connection *con = hctx->gw.remote_conn;
    chunkqueue *cq = con->request_content_queue;
    buffer *payload = hctx->frame.payload;
    char *mem;
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "recv data from client ( fd =", con->fd,
              "), size =", chunkqueue_length(cq));
    for (chunk *c = cq->first; c; c = c->next) {
        char *frame = c->mem->ptr+c->offset;
        /*(chunk_remaining_length() on MEM_CHUNK)*/
        size_t flen = (size_t)(buffer_string_length(c->mem) - c->offset);
        /*(FILE_CHUNK not handled, but might need to add support)*/
        force_assert(c->type == MEM_CHUNK);
        for (size_t i = 0; i < flen; ) {
            switch (hctx->frame.state) {
            case MOD_WEBSOCKET_FRAME_STATE_INIT:
                hctx->frame.ctl.siz = 0;
                if (frame[i] == 0x00) {
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                    i++;
                }
                else if (((unsigned char *)frame)[i] == 0xff) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,"s","recv close frame");
                    return -1;
                }
                else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG,"s","recv invalid frame");
                    return -1;
                }
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
                mem = (char *)memchr(frame+i, 0xff, flen - i);
                if (mem == NULL) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "got continuous payload, size =", flen - i);
                    hctx->frame.ctl.siz += flen - i;
                    if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN, "sx",
                                  "frame size has been exceeded:",
                                  MOD_WEBSOCKET_BUFMAX);
                        return -1;
                    }
                    buffer_append_string_len(payload, frame+i, flen - i);
                    i += flen - i;
                }
                else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "got final payload, size =", (mem - frame+i));
                    hctx->frame.ctl.siz += (mem - frame+i);
                    if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN, "sx",
                                  "frame size has been exceeded:",
                                  MOD_WEBSOCKET_BUFMAX);
                        return -1;
                    }
                    buffer_append_string_len(payload, frame+i, mem - frame+i);
                    i += (mem - frame+i);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                }
                i++;
                if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT
                    && !buffer_is_empty(payload)) {
                    hctx->frame.ctl.siz = 0;
                    chunkqueue_append_buffer(hctx->gw.wb, payload);
                    buffer_clear(payload);
                }
                else {
                    if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT
                        && !buffer_is_empty(payload)) {
                        buffer *b;
                        size_t len = buffer_string_length(payload);
                        len = (len+3)/4*3+1;
                        chunkqueue_get_memory(hctx->gw.wb, &len);
                        b = hctx->gw.wb->last->mem;
                        len = buffer_string_length(b);
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "ss",
                                  "try to base64 decode:", payload->ptr);
                        if (NULL == buffer_append_base64_decode(b, CONST_BUF_LEN(payload), BASE64_STANDARD)) {
                            DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s",
                                      "fail to base64-decode");
                            return -1;
                        }
                        buffer_clear(payload);
                        /*chunkqueue_use_memory()*/
                        hctx->gw.wb->bytes_in += buffer_string_length(b)-len;
                    }
                }
                break;
            default: /* never reach */
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR,"s", "BUG: unknown state");
                return -1;
            }
        }
    }
    /* XXX: should add ability to handle and preserve partial frames above */
    /*(not chunkqueue_reset(); do not reset cq->bytes_in, cq->bytes_out)*/
    chunkqueue_mark_written(cq, chunkqueue_length(cq));
    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */


#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_

#define MOD_WEBSOCKET_OPCODE_CONT   0x00
#define MOD_WEBSOCKET_OPCODE_TEXT   0x01
#define MOD_WEBSOCKET_OPCODE_BIN    0x02
#define MOD_WEBSOCKET_OPCODE_CLOSE  0x08
#define MOD_WEBSOCKET_OPCODE_PING   0x09
#define MOD_WEBSOCKET_OPCODE_PONG   0x0A

#define MOD_WEBSOCKET_FRAME_LEN16   0x7E
#define MOD_WEBSOCKET_FRAME_LEN63   0x7F
#define MOD_WEBSOCKET_FRAME_LEN16_CNT  2
#define MOD_WEBSOCKET_FRAME_LEN63_CNT  8

static int send_rfc_6455(handler_ctx *hctx, mod_wstunnel_frame_type_t type, const char *payload, size_t siz) {
    server *srv = hctx->srv;
    connection *con = hctx->gw.remote_conn;
    char mem[10];
    size_t len;

    /* allowed null payload for ping, pong, close frame */
    if (payload == NULL && (   type == MOD_WEBSOCKET_FRAME_TYPE_TEXT
                            || type == MOD_WEBSOCKET_FRAME_TYPE_BIN   )) {
        return -1;
    }

    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        mem[0] = (char)(0x80 | MOD_WEBSOCKET_OPCODE_TEXT);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = text");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        mem[0] = (char)(0x80 | MOD_WEBSOCKET_OPCODE_BIN);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = binary");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PING:
        mem[0] = (char) (0x80 | MOD_WEBSOCKET_OPCODE_PING);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = ping");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_PONG:
        mem[0] = (char)(0x80 | MOD_WEBSOCKET_OPCODE_PONG);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = pong");
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
    default:
        mem[0] = (char)(0x80 | MOD_WEBSOCKET_OPCODE_CLOSE);
        DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = close");
        break;
    }

    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx", "payload size =", siz);
    if (siz < MOD_WEBSOCKET_FRAME_LEN16) {
        mem[1] = siz;
        len = 2;
    }
    else if (siz <= UINT16_MAX) {
        mem[1] = MOD_WEBSOCKET_FRAME_LEN16;
        mem[2] = (siz >> 8) & 0xff;
        mem[3] = siz & 0xff;
        len = 1+MOD_WEBSOCKET_FRAME_LEN16_CNT+1;
    }
    else {
        mem[1] = MOD_WEBSOCKET_FRAME_LEN63;
        mem[2] = 0;
        mem[3] = 0;
        mem[4] = 0;
        mem[5] = 0;
        mem[6] = (siz >> 24) & 0xff;
        mem[7] = (siz >> 16) & 0xff;
        mem[8] = (siz >> 8) & 0xff;
        mem[9] = siz & 0xff;
        len = 1+MOD_WEBSOCKET_FRAME_LEN63_CNT+1;
    }
    http_chunk_append_mem(srv, con, mem, len);
    if (siz) http_chunk_append_mem(srv, con, payload, siz);
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "send data to client ( fd =",con->fd,"), frame size =",len+siz);
    return 0;
}

static void unmask_payload(handler_ctx *hctx) {
    buffer * const b = hctx->frame.payload;
    for (size_t i = 0, used = buffer_string_length(b); i < used; ++i) {
        b->ptr[i] ^= hctx->frame.ctl.mask[hctx->frame.ctl.mask_cnt];
        hctx->frame.ctl.mask_cnt = (hctx->frame.ctl.mask_cnt + 1) % 4;
    }
}

static int recv_rfc_6455(handler_ctx *hctx) {
    connection *con = hctx->gw.remote_conn;
    chunkqueue *cq = con->request_content_queue;
    buffer *payload = hctx->frame.payload;
    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sdsx",
              "recv data from client ( fd =", con->fd,
              "), size =", chunkqueue_length(cq));
    for (chunk *c = cq->first; c; c = c->next) {
        char *frame = c->mem->ptr+c->offset;
        /*(chunk_remaining_length() on MEM_CHUNK)*/
        size_t flen = (size_t)(buffer_string_length(c->mem) - c->offset);
        /*(FILE_CHUNK not handled, but might need to add support)*/
        force_assert(c->type == MEM_CHUNK);
        for (size_t i = 0; i < flen; ) {
            switch (hctx->frame.state) {
            case MOD_WEBSOCKET_FRAME_STATE_INIT:
                switch (frame[i] & 0x0f) {
                case MOD_WEBSOCKET_OPCODE_CONT:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = continue");
                    hctx->frame.type = hctx->frame.type_before;
                    break;
                case MOD_WEBSOCKET_OPCODE_TEXT:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = text");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
                    hctx->frame.type_before = hctx->frame.type;
                    break;
                case MOD_WEBSOCKET_OPCODE_BIN:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = binary");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_BIN;
                    hctx->frame.type_before = hctx->frame.type;
                    break;
                case MOD_WEBSOCKET_OPCODE_PING:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = ping");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_PING;
                    break;
                case MOD_WEBSOCKET_OPCODE_PONG:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = pong");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_PONG;
                    break;
                case MOD_WEBSOCKET_OPCODE_CLOSE:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "s", "type = close");
                    hctx->frame.type = MOD_WEBSOCKET_FRAME_TYPE_CLOSE;
                    return -1;
                    break;
                default:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "type is invalid");
                    return -1;
                    break;
                }
                i++;
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_LENGTH:
                if ((frame[i] & 0x80) != 0x80) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s",
                              "payload was not masked");
                    return -1;
                }
                hctx->frame.ctl.mask_cnt = 0;
                hctx->frame.ctl.siz = (uint64_t)(frame[i] & 0x7f);
                if (hctx->frame.ctl.siz == 0) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "specified payload size =", hctx->frame.ctl.siz);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                }
                else if (hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN16) {
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.ctl.siz_cnt = MOD_WEBSOCKET_FRAME_LEN16_CNT;
                    hctx->frame.state =
                        MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH;
                }
                else if (hctx->frame.ctl.siz == MOD_WEBSOCKET_FRAME_LEN63) {
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.ctl.siz_cnt = MOD_WEBSOCKET_FRAME_LEN63_CNT;
                    hctx->frame.state =
                        MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH;
                }
                else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "specified payload size =", hctx->frame.ctl.siz);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH:
                hctx->frame.ctl.siz =
                    (hctx->frame.ctl.siz << 8) + (frame[i] & 0xff);
                hctx->frame.ctl.siz_cnt--;
                if (hctx->frame.ctl.siz_cnt <= 0) {
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING &&
                        hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX) {
                        DEBUG_LOG(MOD_WEBSOCKET_LOG_WARN, "sx",
                                  "frame size has been exceeded:",
                                  MOD_WEBSOCKET_BUFMAX);
                        return -1;
                    }
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "specified payload size =", hctx->frame.ctl.siz);
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_MASK:
                hctx->frame.ctl.mask[hctx->frame.ctl.mask_cnt] = frame[i];
                hctx->frame.ctl.mask_cnt++;
                if (hctx->frame.ctl.mask_cnt >= MOD_WEBSOCKET_MASK_CNT) {
                    hctx->frame.ctl.mask_cnt = 0;
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING &&
                        hctx->frame.ctl.siz == 0) {
                        mod_wstunnel_frame_send(hctx,
                                                MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                                NULL, 0);
                    }
                    if (hctx->frame.ctl.siz == 0) {
                        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    }
                    else {
                        hctx->frame.state =
                            MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                    }
                }
                i++;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
                /* hctx->frame.ctl.siz <= SIZE_MAX */
                if (hctx->frame.ctl.siz <= flen - i) {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "read payload, size =", hctx->frame.ctl.siz);
                    buffer_append_string_len(payload, frame+i, (size_t)
                                             (hctx->frame.ctl.siz & SIZE_MAX));
                    i += (size_t)(hctx->frame.ctl.siz & SIZE_MAX);
                    hctx->frame.ctl.siz = 0;
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "rest of frame size =", flen - i);
                /* SIZE_MAX < hctx->frame.ctl.siz */
                }
                else {
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "read payload, size =", flen - i);
                    buffer_append_string_len(payload, frame+i, flen - i);
                    hctx->frame.ctl.siz -= flen - i;
                    i += flen - i;
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_DEBUG, "sx",
                              "rest of payload size =", hctx->frame.ctl.siz);
                }
                switch (hctx->frame.type) {
                case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
                case MOD_WEBSOCKET_FRAME_TYPE_BIN:
                  {
                    unmask_payload(hctx);
                    chunkqueue_append_buffer(hctx->gw.wb, payload);
                    buffer_clear(payload);
                    break;
                  }
                case MOD_WEBSOCKET_FRAME_TYPE_PING:
                    if (hctx->frame.ctl.siz == 0) {
                        unmask_payload(hctx);
                        mod_wstunnel_frame_send(hctx,
                          MOD_WEBSOCKET_FRAME_TYPE_PONG,
                          payload->ptr, buffer_string_length(payload));
                        buffer_clear(payload);
                    }
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_PONG:
                    buffer_clear(payload);
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
                default:
                    DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s",
                              "BUG: invalid frame type");
                    return -1;
                }
                break;
            default:
                DEBUG_LOG(MOD_WEBSOCKET_LOG_ERR, "s", "BUG: invalid state");
                return -1;
            }
        }
    }
    /* XXX: should add ability to handle and preserve partial frames above */
    /*(not chunkqueue_reset(); do not reset cq->bytes_in, cq->bytes_out)*/
    chunkqueue_mark_written(cq, chunkqueue_length(cq));
    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */


int mod_wstunnel_frame_send(handler_ctx *hctx, mod_wstunnel_frame_type_t type,
                             const char *payload, size_t siz) {
  #ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->hybivers >= 8) return send_rfc_6455(hctx, type, payload, siz);
  #endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (0 == hctx->hybivers) return send_ietf_00(hctx, type, payload, siz);
  #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */
    return -1;
}

int mod_wstunnel_frame_recv(handler_ctx *hctx) {
  #ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->hybivers >= 8) return recv_rfc_6455(hctx);
  #endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (0 == hctx->hybivers) return recv_ietf_00(hctx);
  #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */
    return -1;
}
