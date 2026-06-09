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
 * If mod_wstunnel is first to send websocket CLOSE frame, mod_wstunnel calls
 * shutdown(fd, SHUT_WR) for HTTP/1.1 without waiting to receive websocket CLOSE
 * frame from client.  lighttpd continues to read and discard data from HTTP/1.1
 * client for a short time before calling close() on the HTTP/1.1 client socket,
 * but does not parse for websocket CLOSE frame from client.  (RFC6455 suggests
 * waiting to receive websocket CLOSE frame from peer before socket shutdown.)
 *
 * References:
 *   https://en.wikipedia.org/wiki/WebSocket
 *   https://tools.ietf.org/html/rfc6455
 *   https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-00
 */
#include "first.h"

#include <sys/types.h>
#include <limits.h>
#include <string.h>

#include "gw_backend.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"
#include "http_header.h"
#include "http_status.h"
#include "log.h"

#define MOD_WEBSOCKET_LOG_NONE  0
#define MOD_WEBSOCKET_LOG_ERR   1
#define MOD_WEBSOCKET_LOG_WARN  2
#define MOD_WEBSOCKET_LOG_INFO  3
#define MOD_WEBSOCKET_LOG_DEBUG 4

#define DEBUG_LOG_ERR(format, ...) \
  if (hctx->gw.conf.debug >= MOD_WEBSOCKET_LOG_ERR) { log_error(hctx->gw.r->conf.errh, __FILE__, __LINE__, (format), __VA_ARGS__); }

#define DEBUG_LOG_WARN(format, ...) \
  if (hctx->gw.conf.debug >= MOD_WEBSOCKET_LOG_WARN) { log_warn(hctx->gw.r->conf.errh, __FILE__, __LINE__, (format), __VA_ARGS__); }

#define DEBUG_LOG_INFO(format, ...) \
  if (hctx->gw.conf.debug >= MOD_WEBSOCKET_LOG_INFO) { log_info(hctx->gw.r->conf.errh, __FILE__, __LINE__, (format), __VA_ARGS__); }

#define DEBUG_LOG_DEBUG(format, ...) \
  if (hctx->gw.conf.debug >= MOD_WEBSOCKET_LOG_DEBUG) { log_debug(hctx->gw.r->conf.errh, __FILE__, __LINE__, (format), __VA_ARGS__); }

typedef struct {
    gw_plugin_config gw; /* start must match layout of gw_plugin_config */
    const array *origins;
    unsigned int frame_type;
    unsigned short int ping_interval;
} plugin_config;

typedef struct plugin_data {
    PLUGIN_DATA;
    pid_t srv_pid; /* must match layout of gw_plugin_data to defaults member */
    plugin_config defaults;
} plugin_data;

typedef enum {
    MOD_WEBSOCKET_FRAME_STATE_INIT,

    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
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

/* map mod_wstunnel_frame_type_t to string */
static const char * const mod_wstunnel_frame_type_str[] = {
  "text", "binary", "close", "ping", "pong"
};

typedef struct {
    uint64_t siz;

    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
    uint32_t mask_off;
    #define MOD_WEBSOCKET_MASK_CNT 4
    unsigned char mask[MOD_WEBSOCKET_MASK_CNT];
    /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

} mod_wstunnel_frame_control_t;

typedef struct {
    int8_t state;
    int8_t type, type_cont, type_backend; /* mod_wstunnel_frame_type_t */
    mod_wstunnel_frame_control_t ctl;
    buffer *payload;
} mod_wstunnel_frame_t;

typedef struct {
    gw_handler_ctx gw;
    mod_wstunnel_frame_t frame;

    int hybivers;
    int subproto;
    unix_time64_t ping_ts;

    plugin_config conf;
} handler_ctx;

/* prototypes */
static handler_t mod_wstunnel_handshake_create_response(handler_ctx *);
static int mod_wstunnel_frame_send(handler_ctx *, mod_wstunnel_frame_type_t, const char *, size_t);
static int mod_wstunnel_frame_recv(handler_ctx *);
/*#define _MOD_WEBSOCKET_SPEC_IETF_00_*/   /* obsolete */
#define _MOD_WEBSOCKET_SPEC_RFC_6455_

INIT_FUNC(mod_wstunnel_init);
SETDEFAULTS_FUNC(mod_wstunnel_set_defaults);
REQUEST_FUNC(mod_wstunnel_check_extension);
TRIGGER_FUNC(mod_wstunnel_handle_trigger);

static const plugin mod_wstunnel_plugin = {
  .name                         = "wstunnel",
  .version                      = LIGHTTPD_VERSION_ID,
  .init                         = mod_wstunnel_init,
  .cleanup                      = gw_free,
  .set_defaults                 = mod_wstunnel_set_defaults,
  .handle_uri_clean             = mod_wstunnel_check_extension,
  .handle_subrequest            = gw_handle_subrequest,
  .handle_request_reset         = gw_handle_request_reset,
  .handle_trigger               = mod_wstunnel_handle_trigger,
  .handle_waitpid               = gw_handle_waitpid_cb
};

INIT_FUNC(mod_wstunnel_init) {
    plugin_data * const pd = ck_calloc(1, sizeof(plugin_data));
    pd->self = &mod_wstunnel_plugin;
    return pd;
}

__attribute_cold__
__declspec_dllexport__
int mod_wstunnel_plugin_init(plugin *p);
int mod_wstunnel_plugin_init(plugin *p) {
    memcpy(p, &mod_wstunnel_plugin, sizeof(plugin));
    return 0;
}

static void mod_wstunnel_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* wstunnel.server */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            gw_plugin_config * const gw = cpv->v.v;
            pconf->gw.exts      = gw->exts;
            pconf->gw.exts_auth = gw->exts_auth;
            pconf->gw.exts_resp = gw->exts_resp;
        }
        break;
      case 1: /* wstunnel.balance */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->gw.balance = (int)cpv->v.u;
        break;
      case 2: /* wstunnel.debug */
        pconf->gw.debug = (int)cpv->v.u;
        break;
      case 3: /* wstunnel.map-extensions */
        pconf->gw.ext_mapping = cpv->v.a;
        break;
      case 4: /* wstunnel.frame-type */
        pconf->frame_type = cpv->v.u;
        break;
      case 5: /* wstunnel.origins */
        pconf->origins = cpv->v.a;
        break;
      case 6: /* wstunnel.ping-interval */
        pconf->ping_interval = cpv->v.shrt;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_wstunnel_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_wstunnel_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_wstunnel_patch_config(request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_wstunnel_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_wstunnel_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("wstunnel.server"),
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("wstunnel.balance"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("wstunnel.debug"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("wstunnel.map-extensions"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("wstunnel.frame-type"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("wstunnel.origins"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("wstunnel.ping-interval"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_wstunnel"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        gw_plugin_config *gw = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* wstunnel.server */
                gw = ck_calloc(1, sizeof(gw_plugin_config));
                if (!gw_set_defaults_backend(srv, (gw_plugin_data *)p, cpv->v.a,
                                             gw, 0, cpk[cpv->k_id].k)) {
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                /* error if "mode" = "authorizer";
                 * wstunnel can not act as authorizer */
                /*(check after gw_set_defaults_backend())*/
                if (gw->exts_auth && gw->exts_auth->used) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s must not define any hosts with "
                      "attribute \"mode\" = \"authorizer\"", cpk[cpv->k_id].k);
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                cpv->v.v = gw;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* wstunnel.balance */
                cpv->v.u = (unsigned int)gw_get_defaults_balance(srv, cpv->v.b);
                break;
              case 2: /* wstunnel.debug */
              case 3: /* wstunnel.map-extensions */
                break;
              case 4: /* wstunnel.frame-type */
                /*(default frame-type to "text" unless "binary" is specified)*/
                cpv->v.u =
                  buffer_eq_icase_slen(cpv->v.b, CONST_STR_LEN("binary"));
                break;
              case 5: /* wstunnel.origins */
                for (uint32_t j = 0; j < cpv->v.a->used; ++j) {
                    buffer *origin = &((data_string *)cpv->v.a->data[j])->value;
                    if (buffer_is_blank(origin)) {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "unexpected empty string in %s", cpk[cpv->k_id].k);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 6: /* wstunnel.ping-interval */
                break;
              default:/* should not happen */
                break;
            }
        }

        /* disable check-local for all exts (default enabled) */
        if (gw && gw->exts) { /*(check after gw_set_defaults_backend())*/
            gw_exts_clear_check_local(gw->exts);
        }
    }

    /* default is 0 */
    /*p->defaults.balance = (unsigned int)gw_get_defaults_balance(srv, NULL);*/
    p->defaults.ping_interval = 0; /* do not send ping */

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_wstunnel_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static handler_t wstunnel_create_env(gw_handler_ctx *gwhctx) {
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    request_st * const r = hctx->gw.r;
    handler_t rc;
    if (0 != r->reqbody_length && r->http_version == HTTP_VERSION_1_1) {
        /* Defer reading websocket protocol from HTTP/1.1 client until
         * request body has been received, and then discarded.
         * mod_wstunnel_check_extension() requires GET method for HTTP/1.1
         * so (r->conf.http_parseopts & HTTP_PARSEOPT_METHOD_GET_BODY) if
         * r->reqbody_length, which is not the default config */
        if (r->state == CON_STATE_READ_POST) {
            r->conf.stream_request_body &=
              ~(FDEVENT_STREAM_REQUEST | FDEVENT_STREAM_REQUEST_BUFMIN);
            rc = r->con->reqbody_read(r);
            if (rc != HANDLER_GO_ON) return rc;
        }
        chunkqueue_mark_written(&r->reqbody_queue, r->reqbody_length);
    }
    http_response_upgrade_read_body_unknown(r);
    chunkqueue_append_chunkqueue(&r->reqbody_queue, &r->read_queue);
    rc = mod_wstunnel_handshake_create_response(hctx);
    if (rc != HANDLER_GO_ON) return rc;

    r->http_status = (r->http_version > HTTP_VERSION_1_1)
      ? 200  /* OK (response status for CONNECT) */
      : 101; /* Switching Protocols */
    r->resp_body_started = 1;

    hctx->ping_ts = log_monotonic_secs;
    gw_set_transparent(&hctx->gw);

    return HANDLER_GO_ON;
}

static handler_t wstunnel_stdin_append(gw_handler_ctx *gwhctx) {
    /* prepare websocket frames to backend */
    /* (caller should verify r->reqbody_queue) */
    /*assert(!chunkqueue_is_empty(&r->reqbody_queue));*/
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    if (0 == mod_wstunnel_frame_recv(hctx))
        return HANDLER_GO_ON;
    else {
        gw_handle_request_reset(hctx->gw.r, hctx->gw.plugin_data);
        return HANDLER_FINISHED;
    }
}

static handler_t wstunnel_recv_parse(request_st * const r, http_response_opts * const opts, buffer * const b, size_t n) {
    handler_ctx *hctx = (handler_ctx *)opts->pdata;
    if (0 == n) return HANDLER_FINISHED;
    if (mod_wstunnel_frame_send(hctx, hctx->frame.type_backend, b->ptr, n) < 0)
        return HANDLER_ERROR;
    buffer_clear(b);
    UNUSED(r);
    return HANDLER_GO_ON;
}

__attribute_cold__
__attribute_noinline__
static int
wstunnel_err (handler_ctx * const hctx, unsigned short wstatus, const char *err) {
    if (err)
        DEBUG_LOG_ERR("%s", err);
    if (wstatus) {
        char code[2] = { (char)(wstatus >> 8), (char)(wstatus & 0xff) };
        hctx->subproto = wstatus; /* overload to flag CLOSE; wstatus >= 1000 */
        mod_wstunnel_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_CLOSE, code, 2);
    }
    return -1;
}

static int wstunnel_is_allowed_origin(request_st * const r, handler_ctx * const hctx) {
    /* If allowed origins is set (and not empty list), fail closed if no match.
     * Note that origin provided in request header has not been normalized, so
     * change in case or other non-normal forms might not match allowed list */
    const array * const allowed_origins = hctx->conf.origins;
    const buffer *origin = NULL;
    size_t olen;

    if (NULL == allowed_origins || 0 == allowed_origins->used)
        return 0;

    /* "Origin" header is preferred
     * ("Sec-WebSocket-Origin" is from older drafts of websocket spec <= 10) */
    origin = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Origin"));
  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (NULL == origin) {
        origin =
          http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Origin"));
    }
  #endif
    olen = origin ? buffer_clen(origin) : 0;
    if (0 == olen) {
        wstunnel_err(hctx, 0, "Origin header is invalid");
        return 400; /* Bad Request */
    }

    for (size_t i = 0; i < allowed_origins->used; ++i) {
        buffer *b = &((data_string *)allowed_origins->data[i])->value;
        size_t blen = buffer_clen(b);
        if ((olen > blen ? origin->ptr[olen-blen-1] == '.' : olen == blen)
            && 0 == memcmp(origin->ptr+olen-blen, b->ptr, blen)) {
            return 0;
        }
    }
    DEBUG_LOG_INFO("%s does not match any allowed origins", origin->ptr);
    return 403; /* Forbidden */
}

static int wstunnel_check_request(request_st * const r, handler_ctx * const hctx) {
    /*(redundant since HTTP/1.1 required in mod_wstunnel_check_extension())*/
    if (!r->http_host || buffer_is_blank(r->http_host))
        return 400; /* Bad Request */

    return wstunnel_is_allowed_origin(r, hctx);
}

static void wstunnel_backend_error(gw_handler_ctx *gwhctx) {
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    if (hctx->gw.state == GW_STATE_WRITE || hctx->gw.state == GW_STATE_READ)
        wstunnel_err(hctx, 1011, NULL); /* Internal Server Error */
}

static void wstunnel_handler_ctx_free(void *gwhctx) {
    handler_ctx *hctx = (handler_ctx *)gwhctx;
    if (hctx->subproto < 1000 /*(overloaded; CLOSE not yet sent)*/
           /* CON_STATE_HANDLE_REQUEST || CON_STATE_WRITE */
        && hctx->gw.r->state < CON_STATE_RESPONSE_END /*!RESPONSE_END,!ERROR*/
        && (gw_plugin_data *)hctx->gw.r->handler_module
             == hctx->gw.plugin_data /*(needed?)*/
        && (   hctx->gw.state == GW_STATE_WRITE
            || hctx->gw.state == GW_STATE_READ   )) {
        wstunnel_err(hctx, 1001, NULL);
    }
    chunk_buffer_release(hctx->frame.payload);
}

static handler_t wstunnel_handler_setup (request_st * const r, handler_ctx * const hctx, const plugin_config * const pconf) {
    memcpy(&hctx->conf, pconf, sizeof(plugin_config));

    int status = wstunnel_check_request(r, hctx);
    if (status)
        return http_status_set_err(r, status);

    const buffer *vers =
      http_header_request_get(r, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Sec-WebSocket-Version"));
    hctx->hybivers = -1;
    if (vers) {
        const char *err;
        const int64_t hybivers =
          li_restricted_strtoint64(BUF_PTR_LEN(vers), &err);
        if (hybivers == 13 && err == vers->ptr+buffer_clen(vers))
            hctx->hybivers = (int)hybivers;
    }
  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    else
        hctx->hybivers = 0;
  #endif
    if (hctx->hybivers < 0) {
        http_header_response_set(r, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Sec-WebSocket-Version"),
                                 CONST_STR_LEN("13"));
        wstunnel_err(hctx, 0, "invalid Sec-WebSocket-Version");
        return http_status_set_err(r, 400); /* Bad Request */
    }
    DEBUG_LOG_INFO("WebSocket Version = %d", hctx->hybivers);

    hctx->gw.opts.backend     = BACKEND_PROXY; /*(act proxy-like)*/
    hctx->gw.opts.pdata       = hctx;
    hctx->gw.opts.headers     = 0; /*(should not be necessary to unset)*/
    hctx->gw.opts.parse       = wstunnel_recv_parse;
    hctx->gw.stdin_append     = wstunnel_stdin_append;
    hctx->gw.create_env       = wstunnel_create_env;
    hctx->gw.handler_ctx_free = wstunnel_handler_ctx_free;
    hctx->gw.backend_error    = wstunnel_backend_error;
    hctx->gw.response         = chunk_buffer_acquire();

    hctx->frame.state         = MOD_WEBSOCKET_FRAME_STATE_INIT;
    hctx->frame.ctl.siz       = 0;
    hctx->frame.payload       = chunk_buffer_acquire();

    unsigned int binary = hctx->conf.frame_type; /*(0 = "text"; 1 = "binary")*/
    const buffer *vb =
      http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Protocol"));
    if (NULL != vb) {
        if (http_header_str_contains_token(BUF_PTR_LEN(vb), CONST_STR_LEN("binary")))
            hctx->subproto = binary = 1;
        else if (http_header_str_contains_token(BUF_PTR_LEN(vb), CONST_STR_LEN("base64")))
            hctx->subproto = -1;
    }

    if (binary) {
        hctx->frame.type         = MOD_WEBSOCKET_FRAME_TYPE_BIN;
        hctx->frame.type_backend = MOD_WEBSOCKET_FRAME_TYPE_BIN;
    }
  #if 0 /*(already zero-inited)*/
    else {
        hctx->frame.type         = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
        hctx->frame.type_backend = MOD_WEBSOCKET_FRAME_TYPE_TEXT;
    }
  #endif

    return HANDLER_GO_ON;
}

static handler_t mod_wstunnel_check_extension(request_st * const r, void *p_d) {
    if (NULL != r->handler_module)
        return HANDLER_GO_ON;
  if (r->http_version > HTTP_VERSION_1_1) {
    if (!r->h2_connect_ext)
        return HANDLER_GO_ON;
  }
  else {
    if (r->http_method != HTTP_METHOD_GET)
        return HANDLER_GO_ON;
    if (r->http_version != HTTP_VERSION_1_1)
        return HANDLER_GO_ON;

    /*
     * Connection: upgrade, keep-alive, ...
     * Upgrade: WebSocket, ...
     */
    const buffer *vb;
    vb = http_header_request_get(r, HTTP_HEADER_UPGRADE, CONST_STR_LEN("Upgrade"));
    if (NULL == vb
        || !http_header_str_contains_token(BUF_PTR_LEN(vb), CONST_STR_LEN("websocket")))
        return HANDLER_GO_ON;
    vb = http_header_request_get(r, HTTP_HEADER_CONNECTION, CONST_STR_LEN("Connection"));
    if (NULL == vb
        || !http_header_str_contains_token(BUF_PTR_LEN(vb), CONST_STR_LEN("upgrade")))
        return HANDLER_GO_ON;
  }

    plugin_config pconf;
    mod_wstunnel_patch_config(r, p_d, &pconf);
    if (NULL == pconf.gw.exts) return HANDLER_GO_ON;
    pconf.gw.upgrade = 1;

    handler_t rc =
      gw_check_extension(r, (gw_plugin_config *)&pconf,
                         p_d, 1, sizeof(handler_ctx));
    const plugin_data_base * const pd = p_d;
    return (HANDLER_GO_ON == rc && r->handler_module == pd)
      ? wstunnel_handler_setup(r, r->plugin_ctx[pd->id], &pconf)
      : rc;
}

TRIGGER_FUNC(mod_wstunnel_handle_trigger) {
    gw_handle_trigger(srv, p_d);

    plugin_data_base * const pd = p_d;
    const unix_time64_t cur_ts = log_monotonic_secs + 1;
    struct hxcon h1c;
    h1c.rused = 1;

    for (connection *con = srv->conns; con; con = con->next) {
        hxcon * const hx = con->hx ? con->hx : (h1c.r[0] = &con->request, &h1c);
        for (uint32_t i = 0, rused = hx->rused; i < rused; ++i) {
            request_st * const r = hx->r[i];
            handler_ctx * const hctx = r->plugin_ctx[pd->id];
            if (NULL == hctx || r->handler_module != pd)
                continue;

            if (hctx->gw.state != GW_STATE_WRITE && hctx->gw.state != GW_STATE_READ)
                continue;

            /* attempt to cleanly close websocket if connection idle timeout
             * (occurs 1 sec sooner than r->conf.max_read_idle due to +1 above)
             * (note: >= HTTP/2 affected only if entire connection is idle) */
            if (__builtin_expect(
                  (cur_ts - con->read_idle_ts > r->conf.max_read_idle), 0)) {
                DEBUG_LOG_INFO("timeout client (fd=%d)", con->fd);
                wstunnel_err(hctx, 1001, NULL);
                gw_handle_request_reset(r, pd);
                joblist_append(con);
                continue;
            }

            if (0 != hctx->hybivers
                && hctx->conf.ping_interval > 0
                && (int32_t)hctx->conf.ping_interval + hctx->ping_ts < cur_ts) {
                hctx->ping_ts = cur_ts;
                mod_wstunnel_frame_send(hctx, MOD_WEBSOCKET_FRAME_TYPE_PING, CONST_STR_LEN("ping"));
                joblist_append(con);
                continue;
            }
        }
    }

    return HANDLER_GO_ON;
}




/*
 * modified from Norio Kobota mod_websocket_handshake.c
 */

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_

#include <stdlib.h>     /* strtoul() free() */
#include "sys-crypto-md.h"  /* lighttpd */
#include "sys-endian.h"     /* lighttpd */

static int get_key3(request_st * const r, char *buf, uint32_t bytes) {
    /* 8 bytes should have been sent with request
     * for draft-ietf-hybi-thewebsocketprotocol-00 */
    chunkqueue *cq = &r->reqbody_queue;
    /*(caller should ensure bytes available prior to calling this routine)*/
    /*assert(chunkqueue_length(cq) >= 8);*/
    /*assert(8 == bytes);*/
    return chunkqueue_read_data(cq, buf, bytes, r->conf.errh);
}

static int get_key_number(uint32_t *ret, const buffer *b) {
    const char * const s = b->ptr;
    size_t j = 0;
    unsigned long n;
    uint32_t sp = 0;
    char tmp[10 + 1]; /* #define UINT32_MAX_STRLEN 10 */

    for (size_t i = 0, used = buffer_clen(b); i < used; ++i) {
        if (light_isdigit(s[i])) {
            tmp[j] = s[i];
            if (++j >= sizeof(tmp)) return -1;
        }
        else if (s[i] == ' ') ++sp; /* count num spaces */
    }
    tmp[j] = '\0';
    n = strtoul(tmp, NULL, 10);
    if (n > UINT32_MAX || 0 == sp || !light_isdigit(*tmp)) return -1;
    *ret = (uint32_t)n / sp;
    return 0;
}

static int create_MD5_sum(request_st * const r) {
    uint32_t buf[4]; /* MD5 binary hash len */

    const buffer *key1 =
      http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Key1"));
    const buffer *key2 =
      http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Key2"));

    if (NULL == key1 || get_key_number(buf+0, key1) < 0 ||
        NULL == key2 || get_key_number(buf+1, key2) < 0 ||
        get_key3(r, (char *)(buf+2), 2*sizeof(uint32_t)) < 0) {
        return -1;
    }
  #ifdef __BIG_ENDIAN__
  #define ws_htole32(s,u)\
    (s)[0]=((u)>>24);    \
    (s)[1]=((u)>>16);    \
    (s)[2]=((u)>>8);     \
    (s)[3]=((u))
    uint32_t u;
    u = buf[0];
    ws_htole32((unsigned char *)(buf+0), u);
    u = buf[1];
    ws_htole32((unsigned char *)(buf+1), u);
  #endif
    /*(overwrite buf[] with result)*/
    MD5_once((unsigned char *)buf, buf, sizeof(buf));
    chunkqueue_append_mem(&r->write_queue, (char *)buf, sizeof(buf));
    return 0;
}

static int create_response_ietf_00(handler_ctx *hctx) {
    request_st * const r = hctx->gw.r;

    /* "Origin" header is preferred
     * ("Sec-WebSocket-Origin" is from older drafts of websocket spec) */
    const buffer *origin = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Origin"));
    if (NULL == origin) {
        origin =
          http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Origin"));
    }
    if (NULL == origin)
        return wstunnel_err(hctx, 0, "Origin header is invalid");
    /*(redundant since HTTP/1.1 required in mod_wstunnel_check_extension())*/
    if (!r->http_host || buffer_is_blank(r->http_host))
        return -1;
    /* calc MD5 sum from keys */
    if (create_MD5_sum(r) < 0)
        return wstunnel_err(hctx, 0, "Sec-WebSocket-Key is invalid");

    http_header_response_set(r, HTTP_HEADER_UPGRADE,
                             CONST_STR_LEN("Upgrade"),
                             CONST_STR_LEN("websocket"));
  #if 0 /*(added later in http_response_write_header())*/
    http_header_response_append(r, HTTP_HEADER_CONNECTION,
                                CONST_STR_LEN("Connection"),
                                CONST_STR_LEN("upgrade"));
  #endif
  #if 0 /*(Sec-WebSocket-Origin header is not required for hybi-00)*/
    /* Note: it is insecure to simply reflect back origin provided by client
     * (if admin did not configure restricted list of valid origins)
     * (see wstunnel_check_request()) */
    http_header_response_set(r, HTTP_HEADER_OTHER,
                             CONST_STR_LEN("Sec-WebSocket-Origin"),
                             BUF_PTR_LEN(origin));
  #endif

    buffer * const value =
      http_header_response_set_ptr(r, HTTP_HEADER_OTHER,
                                   CONST_STR_LEN("Sec-WebSocket-Location"));
    if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https")))
        buffer_copy_string_len(value, CONST_STR_LEN("wss://"));
    else
        buffer_copy_string_len(value, CONST_STR_LEN("ws://"));
    buffer_append_str2(value, BUF_PTR_LEN(r->http_host),
                              BUF_PTR_LEN(&r->uri.path));
    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */


#ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_

#include "sys-crypto-md.h"  /* lighttpd */
#include "base64.h"         /* lighttpd */

static int create_response_rfc_6455(handler_ctx *hctx) {
    request_st * const r = hctx->gw.r;
  if (r->http_version == HTTP_VERSION_1_1) {
    SHA_CTX sha;
    unsigned char sha_digest[SHA_DIGEST_LENGTH];

    const buffer *value_wskey =
      http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Sec-WebSocket-Key"));
    if (NULL == value_wskey)
        return wstunnel_err(hctx, 0, "Sec-WebSocket-Key is invalid");

    /* get SHA1 hash of key */
    /* refer: RFC-6455 Sec.1.3 Opening Handshake */
    SHA1_Init(&sha);
    SHA1_Update(&sha, (const unsigned char *)BUF_PTR_LEN(value_wskey));
    SHA1_Update(&sha, (const unsigned char *)CONST_STR_LEN("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
    SHA1_Final(sha_digest, &sha);

    http_header_response_set(r, HTTP_HEADER_UPGRADE,
                             CONST_STR_LEN("Upgrade"),
                             CONST_STR_LEN("websocket"));
  #if 0 /*(added later in http_response_write_header())*/
    http_header_response_append(r, HTTP_HEADER_CONNECTION,
                                CONST_STR_LEN("Connection"),
                                CONST_STR_LEN("upgrade"));
  #endif

    buffer * const value =
      http_header_response_set_ptr(r, HTTP_HEADER_OTHER,
                                   CONST_STR_LEN("Sec-WebSocket-Accept"));
    buffer_append_base64_encode(value, sha_digest, SHA_DIGEST_LENGTH, BASE64_STANDARD);
  }

    if (1 == hctx->subproto)
        http_header_response_set(r, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Sec-WebSocket-Protocol"),
                                 CONST_STR_LEN("binary"));
    else if (-1 == hctx->subproto)
        http_header_response_set(r, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Sec-WebSocket-Protocol"),
                                 CONST_STR_LEN("base64"));

    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */


handler_t mod_wstunnel_handshake_create_response(handler_ctx *hctx) {
    request_st * const r = hctx->gw.r;
  #ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->hybivers >= 8) {
        if (0 != create_response_rfc_6455(hctx)) {
            r->http_status = 400; /* Bad Request */
            return HANDLER_ERROR;
        }
        return HANDLER_GO_ON;
    }
  #endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */

  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (hctx->hybivers == 0 && r->http_version == HTTP_VERSION_1_1) {
        /* 8 bytes should have been sent with request
         * for draft-ietf-hybi-thewebsocketprotocol-00 */
        chunkqueue *cq = &r->reqbody_queue;
        if (chunkqueue_length(cq) < 8)
            return HANDLER_WAIT_FOR_EVENT;

        if (0 != create_response_ietf_00(hctx)) {
            r->http_status = 400; /* Bad Request */
            return HANDLER_ERROR;
        }
        return HANDLER_GO_ON;
    }
  #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */

    wstunnel_err(hctx, 0, "unsupported WebSocket Version");
    r->http_status = 503; /* Service Unavailable */
    return HANDLER_ERROR;
}




/*
 * modified from Norio Kobota mod_websocket_frame.c
 */

#include "base64.h"     /* lighttpd */
#include "http_chunk.h" /* lighttpd */

#ifdef _MOD_WEBSOCKET_SPEC_IETF_00_

static int send_ietf_00(handler_ctx *hctx, mod_wstunnel_frame_type_t type, const char *payload, size_t siz) {
    static const char head =  0; /* 0x00 */
    static const char tail = ~0; /* 0xff */
    request_st * const r = hctx->gw.r;
    char *mem;
    size_t len;

    switch (type) {
    case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
        if (0 == siz) return 0;
        http_chunk_append_mem(r, &head, 1);
        http_chunk_append_mem(r, payload, siz);
        http_chunk_append_mem(r, &tail, 1);
        /*len = siz+2;*/
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_BIN:
        if (0 == siz) return 0;
        http_chunk_append_mem(r, &head, 1);
        len = 4*(siz/3)+4+1;
        /* avoid accumulating too much data in memory; send to tmpfile */
        mem = ck_malloc(len);
        len=li_to_base64(mem,len,(unsigned char *)payload,siz,BASE64_STANDARD);
        http_chunk_append_mem(r, mem, len);
        free(mem);
        http_chunk_append_mem(r, &tail, 1);
        /*len += 2;*/
        break;
    case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:
        http_chunk_append_mem(r, &tail, 1);
        http_chunk_append_mem(r, &head, 1);
        /*len = 2;*/
        break;
    default:
        return -1; /*(not reached)*/
    }
    return 0;
}

static int recv_ietf_00(handler_ctx *hctx) {
    buffer_string_prepare_copy(hctx->gw.r->tmp_buf, 65535);
    request_st * const r = hctx->gw.r;
    chunkqueue *cq = &r->reqbody_queue;
    while (!chunkqueue_is_empty(cq)) {
        char *frame = r->tmp_buf->ptr;
        uint32_t i, flen = buffer_string_space(r->tmp_buf);
        if (0 != chunkqueue_peek_data(cq, &frame, &flen, r->conf.errh, 0))
            return wstunnel_err(hctx, 1011, NULL); /* Internal Server Error */
        for (i = 0; i < flen; ) {
            if (hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_INIT) {
                hctx->frame.ctl.siz = 0;
                if (__builtin_expect( (frame[i] != 0x00), 0))
                    return (((unsigned char *)frame)[i] == 0xff) /* close */
                      ? wstunnel_err(hctx, 1000, NULL) /* Normal Closure */
                      : wstunnel_err(hctx, 1002, "frame type invalid");
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                if (++i == flen)
                    break;
            }

            /* hctx->frame.state == MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD */
            /* MOD_WEBSOCKET_FRAME_TYPE_TEXT or MOD_WEBSOCKET_FRAME_TYPE_BIN */
            if (chunkqueue_length(&hctx->gw.wb) > 65536 - 16384) {
                flen = i; /* trigger for loop exit */
                i += chunkqueue_length(cq) + 1;
                break;
            }
            else {
                uint32_t plen = flen - i;
                char *mem = (char *)memchr(frame+i, 0xff, plen);
                if (mem != NULL) {
                    plen = (uint32_t)(mem - (frame+i));
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                }
                hctx->frame.ctl.siz += plen;
                #define MOD_WEBSOCKET_BUFMAX 0xfffff
                if (hctx->frame.ctl.siz > MOD_WEBSOCKET_BUFMAX)
                    return wstunnel_err(hctx, 1002, "frame size has exceeded 0xfffff");
                DEBUG_LOG_DEBUG("recv payload, size=%u", plen);
                buffer * const payload = hctx->frame.payload;
                buffer_append_string_len(payload, frame+i, plen);
                i += plen + 1; /* +1 for 0xff, or flen fully consumed */
                if (buffer_is_blank(payload))
                    continue;
                if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_TEXT) {
                    hctx->frame.ctl.siz = 0;
                    chunkqueue_append_buffer(&hctx->gw.wb, payload);
                    /*buffer_clear(payload);*//*chunkqueue_append_buffer clear*/
                }
                else { /* hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_BIN */
                    /* base64 decode in groups of 4 bytes to avoid buffering
                     * in memory the entire frame, which could be up to 1 MB */
                    plen = buffer_clen(payload);
                    if (hctx->frame.state != MOD_WEBSOCKET_FRAME_STATE_INIT)
                        plen &= ~0x3; /* (plen -= (plen % 4)) */

                    size_t len = (plen+3)/4*3+1;
                    chunkqueue_get_memory(&hctx->gw.wb, &len);
                    buffer * const b = hctx->gw.wb.last->mem;
                    len = buffer_clen(b);
                    if (!buffer_append_base64_decode(b, payload->ptr, plen,
                                                     BASE64_STANDARD))
                        return wstunnel_err(hctx, 1007, "fail to base64-decode");
                    /*chunkqueue_use_memory()*/
                    hctx->gw.wb.bytes_in += buffer_clen(b)-len;

                    const uint32_t n = buffer_clen(payload) - plen;
                    if (0 == n)
                        buffer_clear(payload);
                    else {
                        memmove(payload->ptr, payload->ptr+plen, n);
                        buffer_truncate(payload, n);
                    }
                }
            }
        }
        chunkqueue_mark_written(cq, flen);
        if (i > flen && i - flen > chunkqueue_length(cq))
            break; /* flag to wait to receive more data */
    }
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

/* map mod_wstunnel_frame_type_t to rfc6455 opcode */
static const char mod_wstunnel_frame_type_op[] = {
  MOD_WEBSOCKET_OPCODE_TEXT
 ,MOD_WEBSOCKET_OPCODE_BIN
 ,MOD_WEBSOCKET_OPCODE_CLOSE
 ,MOD_WEBSOCKET_OPCODE_PING
 ,MOD_WEBSOCKET_OPCODE_PONG
};

/* map rfc6455 opcode to mod_wstunnel_frame_type_t */
static const int8_t mod_wstunnel_op_frame_type[] = {
  -1
 ,MOD_WEBSOCKET_FRAME_TYPE_TEXT
 ,MOD_WEBSOCKET_FRAME_TYPE_BIN
 ,-1
 ,-1
 ,-1
 ,-1
 ,-1
 ,MOD_WEBSOCKET_FRAME_TYPE_CLOSE
 ,MOD_WEBSOCKET_FRAME_TYPE_PING
 ,MOD_WEBSOCKET_FRAME_TYPE_PONG
 ,-1
 ,-1
 ,-1
 ,-1
 ,-1
};

static int send_rfc_6455(handler_ctx *hctx, mod_wstunnel_frame_type_t type, const char *payload, size_t siz) {
    char mem[10];
    size_t len;

    /* allowed null payload for ping, pong, close frame */
    if (payload == NULL && (   type == MOD_WEBSOCKET_FRAME_TYPE_TEXT
                            || type == MOD_WEBSOCKET_FRAME_TYPE_BIN   )) {
        return -1;
    }

    mem[0] = (char)(0x80 | mod_wstunnel_frame_type_op[type]);
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
    request_st * const r = hctx->gw.r;
    http_chunk_append_mem(r, mem, len);
  #ifdef __COVERITY__
    if (payload == NULL) ck_assert(0 == siz);
  #endif
    if (siz) http_chunk_append_mem(r, payload, siz);
    return 0;
}

__attribute_hot__
__attribute_noinline__
static void unmask_payload(handler_ctx *hctx) {
    /* For clients such as browsers running untrusted javascript, choosing
     * a random, unpredictable mask is important to prevent a malicious
     * application from selecting the bytes that appear on the wire,
     * but mask might safely be 0 for non-browser clients */
    if (UINT_MAX == hctx->frame.ctl.mask_off) return; /*(skip if mask all 0's)*/

    unsigned char * restrict p = (unsigned char *)hctx->frame.payload->ptr;
    const unsigned char * const restrict mask = hctx->frame.ctl.mask;
    uint32_t used = buffer_clen(hctx->frame.payload);
    uint32_t mask_off = hctx->frame.ctl.mask_off;
    hctx->frame.ctl.mask_off = (mask_off + used) & 3;

  #if 1 /* optimizations for faster unmasking using less CPU */
    if (used > 8) { /*(arbitrarily chosen)*/
        /* future: consider aligning to 32-byte cache line
         *         and unrolling Duff's device to 8 cases */

        used -= (uint32_t)((uintptr_t)p & 3);
        for (int n = (int)((uintptr_t)p & 3); n; --n)
            *p++ ^= mask[mask_off++ & 3];

        /* unmask in groups of 4 bytes (aligned) */
        if (used >> 2) {
            union { uint32_t u; char c[4]; } un;
            for (int i = 0; i < 4; ++i) un.c[i] = mask[mask_off++ & 3];

          #if 1
            /* Duff's device */
            register uint32_t n = ((used >> 2) + 3) / 4;
            switch ((used >> 2) & 3) {
            case 0: do { *(uint32_t*)p ^= un.u; p += 4;__attribute_fallthrough__
            case 3:      *(uint32_t*)p ^= un.u; p += 4;__attribute_fallthrough__
            case 2:      *(uint32_t*)p ^= un.u; p += 4;__attribute_fallthrough__
            case 1:      *(uint32_t*)p ^= un.u; p += 4;
                    } while (--n);
            }
          #else /*(alternative, if compiler does not like Duff's device)*/
            for (uint32_t n = used >> 2; n; --n) {
                *(uint32_t *)p ^= un.u;
                p += 4;
            }
          #endif
        }

        used &= 3;
    }
  #endif

    for (uint32_t i = 0; i < used; ++i)
        p[i] ^= mask[mask_off++ & 3];
}

static int recv_rfc_6455(handler_ctx *hctx) {
    buffer_string_prepare_copy(hctx->gw.r->tmp_buf, 65535);
    request_st * const r = hctx->gw.r;
    chunkqueue *cq = &r->reqbody_queue;
    buffer *payload = hctx->frame.payload;
    while (!chunkqueue_is_empty(cq)) {
        char *frame = r->tmp_buf->ptr;
        uint32_t i, flen = buffer_string_space(r->tmp_buf);
        if (0 != chunkqueue_peek_data(cq, &frame, &flen, r->conf.errh, 0))
            return wstunnel_err(hctx, 1011, NULL); /* Internal Server Error */
        for (i = 0; i < flen; ) {
            switch (hctx->frame.state) {
            case MOD_WEBSOCKET_FRAME_STATE_INIT:
                if (__builtin_expect( (flen - i < 2 + MOD_WEBSOCKET_MASK_CNT), 0)) {
                    /* yield to collect initial 2 bytes of frame + 4 byte mask*/
                    flen = i; /* trigger for loop exit */
                    i += 2 + MOD_WEBSOCKET_MASK_CNT;
                    continue;
                }
                hctx->frame.type = mod_wstunnel_op_frame_type[(frame[i] & 0xf)];
                switch (frame[i] & 0xf) {
                case MOD_WEBSOCKET_OPCODE_CONT:
                    if (0 == hctx->frame.type_cont)
                        return wstunnel_err(hctx, 1002, "stray continuation frame");
                    hctx->frame.type = mod_wstunnel_op_frame_type[hctx->frame.type_cont];
                    if (frame[i] & 0x80) /* fin bit 1 ends continuation */
                        hctx->frame.type_cont = 0;
                    break;
                case MOD_WEBSOCKET_OPCODE_TEXT:
                case MOD_WEBSOCKET_OPCODE_BIN:
                    if (hctx->frame.type_cont)
                        return wstunnel_err(hctx, 1002, "missing continuation frame with fin");
                    if (0 == (frame[i] & 0x80)) /* fin bit 0; continuation */
                        hctx->frame.type_cont = (frame[i] & 0xf);
                    break;
                case MOD_WEBSOCKET_OPCODE_CLOSE:
                    return wstunnel_err(hctx, 1000, NULL); /* Normal Closure */
                case MOD_WEBSOCKET_OPCODE_PING:
                case MOD_WEBSOCKET_OPCODE_PONG:
                    if (0 == (frame[i] & 0x80))
                        return wstunnel_err(hctx, 1002, "control frame fragmented");
                    break;
                default:
                    return wstunnel_err(hctx, 1002, "frame type invalid");
                }

                /* future: might add support: RFC7692 permessage-deflate */
                if (frame[i] & 0x70)
                    return wstunnel_err(hctx, 1002, "reserved bits set");
                if ((frame[i+1] & 0x80) != 0x80)
                    return wstunnel_err(hctx, 1002, "payload not masked");
                hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                const uint8_t siz = (((uint8_t *)frame)[i+1] & 0x7f);
                if (siz < 0x7e)
                    hctx->frame.ctl.siz = siz;
                else {
                    /* MOD_WEBSOCKET_FRAME_LEN16 0x7E */
                    /* MOD_WEBSOCKET_FRAME_LEN63 0x7F */
                    if (siz == MOD_WEBSOCKET_FRAME_LEN16) {
                        /*(already checked that we have at least 6 bytes)*/
                        /* unaligned (potentially) read of big-endian size */
                        /* modern compiler optimizers (gcc, clang) recognize these
                         * patterns and use more efficient instructions (e.g. bswap)
                         * when available */
                        hctx->frame.ctl.siz =
                          ( ((uint64_t)((uint8_t *)frame)[i+2] <<  8)
                           | (uint64_t)((uint8_t *)frame)[i+3] );
                        i += 2;
                      #if 0 /* pedantic adherence to RFC6455 */
                        if (hctx->frame.ctl.siz < 0x7e)
                            return wstunnel_err(hctx, 1002, "oversized length encoding");
                      #endif
                    }
                    else /* siz == MOD_WEBSOCKET_FRAME_LEN63 */
                        hctx->frame.state =
                          MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH;
                    if (frame[i] & 0x8) /* control frames (0x8-0xF) */
                        return wstunnel_err(hctx, 1002, "control frame size invalid");
                }
                i += 2;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_EX_LENGTH:
                if (__builtin_expect( (flen - i < MOD_WEBSOCKET_FRAME_LEN63_CNT
                                                  + MOD_WEBSOCKET_MASK_CNT), 0)) {
                    /* yield to collect extended length */
                    flen = i; /* trigger for loop exit */
                    i += MOD_WEBSOCKET_FRAME_LEN63_CNT + MOD_WEBSOCKET_MASK_CNT;
                    continue;
                }
                else {
                    /* unaligned (potentially) read of big-endian size */
                    /* modern compiler optimizers (gcc, clang) recognize these
                     * patterns and use more efficient instructions (e.g. bswap)
                     * when available */
                    hctx->frame.ctl.siz =
                        ( ((uint64_t)((uint8_t *)frame)[i+0] << 56)
                         |((uint64_t)((uint8_t *)frame)[i+1] << 48)
                         |((uint64_t)((uint8_t *)frame)[i+2] << 40)
                         |((uint64_t)((uint8_t *)frame)[i+3] << 32)
                         |((uint64_t)((uint8_t *)frame)[i+4] << 24)
                         |((uint64_t)((uint8_t *)frame)[i+5] << 16)
                         |((uint64_t)((uint8_t *)frame)[i+6] <<  8)
                         | (uint64_t)((uint8_t *)frame)[i+7] );
                    i += MOD_WEBSOCKET_FRAME_LEN63_CNT;
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_MASK;
                    if (hctx->frame.ctl.siz >> 63)
                        return wstunnel_err(hctx, 1002, "frame size MSB is set");
                  #if 0 /* pedantic adherence to RFC6455 */
                    if (hctx->frame.ctl.siz < 0x10000)
                        return wstunnel_err(hctx, 1002, "oversized length encoding");
                  #endif
                }
                __attribute_fallthrough__
            case MOD_WEBSOCKET_FRAME_STATE_READ_MASK:
                if (__builtin_expect( (flen - i < MOD_WEBSOCKET_MASK_CNT), 0)) {
                    /* yield to collect extended length */
                    flen = i; /* trigger for loop exit */
                    i += MOD_WEBSOCKET_MASK_CNT;
                    continue;
                }
                if (hctx->frame.ctl.siz) {
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD;
                    hctx->frame.ctl.mask_off = /*-1 to skip if mask is all 0's*/
                     (frame[i]|frame[i+1]|frame[i+2]|frame[i+3]) ? 0 : UINT_MAX;
                    memcpy(hctx->frame.ctl.mask,frame+i,MOD_WEBSOCKET_MASK_CNT);
                }
                else {
                    hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    if (hctx->frame.type == MOD_WEBSOCKET_FRAME_TYPE_PING)
                        mod_wstunnel_frame_send(hctx,
                                                MOD_WEBSOCKET_FRAME_TYPE_PONG,
                                                NULL, 0);
                }
                DEBUG_LOG_DEBUG("frame type=%s, specified payload size=%llu",
                                mod_wstunnel_frame_type_str[hctx->frame.type],
                                (unsigned long long)hctx->frame.ctl.siz);
                i += MOD_WEBSOCKET_MASK_CNT;
                break;
            case MOD_WEBSOCKET_FRAME_STATE_READ_PAYLOAD:
                if (chunkqueue_length(&hctx->gw.wb) > 65536 - 16384
                    && hctx->frame.type <= MOD_WEBSOCKET_FRAME_TYPE_BIN) {
                    /* MOD_WEBSOCKET_FRAME_TYPE_TEXT or
                     * MOD_WEBSOCKET_FRAME_TYPE_BIN */
                    flen = i; /* trigger for loop exit */
                    i += chunkqueue_length(cq) + 1;
                    continue;
                }
                else {
                    uint32_t n = flen - i;
                    if (hctx->frame.ctl.siz <= n) {
                        n = (uint32_t)hctx->frame.ctl.siz;
                        hctx->frame.state = MOD_WEBSOCKET_FRAME_STATE_INIT;
                    }
                    hctx->frame.ctl.siz -= n;
                    buffer_append_string_len(payload, frame+i, n);
                    i += n;
                    DEBUG_LOG_DEBUG(
                      "recv payload, size=%u; remaining payload size=%llu",
                      n, (unsigned long long)hctx->frame.ctl.siz);
                }
                switch (hctx->frame.type) {
                case MOD_WEBSOCKET_FRAME_TYPE_TEXT:
                    /* pedantic adherence to RFC6455 would validate UTF-8
                     * payload, but would have to first reassemble message
                     * fragments, if websocket message is fragmented, since
                     * would want to handle messages with fragments
                     *  (improperly) split in the middle of UTF-8 characters */
                case MOD_WEBSOCKET_FRAME_TYPE_BIN:
                    unmask_payload(hctx);
                    chunkqueue_append_buffer(&hctx->gw.wb, payload);
                    /*buffer_clear(payload);*//*chunkqueue_append_buffer clear*/
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_PING:
                    if (hctx->frame.ctl.siz == 0) {
                        unmask_payload(hctx);
                        mod_wstunnel_frame_send(hctx,
                          MOD_WEBSOCKET_FRAME_TYPE_PONG,
                          BUF_PTR_LEN(payload));
                        buffer_clear(payload);
                    }
                    break;
                case MOD_WEBSOCKET_FRAME_TYPE_PONG:
                    buffer_clear(payload);
                    break;
                /*case MOD_WEBSOCKET_FRAME_TYPE_CLOSE:*/
                default:
                    return wstunnel_err(hctx, 1011, NULL);
                }
                break;
            default:
                return wstunnel_err(hctx, 1011, NULL); /*Internal Server Error*/
            }
        }
        chunkqueue_mark_written(cq, flen);
        if (i > flen && i - flen > chunkqueue_length(cq))
            break; /* flag to wait to receive more data */
    }
    return 0;
}

#endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */


int mod_wstunnel_frame_send(handler_ctx *hctx, mod_wstunnel_frame_type_t type,
                             const char *payload, size_t siz) {
    DEBUG_LOG_DEBUG("send to client (fd=%d), frame type=%s, payload size=%zu",
                    hctx->gw.r->con->fd,
                    mod_wstunnel_frame_type_str[type], siz);
  #ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->hybivers >= 8) return send_rfc_6455(hctx, type, payload, siz);
  #endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (0 == hctx->hybivers) return send_ietf_00(hctx, type, payload, siz);
  #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */
    return -1;
}

int mod_wstunnel_frame_recv(handler_ctx *hctx) {
    DEBUG_LOG_DEBUG("recv from client (fd=%d), queue size=%llu",
                    hctx->gw.r->con->fd,
                    (long long)chunkqueue_length(&hctx->gw.r->reqbody_queue));
  #ifdef _MOD_WEBSOCKET_SPEC_RFC_6455_
    if (hctx->hybivers >= 8) return recv_rfc_6455(hctx);
  #endif /* _MOD_WEBSOCKET_SPEC_RFC_6455_ */
  #ifdef _MOD_WEBSOCKET_SPEC_IETF_00_
    if (0 == hctx->hybivers) return recv_ietf_00(hctx);
  #endif /* _MOD_WEBSOCKET_SPEC_IETF_00_ */
    return -1; /*(not reached)*/
}
