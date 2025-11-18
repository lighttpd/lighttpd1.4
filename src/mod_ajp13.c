/*
 * mod_ajp13 - Apache JServ Protocol version 1.3 (AJP13) gateway
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * AJPv13 protocol reference:
 *   https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
 *
 * Note: connection pool (and connection reuse) is not implemented
 */
#include "first.h"

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "gw_backend.h"
typedef gw_plugin_config plugin_config;
typedef gw_plugin_data   plugin_data;
typedef gw_handler_ctx   handler_ctx;

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"
#include "http_chunk.h"
#include "http_header.h"
#include "http_status.h"
#include "http_kv.h"
#include "log.h"

#define AJP13_MAX_PACKET_SIZE 8192


static void
mod_ajp13_merge_config_cpv (plugin_config * const pconf, const config_plugin_value_t * const cpv)
{
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* ajp13.server */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            gw_plugin_config * const gw = cpv->v.v;
            pconf->exts      = gw->exts;
            pconf->exts_auth = gw->exts_auth;
            pconf->exts_resp = gw->exts_resp;
        }
        break;
      case 1: /* ajp13.balance */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->balance = (int)cpv->v.u;
        break;
      case 2: /* ajp13.debug */
        pconf->debug = (int)cpv->v.u;
        break;
      case 3: /* ajp13.map-extensions */
        pconf->ext_mapping = cpv->v.a;
        break;
      default:/* should not happen */
        return;
    }
}


static void
mod_ajp13_merge_config (plugin_config * const pconf, const config_plugin_value_t *cpv)
{
    do {
        mod_ajp13_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_ajp13_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf)
{
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_ajp13_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


SETDEFAULTS_FUNC(mod_ajp13_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ajp13.server"),
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ajp13.balance"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ajp13.debug"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ajp13.map-extensions"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_ajp13"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        gw_plugin_config *gw = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0:{/* ajp13.server */
                gw = ck_calloc(1, sizeof(gw_plugin_config));
                if (!gw_set_defaults_backend(srv, p, cpv->v.a, gw, 0,
                                             cpk[cpv->k_id].k)) {
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                cpv->v.v = gw;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              }
              case 1: /* ajp13.balance */
                cpv->v.u = (unsigned int)gw_get_defaults_balance(srv, cpv->v.b);
                break;
              case 2: /* ajp13.debug */
              case 3: /* ajp13.map-extensions */
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

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_ajp13_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


__attribute_pure__
static inline uint32_t
ajp13_dec_uint16 (const uint8_t * const x)
{
    return (x[0] << 8) | x[1];
}


static inline void
ajp13_enc_uint16_nc (uint8_t * const x, const uint32_t v)
{
    /*(_nc = no check; caller must check for sufficient space in x)*/
    x[0] = 0xFF & (v >> 8);
    x[1] = 0xFF & (v);
}


static uint32_t
ajp13_enc_uint16 (uint8_t * const x, const uint32_t n, const uint32_t v)
{
    if (n + 2 > AJP13_MAX_PACKET_SIZE) return 0;
    ajp13_enc_uint16_nc(x+n, v);
    return n+2;
}


static uint32_t
ajp13_enc_byte (uint8_t * const x, const uint32_t n, const uint32_t v)
{
    if (n + 1 > AJP13_MAX_PACKET_SIZE) return 0;
    x[n] = v;
    return n+1;
}


static uint32_t
ajp13_enc_string (uint8_t * const x, uint32_t n, const char * const s, const uint32_t len)
{
    /*assert(AJP13_MAX_PACKET_SIZE <= UINT16_MAX);*//*(max is 8k in practice)*/
    if (0 == len || len == UINT16_MAX)
        return ajp13_enc_uint16(x, n, 0xFFFF);

    if (n + 2 + len + 1 > AJP13_MAX_PACKET_SIZE) return 0;
    ajp13_enc_uint16_nc(x+n, len);
    n += 2;
    memcpy(x+n, s, len);
    n += len;
    x[n] = '\0';
    return n+1;
}


static handler_t
ajp13_stdin_append (handler_ctx * const hctx)
{
    chunkqueue * const req_cq = &hctx->r->reqbody_queue;
    const off_t req_cqlen = chunkqueue_length(req_cq);
    const off_t max_bytes = hctx->request_id < req_cqlen
      ? hctx->request_id < MAX_WRITE_LIMIT ? hctx->request_id : MAX_WRITE_LIMIT
      : req_cqlen;
    off_t sent = 0;
    uint8_t hdr[4] = { 0x12, 0x34, 0, 0 };

    for (off_t dlen; sent < max_bytes; sent += dlen) {
        dlen = max_bytes - sent > AJP13_MAX_PACKET_SIZE - 4
          ? AJP13_MAX_PACKET_SIZE - 4
          : max_bytes - sent;

        if (-1 != hctx->wb_reqlen) {
            if (hctx->wb_reqlen >= 0)
                hctx->wb_reqlen += sizeof(hdr);
            else
                hctx->wb_reqlen -= sizeof(hdr);
        }

        ajp13_enc_uint16_nc(hdr+2, (uint32_t)dlen);
        (chunkqueue_is_empty(&hctx->wb) || hctx->wb.first->type == MEM_CHUNK)
                                           /* else FILE_CHUNK for temp file */
          ? chunkqueue_append_mem(&hctx->wb, (char *)&hdr, sizeof(hdr))
          : chunkqueue_append_mem_min(&hctx->wb, (char *)&hdr, sizeof(hdr));
        chunkqueue_steal(&hctx->wb, req_cq, dlen);
        /*(hctx->wb_reqlen already includes reqbody_length)*/
    }

    hctx->request_id -= (int)sent;
    return HANDLER_GO_ON;
}


static void
ajp13_stdin_append_n (handler_ctx * const hctx, const uint32_t n)
{
    if (hctx->wb.bytes_in == hctx->wb_reqlen) {
        /*(no additional request body to be sent; send empty packet)*/
        uint8_t hdr[4] = { 0x12, 0x34, 0, 0 };
        hctx->wb_reqlen += sizeof(hdr);
        chunkqueue_append_mem(&hctx->wb, (char *)hdr, sizeof(hdr));
    }

    /* AJP13 connections can be reused, so server and backend must agree on how
     * much data is sent for each serialized request, especially if backend
     * chooses not to read (and use or discard) entire request body from server.
     * If server sent excess data, data might be interpreted as a subsequent
     * request, which might be abused for request smuggling (security). */

    /* overload hctx->request_id to track bytes requested by backend.
     * Value must stay >= 0, since -1 is used to flag end of request */
    if (n <= (uint32_t)(INT_MAX - hctx->request_id))
        hctx->request_id += (int)n;
    else /* unexpected; misbehaving backend sent MANY Get Body Chunk requests */
        hctx->request_id = INT_MAX; /*(limitation of overloaded struct member)*/

    if (hctx->gw_mode != GW_AUTHORIZER)
        ajp13_stdin_append(hctx);
}


__attribute_pure__
static uint8_t
ajp13_method_byte (const http_method_t m)
{
    /* map lighttpd http_method_t to ajp13 method byte */

  #if (defined(__STDC_VERSION__) && __STDC_VERSION__-0 >= 199901L) /* C99 */

    static const uint8_t ajp13_methods[] = {
        [HTTP_METHOD_GET]              = 2,
        [HTTP_METHOD_HEAD]             = 3,
        [HTTP_METHOD_POST]             = 4,
        [HTTP_METHOD_PUT]              = 5,
        [HTTP_METHOD_DELETE]           = 6,
        [HTTP_METHOD_OPTIONS]          = 1,
        [HTTP_METHOD_TRACE]            = 7,
        [HTTP_METHOD_ACL]              = 15,
        [HTTP_METHOD_BASELINE_CONTROL] = 26,
        [HTTP_METHOD_CHECKIN]          = 18,
        [HTTP_METHOD_CHECKOUT]         = 19,
        [HTTP_METHOD_COPY]             = 11,
        [HTTP_METHOD_LABEL]            = 24,
        [HTTP_METHOD_LOCK]             = 13,
        [HTTP_METHOD_MERGE]            = 25,
        [HTTP_METHOD_MKACTIVITY]       = 27,
        [HTTP_METHOD_MKCOL]            = 10,
        [HTTP_METHOD_MKWORKSPACE]      = 22,
        [HTTP_METHOD_MOVE]             = 12,
        [HTTP_METHOD_PROPFIND]         = 8,
        [HTTP_METHOD_PROPPATCH]        = 9,
        [HTTP_METHOD_REPORT]           = 16,
        [HTTP_METHOD_SEARCH]           = 21,
        [HTTP_METHOD_UNCHECKOUT]       = 20,
        [HTTP_METHOD_UNLOCK]           = 14,
        [HTTP_METHOD_UPDATE]           = 23,
        [HTTP_METHOD_VERSION_CONTROL]  = 17
    };

    return m >= 0 && m < (http_method_t)sizeof(ajp13_methods)
      ? ajp13_methods[m]
      : 0;

  #else /*(array position is ajp13 method identifier byte)*/

    static const uint8_t ajp13_methods[] = {
        0,
        HTTP_METHOD_OPTIONS,
        HTTP_METHOD_GET,
        HTTP_METHOD_HEAD,
        HTTP_METHOD_POST,
        HTTP_METHOD_PUT,
        HTTP_METHOD_DELETE,
        HTTP_METHOD_TRACE,
        HTTP_METHOD_PROPFIND,
        HTTP_METHOD_PROPPATCH,
        HTTP_METHOD_MKCOL,
        HTTP_METHOD_COPY,
        HTTP_METHOD_MOVE,
        HTTP_METHOD_LOCK,
        HTTP_METHOD_UNLOCK,
        HTTP_METHOD_ACL,
        HTTP_METHOD_REPORT,
        HTTP_METHOD_VERSION_CONTROL,
        HTTP_METHOD_CHECKIN,
        HTTP_METHOD_CHECKOUT,
        HTTP_METHOD_UNCHECKOUT,
        HTTP_METHOD_SEARCH,
        HTTP_METHOD_MKWORKSPACE,
        HTTP_METHOD_UPDATE,
        HTTP_METHOD_LABEL,
        HTTP_METHOD_MERGE,
        HTTP_METHOD_BASELINE_CONTROL,
        HTTP_METHOD_MKACTIVITY
    };

    uint8_t method;
    for (method = 1; method < sizeof(ajp13_methods); ++method) {
        if (ajp13_methods[method] == m) break;
    }
    return (method < sizeof(ajp13_methods)) ? method : 0;

  #endif
}


static uint32_t
ajp13_enc_request_headers (uint8_t * const x, uint32_t n, const request_st * const r)
{
    const array * const rqst_headers = &r->rqst_headers;
    const int add_content_length =
      (!light_btst(r->rqst_htags, HTTP_HEADER_CONTENT_LENGTH));
    /* num_headers */
    n = ajp13_enc_uint16(x, n, rqst_headers->used + add_content_length);
    if (0 == n) return n;
    /* request_headers */
    if (add_content_length) {
        /* (gw_backend.c sends 411 Length Required if Content-Length not
         *  provided and request body is being streamed to backend.  Add
         *  Content-Length if not provided and request body was collected.) */
        n = ajp13_enc_uint16(x, n, 0xA008);
        if (0 == n) return n;
        char buf[LI_ITOSTRING_LENGTH];
        n = ajp13_enc_string(x, n, buf,
                             li_itostrn(buf, sizeof(buf), r->reqbody_length));
        if (0 == n) return n;
    }
    for (uint32_t i = 0, num = rqst_headers->used; i < num; ++i) {
        const data_string * const ds = (data_string *)rqst_headers->data[i];
        uint8_t code = 0x00;
        switch (ds->ext) { /* map request header to ajp13 SC_REQ_* code */
          case HTTP_HEADER_ACCEPT:          code = 0x01; break;
          case HTTP_HEADER_ACCEPT_ENCODING: code = 0x03; break;
          case HTTP_HEADER_ACCEPT_LANGUAGE: code = 0x04; break;
          case HTTP_HEADER_AUTHORIZATION:   code = 0x05; break;
          case HTTP_HEADER_CONNECTION:      code = 0x06; break;
          case HTTP_HEADER_CONTENT_TYPE:    code = 0x07; break;
          case HTTP_HEADER_CONTENT_LENGTH:  code = 0x08; break;
          case HTTP_HEADER_COOKIE:          code = 0x09; break;
          case HTTP_HEADER_HOST:            code = 0x0B; break;
          case HTTP_HEADER_PRAGMA:          code = 0x0C; break;
          case HTTP_HEADER_REFERER:         code = 0x0D; break;
          case HTTP_HEADER_USER_AGENT:      code = 0x0E; break;
          case HTTP_HEADER_OTHER:
            if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Accept-Charset")))
                code = 0x02;
            else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Cookie2")))
                code = 0x0A;
            break;
          default:
            break;
        }

        n = (code)
          ? ajp13_enc_uint16(x, n, 0xA000 | code)
          : ajp13_enc_string(x, n, BUF_PTR_LEN(&ds->key));
        if (0 == n) return n;
        n = ajp13_enc_string(x, n, BUF_PTR_LEN(&ds->value));
        if (0 == n) return n;
    }
    return n;
}


#if 0
static uint32_t
ajp13_enc_req_attribute (uint8_t * const x, uint32_t n, const char * const k, const uint32_t klen, const char * const v, const uint32_t vlen)
{
    n = ajp13_enc_byte(x, n, 0x0A);
    if (0 == n) return n;
    n = ajp13_enc_string(x, n, k, klen);
    if (0 == n) return n;
    return ajp13_enc_string(x, n, v, vlen);
}
#endif


static uint32_t
ajp13_enc_attribute (uint8_t * const x, uint32_t n, const buffer * const b, uint8_t code)
{
    if (NULL == b) return n;
    n = ajp13_enc_byte(x, n, code);
    if (0 == n) return n;
    return ajp13_enc_string(x, n, BUF_PTR_LEN(b));
}


static uint32_t
ajp13_enc_attributes (uint8_t * const x, uint32_t n, request_st * const r)
{
    const buffer *vb;

    vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
    n = ajp13_enc_attribute(x, n, vb, 0x03);
    if (0 == n) return n;
    vb = http_header_env_get(r, CONST_STR_LEN("AUTH_TYPE"));
    n = ajp13_enc_attribute(x, n, vb, 0x04);
    if (0 == n) return n;

    if (!buffer_is_blank(&r->uri.query)) {
        n = ajp13_enc_attribute(x, n, &r->uri.query, 0x05);
        if (0 == n) return n;
    }

    if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https"))) {
        /* XXX: might have config to avoid this overhead if not needed */

        r->con->srv->request_env(r);

        vb = http_header_env_get(r, CONST_STR_LEN("SSL_CLIENT_CERT"));
        n = ajp13_enc_attribute(x, n, vb, 0x07);
        if (0 == n) return n;
        vb = http_header_env_get(r, CONST_STR_LEN("SSL_CIPHER"));
        n = ajp13_enc_attribute(x, n, vb, 0x08);
        if (0 == n) return n;
        vb = http_header_env_get(r, CONST_STR_LEN("SSL_CIPHER_USE_KEYSIZE"));
        n = ajp13_enc_attribute(x, n, vb, 0x0B);
        if (0 == n) return n;
    }

  #if 0
    /* req_attribute */ /*(what is often included by convention?)*/
    n = ajp13_enc_req_attribute(x, n, CONST_STR_LEN("REDIRECT_URI"),
                                      BUF_PTR_LEN(&r->target_orig));
    if (0 == n) return n;
    if (!buffer_is_equal(&r->target, &r->target_orig)) {
        n = ajp13_enc_req_attribute(x, n, CONST_STR_LEN("REDIRECT_URI"),
                                          BUF_PTR_LEN(&r->target));
        if (0 == n) return n;
    }
    /* Note: if this is extended to pass all env; must not pass HTTP_PROXY */
  #endif

  #if 1 /*(experimental) (???) (XXX: create separate config option?)*/
    /*(use mod_setenv to set value)*/
    vb = http_header_env_get(r, CONST_STR_LEN("AJP13_SECRET"));
    n = ajp13_enc_attribute(x, n, vb, 0x0C);
    if (0 == n) return n;
  #endif

    return n;
}


static uint32_t
ajp13_enc_server_name (uint8_t * const x, const uint32_t n, const request_st * const r)
{
  #if 0
    const data_string * const ds =
      array_get_element_klen(cgienv, CONST_STR_LEN("SERVER_NAME"));
    return (ds)
      ? ajp13_enc_string(x, n, BUF_PTR_LEN(&ds->value))
      : ajp13_enc_string(x, n, NULL, 0);
  #else
    /* copied and modified from http_cgi.c:http_cgi_headers() */
    uint32_t len = buffer_clen(r->server_name);
    if (len) {
        const char * const ptr = r->server_name->ptr;
        if (ptr[0] == '[') {
            const char *colon = strstr(ptr, "]:");
            if (colon) len = (colon + 1) - ptr;
        }
        else {
            const char *colon = strchr(ptr, ':');
            if (colon) len = colon - ptr;
        }
        return ajp13_enc_string(x, n, ptr, len);
    }
    else {
        /* SERVER_ADDR is generated in http_cgi_headers()
         * if the listen addr is, for example, a wildcard addr.
         * XXX: For now, just send an empty string in this case
         * instead of duplicating that code */
        return ajp13_enc_string(x, n, NULL, 0);
    }
  #endif
}


#if 0
static int
ajp13_env_add (void *venv, const char *k, size_t klen, const char *v, size_t vlen)
{
    /*(might be more efficient to store list rather than lighttpd array)*/
    array_set_key_value((array *)venv, k, klen, v, vlen);
    return 0;
}
#endif


static handler_t
ajp13_create_env (handler_ctx * const hctx)
{
    request_st * const r = hctx->r;
    /* AJP13_MAX_PACKET_SIZE currently matches default 8k chunk_buf_sz */
    buffer * const b =
      chunkqueue_prepend_buffer_open_sz(&hctx->wb, AJP13_MAX_PACKET_SIZE);

  #if 0 /*(elide if used only for SERVER_NAME, as is current case)*/
    /* Note: while it might be slightly more efficient to special-case ajp13
     * request creation here (reduce string copy), it is not worth duplicating
     * the logic centralized in http-header-glue.c:http_cgi_headers() */
    array * const cgienv = array_init(64);
  #endif

    do {
      #if 0
      #if 0 /* XXX: potential future extension */
        gw_host * const host = hctx->host;
        http_cgi_opts opts = {
          (hctx->gw_mode == FCGI_AUTHORIZER),
          host->break_scriptfilename_for_php,
          host->docroot,
          host->strip_request_uri
        };
      #else
        http_cgi_opts opts = { 0, 0, NULL, NULL };
      #endif
        if (0 != http_cgi_headers(r, &opts, ajp13_env_add, cgienv)) break;
      #endif

        uint32_t n = 6;
        uint8_t * const x = (uint8_t *)b->ptr;

        x[0] = 0x12;
        x[1] = 0x34;
        x[2] = 0;
        x[3] = 0;
        x[4] = 0x02; /* JK_AJP13_FORWARD_REQUEST */
        /* method */
        const uint8_t method_byte = ajp13_method_byte(r->http_method);
        if (0 == method_byte) break;
        x[5] = method_byte;
        /* protocol */
        const buffer * const proto = http_version_buf(r->http_version);
        n = ajp13_enc_string(x, n, BUF_PTR_LEN(proto));
        if (0 == n) break;
        /* req_uri */
        n = ajp13_enc_string(x, n, BUF_PTR_LEN(&r->uri.path));
        if (0 == n) break;
        /* remote_addr */
        n = ajp13_enc_string(x, n, BUF_PTR_LEN(r->dst_addr_buf));
        if (0 == n) break;
        /* remote_host *//*(skip DNS lookup)*/
        n = ajp13_enc_string(x, n, NULL, 0);
        if (0 == n) break;
        /* server_name */
        n = ajp13_enc_server_name(x, n, r);
        if (0 == n) break;
        /* server_port */
        unsigned short port = sock_addr_get_port(&r->con->srv_socket->addr);
        n = ajp13_enc_uint16(x, n, port);
        if (0 == n) break;
        /* is_ssl */
        n = ajp13_enc_byte(x,n,buffer_is_equal_string(&r->uri.scheme,
                                                      CONST_STR_LEN("https")));
        if (0 == n) break;
        /* num_headers */
        /* request_headers */
        n = ajp13_enc_request_headers(x, n, r);
        if (0 == n) break;
        /* attributes */
        n = ajp13_enc_attributes(x, n, r);
        if (0 == n) break;
        /* request_terminator */
        n = ajp13_enc_byte(x, n, 0xFF);
        if (0 == n) break;
        /* payload length (overwrite in header) */
        ajp13_enc_uint16_nc(x+2, n-4);

      #if 0
        array_free(cgienv);
      #endif

        /* (buffer is reallocated only if n is exactly AJP13_MAX_PACKET_SIZE) */
        /* (could check for one-off; limit to 8k-1 to avoid resizing buffer) */
        buffer_extend(b, n);/*(buffer_commit but extend +1 for '\0' as needed)*/
        chunkqueue_prepend_buffer_commit(&hctx->wb);
        hctx->wb_reqlen = (off_t)n;

        if (r->reqbody_length && hctx->gw_mode != GW_AUTHORIZER) {
            /*chunkqueue_append_chunkqueue(&hctx->wb, &r->reqbody_queue);*/
            if (r->reqbody_length > 0)
                hctx->wb_reqlen += r->reqbody_length;
                /* (eventual) (minimal) total request size, not necessarily
                 * including all ajp13 framing around content length yet */
            else /* as-yet-unknown total rqst sz (Transfer-Encoding: chunked)*/
                hctx->wb_reqlen = -hctx->wb_reqlen;
        }
        /* send single data packet, then wait for Get Body Chunk from backend */
        ajp13_stdin_append_n(hctx, AJP13_MAX_PACKET_SIZE-4);
        hctx->request_id = 0; /* overloaded value; see ajp13_stdin_append_n() */

        plugin_stats_inc("ajp13.requests");
        return HANDLER_GO_ON;
    } while (0);

  #if 0
    array_free(cgienv);
  #endif

    buffer_clear(b);
    chunkqueue_remove_finished_chunks(&hctx->wb);
    return http_status_set_err(r, 400); /* Bad Request */
}


static int
ajp13_expand_headers (buffer * const b, handler_ctx * const hctx, uint32_t plen)
{
    /* hctx->rb must contain at least plen content
     * and all chunks expected to be MEM_CHUNK */
    chunkqueue_compact_mem(hctx->rb, plen);

    /* expect all headers in single AJP13 packet;
     * not handling multiple AJP13_SEND_HEADERS packets
     * (expecting single MEM_CHUNK <= 8k with AJP13 headers) */

    chunk * const c = hctx->rb->first;
    uint8_t *ptr =
      (uint8_t *)c->mem->ptr + c->offset + 5; /* +5 for (4 hdr + 1 type) */
    plen -= 5;

    /* expand headers into buffer to be parsed by common code for responses
     * (parsing might be slightly faster if AJP13-specific, but then would have
     *  to duplicate all http_response_parse_headers() policy)*/

    do {
        uint32_t len;
        if (plen < 2) break;
        plen -= 2;
        buffer_append_string_len(b, CONST_STR_LEN("HTTP/1.1 "));
        buffer_append_int(b, ajp13_dec_uint16(ptr));
        ptr += 2;

        if (plen < 2) break;
        plen -= 2;
        len = ajp13_dec_uint16(ptr);
        ptr += 2;
        buffer_append_char(b, ' ');
        if (len != 65535) { /*(len == 65535 for empty string)*/
            if (plen < len+1) break;
            plen -= len+1; /* include -1 for ending '\0' */
            if (NULL != memchr(ptr, '\n', len)) return 0;
            if (len) buffer_append_string_len(b, (char *)ptr, len);
            ptr += len+1;
        }

        if (plen < 2) break;
        plen -= 2;
        ptr += 2;
        for (uint32_t nhdrs = ajp13_dec_uint16(ptr); nhdrs; --nhdrs) {
            if (plen < 2) break;
            plen -= 2;
            len = ajp13_dec_uint16(ptr);
            /*(len == 65535 should not happen for field name; error out below)*/
            ptr += 2;
            if (len >= 0xA000) {
                if (len == 0xA000 || len > 0xA00B) break;
                static const struct {
                  const char *h;
                  uint32_t len;
                } hcode[] = {
                  { CONST_STR_LEN("\nContent-Type: ")     }
                 ,{ CONST_STR_LEN("\nContent-Language: ") }
                 ,{ CONST_STR_LEN("\nContent-Length: ")   }
                 ,{ CONST_STR_LEN("\nDate: ")             }
                 ,{ CONST_STR_LEN("\nLast-Modified: ")    }
                 ,{ CONST_STR_LEN("\nLocation: ")         }
                 ,{ CONST_STR_LEN("\nSet-Cookie: ")       }
                 ,{ CONST_STR_LEN("\nSet-Cookie2: ")      }
                 ,{ CONST_STR_LEN("\nServlet-Engine: ")   }
                 ,{ CONST_STR_LEN("\nStatus: ")           }
                 ,{ CONST_STR_LEN("\nWWW-Authenticate: ") }
                };
                const uint32_t idx = (len & 0xF) - 1;
                buffer_append_string_len(b, hcode[idx].h, hcode[idx].len);
            }
            else {
                if (plen < len+1) break;
                plen -= len+1;
                if (NULL != memchr(ptr, '\n', len)) return 0;
                buffer_append_str3(b, CONST_STR_LEN("\n"),
                                   (char *)ptr, len,
                                   CONST_STR_LEN(": "));
                ptr += len+1;
            }

            if (plen < 2) break;
            plen -= 2;
            len = ajp13_dec_uint16(ptr);
            ptr += 2;
            if (len == 65535) continue; /*(empty string)*/
            if (plen < len+1) break;
            plen -= len+1;
            if (NULL != memchr(ptr, '\n', len)) return 0;
            buffer_append_string_len(b, (char *)ptr, len);
            ptr += len+1;
        }
    } while (0);

    buffer_append_string_len(b, CONST_STR_LEN("\n\n"));
    return 1;
}


enum {
  AJP13_FORWARD_REQUEST = 2
 ,AJP13_SEND_BODY_CHUNK = 3
 ,AJP13_SEND_HEADERS    = 4
 ,AJP13_END_RESPONSE    = 5
 ,AJP13_GET_BODY_CHUNK  = 6
 ,AJP13_SHUTDOWN        = 7
 ,AJP13_PING            = 8
 ,AJP13_CPONG_REPLY     = 9
 ,AJP13_CPING           = 10
};


__attribute_cold__
static handler_t
ajp13_recv_0(const request_st * const r, const handler_ctx * const hctx)
{
        if (-1 == hctx->request_id) /*(flag request ended)*/
            return HANDLER_FINISHED;
        if (!(fdevent_fdnode_interest(hctx->fdn) & FDEVENT_IN)
            && !(r->conf.stream_response_body
                 & FDEVENT_STREAM_RESPONSE_POLLRDHUP))
            return HANDLER_GO_ON;

        gw_backend_error_trace(hctx, r,
          "unexpected end-of-file (perhaps the ajp13 process died)");
        return HANDLER_ERROR;
}


static handler_t
ajp13_recv_parse_loop (request_st * const r, handler_ctx * const hctx)
{
    log_error_st * const errh = r->conf.errh;
    int fin = 0;
    do {
        uint8_t header[7];
        const off_t rblen = chunkqueue_length(hctx->rb);
        if (rblen < 5)
            break; /* incomplete packet header + min response payload */
        char *ptr = (char *)&header;
        uint32_t pklen = 5;
        if (chunkqueue_peek_data(hctx->rb, &ptr, &pklen, errh, 0) < 0)
            break;
        if (pklen != 5)
            break;
        if (ptr[0] != 'A' || ptr[1] != 'B') {
            log_error(errh, __FILE__, __LINE__,
              "invalid packet prefix sent from container:"
              "pid: %d socket: %s",
              hctx->proc->pid, hctx->proc->connection_name->ptr);
            return HANDLER_ERROR;
        }
        uint32_t plen = ajp13_dec_uint16((uint8_t *)ptr+2);
        if (plen > (unsigned int)rblen - 4)
            break; /* incomplete packet */

        switch(ptr[4]) {
        case AJP13_SEND_HEADERS:
            if (0 == r->resp_body_started) {
                if (plen < 3) {
                    log_error(errh, __FILE__, __LINE__,
                      "AJP13: headers packet received with invalid length");
                    return HANDLER_FINISHED;
                }

                buffer *hdrs = hctx->response;
                if (NULL == hdrs) {
                    hdrs = r->tmp_buf;
                    buffer_clear(hdrs);
                }

                if (!ajp13_expand_headers(hdrs, hctx, 4 + plen)) {
                    log_error(errh, __FILE__, __LINE__,
                      "AJP13: headers packet received with embedded newlines");
                    return http_status_set_err(r, 502); /* Bad Gateway */
                }

                if (HANDLER_GO_ON !=
                    http_response_parse_headers(r, &hctx->opts, hdrs)) {
                    hctx->send_content_body = 0;
                    return HANDLER_FINISHED;
                }
                if (0 == r->resp_body_started) {
                    if (!hctx->response) {
                        hctx->response = chunk_buffer_acquire();
                        buffer_copy_buffer(hctx->response, hdrs);
                    }
                }
                else if (hctx->gw_mode == GW_AUTHORIZER &&
                     (r->http_status == 0 || r->http_status == 200)) {
                    /* authorizer approved request; ignore the content here */
                    hctx->send_content_body = 0;
                    hctx->opts.authorizer |= /*(save response streaming flags)*/
                      (r->conf.stream_response_body
                       & (FDEVENT_STREAM_RESPONSE
                         |FDEVENT_STREAM_RESPONSE_BUFMIN)) << 1;
                    r->conf.stream_response_body &=
                      ~(FDEVENT_STREAM_RESPONSE|FDEVENT_STREAM_RESPONSE_BUFMIN);
                }
              #if 0
                else if ((r->conf.stream_response_body &
                           (FDEVENT_STREAM_RESPONSE|FDEVENT_STREAM_RESPONSE_BUFMIN))
                         && (   r->http_status == 204
                             || r->http_status == 205
                             || r->http_status == 304
                             || r->http_method == HTTP_METHOD_HEAD)) {
                    /* disable streaming to wait for backend protocol to signal
                     * end of response (prevent http_response_write_prepare()
                     * from short-circuiting and finishing responses without
                     * response body) */
                    r->conf.stream_response_body &=
                      ~(FDEVENT_STREAM_RESPONSE|FDEVENT_STREAM_RESPONSE_BUFMIN);
                }
              #endif
            }
            else {
                log_error(errh, __FILE__, __LINE__,
                  "AJP13: headers received after body started");
                /* ignore; discard packet */
            }
            break;
        case AJP13_SEND_BODY_CHUNK:
            if (0 == r->resp_body_started) { /* header not finished */
                log_error(errh, __FILE__, __LINE__,
                  "AJP13: body received before headers");
                return HANDLER_FINISHED;
            }
            else if (hctx->send_content_body) {
                ptr = (char *)&header;
                pklen = 7;
                if (chunkqueue_peek_data(hctx->rb, &ptr, &pklen, errh, 0) < 0)
                    return HANDLER_GO_ON;
                if (pklen != 7)
                    return HANDLER_GO_ON;
                uint32_t len = ajp13_dec_uint16((uint8_t *)ptr+5);
                if (0 == len) break; /*(skip "flush" packet of 0-length data)*/
                if (len > plen - 3) {
                    log_error(errh, __FILE__, __LINE__,
                      "AJP13: body packet received with invalid length");
                    return HANDLER_FINISHED;
                }
                chunkqueue_mark_written(hctx->rb, 7);
                if (0 == http_response_transfer_cqlen(r, hctx->rb, len)) {
                    if (len != plen - 3)
                        chunkqueue_mark_written(hctx->rb, plen - 3 - len);
                    continue;
                }
                else {
                    /* error writing to tempfile;
                     * truncate response or send 500 if nothing sent yet */
                    hctx->send_content_body = 0;
                    return HANDLER_FINISHED;
                }
            }
            else {
                /* ignore; discard packet */
            }
            break;
        case AJP13_GET_BODY_CHUNK:
                        /*assert(3 == plen);*/
            ptr = (char *)&header;
            pklen = 7;
            if (chunkqueue_peek_data(hctx->rb, &ptr, &pklen, errh, 0) < 0)
                return HANDLER_GO_ON;
            if (pklen != 7)
                return HANDLER_GO_ON;
            ajp13_stdin_append_n(hctx, ajp13_dec_uint16((uint8_t *)ptr+5));
            break;
        case AJP13_END_RESPONSE:
                        /*assert(2 == plen);*/
          #if 0
            ptr = (char *)&header;
            pklen = 6;
            if (chunkqueue_peek_data(hctx->rb, &ptr, &pklen, errh, 0) < 0)
                return HANDLER_GO_ON;
            if (pklen != 6)
                return HANDLER_GO_ON;
            if (ptr[5]) {
                /* future: add connection to pool if 'reuse' flag is set */
            }
          #endif
            hctx->request_id = -1; /*(flag request ended)*/
            fin = 1;
            break;
        case AJP13_CPONG_REPLY:
                        /*assert(1 == plen);*/
            break;
        default:
            log_error(errh, __FILE__, __LINE__,
              "AJP13: packet type not handled: %d", ptr[4]);
            /* discard packet */
            break;
        }

        chunkqueue_mark_written(hctx->rb, 4 + plen);
    } while (0 == fin);

    return 0 == fin ? HANDLER_GO_ON : HANDLER_FINISHED;
}


static handler_t
ajp13_recv_parse (request_st * const r, struct http_response_opts_t * const opts, buffer * const b, size_t n)
{
    handler_ctx * const hctx = (handler_ctx *)opts->pdata;
    if (0 == n) return ajp13_recv_0(r, hctx);
    /* future: might try to elide copying if buffer contains full packet(s)
     *         and prior read did not end in a partial packet */
    chunkqueue_append_buffer(hctx->rb, b);
    return ajp13_recv_parse_loop(r, hctx);
}


static handler_t
ajp13_check_extension (request_st * const r, void *p_d)
{
    if (NULL != r->handler_module) return HANDLER_GO_ON;

    plugin_config pconf;
    mod_ajp13_patch_config(r, p_d, &pconf);
    if (NULL == pconf.exts) return HANDLER_GO_ON;

    handler_t rc = gw_check_extension(r, &pconf, p_d, 1, 0);
    if (HANDLER_GO_ON != rc) return rc;

    const plugin_data * const p = p_d;
    if (r->handler_module == p->self) {
        handler_ctx *hctx = r->plugin_ctx[p->id];
        hctx->opts.backend = BACKEND_AJP13;
        hctx->opts.parse = ajp13_recv_parse;
        hctx->opts.pdata = hctx;
        hctx->stdin_append = ajp13_stdin_append;
        hctx->create_env = ajp13_create_env;
        if (!hctx->rb)
            hctx->rb = chunkqueue_init(NULL);
        else
            chunkqueue_reset(hctx->rb);
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_ajp13_plugin_init (plugin *p);
int mod_ajp13_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "ajp13";

    p->init         = gw_init;
    p->cleanup      = gw_free;
    p->set_defaults = mod_ajp13_set_defaults;
    p->handle_request_reset    = gw_handle_request_reset;
    p->handle_uri_clean        = ajp13_check_extension;
    p->handle_subrequest       = gw_handle_subrequest;
    p->handle_trigger          = gw_handle_trigger;
    p->handle_waitpid          = gw_handle_waitpid_cb;

    return 0;
}
