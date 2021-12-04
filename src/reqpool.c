/*
 * reqpool - request objects
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"
#include "reqpool.h"

#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "plugin.h"
#include "plugin_config.h"
#include "request.h"
#include "response.h"

#ifdef HAVE_PCRE2_H
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif


static const request_config *request_config_defaults;


void
request_config_set_defaults (const request_config *config_defaults)
{
    request_config_defaults = config_defaults;
}


__attribute_noinline__
void
request_config_reset (request_st * const r)
{
    memcpy(&r->conf, request_config_defaults, sizeof(request_config));
}


void
request_init_data (request_st * const r, connection * const con, server * const srv)
{
    chunkqueue_init(&r->write_queue);
    chunkqueue_init(&r->read_queue);
    chunkqueue_init(&r->reqbody_queue);

    r->http_method = HTTP_METHOD_UNSET;
    r->http_version = HTTP_VERSION_UNSET;
    r->resp_header_len = 0;
    r->loops_per_request = 0;
    r->con = con;
    r->tmp_buf = srv->tmp_buf;
    r->resp_body_scratchpad = -1;
    r->server_name = &r->uri.authority;

    /* init plugin-specific per-request structures */
    r->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));
    force_assert(NULL != r->plugin_ctx);

    r->cond_cache = calloc(srv->config_context->used, sizeof(cond_cache_t));
    force_assert(NULL != r->cond_cache);

  #ifdef HAVE_PCRE
    if (srv->config_captures) {
        r->cond_captures = srv->config_captures;
        r->cond_match = calloc(srv->config_captures, sizeof(cond_match_t *));
        force_assert(NULL != r->cond_match);
        r->cond_match_data = calloc(srv->config_captures, sizeof(cond_match_t));
        force_assert(NULL != r->cond_match_data);
    }
  #endif

    request_config_reset(r);
}


void
request_reset (request_st * const r)
{
    plugins_call_handle_request_reset(r);

    http_response_reset(r);

    r->loops_per_request = 0;
    r->keep_alive = 0;

    r->h2state = 0; /* H2_STATE_IDLE */
    r->h2id = 0;
    r->http_method = HTTP_METHOD_UNSET;
    r->http_version = HTTP_VERSION_UNSET;

    /*con->proto_default_port = 80;*//*set to default in connection_accepted()*/

    r->http_host = NULL;
    r->reqbody_length = 0;
    r->te_chunked = 0;
    r->resp_body_scratchpad = -1;
    r->rqst_htags = 0;

    r->async_callback = 0;
    r->error_handler_saved_status = 0;
    /*r->error_handler_saved_method = HTTP_METHOD_UNSET;*/
    /*(error_handler_saved_method value is not valid
     * unless error_handler_saved_status is set)*/

    buffer_clear(&r->uri.scheme);

    if (r->rqst_header_len <= BUFFER_MAX_REUSE_SIZE) {
        r->rqst_headers.used = 0;
        /* (Note: total header size not recalculated on HANDLER_COMEBACK
         *  even if other request headers changed during processing)
         * (While this might delay release of larger buffers, it is not
         *  expected to be the general case.  For those systems where it
         *  is a typical case, the larger buffers are likely to be reused) */
        buffer_clear(&r->target);
        buffer_clear(&r->pathinfo);
        /*buffer_clear(&r->target_orig);*/  /* reset later; used by mod_status*/
        /*buffer_clear(&r->uri.path);*/     /* reset later; used by mod_status*/
        /*buffer_clear(&r->uri.query);*/    /* reset later; used by mod_status*/
        /*buffer_clear(&r->uri.authority);*//* reset later; used by mod_status*/
        /*buffer_clear(&r->server_name_buf);*//* reset when used */
    }
    else {
        buffer_reset(&r->target);
        buffer_reset(&r->pathinfo);
        /*buffer_reset(&r->target_orig);*/  /* reset later; used by mod_status*/
        /*buffer_reset(&r->uri.path);*/     /* reset later; used by mod_status*/
        /*buffer_reset(&r->uri.query);*/    /* reset later; used by mod_status*/
        /*buffer_clear(&r->uri.authority);*//* reset later; used by mod_status*/
        /*buffer_clear(&r->server_name_buf);*//* reset when used */
        array_reset_data_strings(&r->rqst_headers);
    }
    r->rqst_header_len = 0;
    if (0 != r->env.used)
        array_reset_data_strings(&r->env);

    chunkqueue_reset(&r->reqbody_queue);
    /* r->read_queue, r->write_queue are shared with con for HTTP/1.1
     * but are different than con->read_queue, con->write_queue for HTTP/2
     * For HTTP/1.1, when &r->read_queue == con->read_queue, r->read_queue
     * is not cleared between requests since it might contain subsequent
     * requests.  (see also request_release()) */

    /* The cond_cache gets reset in response.c */
    /* config_cond_cache_reset(r); */

    request_config_reset(r);
}


#if 0 /* DEBUG_DEV */
__attribute_cold__
static void request_plugin_ctx_check(request_st * const r, server * const srv) {
    /* plugins should have cleaned themselves up */
    for (uint32_t i = 0, used = srv->plugins.used; i < used; ++i) {
        plugin *p = ((plugin **)(srv->plugins.ptr))[i];
        plugin_data_base *pd = p->data;
        if (!pd) continue;
        if (NULL == r->plugin_ctx[pd->id]
            && NULL == r->con->plugin_ctx[pd->id]) continue;
        log_error(r->conf.errh, __FILE__, __LINE__,
          "missing cleanup in %s", p->name);
        r->plugin_ctx[pd->id] = NULL;
        r->con->plugin_ctx[pd->id] = NULL;
    }
}
#endif


void
request_reset_ex (request_st * const r)
{
  #if 0 /* DEBUG_DEV */
    /* plugins should have cleaned themselves up (id range: [1,used]) */
    connection * const con = r->con;
    server * const srv = con->srv;
    for (uint32_t i = 1; i <= srv->plugins.used; ++i) {
        if (NULL != r->plugin_ctx[i] || NULL != con->plugin_ctx[i]) {
            request_plugin_ctx_check(r, srv);
            break;
        }
    }
  #endif

    r->server_name = &r->uri.authority;
    buffer_clear(&r->uri.authority);
    buffer_reset(&r->uri.path);
    buffer_reset(&r->uri.query);
    buffer_reset(&r->physical.path);
    buffer_reset(&r->physical.rel_path);
    buffer_reset(&r->target_orig);
    buffer_reset(&r->target);       /*(see comments in request_reset())*/
    buffer_reset(&r->pathinfo);     /*(see comments in request_reset())*/

    /* preserve; callers must handle changes */
    /*r->state = CON_STATE_CONNECT;*/
}


void
request_free_data (request_st * const r)
{
    chunkqueue_reset(&r->reqbody_queue);
    chunkqueue_reset(&r->write_queue);
    chunkqueue_reset(&r->read_queue);
    array_free_data(&r->rqst_headers);
    array_free_data(&r->resp_headers);
    array_free_data(&r->env);

    free(r->target.ptr);
    free(r->target_orig.ptr);

    free(r->uri.scheme.ptr);
    free(r->uri.authority.ptr);
    free(r->uri.path.ptr);
    free(r->uri.query.ptr);

    free(r->physical.doc_root.ptr);
    free(r->physical.path.ptr);
    free(r->physical.basedir.ptr);
    free(r->physical.etag.ptr);
    free(r->physical.rel_path.ptr);

    free(r->pathinfo.ptr);
    free(r->server_name_buf.ptr);

    free(r->plugin_ctx);
    free(r->cond_cache);
  #ifdef HAVE_PCRE
    if (r->cond_match_data) {
        for (int i = 0, used = r->cond_captures; i < used; ++i) {
          #ifdef HAVE_PCRE2_H
            if (r->cond_match_data[i].match_data)
                pcre2_match_data_free(r->cond_match_data[i].match_data);
          #else /* HAVE_PCRE_H */
            if (r->cond_match_data[i].matches)
                free(r->cond_match_data[i].matches);
          #endif
        }
        free(r->cond_match_data);
        free(r->cond_match);
    }
  #endif

    /* note: r is not zeroed here and r is not freed here */
}


/* linked list of (request_st *) cached for reuse */
static request_st *reqpool;


void
request_pool_free (void)
{
    while (reqpool) {
        request_st * const r = reqpool;
        reqpool = (request_st *)r->con; /*(reuse r->con as next ptr)*/
        request_free_data(r);
        free(r);
    }
}


void
request_release (request_st * const r)
{
    /* (For HTTP/1.1, r == &con->request, and so request_release() not called)
     * r->read_queue, r->write_queue are shared with con for HTTP/1.1
     * but are different than con->read_queue, con->write_queue for HTTP/2
     * For HTTP/1.1, when &r->read_queue == con->read_queue, r->read_queue
     * is not cleared between requests since it might contain subsequent
     * requests.  (see also request_reset()) */
    chunkqueue_reset(&r->read_queue);

    /*(r->cond_cache and r->cond_match are re-init in h2_init_stream())*/

    request_reset(r);
    request_reset_ex(r);
    r->state = CON_STATE_CONNECT;

    r->con = (connection *)reqpool; /*(reuse r->con as next ptr)*/
    reqpool = r;
}


request_st *
request_acquire (connection * const con)
{
    request_st *r = reqpool;
    if (r) {
        reqpool = (request_st *)r->con; /*(reuse r->con as next ptr)*/
    }
    else {
        r = calloc(1, sizeof(request_st));
        force_assert(r);
        request_init_data(r, con, con->srv);
    }

    r->con = con;
    r->tmp_buf = con->srv->tmp_buf;
    return r;
}
