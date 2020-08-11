/*
 * reqpool - request objects
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"
#include "reqpool.h"

#include <stdlib.h>

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "plugin.h"
#include "plugin_config.h"
#include "request.h"
#include "response.h"


void
request_init (request_st * const r, connection * const con, server * const srv)
{
    r->write_queue = chunkqueue_init();
    r->read_queue = chunkqueue_init();
    r->reqbody_queue = chunkqueue_init();

    r->resp_header_len = 0;
    r->loops_per_request = 0;
    r->con = con;
    r->tmp_buf = srv->tmp_buf;

    /* init plugin-specific per-request structures */
    r->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));
    force_assert(NULL != r->plugin_ctx);

    r->cond_cache = calloc(srv->config_context->used, sizeof(cond_cache_t));
    force_assert(NULL != r->cond_cache);

  #ifdef HAVE_PCRE_H
    if (srv->config_context->used > 1) {/*(save 128b per con if no conditions)*/
        r->cond_match =
          calloc(srv->config_context->used, sizeof(cond_match_t));
        force_assert(NULL != r->cond_match);
    }
  #endif
}


void
request_reset (request_st * const r)
{
    plugins_call_handle_request_reset(r);

    http_response_reset(r);

    r->resp_header_len = 0;
    r->loops_per_request = 0;

    r->http_method = HTTP_METHOD_UNSET;
    r->http_version = HTTP_VERSION_UNSET;

    /*con->proto_default_port = 80;*//*set to default in connection_accepted()*/

    r->http_host = NULL;
    r->reqbody_length = 0;
    r->te_chunked = 0;
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

    chunkqueue_reset(r->reqbody_queue);

    /* The cond_cache gets reset in response.c */
    /* config_cond_cache_reset(r); */
}


void
request_free (request_st * const r)
{
    chunkqueue_free(r->reqbody_queue);
    chunkqueue_free(r->write_queue);
    chunkqueue_free(r->read_queue);
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
    free(r->cond_match);

    /* note: r is not zeroed here and r is not freed here */
}
