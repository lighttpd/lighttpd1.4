/*
 * mod_echo - test/debugging module to echo request back to client as response
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * Note: module is hard-coded to handle requests to the exact uri-path: "/echo"
 *
 * Note: testing GET requests with Content-Length requires lighttpd.conf:
 *   server.http-parseopts += ("method-get-body" => "enable")
 */
#include "first.h"

#include <stdlib.h>

#include "base.h"
#include "fdevent.h"
#include "http_chunk.h"
#include "plugin.h"
#include "request.h"
#include "response.h"

typedef struct {
    PLUGIN_DATA;
} plugin_data;

INIT_FUNC(mod_echo_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

#if 1 /*(would be simpler if not supporting streaming w/ bufmin)*/

static handler_t mod_echo_request_body(request_st * const r) {
    chunkqueue * const cq = &r->reqbody_queue;
    chunkqueue_remove_finished_chunks(cq); /* unnecessary? */
    off_t cqlen = chunkqueue_length(cq);
    if ((r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
        && r->resp_body_started) {
        if (chunkqueue_length(&r->write_queue) > 65536 - 4096) {
            /* wait for more data to be sent to client */
            return HANDLER_WAIT_FOR_EVENT;
        }
        else {
            if (cqlen > 65536) {
                cqlen = 65536;
                joblist_append(r->con);
            }
        }
    }

    if (0 != http_chunk_transfer_cqlen(r, cq, (size_t)cqlen))
        return HANDLER_ERROR;

    if (cq->bytes_out == (off_t)r->reqbody_length) {
        /* sent all request body input */
        http_response_backend_done(r);
        return HANDLER_FINISHED;
    }

    cqlen = chunkqueue_length(cq);
    if (cq->bytes_in != (off_t)r->reqbody_length && cqlen < 65536 - 16384) {
        /*(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)*/
        if (!(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN)) {
            r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
            if (r->http_version <= HTTP_VERSION_1_1)
                r->con->is_readable = 1; /*trigger optimistic client read */
        }
    }
    return HANDLER_WAIT_FOR_EVENT;
}

SUBREQUEST_FUNC(mod_echo_handle_subrequest) {
    UNUSED(p_d);

    handler_t rc = mod_echo_request_body(r);
    if (rc != HANDLER_WAIT_FOR_EVENT) return rc;

    chunkqueue * const cq = &r->reqbody_queue;
    if (cq->bytes_in != (off_t)r->reqbody_length) {
        /*(64k - 4k to attempt to avoid temporary files
         * in conjunction with FDEVENT_STREAM_REQUEST_BUFMIN)*/
        if (chunkqueue_length(cq) > 65536 - 4096
            && (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN)) {
            r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
            return HANDLER_WAIT_FOR_EVENT;
        }
        else {
            rc = r->con->reqbody_read(r);
            if (rc != HANDLER_GO_ON) return rc;

            if (-1 == r->reqbody_length
                && !(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST))
                return HANDLER_WAIT_FOR_EVENT;
        }
    }

    return mod_echo_request_body(r);
}

#else /*(would be simpler if not supporting streaming w/ bufmin (above))*/

SUBREQUEST_FUNC(mod_echo_handle_subrequest) {
    UNUSED(p_d);

    handler_t rc = r->con->reqbody_read(r);
    if (rc != HANDLER_GO_ON) return rc;

    chunkqueue * const cq = &r->reqbody_queue;
    if (0 != http_chunk_transfer_cqlen(r, cq, chunkqueue_length(cq)))
        return HANDLER_ERROR;

    if (cq->bytes_out == (off_t)r->reqbody_length) {
        http_response_backend_done(r);
        return HANDLER_FINISHED;
    }
    return HANDLER_WAIT_FOR_EVENT;
}

#endif

URIHANDLER_FUNC(mod_echo_handle_uri_clean) {
    plugin_data *p = p_d;
    if (NULL == r->handler_module
        && buffer_eq_slen(&r->uri.path, CONST_STR_LEN("/echo"))) {
        r->handler_module = p->self;
        r->resp_body_started = 1;
        /* XXX: future: might echo request headers here */
        if (0 == r->reqbody_length) {
            r->resp_body_finished = 1;
            return HANDLER_FINISHED;
        }
    }
    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_echo_plugin_init(plugin *p);
int mod_echo_plugin_init(plugin *p) {
    p->version                 = LIGHTTPD_VERSION_ID;
    p->name                    = "echo";

    p->handle_uri_clean        = mod_echo_handle_uri_clean;
    p->handle_subrequest       = mod_echo_handle_subrequest;
    p->init                    = mod_echo_init;

    return 0;
}
