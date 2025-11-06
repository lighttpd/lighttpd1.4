#ifndef INCLUDED_LI_PLUGINS_H
#define INCLUDED_LI_PLUGINS_H
#include "first.h"

#include "base_decls.h"

__attribute_cold__
int plugins_load(server *srv);

__attribute_cold__
void plugins_free(server *srv);

#if 0 /*(handled differently in http_response_prepare())*/
handler_t plugins_call_handle_uri_clean(request_st *r);
handler_t plugins_call_handle_docroot(request_st *r);
handler_t plugins_call_handle_physical(request_st *r);
handler_t plugins_call_handle_subrequest_start(request_st *r);
#endif
handler_t plugins_call_handle_response_start(request_st *r);
handler_t plugins_call_handle_request_env(request_st *r);
handler_t plugins_call_handle_request_done(request_st *r);
handler_t plugins_call_handle_request_reset(request_st *r);

handler_t plugins_call_handle_connection_accept(connection *con);
handler_t plugins_call_handle_connection_shut_wr(connection *con);
handler_t plugins_call_handle_connection_close(connection *con);

void plugins_call_handle_trigger(server *srv);
handler_t plugins_call_handle_waitpid(server *srv, pid_t pid, int status);

__attribute_cold__
void plugins_call_handle_sighup(server *srv);

__attribute_cold__
handler_t plugins_call_init(server *srv);

__attribute_cold__
handler_t plugins_call_set_defaults(server *srv);

__attribute_cold__
handler_t plugins_call_worker_init(server *srv);

#endif
