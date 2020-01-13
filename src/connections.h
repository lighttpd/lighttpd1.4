#ifndef _CONNECTIONS_H_
#define _CONNECTIONS_H_
#include "first.h"

#include "base.h"

__attribute_cold__
void connections_free(server *srv);

__attribute_cold__
void connection_graceful_shutdown_maint (server *srv);

void connection_periodic_maint (server *srv, time_t cur_ts);

connection * connection_accept(server *srv, server_socket *srv_sock);
connection * connection_accepted(server *srv, server_socket *srv_socket, sock_addr *cnt_addr, int cnt);

const char * connection_get_state(request_state_t state);
const char * connection_get_short_state(request_state_t state);
int connection_state_machine(connection *con);
handler_t connection_handle_read_post_state(request_st *r);

__attribute_cold__
handler_t connection_handle_read_post_error(request_st *r, int http_status);

int connection_write_chunkqueue(connection *con, chunkqueue *c, off_t max_bytes);
void connection_response_reset(request_st *r);

#define joblist_append(con) connection_list_append(&(con)->srv->joblist, (con))
void connection_list_append(connections *conns, connection *con);

#endif
