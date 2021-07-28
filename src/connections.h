#ifndef _CONNECTIONS_H_
#define _CONNECTIONS_H_
#include "first.h"

#include "base_decls.h"

struct server_socket;   /* declaration */

void connections_pool_clear(server *srv);

__attribute_cold__
void connections_free(server *srv);

__attribute_cold__
void connection_graceful_shutdown_maint (server *srv);

void connection_periodic_maint (server *srv, unix_time64_t cur_ts);

int connection_send_1xx (request_st *r, connection *con);

connection * connection_accepted(server *srv, const struct server_socket *srv_socket, sock_addr *cnt_addr, int cnt);

void connection_state_machine(connection *con);

#endif
