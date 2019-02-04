#ifndef _NETWORK_H_
#define _NETWORK_H_
#include "first.h"

#include "base_decls.h"

struct server_socket;   /* declaration */

void network_accept_tcp_nagle_disable(int fd);

__attribute_cold__
int network_init(server *srv, int stdin_fd);

__attribute_cold__
int network_close(server *srv);

__attribute_cold__
int network_register_fdevents(server *srv);

__attribute_cold__
void network_unregister_sock(server *srv, struct server_socket *srv_socket);

#endif
