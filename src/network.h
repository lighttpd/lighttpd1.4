#ifndef _NETWORK_H_
#define _NETWORK_H_
#include "first.h"

#include "server.h"

void network_accept_tcp_nagle_disable(int fd);

int network_init(server *srv, int stdin_fd);
int network_close(server *srv);

int network_register_fdevents(server *srv);
void network_unregister_sock(server *srv, server_socket *srv_socket);

#endif
