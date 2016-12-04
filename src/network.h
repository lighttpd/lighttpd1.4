#ifndef _NETWORK_H_
#define _NETWORK_H_
#include "first.h"

#include "server.h"

void network_accept_tcp_nagle_disable(int fd);

int network_write_chunkqueue(server *srv, connection *con, chunkqueue *c, off_t max_bytes);

int network_init(server *srv);
int network_close(server *srv);

#ifdef HAVE_I2P
int network_register_i2p_fdevent(server *srv, server_socket *srv_socket, i2p_listener *l);
#endif
int network_register_fdevents(server *srv);

#endif
