#ifndef _INET_NTOP_CACHE_H_
#define _INET_NTOP_CACHE_H_
#include "first.h"

#include "base.h"

int sock_addr_inet_pton(sock_addr *addr, const char *str, int family, unsigned short port);

const char * sock_addr_inet_ntop(const sock_addr *addr, char *buf, socklen_t sz);
int sock_addr_inet_ntop_copy_buffer(buffer *b, const sock_addr *addr);
int sock_addr_inet_ntop_append_buffer(buffer *b, const sock_addr *addr);

const char * inet_ntop_cache_get_ip(server *srv, sock_addr *addr);

#endif
