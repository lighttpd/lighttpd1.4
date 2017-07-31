#ifndef _INET_NTOP_CACHE_H_
#define _INET_NTOP_CACHE_H_
#include "first.h"

#include <sys/types.h>
#include "sys-socket.h"
#include "base_decls.h"
#include "buffer.h"

unsigned short sock_addr_get_port (const sock_addr *addr);

int sock_addr_inet_pton(sock_addr *addr, const char *str, int family, unsigned short port);

const char * sock_addr_inet_ntop(const sock_addr *addr, char *buf, socklen_t sz);
int sock_addr_inet_ntop_copy_buffer(buffer *b, const sock_addr *addr);
int sock_addr_inet_ntop_append_buffer(buffer *b, const sock_addr *addr);
int sock_addr_nameinfo_append_buffer(server *srv, buffer *b, const sock_addr *addr);

int sock_addr_from_buffer_hints_numeric(server *srv, sock_addr *addr, socklen_t *len, const buffer *b, int family, unsigned short port);
int sock_addr_from_str_hints(server *srv, sock_addr *addr, socklen_t *len, const char *str, int family, unsigned short port);
int sock_addr_from_str_numeric(server *srv, sock_addr *addr, const char *str);

const char * inet_ntop_cache_get_ip(server *srv, sock_addr *addr);

#endif
