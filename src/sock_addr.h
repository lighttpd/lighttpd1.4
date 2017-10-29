#ifndef INCLUDED_SOCK_ADDR_H
#define INCLUDED_SOCK_ADDR_H
#include "first.h"

#include <sys/types.h>
#include "sys-socket.h"

#include "base_decls.h"
#include "buffer.h"


union sock_addr {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
#endif
	struct sockaddr_in ipv4;
#ifdef HAVE_SYS_UN_H
	struct sockaddr_un un;
#endif
	struct sockaddr plain;
};


static inline int sock_addr_get_family (const sock_addr *saddr);
static inline int sock_addr_get_family (const sock_addr *saddr) {
	return saddr->plain.sa_family;
}

unsigned short sock_addr_get_port (const sock_addr *saddr);
int sock_addr_is_addr_wildcard (const sock_addr *saddr);
int sock_addr_is_family_eq (const sock_addr *saddr1, const sock_addr *saddr2);
int sock_addr_is_port_eq (const sock_addr *saddr1, const sock_addr *saddr2);
int sock_addr_is_addr_eq (const sock_addr *saddr1, const sock_addr *saddr2);
/*int sock_addr_is_addr_port_eq (const sock_addr *saddr1, const sock_addr *saddr2);*/
int sock_addr_is_addr_eq_bits(const sock_addr *a, const sock_addr *b, int bits);
int sock_addr_assign (sock_addr *saddr, int family, unsigned short nport, const void *naddr);

int sock_addr_inet_pton(sock_addr *saddr, const char *str, int family, unsigned short port);

const char * sock_addr_inet_ntop(const sock_addr *saddr, char *buf, socklen_t sz);
int sock_addr_inet_ntop_copy_buffer(buffer *b, const sock_addr *saddr);
int sock_addr_inet_ntop_append_buffer(buffer *b, const sock_addr *saddr);
int sock_addr_stringify_append_buffer(buffer *b, const sock_addr *saddr);
int sock_addr_nameinfo_append_buffer(server *srv, buffer *b, const sock_addr *saddr);

int sock_addr_from_buffer_hints_numeric(server *srv, sock_addr *saddr, socklen_t *len, const buffer *b, int family, unsigned short port);
int sock_addr_from_str_hints(server *srv, sock_addr *saddr, socklen_t *len, const char *str, int family, unsigned short port);
int sock_addr_from_str_numeric(server *srv, sock_addr *saddr, const char *str);


#endif
