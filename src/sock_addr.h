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


__attribute_pure__
static inline int sock_addr_get_family (const sock_addr *saddr);
static inline int sock_addr_get_family (const sock_addr *saddr) {
	return saddr->plain.sa_family;
}

__attribute_pure__
unsigned short sock_addr_get_port (const sock_addr *saddr);

__attribute_pure__
int sock_addr_is_addr_wildcard (const sock_addr *saddr);

__attribute_pure__
int sock_addr_is_family_eq (const sock_addr *saddr1, const sock_addr *saddr2);

__attribute_pure__
int sock_addr_is_port_eq (const sock_addr *saddr1, const sock_addr *saddr2);

__attribute_pure__
int sock_addr_is_addr_eq (const sock_addr *saddr1, const sock_addr *saddr2);

#if 0
__attribute_pure__
int sock_addr_is_addr_port_eq (const sock_addr *saddr1, const sock_addr *saddr2);
#endif

__attribute_pure__
int sock_addr_is_addr_eq_bits(const sock_addr * restrict a, const sock_addr * restrict b, int bits);

void sock_addr_set_port (sock_addr * restrict saddr, unsigned short port);

int sock_addr_assign (sock_addr * restrict saddr, int family, unsigned short nport, const void * restrict naddr);

int sock_addr_inet_pton(sock_addr * restrict saddr, const char * restrict str, int family, unsigned short port);

const char * sock_addr_inet_ntop(const sock_addr * restrict saddr, char * restrict buf, socklen_t sz);
int sock_addr_inet_ntop_copy_buffer(buffer * restrict b, const sock_addr * restrict saddr);
int sock_addr_inet_ntop_append_buffer(buffer * restrict b, const sock_addr * restrict saddr);
int sock_addr_stringify_append_buffer(buffer * restrict b, const sock_addr * restrict saddr);
int sock_addr_nameinfo_append_buffer(buffer * restrict b, const sock_addr * restrict saddr, log_error_st * restrict errh);

int sock_addr_from_buffer_hints_numeric(sock_addr * restrict saddr, socklen_t * restrict len, const buffer * restrict b, int family, unsigned short port, log_error_st * restrict errh);
int sock_addr_from_str_hints(sock_addr * restrict saddr, socklen_t * restrict len, const char * restrict str, int family, unsigned short port, log_error_st * restrict errh);
int sock_addr_from_str_numeric(sock_addr * restrict saddr, const char * restrict str, log_error_st * restrict errh);


#endif
