#include "first.h"

#include "inet_ntop_cache.h"

#include "sys-socket.h"
#include <sys/types.h>
#include <string.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "sock_addr.h"


const char * inet_ntop_cache_get_ip(server *srv, sock_addr *addr) {
#ifdef HAVE_IPV6
	typedef struct {
		int family;
		union {
			struct in6_addr ipv6;
			struct in_addr  ipv4;
		} addr;
		char b2[INET6_ADDRSTRLEN + 1];
	} inet_ntop_cache_type;
	#define INET_NTOP_CACHE_MAX 4
	static inet_ntop_cache_type inet_ntop_cache[INET_NTOP_CACHE_MAX];
	static int ndx;

	int i;
	UNUSED(srv);
      #ifdef HAVE_SYS_UN_H
	if (addr->plain.sa_family == AF_UNIX) return addr->un.sun_path;
      #endif
	for (i = 0; i < INET_NTOP_CACHE_MAX; i++) {
		if (inet_ntop_cache[i].family == addr->plain.sa_family) {
			if (inet_ntop_cache[i].family == AF_INET6 &&
			    0 == memcmp(inet_ntop_cache[i].addr.ipv6.s6_addr, addr->ipv6.sin6_addr.s6_addr, 16)) {
				/* IPv6 found in cache */
				break;
			} else if (inet_ntop_cache[i].family == AF_INET &&
				   inet_ntop_cache[i].addr.ipv4.s_addr == addr->ipv4.sin_addr.s_addr) {
				/* IPv4 found in cache */
				break;

			}
		}
	}

	if (i == INET_NTOP_CACHE_MAX) {
		/* not found in cache */
		const char *s;

		i = ndx;
		if (++ndx >= INET_NTOP_CACHE_MAX) ndx = 0;
		s = sock_addr_inet_ntop(addr, inet_ntop_cache[i].b2, INET6_ADDRSTRLEN);
		if (NULL == s) return "";

		inet_ntop_cache[i].family = addr->plain.sa_family;

		if (inet_ntop_cache[i].family == AF_INET) {
			inet_ntop_cache[i].addr.ipv4.s_addr = addr->ipv4.sin_addr.s_addr;
		} else if (inet_ntop_cache[i].family == AF_INET6) {
			memcpy(inet_ntop_cache[i].addr.ipv6.s6_addr, addr->ipv6.sin6_addr.s6_addr, 16);
		}
	}

	return inet_ntop_cache[i].b2;
#else
	UNUSED(srv);
	if (addr->plain.sa_family == AF_INET) return inet_ntoa(addr->ipv4.sin_addr);
      #ifdef HAVE_SYS_UN_H
	if (addr->plain.sa_family == AF_UNIX) return addr->un.sun_path;
      #endif
	return "";
#endif
}
