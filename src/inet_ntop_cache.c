#include "first.h"

#include "inet_ntop_cache.h"
#include "base.h"

#include "sys-socket.h"
#include <sys/types.h>
#include <errno.h>
#include <string.h>


int sock_addr_inet_pton(sock_addr *addr, const char *str,
                        int family, unsigned short port)
{
    if (AF_INET == family) {
        memset(&addr->ipv4, 0, sizeof(struct sockaddr_in));
        addr->ipv4.sin_family  = AF_INET;
        addr->ipv4.sin_port    = htons(port);
      #if defined(HAVE_INET_ATON) /*(Windows does not provide inet_aton())*/
        return (0 != inet_aton(str, &addr->ipv4.sin_addr));
      #else
        return ((addr->ipv4.sin_addr.s_addr = inet_addr(str)) != INADDR_NONE);
      #endif
    }
  #ifdef HAVE_IPV6
    else if (AF_INET6 == family) {
        memset(&addr->ipv6, 0, sizeof(struct sockaddr_in6));
        addr->ipv6.sin6_family = AF_INET6;
        addr->ipv6.sin6_port   = htons(port);
        return inet_pton(AF_INET6, str, &addr->ipv6.sin6_addr);
    }
  #endif
    else {
        errno = EAFNOSUPPORT;
        return -1;
    }
}


const char * sock_addr_inet_ntop(const sock_addr *addr, char *buf, socklen_t sz)
{
    if (addr->plain.sa_family == AF_INET) {
      #if defined(HAVE_INET_PTON) /*(expect inet_ntop if inet_pton)*/
        return inet_ntop(AF_INET,(const void *)&addr->ipv4.sin_addr,buf,sz);
      #else /*(inet_ntoa() not thread-safe)*/
        return inet_ntoa(addr->ipv4.sin_addr);
      #endif
    }
  #ifdef HAVE_IPV6
    else if (addr->plain.sa_family == AF_INET6) {
        return inet_ntop(AF_INET6,(const void *)&addr->ipv6.sin6_addr,buf,sz);
    }
  #endif
  #ifdef HAVE_SYS_UN_H
    else if (addr->plain.sa_family == AF_UNIX) {
        return addr->un.sun_path;
    }
  #endif
    else {
        errno = EAFNOSUPPORT;
        return NULL;
    }
}


int sock_addr_inet_ntop_copy_buffer(buffer *b, const sock_addr *addr)
{
    /*(incur cost of extra copy to avoid potential extra memory allocation)*/
    char buf[UNIX_PATH_MAX];
    const char *s = sock_addr_inet_ntop(addr, buf, sizeof(buf));
    if (NULL == s) return -1; /*(buffer not modified if any error occurs)*/
    buffer_copy_string(b, s);
    return 0;
}


int sock_addr_inet_ntop_append_buffer(buffer *b, const sock_addr *addr)
{
    /*(incur cost of extra copy to avoid potential extra memory allocation)*/
    char buf[UNIX_PATH_MAX];
    const char *s = sock_addr_inet_ntop(addr, buf, sizeof(buf));
    if (NULL == s) return -1; /*(buffer not modified if any error occurs)*/
    buffer_append_string(b, s);
    return 0;
}


const char * inet_ntop_cache_get_ip(server *srv, sock_addr *addr) {
#ifdef HAVE_IPV6
	size_t ndx = 0, i;
	for (i = 0; i < INET_NTOP_CACHE_MAX; i++) {
		if (srv->inet_ntop_cache[i].ts != 0 && srv->inet_ntop_cache[i].family == addr->plain.sa_family) {
			if (srv->inet_ntop_cache[i].family == AF_INET6 &&
			    0 == memcmp(srv->inet_ntop_cache[i].addr.ipv6.s6_addr, addr->ipv6.sin6_addr.s6_addr, 16)) {
				/* IPv6 found in cache */
				break;
			} else if (srv->inet_ntop_cache[i].family == AF_INET &&
				   srv->inet_ntop_cache[i].addr.ipv4.s_addr == addr->ipv4.sin_addr.s_addr) {
				/* IPv4 found in cache */
				break;

			}
		}
	}

	if (i == INET_NTOP_CACHE_MAX) {
		/* not found in cache */
		const char *s;

		/* TODO: ndx is never modified above;
		 * inet_ntop_cache is effectively a 1-element cache */

		i = ndx;
		s =
		inet_ntop(addr->plain.sa_family,
			  addr->plain.sa_family == AF_INET6 ?
			  (const void *) &(addr->ipv6.sin6_addr) :
			  (const void *) &(addr->ipv4.sin_addr),
			  srv->inet_ntop_cache[i].b2, INET6_ADDRSTRLEN);
		if (NULL == s) return "";

		srv->inet_ntop_cache[i].ts = srv->cur_ts;
		srv->inet_ntop_cache[i].family = addr->plain.sa_family;

		if (srv->inet_ntop_cache[i].family == AF_INET) {
			srv->inet_ntop_cache[i].addr.ipv4.s_addr = addr->ipv4.sin_addr.s_addr;
		} else if (srv->inet_ntop_cache[i].family == AF_INET6) {
			memcpy(srv->inet_ntop_cache[i].addr.ipv6.s6_addr, addr->ipv6.sin6_addr.s6_addr, 16);
		}
	}

	return srv->inet_ntop_cache[i].b2;
#else
	UNUSED(srv);
	return inet_ntoa(addr->ipv4.sin_addr);
#endif
}
