#include "first.h"

#include "sock_addr_cache.h"

#include "sys-socket.h"
#include <string.h>

#include "buffer.h"
#include "sock_addr.h"


int sock_addr_cache_inet_ntop_copy_buffer(buffer * const restrict b, const sock_addr * const restrict saddr)
{
  #define NTOP_CACHE_MAX 4
    static int ndx4;
    static struct { struct in_addr  ipv4;       } ntop4_cache[NTOP_CACHE_MAX];
    static struct { char s[INET_ADDRSTRLEN+1];  } ntop4_strs[NTOP_CACHE_MAX];
  #ifdef HAVE_IPV6
    static int ndx6;
    static struct { struct in6_addr ipv6;       } ntop6_cache[NTOP_CACHE_MAX];
    static struct { char s[INET6_ADDRSTRLEN+1]; } ntop6_strs[NTOP_CACHE_MAX];
  #endif
    switch (saddr->plain.sa_family) {
      case AF_INET:
        for (int i = 0; i < NTOP_CACHE_MAX; ++i) {
            if (ntop4_cache[i].ipv4.s_addr == saddr->ipv4.sin_addr.s_addr) {
                buffer_copy_string(b, ntop4_strs[i].s);
                return 0;
            }
        }
        break;
     #ifdef HAVE_IPV6
      case AF_INET6:
        for (int i = 0; i < NTOP_CACHE_MAX; ++i) {
            if (0 == memcmp(ntop6_cache[i].ipv6.s6_addr,
                            saddr->ipv6.sin6_addr.s6_addr, 16)) {
                buffer_copy_string(b, ntop6_strs[i].s);
                return 0;
            }
        }
        break;
     #endif
      default:
        break;
    }

    if (0 != sock_addr_inet_ntop_copy_buffer(b, saddr)) {
        buffer_blank(b);
        return -1;
    }

    switch (saddr->plain.sa_family) {
      case AF_INET:
        ntop4_cache[ndx4].ipv4.s_addr = saddr->ipv4.sin_addr.s_addr;
        memcpy(ntop4_strs+ndx4, b->ptr, buffer_clen(b)+1);
        if (++ndx4 == NTOP_CACHE_MAX) ndx4 = 0;
        break;
     #ifdef HAVE_IPV6
      case AF_INET6:
        memcpy(ntop6_cache[ndx6].ipv6.s6_addr,saddr->ipv6.sin6_addr.s6_addr,16);
        memcpy(ntop6_strs+ndx6, b->ptr, buffer_clen(b)+1);
        if (++ndx6 == NTOP_CACHE_MAX) ndx6 = 0;
        break;
     #endif
      default:
        break;
    }
    return 0;
}
