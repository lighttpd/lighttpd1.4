#include "first.h"

#include "inet_ntop_cache.h"
#include "base.h"
#include "log.h"

#include "sys-socket.h"
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <netdb.h>
#endif


unsigned short sock_addr_get_port (const sock_addr *addr)
{
    switch (addr->plain.sa_family) {
      case AF_INET:
        return ntohs(addr->ipv4.sin_port);
     #ifdef HAVE_IPV6
      case AF_INET6:
        return ntohs(addr->ipv6.sin6_port);
     #endif
      default: /* case AF_UNIX: */
        return 0;
    }
}


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


int sock_addr_nameinfo_append_buffer(server *srv, buffer *b, const sock_addr *addr)
{
    /*(this routine originates from
     * http-header-glue.c:http_response_redirect_to_directory())*/
    /*(note: name resolution here is *blocking*)*/
    if (AF_INET == addr->plain.sa_family) {
        struct hostent *he = gethostbyaddr((char *)&addr->ipv4.sin_addr,
                                           sizeof(struct in_addr), AF_INET);
        if (NULL == he) {
            log_error_write(srv, __FILE__, __LINE__,
                            "SdS", "NOTICE: gethostbyaddr failed: ",
                            h_errno, ", using ip-address instead");

            sock_addr_inet_ntop_append_buffer(b, addr);
        } else {
            buffer_append_string(b, he->h_name);
        }
    }
  #ifdef HAVE_IPV6
    else if (AF_INET6 == addr->plain.sa_family) {
        char hbuf[256];
        if (0 != getnameinfo((const struct sockaddr *)(&addr->ipv6),
                             sizeof(addr->ipv6),
                             hbuf, sizeof(hbuf), NULL, 0, 0)) {
            log_error_write(srv, __FILE__, __LINE__,
                            "SSS", "NOTICE: getnameinfo failed: ",
                            strerror(errno), ", using ip-address instead");

            buffer_append_string_len(b, CONST_STR_LEN("["));
            sock_addr_inet_ntop_append_buffer(b, addr);
            buffer_append_string_len(b, CONST_STR_LEN("]"));
        } else {
            buffer_append_string(b, hbuf);
        }
    }
  #endif
    else {
        log_error_write(srv, __FILE__, __LINE__,
                        "S", "ERROR: unsupported address-type");
        return -1;
    }

    return 0;
}


int sock_addr_from_str_hints(server *srv, sock_addr *addr, socklen_t *len, const char *str, int family, unsigned short port)
{
    /*(note: name resolution here is *blocking*)*/
    switch(family) {
      case AF_UNSPEC:
        if (0 == strcmp(str, "localhost")) {
            /*(special-case "localhost" to IPv4 127.0.0.1)*/
            memset(addr, 0, sizeof(struct sockaddr_in));
            addr->ipv4.sin_family = AF_INET;
            addr->ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr->ipv4.sin_port = htons(port);
            *len = sizeof(struct sockaddr_in);
            return 1;
        }
       #ifdef HAVE_IPV6
        else {
            struct addrinfo hints, *res;
            int r;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            if (0 != (r = getaddrinfo(str, NULL, &hints, &res))) {
                log_error_write(srv, __FILE__, __LINE__,
                                "sssss", "getaddrinfo failed: ",
                                gai_strerror(r), "'", str, "'");
                return 0;
            }

            memcpy(addr, res->ai_addr, res->ai_addrlen);
            freeaddrinfo(res);
            if (AF_INET6 == addr->plain.sa_family) {
                addr->ipv6.sin6_port = htons(port);
                *len = sizeof(struct sockaddr_in6);
            }
            else { /* AF_INET */
                addr->ipv4.sin_port = htons(port);
                *len = sizeof(struct sockaddr_in);
            }
            return 1;
        }
       #else
        /* fall through */
       #endif
     #ifdef HAVE_IPV6
      case AF_INET6:
        memset(addr, 0, sizeof(struct sockaddr_in6));
        addr->ipv6.sin6_family = AF_INET6;
        if (0 == strcmp(str, "::")) {
            addr->ipv6.sin6_addr = in6addr_any;
        }
        else if (0 == strcmp(str, "::1")) {
            addr->ipv6.sin6_addr = in6addr_loopback;
        }
        else {
            struct addrinfo hints, *res;
            int r;

            memset(&hints, 0, sizeof(hints));

            hints.ai_family   = AF_INET6;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            if (0 != (r = getaddrinfo(str, NULL, &hints, &res))) {
                hints.ai_family = AF_INET;
                if (
                  #ifdef EAI_ADDRFAMILY
                    EAI_ADDRFAMILY == r &&
                  #endif
                    0 == getaddrinfo(str, NULL, &hints, &res)) {
                    memcpy(addr, res->ai_addr, res->ai_addrlen);
                    addr->ipv4.sin_family = AF_INET;
                    addr->ipv4.sin_port = htons(port);
                    *len = sizeof(struct sockaddr_in);
                    /*assert(*len == res->ai_addrlen);*/
                    freeaddrinfo(res);
                    return 1;
                }

                log_error_write(srv, __FILE__, __LINE__,
                                "sssss", "getaddrinfo failed: ",
                                gai_strerror(r), "'", str, "'");

                return 0;
            }

            memcpy(addr, res->ai_addr, res->ai_addrlen);
            freeaddrinfo(res);
        }
        addr->ipv6.sin6_port = htons(port);
        *len = sizeof(struct sockaddr_in6);
        return 1;
     #endif
      case AF_INET:
        memset(addr, 0, sizeof(struct sockaddr_in));
        addr->ipv4.sin_family = AF_INET;
        if (0 == strcmp(str, "0.0.0.0")) {
            addr->ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        else if (0 == strcmp(str, "127.0.0.1")) {
            addr->ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        else {
          #ifdef HAVE_INET_PTON
            /*(reuse HAVE_INET_PTON for presence of getaddrinfo())*/
            struct addrinfo hints, *res;
            int r;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            if (0 != (r = getaddrinfo(str, NULL, &hints, &res))) {
                log_error_write(srv, __FILE__, __LINE__,
                                "sssss", "getaddrinfo failed: ",
                                gai_strerror(r), "'", str, "'");
                return 0;
            }

            memcpy(addr, res->ai_addr, res->ai_addrlen);
            freeaddrinfo(res);
          #else
            struct hostent *he = gethostbyname(str);
            if (NULL == he) {
                log_error_write(srv, __FILE__, __LINE__, "sds",
                                "gethostbyname failed:", h_errno, str);
                return 0;
            }

            if (he->h_addrtype != AF_INET) {
                log_error_write(srv, __FILE__, __LINE__, "sd",
                                "addr-type != AF_INET:", he->h_addrtype);
                return 0;
            }

            if (he->h_length != sizeof(struct in_addr)) {
                log_error_write(srv, __FILE__, __LINE__, "sd",
                                "addr-length != sizeof(in_addr):",he->h_length);
                return 0;
            }

            memcpy(&addr->ipv4.sin_addr.s_addr,he->h_addr_list[0],he->h_length);
          #endif
        }
        addr->ipv4.sin_port = htons(port);
        *len = sizeof(struct sockaddr_in);
        return 1;
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        memset(addr, 0, sizeof(struct sockaddr_un));
        addr->un.sun_family = AF_UNIX;
        {
            size_t hostlen = strlen(str) + 1;
            if (hostlen > sizeof(addr->un.sun_path)) {
                log_error_write(srv, __FILE__, __LINE__, "sS",
                                "unix socket filename too long:", str);
                /*errno = ENAMETOOLONG;*/
                return 0;
            }
            memcpy(addr->un.sun_path, str, hostlen);
          #if defined(SUN_LEN)
            *len = SUN_LEN(&addr->un);
          #else
            /* stevens says: */
            *len = hostlen + sizeof(addr->un.sun_family);
          #endif
        }
        return 1;
     #else
      case AF_UNIX:
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "unix domain sockets are not supported.");
        return 0;
     #endif
      default:
        log_error_write(srv, __FILE__, __LINE__, "sd",
                        "address family unsupported:", family);
        /*errno = EAFNOSUPPORT;*/
        return 0;
    }
}


int sock_addr_from_str_numeric(server *srv, sock_addr *addr, const char *str)
{
    /*(note: does not handle port if getaddrinfo() is not available)*/
    /*(note: getaddrinfo() is stricter than inet_aton() in what is accepted)*/
    /*(this routine originates from mod_extforward.c:ipstr_to_sockaddr()*/
  #ifdef HAVE_IPV6
    struct addrinfo hints, *addrlist = NULL;
    int result;

    /**
      * quoting $ man getaddrinfo
      *
      * NOTES
      *  AI_ADDRCONFIG, AI_ALL, and AI_V4MAPPED are available since glibc 2.3.3.
      *  AI_NUMERICSERV is available since glibc 2.3.4.
      */
   #ifndef AI_NUMERICSERV
   #define AI_NUMERICSERV 0
   #endif
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    errno = 0;
    result = getaddrinfo(str, NULL, &hints, &addrlist);

    if (result != 0) {
        log_error_write(srv, __FILE__, __LINE__, "SSSs(S)",
                        "could not parse ip address ", str, " because ",
                        gai_strerror(result), strerror(errno));
    } else if (addrlist == NULL) {
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "Problem in parsing ip address ", str,
                        ": succeeded, but no information returned");
        result = -1;
    } else switch (addrlist->ai_family) {
    case AF_INET:
        memcpy(&addr->ipv4, addrlist->ai_addr, sizeof(addr->ipv4));
        force_assert(AF_INET == addr->plain.sa_family);
        break;
    case AF_INET6:
        memcpy(&addr->ipv6, addrlist->ai_addr, sizeof(addr->ipv6));
        force_assert(AF_INET6 == addr->plain.sa_family);
        break;
    default:
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "Problem in parsing ip address ", str,
                        ": succeeded, but unknown family");
        result = -1;
        break;
    }

    freeaddrinfo(addrlist);
    return (0 == result);
  #else
    UNUSED(srv);
    addr->ipv4.sin_addr.s_addr = inet_addr(str);
    addr->plain.sa_family = AF_INET;
    return (addr->ipv4.sin_addr.s_addr != 0xFFFFFFFF);
  #endif
}


int sock_addr_from_buffer_hints_numeric(server *srv, sock_addr *addr, socklen_t *len, const buffer *b, int family, unsigned short port)
{
    /*(this routine originates from mod_fastcgi.c and mod_scgi.c)*/
    if (buffer_string_is_empty(b)) {
        /*(preserve existing behavior (for now))*/
        /*(would be better if initialized default when reading config)*/
        memset(&addr->ipv4, 0, sizeof(struct sockaddr_in));
        addr->ipv4.sin_family = AF_INET;
        addr->ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr->ipv4.sin_port = htons(port);
        *len = sizeof(struct sockaddr_in);
        return 1;
    }
    else if (1 == sock_addr_inet_pton(addr, b->ptr, family, port)) {
        *len = (family == AF_INET)
          ? sizeof(struct sockaddr_in)   /* family == AF_INET */
          : sizeof(struct sockaddr_in6); /* family == AF_INET6 */
        return 1;
    }
  #if defined(HAVE_IPV6) && defined(HAVE_INET_PTON)
    else if (family == AF_INET6) {
        log_error_write(srv, __FILE__, __LINE__, "sb",
                        "invalid IPv6 address literal:", b);
        return 0;
    }
  #endif
  #ifndef HAVE_INET_PTON /*(preserve existing behavior (for now))*/
    else {
        struct hostent *he = gethostbyname(b->ptr);
        if (NULL == he) {
            log_error_write(srv, __FILE__, __LINE__, "sdb",
                            "gethostbyname failed:", h_errno, b);
            return 0;
        }

        if (he->h_addrtype != AF_INET) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "addr-type != AF_INET:", he->h_addrtype);
            return 0;
        }

        if (he->h_length != sizeof(struct in_addr)) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "addr-length != sizeof(in_addr):",he->h_length);
            return 0;
        }

        memset(&addr->ipv4, 0, sizeof(struct sockaddr_in));
        memcpy(&addr->ipv4.sin_addr.s_addr, he->h_addr_list[0], he->h_length);
        addr->ipv4.sin_family = AF_INET;
        addr->ipv4.sin_port = htons(port);
        *len = sizeof(struct sockaddr_in);
    }
  #else
    UNUSED(srv);
  #endif

    return 0;
}


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
		s =
		inet_ntop(addr->plain.sa_family,
			  addr->plain.sa_family == AF_INET6 ?
			  (const void *) &(addr->ipv6.sin6_addr) :
			  (const void *) &(addr->ipv4.sin_addr),
			  inet_ntop_cache[i].b2, INET6_ADDRSTRLEN);
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
