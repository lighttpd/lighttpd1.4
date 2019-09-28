#include "first.h"

#include "sock_addr.h"

#include "sys-socket.h"
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include "base.h"
#include "log.h"


unsigned short sock_addr_get_port (const sock_addr *saddr)
{
    switch (saddr->plain.sa_family) {
      case AF_INET:
        return ntohs(saddr->ipv4.sin_port);
     #ifdef HAVE_IPV6
      case AF_INET6:
        return ntohs(saddr->ipv6.sin6_port);
     #endif
     #ifdef HAVE_SYS_UN_H
     /*case AF_UNIX:*/
     #endif
      default:
        return 0;
    }
}


int sock_addr_is_addr_wildcard (const sock_addr *saddr)
{
    switch (saddr->plain.sa_family) {
      case AF_INET:
        return (saddr->ipv4.sin_addr.s_addr == INADDR_ANY); /*(htonl(0x0))*/
     #ifdef HAVE_IPV6
      case AF_INET6:
        return !memcmp(&saddr->ipv6.sin6_addr,&in6addr_any,sizeof(in6addr_any));
     #endif
     #ifdef HAVE_SYS_UN_H
     /*case AF_UNIX:*/
     #endif
      default:
        return 0;
    }
}


int sock_addr_is_family_eq (const sock_addr *saddr1, const sock_addr *saddr2)
{
    return saddr1->plain.sa_family == saddr2->plain.sa_family;
}


int sock_addr_is_port_eq (const sock_addr *saddr1, const sock_addr *saddr2)
{
    if (!sock_addr_is_family_eq(saddr1, saddr2)) return 0;
    switch (saddr1->plain.sa_family) {
      case AF_INET:
        return saddr1->ipv4.sin_port == saddr2->ipv4.sin_port;
     #ifdef HAVE_IPV6
      case AF_INET6:
        return saddr1->ipv6.sin6_port == saddr2->ipv6.sin6_port;
     #endif
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        return 1;
     #endif
      default:
        return 0;
    }
}


int sock_addr_is_addr_eq (const sock_addr *saddr1, const sock_addr *saddr2)
{
    if (!sock_addr_is_family_eq(saddr1, saddr2)) return 0;
    switch (saddr1->plain.sa_family) {
      case AF_INET:
        return saddr1->ipv4.sin_addr.s_addr == saddr2->ipv4.sin_addr.s_addr;
     #ifdef HAVE_IPV6
      case AF_INET6:
        return 0 == memcmp(&saddr1->ipv6.sin6_addr, &saddr2->ipv6.sin6_addr,
                           sizeof(struct in6_addr));
     #endif
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        return 0 == strcmp(saddr1->un.sun_path, saddr2->un.sun_path);
     #endif
      default:
        return 0;
    }
}


#if 0
int sock_addr_is_addr_port_eq (const sock_addr *saddr1, const sock_addr *saddr2)
{
    if (!sock_addr_is_family_eq(saddr1, saddr2)) return 0;
    switch (saddr1->plain.sa_family) {
      case AF_INET:
        return saddr1->ipv4.sin_port == saddr2->ipv4.sin_port
            && saddr1->ipv4.sin_addr.s_addr == saddr2->ipv4.sin_addr.s_addr;
     #ifdef HAVE_IPV6
      case AF_INET6:
        return saddr1->ipv6.sin6_port == saddr2->ipv6.sin6_port
            && 0 == memcmp(&saddr1->ipv6.sin6_addr, &saddr2->ipv6.sin6_addr,
                           sizeof(struct in6_addr));
     #endif
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        return 0 == strcmp(saddr1->un.sun_path, saddr2->un.sun_path);
     #endif
      default:
        return 0;
    }
}
#endif


int sock_addr_is_addr_eq_bits(const sock_addr *a, const sock_addr *b, int bits) {
    switch (a->plain.sa_family) {
      case AF_INET:
      {
        uint32_t nm; /* build netmask */
        if (bits > 32) bits = 32;
        nm = htonl(~((1u << (32 - (0 != bits ? bits : 32))) - 1));
        if (b->plain.sa_family == AF_INET) {
            return
              (a->ipv4.sin_addr.s_addr & nm) == (b->ipv4.sin_addr.s_addr & nm);
        }
       #ifdef HAVE_IPV6
        else if (b->plain.sa_family == AF_INET6
                 && IN6_IS_ADDR_V4MAPPED(&b->ipv6.sin6_addr)) {
          #ifdef s6_addr32
            in_addr_t x = b->ipv6.sin6_addr.s6_addr32[3];
          #else
            in_addr_t x;
            memcpy(&x, b->ipv6.sin6_addr.s6_addr+12, sizeof(in_addr_t));
          #endif
            return ((a->ipv4.sin_addr.s_addr & nm) == (x & nm));
        }
       #endif
        return 0;
      }
     #ifdef HAVE_IPV6
      case AF_INET6:
        if (bits > 128) bits = 128;
        if (b->plain.sa_family == AF_INET6) {
            uint8_t *c = (uint8_t *)&a->ipv6.sin6_addr.s6_addr[0];
            uint8_t *d = (uint8_t *)&b->ipv6.sin6_addr.s6_addr[0];
            int match;
            do {
                match = (bits >= 8)
                  ? *c++ == *d++
                  : (*c >> (8 - bits)) == (*d >> (8 - bits));
            } while (match && (bits -= 8) > 0);
            return match;
        }
        else if (b->plain.sa_family == AF_INET
                 && IN6_IS_ADDR_V4MAPPED(&a->ipv6.sin6_addr)) {
            uint32_t nm = bits < 128
              ? htonl(~(~0u >> (bits > 96 ? bits - 96 : 0)))
              : ~0u;
          #ifdef s6_addr32
            in_addr_t x = a->ipv6.sin6_addr.s6_addr32[3];
          #else
            in_addr_t x;
            memcpy(&x, a->ipv6.sin6_addr.s6_addr+12, sizeof(in_addr_t));
          #endif
            return ((x & nm) == (b->ipv4.sin_addr.s_addr & nm));
        }
        return 0;
     #endif
     #ifdef HAVE_SYS_UN_H
     /*case AF_UNIX:*/
     #endif
      default:
        return 0;
    }
}


int sock_addr_assign (sock_addr *saddr, int family, unsigned short nport, const void *naddr)
{
    switch (family) {
      case AF_INET:
        memset(&saddr->ipv4, 0, sizeof(struct sockaddr_in));
        saddr->ipv4.sin_family = AF_INET;
        saddr->ipv4.sin_port = nport;
        memcpy(&saddr->ipv4.sin_addr, naddr, 4);
        return 0;
     #ifdef HAVE_IPV6
      case AF_INET6:
        memset(&saddr->ipv6, 0, sizeof(struct sockaddr_in6));
        saddr->ipv6.sin6_family = AF_INET6;
        saddr->ipv6.sin6_port = nport;
        memcpy(&saddr->ipv6.sin6_addr, naddr, 16);
        return 0;
     #endif
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
      {
        size_t len = strlen((char *)naddr) + 1;
        if (len > sizeof(saddr->un.sun_path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memset(&saddr->un, 0, sizeof(struct sockaddr_un));
        saddr->un.sun_family = AF_UNIX;
        memcpy(saddr->un.sun_path, naddr, len);
        return 0;
      }
     #endif
      default:
        errno = EAFNOSUPPORT;
        return -1;
    }
}


int sock_addr_inet_pton(sock_addr *saddr, const char *str,
                        int family, unsigned short port)
{
    switch (family) {
      case AF_INET:
        memset(&saddr->ipv4, 0, sizeof(struct sockaddr_in));
        saddr->ipv4.sin_family  = AF_INET;
        saddr->ipv4.sin_port    = htons(port);
      #if defined(HAVE_INET_ATON) /*(Windows does not provide inet_aton())*/
        return (0 != inet_aton(str, &saddr->ipv4.sin_addr));
      #else
        return ((saddr->ipv4.sin_addr.s_addr = inet_addr(str)) != INADDR_NONE);
      #endif
     #ifdef HAVE_IPV6
      case AF_INET6:
        memset(&saddr->ipv6, 0, sizeof(struct sockaddr_in6));
        saddr->ipv6.sin6_family = AF_INET6;
        saddr->ipv6.sin6_port   = htons(port);
        return inet_pton(AF_INET6, str, &saddr->ipv6.sin6_addr);
     #endif
      default:
        errno = EAFNOSUPPORT;
        return -1;
    }
}


const char * sock_addr_inet_ntop(const sock_addr *saddr, char *buf, socklen_t sz)
{
    switch (saddr->plain.sa_family) {
      case AF_INET:
       #if defined(HAVE_INET_PTON) /*(expect inet_ntop if inet_pton)*/
        return inet_ntop(AF_INET,(const void *)&saddr->ipv4.sin_addr,buf,sz);
       #else /*(inet_ntoa() not thread-safe)*/
        return inet_ntoa(saddr->ipv4.sin_addr);
       #endif
     #ifdef HAVE_IPV6
      case AF_INET6:
        return inet_ntop(AF_INET6,(const void *)&saddr->ipv6.sin6_addr,buf,sz);
     #endif
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        return saddr->un.sun_path;
     #endif
      default:
        errno = EAFNOSUPPORT;
        return NULL;
    }
}


int sock_addr_inet_ntop_copy_buffer(buffer *b, const sock_addr *saddr)
{
    /*(incur cost of extra copy to avoid potential extra memory allocation)*/
    char buf[UNIX_PATH_MAX];
    const char *s = sock_addr_inet_ntop(saddr, buf, sizeof(buf));
    if (NULL == s) return -1; /*(buffer not modified if any error occurs)*/
    buffer_copy_string(b, s);
    return 0;
}


int sock_addr_inet_ntop_append_buffer(buffer *b, const sock_addr *saddr)
{
    /*(incur cost of extra copy to avoid potential extra memory allocation)*/
    char buf[UNIX_PATH_MAX];
    const char *s = sock_addr_inet_ntop(saddr, buf, sizeof(buf));
    if (NULL == s) return -1; /*(buffer not modified if any error occurs)*/
    buffer_append_string(b, s);
    return 0;
}

int sock_addr_stringify_append_buffer(buffer *b, const sock_addr *saddr)
{
    switch (saddr->plain.sa_family) {
      case AF_INET:
        if (0 != sock_addr_inet_ntop_append_buffer(b, saddr)) return -1;
        buffer_append_string_len(b, CONST_STR_LEN(":"));
        buffer_append_int(b, ntohs(saddr->ipv4.sin_port));
        return 0;
     #ifdef HAVE_IPV6
      case AF_INET6:
        buffer_append_string_len(b, CONST_STR_LEN("["));
        if (0 != sock_addr_inet_ntop_append_buffer(b, saddr)) {
          #ifdef __COVERITY__
            force_assert(buffer_string_length(b) > 0); /*(appended "[")*/
          #endif
            /* coverity[overflow_sink : FALSE] */
            buffer_string_set_length(b, buffer_string_length(b)-1);
            return -1;
        }
        buffer_append_string_len(b, CONST_STR_LEN("]"));
        buffer_append_string_len(b, CONST_STR_LEN(":"));
        buffer_append_int(b, ntohs(saddr->ipv6.sin6_port));
        return 0;
     #endif
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        buffer_append_string(b, saddr->un.sun_path);
        return 0;
     #endif
      default:
        return 0;
    }
}


int sock_addr_nameinfo_append_buffer(server *srv, buffer *b, const sock_addr *saddr)
{
    /*(this routine originates from
     * http-header-glue.c:http_response_redirect_to_directory())*/
    /*(note: name resolution here is *blocking*)*/
    switch (saddr->plain.sa_family) {
      case AF_INET:
      {
        struct hostent *he = gethostbyaddr((char *)&saddr->ipv4.sin_addr,
                                           sizeof(struct in_addr), AF_INET);
        if (NULL == he) {
            log_error_write(srv, __FILE__, __LINE__,
                            "SdS", "NOTICE: gethostbyaddr failed: ",
                            h_errno, ", using ip-address instead");

            sock_addr_inet_ntop_append_buffer(b, saddr);
        } else {
            buffer_append_string(b, he->h_name);
        }
        return 0;
      }
     #ifdef HAVE_IPV6
      case AF_INET6:
      {
        char hbuf[256];
        if (0 != getnameinfo((const struct sockaddr *)(&saddr->ipv6),
                             sizeof(saddr->ipv6),
                             hbuf, sizeof(hbuf), NULL, 0, 0)) {
            log_error_write(srv, __FILE__, __LINE__,
                            "SSS", "NOTICE: getnameinfo failed: ",
                            strerror(errno), ", using ip-address instead");

            buffer_append_string_len(b, CONST_STR_LEN("["));
            sock_addr_inet_ntop_append_buffer(b, saddr);
            buffer_append_string_len(b, CONST_STR_LEN("]"));
        } else {
            buffer_append_string(b, hbuf);
        }
        return 0;
      }
     #endif
      default:
        log_error_write(srv, __FILE__, __LINE__,
                        "S", "ERROR: unsupported address-type");
        return -1;
    }
}


int sock_addr_from_str_hints(server *srv, sock_addr *saddr, socklen_t *len, const char *str, int family, unsigned short port)
{
    /*(note: name resolution here is *blocking*)*/
    switch(family) {
      case AF_UNSPEC:
        if (0 == strcmp(str, "localhost")) {
            /*(special-case "localhost" to IPv4 127.0.0.1)*/
            memset(saddr, 0, sizeof(struct sockaddr_in));
            saddr->ipv4.sin_family = AF_INET;
            saddr->ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            saddr->ipv4.sin_port = htons(port);
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

            memcpy(saddr, res->ai_addr, res->ai_addrlen);
            freeaddrinfo(res);
            if (AF_INET6 == saddr->plain.sa_family) {
                saddr->ipv6.sin6_port = htons(port);
                *len = sizeof(struct sockaddr_in6);
            }
            else { /* AF_INET */
                saddr->ipv4.sin_port = htons(port);
                *len = sizeof(struct sockaddr_in);
            }
            return 1;
        }
       #else
        /* fall through */
       #endif
     #ifdef HAVE_IPV6
      case AF_INET6:
        memset(saddr, 0, sizeof(struct sockaddr_in6));
        saddr->ipv6.sin6_family = AF_INET6;
        if (0 == strcmp(str, "::")) {
            saddr->ipv6.sin6_addr = in6addr_any;
        }
        else if (0 == strcmp(str, "::1")) {
            saddr->ipv6.sin6_addr = in6addr_loopback;
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
                    memcpy(saddr, res->ai_addr, res->ai_addrlen);
                    saddr->ipv4.sin_family = AF_INET;
                    saddr->ipv4.sin_port = htons(port);
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

            memcpy(saddr, res->ai_addr, res->ai_addrlen);
            freeaddrinfo(res);
        }
        saddr->ipv6.sin6_port = htons(port);
        *len = sizeof(struct sockaddr_in6);
        return 1;
     #endif
      case AF_INET:
        memset(saddr, 0, sizeof(struct sockaddr_in));
        saddr->ipv4.sin_family = AF_INET;
        if (0 == strcmp(str, "0.0.0.0")) {
            saddr->ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        else if (0 == strcmp(str, "127.0.0.1")) {
            saddr->ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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

            memcpy(saddr, res->ai_addr, res->ai_addrlen);
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

            memcpy(&saddr->ipv4.sin_addr.s_addr,
                   he->h_addr_list[0], he->h_length);
          #endif
        }
        saddr->ipv4.sin_port = htons(port);
        *len = sizeof(struct sockaddr_in);
        return 1;
     #ifdef HAVE_SYS_UN_H
      case AF_UNIX:
        memset(saddr, 0, sizeof(struct sockaddr_un));
        saddr->un.sun_family = AF_UNIX;
        {
            size_t hostlen = strlen(str) + 1;
            if (hostlen > sizeof(saddr->un.sun_path)) {
                log_error_write(srv, __FILE__, __LINE__, "sS",
                                "unix socket filename too long:", str);
                /*errno = ENAMETOOLONG;*/
                return 0;
            }
            memcpy(saddr->un.sun_path, str, hostlen);
          #if defined(SUN_LEN)
            *len = SUN_LEN(&saddr->un)+1;
          #else
            *len = offsetof(struct sockaddr_un, sun_path) + hostlen;
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


int sock_addr_from_str_numeric(server *srv, sock_addr *saddr, const char *str)
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
        return result;
    } else if (addrlist == NULL) {
        log_error_write(srv, __FILE__, __LINE__, "SSS",
                        "Problem in parsing ip address ", str,
                        ": succeeded, but no information returned");
        return -1;
    } else switch (addrlist->ai_family) {
    case AF_INET:
        memcpy(&saddr->ipv4, addrlist->ai_addr, sizeof(saddr->ipv4));
        force_assert(AF_INET == saddr->plain.sa_family);
        break;
    case AF_INET6:
        memcpy(&saddr->ipv6, addrlist->ai_addr, sizeof(saddr->ipv6));
        force_assert(AF_INET6 == saddr->plain.sa_family);
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
    saddr->ipv4.sin_addr.s_addr = inet_addr(str);
    saddr->plain.sa_family = AF_INET;
    return (saddr->ipv4.sin_addr.s_addr != 0xFFFFFFFF);
  #endif
}


int sock_addr_from_buffer_hints_numeric(server *srv, sock_addr *saddr, socklen_t *len, const buffer *b, int family, unsigned short port)
{
    /*(this routine originates from mod_fastcgi.c and mod_scgi.c)*/
    if (buffer_string_is_empty(b)) {
        /*(preserve existing behavior (for now))*/
        /*(would be better if initialized default when reading config)*/
        memset(&saddr->ipv4, 0, sizeof(struct sockaddr_in));
        saddr->ipv4.sin_family = AF_INET;
        saddr->ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        saddr->ipv4.sin_port = htons(port);
        *len = sizeof(struct sockaddr_in);
        return 1;
    }
    else if (1 == sock_addr_inet_pton(saddr, b->ptr, family, port)) {
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

        memset(&saddr->ipv4, 0, sizeof(struct sockaddr_in));
        memcpy(&saddr->ipv4.sin_addr.s_addr, he->h_addr_list[0], he->h_length);
        saddr->ipv4.sin_family = AF_INET;
        saddr->ipv4.sin_port = htons(port);
        *len = sizeof(struct sockaddr_in);
    }
  #else
    UNUSED(srv);
  #endif

    return 0;
}
