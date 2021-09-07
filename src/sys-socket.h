#ifndef WIN32_SOCKET_H
#define WIN32_SOCKET_H
#include "first.h"

#ifdef _WIN32

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#include <winsock2.h>
/* https://docs.microsoft.com/en-us/windows/win32/winsock/sockaddr-2 */
#include <ws2tcpip.h>
typedef uint32_t in_addr_t;
typedef unsigned short sa_family_t;
#define recv(a,b,c,d) recv((a),(char *)(b),(c),(d))
#define getsockopt(a,b,c,d,e) getsockopt((a),(b),(c),(char *)(d),(e))
#define setsockopt(a,b,c,d,e) setsockopt((a),(b),(c),(char *)(d),(e))
#ifndef S_IFSOCK /*(used by lighttpd to mark fd type)*/
#define S_IFSOCK 0140000
#endif

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#endif


#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN   16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN  46
#endif
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif

/* for solaris 2.5 and NetBSD 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#endif
