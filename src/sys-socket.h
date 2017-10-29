#ifndef WIN32_SOCKET_H
#define WIN32_SOCKET_H
#include "first.h"

#ifdef __WIN32

#include <winsock2.h>

#define ECONNRESET WSAECONNRESET
#define EINPROGRESS WSAEINPROGRESS
#define EALREADY WSAEALREADY
#define ECONNABORTED WSAECONNABORTED

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

#endif
