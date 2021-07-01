/*
 * simple and trivial SCGI server with hard-coded results for use in unit tests
 * - listens on STDIN_FILENO (socket on STDIN_FILENO must be set up by caller)
 * - processes a single SCGI request at a time
 * - arbitrary limitation: reads request headers netstring up to 64k in size
 * - expect recv data for request headers netstring every 25ms or less (or fail)
 * - no read timeouts for request body; might block reading request body
 * - no write timeouts; might block writing response
 * - no retry if partial send
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define _CRT_SECURE_NO_WARNINGS
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4267)
#pragma warning(disable:5105) /* warning in winbase.h; good job MS */
#endif
#endif

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#else
#include <io.h>
#include <winsock2.h>
#include <basetsd.h> /* SSIZE_T */
#define ssize_t SSIZE_T
#define poll WSAPoll
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int finished;
static char buf[65536];


#ifdef _WIN32
static int
sock_nb_set (SOCKET fd, unsigned int nb)
{
    u_long l = nb;
    return ioctlsocket(fd, FIONBIO, &l);
}
#else
static int
sock_nb_set (int fd, unsigned int nb)
{
    return nb
      ? fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) |  O_NONBLOCK)
      : fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
}
#endif


static char *
scgi_getenv(char *r, const unsigned long rlen, const char * const name)
{
    /* simple search;
     * if many lookups are done, then should use more efficient data structure*/
    char * const end = r+rlen;
    char *z;
    const size_t len = strlen(name);
    do {
        if (0 == strcmp(r, name)) return r+len+1;

        z = memchr(r, '\0', (size_t)(end-r));
        if (NULL == z) return NULL;
        z = memchr(z+1, '\0', (size_t)(end-r));
        if (NULL == z) return NULL;
        r = z+1;
    } while (r < end);
    return NULL;
}


#ifdef _WIN32
static void
scgi_process (const SOCKET fd)
#else
static void
scgi_process (const int fd)
#endif
{
    ssize_t rd = 0, offset = 0;
    char *p = NULL, *r;
    unsigned long rlen;
    long long cl;

    sock_nb_set(fd, 1);

    do {
        struct pollfd pfd = { fd, POLLIN, 0 };
        switch (poll(&pfd, 1, 25)) { /* 25ms timeout */
          default: /* 1; the only pfd has revents */
            break;
          case -1: /* error */
          case  0: /* timeout */
            pfd.revents |= POLLERR;
            break;
        }
        if (!(pfd.revents & POLLIN))
            break;
        do {
            rd = recv(fd, buf+offset, sizeof(buf)-offset, MSG_DONTWAIT);
        }
      #ifdef _WIN32
        while (rd < 0 && WSAGetLastError() == WSAEINTR);
      #else
        while (rd < 0 && errno == EINTR);
      #endif
        if (rd > 0)
            offset += rd;
        else if (0 == rd) {
            p = memchr(buf, ':', offset);
            break;
        }
      #ifdef _WIN32
        else if (WSAGetLastError() == WSAEWOULDBLOCK)
      #else
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
      #endif
            continue;
        else
            break;
    } while (NULL == (p = memchr(buf,':',offset)) && offset < 21);
    if (NULL == p)
        return; /* timeout or error receiving start of netstring */
    rlen = strtoul(buf, &p, 10);
    if (*buf == '-' || *p != ':' || p == buf || rlen == ULONG_MAX)
        return; /* invalid netstring (and rlen == ULONG_MAX is too long)*/
    if (rlen > sizeof(buf) - (p - buf) - 2)
        return; /* netstring longer than arbitrary limit we accept here */
    rlen += (unsigned long)(p - buf) + 2;

    while ((ssize_t)rlen < offset) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        switch (poll(&pfd, 1, 25)) { /* 25ms timeout */
          default: /* 1; the only pfd has revents */
            break;
          case -1: /* error */
          case  0: /* timeout */
            pfd.revents |= POLLERR;
            break;
        }
        if (!(pfd.revents & POLLIN))
            break;
        do {
            rd = recv(fd, buf+offset, sizeof(buf)-offset, MSG_DONTWAIT);
        } while (rd < 0 && errno == EINTR);
        if (rd > 0)
            offset += rd;
        else if (0 == rd)
            break;
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        else
            break;
    }
    if (offset < (ssize_t)rlen)
        return; /* timeout or error receiving netstring */
    if (buf[rlen-1] != ',')
        return; /* invalid netstring */
    rlen -= (unsigned long)(p - buf) + 2;
    r = p+1;

    /* not checking for empty headers in SCGI request (empty values allowed) */

    /* SCGI request must contain "SCGI" header with value "1" */
    p = scgi_getenv(r, rlen, "SCGI");
    if (NULL == p || p[0] != '1' || p[1] != '\0')
        return; /* missing or invalid SCGI header */

    /* CONTENT_LENGTH must be first header in SCGI request; always required */
    if (0 != strcmp(r, "CONTENT_LENGTH"))
        return; /* missing CONTENT_LENGTH */

    errno = 0;
    cl = strtoll(r+sizeof("CONTENT_LENGTH"), &p, 10);
    if (*p != '\0' || p == r+sizeof("CONTENT_LENGTH") || cl < 0 || 0 != errno)
        return; /* invalid CONTENT_LENGTH */

    sock_nb_set(fd, 0);

    /* read,discard request body (currently ignored in these SCGI unit tests)
     * (make basic effort to read body; ignore any timeouts or errors here) */
    cl -= (offset - (r+rlen+1 - buf));
    while (cl > 0) {
        char x[8192];
        do {
            rd = recv(fd, x, (cl>(long long)sizeof(x)?sizeof(x):(size_t)cl), 0);
        } while (rd < 0 && errno == EINTR);
        if (rd <= 0)
            break;
        cl -= rd;
    }

    /*(similar to fcgi-responder.c:fcgi_process_params())*/
    const char *cdata = NULL;
    if (NULL != (p = scgi_getenv(r, rlen, "QUERY_STRING"))) {
        if (0 == strcmp(p, "lf"))
            cdata = "Status: 200 OK\n\n";
        else if (0 == strcmp(p, "crlf"))
            cdata = "Status: 200 OK\r\n\r\n";
        else if (0 == strcmp(p, "slow-lf")) {
            cdata = "Status: 200 OK\n";
            send(fd, cdata, strlen(cdata), MSG_NOSIGNAL);
            cdata = "\n";
        }
        else if (0 == strcmp(p,"slow-crlf")) {
            cdata = "Status: 200 OK\r\n";
            send(fd, cdata, strlen(cdata), MSG_NOSIGNAL);
            cdata = "\r\n";
        }
        else if (0 == strcmp(p, "die-at-end")) {
            cdata = "Status: 200 OK\r\n\r\n";
            finished = 1;
        }
        else
            cdata = "Status: 200 OK\r\n\r\n";
    }
    else {
        cdata = "Status: 500 Internal Foo\r\n\r\n";
        p = NULL;
    }

    /*(note: *not* buffering to send response header and body together)*/

    if (cdata) send(fd, cdata, strlen(cdata), MSG_NOSIGNAL);

    if (NULL == p)
        cdata = NULL;
    else if (0 == strncmp(p, "env=", 4))
        cdata = scgi_getenv(r, rlen, p+4);
    else
        cdata = "test123";

    if (cdata) send(fd, cdata, strlen(cdata), MSG_NOSIGNAL);
}


int
main (void)
{
  #ifdef _WIN32

    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (0 != WSAStartup(wVersionRequested, &wsaData))
        return -1;

    SOCKET lfd = (SOCKET)GetStdHandle(STD_INPUT_HANDLE);
    sock_nb_set(lfd, 0);

    SOCKET fd;
    do {
        fd = accept(lfd, NULL, NULL);
        if (fd == INVALID_SOCKET)
            continue;
        scgi_process(fd);
    } while (fd != INVALID_SOCKET
             ? 0 == closesocket(fd) && !finished
             : WSAGetLastError() == WSAEINTR);

    WSACleanup();
    return 0;

  #else

    int fd;
    fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) & ~O_NONBLOCK);
    close(STDOUT_FILENO); /*(so that accept() returns fd to STDOUT_FILENO)*/

    do {
        fd = accept(STDIN_FILENO, NULL, NULL);
        if (fd < 0)
            continue;
        assert(fd == STDOUT_FILENO);
        scgi_process(fd);
    } while (fd > 0 ? 0 == close(fd) && !finished : errno == EINTR);

    return 0;

  #endif

}
