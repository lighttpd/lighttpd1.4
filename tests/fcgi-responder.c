/*
 * simple and trivial FastCGI server w/ hard-coded results for use in unit tests
 * - processes a single FastCGI request at a time (serially)
 * - listens on FCGI_LISTENSOCK_FILENO
 *   (socket on FCGI_LISTENSOCK_FILENO must be set up by invoker)
 *   expects to be started w/ listening socket already on FCGI_LISTENSOCK_FILENO
 * - expect recv data for request headers every 10ms or less
 * - no read timeouts for request body; might block reading request body
 * - no write timeouts; might block writing response
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SIGNAL      /* XXX: must be defined; config.h not included here */
#include <signal.h>
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#include "../src/compat/fastcgi.h"

static int finished;
static unsigned char buf[65536];


static void
fcgi_header (FCGI_Header * const header, const unsigned char type, const int request_id, const int contentLength, const unsigned char paddingLength)
{
    /*force_assert(contentLength <= FCGI_MAX_LENGTH);*/

    header->version         = FCGI_VERSION_1;
    header->type            = type;
    header->requestIdB1     = (request_id    >> 8) & 0xff;
    header->requestIdB0     =  request_id          & 0xff;
    header->contentLengthB1 = (contentLength >> 8) & 0xff;
    header->contentLengthB0 =  contentLength       & 0xff;
    header->paddingLength   = paddingLength;
    header->reserved        = 0;
}


static void
fcgi_unknown_type_rec (FCGI_UnknownTypeRecord * const rec, const int req_id, const unsigned char type)
{
    fcgi_header(&rec->header, FCGI_UNKNOWN_TYPE, req_id, sizeof(rec->header), 0);
    memset(&rec->body.reserved, 0, sizeof(rec->body.reserved));
    rec->body.type = type;
}


static void
fcgi_end_request_rec (FCGI_EndRequestRecord * const rec, const int req_id, const uint32_t appStatus, const unsigned char protocolStatus)
{
    fcgi_header(&rec->header, FCGI_END_REQUEST, req_id, sizeof(rec->header), 0);
    rec->body.appStatusB3    = (appStatus >> 24) & 0xff;
    rec->body.appStatusB2    = (appStatus >> 16) & 0xff;
    rec->body.appStatusB1    = (appStatus >>  8) & 0xff;
    rec->body.appStatusB0    =  appStatus        & 0xff;
    rec->body.protocolStatus = protocolStatus;
    rec->body.reserved[0]    = 0;
    rec->body.reserved[1]    = 0;
    rec->body.reserved[2]    = 0;
}


static int
fcgi_puts (const int req_id, const char * const str, size_t len, FILE * const stream)
{
    if (NULL == str) return -1;

    FCGI_Header header;

    for (size_t offset = 0, part; offset != len; offset += part) {
        part = len - offset > FCGI_MAX_LENGTH ? FCGI_MAX_LENGTH : len - offset;
        fcgi_header(&header, FCGI_STDOUT, req_id, part, 0);
        if (1 != fwrite(&header, sizeof(header), 1, stream))
            return -1;
        if (part != fwrite(str+offset, 1, part, stream))
            return -1;
    }

    return 0;
}


static const char *
fcgi_getenv(const unsigned char * const r, const uint32_t rlen, const char * const name, int nlen, int *len)
{
    /* simple search;
     * if many lookups are done, then should use more efficient data structure*/
    for (uint32_t i = 0; i < rlen; ) {
        int klen = r[i];
        if (!(r[i] & 0x80))
            ++i;
        else {
            klen = ((r[i] & ~0x80)<<24) | (r[i+1]<<16) | (r[i+2]<<8) | r[i+3];
            i += 4;
        }
        int vlen = r[i];
        if (!(r[i] & 0x80))
            ++i;
        else {
            vlen = ((r[i] & ~0x80)<<24) | (r[i+1]<<16) | (r[i+2]<<8) | r[i+3];
            i += 4;
        }

        if (klen == nlen && 0 == memcmp(r+i, name, klen)) {
            *len = vlen;
            return (const char *)r+i+klen;
        }

        i += klen + vlen;
    }

    char s[256];
    if (nlen > (int)sizeof(s)-1)
        return NULL;
    memcpy(s, name, nlen);
    s[nlen] = '\0';
    char *e = getenv(s);
    if (e) *len = strlen(e);
    return e;
}


static int
fcgi_process_params (FILE * const stream, int req_id, int role, unsigned char * const r, uint32_t rlen)
{
    const char *p = NULL;
    int len;

    /* (FCGI_STDIN currently ignored in these FastCGI unit test responses, so
     *  generate response here based on query string values (indicating test) */

    const char *cdata = NULL;

    if (NULL != (p = fcgi_getenv(r, rlen, "QUERY_STRING", 12, &len))) {
        if (2 == len && 0 == memcmp(p, "lf", 2))
            cdata = "Status: 200 OK\n\n";
        else if (4 == len && 0 == memcmp(p, "crlf", 4))
            cdata = "Status: 200 OK\r\n\r\n";
        else if (7 == len && 0 == memcmp(p, "slow-lf", 7)) {
            cdata = "Status: 200 OK\n";
            if (0 != fcgi_puts(req_id, cdata, strlen(cdata), stream))
                return -1;
            fflush(stdout);
            cdata = "\n";
        }
        else if (9 == len && 0 == memcmp(p, "slow-crlf", 9)) {
            cdata = "Status: 200 OK\r\n";
            if (0 != fcgi_puts(req_id, cdata, strlen(cdata), stream))
                return -1;
            fflush(stdout);
            cdata = "\r\n";
        }
        else if (10 == len && 0 == memcmp(p, "die-at-end", 10)) {
            cdata = "Status: 200 OK\r\n\r\n";
            finished = 1;
        }
        else if (role == FCGI_AUTHORIZER
                 && len >= 5 && 0 == memcmp(p, "auth-", 5)) {
            if (7 == len && 0 == memcmp(p, "auth-ok", 7))
                cdata = "Status: 200 OK\r\n\r\n";
            else if (8 == len && 0 == memcmp(p, "auth-var", 8)) {
                /* Status: 200 OK to allow access is implied
                 * if Status header is not included in response */
                cdata = "Variable-X-LIGHTTPD-FCGI-AUTH: "
                        "LighttpdTestContent\r\n\r\n";
                p = NULL;
            }
            else {
                cdata = "Status: 403 Forbidden\r\n\r\n";
                p = NULL;
            }
        }
        else
            cdata = "Status: 200 OK\r\n\r\n";
    }
    else {
        cdata = "Status: 500 Internal Foo\r\n\r\n";
        p = NULL;
    }

    if (cdata && 0 != fcgi_puts(req_id, cdata, strlen(cdata), stream))
        return -1;

    if (NULL == p)
        cdata = NULL;
    else if (len > 4 && 0 == memcmp(p, "env=", 4))
        cdata = fcgi_getenv(r, rlen, p+4, len-4, &len);
    else if (8 == len && 0 == memcmp(p, "auth-var", 8))
        cdata = fcgi_getenv(r, rlen, "X_LIGHTTPD_FCGI_AUTH", 20, &len);
    else {
        cdata = "test123";
        len = sizeof("test123")-1;
    }

    if (cdata && 0 != fcgi_puts(req_id, cdata, (size_t)len, stream))
        return -1;

    /*(XXX: always sending appStatus 0)*/
    FCGI_EndRequestRecord endrec;
    fcgi_end_request_rec(&endrec, req_id, 0, FCGI_REQUEST_COMPLETE);
    if (1 != fwrite(&endrec, sizeof(endrec), 1, stream))
        return -1; /* error writing FCGI_END_REQUEST; ignore */

    return -2; /* done */
}


static int
fcgi_dispatch_packet (FILE *stream, ssize_t offset, uint32_t len)
{
    FCGI_Header * const h = (FCGI_Header *)(buf+offset);
    int req_id = (h->requestIdB1 << 8) | h->requestIdB0;
    int type   = h->type;

    if (type > FCGI_MAXTYPE) {
        FCGI_UnknownTypeRecord unkrec;
        fcgi_unknown_type_rec(&unkrec, req_id, type);
        if (1 != fwrite(&unkrec, sizeof(unkrec), 1, stream))
            return -1;
        return 0;
    }

    if (0 == req_id) {
        /* not implemented: FCGI_GET_VALUES
         *                  FCGI_GET_VALUES_RESULT
         *                    FCGI_MAX_CONNS:  1
         *                    FCGI_MAX_REQS:   1
         *                    FCGI_MPXS_CONNS: 0
         *                  ...
         */
        return 0;
    }

    /* XXX: save role from FCGI_BEGIN_REQUEST; should keep independent state */
    static int role;

    switch (type) {
      case FCGI_BEGIN_REQUEST:
        role = (buf[offset+FCGI_HEADER_LEN] << 8)
             |  buf[offset+FCGI_HEADER_LEN+1];
        return 0;  /* ignore; could save req_id and match further packets */
      case FCGI_ABORT_REQUEST:
        return -2; /* done */
      case FCGI_END_REQUEST:
        return -1; /* unexpected; this server is not sending FastCGI requests */
      case FCGI_PARAMS:
        return fcgi_process_params(stream, req_id, role,
                                   buf+offset+FCGI_HEADER_LEN, len);
      case FCGI_STDIN:
        /* XXX: TODO read and discard request body
         * (currently ignored in these FastCGI unit tests)
         * (make basic effort to read body; ignore any timeouts or errors) */
        return -1; /* unexpected; this server is not expecting request body */
      case FCGI_STDOUT:
        return -1; /* unexpected; this server is not sending FastCGI requests */
      case FCGI_STDERR:
        return -1; /* unexpected; this server is not sending FastCGI requests */
      case FCGI_DATA:
        return -1; /* unexpected; this server is not sending FastCGI requests */
      case FCGI_GET_VALUES:
        return 0;  /* ignore; not implemented */
      case FCGI_GET_VALUES_RESULT:
        return 0;  /* ignore; not implemented */
      default:
        return -1; /* unexpected */
    }
}


static ssize_t
fcgi_recv_packet (FILE * const stream, ssize_t sz)
{
    ssize_t offset = 0;
    while (sz - offset >= (ssize_t)FCGI_HEADER_LEN) {
        FCGI_Header * const h = (FCGI_Header *)(buf+offset);
        uint32_t pad = h->paddingLength;
        uint32_t len = (h->contentLengthB1 << 8) | h->contentLengthB0;
        if (sz - offset < (ssize_t)(FCGI_HEADER_LEN + len + pad))
            break;
        int rc = fcgi_dispatch_packet(stream, offset, len);
        if (rc < 0)
            return rc;
        offset += (ssize_t)(FCGI_HEADER_LEN + len + pad);
    }
    return offset;
}


static int
fcgi_recv (const int fd, FILE * const stream)
{
    ssize_t rd = 0, offset = 0;

    /* XXX: remain blocking */
    /*fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);*/

    do {
        struct pollfd pfd = { fd, POLLIN, 0 };
        switch (poll(&pfd, 1, 10)) { /* 10ms timeout */
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

        if (rd > 0) {
            offset += rd;
            rd = fcgi_recv_packet(stream, offset);
            if (rd < 0)
                return (-2 == rd) ? 0 : -1; /*(-2 indicates done)*/
            if (rd > 0) {
                offset -= rd;
                if (offset)
                    memmove(buf, buf+rd, offset);
            }
        }
        else if (0 == rd || (errno != EAGAIN && errno != EWOULDBLOCK))
            break;
    } while (offset < (ssize_t)sizeof(buf));

    return -1;
}


int
main (void)
{
    int fd;
    fcntl(FCGI_LISTENSOCK_FILENO, F_SETFL,
          fcntl(FCGI_LISTENSOCK_FILENO, F_GETFL) & ~O_NONBLOCK);

  #ifdef HAVE_SIGNAL
    signal(SIGINT,  SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
  #endif

    do {
        fd = accept(FCGI_LISTENSOCK_FILENO, NULL, NULL);
        if (fd < 0)
            continue;
        /* XXX: skip checking FCGI_WEB_SERVER_ADDRS; not implemented */

        /* uses stdio to retain prior behavior of output buffering (default)
         * and flushing with fflush() at specific points */
        FILE *stream = fdopen(fd, "r+");
        if (NULL == stream) {
            close(fd);
            continue;
        }
        fcgi_recv(fd, stream);
        fflush(stream);
        fclose(stream);
    } while (fd > 0 ? !finished : errno == EINTR);

    return 0;
}
