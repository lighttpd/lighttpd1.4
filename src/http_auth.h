#ifndef _HTTP_AUTH_H_
#define _HTTP_AUTH_H_
#include "first.h"

#include "base.h"

typedef struct http_auth_backend_t {
    const char *name;
    handler_t(*basic)(server *srv, connection *con, void *p_d, const buffer *username, const buffer *realm, const char *pw);
    handler_t(*digest)(server *srv, connection *con, void *p_d, const char *username, const char *realm, unsigned char HA1[16]);
    void *p_d;
} http_auth_backend_t;

const http_auth_backend_t * http_auth_backend_get (const buffer *name);
void http_auth_backend_set (const http_auth_backend_t *backend);

#endif
