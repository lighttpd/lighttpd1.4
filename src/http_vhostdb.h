#ifndef _HTTP_VHOST_H_
#define _HTTP_VHOST_H_
#include "first.h"

#include "base.h"

struct http_vhostdb_backend_t;

typedef struct http_vhostdb_backend_t {
    const char *name;
    int(*query)(server *srv, connection *con, void *p_d, buffer *result);
    void *p_d;
} http_vhostdb_backend_t;

const http_vhostdb_backend_t * http_vhostdb_backend_get (const buffer *name);
void http_vhostdb_backend_set (const http_vhostdb_backend_t *backend);

#endif
