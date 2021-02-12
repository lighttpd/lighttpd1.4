#ifndef _HTTP_VHOST_H_
#define _HTTP_VHOST_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

__attribute_cold__
void http_vhostdb_dumbdata_reset (void);

typedef struct http_vhostdb_backend_t {
    const char *name;
    int(*query)(request_st *r, void *p_d, buffer *result);
    void *p_d;
} http_vhostdb_backend_t;

__attribute_cold__
const http_vhostdb_backend_t * http_vhostdb_backend_get (const buffer *name);

__attribute_cold__
void http_vhostdb_backend_set (const http_vhostdb_backend_t *backend);

#endif
