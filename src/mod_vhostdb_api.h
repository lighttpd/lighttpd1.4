/*
 * mod_vhostdb_api - virtual hosts mapping backend registration
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_MOD_VHOSTDB_API_H
#define INCLUDED_MOD_VHOSTDB_API_H
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
__attribute_pure__
const http_vhostdb_backend_t * http_vhostdb_backend_get (const buffer *name);

__attribute_cold__
void http_vhostdb_backend_set (const http_vhostdb_backend_t *backend);

#endif
