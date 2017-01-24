#include "first.h"

#include "http_vhostdb.h"

#include <string.h>


static http_vhostdb_backend_t http_vhostdb_backends[8];

void http_vhostdb_dumbdata_reset (void)
{
    memset(http_vhostdb_backends, 0, sizeof(http_vhostdb_backends));
}

const http_vhostdb_backend_t * http_vhostdb_backend_get (const buffer *name)
{
    int i = 0;
    while (NULL != http_vhostdb_backends[i].name
           && 0 != strcmp(http_vhostdb_backends[i].name, name->ptr)) {
        ++i;
    }
    return (NULL != http_vhostdb_backends[i].name)
      ? http_vhostdb_backends+i
      : NULL;
}

void http_vhostdb_backend_set (const http_vhostdb_backend_t *backend)
{
    unsigned int i = 0;
    while (NULL != http_vhostdb_backends[i].name) ++i;
    /*(must resize http_vhostdb_backends[] if too many different backends)*/
    force_assert(
      i < (sizeof(http_vhostdb_backends)/sizeof(http_vhostdb_backend_t))-1);
    memcpy(http_vhostdb_backends+i, backend, sizeof(http_vhostdb_backend_t));
}
