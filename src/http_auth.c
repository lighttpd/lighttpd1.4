#include "first.h"

#include "http_auth.h"

#include <string.h>


static http_auth_backend_t http_auth_backends[8];

const http_auth_backend_t * http_auth_backend_get (const buffer *name)
{
    int i = 0;
    while (NULL != http_auth_backends[i].name
           && 0 != strcmp(http_auth_backends[i].name, name->ptr)) {
        ++i;
    }
    return http_auth_backends+i;
}

void http_auth_backend_set (const http_auth_backend_t *backend)
{
    unsigned int i = 0;
    while (NULL != http_auth_backends[i].name) ++i;
    /*(must resize http_auth_backends[] if too many different auth backends)*/
    force_assert(i<(sizeof(http_auth_backends)/sizeof(http_auth_backend_t))-1);
    memcpy(http_auth_backends+i, backend, sizeof(http_auth_backend_t));
}
