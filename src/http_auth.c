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

int http_auth_md5_hex2bin (const char *md5hex, size_t len, unsigned char md5bin[16])
{
    /* validate and transform 32-byte MD5 hex string to 16-byte binary MD5 */
    if (32 != len) return -1; /*(Note: char *md5hex must be a 32-char string)*/
    for (int i = 0; i < 32; i+=2) {
        int hi = md5hex[i];
        int lo = md5hex[i+1];
        if ('0' <= hi && hi <= '9')                    hi -= '0';
        else if ((hi |= 0x20), 'a' <= hi && hi <= 'f') hi += -'a' + 10;
        else                                           return -1;
        if ('0' <= lo && lo <= '9')                    lo -= '0';
        else if ((lo |= 0x20), 'a' <= lo && lo <= 'f') lo += -'a' + 10;
        else                                           return -1;
        md5bin[(i >> 1)] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

#if 0
int http_auth_md5_hex2lc (char *md5hex)
{
    /* validate and transform 32-byte MD5 hex string to lowercase */
    int i;
    for (i = 0; md5hex[i]; ++i) {
        int c = md5hex[i];
        if ('0' <= c && c <= '9')                   continue;
        else if ((c |= 0x20), 'a' <= c && c <= 'f') md5hex[i] = c;
        else                                        return -1;
    }
    return (32 == i) ? 0 : -1; /*(Note: char *md5hex must be a 32-char string)*/
}
#endif
