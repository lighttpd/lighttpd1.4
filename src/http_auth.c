#include "first.h"

#include "http_auth.h"
#include "http_header.h"

#include <stdlib.h>
#include <string.h>


static http_auth_scheme_t http_auth_schemes[8];

const http_auth_scheme_t * http_auth_scheme_get (const buffer *name)
{
    int i = 0;
    while (NULL != http_auth_schemes[i].name
           && 0 != strcmp(http_auth_schemes[i].name, name->ptr)) {
        ++i;
    }
    return (NULL != http_auth_schemes[i].name) ? http_auth_schemes+i : NULL;
}

void http_auth_scheme_set (const http_auth_scheme_t *scheme)
{
    unsigned int i = 0;
    while (NULL != http_auth_schemes[i].name) ++i;
    /*(must resize http_auth_schemes[] if too many different auth schemes)*/
    force_assert(i<(sizeof(http_auth_schemes)/sizeof(http_auth_scheme_t))-1);
    memcpy(http_auth_schemes+i, scheme, sizeof(http_auth_scheme_t));
}


static http_auth_backend_t http_auth_backends[12];

const http_auth_backend_t * http_auth_backend_get (const buffer *name)
{
    int i = 0;
    while (NULL != http_auth_backends[i].name
           && 0 != strcmp(http_auth_backends[i].name, name->ptr)) {
        ++i;
    }
    return (NULL != http_auth_backends[i].name) ? http_auth_backends+i : NULL;
}

void http_auth_backend_set (const http_auth_backend_t *backend)
{
    unsigned int i = 0;
    while (NULL != http_auth_backends[i].name) ++i;
    /*(must resize http_auth_backends[] if too many different auth backends)*/
    force_assert(i<(sizeof(http_auth_backends)/sizeof(http_auth_backend_t))-1);
    memcpy(http_auth_backends+i, backend, sizeof(http_auth_backend_t));
}


int http_auth_const_time_memeq (const void *a, const void *b, const size_t len)
{
    /* constant time memory compare, unless compiler figures it out
     * (similar to mod_secdownload.c:const_time_memeq()) */
    /* caller should prefer http_auth_const_time_memeq_pad()
     * if not operating on digests, which have defined lengths */
    /* Note: some libs provide similar funcs, e.g.
     * OpenSSL:
     *   int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
     * Note: some OS provide similar funcs, e.g.
     * OpenBSD: int timingsafe_bcmp(const void *b1, const void *b2, size_t len)
     * NetBSD: int consttime_memequal(void *b1, void *b2, size_t len)
     */
    const volatile unsigned char * const av = (const unsigned char *)a;
    const volatile unsigned char * const bv = (const unsigned char *)b;
    int diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (av[i] ^ bv[i]);
    }
    return (0 == diff);
}


int http_auth_const_time_memeq_pad (const void *a, const size_t alen, const void *b, const size_t blen)
{
    /* constant time memory compare, unless compiler figures it out
     * (similar to mod_secdownload.c:const_time_memeq()) */
    /* round to next multiple of 64 to avoid potentially leaking exact
     * password length when subject to high precision timing attacks)
     * (not necessary when comparing digests, which have defined lengths)
     */
    /* Note: some libs provide similar funcs but might not obscure length, e.g.
     * OpenSSL:
     *   int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
     * Note: some OS provide similar funcs but might not obscure length, e.g.
     * OpenBSD: int timingsafe_bcmp(const void *b1, const void *b2, size_t len)
     * NetBSD: int consttime_memequal(void *b1, void *b2, size_t len)
     */
    const volatile unsigned char * const av = (const unsigned char *)a;
    const volatile unsigned char * const bv = (const unsigned char *)b;
    size_t lim = ((alen >= blen ? alen : blen) + 0x3F) & ~0x3F;
    int diff = (alen != blen); /*(never match if string length mismatch)*/
    for (size_t i = 0, j = 0; lim; --lim) {
        diff |= (av[i] ^ bv[j]);
        i += (i < alen);
        j += (j < blen);
    }
    return (0 == diff);
}


void http_auth_dumbdata_reset (void)
{
    memset(http_auth_schemes, 0, sizeof(http_auth_schemes));
    memset(http_auth_backends, 0, sizeof(http_auth_backends));
}


http_auth_require_t * http_auth_require_init (void)
{
    http_auth_require_t *require = calloc(1, sizeof(http_auth_require_t));
    force_assert(NULL != require);

    require->realm = buffer_init();
    require->valid_user = 0;
    require->user = array_init();
    require->group = array_init();
    require->host = array_init();

    return require;
}

void http_auth_require_free (http_auth_require_t * const require)
{
    buffer_free(require->realm);
    array_free(require->user);
    array_free(require->group);
    array_free(require->host);
    free(require);
}

/* (case-sensitive version of array.c:array_get_index(),
 *  and common case expects small num of allowed tokens,
 *  so it is reasonably performant to simply walk the array) */
static int http_auth_array_contains (const array * const a, const char * const k, const size_t klen)
{
    for (size_t i = 0, used = a->used; i < used; ++i) {
        if (buffer_is_equal_string(a->data[i]->key, k, klen)) {
            return 1;
        }
    }
    return 0;
}

int http_auth_match_rules (const http_auth_require_t * const require, const char * const user, const char * const group, const char * const host)
{
    if (NULL != user
        && (require->valid_user
            || http_auth_array_contains(require->user, user, strlen(user)))) {
        return 1; /* match */
    }

    if (NULL != group
        && http_auth_array_contains(require->group, group, strlen(group))) {
        return 1; /* match */
    }

    if (NULL != host
        && http_auth_array_contains(require->host, host, strlen(host))) {
        return 1; /* match */
    }

    return 0; /* no match */
}

void http_auth_setenv(connection *con, const char *username, size_t ulen, const char *auth_type, size_t alen) {
    http_header_env_set(con, CONST_STR_LEN("REMOTE_USER"), username, ulen);
    http_header_env_set(con, CONST_STR_LEN("AUTH_TYPE"), auth_type, alen);
}

unsigned int http_auth_digest_len (int algo)
{
    if (algo & (HTTP_AUTH_DIGEST_SHA256 | HTTP_AUTH_DIGEST_SHA512_256)) {
        /* HTTP_AUTH_DIGEST_SHA512_256_BINLEN */
        return HTTP_AUTH_DIGEST_SHA256_BINLEN;
    }
    if (algo & HTTP_AUTH_DIGEST_MD5) {
        return HTTP_AUTH_DIGEST_MD5_BINLEN;
    }

    return 0;
}

int http_auth_digest_hex2bin (const char *hexstr, size_t len, unsigned char *bin, size_t binlen)
{
    /* validate and transform 32-byte MD5 hex string to 16-byte binary MD5,
     * or 64-byte SHA-256 or SHA-512-256 hex string to 32-byte binary digest */
    if (len > (binlen << 1)) return -1;
    for (int i = 0, ilen = (int)len; i < ilen; i+=2) {
        int hi = hexstr[i];
        int lo = hexstr[i+1];
        if ('0' <= hi && hi <= '9')                    hi -= '0';
        else if ((hi |= 0x20), 'a' <= hi && hi <= 'f') hi += -'a' + 10;
        else                                           return -1;
        if ('0' <= lo && lo <= '9')                    lo -= '0';
        else if ((lo |= 0x20), 'a' <= lo && lo <= 'f') lo += -'a' + 10;
        else                                           return -1;
        bin[(i >> 1)] = (unsigned char)((hi << 4) | lo);
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
