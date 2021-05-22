/*
 * mod_auth_api - HTTP Auth backend registration, low-level shared funcs
 *
 * Fully-rewritten from original
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "mod_auth_api.h"
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


void http_auth_dumbdata_reset (void)
{
    memset(http_auth_schemes, 0, sizeof(http_auth_schemes));
    memset(http_auth_backends, 0, sizeof(http_auth_backends));
}


http_auth_require_t * http_auth_require_init (void)
{
    http_auth_require_t *require = calloc(1, sizeof(http_auth_require_t));
    force_assert(NULL != require);
    return require;
}

void http_auth_require_free (http_auth_require_t * const require)
{
    array_free_data(&require->user);
    array_free_data(&require->group);
    array_free_data(&require->host);
    free(require);
}

/* (case-sensitive version of array.c:array_get_index(),
 *  and common case expects small num of allowed tokens,
 *  so it is reasonably performant to simply walk the array) */
__attribute_pure__
static int http_auth_array_contains (const array * const a, const char * const k, const size_t klen)
{
    for (size_t i = 0, used = a->used; i < used; ++i) {
        if (buffer_is_equal_string(&a->data[i]->key, k, klen)) {
            return 1;
        }
    }
    return 0;
}

int http_auth_match_rules (const http_auth_require_t * const require, const char * const user, const char * const group, const char * const host)
{
    if (NULL != user
        && (require->valid_user
            || http_auth_array_contains(&require->user, user, strlen(user)))) {
        return 1; /* match */
    }

    if (NULL != group
        && http_auth_array_contains(&require->group, group, strlen(group))) {
        return 1; /* match */
    }

    if (NULL != host
        && http_auth_array_contains(&require->host, host, strlen(host))) {
        return 1; /* match */
    }

    return 0; /* no match */
}

void http_auth_setenv(request_st * const r, const char *username, size_t ulen, const char *auth_type, size_t alen) {
    http_header_env_set(r, CONST_STR_LEN("REMOTE_USER"), username, ulen);
    http_header_env_set(r, CONST_STR_LEN("AUTH_TYPE"), auth_type, alen);
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
