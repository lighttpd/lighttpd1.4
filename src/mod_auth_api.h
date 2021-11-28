/*
 * mod_auth_api - HTTP auth backend registration, low-level shared funcs
 *
 * Fully-rewritten from original
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_MOD_AUTH_API_H
#define INCLUDED_MOD_AUTH_API_H
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"

__attribute_cold__
void http_auth_dumbdata_reset (void);

typedef enum http_auth_digest_type {
    HTTP_AUTH_DIGEST_NONE       = 0
   ,HTTP_AUTH_DIGEST_SESS       = 0x01
   ,HTTP_AUTH_DIGEST_MD5        = 0x02
   ,HTTP_AUTH_DIGEST_SHA256     = 0x04
   ,HTTP_AUTH_DIGEST_SHA512_256 = 0x08
} http_auth_digest_type;

#define HTTP_AUTH_DIGEST_MD5_BINLEN        16 /* MD5_DIGEST_LENGTH */
#define HTTP_AUTH_DIGEST_SHA256_BINLEN     32 /* SHA256_DIGEST_LENGTH */
#define HTTP_AUTH_DIGEST_SHA512_256_BINLEN 32 /* SHA512_256_DIGEST_LENGTH */

__attribute_const__
unsigned int http_auth_digest_len (int algo);

struct http_auth_scheme_t;
struct http_auth_require_t;
struct http_auth_backend_t;

typedef struct http_auth_require_t {
    const struct http_auth_scheme_t *scheme;
    const buffer *realm;
    const buffer *nonce_secret;
    uint8_t valid_user;
    uint8_t userhash;
    int algorithm;
    array user;
    array group;
    array host;
} http_auth_require_t;

__attribute_cold__
__attribute_malloc__
http_auth_require_t * http_auth_require_init (void);

__attribute_cold__
void http_auth_require_free (http_auth_require_t *require);

__attribute_pure__
int http_auth_match_rules (const http_auth_require_t *require, const char *user, const char *group, const char *host);

typedef struct http_auth_info_t {
    int dalgo;
    unsigned int dlen;
    const char *username;
    size_t ulen;
    const char *realm;
    size_t rlen;
    int userhash;
    /*(must be >= largest binary digest length accepted above)*/
    unsigned char digest[32];
    char userbuf[256];
} http_auth_info_t;

typedef struct http_auth_backend_t {
    const char *name;
    handler_t(*basic)(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
    handler_t(*digest)(request_st *r, void *p_d, http_auth_info_t *ai);
    void *p_d;
} http_auth_backend_t;

typedef struct http_auth_scheme_t {
    const char *name;
    handler_t(*checkfn)(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);
    /*(backend is arg only because auth.backend is separate config directive)*/
    void *p_d;
} http_auth_scheme_t;

__attribute_cold__
__attribute_pure__
const http_auth_scheme_t * http_auth_scheme_get (const buffer *name);

__attribute_cold__
void http_auth_scheme_set (const http_auth_scheme_t *scheme);

__attribute_cold__
__attribute_pure__
const http_auth_backend_t * http_auth_backend_get (const buffer *name);

__attribute_cold__
void http_auth_backend_set (const http_auth_backend_t *backend);

void http_auth_setenv(request_st *r, const char *username, size_t ulen, const char *auth_type, size_t alen);

#endif
