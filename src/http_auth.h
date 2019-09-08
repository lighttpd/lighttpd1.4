#ifndef _HTTP_AUTH_H_
#define _HTTP_AUTH_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"

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

unsigned int http_auth_digest_len (int algo);

struct http_auth_scheme_t;
struct http_auth_require_t;
struct http_auth_backend_t;

typedef struct http_auth_require_t {
    const struct http_auth_scheme_t *scheme;
    buffer *realm;
    int valid_user;
    int algorithm;
    array *user;
    array *group;
    array *host;
} http_auth_require_t;

http_auth_require_t * http_auth_require_init (void);
void http_auth_require_free (http_auth_require_t *require);
int http_auth_match_rules (const http_auth_require_t *require, const char *user, const char *group, const char *host);

typedef struct http_auth_info_t {
    int dalgo;
    unsigned int dlen;
    const char *username;
    size_t ulen;
    const char *realm;
    size_t rlen;
    /*(must be >= largest binary digest length accepted above)*/
    unsigned char digest[32];
} http_auth_info_t;

typedef struct http_auth_backend_t {
    const char *name;
    handler_t(*basic)(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
    handler_t(*digest)(server *srv, connection *con, void *p_d, http_auth_info_t *ai);
    void *p_d;
} http_auth_backend_t;

typedef struct http_auth_scheme_t {
    const char *name;
    handler_t(*checkfn)(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);
    /*(backend is arg only because auth.backend is separate config directive)*/
    void *p_d;
} http_auth_scheme_t;

const http_auth_scheme_t * http_auth_scheme_get (const buffer *name);
void http_auth_scheme_set (const http_auth_scheme_t *scheme);
const http_auth_backend_t * http_auth_backend_get (const buffer *name);
void http_auth_backend_set (const http_auth_backend_t *backend);

__attribute_pure__
int http_auth_const_time_memeq (const void *a, const void *b, size_t len);

__attribute_pure__
int http_auth_const_time_memeq_pad (const void *a, size_t alen, const void *b, size_t blen);

void http_auth_setenv(connection *con, const char *username, size_t ulen, const char *auth_type, size_t alen);

int http_auth_digest_hex2bin (const char *hexstr, size_t len, unsigned char *bin, size_t binlen);

#endif
