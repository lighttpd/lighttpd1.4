#include "first.h"


/*(htpasswd)*/
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#elif defined(__linux__)
/* linux needs _XOPEN_SOURCE */
# define _XOPEN_SOURCE
#endif

#if defined(HAVE_LIBCRYPT) && !defined(HAVE_CRYPT)
/* always assume crypt() is present if we have -lcrypt */
# define HAVE_CRYPT
#endif

#include "sys-crypto.h"
#ifdef USE_OPENSSL_CRYPTO
#include <openssl/md4.h>
#endif

#include "safe_memclear.h"
/*(htpasswd)*/


#include "base.h"
#include "plugin.h"
#include "http_auth.h"
#include "log.h"

#include "algo_sha1.h"
#include "base64.h"
#include "md5.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * htdigest, htpasswd, plain auth backends
 */

typedef struct {
    buffer *auth_plain_groupfile;
    buffer *auth_plain_userfile;
    buffer *auth_htdigest_userfile;
    buffer *auth_htpasswd_userfile;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

static handler_t mod_authn_file_htdigest_digest(server *srv, connection *con, void *p_d, http_auth_info_t *ai);
static handler_t mod_authn_file_htdigest_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
static handler_t mod_authn_file_plain_digest(server *srv, connection *con, void *p_d, http_auth_info_t *ai);
static handler_t mod_authn_file_plain_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
static handler_t mod_authn_file_htpasswd_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_file_init) {
    static http_auth_backend_t http_auth_backend_htdigest =
      { "htdigest", mod_authn_file_htdigest_basic, mod_authn_file_htdigest_digest, NULL };
    static http_auth_backend_t http_auth_backend_htpasswd =
      { "htpasswd", mod_authn_file_htpasswd_basic, NULL, NULL };
    static http_auth_backend_t http_auth_backend_plain =
      { "plain", mod_authn_file_plain_basic, mod_authn_file_plain_digest, NULL };
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_auth_backend_htdigest */
    http_auth_backend_htdigest.p_d = p;
    http_auth_backend_set(&http_auth_backend_htdigest);

    /* register http_auth_backend_htpasswd */
    http_auth_backend_htpasswd.p_d = p;
    http_auth_backend_set(&http_auth_backend_htpasswd);

    /* register http_auth_backend_plain */
    http_auth_backend_plain.p_d = p;
    http_auth_backend_set(&http_auth_backend_plain);

    return p;
}

FREE_FUNC(mod_authn_file_free) {
    plugin_data *p = p_d;

    UNUSED(srv);

    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        size_t i;
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (NULL == s) continue;

            buffer_free(s->auth_plain_groupfile);
            buffer_free(s->auth_plain_userfile);
            buffer_free(s->auth_htdigest_userfile);
            buffer_free(s->auth_htpasswd_userfile);

            free(s);
        }
        free(p->config_storage);
    }

    free(p);

    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_authn_file_set_defaults) {
    plugin_data *p = p_d;
    size_t i;

    config_values_t cv[] = {
        { "auth.backend.plain.groupfile",   NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
        { "auth.backend.plain.userfile",    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { "auth.backend.htdigest.userfile", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
        { "auth.backend.htpasswd.userfile", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 3 */
        { NULL,                             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        data_config const* config = (data_config const*)srv->config_context->data[i];
        plugin_config *s;

        s = calloc(1, sizeof(plugin_config));
        s->auth_plain_groupfile = buffer_init();
        s->auth_plain_userfile = buffer_init();
        s->auth_htdigest_userfile = buffer_init();
        s->auth_htpasswd_userfile = buffer_init();

        cv[0].destination = s->auth_plain_groupfile;
        cv[1].destination = s->auth_plain_userfile;
        cv[2].destination = s->auth_htdigest_userfile;
        cv[3].destination = s->auth_htpasswd_userfile;

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_authn_file_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH(auth_plain_groupfile);
    PATCH(auth_plain_userfile);
    PATCH(auth_htdigest_userfile);
    PATCH(auth_htpasswd_userfile);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.plain.groupfile"))) {
                PATCH(auth_plain_groupfile);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.plain.userfile"))) {
                PATCH(auth_plain_userfile);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.htdigest.userfile"))) {
                PATCH(auth_htdigest_userfile);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.htpasswd.userfile"))) {
                PATCH(auth_htpasswd_userfile);
            }
        }
    }

    return 0;
}
#undef PATCH




#ifdef USE_OPENSSL_CRYPTO

static void mod_authn_file_digest_sha256(http_auth_info_t *ai, const char *pw, size_t pwlen) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char *)ai->username, ai->ulen);
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    SHA256_Update(&ctx, (const unsigned char *)ai->realm, ai->rlen);
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    SHA256_Update(&ctx, (const unsigned char *)pw, pwlen);
    SHA256_Final(ai->digest, &ctx);
}

#ifdef SHA512_256_DIGEST_LENGTH
static void mod_authn_file_digest_sha512_256(http_auth_info_t *ai, const char *pw, size_t pwlen) {
    SHA512_CTX ctx;
    SHA512_256_Init(&ctx);
    SHA512_256_Update(&ctx, (const unsigned char *)ai->username, ai->ulen);
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    SHA512_256_Update(&ctx, (const unsigned char *)ai->realm, ai->rlen);
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    SHA512_256_Update(&ctx, (const unsigned char *)pw, pwlen);
    SHA512_256_Final(ai->digest, &ctx);
}
#endif

#endif

static void mod_authn_file_digest_md5(http_auth_info_t *ai, const char *pw, size_t pwlen) {
    li_MD5_CTX ctx;
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, (const unsigned char *)ai->username, ai->ulen);
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    li_MD5_Update(&ctx, (const unsigned char *)ai->realm, ai->rlen);
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    li_MD5_Update(&ctx, (const unsigned char *)pw, pwlen);
    li_MD5_Final(ai->digest, &ctx);
}

static void mod_authn_file_digest(http_auth_info_t *ai, const char *pw, size_t pwlen) {

    if (ai->dalgo & HTTP_AUTH_DIGEST_MD5)
        mod_authn_file_digest_md5(ai, pw, pwlen);
  #ifdef USE_OPENSSL_CRYPTO
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA256)
        mod_authn_file_digest_sha256(ai, pw, pwlen);
   #ifdef SHA512_256_DIGEST_LENGTH
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA512_256)
        mod_authn_file_digest_sha512_256(ai, pw, pwlen);
   #endif
  #endif
}




static int mod_authn_file_htdigest_get_loop(server *srv, FILE *fp, const buffer *auth_fn, http_auth_info_t *ai) {
    char f_user[1024];

    while (NULL != fgets(f_user, sizeof(f_user), fp)) {
        char *f_pwd, *f_realm;
        size_t u_len, r_len;

        /* skip blank lines and comment lines (beginning '#') */
        if (f_user[0] == '#' || f_user[0] == '\n' || f_user[0] == '\0') continue;

        /*
         * htdigest format
         *
         * user:realm:md5(user:realm:password)
         */

        if (NULL == (f_realm = strchr(f_user, ':'))) {
            log_error_write(srv, __FILE__, __LINE__, "sbs",
                    "parsed error in", auth_fn,
                    "expected 'username:realm:hashed password'");

            continue; /* skip bad lines */
        }

        if (NULL == (f_pwd = strchr(f_realm + 1, ':'))) {
            log_error_write(srv, __FILE__, __LINE__, "sbs",
                    "parsed error in", auth_fn,
                    "expected 'username:realm:hashed password'");

            continue; /* skip bad lines */
        }

        /* get pointers to the fields */
        u_len = f_realm - f_user;
        f_realm++;
        r_len = f_pwd - f_realm;
        f_pwd++;

        if (ai->ulen == u_len && ai->rlen == r_len
            && 0 == memcmp(ai->username, f_user, u_len)
            && 0 == memcmp(ai->realm, f_realm, r_len)) {
            /* found */

            size_t pwd_len = strlen(f_pwd);
            if (f_pwd[pwd_len-1] == '\n') --pwd_len;

            if (pwd_len != (ai->dlen << 1)) continue;
            return http_auth_digest_hex2bin(f_pwd, pwd_len,
                                            ai->digest, sizeof(ai->digest));
        }
    }

    return -1;
}

static int mod_authn_file_htdigest_get(server *srv, connection *con, void *p_d, http_auth_info_t *ai) {
    plugin_data *p = (plugin_data *)p_d;
    const buffer *auth_fn;
    FILE *fp;

    mod_authn_file_patch_connection(srv, con, p);
    auth_fn = p->conf.auth_htdigest_userfile;
    if (buffer_string_is_empty(auth_fn)) return -1;

    fp = fopen(auth_fn->ptr, "r");
    if (NULL != fp) {
        int rc = mod_authn_file_htdigest_get_loop(srv, fp, auth_fn, ai);
        fclose(fp);
        return rc;
    }
    else {
        log_error_write(srv, __FILE__, __LINE__, "sbss", "opening digest-userfile", auth_fn, "failed:", strerror(errno));
        return -1;
    }
}

static handler_t mod_authn_file_htdigest_digest(server *srv, connection *con, void *p_d, http_auth_info_t *ai) {
    return (0 == mod_authn_file_htdigest_get(srv, con, p_d, ai))
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}

static handler_t mod_authn_file_htdigest_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw) {
    http_auth_info_t ai;
    unsigned char htdigest[sizeof(ai.digest)];

    /* supports single choice of algorithm for digest stored in htdigest file */
    ai.dalgo    = (require->algorithm & ~HTTP_AUTH_DIGEST_SESS);
    ai.dlen     = http_auth_digest_len(ai.dalgo);
    ai.username = username->ptr;
    ai.ulen     = buffer_string_length(username);
    ai.realm    = require->realm->ptr;
    ai.rlen     = buffer_string_length(require->realm);

    if (mod_authn_file_htdigest_get(srv, con, p_d, &ai)) return HANDLER_ERROR;

    if (ai.dlen > sizeof(htdigest)) return HANDLER_ERROR;/*(should not happen)*/
    memcpy(htdigest, ai.digest, ai.dlen); /*(save digest before reuse of ai)*/

    mod_authn_file_digest(&ai, pw, strlen(pw));

    return (0 == memcmp(htdigest, ai.digest, ai.dlen)
            && http_auth_match_rules(require, username->ptr, NULL, NULL))
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}




static int mod_authn_file_htpasswd_get(server *srv, const buffer *auth_fn, const char *username, size_t userlen, buffer *password) {
    FILE *fp;
    char f_user[1024];

    if (NULL == username) return -1;

    if (buffer_string_is_empty(auth_fn)) return -1;
    fp = fopen(auth_fn->ptr, "r");
    if (NULL == fp) {
        log_error_write(srv, __FILE__, __LINE__, "sbss",
                "opening plain-userfile", auth_fn, "failed:", strerror(errno));

        return -1;
    }

    while (NULL != fgets(f_user, sizeof(f_user), fp)) {
        char *f_pwd;
        size_t u_len;

        /* skip blank lines and comment lines (beginning '#') */
        if (f_user[0] == '#' || f_user[0] == '\n' || f_user[0] == '\0') continue;

        /*
         * htpasswd format
         *
         * user:crypted passwd
         */

        if (NULL == (f_pwd = strchr(f_user, ':'))) {
            log_error_write(srv, __FILE__, __LINE__, "sbs",
                    "parsed error in", auth_fn,
                    "expected 'username:hashed password'");

            continue; /* skip bad lines */
        }

        /* get pointers to the fields */
        u_len = f_pwd - f_user;
        f_pwd++;

        if (userlen == u_len && 0 == memcmp(username, f_user, u_len)) {
            /* found */

            size_t pwd_len = strlen(f_pwd);
            if (f_pwd[pwd_len-1] == '\n') --pwd_len;

            buffer_copy_string_len(password, f_pwd, pwd_len);

            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

static handler_t mod_authn_file_plain_digest(server *srv, connection *con, void *p_d, http_auth_info_t *ai) {
    plugin_data *p = (plugin_data *)p_d;
    buffer *password_buf = buffer_init();/* password-string from auth-backend */
    int rc;
    mod_authn_file_patch_connection(srv, con, p);
    rc = mod_authn_file_htpasswd_get(srv, p->conf.auth_plain_userfile, ai->username, ai->ulen, password_buf);
    if (0 == rc) {
        /* generate password from plain-text */
        mod_authn_file_digest(ai, CONST_BUF_LEN(password_buf));
    }
    buffer_free(password_buf);
    return (0 == rc) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static handler_t mod_authn_file_plain_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw) {
    plugin_data *p = (plugin_data *)p_d;
    buffer *password_buf = buffer_init();/* password-string from auth-backend */
    int rc;
    mod_authn_file_patch_connection(srv, con, p);
    rc = mod_authn_file_htpasswd_get(srv, p->conf.auth_plain_userfile, CONST_BUF_LEN(username), password_buf);
    if (0 == rc) {
        rc = http_auth_const_time_memeq(CONST_BUF_LEN(password_buf), pw, strlen(pw)) ? 0 : -1;
    }
    buffer_free(password_buf);
    return 0 == rc && http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}




/**
 * the $apr1$ handling is taken from apache 1.3.x
 */

/*
 * The apr_md5_encode() routine uses much code obtained from the FreeBSD 3.0
 * MD5 crypt() function, which is licenced as follows:
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

#define APR_MD5_DIGESTSIZE 16
#define APR1_ID "$apr1$"

/*
 * The following MD5 password encryption code was largely borrowed from
 * the FreeBSD 3.0 /usr/src/lib/libcrypt/crypt.c file, which is
 * licenced as stated above.
 */

static void to64(char *s, unsigned long v, int n)
{
    static const unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

static void apr_md5_encode(const char *pw, const char *salt, char *result, size_t nbytes) {
    /*
     * Minimum size is 8 bytes for salt, plus 1 for the trailing NUL,
     * plus 4 for the '$' separators, plus the password hash itself.
     * Let's leave a goodly amount of leeway.
     */

    char passwd[120], *p;
    const char *sp, *ep;
    unsigned char final[APR_MD5_DIGESTSIZE];
    ssize_t sl, pl, i;
    li_MD5_CTX ctx, ctx1;
    unsigned long l;

    /*
     * Refine the salt first.  It's possible we were given an already-hashed
     * string as the salt argument, so extract the actual salt value from it
     * if so.  Otherwise just use the string up to the first '$' as the salt.
     */
    sp = salt;

    /*
     * If it starts with the magic string, then skip that.
     */
    if (!strncmp(sp, APR1_ID, strlen(APR1_ID))) {
        sp += strlen(APR1_ID);
    }

    /*
     * It stops at the first '$' or 8 chars, whichever comes first
     */
    for (ep = sp; (*ep != '\0') && (*ep != '$') && (ep < (sp + 8)); ep++) {
        continue;
    }

    /*
     * Get the length of the true salt
     */
    sl = ep - sp;

    /*
     * 'Time to make the doughnuts..'
     */
    li_MD5_Init(&ctx);

    /*
     * The password first, since that is what is most unknown
     */
    li_MD5_Update(&ctx, pw, strlen(pw));

    /*
     * Then our magic string
     */
    li_MD5_Update(&ctx, APR1_ID, strlen(APR1_ID));

    /*
     * Then the raw salt
     */
    li_MD5_Update(&ctx, sp, sl);

    /*
     * Then just as many characters of the MD5(pw, salt, pw)
     */
    li_MD5_Init(&ctx1);
    li_MD5_Update(&ctx1, pw, strlen(pw));
    li_MD5_Update(&ctx1, sp, sl);
    li_MD5_Update(&ctx1, pw, strlen(pw));
    li_MD5_Final(final, &ctx1);
    for (pl = strlen(pw); pl > 0; pl -= APR_MD5_DIGESTSIZE) {
        li_MD5_Update(&ctx, final,
                      (pl > APR_MD5_DIGESTSIZE) ? APR_MD5_DIGESTSIZE : pl);
    }

    /*
     * Don't leave anything around in vm they could use.
     */
    memset(final, 0, sizeof(final));

    /*
     * Then something really weird...
     */
    for (i = strlen(pw); i != 0; i >>= 1) {
        if (i & 1) {
            li_MD5_Update(&ctx, final, 1);
        }
        else {
            li_MD5_Update(&ctx, pw, 1);
        }
    }

    /*
     * Now make the output string.  We know our limitations, so we
     * can use the string routines without bounds checking.
     */
    strcpy(passwd, APR1_ID);
    strncat(passwd, sp, sl);
    strcat(passwd, "$");

    li_MD5_Final(final, &ctx);

    /*
     * And now, just to make sure things don't run too fast..
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for (i = 0; i < 1000; i++) {
        li_MD5_Init(&ctx1);
        if (i & 1) {
            li_MD5_Update(&ctx1, pw, strlen(pw));
        }
        else {
            li_MD5_Update(&ctx1, final, APR_MD5_DIGESTSIZE);
        }
        if (i % 3) {
            li_MD5_Update(&ctx1, sp, sl);
        }

        if (i % 7) {
            li_MD5_Update(&ctx1, pw, strlen(pw));
        }

        if (i & 1) {
            li_MD5_Update(&ctx1, final, APR_MD5_DIGESTSIZE);
        }
        else {
            li_MD5_Update(&ctx1, pw, strlen(pw));
        }
        li_MD5_Final(final,&ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p, l, 4); p += 4;
    l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p, l, 4); p += 4;
    l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p, l, 4); p += 4;
    l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p, l, 4); p += 4;
    l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p, l, 4); p += 4;
    l =                    final[11]                ; to64(p, l, 2); p += 2;
    *p = '\0';

    /*
     * Don't leave anything around in vm they could use.
     */
    safe_memclear(final, sizeof(final));

    /* FIXME
     */
#define apr_cpystrn strncpy
    apr_cpystrn(result, passwd, nbytes - 1);
}

static void apr_sha_encode(const char *pw, char *result, size_t nbytes) {
    unsigned char digest[20];
    size_t base64_written;
    SHA_CTX sha1;

    SHA1_Init(&sha1);
    SHA1_Update(&sha1, (const unsigned char *) pw, strlen(pw));
    SHA1_Final(digest, &sha1);

    memset(result, 0, nbytes);

    /* need 5 bytes for "{SHA}", 28 for base64 (3 bytes -> 4 bytes) of SHA1 (20 bytes), 1 terminating */
    if (nbytes < 5 + 28 + 1) return;

    memcpy(result, "{SHA}", 5);
    base64_written = li_to_base64(result + 5, nbytes - 5, digest, 20, BASE64_STANDARD);
    force_assert(base64_written == 28);
    result[5 + base64_written] = '\0'; /* terminate string */
}

static handler_t mod_authn_file_htpasswd_basic(server *srv, connection *con, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw) {
    plugin_data *p = (plugin_data *)p_d;
    buffer *password = buffer_init();/* password-string from auth-backend */
    int rc;
    mod_authn_file_patch_connection(srv, con, p);
    rc = mod_authn_file_htpasswd_get(srv, p->conf.auth_htpasswd_userfile, CONST_BUF_LEN(username), password);
    if (0 == rc) {
        char sample[256];
        rc = -1;
        if (!strncmp(password->ptr, APR1_ID, strlen(APR1_ID))) {
            /*
             * The hash was created using $apr1$ custom algorithm.
             */
            apr_md5_encode(pw, password->ptr, sample, sizeof(sample));
            rc = strcmp(sample, password->ptr);
        }
        else if (0 == strncmp(password->ptr, "{SHA}", 5)) {
            apr_sha_encode(pw, sample, sizeof(sample));
            rc = strcmp(sample, password->ptr);
        }
      #if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT)
        /* a simple DES password is 2 + 11 characters. everything else should be longer. */
        else if (buffer_string_length(password) >= 13) {
            char *crypted;
           #if defined(HAVE_CRYPT_R)
            struct crypt_data crypt_tmp_data;
            #ifdef _AIX
            memset(&crypt_tmp_data, 0, sizeof(crypt_tmp_data));
            #else
            crypt_tmp_data.initialized = 0;
            #endif
           #endif
           #ifdef USE_OPENSSL_CRYPTO /* (for MD4_*() (e.g. MD4_Update())) */
           #ifndef NO_MD4 /*(e.g. wolfSSL built without MD4)*/
            if (0 == memcmp(password->ptr, CONST_STR_LEN("$1+ntlm$"))) {
                /* CRYPT-MD5-NTLM algorithm
                 * This algorithm allows for the construction of (slight more)
                 * secure, salted password hashes from an environment where only
                 * legacy NTLM hashes are available and where it is not feasible
                 * to re-hash all the passwords with the MD5-based crypt(). */
                /* Note: originally, LM password were limited to 14 chars.
                 * NTLM passwords limited to 127 chars, and encoding to UCS-2LE
                 * requires double that, so sample[256] buf is large enough.
                 * Prior sample[120] size likely taken from apr_md5_encode(). */
                char *b = password->ptr+sizeof("$1+ntlm$")-1;
                char *e = strchr(b, '$');
                size_t slen = (NULL != e) ? (size_t)(e - b) : sizeof(sample);
                size_t pwlen = strlen(pw) * 2;
                if (slen < sizeof(sample) - (sizeof("$1$")-1)
                    && pwlen < sizeof(sample)) {
                    /* compute NTLM hash and convert to lowercase hex chars
                     * (require lc hex chars from li_tohex()) */
                    char ntlmhash[16];
                    char ntlmhex[33]; /*(sizeof(ntlmhash)*2 + 1)*/
                    MD4_CTX c;
                    MD4_Init(&c);
                    if (pwlen) {
                        /*(reuse sample buffer to encode pw into UCS-2LE)
                         *(Note: assumes pw input in ISO-8859-1) */
                        /*(buffer sizes checked above)*/
                        for (int i=0; i < (int)pwlen; i+=2) {
                            sample[i] = pw[(i >> 1)];
                            sample[i+1] = 0;
                        }
                        MD4_Update(&c, (unsigned char *)sample, pwlen);
                    }
                    MD4_Final((unsigned char *)ntlmhash, &c);
                    li_tohex(ntlmhex,sizeof(ntlmhex),ntlmhash,sizeof(ntlmhash));

                    /*(reuse sample buffer for salt  (FYI: expect slen == 8))*/
                    memcpy(sample, "$1$", sizeof("$1$")-1);
                    memcpy(sample+sizeof("$1$")-1, b, slen);
                    sample[sizeof("$1$")-1+slen] = '\0';
                   #if defined(HAVE_CRYPT_R)
                    crypted = crypt_r(ntlmhex, sample, &crypt_tmp_data);
                   #else
                    crypted = crypt(ntlmhex, sample);
                   #endif
                    if (NULL != crypted
                        && 0 == strncmp(crypted, "$1$", sizeof("$1$")-1)) {
                        rc = strcmp(b, crypted+3); /*skip crypted "$1$" prefix*/
                    }
                }
            }
            else
           #endif
           #endif
            {
               #if defined(HAVE_CRYPT_R)
                crypted = crypt_r(pw, password->ptr, &crypt_tmp_data);
               #else
                crypted = crypt(pw, password->ptr);
               #endif
                if (NULL != crypted) {
                    rc = strcmp(password->ptr, crypted);
                }
            }
        }
      #endif
    }
    buffer_free(password);
    return 0 == rc && http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}


int mod_authn_file_plugin_init(plugin *p);
int mod_authn_file_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = buffer_init_string("authn_file");
    p->init        = mod_authn_file_init;
    p->set_defaults= mod_authn_file_set_defaults;
    p->cleanup     = mod_authn_file_free;

    p->data        = NULL;

    return 0;
}
