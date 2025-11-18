#include "first.h"


/*(htpasswd)*/
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#elif defined(__linux__)
/* linux needs _XOPEN_SOURCE */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#elif !defined(_MSC_VER)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _XOPEN_CRYPT
#define _XOPEN_CRYPT 1
#endif
#include <unistd.h>
#endif

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "mod_auth_api.h"
#include "sys-crypto-md.h" /* USE_LIB_CRYPTO */
#include "sys-unistd.h" /* <unistd.h> */

#include "base64.h"
#include "ck.h"
#include "fdevent.h"
#include "log.h"
#include "plugin.h"
#include "request.h"

/*
 * htdigest, htpasswd, plain auth backends
 */

typedef struct {
    const buffer *auth_plain_groupfile;
    const buffer *auth_plain_userfile;
    const buffer *auth_htdigest_userfile;
    const buffer *auth_htpasswd_userfile;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

static handler_t mod_authn_file_htdigest_digest(request_st *r, void *p_d, http_auth_info_t *ai);
static handler_t mod_authn_file_htdigest_basic(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
static handler_t mod_authn_file_plain_digest(request_st *r, void *p_d, http_auth_info_t *ai);
static handler_t mod_authn_file_plain_basic(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
static handler_t mod_authn_file_htpasswd_basic(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_file_init) {
    static http_auth_backend_t http_auth_backend_htdigest =
      { "htdigest", mod_authn_file_htdigest_basic, mod_authn_file_htdigest_digest, NULL };
    static http_auth_backend_t http_auth_backend_htpasswd =
      { "htpasswd", mod_authn_file_htpasswd_basic, NULL, NULL };
    static http_auth_backend_t http_auth_backend_plain =
      { "plain", mod_authn_file_plain_basic, mod_authn_file_plain_digest, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

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

static void mod_authn_file_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.plain.groupfile */
        pconf->auth_plain_groupfile = cpv->v.b;
        break;
      case 1: /* auth.backend.plain.userfile */
        pconf->auth_plain_userfile = cpv->v.b;
        break;
      case 2: /* auth.backend.htdigest.userfile */
        pconf->auth_htdigest_userfile = cpv->v.b;
        break;
      case 3: /* auth.backend.htpasswd.userfile */
        pconf->auth_htpasswd_userfile = cpv->v.b;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_authn_file_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_authn_file_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_authn_file_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_file_merge_config(pconf,
                                        p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_authn_file_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.plain.groupfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.plain.userfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.htdigest.userfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.htpasswd.userfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_file"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.plain.groupfile */
              case 1: /* auth.backend.plain.userfile */
              case 2: /* auth.backend.htdigest.userfile */
              case 3: /* auth.backend.htpasswd.userfile */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_file_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}




static void mod_authn_file_digest(http_auth_info_t *ai, const char *pw, size_t pwlen) {

    li_md_iov_fn digest_iov = MD5_iov;
    /* (ai->dalgo & HTTP_AUTH_DIGEST_MD5) default */
  #ifdef USE_LIB_CRYPTO
    if (ai->dalgo & HTTP_AUTH_DIGEST_SHA256)
        digest_iov = SHA256_iov;
   #ifdef USE_LIB_CRYPTO_SHA512_256
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA512_256)
        digest_iov = SHA512_256_iov;
   #endif
  #endif

    struct const_iovec iov[] = {
      { ai->username, ai->ulen }
     ,{ ":", 1 }
     ,{ ai->realm, ai->rlen }
     ,{ ":", 1 }
     ,{ pw, pwlen }
    };
    digest_iov(ai->digest, iov, sizeof(iov)/sizeof(*iov));
}




static int mod_authn_file_htdigest_get_loop(const char *data, const buffer *auth_fn, http_auth_info_t *ai, log_error_st *errh) {
    const char *f_user = data, *n;
    do {
        n = strchr(f_user, '\n');
        /* (last line might not end in '\n') */
        if (NULL == n) n = f_user + strlen(f_user);

        char *f_pwd, *f_realm;
        size_t u_len, r_len;

        /* skip blank lines and comment lines (beginning '#') */
        if (f_user[0] == '\n' || f_user[0] == '\r' ||
            f_user[0] == '#'  || f_user[0] == '\0') continue;
        /* skip excessively long lines */
        if (n - f_user > 1024) continue;

        /*
         * htdigest format
         *
         * (4th field for userhash is optional,
         *  though must be lowercase hex string if present)
         *
         * user:realm:<md5(user:realm:password)>:<md5(user:realm)>
         * user:realm:<sha256(user:realm:password)>:<sha256(user:realm)>
         */

        if (NULL == (f_realm = memchr(f_user, ':', n - f_user))
            || NULL == (f_pwd = memchr(f_realm+1, ':', n - (f_realm+1)))) {
            log_error(errh, __FILE__, __LINE__,
              "parse error in %s expected 'username:realm:digest[:userhash]'",
              auth_fn->ptr);
            continue; /* skip bad lines */
        }

        /* get pointers to the fields */
        u_len = f_realm - f_user;
        f_realm++;
        r_len = f_pwd - f_realm;
        f_pwd++;
        const char *f_userhash = memchr(f_pwd, ':', (size_t)(n - f_pwd));

        if (ai->userhash) {
            if (NULL == f_userhash) continue;
            ++f_userhash;
            size_t uh_len = n - f_userhash;
            if (f_userhash[uh_len-1] == '\r') --uh_len;
            if (ai->ulen == uh_len && ai->rlen == r_len
                /*(timing-safe hash cmp might not matter much; do it anyway)*/
                /*&& 0 == memcmp(ai->username, f_userhash, uh_len)*/
                && ck_memeq_const_time_fixed_len(ai->username,f_userhash,uh_len)
                && 0 == memcmp(ai->realm, f_realm, r_len)
                && u_len <= sizeof(ai->userbuf)) {
                /* found */
                ai->ulen = u_len;
                ai->username = memcpy(ai->userbuf, f_user, u_len);
                --f_userhash; /*(step back to ':' for pwd_len below)*/
            }
            else
                continue;
        }
        else
        if (ai->ulen == u_len && ai->rlen == r_len
            && 0 == memcmp(ai->username, f_user, u_len)
            && 0 == memcmp(ai->realm, f_realm, r_len)) {
            /* found */
            if (NULL == f_userhash) f_userhash = n;
        }
        else {
            continue;
        }

        {
            /* found */
            size_t pwd_len = f_userhash - f_pwd;
            if (f_pwd[pwd_len-1] == '\r') --pwd_len;

            if (pwd_len != (ai->dlen << 1)) continue;
            return li_hex2bin(ai->digest, sizeof(ai->digest), f_pwd, pwd_len);
        }
    } while (*n && *(f_user = n+1));

    return -1;
}

static int mod_authn_file_htdigest_get(request_st * const r, void *p_d, http_auth_info_t * const ai) {
    plugin_config pconf;
    mod_authn_file_patch_config(r, p_d, &pconf);
    const buffer * const auth_fn = pconf.auth_htdigest_userfile;
    if (!auth_fn) return -1;

    off_t dlen = 64*1024*1024;/*(arbitrary limit: 64 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(auth_fn->ptr,&dlen,r->conf.errh,malloc,free);
    if (NULL == data) return -1;

    int rc = mod_authn_file_htdigest_get_loop(data, auth_fn, ai, r->conf.errh);
    ck_memzero(data, (size_t)dlen);
    free(data);
    return rc;
}

static handler_t mod_authn_file_htdigest_digest(request_st * const r, void *p_d, http_auth_info_t * const ai) {
    return (0 == mod_authn_file_htdigest_get(r, p_d, ai))
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}

static handler_t mod_authn_file_htdigest_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    http_auth_info_t ai;
    unsigned char htdigest[sizeof(ai.digest)];

    /* supports single choice of algorithm for digest stored in htdigest file */
    ai.dalgo    = (require->algorithm & ~HTTP_AUTH_DIGEST_SESS);
    ai.dlen     = http_auth_digest_len(ai.dalgo);
    ai.username = username->ptr;
    ai.ulen     = buffer_clen(username);
    ai.realm    = require->realm->ptr;
    ai.rlen     = buffer_clen(require->realm);
    ai.userhash = 0;

    if (mod_authn_file_htdigest_get(r, p_d, &ai)) return HANDLER_ERROR;

    if (ai.dlen > sizeof(htdigest)) {
        ck_memzero(ai.digest, ai.dlen);
        return HANDLER_ERROR;/*(should not happen)*/
    }
    memcpy(htdigest, ai.digest, ai.dlen); /*(save digest before reuse of ai)*/

    mod_authn_file_digest(&ai, pw, strlen(pw));

    int rc = (ck_memeq_const_time_fixed_len(htdigest, ai.digest, ai.dlen)
           && http_auth_match_rules(require, username->ptr, NULL, NULL));

    ck_memzero(htdigest, ai.dlen);
    ck_memzero(ai.digest, ai.dlen);
    return rc ? HANDLER_GO_ON : HANDLER_ERROR;
}




static int mod_authn_file_htpasswd_get(const buffer *auth_fn, const char *username, size_t userlen, buffer *password, log_error_st *errh) {
    if (NULL == username) return -1;
    if (!auth_fn) return -1;

    off_t dlen = 64*1024*1024;/*(arbitrary limit: 64 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(auth_fn->ptr, &dlen, errh, malloc, free);
    if (NULL == data) return -1;

    int rc = -1;
    const char *f_user = data, *n;
    do {
        n = strchr(f_user, '\n');
        /* (last line might not end in '\n') */
        if (NULL == n) n = f_user + strlen(f_user);

        char *f_pwd;
        size_t u_len;

        /* skip blank lines and comment lines (beginning '#') */
        if (f_user[0] == '\n' || f_user[0] == '\r' ||
            f_user[0] == '#'  || f_user[0] == '\0') continue;
        /* skip excessively long lines */
        if (n - f_user > 1024) continue;

        /*
         * htpasswd format
         *
         * user:crypted passwd
         */

        if (NULL == (f_pwd = memchr(f_user, ':', n - f_user))) {
            log_error(errh, __FILE__, __LINE__,
              "parsed error in %s expected 'username:password'",
              auth_fn->ptr);
            continue; /* skip bad lines */
        }

        /* get pointers to the fields */
        u_len = f_pwd - f_user;
        f_pwd++;

        if (userlen == u_len && 0 == memcmp(username, f_user, u_len)) {
            /* found */

            size_t pwd_len = n - f_pwd;
            if (f_pwd[pwd_len-1] == '\r') --pwd_len;

            buffer_copy_string_len(password, f_pwd, pwd_len);

            rc = 0;
            break;
        }
    } while (*n && *(f_user = n+1));

    ck_memzero(data, (size_t)dlen);
    free(data);
    return rc;
}

static handler_t mod_authn_file_plain_digest(request_st * const r, void *p_d, http_auth_info_t * const ai) {
    plugin_config pconf;
    mod_authn_file_patch_config(r, p_d, &pconf);
    buffer * const tb = r->tmp_buf; /* password-string from auth-backend */
    int rc = mod_authn_file_htpasswd_get(pconf.auth_plain_userfile,
                                         ai->username, ai->ulen, tb,
                                         r->conf.errh);
    if (0 != rc) return HANDLER_ERROR;

    /* generate password digest from plain-text */
    mod_authn_file_digest(ai, BUF_PTR_LEN(tb));
    size_t tblen = (buffer_clen(tb) + 63) & ~63u;
    buffer_clear(tb);
    ck_memzero(tb->ptr, tblen < tb->size ? tblen : tb->size);
    return HANDLER_GO_ON;
}

static handler_t mod_authn_file_plain_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    plugin_config pconf;
    mod_authn_file_patch_config(r, p_d, &pconf);
    buffer * const tb = r->tmp_buf; /* password-string from auth-backend */
    int rc = mod_authn_file_htpasswd_get(pconf.auth_plain_userfile,
                                         BUF_PTR_LEN(username), tb,
                                         r->conf.errh);
    if (0 == rc) {
        rc = ck_memeq_const_time(BUF_PTR_LEN(tb), pw, strlen(pw)) ? 0 : -1;
        size_t tblen = (buffer_clen(tb) + 63) & ~63u;
        buffer_clear(tb);
        ck_memzero(tb->ptr, tblen < tb->size ? tblen : tb->size);
    }
    return 0 == rc && http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}




/**
 * the $apr1$ handling is taken from apache 1.3.x
 * XXX: code has since been modified for slightly better performance
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

static size_t apr_md5_encode(const char *pw, const char *salt, char *result, size_t nbytes) {
    force_assert(nbytes >= 37); /*(nbytes should be >= 37)*/

    const size_t pwlen = strlen(pw);
    ssize_t sl;

    /*
     * Refine the salt first.  It's possible we were given an already-hashed
     * string as the salt argument, so extract the actual salt value from it
     * if so.  Otherwise just use the string up to the first '$' as the salt.
     */

  #if 0 /*(already checked and stepped-over in caller)*/
    /*
     * If it starts with the magic string, then skip that.
     */
    if (!strncmp(salt, APR1_ID, sizeof(APR1_ID)-1)) {
        salt += sizeof(APR1_ID)-1;
    }
  #endif

    /*
     * Get the length of the true salt
     */
    /*
     * It stops at the first '$' or 8 chars, whichever comes first
     */
    for (sl = 0; sl < 8 && salt[sl] != '$' && salt[sl] != '\0'; ++sl) ;

    /* result begins with "$apr1$salt$" */
    memcpy(result, APR1_ID, sizeof(APR1_ID)-1);
    memcpy(result+sizeof(APR1_ID)-1, salt, sl);
    result[sizeof(APR1_ID)-1+sl] = '$';

    MD5_CTX ctx;
    unsigned char final[APR_MD5_DIGESTSIZE];

    MD5_Init(&ctx);
    MD5_Update(&ctx, pw, pwlen);
    MD5_Update(&ctx, salt, sl);
    MD5_Update(&ctx, pw, pwlen);
    MD5_Final(final, &ctx);

    /*
     * 'Time to make the doughnuts..'
     */
    MD5_Init(&ctx);

    /*
     * The password first, since that is what is most unknown
     */
    MD5_Update(&ctx, pw, pwlen);

  #if 0
    /*
     * Then our magic string
     */
    MD5_Update(&ctx, APR1_ID, sizeof(APR1_ID)-1);

    /*
     * Then the raw salt
     */
    MD5_Update(&ctx, salt, sl);
  #else
    MD5_Update(&ctx, result, sizeof(APR1_ID)-1 + sl);
  #endif

    /*
     * Then just as many characters of the MD5(pw, salt, pw)
     */
    for (ssize_t pl = pwlen; pl > 0; pl -= APR_MD5_DIGESTSIZE) {
        MD5_Update(&ctx, final,
                   (pl > APR_MD5_DIGESTSIZE) ? APR_MD5_DIGESTSIZE : pl);
    }

    /*
     * Don't leave anything around in vm they could use.
     */
    /*ck_memzero(final, sizeof(final));*/
    final[0] = 0; /*(preserve behavior for loop below)*/

    /*
     * Then something really weird...
     */
    for (size_t i = pwlen; i != 0; i >>= 1) {
        MD5_Update(&ctx, (i & 1) ? (char *)final : pw, 1);
    }
    MD5_Final(final, &ctx);

    /*
     * And now, just to make sure things don't run too fast..
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for (int i = 0; i < 1000; ++i) {
        MD5_Init(&ctx);
        if (i & 1) {
            MD5_Update(&ctx, pw, pwlen);
        }
        else {
            MD5_Update(&ctx, final, APR_MD5_DIGESTSIZE);
        }
        if (i % 3) {
            MD5_Update(&ctx, salt, sl);
        }

        if (i % 7) {
            MD5_Update(&ctx, pw, pwlen);
        }

        if (i & 1) {
            MD5_Update(&ctx, final, APR_MD5_DIGESTSIZE);
        }
        else {
            MD5_Update(&ctx, pw, pwlen);
        }
        MD5_Final(final,&ctx);
    }

    /*
     * Now make the output string. (nbytes checked at top of func)
     * Maximum result size below is 37:
     *   6 for APR_ID, <= 8 for salt, 1 for '$', 22 for password hash
     */

    result += sizeof(APR1_ID)-1 + sl + 1;
    to64(result,    (final[ 0]<<16) | (final[ 6]<<8) | final[12], 4);
    to64(result+4,  (final[ 1]<<16) | (final[ 7]<<8) | final[13], 4);
    to64(result+8,  (final[ 2]<<16) | (final[ 8]<<8) | final[14], 4);
    to64(result+12, (final[ 3]<<16) | (final[ 9]<<8) | final[15], 4);
    to64(result+16, (final[ 4]<<16) | (final[10]<<8) | final[ 5], 4);
    to64(result+20,                    final[11]                , 2);

    /*
     * Don't leave anything around in vm they could use.
     */
    ck_memzero(final, sizeof(final));
    return (sizeof(APR1_ID)-1 + sl + 1 + 22);
}

#if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT)
static int mod_authn_file_crypt_cmp(const buffer * const password, const char * const pw) {
            int rc = -1;
            char *crypted = NULL;
           #if 0 && defined(HAVE_CRYPT_R)
            struct crypt_data crypt_tmp_data;
            #ifdef _AIX
            memset(&crypt_tmp_data, 0, sizeof(crypt_tmp_data));
            #else
            crypt_tmp_data.initialized = 0;
            #endif
           #endif
           #ifdef USE_LIB_CRYPTO_MD4 /*(for MD4_*() (e.g. MD4_Update()))*/
            /*(caller checked buffer_clen(passwd) >= 13)*/
            if (0 == memcmp(password->ptr, CONST_STR_LEN("$1+ntlm$"))) {
                /* CRYPT-MD5-NTLM algorithm
                 * This algorithm allows for the construction of (slightly more)
                 * secure, salted password hashes from an environment where only
                 * legacy NTLM hashes are available and where it is not feasible
                 * to re-hash all the passwords with the MD5-based crypt(). */
                /* Note: originally, LM password were limited to 14 chars.
                 * NTLM passwords limited to 127 chars, and encoding to UCS-2LE
                 * requires double that, so sample[256] buf is large enough.
                 * Prior sample[120] size likely taken from apr_md5_encode(). */
                char sample[256];
                char *b = password->ptr+sizeof("$1+ntlm$")-1;
                char *e = strchr(b, '$');
                size_t slen = (NULL != e) ? (size_t)(e - b) : sizeof(sample);
                size_t pwlen = strlen(pw) * 2;
                if (slen < sizeof(sample) - (sizeof("$1$")-1)
                    && pwlen < sizeof(sample)) {
                    /* compute NTLM hash and convert to lowercase hex chars
                     * (require lc hex chars from li_tohex()) */
                    if (pwlen) {
                        /*(reuse sample buffer to encode pw into UCS-2LE)
                         *(Note: assumes pw input in ISO-8859-1) */
                        /*(buffer sizes checked above)*/
                        for (int i=0; i < (int)pwlen; i+=2) {
                            sample[i] = pw[(i >> 1)];
                            sample[i+1] = 0;
                        }
                    }
                    char ntlmhash[MD4_DIGEST_LENGTH];
                    char ntlmhex[MD4_DIGEST_LENGTH*2+1];
                    MD4_once((unsigned char *)ntlmhash, sample, pwlen);
                    li_tohex(ntlmhex,sizeof(ntlmhex),ntlmhash,sizeof(ntlmhash));
                    ntlmhex[MD4_DIGEST_LENGTH*2] = '\0';

                    /*(reuse sample buffer for salt  (FYI: expect slen == 8))*/
                    memcpy(sample, "$1$", sizeof("$1$")-1);
                    memcpy(sample+sizeof("$1$")-1, b, slen);
                    sample[sizeof("$1$")-1+slen] = '\0';
                   #if 0 && defined(HAVE_CRYPT_R)
                    crypted = crypt_r(ntlmhex, sample, &crypt_tmp_data);
                   #else
                    crypted = crypt(ntlmhex, sample);
                   #endif
                    if (NULL != crypted
                        && 0 == strncmp(crypted, "$1$", sizeof("$1$")-1)) {
                        rc = strcmp(b, crypted+3); /*skip crypted "$1$" prefix*/
                    }
                    ck_memzero(sample, sizeof(sample));
                }
            }
            else
           #endif
            {
               #if 0 && defined(HAVE_CRYPT_R)
                crypted = crypt_r(pw, password->ptr, &crypt_tmp_data);
               #else
                crypted = crypt(pw, password->ptr);
               #endif
                if (NULL != crypted) {
                    rc = strcmp(password->ptr, crypted);
                }
            }
            if (NULL != crypted) {
                size_t crypwlen = strlen(crypted);
                if (crypwlen >= 13) ck_memzero(crypted, crypwlen);
            }
            return rc;
}
#endif

static handler_t mod_authn_file_htpasswd_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    plugin_config pconf;
    mod_authn_file_patch_config(r, p_d, &pconf);
    buffer * const tb = r->tmp_buf; /* password-string from auth-backend */
    int rc = mod_authn_file_htpasswd_get(pconf.auth_htpasswd_userfile,
                                         BUF_PTR_LEN(username), tb,
                                         r->conf.errh);
    if (0 != rc) return HANDLER_ERROR;

    uint32_t tblen = buffer_clen(tb);
    rc = -1;
    if (tblen >= 5 && 0 == memcmp(tb->ptr, "{SHA}", 5)) {
        /* 32 == (5 for "{SHA}" + 28 for base64 of SHA1 (20 bytes)) */
        unsigned char digest[SHA_DIGEST_LENGTH*2];
        SHA1_once(digest+SHA_DIGEST_LENGTH, pw, strlen(pw));
        rc = SHA_DIGEST_LENGTH
               == li_base64_dec(digest, sizeof(digest),
                                tb->ptr+5, tblen-5, BASE64_STANDARD)
          && ck_memeq_const_time_fixed_len(digest, digest+SHA_DIGEST_LENGTH,
                                           SHA_DIGEST_LENGTH);
        rc = !rc; /* (0 == rc) for match */
        ck_memzero(digest, sizeof(digest));
    }
    else if (tblen >= 6 && 0 == memcmp(tb->ptr, "$apr1$", 6)) {
        char sample[40]; /*(see comments at end of apr_md5_encode())*/
        rc = tblen == apr_md5_encode(pw, tb->ptr+6, sample, sizeof(sample))
          && ck_memeq_const_time_fixed_len(sample, tb->ptr, tblen);
        rc = !rc; /* (0 == rc) for match */
        ck_memzero(sample, sizeof(sample));
    }
  #if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT)
    /* simple DES password is 2 + 11 characters;
     * everything else should be longer */
    else if (tblen >= 13) {
        rc = mod_authn_file_crypt_cmp(tb, pw);
    }
  #endif
    tblen = (tblen + 63) & ~63u;
    buffer_clear(tb);
    ck_memzero(tb->ptr, tblen < tb->size ? tblen : tb->size);
    return 0 == rc && http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON
      : HANDLER_ERROR;
}


__attribute_cold__
__declspec_dllexport__
int mod_authn_file_plugin_init(plugin *p);
int mod_authn_file_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "authn_file";
    p->init        = mod_authn_file_init;
    p->set_defaults= mod_authn_file_set_defaults;

    return 0;
}
