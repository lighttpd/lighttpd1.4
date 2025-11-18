/*
 * http_auth - HTTP authentication and authorization
 *
 * Largely-rewritten from original
 * Copyright(c) 2016,2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "mod_auth_api.h"
#include "sys-crypto-md.h" /* USE_LIB_CRYPTO */

#include "base.h"
#include "ck.h"
#include "http_header.h"
#include "http_status.h"
#include "log.h"
#include "algo_splaytree.h"
#include "plugin.h"
#include "plugin_config.h"

/**
 * auth framework
 */

typedef struct {
    splay_tree *sptree; /* data in nodes of tree are (http_auth_cache_entry *)*/
    time_t max_age;
} http_auth_cache;

typedef struct {
    const http_auth_backend_t *auth_backend;
    const array *auth_require;
    http_auth_cache *auth_cache;
    unsigned int auth_extern_authn;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

typedef struct {
    const struct http_auth_require_t *require;
    unix_time64_t ctime;
    int dalgo;
    uint32_t dlen;
    uint32_t ulen;
    uint32_t klen;
    char *k;
    char *username;
    char *pwdigest;
} http_auth_cache_entry;

static http_auth_cache_entry *
http_auth_cache_entry_init (const struct http_auth_require_t * const require, const int dalgo, const char *k, const uint32_t klen, const char *username, const uint32_t ulen, const char *pw, const uint32_t pwlen)
{
    /*(similar to buffer_copy_string_len() for each element,
     * but allocate exact lengths in single chunk of memory
     * for cache to avoid wasting space and for memory locality)*/
    /* http_auth_require_t is stored instead of copying realm
     *(store pointer to http_auth_require_t, which is persistent
     * and will be different for each realm + permissions combo)*/
    http_auth_cache_entry * const ae =
      ck_malloc(sizeof(http_auth_cache_entry) + ulen + pwlen
                + (k == username ? 0 : klen));
    ae->require = require;
    ae->ctime = log_monotonic_secs;
    ae->dalgo = dalgo;
    ae->ulen = ulen;
    ae->dlen = pwlen;
    ae->klen = klen;
    ae->username = (char *)(ae + 1);
    ae->pwdigest = ae->username + ulen;
    ae->k = (k == username)
      ? ae->username
      : memcpy(ae->pwdigest + pwlen, k, klen);
    memcpy(ae->username, username, ulen);
    memcpy(ae->pwdigest, pw, pwlen);
    return ae;
}

static void
http_auth_cache_entry_free (void *data)
{
    http_auth_cache_entry * const ae = data;
    ck_memzero(ae->pwdigest, ae->dlen);
    free(ae);
}

static void
http_auth_cache_free (http_auth_cache *ac)
{
    splay_tree *sptree = ac->sptree;
    while (sptree) {
        http_auth_cache_entry_free(sptree->data);
        sptree = splaytree_delete_splayed_node(sptree);
    }
    free(ac);
}

static http_auth_cache *
http_auth_cache_init (const array *opts)
{
    http_auth_cache *ac = ck_malloc(sizeof(http_auth_cache));
    ac->sptree = NULL;
    ac->max_age = 600; /* 10 mins */
    for (uint32_t i = 0, used = opts->used; i < used; ++i) {
        data_unset *du = opts->data[i];
        if (buffer_is_equal_string(&du->key, CONST_STR_LEN("max-age")))
            ac->max_age = (time_t)
              config_plugin_value_to_int32(du, 600); /* 10 min if invalid num */
    }
    return ac;
}

__attribute_pure__
static int
http_auth_cache_hash (const struct http_auth_require_t * const require, const char *username, const uint32_t ulen)
{
    /* (similar to splaytree_djbhash(), but with two strings hashed) */
    uint32_t h = /*(hash pointer value, which includes realm and permissions)*/
      djbhash((char *)(intptr_t)require, sizeof(intptr_t), DJBHASH_INIT);
    h = djbhash(username, ulen, h);
    return (int32_t)h;
}

static http_auth_cache_entry *
http_auth_cache_query (splay_tree ** const sptree, const int ndx)
{
    *sptree = splaytree_splay(*sptree, ndx);
    return (*sptree && (*sptree)->key == ndx) ? (*sptree)->data : NULL;
}

static void
http_auth_cache_insert (splay_tree ** const sptree, const int ndx, void * const data, void(data_free_fn)(void *))
{
    /*(not necessary to re-splay (with current usage) since single-threaded
     * and splaytree has not been modified since http_auth_cache_query())*/
    /* *sptree = splaytree_splay(*sptree, ndx); */
    if (NULL == *sptree || (*sptree)->key != ndx)
        *sptree = splaytree_insert_splayed(*sptree, ndx, data);
    else { /* collision; replace old entry */
        data_free_fn((*sptree)->data);
        (*sptree)->data = data;
    }
}

/* walk though cache, collect expired ids, and remove them in a second loop */
static void
mod_auth_tag_old_entries (splay_tree * const t, int * const keys, int * const ndx, const time_t max_age, const unix_time64_t cur_ts)
{
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/
    if (t->left)
        mod_auth_tag_old_entries(t->left, keys, ndx, max_age, cur_ts);
    if (t->right)
        mod_auth_tag_old_entries(t->right, keys, ndx, max_age, cur_ts);
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/

    const http_auth_cache_entry * const ae = t->data;
    if (cur_ts - ae->ctime > max_age)
        keys[(*ndx)++] = t->key;
}

__attribute_noinline__
static void
mod_auth_periodic_cleanup(splay_tree **sptree_ptr, const time_t max_age, const unix_time64_t cur_ts)
{
    splay_tree *sptree = *sptree_ptr;
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    do {
        if (!sptree) break;
        max_ndx = 0;
        mod_auth_tag_old_entries(sptree, keys, &max_ndx, max_age, cur_ts);
        for (i = 0; i < max_ndx; ++i) {
            sptree = splaytree_splay_nonnull(sptree, keys[i]);
            http_auth_cache_entry_free(sptree->data);
            sptree = splaytree_delete_splayed_node(sptree);
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
    *sptree_ptr = sptree;
}

TRIGGER_FUNC(mod_auth_periodic)
{
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_monotonic_secs;
    if (cur_ts & 0x7) return HANDLER_GO_ON; /*(continue once each 8 sec)*/
    UNUSED(srv);

    /* future: might construct array of (http_auth_cache *) at startup
     *         to avoid the need to search for them here */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    if (NULL == p->cvlist) return HANDLER_GO_ON;
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; cpv->k_id != -1; ++cpv) {
            if (cpv->k_id != 3) continue; /* k_id == 3 for auth.cache */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            http_auth_cache *ac = cpv->v.v;
            mod_auth_periodic_cleanup(&ac->sptree, ac->max_age, cur_ts);
        }
    }

    return HANDLER_GO_ON;
}




static handler_t mod_auth_check_basic(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);
static handler_t mod_auth_check_digest(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);
static handler_t mod_auth_check_extern(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);

INIT_FUNC(mod_auth_init) {
	static http_auth_scheme_t http_auth_scheme_basic  = { "basic",  mod_auth_check_basic,  NULL };
	static http_auth_scheme_t http_auth_scheme_digest = { "digest", mod_auth_check_digest, NULL };
	static const http_auth_scheme_t http_auth_scheme_extern = { "extern", mod_auth_check_extern, NULL };
	plugin_data *p = ck_calloc(1, sizeof(*p));

	/* register http_auth_scheme_* */
	http_auth_scheme_basic.p_d = p;
	http_auth_scheme_set(&http_auth_scheme_basic);
	http_auth_scheme_digest.p_d = p;
	http_auth_scheme_set(&http_auth_scheme_digest);
	http_auth_scheme_set(&http_auth_scheme_extern);

	return p;
}

FREE_FUNC(mod_auth_free) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 1: /* auth.require */
                array_free(cpv->v.v);
                break;
              case 3: /* auth.cache */
                http_auth_cache_free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }

    http_auth_dumbdata_reset();
}

/* data type for mod_auth structured data
 * (parsed from auth.require array of strings) */
typedef struct {
    DATA_UNSET;
    http_auth_require_t *require;
} data_auth;

static void data_auth_free(data_unset *d)
{
    data_auth * const dauth = (data_auth *)d;
    free(dauth->key.ptr);
    http_auth_require_free(dauth->require);
    free(dauth);
}

__attribute_returns_nonnull__
static data_auth *data_auth_init(void)
{
    static const struct data_methods fn = {
      NULL, /* copy must not be called on this data */
      data_auth_free,
      NULL, /* insert_dup must not be called on this data */
    };
    data_auth * const dauth = ck_calloc(1, sizeof(*dauth));
    dauth->type       = TYPE_OTHER;
    dauth->fn         = &fn;

    dauth->require = http_auth_require_init();

    return dauth;
}

static int mod_auth_algorithm_parse(http_auth_info_t *ai, const char *s, size_t len) {
    if (0 == len) {
        ai->dalgo = HTTP_AUTH_DIGEST_MD5;
        ai->dlen  = HTTP_AUTH_DIGEST_MD5_BINLEN;
        return 1;
    }

    if (len > 5
        && (s[len-5]       ) == '-'
        && (s[len-4] | 0x20) == 's'
        && (s[len-3] | 0x20) == 'e'
        && (s[len-2] | 0x20) == 's'
        && (s[len-1] | 0x20) == 's') {
        ai->dalgo = HTTP_AUTH_DIGEST_SESS;
        len -= 5;
    }
    else {
        ai->dalgo = HTTP_AUTH_DIGEST_NONE;
    }

    if (3 == len
        && 'm' == (s[0] | 0x20)
        && 'd' == (s[1] | 0x20)
        && '5' == (s[2]       )) {
        ai->dalgo |= HTTP_AUTH_DIGEST_MD5;
        ai->dlen   = HTTP_AUTH_DIGEST_MD5_BINLEN;
        return 1;
    }
  #ifdef USE_LIB_CRYPTO
    else if (len >= 7
             && 's' == (s[0] | 0x20)
             && 'h' == (s[1] | 0x20)
             && 'a' == (s[2] | 0x20)
             && '-' == (s[3]       )) {
        if (len == 7 && s[4] == '2' && s[5] == '5' && s[6] == '6') {
            ai->dalgo |= HTTP_AUTH_DIGEST_SHA256;
            ai->dlen   = HTTP_AUTH_DIGEST_SHA256_BINLEN;
            return 1;
        }
      #ifdef USE_LIB_CRYPTO_SHA512_256
        if (len == 11 && 0 == memcmp(s+4, "512-256", 7)) {
            ai->dalgo |= HTTP_AUTH_DIGEST_SHA512_256;
            ai->dlen   = HTTP_AUTH_DIGEST_SHA512_256_BINLEN;
            return 1;
        }
      #endif
    }
  #endif
    return 0; /*(error)*/
}

static int mod_auth_algorithms_parse(int *algorithm, buffer *algos) {
    for (const char *s = algos->ptr, *p; s; s = p ? p+1 : NULL) {
        http_auth_info_t ai;
        p = strchr(s, '|');
        if (!mod_auth_algorithm_parse(&ai, s, p ? (size_t)(p - s) : strlen(s)))
            return 0;
        *algorithm |= ai.dalgo;
    }
    return 1;
}

static int mod_auth_require_parse (http_auth_require_t * const require, const buffer *b, log_error_st *errh)
{
    /* user=name1|user=name2|group=name3|host=name4 */

    const char *str = b->ptr;
    const char *p;

    if (buffer_is_equal_string(b, CONST_STR_LEN("valid-user"))) {
        require->valid_user = 1;
        return 1; /* success */
    }

    do {
        const char *eq;
        size_t len;
        p = strchr(str, '|');
        len = NULL != p ? (size_t)(p - str) : strlen(str);
        eq = memchr(str, '=', len);
        if (NULL == eq) {
            log_error(errh, __FILE__, __LINE__,
              "error parsing auth.require 'require' field: missing '=' "
              "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\"). "
              "error value: %s error near: %s", b->ptr, str);
            return 0;
        }
        if (eq[1] == '|' || eq[1] == '\0') {
            log_error(errh, __FILE__, __LINE__,
              "error parsing auth.require 'require' field: "
              "missing token after '=' "
              "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\"). "
              "error value: %s error near: %s", b->ptr, str);
            return 0;
        }

        switch ((int)(eq - str)) {
          case 4:
            if (0 == memcmp(str, CONST_STR_LEN("user"))) {
                /*("user=" is 5)*/
                array_insert_value(&require->user, str+5, len-5);
                continue;
            }
            else if (0 == memcmp(str, CONST_STR_LEN("host"))) {
                /*("host=" is 5)*/
                array_insert_value(&require->host, str+5, len-5);
                log_error(errh, __FILE__, __LINE__,
                  "warning parsing auth.require 'require' field: "
                  "'host' not implemented; field value: %s", b->ptr);
                continue;
            }
            break; /* to error */
          case 5:
            if (0 == memcmp(str, CONST_STR_LEN("group"))) {
                /*("group=" is 6)*/
                array_insert_value(&require->group, str+6, len-6);
              #if 0/*(supported by mod_authn_ldap, but not all other backends)*/
                log_error(errh, __FILE__, __LINE__,
                  "warning parsing auth.require 'require' field: "
                  "'group' not implemented; field value: %s", b->ptr);
              #endif
                continue;
            }
            break; /* to error */
          case 10:
            if (0 == memcmp(str, CONST_STR_LEN("valid-user"))) {
                log_error(errh, __FILE__, __LINE__,
                  "error parsing auth.require 'require' field: "
                  "valid user can not be combined with other require rules "
                  "(expecting \"valid-user\" or "
                  "\"user=a|user=b|group=g|host=h\"). error value: %s", b->ptr);
                return 0;
            }
            break; /* to error */
          default:
            break; /* to error */
        }

        log_error(errh, __FILE__, __LINE__,
          "error parsing auth.require 'require' field: "
          "invalid/unsupported token "
          "(expecting \"valid-user\" or \"user=a|user=b|group=g|host=h\"). "
          "error value: %s error near: %s", b->ptr, str);
        return 0;

    } while (p && *((str = p+1)));

    return 1; /* success */
}

static handler_t mod_auth_require_parse_array(const array *value, array * const auth_require, log_error_st *errh)
{
		for (uint32_t n = 0; n < value->used; ++n) {
			size_t m;
			data_array *da_file = (data_array *)value->data[n];
			const buffer *method = NULL, *realm = NULL, *require = NULL;
			const buffer *nonce_secret = NULL;
			data_unset *userhash = NULL;
			const http_auth_scheme_t *auth_scheme;
			buffer *algos = NULL;
			int algorithm = HTTP_AUTH_DIGEST_SESS;

			if (!array_is_kvstring(&da_file->value)) {
				log_error(errh, __FILE__, __LINE__,
				  "unexpected value for auth.require; expected "
				  "auth.require = ( \"urlpath\" => ( \"option\" => \"value\" ) )");

				return HANDLER_ERROR;
			}

			for (m = 0; m < da_file->value.used; m++) {
				if (da_file->value.data[m]->type == TYPE_STRING) {
					data_string *ds = (data_string *)da_file->value.data[m];
					if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("method"))) {
						method = &ds->value;
					} else if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("realm"))) {
						realm = &ds->value;
					} else if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("require"))) {
						require = &ds->value;
					} else if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("algorithm"))) {
						algos = &ds->value;
					} else if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("nonce_secret"))
					           || buffer_is_equal_string(&ds->key, CONST_STR_LEN("nonce-secret"))) {
						nonce_secret = &ds->value;
					} else if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("userhash"))) {
						userhash = (data_unset *)ds;
					} else {
						log_error(errh, __FILE__, __LINE__,
						  "the field is unknown in: "
						  "auth.require = ( \"...\" => ( ..., -> \"%s\" <- => \"...\" ) )",
						  da_file->value.data[m]->key.ptr);

						return HANDLER_ERROR;
					}
				} else {
					log_error(errh, __FILE__, __LINE__,
					  "a string was expected for: "
					  "auth.require = ( \"...\" => ( ..., -> \"%s\" <- => \"...\" ) )",
					  da_file->value.data[m]->key.ptr);

					return HANDLER_ERROR;
				}
			}

			if (!method || buffer_is_blank(method)) {
				log_error(errh, __FILE__, __LINE__,
				  "the method field is missing or blank in: "
				  "auth.require = ( \"...\" => ( ..., \"method\" => \"...\" ) )");
				return HANDLER_ERROR;
			} else {
				auth_scheme = http_auth_scheme_get(method);
				if (NULL == auth_scheme) {
					log_error(errh, __FILE__, __LINE__,
					  "unknown method %s (e.g. \"basic\", \"digest\" or \"extern\") in "
					  "auth.require = ( \"...\" => ( ..., \"method\" => \"...\") )", method->ptr);
					return HANDLER_ERROR;
				}
			}

			if (!realm) {
				log_error(errh, __FILE__, __LINE__,
				  "the realm field is missing in: "
				  "auth.require = ( \"...\" => ( ..., \"realm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (!require || buffer_is_blank(require)) {
				log_error(errh, __FILE__, __LINE__,
				  "the require field is missing or blank in: "
				  "auth.require = ( \"...\" => ( ..., \"require\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (!algos || buffer_is_blank(algos)) {
				algorithm |= HTTP_AUTH_DIGEST_MD5;
			} else if (!mod_auth_algorithms_parse(&algorithm, algos)) {
				log_error(errh, __FILE__, __LINE__,
				  "invalid algorithm in: "
				  "auth.require = ( \"...\" => ( ..., \"algorithm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			for (uint32_t o = 0; o < n; ++o) {
				const buffer *k = &((data_array *)value->data[o])->key;
				if (buffer_clen(&da_file->key) >= buffer_clen(k)
				    && 0 == strncmp(da_file->key.ptr, k->ptr, buffer_clen(k))) {
					log_error(errh, __FILE__, __LINE__,
					  "auth.require path (\"%s\") will never match due to "
					  "earlier match (\"%s\"); fix by sorting longer paths "
					  "before shorter paths", da_file->key.ptr, k->ptr);
					break;
				}
			}

			if (require) { /*(always true at this point)*/
				data_auth * const dauth = data_auth_init();
				buffer_copy_buffer(&dauth->key, &da_file->key);
				dauth->require->scheme = auth_scheme;
				dauth->require->algorithm = algorithm;
				dauth->require->realm = realm;
				dauth->require->nonce_secret = nonce_secret; /*(NULL is ok)*/
				dauth->require->userhash = config_plugin_value_to_bool(userhash, 0);
				if (!mod_auth_require_parse(dauth->require, require, errh)) {
					dauth->fn->free((data_unset *)dauth);
					return HANDLER_ERROR;
				}
				array_insert_unique(auth_require, (data_unset *)dauth);
			}
		}

	return HANDLER_GO_ON;
}

static void mod_auth_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->auth_backend = cpv->v.v;
        break;
      case 1: /* auth.require */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->auth_require = cpv->v.v;
        break;
      case 2: /* auth.extern-authn */
        pconf->auth_extern_authn = cpv->v.u;
        break;
      case 3: /* auth.cache */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->auth_cache = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_auth_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_auth_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_auth_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_auth_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_auth_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.require"),
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.extern-authn"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.cache"),
        T_CONFIG_ARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_auth"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend */
                if (!buffer_is_blank(cpv->v.b)) {
                    const http_auth_backend_t * const auth_backend =
                      http_auth_backend_get(cpv->v.b);
                    if (NULL == auth_backend) {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "auth.backend not supported: %s", cpv->v.b->ptr);
                        return HANDLER_ERROR;
                    }
                    *(const http_auth_backend_t **)&cpv->v.v = auth_backend;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              case 1: /* auth.require */
                {
                    array * const a = array_init(4);
                    if (HANDLER_GO_ON !=
                        mod_auth_require_parse_array(cpv->v.a, a, srv->errh)) {
                        array_free(a);
                        return HANDLER_ERROR;
                    }
                    cpv->v.a = a;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              case 2: /* auth.extern-authn */
                break;
              case 3: /* auth.cache */
                cpv->v.v = http_auth_cache_init(cpv->v.a);
                cpv->vtype = T_CONFIG_LOCAL;
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
            mod_auth_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static handler_t mod_auth_uri_handler(request_st * const r, void *p_d) {
	plugin_config pconf;
	mod_auth_patch_config(r, p_d, &pconf);

	if (pconf.auth_require == NULL) return HANDLER_GO_ON;

	/* search auth directives for first prefix match against URL path */
	/* if we have a case-insensitive FS we have to lower-case the URI here too */
	const data_auth * const dauth = (!r->conf.force_lowercase_filenames)
	   ? (data_auth *)array_match_key_prefix(pconf.auth_require, &r->uri.path)
	   : (data_auth *)array_match_key_prefix_nc(pconf.auth_require, &r->uri.path);
	if (NULL == dauth) return HANDLER_GO_ON;

	{
			if (pconf.auth_extern_authn) {
				const buffer *vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
				if (NULL != vb && http_auth_match_rules(dauth->require, vb->ptr, NULL, NULL)) {
					return HANDLER_GO_ON;
				}
			}
			/* NOTE: &pconf passed instead of scheme->p_d
			 * Third-party scheme could access its own static plugin_data config
			 * or needs to call its own _patch_config() to get its config */
			const http_auth_scheme_t * const scheme = dauth->require->scheme;
			return scheme->checkfn(r, &pconf, dauth->require, pconf.auth_backend);
	}
}


__attribute_cold__
__declspec_dllexport__
int mod_auth_plugin_init(plugin *p);
int mod_auth_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "auth";
	p->init        = mod_auth_init;
	p->set_defaults = mod_auth_set_defaults;
	p->handle_trigger = mod_auth_periodic;
	p->handle_uri_clean = mod_auth_uri_handler;
	p->cleanup     = mod_auth_free;

	return 0;
}




/*
 * auth schemes (basic, digest, extern)
 *
 * (could be in separate file from mod_auth.c as long as registration occurs)
 */

#include "sys-crypto-md.h"
#include "base64.h"
#include "rand.h"
#include "http_header.h"

__attribute_cold__
static handler_t
mod_auth_send_400_bad_request (request_st * const r)
{
    /* a field was missing or invalid */
    return http_status_set_err(r, 400); /* Bad Request */
}



__attribute_noinline__
static handler_t
mod_auth_send_401_unauthorized_basic (request_st * const r, const buffer * const realm)
{
    buffer_append_str3(
      http_header_response_set_ptr(r, HTTP_HEADER_WWW_AUTHENTICATE,
                                   CONST_STR_LEN("WWW-Authenticate")),
      CONST_STR_LEN("Basic realm=\""),
      BUF_PTR_LEN(realm),
      CONST_STR_LEN("\", charset=\"UTF-8\""));
    return http_status_set_err(r, 401); /* Unauthorized */
}


__attribute_cold__
static handler_t
mod_auth_basic_misconfigured (request_st * const r, const struct http_auth_backend_t * const backend)
{
    if (NULL == backend)
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth.backend not configured for %s", r->uri.path.ptr);
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth.require \"method\" => \"basic\" invalid "
          "(try \"digest\"?) for %s", r->uri.path.ptr);

    return http_status_set_err(r, 500); /* Internal Server Error */
}


static handler_t
mod_auth_check_basic(request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend)
{
    if (NULL == backend || NULL == backend->basic)
        return mod_auth_basic_misconfigured(r, backend);

    const buffer * const vb =
      http_header_request_get(r, HTTP_HEADER_AUTHORIZATION,
                              CONST_STR_LEN("Authorization"));
    if (NULL == vb || !buffer_eq_icase_ssn(vb->ptr, CONST_STR_LEN("Basic ")))
        return mod_auth_send_401_unauthorized_basic(r, require->realm);
  #ifdef __COVERITY__
    if (buffer_clen(vb) < sizeof("Basic ")-1)
        return mod_auth_send_400_bad_request(r);
  #endif

    size_t ulen = buffer_clen(vb) - (sizeof("Basic ")-1);
    size_t pwlen;
    char *pw;
    char user[1024];

    /* base64-decode Authorization into username:password string;
     * limit base64-decoded username:password string to fit into 1k buf */
    if (ulen > 1363) /*(1363/4*3+3 = 1023)*/
        return mod_auth_send_401_unauthorized_basic(r, require->realm);
    /* coverity[overflow_sink : FALSE] */
    ulen = li_base64_dec((unsigned char *)user, sizeof(user),
                         vb->ptr+sizeof("Basic ")-1, ulen, BASE64_STANDARD);
    if (0 == ulen) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "decoding base64-string failed %s", vb->ptr+sizeof("Basic ")-1);
        return mod_auth_send_400_bad_request(r);
    }
    user[ulen] = '\0';
    pw = memchr(user, ':', ulen);
    if (NULL == pw) {
        log_error(r->conf.errh, __FILE__, __LINE__, "missing ':' in %s", user);
        return mod_auth_send_400_bad_request(r);
    }
    *pw++ = '\0';
    pwlen = (size_t)(user + ulen - pw);
    ulen  = (size_t)(pw - 1 - user);

    plugin_config * const pconf = p_d; /* pconf; see mod_auth_uri_handler() */
    splay_tree ** const sptree = pconf->auth_cache
      ? &pconf->auth_cache->sptree
      : NULL;
    http_auth_cache_entry *ae = NULL;
    handler_t rc = HANDLER_ERROR;
    int ndx = -1;
    if (sptree) {
        ndx = http_auth_cache_hash(require, user, ulen);
        ae = http_auth_cache_query(sptree, ndx);
        if (ae && ae->require == require
            && ulen == ae->ulen && 0 == memcmp(user, ae->username, ulen))
            rc = ck_memeq_const_time(ae->pwdigest, ae->dlen, pw, pwlen)
              ? HANDLER_GO_ON
              : HANDLER_ERROR;
        else /*(not found or hash collision)*/
            ae = NULL;
    }

    if (NULL == ae) {
        const buffer userb = { user, ulen+1, 0 };
        rc = backend->basic(r, backend->p_d, require, &userb, pw);
    }

    switch (rc) {
    case HANDLER_GO_ON:
        http_auth_setenv(r, user, ulen, CONST_STR_LEN("Basic"));
        if (sptree && NULL == ae) { /*(cache (new) successful result)*/
            ae = http_auth_cache_entry_init(require, 0, user, ulen, user, ulen,
                                            pw, pwlen);
            http_auth_cache_insert(sptree, ndx, ae, http_auth_cache_entry_free);
        }
        break;
    case HANDLER_WAIT_FOR_EVENT:
    case HANDLER_FINISHED:
        break;
    case HANDLER_ERROR:
    default:
        log_error(r->conf.errh, __FILE__, __LINE__,
          "password doesn't match for %s username: %s IP: %s",
          r->uri.path.ptr, user, r->dst_addr_buf->ptr);
        r->keep_alive = -1; /*(disable keep-alive if bad password)*/
        rc = mod_auth_send_401_unauthorized_basic(r, require->realm);
        break;
    }

    ck_memzero(pw, pwlen);
    return rc;
}



enum http_auth_digest_params_e {
  e_username = 0
 ,e_realm
 ,e_nonce
 ,e_uri
 ,e_algorithm
 ,e_qop
 ,e_cnonce
 ,e_nc
 ,e_response
 ,e_userstar
 ,e_userhash
 ,http_auth_digest_params_sz /*(last item)*/
};

typedef struct http_auth_digest_params_t {
    const char *ptr[http_auth_digest_params_sz];
    uint16_t len[http_auth_digest_params_sz];
    unix_time64_t send_nextnonce_ts;
    unsigned char rdigest[MD_DIGEST_LENGTH_MAX];/*(earlier members get 0-init)*/
} http_auth_digest_params_t;


static void
mod_auth_digest_mutate (http_auth_info_t * const ai, const http_auth_digest_params_t * const dp, const buffer * const method)
{
    force_assert(method);
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
    size_t n;
    struct const_iovec iov[11];
    char a1[MD_DIGEST_LENGTH_MAX*2];
    char a2[MD_DIGEST_LENGTH_MAX*2];

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        /* http://www.rfc-editor.org/errata_search.php?rfc=2617
         * Errata ID: 1649 */
        iov[0].iov_base = a1;
        iov[0].iov_len  = ai->dlen*2;
        iov[1].iov_base = ":";
        iov[1].iov_len  = 1;
        iov[2].iov_base = dp->ptr[e_nonce];
        iov[2].iov_len  = dp->len[e_nonce];
        iov[3].iov_base = ":";
        iov[3].iov_len  = 1;
        iov[4].iov_base = dp->ptr[e_cnonce];
        iov[4].iov_len  = dp->len[e_cnonce];
        digest_iov(ai->digest, iov, 5);
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
    }

    /* calculate H(A2) */
    iov[0].iov_base = method->ptr;
    iov[0].iov_len  = buffer_clen(method);
    iov[1].iov_base = ":";
    iov[1].iov_len  = 1;
    iov[2].iov_base = dp->ptr[e_uri];
    iov[2].iov_len  = dp->len[e_uri];
    n = 3;
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (dp->ptr[e_qop] && buffer_eq_icase_ss(dp->ptr[e_qop], dp->len[e_qop],
                                             CONST_STR_LEN("auth-int"))) {
        iov[3].iov_base = ":";
        iov[3].iov_len  = 1;
        iov[4].iov_base = [body checksum];
        iov[4].iov_len  = ai->dlen*2;
        n = 5;
    }
  #endif
    digest_iov(ai->digest, iov, n);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    iov[0].iov_base = a1;
    iov[0].iov_len  = ai->dlen*2;
    iov[1].iov_base = ":";
    iov[1].iov_len  = 1;
    iov[2].iov_base = dp->ptr[e_nonce];
    iov[2].iov_len  = dp->len[e_nonce];
    iov[3].iov_base = ":";
    iov[3].iov_len  = 1;
    n = 4;
    if (dp->len[e_qop]) {
        iov[4].iov_base = dp->ptr[e_nc];
        iov[4].iov_len  = dp->len[e_nc];
        iov[5].iov_base = ":";
        iov[5].iov_len  = 1;
        iov[6].iov_base = dp->ptr[e_cnonce];
        iov[6].iov_len  = dp->len[e_cnonce];
        iov[7].iov_base = ":";
        iov[7].iov_len  = 1;
        iov[8].iov_base = dp->ptr[e_qop];
        iov[8].iov_len  = dp->len[e_qop];
        iov[9].iov_base = ":";
        iov[9].iov_len  = 1;
        n = 10;
    }
    iov[n].iov_base = a2;
    iov[n].iov_len  = ai->dlen*2;
    digest_iov(ai->digest, iov, n+1);
}


static void
mod_auth_append_nonce (buffer *b, unix_time64_t cur_ts, const struct http_auth_require_t *require, int dalgo, unsigned int *rndptr)
{
    buffer_append_uint_hex(b, (uintmax_t)cur_ts);
    buffer_append_char(b, ':');
    const buffer * const nonce_secret = require->nonce_secret;
    unsigned int rnd;
    if (NULL == nonce_secret)
        rnd = rndptr ? *rndptr : (unsigned int)li_rand_pseudo();
    else { /*(do not directly expose random number generator single value)*/
        rndptr
          ? (void)(rnd = *rndptr)
          : li_rand_pseudo_bytes((unsigned char *)&rnd, sizeof(rnd));
        buffer_append_uint_hex(b, (uintmax_t)rnd);
        buffer_append_char(b, ':');
    }

    size_t n;
    struct const_iovec iov[3];

  #if 0
    char a1[LI_ITOSTRING_LENGTH];
    char a2[LI_ITOSTRING_LENGTH];
    iov[0].iov_base = a1;
    iov[0].iov_len  = li_itostrn(a1, sizeof(a1), cur_ts);
    iov[1].iov_base = a2;
    iov[1].iov_len  = li_itostrn(a2, sizeof(a2), rnd);
  #else
    iov[0].iov_base = &cur_ts;
    iov[0].iov_len  = sizeof(cur_ts);
    iov[1].iov_base = &rnd;
    iov[1].iov_len  = sizeof(rnd);
  #endif
    n = 2;
    if (nonce_secret) {
        iov[2].iov_base = nonce_secret->ptr;
        iov[2].iov_len  = buffer_clen(nonce_secret);
        n = 3;
    }

    unsigned char h[MD_DIGEST_LENGTH_MAX];
    switch (dalgo) {
     #ifdef USE_LIB_CRYPTO
      #ifdef USE_LIB_CRYPTO_SHA512_256
      case HTTP_AUTH_DIGEST_SHA512_256:
        SHA512_256_iov(h, iov, n);
        n = HTTP_AUTH_DIGEST_SHA512_256_BINLEN;
        break;
      #endif
      case HTTP_AUTH_DIGEST_SHA256:
        SHA256_iov(h, iov, n);
        n = HTTP_AUTH_DIGEST_SHA256_BINLEN;
        break;
     #endif
      /*case HTTP_AUTH_DIGEST_MD5:*/
      default:
        MD5_iov(h, iov, n);
        n = HTTP_AUTH_DIGEST_MD5_BINLEN;
        break;
    }
    li_tohex(buffer_extend(b, n*2), n*2, (const char *)h, n);
}


static void
mod_auth_digest_www_authenticate (buffer *b, unix_time64_t cur_ts, const struct http_auth_require_t *require, int nonce_stale)
{
    int algos = nonce_stale ? nonce_stale : require->algorithm;
    int n = 0;
    int algoid[3];
    unsigned int algolen[3];
    const char *algoname[3];
  #ifdef USE_LIB_CRYPTO
   #ifdef USE_LIB_CRYPTO_SHA512_256
    if (algos & HTTP_AUTH_DIGEST_SHA512_256) {
        algoid[n] = HTTP_AUTH_DIGEST_SHA512_256;
        algoname[n] = "SHA-512-256";
        algolen[n] = sizeof("SHA-512-256")-1;
        ++n;
    }
   #endif
    if (algos & HTTP_AUTH_DIGEST_SHA256) {
        algoid[n] = HTTP_AUTH_DIGEST_SHA256;
        algoname[n] = "SHA-256";
        algolen[n] = sizeof("SHA-256")-1;
        ++n;
    }
  #endif
    if (algos & HTTP_AUTH_DIGEST_MD5) {
        algoid[n] = HTTP_AUTH_DIGEST_MD5;
        algoname[n] = "MD5";
        algolen[n] = sizeof("MD5")-1;
        ++n;
    }

    buffer_clear(b);
    for (int i = 0; i < n; ++i) {
        struct const_iovec iov[] = {
          { CONST_STR_LEN("\r\nWWW-Authenticate: ") }
         ,{ CONST_STR_LEN("Digest realm=\"") }
         ,{ BUF_PTR_LEN(require->realm) }
         ,{ CONST_STR_LEN("\", charset=\"UTF-8\", algorithm=") }
         ,{ algoname[i], algolen[i] }
         ,{ CONST_STR_LEN(", nonce=\"") }
        };
        buffer_append_iovec(b, iov+(0==i), sizeof(iov)/sizeof(*iov)-(0==i));
        mod_auth_append_nonce(b, cur_ts, require, algoid[i], NULL);
        buffer_append_string_len(b, CONST_STR_LEN("\", qop=\"auth\""));
        if (require->userhash) {
            buffer_append_string_len(b, CONST_STR_LEN(", userhash=true"));
        }
        if (nonce_stale) {
            buffer_append_string_len(b, CONST_STR_LEN(", stale=true"));
        }
    }
}


__attribute_noinline__
static handler_t
mod_auth_send_401_unauthorized_digest(request_st * const r, const struct http_auth_require_t * const require, int nonce_stale)
{
    mod_auth_digest_www_authenticate(
      http_header_response_set_ptr(r, HTTP_HEADER_WWW_AUTHENTICATE,
                                   CONST_STR_LEN("WWW-Authenticate")),
      log_epoch_secs, require, nonce_stale);
    return http_status_set_err(r, 401); /* Unauthorized */
}


static void
mod_auth_digest_authentication_info (buffer *b, unix_time64_t cur_ts, const struct http_auth_require_t *require, int dalgo)
{
    buffer_clear(b);
    buffer_append_string_len(b, CONST_STR_LEN("nextnonce=\""));
    mod_auth_append_nonce(b, cur_ts, require, dalgo, NULL);
    buffer_append_char(b, '"');
}


static handler_t
mod_auth_digest_get (request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend, http_auth_info_t * const ai)
{
    plugin_config * const pconf = p_d; /* pconf; see mod_auth_uri_handler() */
    splay_tree ** const sptree = pconf->auth_cache
      ? &pconf->auth_cache->sptree
      : NULL;
    http_auth_cache_entry *ae = NULL;
    handler_t rc = HANDLER_GO_ON;
    int ndx = -1;

    const char *user = ai->username;
    const uint32_t ulen = ai->ulen;
    char userbuf[sizeof(ai->userbuf)];
    if (ai->userhash && ulen <= sizeof(userbuf)) {
        /*(lowercase hex in userhash for consistency)*/
        const char * const restrict s = ai->username;
        for (uint_fast32_t i = 0; i < ulen; ++i)
            userbuf[i] = !light_isupper(s[i]) ? s[i] : (s[i] | 0x20);
        user = userbuf;
    }

    if (sptree) {
        ndx = http_auth_cache_hash(require, user, ulen);
        ae = http_auth_cache_query(sptree, ndx);
        if (ae && ae->require == require
            && ae->dalgo == ai->dalgo
            && ae->dlen == ai->dlen
            && ae->klen == ulen
            && 0 == memcmp(ae->k, user, ulen)
            && (ae->k == ae->username || ai->userhash)) {
            memcpy(ai->digest, ae->pwdigest, ai->dlen);
            if (ae->k != ae->username) { /*(userhash was key; copy username)*/
                if (__builtin_expect( (ae->ulen <= sizeof(ai->userbuf)), 1)) {
                    ai->ulen = ae->ulen;
                    ai->username = memcpy(ai->userbuf, ae->username, ae->ulen);
                }
            }
        }
        else /*(not found or hash collision)*/
            ae = NULL;
    }

    if (NULL == ae) {
        if (ai->userhash && ulen <= sizeof(ai->userbuf))
            ai->username = memcpy(ai->userbuf, userbuf, ulen);
            /* ai->username (lowercase userhash) will be replaced by username */
        rc = backend->digest(r, backend->p_d, ai);
    }

    switch (rc) {
    case HANDLER_GO_ON:
        break;
    case HANDLER_WAIT_FOR_EVENT:
        return HANDLER_WAIT_FOR_EVENT;
    case HANDLER_FINISHED:
        return HANDLER_FINISHED;
    case HANDLER_ERROR:
    default:
        r->keep_alive = -1; /*(disable keep-alive if unknown user)*/
        return mod_auth_send_401_unauthorized_digest(r, require, 0);
    }

    if (sptree && NULL == ae) { /*(cache digest from backend)*/
        ae = http_auth_cache_entry_init(require, ai->dalgo, user, ulen,
                                        ai->username, ai->ulen,
                                        (char *)ai->digest, ai->dlen);
        http_auth_cache_insert(sptree, ndx, ae, http_auth_cache_entry_free);
    }

    return rc;
}


__attribute_cold__
static handler_t
mod_auth_digest_misconfigured (request_st * const r, const struct http_auth_backend_t * const backend)
{
    if (NULL == backend)
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth.backend not configured for %s", r->uri.path.ptr);
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth.require \"method\" => \"digest\" invalid "
          "(try \"basic\"?) for %s", r->uri.path.ptr);

    return http_status_set_err(r, 500); /* Internal Server Error */
}


static void
mod_auth_digest_parse_authorization (http_auth_digest_params_t * const dp, const char *c)
{
    struct digest_kv {
        const char *key;
        uint32_t klen;
        enum http_auth_digest_params_e id;
    };

    static const struct digest_kv dkv[] = {
        { CONST_STR_LEN("username"),  e_username },
        { CONST_STR_LEN("realm"),     e_realm },
        { CONST_STR_LEN("nonce"),     e_nonce },
        { CONST_STR_LEN("uri"),       e_uri },
        { CONST_STR_LEN("algorithm"), e_algorithm },
        { CONST_STR_LEN("qop"),       e_qop },
        { CONST_STR_LEN("cnonce"),    e_cnonce },
        { CONST_STR_LEN("nc"),        e_nc },
        { CONST_STR_LEN("response"),  e_response },
        { CONST_STR_LEN("username*"), e_userstar },
        { CONST_STR_LEN("userhash"),  e_userhash },

        { NULL, 0, http_auth_digest_params_sz }
    };

    /* parse credentials from client */
    /* (caller must pass c pointing to string after "Digest ") */
    for (const char *e; *c; c++) {
        /* skip whitespaces */
        while (*c == ' ' || *c == '\t' || *c == ',') ++c;
        if (!*c) break;
        for (e = c; *e!='=' && *e!=' ' && *e!='\t' && *e!='\0'; ++e) ;
        const uint32_t tlen = (uint32_t)(e - c);

        for (int i = 0; dkv[i].key; ++i) {
            if (tlen != dkv[i].klen || 0 != memcmp(c, dkv[i].key, tlen))
                continue;
            c += tlen;
            /* detect and step over '='; ignore BWS (bad whitespace) */
            if (__builtin_expect( (*c != '='), 0)) {
                while (*c == ' ' || *c == '\t') ++c;
                if (*c != '=') return; /*(including '\0')*/
            }
            do { ++c; } while (*c == ' ' || *c == '\t');

            if (*c == '"') {
                for (e = ++c; *e != '"' && *e != '\0'; ++e) {
                    if (*e == '\\' && *++e == '\0') return;
                }
                if (*e != '"') return;
                /* value with "..." *//*(XXX: quoted value not unescaped)*/
            }
            else {
                for (e = c; *e!=',' && *e!=' ' && *e!='\t' && *e!='\0'; ++e) ;
                /* value without "..." */
            }
            dp->ptr[dkv[i].id] = c;
            dp->len[dkv[i].id] = (uint16_t)(e - c);
            c = e;
            if (*c != ',') {
                /*(could more strictly check for linear whitespace)*/
                c = strchr(c, ',');
                if (!c) return;
            }
            break;
        }
    }
}


static handler_t
mod_auth_digest_validate_userstar (request_st * const r, http_auth_digest_params_t * const dp, http_auth_info_t * const ai)
{
    /*assert(dp->ptr[e_userstar]);*/

    if (dp->len[e_userhash] == 4) { /*("true")*/
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: invalid \"username*\" with \"userhash\" = true");
        return mod_auth_send_400_bad_request(r);
    }

    /* "username*" RFC5987 ext-value
     * ext-value = charset  "'" [ language ] "'" value-chars */
    const char *ptr = dp->ptr[e_userstar];
    uint32_t len    = dp->len[e_userstar];
    /* validate and step over charset... */
    if ((*ptr | 0x20) == 'u' && len > 5
        && buffer_eq_icase_ssn(ptr, "utf-8", 5))
        ptr += 5;
    else if ((*ptr | 0x20) == 'i' && len > 10
             && buffer_eq_icase_ssn(ptr, "iso-8859-1", 10))
        ptr += 10;
    else
        ptr = "\n"; /*(invalid char; (not '\''); error below)*/
    /* step over ...'language'... */
    if (*ptr++ != '\''
        || !(ptr = memchr(ptr, '\'',
                          len - (uint32_t)(ptr - dp->ptr[e_userstar])))) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: invalid \"username*\" ext-value");
        return mod_auth_send_400_bad_request(r);
    }
    ++ptr;

    /* decode %XX encodings (could be more efficient by combining tests) */
    buffer * const tb = r->tmp_buf;
    buffer_copy_string_len(tb, ptr, len-(uint32_t)(ptr - dp->ptr[e_userstar]));
    buffer_urldecode_path(tb);
    if (dp->ptr[e_userstar][0] == 'u' && !buffer_is_valid_UTF8(tb)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: invalid \"username*\" invalid UTF-8");
        return mod_auth_send_400_bad_request(r);
    }
    len = buffer_clen(tb);
    if (len > sizeof(ai->userbuf)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: invalid \"username*\" too long");
        return mod_auth_send_400_bad_request(r);
    }
    for (ptr = tb->ptr; *ptr; ++ptr) {
        /* prohibit decoded control chars, including '\0','\r','\n' */
        /* (theoretically could permit '\t', but not currently done) */
        if (*(unsigned char *)ptr < 0x20 || *ptr == 127) { /* iscntrl() */
            log_error(r->conf.errh, __FILE__, __LINE__,
              "digest: invalid \"username*\" contains ctrl chars");
            return mod_auth_send_400_bad_request(r);
        }
    }

    ai->ulen     = len;
    ai->username = memcpy(ai->userbuf, tb->ptr, len);
    return HANDLER_GO_ON;
}


static handler_t
mod_auth_digest_validate_params (request_st * const r, const struct http_auth_require_t * const require, http_auth_digest_params_t * const dp, http_auth_info_t * const ai)
{
    /* check for required parameters */
    if ((!dp->ptr[e_qop] || (dp->ptr[e_nc] && dp->ptr[e_cnonce]))
        && ((NULL != dp->ptr[e_username]) ^ (NULL != dp->ptr[e_userstar]))
        && dp->ptr[e_realm]
        && dp->ptr[e_nonce]
        && dp->ptr[e_uri]
        && dp->ptr[e_response]) {
        ai->username = dp->ptr[e_username];
        ai->ulen     = dp->len[e_username];
        ai->realm    = dp->ptr[e_realm];
        ai->rlen     = dp->len[e_realm];
        ai->userhash = (dp->len[e_userhash]==4);/*("true", not "false",absent)*/
        if (!ai->username) { /* (dp->ptr[e_userstar]) */
            if (HANDLER_GO_ON != mod_auth_digest_validate_userstar(r, dp, ai))
                return HANDLER_FINISHED;
        }
    }
    else {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: missing field");
        return mod_auth_send_400_bad_request(r);
    }

    if (!buffer_eq_slen(require->realm, ai->realm, ai->rlen)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: realm mismatch");
        return mod_auth_send_401_unauthorized_digest(r, require, 0);
    }

    if (!mod_auth_algorithm_parse(ai,dp->ptr[e_algorithm],dp->len[e_algorithm])
        || !(require->algorithm & ai->dalgo & ~HTTP_AUTH_DIGEST_SESS)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: (%.*s): invalid",
          (int)dp->len[e_algorithm], dp->ptr[e_algorithm]);
        return mod_auth_send_401_unauthorized_digest(r, require, 0);
    }

    /* *-sess requires nonce and cnonce */
    if ((ai->dalgo & HTTP_AUTH_DIGEST_SESS)
        && (!dp->ptr[e_nonce] || !dp->ptr[e_cnonce])) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: (%.*s): missing field",
          (int)dp->len[e_algorithm], dp->ptr[e_algorithm]);
        return mod_auth_send_400_bad_request(r);
    }

    if (0 != li_hex2bin(dp->rdigest, sizeof(dp->rdigest),
                        dp->ptr[e_response], dp->len[e_response])
        || dp->len[e_response] != (ai->dlen << 1)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: (%s): invalid format", dp->ptr[e_response]);
        return mod_auth_send_400_bad_request(r);
    }

    if (dp->ptr[e_qop]&& buffer_eq_icase_ss(dp->ptr[e_qop], dp->len[e_qop],
                                            CONST_STR_LEN("auth-int"))) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: qop=auth-int not supported");
        return mod_auth_send_400_bad_request(r);
    }

    /* detect if attacker is attempting to reuse valid digest for one uri
     * on a different request uri.  Might also happen if intermediate proxy
     * altered client request line.  (Altered request would not result in
     * the same digest as that calculated by the client.)
     * Internal redirects such as with mod_rewrite will modify request uri.
     * Reauthentication is done to detect crossing auth realms, but this
     * uri validation step is bypassed.  r->target_orig is
     * original request-target sent in client request. */
    if (!buffer_eq_slen(&r->target_orig, dp->ptr[e_uri], dp->len[e_uri])) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: auth failed: uri mismatch (%s != %.*s), IP: %s",
          r->target_orig.ptr, (int)dp->len[e_uri], dp->ptr[e_uri],
          r->dst_addr_buf->ptr);
        return mod_auth_send_400_bad_request(r);
    }

    return HANDLER_GO_ON;
}


static handler_t
mod_auth_digest_validate_nonce (request_st * const r, const struct http_auth_require_t * const require, http_auth_digest_params_t * const dp, http_auth_info_t * const ai)
{
    /* check age of nonce.  Note, random data is used in nonce generation
     * in mod_auth_send_401_unauthorized_digest().  If that were replaced
     * with nanosecond time, then nonce secret would remain unique enough
     * for the purposes of Digest auth, and would be reproducible (and
     * verifiable) if nanoseconds were included with seconds as part of the
     * nonce "timestamp:secret".  However, doing so would expose a high
     * precision timestamp of the system to attackers.  timestamp in nonce
     * could theoretically be modified and still produce same md5sum, but
     * that is highly unlikely within a 10 min (moving) window of valid
     * time relative to current time (now).
     * If it is desired to validate that nonces were generated by server,
     * then specify auth.require = ( ... => ( "nonce-secret" => "..." ) )
     * When secret is specified, then instead of nanoseconds, the random
     * data value (included for unique nonces) will be exposed in the nonce
     * along with the timestamp, and the additional secret will be used to
     * validate that the server generated the nonce using that secret. */
    unix_time64_t ts = 0;
    const unsigned char * const nonce = (unsigned char *)dp->ptr[e_nonce];
    int i;
    for (i = 0; i < 16 && light_isxdigit(nonce[i]); ++i)
        ts = (unix_time64_t)((uint64_t)ts << 4) | hex2int(nonce[i]);

    const unix_time64_t cur_ts = log_epoch_secs;
    if (nonce[i++] != ':' || ts > cur_ts || cur_ts - ts > 600) { /*(10 mins)*/
        /* nonce is stale; have client regenerate digest */
        return mod_auth_send_401_unauthorized_digest(r, require, ai->dalgo);
    }

    if (cur_ts - ts > 540)  /*(9 mins)*/
        dp->send_nextnonce_ts = cur_ts;

    if (require->nonce_secret) {
        unsigned int rnd = 0;
        for (int j = i+8; i < j && light_isxdigit(nonce[i]); ++i) {
            rnd = (rnd << 4) + hex2int(nonce[i]);
        }
        if (nonce[i] != ':') {
            /* nonce is invalid;
             * expect extra field w/ require->nonce_secret */
            log_error(r->conf.errh, __FILE__, __LINE__,
              "digest: nonce invalid");
            return mod_auth_send_400_bad_request(r);
        }
        buffer * const tb = r->tmp_buf;
        buffer_clear(tb);
        mod_auth_append_nonce(tb, ts, require, ai->dalgo, &rnd);
        if (!buffer_eq_slen(tb, dp->ptr[e_nonce], dp->len[e_nonce])) {
            /* nonce not generated using current require->nonce_secret */
            log_error(r->conf.errh, __FILE__, __LINE__,
              "digest: nonce mismatch");
            return mod_auth_send_401_unauthorized_digest(r, require, 0);
        }
    }

    return HANDLER_GO_ON;
}


static handler_t
mod_auth_check_digest (request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend)
{
    if (NULL == backend || NULL == backend->digest)
        return mod_auth_digest_misconfigured(r, backend);

    const buffer * const vb =
      http_header_request_get(r, HTTP_HEADER_AUTHORIZATION,
                              CONST_STR_LEN("Authorization"));
    if (NULL == vb || !buffer_eq_icase_ssn(vb->ptr, CONST_STR_LEN("Digest ")))
        return mod_auth_send_401_unauthorized_digest(r, require, 0);
  #ifdef __COVERITY__
    if (buffer_clen(vb) < sizeof("Digest ")-1)
        return mod_auth_send_400_bad_request(r);
  #endif

    http_auth_digest_params_t dp;
    http_auth_info_t ai;
    handler_t rc;

    /* XXX: should use offsetof() (if portable enough) */
    memset(&dp, 0, sizeof(dp) - sizeof(dp.rdigest));

    mod_auth_digest_parse_authorization(&dp, vb->ptr + sizeof("Digest ")-1);

    rc = mod_auth_digest_validate_params(r, require, &dp, &ai);
    if (__builtin_expect( (HANDLER_GO_ON != rc), 0))
        return rc;

    rc = mod_auth_digest_validate_nonce(r, require, &dp, &ai);
    if (__builtin_expect( (HANDLER_GO_ON != rc), 0))
        return rc;

    rc = mod_auth_digest_get(r, p_d, require, backend, &ai);
    if (__builtin_expect( (HANDLER_GO_ON != rc), 0))
        return rc;

    int eq;
    unsigned char digcpy[sizeof(ai.digest)];
    if (r->h2_connect_ext)
        memcpy(digcpy, ai.digest, ai.dlen);

    mod_auth_digest_mutate(&ai, &dp, http_method_buf(r->http_method));

    eq = ck_memeq_const_time_fixed_len(dp.rdigest, ai.digest, ai.dlen);
    if (r->h2_connect_ext) {
        if (!eq) {
            memcpy(ai.digest, digcpy, ai.dlen);
            mod_auth_digest_mutate(&ai, &dp, http_method_buf(HTTP_METHOD_GET));
            eq = ck_memeq_const_time_fixed_len(dp.rdigest, ai.digest, ai.dlen);
        }
        ck_memzero(digcpy, ai.dlen);
    }

    if (!eq) {
        /*ck_memzero(ai.digest, ai.dlen);*//*skip clear since mutated*/
        /* digest not ok */
        log_error(r->conf.errh, __FILE__, __LINE__,
          "digest: auth failed for %.*s: wrong password, IP: %s",
          (int)ai.ulen, ai.username, r->dst_addr_buf->ptr);
        r->keep_alive = -1; /*(disable keep-alive if bad password)*/
        return mod_auth_send_401_unauthorized_digest(r, require, 0);
    }
    /*ck_memzero(ai.digest, ai.dlen);*//* skip clear since mutated */

    /* check authorization (authz); string args must be '\0'-terminated) */
    buffer * const tb = r->tmp_buf;
    buffer_copy_string_len(tb, ai.username, ai.ulen);
    if (!http_auth_match_rules(require, tb->ptr, NULL, NULL))
        return mod_auth_send_401_unauthorized_digest(r, require, 0);

    if (dp.send_nextnonce_ts) {
        /*(send nextnonce when expiration is approaching)*/
        mod_auth_digest_authentication_info(
          http_header_response_set_ptr(r, HTTP_HEADER_OTHER,
                                       CONST_STR_LEN("Authentication-Info")),
          dp.send_nextnonce_ts /*(cur_ts)*/, require, ai.dalgo);
    }

    http_auth_setenv(r, ai.username, ai.ulen, CONST_STR_LEN("Digest"));
    return HANDLER_GO_ON;
}



static handler_t mod_auth_check_extern(request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend) {
    /* require REMOTE_USER already set */
    const buffer *vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
    UNUSED(p_d);
    UNUSED(backend);
    return (NULL != vb && http_auth_match_rules(require, vb->ptr, NULL, NULL))
      ? HANDLER_GO_ON
      : http_status_set_err(r, 401); /* Unauthorized */
}
