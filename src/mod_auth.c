#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "sys-crypto-md.h" /* USE_LIB_CRYPTO */

#include "base.h"
#include "plugin.h"
#include "http_auth.h"
#include "http_header.h"
#include "log.h"
#include "safe_memclear.h"
#include "splaytree.h"

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
    plugin_config conf;
} plugin_data;

typedef struct {
    const struct http_auth_require_t *require;
    time_t ctime;
    int dalgo;
    uint32_t dlen;
    uint32_t ulen;
    char *username;
    char *pwdigest;
} http_auth_cache_entry;

static http_auth_cache_entry *
http_auth_cache_entry_init (const struct http_auth_require_t * const require, const int dalgo, const char *username, const uint32_t ulen, const char *pw, const uint32_t pwlen)
{
    /*(similar to buffer_copy_string_len() for each element,
     * but allocate exact lengths in single chunk of memory
     * for cache to avoid wasting space and for memory locality)*/
    /* http_auth_require_t is stored instead of copying realm
     *(store pointer to http_auth_require_t, which is persistent
     * and will be different for each realm + permissions combo)*/
    http_auth_cache_entry * const ae =
      malloc(sizeof(http_auth_cache_entry) + ulen + pwlen);
    force_assert(ae);
    ae->require = require;
    ae->ctime = log_epoch_secs;
    ae->dalgo = dalgo;
    ae->ulen = ulen;
    ae->dlen = pwlen;
    ae->username = (char *)(ae + 1);
    ae->pwdigest = ae->username + ulen;
    memcpy(ae->username, username, ulen);
    memcpy(ae->pwdigest, pw, pwlen);
    return ae;
}

static void
http_auth_cache_entry_free (void *data)
{
    http_auth_cache_entry * const ae = data;
    safe_memclear(ae->pwdigest, ae->dlen);
    free(ae);
}

static void
http_auth_cache_free (http_auth_cache *ac)
{
    splay_tree *sptree = ac->sptree;
    while (sptree) {
        http_auth_cache_entry_free(sptree->data);
        sptree = splaytree_delete(sptree, sptree->key);
    }
    free(ac);
}

static http_auth_cache *
http_auth_cache_init (const array *opts)
{
    http_auth_cache *ac = malloc(sizeof(http_auth_cache));
    force_assert(ac);
    ac->sptree = NULL;
    ac->max_age = 600; /* 10 mins */
    for (uint32_t i = 0, used = opts->used; i < used; ++i) {
        data_string *ds = (data_string *)opts->data[i];
        if (buffer_is_equal_string(&ds->key, CONST_STR_LEN("max-age"))) {
            if (ds->type == TYPE_STRING)
                ac->max_age = (time_t)strtol(ds->value.ptr, NULL, 10);
            else if (ds->type == TYPE_INTEGER)
                ac->max_age = (time_t)((data_integer *)ds)->value;
        }
    }
    return ac;
}

static int
http_auth_cache_hash (const struct http_auth_require_t * const require, const char *username, const uint32_t ulen)
{
    uint32_t h = /*(hash pointer value, which includes realm and permissions)*/
      djbhash((char *)(intptr_t)require, sizeof(intptr_t), DJBHASH_INIT);
    h = djbhash(username, ulen, h);
    /* strip highest bit of hash value for splaytree (see splaytree_djbhash())*/
    return (int32_t)(h & ~(((uint32_t)1) << 31));
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
        *sptree = splaytree_insert(*sptree, ndx, data);
    else { /* collision; replace old entry */
        data_free_fn((*sptree)->data);
        (*sptree)->data = data;
    }
}

/* walk though cache, collect expired ids, and remove them in a second loop */
static void
mod_auth_tag_old_entries (splay_tree * const t, int * const keys, int * const ndx, const time_t max_age, const time_t cur_ts)
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
mod_auth_periodic_cleanup(splay_tree **sptree_ptr, const time_t max_age, const time_t cur_ts)
{
    splay_tree *sptree = *sptree_ptr;
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    do {
        if (!sptree) break;
        max_ndx = 0;
        mod_auth_tag_old_entries(sptree, keys, &max_ndx, max_age, cur_ts);
        for (i = 0; i < max_ndx; ++i) {
            int ndx = keys[i];
            sptree = splaytree_splay(sptree, ndx);
            if (sptree && sptree->key == ndx) {
                http_auth_cache_entry_free(sptree->data);
                sptree = splaytree_delete(sptree, ndx);
            }
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
    *sptree_ptr = sptree;
}

TRIGGER_FUNC(mod_auth_periodic)
{
    const plugin_data * const p = p_d;
    const time_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x7) return HANDLER_GO_ON; /*(continue once each 8 sec)*/
    UNUSED(srv);

    /* future: might construct array of (http_auth_cache *) at startup
     *         to avoid the need to search for them here */
    for (int i = 0, used = p->nconfig; i < used; ++i) {
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
	plugin_data *p = calloc(1, sizeof(*p));
	force_assert(p);

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

static data_auth *data_auth_init(void)
{
    static const struct data_methods fn = {
      NULL, /* copy must not be called on this data */
      data_auth_free,
      NULL, /* insert_dup must not be called on this data */
      NULL  /* print must not be called on this data */
    };
    data_auth * const dauth = calloc(1, sizeof(*dauth));
    force_assert(NULL != dauth);
    dauth->type       = TYPE_OTHER;
    dauth->fn         = &fn;

    dauth->require = http_auth_require_init();

    return dauth;
}

static int mod_auth_algorithm_parse(http_auth_info_t *ai, const char *s) {
    size_t len;
    if (NULL == s) {
        ai->dalgo = HTTP_AUTH_DIGEST_MD5;
        ai->dlen  = HTTP_AUTH_DIGEST_MD5_BINLEN;
        return 1;
    }

    len = strlen(s);
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
    for (char *s = algos->ptr, *p; s; s = p ? p+1 : NULL) {
        http_auth_info_t ai;
        int rc;
        p = strchr(s, '|');
        if (p) *p = '\0';
        rc = mod_auth_algorithm_parse(&ai, s);
        if (p) *p = '|';
        if (!rc) return 0;
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
                array_set_key_value(&require->user, str+5, len-5, CONST_STR_LEN(""));
                continue;
            }
            else if (0 == memcmp(str, CONST_STR_LEN("host"))) {
                /*("host=" is 5)*/
                array_set_key_value(&require->host, str+5, len-5, CONST_STR_LEN(""));
                log_error(errh, __FILE__, __LINE__,
                  "warning parsing auth.require 'require' field: "
                  "'host' not implemented; field value: %s", b->ptr);
                continue;
            }
            break; /* to error */
          case 5:
            if (0 == memcmp(str, CONST_STR_LEN("group"))) {
                /*("group=" is 6)*/
                array_set_key_value(&require->group, str+6, len-6, CONST_STR_LEN(""));
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

			if (buffer_string_is_empty(method)) {
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

			if (buffer_is_empty(realm)) {
				log_error(errh, __FILE__, __LINE__,
				  "the realm field is missing in: "
				  "auth.require = ( \"...\" => ( ..., \"realm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (buffer_string_is_empty(require)) {
				log_error(errh, __FILE__, __LINE__,
				  "the require field is missing or blank in: "
				  "auth.require = ( \"...\" => ( ..., \"require\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (buffer_string_is_empty(algos)) {
				algorithm |= HTTP_AUTH_DIGEST_MD5;
			} else if (!mod_auth_algorithms_parse(&algorithm, algos)) {
				log_error(errh, __FILE__, __LINE__,
				  "invalid algorithm in: "
				  "auth.require = ( \"...\" => ( ..., \"algorithm\" => \"...\" ) )");
				return HANDLER_ERROR;
			}

			if (require) { /*(always true at this point)*/
				data_auth * const dauth = data_auth_init();
				buffer_copy_buffer(&dauth->key, &da_file->key);
				dauth->require->scheme = auth_scheme;
				dauth->require->algorithm = algorithm;
				dauth->require->realm = realm;
				dauth->require->nonce_secret = nonce_secret; /*(NULL is ok)*/
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

static void mod_auth_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_auth_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
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
                if (!buffer_string_is_empty(cpv->v.b)) {
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
	plugin_data *p = p_d;
	data_auth *dauth;

	mod_auth_patch_config(r, p);

	if (p->conf.auth_require == NULL) return HANDLER_GO_ON;

	/* search auth directives for first prefix match against URL path */
	/* if we have a case-insensitive FS we have to lower-case the URI here too */
	dauth = (!r->conf.force_lowercase_filenames)
	   ? (data_auth *)array_match_key_prefix(p->conf.auth_require, &r->uri.path)
	   : (data_auth *)array_match_key_prefix_nc(p->conf.auth_require, &r->uri.path);
	if (NULL == dauth) return HANDLER_GO_ON;

	{
			const http_auth_scheme_t * const scheme = dauth->require->scheme;
			if (p->conf.auth_extern_authn) {
				const buffer *vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
				if (NULL != vb && http_auth_match_rules(dauth->require, vb->ptr, NULL, NULL)) {
					return HANDLER_GO_ON;
				}
			}
			return scheme->checkfn(r, scheme->p_d, dauth->require, p->conf.auth_backend);
	}
}


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
static handler_t mod_auth_send_400_bad_request(request_st * const r) {

	/* a field was missing or invalid */
	r->http_status = 400; /* Bad Request */
	r->handler_module = NULL;

	return HANDLER_FINISHED;
}

static handler_t mod_auth_send_401_unauthorized_basic(request_st * const r, const buffer * const realm) {
	r->http_status = 401;
	r->handler_module = NULL;

	buffer * const tb = r->tmp_buf;
	buffer_copy_string_len(tb, CONST_STR_LEN("Basic realm=\""));
	buffer_append_string_buffer(tb, realm);
	buffer_append_string_len(tb, CONST_STR_LEN("\", charset=\"UTF-8\""));

	http_header_response_set(r, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(tb));

	return HANDLER_FINISHED;
}

static handler_t mod_auth_check_basic(request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend) {
	const buffer *b = http_header_request_get(r, HTTP_HEADER_AUTHORIZATION, CONST_STR_LEN("Authorization"));
	buffer *username;
	char *pw;
	handler_t rc = HANDLER_UNSET;

	if (NULL == backend) {
		log_error(r->conf.errh, __FILE__, __LINE__, "auth.backend not configured for %s", r->uri.path.ptr);
		r->http_status = 500;
		r->handler_module = NULL;
		return HANDLER_FINISHED;
	}

	if (NULL == b) {
		return mod_auth_send_401_unauthorized_basic(r, require->realm);
	}

	if (!buffer_eq_icase_ssn(b->ptr, CONST_STR_LEN("Basic "))) {
		return mod_auth_send_401_unauthorized_basic(r, require->realm);
	}
      #ifdef __COVERITY__
	if (buffer_string_length(b) < sizeof("Basic ")-1) {
		return mod_auth_send_400_bad_request(r);
	}
      #endif

	username = buffer_init();

	/* coverity[overflow_sink : FALSE] */
	if (!buffer_append_base64_decode(username, b->ptr+sizeof("Basic ")-1, buffer_string_length(b)-(sizeof("Basic ")-1), BASE64_STANDARD)) {
		log_error(r->conf.errh, __FILE__, __LINE__, "decoding base64-string failed %s", b->ptr+sizeof("Basic ")-1);

		buffer_free(username);
		return mod_auth_send_400_bad_request(r);
	}

	/* r2 == user:password */
	if (NULL == (pw = strchr(username->ptr, ':'))) {
		log_error(r->conf.errh, __FILE__, __LINE__, "missing ':' in %s", username->ptr);

		buffer_free(username);
		return mod_auth_send_400_bad_request(r);
	}

	uint32_t pwlen = buffer_string_length(username);
	buffer_string_set_length(username, pw - username->ptr);
	pw++;
	pwlen -= (pw - username->ptr);

	plugin_data * const p = p_d;
	splay_tree ** sptree = p->conf.auth_cache
	  ? &p->conf.auth_cache->sptree
	  : NULL;
	http_auth_cache_entry *ae = NULL;
	int ndx = -1;
	if (sptree) {
		ndx = http_auth_cache_hash(require, CONST_BUF_LEN(username));
		ae = http_auth_cache_query(sptree, ndx);
		if (ae && ae->require == require
		    && buffer_is_equal_string(username, ae->username, ae->ulen))
			rc = http_auth_const_time_memeq_pad(ae->pwdigest, ae->dlen,
			                                    pw, pwlen)
			  ? HANDLER_GO_ON
			  : HANDLER_ERROR;
		else /*(not found or hash collision)*/
			ae = NULL;
	}

	if (NULL == ae) /* (HANDLER_UNSET == rc) */
		rc = backend->basic(r, backend->p_d, require, username, pw);

	switch (rc) {
	case HANDLER_GO_ON:
		http_auth_setenv(r, CONST_BUF_LEN(username), CONST_STR_LEN("Basic"));
		if (sptree && NULL == ae) { /*(cache (new) successful result)*/
			ae = http_auth_cache_entry_init(require, 0, CONST_BUF_LEN(username),
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
		  r->uri.path.ptr, username->ptr, r->con->dst_addr_buf->ptr);
		r->keep_alive = 0; /*(disable keep-alive if bad password)*/
		rc = HANDLER_UNSET;
		break;
	}

	buffer_free(username);
	return (HANDLER_UNSET != rc) ? rc : mod_auth_send_401_unauthorized_basic(r, require->realm);
}


#ifdef USE_LIB_CRYPTO

static void mod_auth_digest_mutate_sha256(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    SHA256_CTX ctx;
    char a1[HTTP_AUTH_DIGEST_SHA256_BINLEN*2+1];
    char a2[HTTP_AUTH_DIGEST_SHA256_BINLEN*2+1];

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        SHA256_Init(&ctx);
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
        SHA256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA256_Final(ai->digest, &ctx);
    }

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    /* calculate H(A2) */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char *)m, strlen(m));
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    SHA256_Update(&ctx, (unsigned char *)uri, strlen(uri));
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (qop && buffer_eq_icase_ss(qop, strlen(qop), CONST_STR_LEN("auth-int"))){
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *) [body checksum], ai->dlen*2);
    }
  #endif
    SHA256_Final(ai->digest, &ctx);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    SHA256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    SHA256_Update(&ctx, CONST_STR_LEN(":"));
    if (qop && *qop) {
        SHA256_Update(&ctx, (unsigned char *)nc, strlen(nc));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
        SHA256_Update(&ctx, (unsigned char *)qop, strlen(qop));
        SHA256_Update(&ctx, CONST_STR_LEN(":"));
    }
    SHA256_Update(&ctx, (unsigned char *)a2, sizeof(a2)-1);
    SHA256_Final(ai->digest, &ctx);
}

static void mod_auth_digest_nonce_sha256(buffer *b, time_t cur_ts, int rnd, const buffer *secret) {
    SHA256_CTX ctx;
    size_t len;
    unsigned char h[HTTP_AUTH_DIGEST_SHA256_BINLEN];
    char hh[HTTP_AUTH_DIGEST_SHA256_BINLEN*2+1];
    force_assert(sizeof(hh) >= LI_ITOSTRING_LENGTH);
    SHA256_Init(&ctx);
    len = li_itostrn(hh, sizeof(hh), cur_ts);
    SHA256_Update(&ctx, (unsigned char *)hh, len);
    len = li_itostrn(hh, sizeof(hh), rnd);
    SHA256_Update(&ctx, (unsigned char *)hh, len);
    if (secret) {
        len = buffer_string_length(secret);
        SHA256_Update(&ctx, (unsigned char *)secret->ptr, len);
    }
    SHA256_Final(h, &ctx);
    li_tohex(hh, sizeof(hh), (const char *)h, sizeof(h));
    buffer_append_string_len(b, hh, sizeof(hh)-1);
}

#ifdef USE_LIB_CRYPTO_SHA512_256

static void mod_auth_digest_mutate_sha512_256(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    SHA512_CTX ctx;
    char a1[HTTP_AUTH_DIGEST_SHA512_256_BINLEN*2+1];
    char a2[HTTP_AUTH_DIGEST_SHA512_256_BINLEN*2+1];

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        SHA512_256_Init(&ctx);
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
        SHA512_256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA512_256_Final(ai->digest, &ctx);
    }

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    /* calculate H(A2) */
    SHA512_256_Init(&ctx);
    SHA512_256_Update(&ctx, (unsigned char *)m, strlen(m));
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    SHA512_256_Update(&ctx, (unsigned char *)uri, strlen(uri));
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (qop && buffer_eq_icase_ss(qop, strlen(qop), CONST_STR_LEN("auth-int"))){
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)[body checksum], ai->dlen*2);
    }
  #endif
    SHA512_256_Final(ai->digest, &ctx);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    SHA512_256_Init(&ctx);
    SHA512_256_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    SHA512_256_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    if (qop && *qop) {
        SHA512_256_Update(&ctx, (unsigned char *)nc, strlen(nc));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
        SHA512_256_Update(&ctx, (unsigned char *)qop, strlen(qop));
        SHA512_256_Update(&ctx, CONST_STR_LEN(":"));
    }
    SHA512_256_Update(&ctx, (unsigned char *)a2, sizeof(a2)-1);
    SHA512_256_Final(ai->digest, &ctx);
}

static void mod_auth_digest_nonce_sha512_256(buffer *b, time_t cur_ts, int rnd, const buffer *secret) {
    SHA512_CTX ctx;
    size_t len;
    unsigned char h[HTTP_AUTH_DIGEST_SHA512_256_BINLEN];
    char hh[HTTP_AUTH_DIGEST_SHA512_256_BINLEN*2+1];
    force_assert(sizeof(hh) >= LI_ITOSTRING_LENGTH);
    SHA512_256_Init(&ctx);
    len = li_itostrn(hh, sizeof(hh), cur_ts);
    SHA512_256_Update(&ctx, (unsigned char *)hh, len);
    len = li_itostrn(hh, sizeof(hh), rnd);
    SHA512_256_Update(&ctx, (unsigned char *)hh, len);
    if (secret) {
        len = buffer_string_length(secret);
        SHA512_256_Update(&ctx, (unsigned char *)secret->ptr, len);
    }
    SHA512_256_Final(h, &ctx);
    li_tohex(hh, sizeof(hh), (const char *)h, sizeof(h));
    buffer_append_string_len(b, hh, sizeof(hh)-1);
}

#endif /* USE_LIB_CRYPTO_SHA512_256 */

#endif /* USE_LIB_CRYPTO */

static void mod_auth_digest_mutate_md5(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    li_MD5_CTX ctx;
    char a1[HTTP_AUTH_DIGEST_MD5_BINLEN*2+1];
    char a2[HTTP_AUTH_DIGEST_MD5_BINLEN*2+1];

    if (ai->dalgo & HTTP_AUTH_DIGEST_SESS) {
        li_MD5_Init(&ctx);
        /* http://www.rfc-editor.org/errata_search.php?rfc=2617
         * Errata ID: 1649 */
        li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);
        li_MD5_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        li_MD5_Final(ai->digest, &ctx);
    }

    li_tohex(a1, sizeof(a1), (const char *)ai->digest, ai->dlen);

    /* calculate H(A2) */
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, (unsigned char *)m, strlen(m));
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    li_MD5_Update(&ctx, (unsigned char *)uri, strlen(uri));
  #if 0
    /* qop=auth-int not supported, already checked in caller */
    if (qop && buffer_eq_icase_ss(qop, strlen(qop), CONST_STR_LEN("auth-int"))){
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *) [body checksum], ai->dlen*2);
    }
  #endif
    li_MD5_Final(ai->digest, &ctx);
    li_tohex(a2, sizeof(a2), (const char *)ai->digest, ai->dlen);

    /* calculate response */
    li_MD5_Init(&ctx);
    li_MD5_Update(&ctx, (unsigned char *)a1, sizeof(a1)-1);
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    li_MD5_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    if (qop && *qop) {
        li_MD5_Update(&ctx, (unsigned char *)nc, strlen(nc));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
        li_MD5_Update(&ctx, (unsigned char *)qop, strlen(qop));
        li_MD5_Update(&ctx, CONST_STR_LEN(":"));
    }
    li_MD5_Update(&ctx, (unsigned char *)a2, sizeof(a2)-1);
    li_MD5_Final(ai->digest, &ctx);
}

static void mod_auth_digest_nonce_md5(buffer *b, time_t cur_ts, int rnd, const buffer *secret) {
    li_MD5_CTX ctx;
    size_t len;
    unsigned char h[HTTP_AUTH_DIGEST_MD5_BINLEN];
    char hh[HTTP_AUTH_DIGEST_MD5_BINLEN*2+1];
    force_assert(sizeof(hh) >= LI_ITOSTRING_LENGTH);
    li_MD5_Init(&ctx);
    len = li_itostrn(hh, sizeof(hh), cur_ts);
    li_MD5_Update(&ctx, (unsigned char *)hh, len);
    len = li_itostrn(hh, sizeof(hh), rnd);
    li_MD5_Update(&ctx, (unsigned char *)hh, len);
    if (secret) {
        len = buffer_string_length(secret);
        li_MD5_Update(&ctx, (unsigned char *)secret->ptr, len);
    }
    li_MD5_Final(h, &ctx);
    li_tohex(hh, sizeof(hh), (const char *)h, sizeof(h));
    buffer_append_string_len(b, hh, sizeof(hh)-1);
}

static void mod_auth_digest_mutate(http_auth_info_t *ai, const char *m, const char *uri, const char *nonce, const char *cnonce, const char *nc, const char *qop) {
    if (ai->dalgo & HTTP_AUTH_DIGEST_MD5)
        mod_auth_digest_mutate_md5(ai, m, uri, nonce, cnonce, nc, qop);
  #ifdef USE_LIB_CRYPTO
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA256)
        mod_auth_digest_mutate_sha256(ai, m, uri, nonce, cnonce, nc, qop);
   #ifdef USE_LIB_CRYPTO_SHA512_256
    else if (ai->dalgo & HTTP_AUTH_DIGEST_SHA512_256)
        mod_auth_digest_mutate_sha512_256(ai, m, uri, nonce, cnonce, nc, qop);
   #endif
  #endif
}

static void mod_auth_append_nonce(buffer *b, time_t cur_ts, const struct http_auth_require_t *require, int dalgo, int *rndptr) {
    buffer_append_uint_hex(b, (uintmax_t)cur_ts);
    buffer_append_string_len(b, CONST_STR_LEN(":"));
    const buffer * const nonce_secret = require->nonce_secret;
    int rnd;
    if (NULL == nonce_secret)
        rnd = rndptr ? *rndptr : li_rand_pseudo();
    else { /*(do not directly expose random number generator single value)*/
        rndptr
          ? (void)(rnd = *rndptr)
          : li_rand_pseudo_bytes((unsigned char *)&rnd, sizeof(rnd));
        buffer_append_uint_hex(b, (uintmax_t)rnd);
        buffer_append_string_len(b, CONST_STR_LEN(":"));
    }
    switch (dalgo) {
     #ifdef USE_LIB_CRYPTO
      #ifdef USE_LIB_CRYPTO_SHA512_256
      case HTTP_AUTH_DIGEST_SHA512_256:
        mod_auth_digest_nonce_sha512_256(b, cur_ts, rnd, nonce_secret);
        break;
      #endif
      case HTTP_AUTH_DIGEST_SHA256:
        mod_auth_digest_nonce_sha256(b, cur_ts, rnd, nonce_secret);
        break;
     #endif
      /*case HTTP_AUTH_DIGEST_MD5:*/
      default:
        mod_auth_digest_nonce_md5(b, cur_ts, rnd, nonce_secret);
        break;
    }
}

static void mod_auth_digest_www_authenticate(buffer *b, time_t cur_ts, const struct http_auth_require_t *require, int nonce_stale) {
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
        if (i > 0) {
            buffer_append_string_len(b,CONST_STR_LEN("\r\nWWW-Authenticate: "));
        }
        buffer_append_string_len(b, CONST_STR_LEN("Digest realm=\""));
        buffer_append_string_buffer(b, require->realm);
        buffer_append_string_len(b, CONST_STR_LEN("\", charset=\"UTF-8\", algorithm="));
        buffer_append_string_len(b, algoname[i], algolen[i]);
        buffer_append_string_len(b, CONST_STR_LEN(", nonce=\""));
        mod_auth_append_nonce(b, cur_ts, require, algoid[i], NULL);
        buffer_append_string_len(b, CONST_STR_LEN("\", qop=\"auth\""));
        if (nonce_stale) {
            buffer_append_string_len(b, CONST_STR_LEN(", stale=true"));
        }
    }
}

static void mod_auth_digest_authentication_info(buffer *b, time_t cur_ts, const struct http_auth_require_t *require, int dalgo) {
    buffer_clear(b);
    buffer_append_string_len(b, CONST_STR_LEN("nextnonce=\""));
    mod_auth_append_nonce(b, cur_ts, require, dalgo, NULL);
    buffer_append_string_len(b, CONST_STR_LEN("\""));
}

typedef struct {
	const char *key;
	int key_len;
	char **ptr;
} digest_kv;

static handler_t mod_auth_send_401_unauthorized_digest(request_st *r, const struct http_auth_require_t *require, int nonce_stale);

static handler_t mod_auth_check_digest(request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend) {
	const buffer *vb = http_header_request_get(r, HTTP_HEADER_AUTHORIZATION, CONST_STR_LEN("Authorization"));

	char *username = NULL;
	char *realm = NULL;
	char *nonce = NULL;
	char *uri = NULL;
	char *algorithm = NULL;
	char *qop = NULL;
	char *cnonce = NULL;
	char *nc = NULL;
	char *respons = NULL;

	char *e, *c;
	int i;
	buffer *b;
	http_auth_info_t ai;
	unsigned char rdigest[HTTP_AUTH_DIGEST_SHA256_BINLEN];


	/* init pointers */
#define S(x) \
	x, sizeof(x)-1, NULL
	digest_kv dkv[10] = {
		{ S("username=") },
		{ S("realm=") },
		{ S("nonce=") },
		{ S("uri=") },
		{ S("algorithm=") },
		{ S("qop=") },
		{ S("cnonce=") },
		{ S("nc=") },
		{ S("response=") },

		{ NULL, 0, NULL }
	};
#undef S

	dkv[0].ptr = &username;
	dkv[1].ptr = &realm;
	dkv[2].ptr = &nonce;
	dkv[3].ptr = &uri;
	dkv[4].ptr = &algorithm;
	dkv[5].ptr = &qop;
	dkv[6].ptr = &cnonce;
	dkv[7].ptr = &nc;
	dkv[8].ptr = &respons;

	if (NULL == backend) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "auth.backend not configured for %s", r->uri.path.ptr);
		r->http_status = 500;
		r->handler_module = NULL;
		return HANDLER_FINISHED;
	}

	if (NULL == vb) {
		return mod_auth_send_401_unauthorized_digest(r, require, 0);
	}

	if (!buffer_eq_icase_ssn(vb->ptr, CONST_STR_LEN("Digest "))) {
		return mod_auth_send_401_unauthorized_digest(r, require, 0);
	} else {
		size_t n = buffer_string_length(vb);
	      #ifdef __COVERITY__
		if (n < sizeof("Digest ")-1) {
			return mod_auth_send_400_bad_request(r);
		}
	      #endif
		n -= (sizeof("Digest ")-1);
		b = buffer_init();
		buffer_copy_string_len(b,vb->ptr+sizeof("Digest ")-1,n);
	}

	/* parse credentials from client */
	for (c = b->ptr; *c; c++) {
		/* skip whitespaces */
		while (*c == ' ' || *c == '\t') c++;
		if (!*c) break;

		for (i = 0; dkv[i].key; i++) {
			if ((0 == strncmp(c, dkv[i].key, dkv[i].key_len))) {
				if ((c[dkv[i].key_len] == '"') &&
				    (NULL != (e = strchr(c + dkv[i].key_len + 1, '"')))) {
					/* value with "..." */
					*(dkv[i].ptr) = c + dkv[i].key_len + 1;
					c = e;

					*e = '\0';
				} else if (NULL != (e = strchr(c + dkv[i].key_len, ','))) {
					/* value without "...", terminated by ',' */
					*(dkv[i].ptr) = c + dkv[i].key_len;
					c = e;

					*e = '\0';
				} else {
					/* value without "...", terminated by EOL */
					*(dkv[i].ptr) = c + dkv[i].key_len;
					c += strlen(c) - 1;
				}
				break;
			}
		}
	}

	/* check if everything is transmitted */
	if (!username ||
	    !realm ||
	    !nonce ||
	    !uri ||
	    (qop && (!nc || !cnonce)) ||
	    !respons ) {
		/* missing field */

		log_error(r->conf.errh, __FILE__, __LINE__,
		  "digest: missing field");

		buffer_free(b);
		return mod_auth_send_400_bad_request(r);
	}

	ai.username = username;
	ai.ulen     = strlen(username);
	ai.realm    = realm;
	ai.rlen     = strlen(realm);

	if (!buffer_is_equal_string(require->realm, ai.realm, ai.rlen)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "digest: realm mismatch");
		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(r, require, 0);
	}

	if (!mod_auth_algorithm_parse(&ai, algorithm)
	    || !(require->algorithm & ai.dalgo & ~HTTP_AUTH_DIGEST_SESS)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "digest: (%s): invalid", algorithm);
		buffer_free(b);
		return mod_auth_send_400_bad_request(r);
	}

	/**
	 * protect the md5-sess against missing cnonce and nonce
	 */
	if ((ai.dalgo & HTTP_AUTH_DIGEST_SESS) && (!nonce || !cnonce)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "digest: (%s): missing field", algorithm);

		buffer_free(b);
		return mod_auth_send_400_bad_request(r);
	}

	{
		size_t resplen = strlen(respons);
		if (0 != http_auth_digest_hex2bin(respons, resplen,
						  rdigest, sizeof(rdigest))
		    || resplen != (ai.dlen << 1)) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "digest: (%s): invalid format", respons);
			buffer_free(b);
			return mod_auth_send_400_bad_request(r);
		}
	}

	if (qop && buffer_eq_icase_ss(qop, strlen(qop), CONST_STR_LEN("auth-int"))){
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "digest: qop=auth-int not supported");

		buffer_free(b);
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
	{
		const size_t ulen = strlen(uri);
		if (!buffer_is_equal_string(&r->target_orig, uri, ulen)) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "digest: auth failed: uri mismatch (%s != %s), IP: %s",
			  r->target_orig.ptr, uri, r->con->dst_addr_buf->ptr);
			buffer_free(b);
			return mod_auth_send_400_bad_request(r);
		}
	}

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
	 * then specify auth.require = ( ... => ( "secret" => "..." ) )
	 * When secret is specified, then instead of nanoseconds, the random
	 * data value (included for unique nonces) will be exposed in the nonce
	 * along with the timestamp, and the additional secret will be used to
	 * validate that the server generated the nonce using that secret. */
	int send_nextnonce;
	{
		time_t ts = 0;
		const unsigned char * const nonce_uns = (unsigned char *)nonce;
		for (i = 0; i < 8 && light_isxdigit(nonce_uns[i]); ++i) {
			ts = (ts << 4) + hex2int(nonce_uns[i]);
		}
		const time_t cur_ts = log_epoch_secs;
		if (nonce[i] != ':'
		    || ts > cur_ts || cur_ts - ts > 600) { /*(10 mins)*/
			/* nonce is stale; have client regenerate digest */
			buffer_free(b);
			return mod_auth_send_401_unauthorized_digest(r, require, ai.dalgo);
		}

		send_nextnonce = (cur_ts - ts > 540); /*(9 mins)*/

		if (require->nonce_secret) {
			unsigned int rnd = 0;
			for (int j = i+8; i < j && light_isxdigit(nonce_uns[i]); ++i) {
				rnd = (rnd << 4) + hex2int(nonce_uns[i]);
			}
			if (nonce[i] != ':') {
				/* nonce is invalid;
				 * expect extra field w/ require->nonce_secret */
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "digest: nonce invalid");
				buffer_free(b);
				return mod_auth_send_400_bad_request(r);
			}
			buffer * const tb = r->tmp_buf;
			buffer_clear(tb);
			mod_auth_append_nonce(tb, cur_ts, require, ai.dalgo, (int *)&rnd);
			if (!buffer_eq_slen(tb, nonce, strlen(nonce))) {
				/* nonce not generated using current require->nonce_secret */
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "digest: nonce mismatch");
				buffer_free(b);
				return mod_auth_send_401_unauthorized_digest(r, require, 0);
			}
		}
	}

	handler_t rc = HANDLER_UNSET;

	plugin_data * const p = p_d;
	splay_tree ** sptree = p->conf.auth_cache
	  ? &p->conf.auth_cache->sptree
	  : NULL;
	http_auth_cache_entry *ae = NULL;
	int ndx = -1;
	if (sptree) {
		ndx = http_auth_cache_hash(require, ai.username, ai.ulen);
		ae = http_auth_cache_query(sptree, ndx);
		if (ae && ae->require == require
		    && ae->dalgo == ai.dalgo
		    && ae->dlen == ai.dlen
		    && ae->ulen == ai.ulen
		    && 0 == memcmp(ae->username, ai.username, ai.ulen)) {
			rc = HANDLER_GO_ON;
			memcpy(ai.digest, ae->pwdigest, ai.dlen);
		}
		else /*(not found or hash collision)*/
			ae = NULL;
	}

	if (HANDLER_UNSET == rc)
		rc = backend->digest(r, backend->p_d, &ai);

	switch (rc) {
	case HANDLER_GO_ON:
		break;
	case HANDLER_WAIT_FOR_EVENT:
		buffer_free(b);
		return HANDLER_WAIT_FOR_EVENT;
	case HANDLER_FINISHED:
		buffer_free(b);
		return HANDLER_FINISHED;
	case HANDLER_ERROR:
	default:
		r->keep_alive = 0; /*(disable keep-alive if unknown user)*/
		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(r, require, 0);
	}

	if (sptree && NULL == ae) { /*(cache digest from backend)*/
		ae = http_auth_cache_entry_init(require, ai.dalgo, ai.username, ai.ulen,
		                                (char *)ai.digest, ai.dlen);
		http_auth_cache_insert(sptree, ndx, ae, http_auth_cache_entry_free);
	}

	const char *m = get_http_method_name(r->http_method);
	force_assert(m);

	mod_auth_digest_mutate(&ai,m,uri,nonce,cnonce,nc,qop);

	if (!http_auth_const_time_memeq(rdigest, ai.digest, ai.dlen)) {
		/* digest not ok */
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "digest: auth failed for %s: wrong password, IP: %s",
		  username, r->con->dst_addr_buf->ptr);
		r->keep_alive = 0; /*(disable keep-alive if bad password)*/

		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(r, require, 0);
	}

	/* value is our allow-rules */
	if (!http_auth_match_rules(require, username, NULL, NULL)) {
		buffer_free(b);
		return mod_auth_send_401_unauthorized_digest(r, require, 0);
	}

	if (send_nextnonce) {
			/*(send nextnonce when expiration is approaching)*/
			buffer * const tb = r->tmp_buf;
			const time_t cur_ts = log_epoch_secs;
			mod_auth_digest_authentication_info(tb, cur_ts, require, ai.dalgo);
			http_header_response_set(r, HTTP_HEADER_OTHER,
			                         CONST_STR_LEN("Authentication-Info"),
			                         CONST_BUF_LEN(tb));
	}

	http_auth_setenv(r, ai.username, ai.ulen, CONST_STR_LEN("Digest"));

	buffer_free(b);

	return HANDLER_GO_ON;
}

static handler_t mod_auth_send_401_unauthorized_digest(request_st * const r, const struct http_auth_require_t * const require, int nonce_stale) {
	buffer * const tb = r->tmp_buf;
	mod_auth_digest_www_authenticate(tb, log_epoch_secs, require, nonce_stale);
	http_header_response_set(r, HTTP_HEADER_OTHER, CONST_STR_LEN("WWW-Authenticate"), CONST_BUF_LEN(tb));

	r->http_status = 401;
	r->handler_module = NULL;
	return HANDLER_FINISHED;
}

static handler_t mod_auth_check_extern(request_st * const r, void *p_d, const struct http_auth_require_t * const require, const struct http_auth_backend_t * const backend) {
	/* require REMOTE_USER already set */
	const buffer *vb = http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
	UNUSED(p_d);
	UNUSED(backend);
	if (NULL != vb && http_auth_match_rules(require, vb->ptr, NULL, NULL)) {
		return HANDLER_GO_ON;
	} else {
		r->http_status = 401;
		r->handler_module = NULL;
		return HANDLER_FINISHED;
	}
}
