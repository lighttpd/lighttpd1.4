#include "first.h"

#include "sys-crypto-md.h"
#include "algo_hmac.h"
#include "base.h"
#include "base64.h"
#include "burl.h"
#include "log.h"
#include "buffer.h"
#include "chunk.h"
#include "ck.h"
#include "http_chunk.h"
#include "http_etag.h"
#include "http_header.h"
#include "rand.h"
#include "response.h"   /* http_response_send_1xx() */

#include "plugin.h"

#include "mod_magnet_cache.h"
#include "sock_addr.h"
#include "stat_cache.h"
#include "status_counter.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <lua.h>
#include <lauxlib.h>

#define LUA_RIDX_LIGHTTPD_REQUEST "lighty.request"

#define MAGNET_RESTART_REQUEST      99

/* plugin config for all request/connections */

static jmp_buf exceptionjmp;

typedef struct {
    script * const *url_raw;
    script * const *physical_path;
    script * const *response_start;
    int stage;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    script_cache cache;
} plugin_data;

INIT_FUNC(mod_magnet_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_magnet_free) {
    plugin_data * const p = p_d;
    script_cache_free_data(&p->cache);
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0: /* magnet.attract-raw-url-to */
              case 1: /* magnet.attract-physical-path-to */
              case 2: /* magnet.attract-response-start-to */
                free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static void mod_magnet_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    if (cpv->vtype != T_CONFIG_LOCAL)
        return;
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* magnet.attract-raw-url-to */
        pconf->url_raw = cpv->v.v;
        break;
      case 1: /* magnet.attract-physical-path-to */
        pconf->physical_path = cpv->v.v;
        break;
      case 2: /* magnet.attract-response-start-to */
        pconf->response_start = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_magnet_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_magnet_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_magnet_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_magnet_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_magnet_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("magnet.attract-raw-url-to"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("magnet.attract-physical-path-to"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("magnet.attract-response-start-to"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_magnet"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* magnet.attract-raw-url-to */
              case 1: /* magnet.attract-physical-path-to */
              case 2: /* magnet.attract-response-start-to */
                if (0 == cpv->v.a->used) {
                    cpv->v.v = NULL;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                else {
                    script ** const a =
                      malloc(sizeof(script *)*(cpv->v.a->used+1));
                    force_assert(a);
                    for (uint32_t j = 0; j < cpv->v.a->used; ++j) {
                        data_string *ds = (data_string *)cpv->v.a->data[j];
                        if (buffer_is_blank(&ds->value)) {
                            log_error(srv->errh, __FILE__, __LINE__,
                              "unexpected (blank) value for %s; "
                              "expected list of \"scriptpath\"", cpk[cpv->k_id].k);
                            free(a);
                            return HANDLER_ERROR;
                        }
                        a[j] = script_cache_get_script(&p->cache, &ds->value);
                    }
                    a[cpv->v.a->used] = NULL;
                    cpv->v.v = a;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
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
            mod_magnet_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
/* lua5.1 backward compat definition */
static void lua_pushglobaltable(lua_State *L) { /* (-0, +1, -) */
	lua_pushvalue(L, LUA_GLOBALSINDEX);
}
#endif

static void magnet_setfenv_mainfn(lua_State *L, int funcIndex) { /* (-1, 0, -) */
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 502
	/* set "_ENV" upvalue, which should be the first upvalue of a "main" lua
	 * function if it uses any global names
	 */

	const char* first_upvalue_name = lua_getupvalue(L, funcIndex, 1);
	if (NULL == first_upvalue_name) return; /* doesn't have any upvalues */
	lua_pop(L, 1); /* only need the name of the upvalue, not the value */

	if (0 != strcmp(first_upvalue_name, "_ENV")) return;

	if (NULL == lua_setupvalue(L, funcIndex, 1)) {
		/* pop value if lua_setupvalue didn't set the (not existing) upvalue */
		lua_pop(L, 1);
	}
#else
	lua_setfenv(L, funcIndex);
#endif
}

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
/* lua 5.1 deprecated luaL_getn() for lua_objlen() */
/* lua 5.2 renamed lua_objlen() to lua_rawlen() */
#define lua_rawlen lua_objlen
/* lua 5.2 deprecated luaL_register() for luaL_setfuncs()
 * (this define is valid only when 0 == nup) */
#define luaL_setfuncs(L, l, nup) luaL_register((L), NULL, (l))
#endif

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
/* lua 5.2 already supports __pairs */

/* See http://lua-users.org/wiki/GeneralizedPairsAndIpairs for implementation details.
 * Override the default pairs() function to allow us to use a __pairs metakey
 */
static int magnet_pairs(lua_State *L) {
	luaL_checkany(L, 1); /* "self" */

	if (luaL_getmetafield(L, 1, "__pairs")) {
		/* call __pairs(self) */
		lua_pushvalue(L, 1);
		lua_call(L, 1, 3);
	} else {
		/* call <original-pairs-method>(self) */
		lua_pushvalue(L, lua_upvalueindex(1));
		lua_pushvalue(L, 1);
		lua_call(L, 1, 3);
	}
	return 3;
}
#endif


/* XXX: mystery why dir walk (readdir) is not already part of lua io liolib.c */

#ifndef _D_EXACT_NAMLEN
#ifdef _DIRENT_HAVE_D_NAMLEN
#define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
#else
#define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))
#endif
#endif

static int magnet_readdir_iter(lua_State *L) {
    DIR ** const d = (DIR **)lua_touserdata(L, lua_upvalueindex(1));
    if (NULL == *d) return 0;

    /* readdir() and skip over "." and ".." */
    struct dirent *de;
    const char *n;
    do {
        de = readdir(*d);
    } while (de && (n = de->d_name)[0] == '.'
             && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')));

    if (de) {
        lua_pushlstring(L, de->d_name, _D_EXACT_NAMLEN(de));
        return 1;
    }
    else { /* EOF */
        closedir(*d);
        *d = NULL;
        return 0;
    }
}

static int magnet_readdir_gc(lua_State *L) {
    /*DIR ** const d = ((DIR **)luaL_checkudata(L, 1, "lighty.DIR"));*/
    DIR ** const d = lua_touserdata(L, 1);
    if (*d) closedir(*d);
    return 0;
}

static void magnet_readdir_metatable(lua_State * const L) {
    if (luaL_newmetatable(L, "lighty.DIR")) {                 /* (sp += 1) */
        lua_pushcclosure(L, magnet_readdir_gc, 0);            /* (sp += 1) */
        lua_setfield(L, -2, "__gc");                          /* (sp -= 1) */
        lua_pushboolean(L, 0);                                /* (sp += 1) */
        lua_setfield(L, -2, "__metatable"); /* protect metatable (sp -= 1) */
    }
}

static int magnet_readdir(lua_State *L) {
    const char * const s = luaL_checkstring(L, 1);
    DIR * const d = opendir(s);
    if (d) {
      #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 504
        DIR ** const dp = (DIR **)lua_newuserdata(L, sizeof(DIR *));
      #else
        DIR ** const dp = (DIR **)lua_newuserdatauv(L, sizeof(DIR *), 0);
      #endif
        *dp = d;
        magnet_readdir_metatable(L);
        lua_setmetatable(L, -2);
        lua_pushcclosure(L, magnet_readdir_iter, 1);
    }
    else
        lua_pushnil(L);
    return 1;
}


static int magnet_newindex_readonly(lua_State *L) {
    lua_pushliteral(L, "lua table is read-only");
    return lua_error(L);
}

static void magnet_push_buffer(lua_State *L, const buffer *b) {
    if (b && !buffer_is_unset(b))
        lua_pushlstring(L, BUF_PTR_LEN(b));
    else
        lua_pushnil(L);
}

#if 0
static int magnet_array_get_element(lua_State *L, const array *a) {
    /* __index: param 1 is the (empty) table the value was not found in */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    const data_string * const ds = (const data_string *)
      array_get_element_klen(a, k, klen);
    magnet_push_buffer(L, NULL != ds ? &ds->value : NULL);
    return 1;
}
#endif

/* Define a function that will iterate over an array* (in upval 1) using current position (upval 2) */
static int magnet_array_next(lua_State *L) {
	data_unset *du;
	data_string *ds;
	data_integer *di;

	size_t pos = lua_tointeger(L, lua_upvalueindex(1));
	array *a = lua_touserdata(L, lua_upvalueindex(2));

	lua_settop(L, 0);

	if (pos >= a->used) return 0;
	if (NULL != (du = a->data[pos])) {
		lua_pushlstring(L, BUF_PTR_LEN(&du->key));
		switch (du->type) {
			case TYPE_STRING:
				ds = (data_string *)du;
				magnet_push_buffer(L, &ds->value);
				break;
			case TYPE_INTEGER:
				di = (data_integer *)du;
				lua_pushinteger(L, di->value);
				break;
			default:
				lua_pushnil(L);
				break;
		}

		/* Update our positional upval to reflect our new current position */
		pos++;
		lua_pushinteger(L, pos);
		lua_replace(L, lua_upvalueindex(1));

		/* Returning 2 items on the stack (key, value) */
		return 2;
	}
	return 0;
}

/* Create the closure necessary to iterate over the array *a with the above function */
static int magnet_array_pairs(lua_State *L, array *a) {
	lua_pushinteger(L, 0); /* Push our current pos (the start) into upval 1 */
	lua_pushlightuserdata(L, a); /* Push our array *a into upval 2 */
	lua_pushcclosure(L, magnet_array_next, 2); /* Push our new closure with 2 upvals */
	return 1;
}

static request_st * magnet_get_request(lua_State *L) {
	lua_getfield(L, LUA_REGISTRYINDEX, LUA_RIDX_LIGHTTPD_REQUEST);
	request_st * const r = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return r;
}

typedef struct {
	const char *ptr;
	size_t len;
} const_buffer;

static const_buffer magnet_checkconstbuffer(lua_State *L, int idx) {
	const_buffer cb;
	if (!lua_isnil(L, idx))
		cb.ptr = luaL_checklstring(L, idx, &cb.len);
	else {
		cb.ptr = NULL;
		cb.len = 0;
	}
	return cb;
}

static const buffer* magnet_checkbuffer(lua_State *L, int idx, buffer *b) {
	const_buffer cb = magnet_checkconstbuffer(L, idx);
	/* assign result into (buffer *), and return (const buffer *)
	 * (note: caller must not free result) */
	*(const char **)&b->ptr = cb.ptr ? cb.ptr : "";
	b->used = cb.len+1;
	b->size = 0;
	return b;
}

static int magnet_print(lua_State *L) {
	const_buffer cb = magnet_checkconstbuffer(L, 1);
	request_st * const r = magnet_get_request(L);
	log_error(r->conf.errh, __FILE__, __LINE__, "(lua-print) %s", cb.ptr);
	return 0;
}


static int magnet_stat_field(lua_State *L) {
    if (lua_gettop(L) != 2)
        return 0; /*(should not happen; __index method in protected metatable)*/

    stat_cache_entry * const sce = *(stat_cache_entry **)lua_touserdata(L, -2);
    const_buffer k = magnet_checkconstbuffer(L, -1);
    switch (k.len ? k.ptr[0] : 0) {
      case 'c': { /* content-type */
        if (0 != strcmp(k.ptr, "content-type")) break;
        request_st * const r = magnet_get_request(L);
        const buffer *content_type = stat_cache_content_type_get(sce, r);
        if (content_type && !buffer_is_blank(content_type))
            lua_pushlstring(L, BUF_PTR_LEN(content_type));
        else
            lua_pushnil(L);
        return 1;
      }
      case 'e': { /* etag */
        if (0 != strcmp(k.ptr, "etag")) break;
        request_st * const r = magnet_get_request(L);
        const buffer *etag = stat_cache_etag_get(sce, r->conf.etag_flags);
        if (etag && !buffer_is_blank(etag))
            lua_pushlstring(L, BUF_PTR_LEN(etag));
        else
            lua_pushnil(L);
        return 1;
      }
      case 'i': /* is_* */
        if (k.len < 4) break;
        switch (k.ptr[3]) {
          case 'b': /* is_block */
            if (0 == strcmp(k.ptr, "is_block")) {
                lua_pushboolean(L, S_ISBLK(sce->st.st_mode));
                return 1;
            }
            break;
          case 'c': /* is_char */
            if (0 == strcmp(k.ptr, "is_char")) {
                lua_pushboolean(L, S_ISCHR(sce->st.st_mode));
                return 1;
            }
            break;
          case 'd': /* is_dir */
            if (0 == strcmp(k.ptr, "is_dir")) {
                lua_pushboolean(L, S_ISDIR(sce->st.st_mode));
                return 1;
            }
            break;
          case 'f': /* is_file is_fifo */
            if (0 == strcmp(k.ptr, "is_file")) {
                lua_pushboolean(L, S_ISREG(sce->st.st_mode));
                return 1;
            }
            if (0 == strcmp(k.ptr, "is_fifo")) {
                lua_pushboolean(L, S_ISFIFO(sce->st.st_mode));
                return 1;
            }
            break;
          case 'l': /* is_link */
            if (0 == strcmp(k.ptr, "is_link")) {
                lua_pushboolean(L, S_ISLNK(sce->st.st_mode));
                return 1;
            }
            break;
          case 's': /* is_socket */
            if (0 == strcmp(k.ptr, "is_socket")) {
                lua_pushboolean(L, S_ISSOCK(sce->st.st_mode));
                return 1;
            }
            break;
          default:
            break;
        }
        break;
      case 's': /* st_* */
        if (k.len < 4) break;
        switch (k.ptr[3]) {
          case 'a': /* st_atime */
            if (0 == strcmp(k.ptr, "st_atime")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_atime));
                return 1;
            }
            break;
          case 'c': /* st_ctime */
            if (0 == strcmp(k.ptr, "st_ctime")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_ctime));
                return 1;
            }
            break;
          case 'i': /* st_ino */
            if (0 == strcmp(k.ptr, "st_ino")) {
                lua_pushinteger(L, sce->st.st_ino);
                return 1;
            }
            break;
          case 'm': /* st_mtime st_mode */
            if (0 == strcmp(k.ptr, "st_mtime")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_mtime));
                return 1;
            }
            if (0 == strcmp(k.ptr, "st_mode")) {
                lua_pushinteger(L, sce->st.st_mode);
                return 1;
            }
            break;
          case 'g': /* st_gid */
            if (0 == strcmp(k.ptr, "st_gid")) {
                lua_pushinteger(L, sce->st.st_gid);
                return 1;
            }
            break;
          case 's': /* st_size */
            if (0 == strcmp(k.ptr, "st_size")) {
                lua_pushinteger(L, sce->st.st_size);
                return 1;
            }
            break;
          case 'u': /* st_uid */
            if (0 == strcmp(k.ptr, "st_uid")) {
                lua_pushinteger(L, sce->st.st_uid);
                return 1;
            }
            break;
          default:
            break;
        }
        break;
      default:
        break;
    }

    lua_pushliteral(L, "stat[\"field\"] invalid: ");
    lua_pushvalue(L, -2); /* field */
    lua_concat(L, 2);
    lua_error(L);
    return 0;
}


__attribute_cold__
static int magnet_stat_pairs_noimpl_iter(lua_State *L) {
    request_st * const r = magnet_get_request(L);
    log_error(r->conf.errh, __FILE__, __LINE__,
      "(lua) pairs() not implemented on lighty.stat object; "
      "returning empty iter");
    return 0;
}


__attribute_cold__
static int magnet_stat_pairs_noimpl(lua_State *L) {
    lua_pushcclosure(L, magnet_stat_pairs_noimpl_iter, 0);
    return 1;
}


static void magnet_stat_metatable(lua_State *L) {
    if (luaL_newmetatable(L, "lighty.stat")) {                  /* (sp += 1) */
        lua_pushcfunction(L, magnet_stat_field);                /* (sp += 1) */
        lua_setfield(L, -2, "__index");                         /* (sp -= 1) */
        lua_pushcfunction(L, magnet_newindex_readonly);         /* (sp += 1) */
        lua_setfield(L, -2, "__newindex");                      /* (sp -= 1) */
        lua_pushcfunction(L, magnet_stat_pairs_noimpl);         /* (sp += 1) */
        lua_setfield(L, -2, "__pairs");                         /* (sp -= 1) */
        lua_pushboolean(L, 0);                                  /* (sp += 1) */
        lua_setfield(L, -2, "__metatable"); /* protect metatable   (sp -= 1) */
    }
}


static int magnet_stat(lua_State *L) {
    buffer stor; /*(note: do not free magnet_checkbuffer() result)*/
    const buffer * const sb = magnet_checkbuffer(L, 1, &stor);
    stat_cache_entry * const sce = (!buffer_is_blank(sb))
      ? stat_cache_get_entry(sb)
      : NULL;
    if (NULL == sce) {
        lua_pushnil(L);
        return 1;
    }

    /* note: caching sce valid only for procedural script which does not yield;
     * (sce might not be valid if script yields and is later resumed)
     * (script must not cache sce in persistent global state for later use)
     * (If we did want sce to be persistent, then could increment sce refcnt,
     *  and set up __gc metatable method to decrement sce refcnt) */
    stat_cache_entry ** const udata =(struct stat_cache_entry**)/* (sp += 1) */
     #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 504
      lua_newuserdata(L, sizeof(stat_cache_entry *));
     #else
      lua_newuserdatauv(L, sizeof(stat_cache_entry *), 0);
     #endif
    *udata = sce;

    magnet_stat_metatable(L);                                   /* (sp += 1) */
    lua_setmetatable(L, -2);                                    /* (sp -= 1) */
    return 1;
}


static int magnet_time(lua_State *L) {
    lua_pushinteger(L, (lua_Integer)log_epoch_secs);
    return 1;
}


static int magnet_rand(lua_State *L) {
    lua_pushinteger(L, (lua_Integer)li_rand_pseudo());
    return 1;
}


static int magnet_md_once(lua_State *L) {
    if (lua_gettop(L) != 2) {
        lua_pushliteral(L,
          "lighty.c.md(algo, data): incorrect number of arguments");
        return lua_error(L);
    }
    const_buffer algo = magnet_checkconstbuffer(L, -2);
    const_buffer msg  = magnet_checkconstbuffer(L, -1);
    uint8_t digest[MD_DIGEST_LENGTH_MAX];
    uint32_t dlen = 0;
    switch (algo.len) {
     #ifdef USE_LIB_CRYPTO
      case 6:
       #ifdef USE_LIB_CRYPTO_SHA512
        if (0 == memcmp(algo.ptr, "sha512", 6)) {
            SHA512_once(digest, msg.ptr, msg.len);
            dlen = SHA512_DIGEST_LENGTH;
            break;
        }
       #endif
       #ifdef USE_LIB_CRYPTO_SHA256
        if (0 == memcmp(algo.ptr, "sha256", 6)) {
            SHA256_once(digest, msg.ptr, msg.len);
            dlen = SHA256_DIGEST_LENGTH;
            break;
        }
       #endif
        break;
      case 4:
       #ifdef USE_LIB_CRYPTO_SHA1
        if (0 == memcmp(algo.ptr, "sha1", 4)) {
            SHA1_once(digest, msg.ptr, msg.len);
            dlen = SHA1_DIGEST_LENGTH;
            break;
        }
       #endif
        break;
     #endif
      case 3:
        if (0 == memcmp(algo.ptr, "md5", 3)) {
            MD5_once(digest, msg.ptr, msg.len);
            dlen = MD5_DIGEST_LENGTH;
            break;
        }
        break;
      default:
        break;
    }

    if (dlen) {
        char dighex[MD_DIGEST_LENGTH_MAX*2+1];
        li_tohex_uc(dighex, sizeof(dighex), (char *)digest, dlen);
        lua_pushlstring(L, dighex, dlen*2);
    }
    else
        lua_pushnil(L);

    return 1;
}

static int magnet_hmac_once(lua_State *L) {
    if (lua_gettop(L) != 3) {
        lua_pushliteral(L,
          "lighty.c.hmac(algo, secret, data): incorrect number of arguments");
        return lua_error(L);
    }
    const_buffer algo   = magnet_checkconstbuffer(L, -3);
    const_buffer secret = magnet_checkconstbuffer(L, -2);
    const_buffer msg    = magnet_checkconstbuffer(L, -1);
    const uint8_t * const msgptr = (uint8_t *)msg.ptr;
    uint8_t digest[MD_DIGEST_LENGTH_MAX];
    uint32_t dlen = 0;
    int rc = 0;
    switch (algo.len) {
     #ifdef USE_LIB_CRYPTO
      case 6:
       #ifdef USE_LIB_CRYPTO_SHA512
        if (0 == memcmp(algo.ptr, "sha512", 6)) {
            rc = li_hmac_sha512(digest,secret.ptr,secret.len,msgptr,msg.len);
            dlen = SHA512_DIGEST_LENGTH;
            break;
        }
       #endif
       #ifdef USE_LIB_CRYPTO_SHA256
        if (0 == memcmp(algo.ptr, "sha256", 6)) {
            rc = li_hmac_sha256(digest,secret.ptr,secret.len,msgptr,msg.len);
            dlen = SHA256_DIGEST_LENGTH;
            break;
        }
       #endif
        break;
      case 4:
       #ifdef USE_LIB_CRYPTO_SHA1
        if (0 == memcmp(algo.ptr, "sha1", 4)) {
            rc = li_hmac_sha1(digest,secret.ptr,secret.len,msgptr,msg.len);
            dlen = SHA1_DIGEST_LENGTH;
            break;
        }
       #endif
        break;
     #endif
      case 3:
        if (0 == memcmp(algo.ptr, "md5", 3)) {
            rc = li_hmac_md5(digest,secret.ptr,secret.len,msgptr,msg.len);
            dlen = MD5_DIGEST_LENGTH;
            break;
        }
        break;
      default:
        break;
    }

    if (rc) {
        char dighex[MD_DIGEST_LENGTH_MAX*2+1];
        li_tohex_uc(dighex, sizeof(dighex), (char *)digest, dlen);
        lua_pushlstring(L, dighex, dlen*2);
    }
    else
        lua_pushnil(L);

    return 1;
}

static int magnet_digest_eq(lua_State *L) {
    if (lua_gettop(L) != 2) {
        lua_pushliteral(L,
          "lighty.c.digest_eq(d1, d2): incorrect number of arguments");
        return lua_error(L);
    }
    const_buffer d1 = magnet_checkconstbuffer(L, -2);
    const_buffer d2 = magnet_checkconstbuffer(L, -1);
    /* convert hex to binary: validate hex and eliminate hex case comparison */
    uint8_t b1[MD_DIGEST_LENGTH_MAX];
    uint8_t b2[MD_DIGEST_LENGTH_MAX];
    int rc = (d1.len == d2.len)
          && 0 == li_hex2bin(b1, sizeof(b1), d1.ptr, d1.len)
          && 0 == li_hex2bin(b2, sizeof(b2), d2.ptr, d2.len)
          && ck_memeq_const_time_fixed_len(b1, b2, d2.len >> 1);
    lua_pushboolean(L, rc);
    return 1;
}

static int magnet_secret_eq(lua_State *L) {
    if (lua_gettop(L) != 2) {
        lua_pushliteral(L,
          "lighty.c.secret_eq(d1, d2): incorrect number of arguments");
        return lua_error(L);
    }
    const_buffer d1 = magnet_checkconstbuffer(L, -2);
    const_buffer d2 = magnet_checkconstbuffer(L, -1);
    lua_pushboolean(L, ck_memeq_const_time(d1.ptr, d1.len, d2.ptr, d2.len));
    return 1;
}

static int magnet_b64dec(lua_State *L, base64_charset dict) {
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    if (buffer_append_base64_decode(b, s.ptr, s.len, dict))
        lua_pushlstring(L, BUF_PTR_LEN(b));
    else
        lua_pushnil(L);
    chunk_buffer_release(b);
    return 1;
}

static int magnet_b64enc(lua_State *L, base64_charset dict) {
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    buffer_append_base64_encode_no_padding(b, (uint8_t *)s.ptr, s.len, dict);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1;
}

static int magnet_b64urldec(lua_State *L) {
    return magnet_b64dec(L, BASE64_URL);
}

static int magnet_b64urlenc(lua_State *L) {
    return magnet_b64enc(L, BASE64_URL);
}

static int magnet_b64stddec(lua_State *L) {
    return magnet_b64dec(L, BASE64_STANDARD);
}

static int magnet_b64stdenc(lua_State *L) {
    return magnet_b64enc(L, BASE64_STANDARD);
}

static int magnet_hexdec(lua_State *L) {
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    uint8_t * const p = (uint8_t *)buffer_extend(b, s.len >> 1);
    int rc = li_hex2bin(p, s.len >> 1, s.ptr, s.len);
    if (0 == rc)
        lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return rc+1; /* 1 on success (pushed string); 0 on failure (no value) */
}

static int magnet_hexenc(lua_State *L) {
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    buffer_append_string_encoded_hex_uc(b, s.ptr, s.len);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1; /* uppercase hex string; use lua s = s:lower() to lowercase */
}

static int magnet_xmlenc(lua_State *L) {
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
  #if 1
    buffer_append_string_encoded(b, s.ptr, s.len, ENCODING_MINIMAL_XML);
  #else
    const char *e;
    size_t i, n, elen;
    for (i = 0, n = 0; i < s.len; ++i) {
        switch (s.ptr[i]) {
          default: continue;
          case '<':  e = "&lt;";   elen = sizeof("&lt;")-1;   break;
          case '>':  e = "&gt;";   elen = sizeof("&gt;")-1;   break;
          case '&':  e = "&amp;";  elen = sizeof("&amp;")-1;  break;
          case '\'': e = "&apos;"; elen = sizeof("&apos;")-1; break;
          case '"':  e = "&quot;"; elen = sizeof("&quot;")-1; break;
          /*(XXX: would be good idea to add CTRLs, DEL, '`' */
        }
        buffer_append_str2(b, s.ptr+n, i-n, e, elen);
        n = i+1;
    }
    if (i-n)
        buffer_append_string_len(b, s.ptr+n, i-n);
  #endif
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1;
}

static int magnet_urldec(lua_State *L) {
    /* url-decode and replace non-printable chars with '_'
     * This function should not be used on query-string unless it is used on
     * portions of query-string after splitting on '&', replacing '+' w/ ' ' */
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    buffer_copy_string_len(b, s.ptr, s.len);
    buffer_urldecode_path(b);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1;
}

static int magnet_urlenc(lua_State *L) {
    /* url-encode path
     * ('?' is encoded, if present)
     *  caller must split string if '?' is part of query-string)
     * ('/' is not encoded; caller must encode if not path separator) */
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    buffer_append_string_encoded(b, s.ptr, s.len, ENCODING_REL_URI);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1;
}

static void magnet_urldec_query_part(buffer * const b, const char *s, const size_t slen) {
    buffer_clear(b);
    char *p = buffer_extend(b, slen);
    for (size_t i = 0; i < slen; ++i)
        p[i] = (s[i] != '+') ? s[i] : ' ';
    buffer_urldecode_path(b);
}

static int magnet_urldec_query(lua_State *L) {
    /* split on '&' and '=', url-decode and replace non-printable chars w/ '_',
     * and store components in table
     * (string input should be query-string without leading '?')
     * (note: duplicated keys replace earlier values, but this interface returns
     *  an table useful for lookups, so this limitation is often acceptable) */
    lua_createtable(L, 0, 0);
    if (lua_isnil(L, -1)) {
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        return 1;
    }
    buffer * const k = chunk_buffer_acquire();
    buffer * const v = chunk_buffer_acquire();
    for (const char *qs = s.ptr, *eq, *amp; *qs; qs = amp+1) {
        for (amp = qs, eq = NULL; *amp && *amp != '&'; ++amp) {
            if (*amp == '=' && !eq) eq = amp;
        }
        if (amp != qs) {
            if (eq) {
                magnet_urldec_query_part(k, qs, (size_t)(eq - qs));
                magnet_urldec_query_part(v, eq+1, (size_t)(amp - (eq+1)));
            }
            else {
                magnet_urldec_query_part(k, qs, (size_t)(amp - qs));
                lua_pushnil(L);
            }
            lua_pushlstring(L, BUF_PTR_LEN(k));
            lua_pushlstring(L, BUF_PTR_LEN(v));
            lua_rawset(L, -3);
        }
        if (*amp == '\0') break;
    }
    chunk_buffer_release(k);
    chunk_buffer_release(v);
    return 1;
}

static void magnet_urlenc_query_part(buffer * const b, const char * const s, const size_t slen, const int iskey) {
    /* encode query part (each part is typically much smaller than chunk buffer)
     * all required chars plus '&' ';' '+' '\'' (and encode '=' if part of key)
     * (burl_append(b,str,len,BURL_ENCODE_ALL) works, but over-encodes) */
  #if 0
    /* alternative: (over-encodes some, but less than burl_append()) */
    UNUSED(iskey);
    buffer_append_string_encoded(b, s, slen, ENCODING_REL_URI);
  #else
    static const char hex_chars_uc[] = "0123456789ABCDEF";
    char * const p = buffer_string_prepare_append(b, slen*3);
    int j = 0;
    for (size_t i = 0; i < slen; ++i, ++j) {
        int c = s[i];
        if (!light_isalnum(c)) switch (c) {
          case ' ':
            c = '+';
            break;
          /*case '\'':*//*(ok in url query-part, but might be misused in HTML)*/
          case '!': case '$': case '(': case ')': case '*': case ',': case '-':
          case '.': case '/': case ':': case '?': case '@': case '_': case '~':
            break;
          case '=':
            if (!iskey) break;
            __attribute_fallthrough__
          default:
            p[j]   = '%';
            p[++j] = hex_chars_uc[(s[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[s[i] & 0xF];
            continue;
        }
        p[j] = c;
    }
    buffer_commit(b, j);
  #endif
}

static int magnet_urlenc_query(lua_State *L) {
    /* encode pairs in lua table into query string
     * (caller should add leading '?' or '&' when appending to full URL)
     * (caller should skip empty table if appending to existing query-string) */
    const int n = lua_istable(L, 1) ? (int)lua_rawlen(L, 1) : 0;
    if (n == 0) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    const_buffer s;
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
        if (lua_isstring(L, -2)) {
            if (!buffer_is_blank(b))
                buffer_append_string_len(b, CONST_STR_LEN("&"));
            s = magnet_checkconstbuffer(L, -2);
            magnet_urlenc_query_part(b, s.ptr, s.len, 1);
            if (!lua_isnil(L, -1)) {
                s = magnet_checkconstbuffer(L, -1);
                buffer_append_string_len(b, CONST_STR_LEN("="));
                magnet_urlenc_query_part(b, s.ptr, s.len, 0);
            }
        }
    }
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1;
}

static int magnet_urlenc_normalize(lua_State *L) {
    /* normalize url-encoding
     * url-encode (and url-decode safe chars) to normalize url-path
     * ('?' is treated as start of query-string and is not encoded;
     *  caller must encode '?' if intended to be part of url-path)
     * ('/' is not encoded; caller must encode if not path separator)
     * (burl_append() is not exposed here; caller might want to build
     *  url with lighty.c.urlenc() and lighty.c.urlenc_query(),
     *  then call lighty.c.urlenc_normalize()) */
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    buffer * const t = chunk_buffer_acquire();
  #if 0 /*(?maybe have different interface to use config policy?)*/
    request_st * const r = magnet_get_request(L);
    const int flags = r->conf.http_parseopts;
  #else
    const int flags = HTTP_PARSEOPT_URL_NORMALIZE
                    | HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED
                    | HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED
                    | HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE
                    | HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE
                    | HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS;
  #endif
    buffer_copy_string_len(b, s.ptr, s.len);
    burl_normalize(b, t, flags);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(t);
    chunk_buffer_release(b);
    return 1;
}

static int magnet_fspath_simplify(lua_State *L) {
    /* simplify filesystem path */
    if (lua_isnil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = chunk_buffer_acquire();
    buffer_copy_string_len(b, s.ptr, s.len);
    buffer_path_simplify(b);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    chunk_buffer_release(b);
    return 1;
}

static const char * magnet_cookie_param_push(lua_State *L, const char *s) {
    const char *b = s;
    while (    *s!=';' && *s!=' ' && *s!='\t' && *s!='\r' && *s!='\n' && *s)
        ++s;
    lua_pushlstring(L, b, (size_t)(s-b));
    return s;
}

static int magnet_cookie_tokens(lua_State *L) {
    lua_createtable(L, 0, 0);
    if (lua_isnil(L, -1))
        return 1;
    const char *s = luaL_checkstring(L, -1);
    do {
        while (*s==';' || *s==' ' || *s=='\t' || *s=='\r' || *s=='\n')
            ++s;
        if (*s == '\0') break;
        s = magnet_cookie_param_push(L, s);
        while (           *s==' ' || *s=='\t' || *s=='\r' || *s=='\n')
            ++s;
        if (*s == '=') {
            while (       *s==' ' || *s=='\t' || *s=='\r' || *s=='\n')
                ++s;
            if (*s==';' || *s=='\0')
                lua_pushnil(L);
            else
                s = magnet_cookie_param_push(L, s);
        }
        else {
            lua_pushnil(L);
        }
        lua_settable(L, -3);
        while (*s!=';' && *s!='\0') ++s; /* ignore/skip stray tokens */
    } while (*s++);
    return 1;
}

static int magnet_atpanic(lua_State *L) {
	request_st * const r = magnet_get_request(L);
	log_error(r->conf.errh, __FILE__, __LINE__, "(lua-atpanic) %s",
	          lua_isstring(L, 1) ? lua_tostring(L, 1) : "");
	longjmp(exceptionjmp, 1);
}

static int magnet_reqhdr_get(lua_State *L) {
    /* __index: param 1 is the (empty) table the value was not found in */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    request_st * const r = magnet_get_request(L);
    const int id = http_header_hkey_get(k, (uint32_t)klen);
    const buffer * const vb = http_header_request_get(r, id, k, klen);
    magnet_push_buffer(L, NULL != vb ? vb : NULL);
    return 1;
}

static int magnet_reqhdr_set(lua_State *L) {
    /* __newindex: param 1 is (empty) table in which value is to be set */
    const_buffer k = magnet_checkconstbuffer(L, 2);
    const_buffer v = magnet_checkconstbuffer(L, 3);

    request_st * const r = magnet_get_request(L);
    enum http_header_e id = http_header_hkey_get(k.ptr, (uint32_t)k.len);

    switch (id) {
      /*case HTTP_HEADER_OTHER:*/
      default:
        break;

      case HTTP_HEADER_HOST:
        /* do not allow Host to be unset, even if HTTP/1.0
         * (change Host to something else, if you must */
        if (0 == v.len) return 0;

        /*(must set r->http_host if r->http_host was not previously set)*/
        /* copied from request.c:http_request_header_set_Host() */
        r->http_host = http_header_request_set_ptr(r, HTTP_HEADER_HOST,
                                                   CONST_STR_LEN("Host"));
        buffer_copy_string_len_lc(r->http_host, v.ptr, v.len);
        return 0;

      case HTTP_HEADER_CONTENT_LENGTH:
        /* not attempting to handle Content-Length modification; may revisit */
        /* future: might permit setting to 0 to force discard of request body
         * but would have to check if request body present, and if
         * Content-Length was set, or if Transfer-Encoding: chunked,
         * and handle resetting internal chunked encoding state,
         * as well as making sure that this is handled properly for HTTP/2 */
        return 0; /* silently ignore; do not allow modification */

      /* do not permit modification of hop-by-hop (connection) headers */

      case HTTP_HEADER_CONNECTION:
        /* do not permit modification of Connection, incl add/remove tokens */
        /* future: might provide a different interface to set r->keep_alive = 0,
         *         and also handle in context if HTTP/2 */
      case HTTP_HEADER_TRANSFER_ENCODING:
      case HTTP_HEADER_SET_COOKIE:/*(response hdr;avoid accidental reflection)*/
        return 0; /* silently ignore; do not allow modification */
     #if 0 /*(eh, if script sets Upgrade, script probably intends this action)*/
      case HTTP_HEADER_UPGRADE:
        /* note: modifications here do not modify Connection header
         *       to add or remove "upgrade" token */
        /* future: might allow removal of existing tokens, but not addition */
        if (0 != v.len) return 0; /* do not allow Upgrade other than to unset */
        break;
     #endif
     #if 0 /*(eh, if script sets TE, script probably intends this action)*/
      case HTTP_HEADER_TE:
        if (0 != v.len) return 0; /* do not allow TE other than to unset */
        break;
     #endif
    }

    v.len
      ? http_header_request_set(r, id, k.ptr, k.len, v.ptr, v.len)
      : http_header_request_unset(r, id, k.ptr, k.len);
    return 0;
}

static int magnet_reqhdr_pairs(lua_State *L) {
	request_st * const r = magnet_get_request(L);
	return magnet_array_pairs(L, &r->rqst_headers);
}

static int magnet_resphdr_get(lua_State *L) {
    /* __index: param 1 is the (empty) table the value was not found in */
    /* Note: access to lighttpd r->resp_headers here is *independent* from
     * the (pending) changes in the (deprecated) lua lighty.headers[] table */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    request_st * const r = magnet_get_request(L);
    const int id = http_header_hkey_get(k, (uint32_t)klen);
    const buffer * const vb = http_header_response_get(r, id, k, klen);
    magnet_push_buffer(L, NULL != vb ? vb : NULL);
    return 1;
}

static int magnet_resphdr_set_kv(lua_State *L, request_st * const r) {
    const const_buffer k = magnet_checkconstbuffer(L, -2);
    const const_buffer v = magnet_checkconstbuffer(L, -1);
    const enum http_header_e id = http_header_hkey_get(k.ptr, (uint32_t)k.len);

    switch (id) {
      /*case HTTP_HEADER_OTHER:*/
      default:
        break;

      case HTTP_HEADER_CONTENT_LENGTH:
        /* lighttpd handles Content-Length or Transfer-Encoding for response */
        return 0; /* silently ignore; do not allow modification */

      /* do not permit modification of hop-by-hop (connection) headers */

      case HTTP_HEADER_CONNECTION:
        /* do not permit modification of Connection, incl add/remove tokens */
        /* future: might provide a different interface to set r->keep_alive = 0,
         *         and also handle in context if HTTP/2 */
      case HTTP_HEADER_TRANSFER_ENCODING:
        return 0; /* silently ignore; do not allow modification */
    }

    if (0 == v.len) {
        http_header_response_unset(r, id, k.ptr, k.len);
        return 0;
    }

    buffer * const vb = http_header_response_set_ptr(r, id, k.ptr, k.len);
    buffer_copy_string_len(vb, v.ptr, v.len);

    if (r->http_version >= HTTP_VERSION_2) {
        /* handle multi-line response headers with HTTP/2
         * (lowercase header name and mark r->resp_header_repeated)
         * (similar to http_header.c:http_header_response_insert_addtl()) */
        for (char *n = vb->ptr; (n = strchr(n, '\n')); ) {
            r->resp_header_repeated = 1;
            do {
                ++n;
                if (light_isupper(*n)) *n |= 0x20;
            } while (*n != ':' && *n != '\n' && *n != '\0');
        }
    }

    return 0;
}

static int magnet_resphdr_set(lua_State *L) {
    /* __newindex: param 1 is (empty) table in which value is to be set */
    /*const_buffer k = magnet_checkconstbuffer(L, 2);*/
    /*const_buffer v = magnet_checkconstbuffer(L, 3);*/
    request_st * const r = magnet_get_request(L);
    return magnet_resphdr_set_kv(L, r);
}

static int magnet_resphdr_pairs(lua_State *L) {
    request_st * const r = magnet_get_request(L);
    return magnet_array_pairs(L, &r->resp_headers);
}

static int magnet_status_get(lua_State *L) {
	/* __index: param 1 is the (empty) table the value was not found in */
	const_buffer key = magnet_checkconstbuffer(L, 2);
	int *i = status_counter_get_counter(key.ptr, key.len);
	lua_pushinteger(L, (lua_Integer)*i);

	return 1;
}

static int magnet_status_set(lua_State *L) {
	/* __newindex: param 1 is the (empty) table the value is supposed to be set in */
	const_buffer key = magnet_checkconstbuffer(L, 2);
	int counter = (int) luaL_checkinteger(L, 3);

	status_counter_set(key.ptr, key.len, counter);

	return 0;
}

static int magnet_status_pairs(lua_State *L) {
	return magnet_array_pairs(L, &plugin_stats);
}

typedef struct {
	const char *name;
	uint32_t nlen;
	enum {
		MAGNET_ENV_UNSET,

		MAGNET_ENV_PHYSICAL_PATH,
		MAGNET_ENV_PHYSICAL_REL_PATH,
		MAGNET_ENV_PHYSICAL_DOC_ROOT,
		MAGNET_ENV_PHYSICAL_BASEDIR,

		MAGNET_ENV_URI_PATH,
		MAGNET_ENV_URI_PATH_RAW,
		MAGNET_ENV_URI_SCHEME,
		MAGNET_ENV_URI_AUTHORITY,
		MAGNET_ENV_URI_QUERY,

		MAGNET_ENV_REQUEST_METHOD,
		MAGNET_ENV_REQUEST_URI,
		MAGNET_ENV_REQUEST_ORIG_URI,
		MAGNET_ENV_REQUEST_PATH_INFO,
		MAGNET_ENV_REQUEST_REMOTE_ADDR,
		MAGNET_ENV_REQUEST_REMOTE_PORT,
		MAGNET_ENV_REQUEST_SERVER_ADDR,
		MAGNET_ENV_REQUEST_SERVER_PORT,
		MAGNET_ENV_REQUEST_PROTOCOL,

		MAGNET_ENV_RESPONSE_HTTP_STATUS,
		MAGNET_ENV_RESPONSE_BODY_LENGTH,
		MAGNET_ENV_RESPONSE_BODY
	} type;
} magnet_env_t;

static const magnet_env_t magnet_env[] = {
    { CONST_STR_LEN("physical.path"),        MAGNET_ENV_PHYSICAL_PATH },
    { CONST_STR_LEN("physical.rel-path"),    MAGNET_ENV_PHYSICAL_REL_PATH },
    { CONST_STR_LEN("physical.doc-root"),    MAGNET_ENV_PHYSICAL_DOC_ROOT },
    { CONST_STR_LEN("physical.basedir"),     MAGNET_ENV_PHYSICAL_BASEDIR },

    { CONST_STR_LEN("uri.path"),             MAGNET_ENV_URI_PATH },
    { CONST_STR_LEN("uri.path-raw"),         MAGNET_ENV_URI_PATH_RAW },
    { CONST_STR_LEN("uri.scheme"),           MAGNET_ENV_URI_SCHEME },
    { CONST_STR_LEN("uri.authority"),        MAGNET_ENV_URI_AUTHORITY },
    { CONST_STR_LEN("uri.query"),            MAGNET_ENV_URI_QUERY },

    { CONST_STR_LEN("request.method"),       MAGNET_ENV_REQUEST_METHOD },
    { CONST_STR_LEN("request.uri"),          MAGNET_ENV_REQUEST_URI },
    { CONST_STR_LEN("request.orig-uri"),     MAGNET_ENV_REQUEST_ORIG_URI },
    { CONST_STR_LEN("request.path-info"),    MAGNET_ENV_REQUEST_PATH_INFO },
    { CONST_STR_LEN("request.remote-ip"),    MAGNET_ENV_REQUEST_REMOTE_ADDR },
    { CONST_STR_LEN("request.remote-addr"),  MAGNET_ENV_REQUEST_REMOTE_ADDR },
    { CONST_STR_LEN("request.remote-port"),  MAGNET_ENV_REQUEST_REMOTE_PORT },
    { CONST_STR_LEN("request.server-addr"),  MAGNET_ENV_REQUEST_SERVER_ADDR },
    { CONST_STR_LEN("request.server-port"),  MAGNET_ENV_REQUEST_SERVER_PORT },
    { CONST_STR_LEN("request.protocol"),     MAGNET_ENV_REQUEST_PROTOCOL },

    { CONST_STR_LEN("response.http-status"), MAGNET_ENV_RESPONSE_HTTP_STATUS },
    { CONST_STR_LEN("response.body-length"), MAGNET_ENV_RESPONSE_BODY_LENGTH },
    { CONST_STR_LEN("response.body"),        MAGNET_ENV_RESPONSE_BODY },

    { NULL, 0, MAGNET_ENV_UNSET }
};

static buffer *magnet_env_get_buffer_by_id(request_st * const r, int id) {
	buffer *dest = NULL;

	/**
	 * map all internal variables to lua
	 *
	 */

	switch (id) {
	case MAGNET_ENV_PHYSICAL_PATH: dest = &r->physical.path; break;
	case MAGNET_ENV_PHYSICAL_REL_PATH: dest = &r->physical.rel_path; break;
	case MAGNET_ENV_PHYSICAL_DOC_ROOT: dest = &r->physical.doc_root; break;
	case MAGNET_ENV_PHYSICAL_BASEDIR: dest = &r->physical.basedir; break;

	case MAGNET_ENV_URI_PATH: dest = &r->uri.path; break;
	case MAGNET_ENV_URI_PATH_RAW:
	    {
		dest = r->tmp_buf;
		buffer_clear(dest);
		uint32_t len = buffer_clen(&r->target);
		char *qmark = memchr(r->target.ptr, '?', len);
		buffer_copy_string_len(dest, r->target.ptr, qmark ? (uint32_t)(qmark - r->target.ptr) : len);
		break;
	    }
	case MAGNET_ENV_URI_SCHEME: dest = &r->uri.scheme; break;
	case MAGNET_ENV_URI_AUTHORITY: dest = &r->uri.authority; break;
	case MAGNET_ENV_URI_QUERY: dest = &r->uri.query; break;

	case MAGNET_ENV_REQUEST_METHOD:
		dest = r->tmp_buf;
		buffer_clear(dest);
		http_method_append(dest, r->http_method);
		break;
	case MAGNET_ENV_REQUEST_URI:      dest = &r->target; break;
	case MAGNET_ENV_REQUEST_ORIG_URI: dest = &r->target_orig; break;
	case MAGNET_ENV_REQUEST_PATH_INFO: dest = &r->pathinfo; break;
	case MAGNET_ENV_REQUEST_REMOTE_ADDR: dest = &r->con->dst_addr_buf; break;
	case MAGNET_ENV_REQUEST_REMOTE_PORT:
		dest = r->tmp_buf;
		buffer_clear(dest);
		buffer_append_int(dest, sock_addr_get_port(&r->con->dst_addr));
		break;
	case MAGNET_ENV_REQUEST_SERVER_ADDR: /* local IP without port */
	    {
		const server_socket * const srv_socket = r->con->srv_socket;
		dest = r->tmp_buf;
		buffer_clear(dest);
		switch (sock_addr_get_family(&srv_socket->addr)) {
		case AF_INET:
		case AF_INET6:
			if (sock_addr_is_addr_wildcard(&srv_socket->addr)) {
				sock_addr addrbuf;
				socklen_t addrlen = sizeof(addrbuf);
				const int fd = r->con->fd;
				if (0 == getsockname(fd,(struct sockaddr *)&addrbuf,&addrlen)) {
					char buf[INET6_ADDRSTRLEN + 1];
					const char *s = sock_addr_inet_ntop(&addrbuf, buf, sizeof(buf));
					if (NULL != s)
						buffer_copy_string_len(dest, s, strlen(s));
				}
			}
			else
				buffer_copy_string_len(dest, srv_socket->srv_token->ptr,
				                       srv_socket->srv_token_colon);
			break;
		default:
			break;
		}
		break;
	    }
	case MAGNET_ENV_REQUEST_SERVER_PORT:
	    {
		const server_socket * const srv_socket = r->con->srv_socket;
		const buffer * const srv_token = srv_socket->srv_token;
		const uint32_t portoffset = srv_socket->srv_token_colon+1;
		dest = r->tmp_buf;
		buffer_copy_string_len(dest, srv_token->ptr+portoffset,
		                       buffer_clen(srv_token)-portoffset);
		break;
	    }
	case MAGNET_ENV_REQUEST_PROTOCOL:
		dest = r->tmp_buf;
		buffer_clear(dest);
		http_version_append(dest, r->http_version);
		break;
	case MAGNET_ENV_RESPONSE_HTTP_STATUS:
		dest = r->tmp_buf;
		buffer_clear(dest);
		buffer_append_int(dest, r->http_status);
		break;
	case MAGNET_ENV_RESPONSE_BODY_LENGTH:
		dest = r->tmp_buf;
		buffer_clear(dest);
		if (!r->resp_body_finished)
			break;
		buffer_append_int(dest, chunkqueue_length(&r->write_queue));
		break;
	case MAGNET_ENV_RESPONSE_BODY:
		if (!r->resp_body_finished)
			break;
		else {
			chunkqueue * const cq = &r->write_queue;
			off_t len = chunkqueue_length(cq);
			if (0 == len) {
				dest = r->tmp_buf;
				buffer_copy_string_len(dest, CONST_STR_LEN(""));
				break;
			}
			dest = chunkqueue_read_squash(cq, r->conf.errh);
			if (NULL == dest) {
				dest = r->tmp_buf;
				buffer_clear(dest);
			}
		}
		break;

	case MAGNET_ENV_UNSET: break;
	}

	return dest;
}

static int magnet_env_get_id(const char * const key, const size_t klen) {
    for (int i = 0; magnet_env[i].name; ++i) {
        if (klen == magnet_env[i].nlen
            && 0 == memcmp(key, magnet_env[i].name, klen))
            return magnet_env[i].type;
    }
    return MAGNET_ENV_UNSET;
}

static buffer *magnet_env_get_buffer(request_st * const r, const char * const k, const size_t klen) {
    return magnet_env_get_buffer_by_id(r, magnet_env_get_id(k, klen));
}

static int magnet_env_get(lua_State *L) {
    /* __index: param 1 is the (empty) table the value was not found in */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    request_st * const r = magnet_get_request(L);
    magnet_push_buffer(L, magnet_env_get_buffer(r, k, klen));
    return 1;
}

static int magnet_env_set(lua_State *L) {
    /* __newindex: param 1 is the (empty) table the value is supposed to be set in */
    size_t klen;
    const char * const key = luaL_checklstring(L, 2, &klen);
    const_buffer val = magnet_checkconstbuffer(L, 3);

    request_st * const r = magnet_get_request(L);
    const int env_id = magnet_env_get_id(key, klen);

    switch (env_id) {
      default:
        break;
      case MAGNET_ENV_URI_PATH_RAW:
      {
        /* modify uri-path of r->target; preserve query-part, if present */
        /* XXX: should we require that resulting path begin with '/' or %2F ? */
        const uint32_t len = buffer_clen(&r->target);
        const char * const qmark = memchr(r->target.ptr, '?', len);
        if (NULL != qmark)
            buffer_copy_string_len(r->tmp_buf, qmark,
                                   len - (uint32_t)(qmark - r->target.ptr));
        buffer_copy_string_len(&r->target, val.ptr, val.len);
        if (NULL != qmark)
            buffer_append_string_buffer(&r->target, r->tmp_buf);
        return 0;
      }
      case MAGNET_ENV_REQUEST_REMOTE_ADDR:
       #ifdef HAVE_SYS_UN_H
        if (val.len && *val.ptr == '/'
            && 0 == sock_addr_assign(&r->con->dst_addr, AF_UNIX, 0, val.ptr)) {
        }
        else
       #endif
        {
            sock_addr saddr;
            saddr.plain.sa_family = AF_UNSPEC;
            if (1 == sock_addr_from_str_numeric(&saddr, val.ptr, r->conf.errh)
                && saddr.plain.sa_family != AF_UNSPEC) {
                sock_addr_set_port(&saddr, 0);
                memcpy(&r->con->dst_addr, &saddr, sizeof(sock_addr));
            }
            else {
                return luaL_error(L, "lighty.r.req_attr['%s'] invalid addr: %s",
                                  key, val.ptr);
            }
        }
        buffer_copy_string_len(&r->con->dst_addr_buf, val.ptr, val.len);
        config_cond_cache_reset_item(r, COMP_HTTP_REMOTE_IP);
        return 0;
      case MAGNET_ENV_REQUEST_REMOTE_PORT:
        sock_addr_set_port(&r->con->dst_addr, (unsigned short)atoi(val.ptr));
        return 0;
      case MAGNET_ENV_RESPONSE_HTTP_STATUS:
      case MAGNET_ENV_RESPONSE_BODY_LENGTH:
      case MAGNET_ENV_RESPONSE_BODY:
        return luaL_error(L, "lighty.r.req_attr['%s'] is read-only", key);
    }

    buffer * const dest = magnet_env_get_buffer_by_id(r, env_id);
    if (NULL == dest)
        return luaL_error(L, "couldn't store '%s' in lighty.r.req_attr[]", key);

    if (lua_isnil(L, 3)) {
        if (env_id==MAGNET_ENV_URI_QUERY || env_id==MAGNET_ENV_PHYSICAL_PATH)
            buffer_clear(dest);
        else
            buffer_blank(dest);
    }
    else {
        buffer_copy_string_len(dest, val.ptr, val.len);
        /* NB: setting r->uri.query does not modify query-part in r->target */
    }

    switch (env_id) {
      case MAGNET_ENV_URI_SCHEME:
        buffer_to_lower(dest);
        config_cond_cache_reset_item(r, COMP_HTTP_SCHEME);
        break;
      case MAGNET_ENV_URI_AUTHORITY:
        r->server_name = dest;
        buffer_to_lower(dest);
        config_cond_cache_reset_item(r, COMP_HTTP_HOST);
        break;
      case MAGNET_ENV_URI_PATH:
        config_cond_cache_reset_item(r, COMP_HTTP_URL);
        break;
      case MAGNET_ENV_URI_QUERY:
        config_cond_cache_reset_item(r, COMP_HTTP_QUERY_STRING);
        break;
      default:
        break;
    }

    return 0;
}

static int magnet_env_next(lua_State *L) {
	const int pos = lua_tointeger(L, lua_upvalueindex(1));

	/* ignore previous key: use upvalue for current pos */
	lua_settop(L, 0);

	if (NULL == magnet_env[pos].name) return 0; /* end of list */
	/* Update our positional upval to reflect our new current position */
	lua_pushinteger(L, pos + 1);
	lua_replace(L, lua_upvalueindex(1));

	/* key to return */
	lua_pushlstring(L, magnet_env[pos].name, magnet_env[pos].nlen);

	/* get value */
	request_st * const r = magnet_get_request(L);
	magnet_push_buffer(L, magnet_env_get_buffer_by_id(r, magnet_env[pos].type));

	/* return 2 items on the stack (key, value) */
	return 2;
}

static int magnet_env_pairs(lua_State *L) {
	lua_pushinteger(L, 0); /* Push our current pos (the start) into upval 1 */
	lua_pushcclosure(L, magnet_env_next, 1); /* Push our new closure with 1 upvals */
	return 1;
}

static int magnet_envvar_get(lua_State *L) {
    /* __index: param 1 is the (empty) table the value was not found in */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    request_st * const r = magnet_get_request(L);
    const buffer * const vb = http_header_env_get(r, k, klen);
    magnet_push_buffer(L, NULL != vb ? vb : NULL);
    return 1;
}

static int magnet_envvar_set(lua_State *L) {
    /* __newindex: param 1 is the (empty) table the value is supposed to be set in */
    const_buffer key = magnet_checkconstbuffer(L, 2);
    const_buffer val = magnet_checkconstbuffer(L, 3);
    request_st * const r = magnet_get_request(L);
    http_header_env_set(r, key.ptr, key.len, val.ptr, val.len);
    return 0;
}

static int magnet_envvar_pairs(lua_State *L) {
	request_st * const r = magnet_get_request(L);
	return magnet_array_pairs(L, &r->env);
}


static int magnet_respbody_add(lua_State *L) {
    request_st * const r = magnet_get_request(L);
    if (lua_isstring(L, -1)) {
        const_buffer data = magnet_checkconstbuffer(L, -1);
        http_chunk_append_mem(r, data.ptr, data.len);
        return 1; /* boolean true */
    }
    else if (!lua_istable(L, -1))
        return 0; /* boolean false */

    /* note: differs from magnet_attach_content();
     * magnet_attach_content() has misnamed 'length' param which
     * is treated as 0-offset pos one after end of range to send.
     * Here, 'length' means 'length', as one would expect */
    for (int i=1, end=0, n=(int)lua_rawlen(L,-1); !end && i <= n; ++i) {
        lua_rawgeti(L, -1, i);

        if (lua_isstring(L, -1)) {
            const_buffer data = magnet_checkconstbuffer(L, -1);
            http_chunk_append_mem(r, data.ptr, data.len);
        }
        else if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "filename");
            lua_getfield(L, -2, "length");
            lua_getfield(L, -3, "offset");

            if (lua_isstring(L, -3)) { /* filename has to be a string */
                off_t off = (off_t) luaL_optinteger(L, -1, 0);
                off_t len = (off_t) luaL_optinteger(L, -2, -1);
                /*(-1 len as flag to use file size minus offset (below))*/
                buffer stor; /*(note: do not free magnet_checkbuffer() result)*/
                const buffer * const fn = magnet_checkbuffer(L, -3, &stor);
                stat_cache_entry * const sce = (!buffer_is_blank(fn))
                  ? stat_cache_get_entry_open(fn, r->conf.follow_symlink)
                  : NULL;
                if (sce && (sce->fd >= 0 || sce->st.st_size == 0)) {
                    /* treat negative offset as bytes from end of file */
                    /* treat negative len as bytes from offset to end of file */
                    if (off > sce->st.st_size)
                        off = sce->st.st_size;
                    else if (off < 0) {
                        off = sce->st.st_size - off;
                        if (off < 0) off = 0;
                    }
                    if (len < 0 || sce->st.st_size - off < len)
                        len = sce->st.st_size - off;
                    if (len)
                        http_chunk_append_file_ref_range(r, sce, off, len);
                }
                else {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "error opening file '%s'", fn->ptr);
                    end = 1;
                }
            }
            else {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "body[%d] table field \"filename\" must be a string", i);
                end = 1;
            }

            lua_pop(L, 3);
        }
        else if (lua_isnil(L, -1)) { /* end of list */
            end = 1;
        }
        else {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "body[%d] is neither a string nor a table", i);
            end = 1;
        }

        lua_pop(L, 1); /* pop the content[...] entry value */
    }

    return 1; /* boolean true */
}


static int magnet_respbody(lua_State *L) {
    /* __index: param 1 is the (empty) table the value was not found in */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    switch (k[0]) {
      case 'a': /* add; lighty.r.resp_body.add */
        if (k[1] == 'd' && k[2] == 'd' && k[3] == '\0') {
            lua_pushcclosure(L, magnet_respbody_add, 0);
            return 1;
        }
        break;
     #if 0 /*(future: provide pairs() interface to iterate over chunkqueue)*/
           /*(might convert chunks into table of strings, {filename="..."})*/
           /*(what about c->offset into chunk?)*/
      case 'g': /* get; lighty.r.resp_body.get */
        if (k[1] == 'e' && k[2] == 't' && k[3] == '\0') {
            /* equivalent to lighty.r.attr["response.body"] */
            /* equivalent to lighty.env["response.body"] */
            if (r->resp_body_finished) {
                chunkqueue * const cq = &r->write_queue;
                chunkqueue_length(cq)
                  ? magnet_push_buffer(L,
                                       chunkqueue_read_squash(cq,r->conf.errh))
                  : lua_pushlstring(L, "", 0);
            }
            else
                lua_pushnil(L); /*(?maybe return -1 instead if len unknown?)*/
            return 1;
        }
        break;
     #endif
      case 'l': /* len; lighty.r.resp_body.len */
        if (k[1] == 'e' && k[2] == 'n' && k[3] == '\0') {
            /* equivalent to lighty.r.req_attr["response.body-length"] */
            /* equivalent to lighty.env["response.body-length"] */
            request_st * const r = magnet_get_request(L);
            if (r->resp_body_finished)
                lua_pushinteger(L, chunkqueue_length(&r->write_queue));
            else
                lua_pushnil(L); /*(?maybe return -1 instead if len unknown?)*/
            return 1;
        }
        break;
      case 's': /* set; lighty.r.resp_body.set */
        if (k[1] == 'e' && k[2] == 't' && k[3] == '\0') {
            request_st * const r = magnet_get_request(L);
            http_response_body_clear(r, 0); /* clear respbody, then add */
            lua_pushcclosure(L, magnet_respbody_add, 0);
            return 1;
        }
        break;
      default:
        break;
    }
    lua_pushliteral(L, "lighty.r.resp_body invalid method or param");
    lua_error(L);
    return 0;
}


static int magnet_lighty_result_get(lua_State *L) {
    /* __index: param 1 is the lighty table the value was not found in */
    lua_getfield(L, 1, "result"); /* lighty.result */
    lua_pushvalue(L, 2);
    lua_rawget(L, -2);
    if (lua_isnil(L, -1)) {
        const_buffer k = magnet_checkconstbuffer(L, 2);
        if (k.len == 7 && 0 == memcmp(k.ptr, "content", 7)) {
            lua_pop(L, 1); /* pop nil */
            lua_createtable(L, 0, 0); /* create "content" table on demand */
            lua_pushvalue(L, -1);
            lua_rawset(L, 3); /* set in "lighty.result" */
        }
    }
    lua_replace(L, 3);
    return 1;
}

static int magnet_lighty_result_set(lua_State *L) {
    /* __newindex: param 1 is lighty table the value is supposed to be set in */
    /* assign value to table, replacing existing value, if any
     * (expecting "content" here, but compatible with prior misuse potential)
     * (special-case "header" back into lighty.header) */
    const_buffer k = magnet_checkconstbuffer(L, 2);
    if (k.len != 6 || 0 != memcmp(k.ptr, "header", 6)) {
        lua_getfield(L, 1, "result"); /* lighty.result */
        lua_replace(L, 1); /* replace param 1, original target table */
    }
    lua_rawset(L, -3);
    return 0;
}


static void magnet_copy_response_header(lua_State * const L, request_st * const r) {
    lua_getfield(L, -1, "header"); /* lighty.header */
    if (lua_istable(L, -1)) {
        for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
            if (lua_isstring(L, -1) && lua_isstring(L, -2))
                magnet_resphdr_set_kv(L, r);
        }
    }
    lua_pop(L, 1); /* pop lighty.header */
}

/**
 * walk through the content array set by lua script, e.g.
 *   lighy.header["Content-Type"] = "text/html"
 *   lighty.content =
 *     { "<html><body><pre>", { file = "/content" } , "</pre></body></html>" }
 *   return 200
 */
static int magnet_attach_content(lua_State * const L, request_st * const r) {
	lua_getfield(L, -1, "result");  /* lighty.result */
	lua_getfield(L, -1, "content"); /* lighty.result.content */
	if (lua_istable(L, -1)) {
		/* content is found, and is a table */
		http_response_body_clear(r, 0);
		for (int i=1, end=0, n=(int)lua_rawlen(L,-1); !end && i <= n; ++i) {
			lua_rawgeti(L, -1, i);

			/* -1 is the value and should be the value ... aka a table */
			if (lua_isstring(L, -1)) {
				const_buffer data = magnet_checkconstbuffer(L, -1);
				http_chunk_append_mem(r, data.ptr, data.len);
			} else if (lua_istable(L, -1)) {
				lua_getfield(L, -1, "filename");
				lua_getfield(L, -2, "length"); /* (0-based) end of range (not actually "length") */
				lua_getfield(L, -3, "offset"); /* (0-based) start of range */

				if (lua_isstring(L, -3)) { /* filename has to be a string */
					off_t off = (off_t) luaL_optinteger(L, -1, 0);
					off_t len = (off_t) luaL_optinteger(L, -2, -1); /*(-1 as flag to use file size minus offset (below))*/
					if (off < 0) {
						log_error(r->conf.errh, __FILE__, __LINE__,
						  "offset for '%s' is negative", lua_tostring(L, -3));
						end = 1;
					} else if (len >= off) {
						len -= off;
					} else if (-1 != len) {
						log_error(r->conf.errh, __FILE__, __LINE__,
						  "offset > length for '%s'", lua_tostring(L, -3));
						end = 1;
					}

					if (!end && 0 != len) {
						buffer stor; /*(note: do not free magnet_checkbuffer() result)*/
						const buffer * const fn = magnet_checkbuffer(L, -3, &stor);
						stat_cache_entry * const sce = (!buffer_is_blank(fn))
						  ? stat_cache_get_entry_open(fn, r->conf.follow_symlink)
						  : NULL;
						if (sce && (sce->fd >= 0 || sce->st.st_size == 0)) {
							if (len == -1 || sce->st.st_size - off < len)
								len = sce->st.st_size - off;
							if (len > 0)
								http_chunk_append_file_ref_range(r, sce, off, len);
						} else {
							log_error(r->conf.errh, __FILE__, __LINE__,
							  "error opening file content '%s' at offset %lld",
							          lua_tostring(L, -3), (long long)off);
							end = 1;
						}
					}
				} else {
					log_error(r->conf.errh, __FILE__, __LINE__,
					  "content[%d] is a table and field \"filename\" must be a string", i);
					end = 1;
				}

				lua_pop(L, 3);
			} else if (lua_isnil(L, -1)) {
				/* end of list */
				end = 1;
			} else {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "content[%d] is neither a string nor a table", i);
				end = 1;
			}

			lua_pop(L, 1); /* pop the content[...] entry value */
		}
	} else if (!lua_isnil(L, -1)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "lighty.content has to be a table");
	}
	lua_pop(L, 2); /* pop lighty.result.content and lighty.result */

	return 0;
}

static void magnet_mainenv_metatable(lua_State * const L) {
    if (luaL_newmetatable(L, "lighty.mainenv")) {             /* (sp += 1) */
        lua_pushglobaltable(L);                               /* (sp += 1) */
        lua_setfield(L, -2, "__index"); /* { __index = _G }      (sp -= 1) */
        lua_pushboolean(L, 0);                                /* (sp += 1) */
        lua_setfield(L, -2, "__metatable"); /* protect metatable (sp -= 1) */
    }
}

__attribute_cold__
static void magnet_init_lighty_table(lua_State * const L) {
    /* init lighty table and other initial setup for global lua_State */

    lua_atpanic(L, magnet_atpanic);

    lua_pushglobaltable(L);                                   /* (sp += 1) */

    /* we have to overwrite the print function */
    lua_pushcfunction(L, magnet_print);                       /* (sp += 1) */
    lua_setfield(L, -2, "print"); /* -1 is the env we want to set(sp -= 1) */

  #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
    /* override the default pairs() function to our __pairs capable version;
     * not needed for lua 5.2+
     */
    lua_getglobal(L, "pairs"); /* push original pairs()          (sp += 1) */
    lua_pushcclosure(L, magnet_pairs, 1);
    lua_setfield(L, -2, "pairs");                             /* (sp -= 1) */
  #endif

    lua_pop(L, 1); /* pop global table */                     /* (sp -= 1) */

    magnet_mainenv_metatable(L); /* init table for mem locality  (sp += 1) */
    magnet_stat_metatable(L);    /* init table for mem locality  (sp += 1) */
    magnet_readdir_metatable(L); /* init table for mem locality  (sp += 1) */
    lua_pop(L, 3);               /* pop init'd metatables        (sp -= 3) */

    /* lighty table
     *
     * lighty.r.req_header[]     HTTP request headers
     * lighty.r.req_attr[]       HTTP request attributes / components
     * lighty.r.req_env[]        HTTP request environment variables
     * lighty.r.resp_header[]    HTTP response headers
     * lighty.r.resp_body.*      HTTP response body accessors
     * lighty.r.resp_body.len    HTTP response body length
     * lighty.r.resp_body.add()  HTTP response body add (string or table)
     * lighty.r.resp_body.set()  HTTP response body set (string or table)
     *
     * (older interface)
     *
     * lighty.request[]      HTTP request headers
     * lighty.req_env[]      environment variables
     * lighty.env[]          lighttpd request metadata,
     *                       various url components,
     *                       physical file paths;
     *                       might contain nil values
     *
     * lighty.header[]       (script) HTTP response headers
     * lighty.content[]      (script) HTTP response body (table of string/file)
     *
     * lighty.status[]       lighttpd status counters
     */

    /*(adjust the preallocation if more entries are added)*/
    lua_createtable(L, 0, 9); /* lighty.* (returned on stack)    (sp += 1) */

    lua_createtable(L, 0, 5); /* lighty.r                        (sp += 1) */

    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 4); /* metatable for req_header table  (sp += 1) */
    lua_pushcfunction(L, magnet_reqhdr_get);                  /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_reqhdr_set);                  /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_reqhdr_pairs);                /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to req_header  (sp -= 1) */
    lua_setfield(L, -2, "req_header"); /* req_header = {}        (sp -= 1) */

    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 4); /* metatable for req_attr table    (sp += 1) */
    lua_pushcfunction(L, magnet_env_get);                     /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_env_set);                     /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_env_pairs);                   /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to req_attr    (sp -= 1) */
    lua_setfield(L, -2, "req_attr"); /* req_attr = {}            (sp -= 1) */

    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 4); /* metatable for req_env table     (sp += 1) */
    lua_pushcfunction(L, magnet_envvar_get);                  /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_envvar_set);                  /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_envvar_pairs);                /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to req_env     (sp -= 1) */
    lua_setfield(L, -2, "req_env"); /* req_env = {}              (sp -= 1) */

    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 4); /* metatable for resp_header table (sp += 1) */
    lua_pushcfunction(L, magnet_resphdr_get);                 /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_resphdr_set);                 /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_resphdr_pairs);               /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to resp_header (sp -= 1) */
    lua_setfield(L, -2, "resp_header"); /* resp_header = {}      (sp -= 1) */

    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 3); /* metatable for resp_body table   (sp += 1) */
    lua_pushcfunction(L, magnet_respbody);                    /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to resp_body   (sp -= 1) */
    lua_setfield(L, -2, "resp_body"); /* resp_body = {}          (sp -= 1) */

    lua_createtable(L, 0, 2); /* metatable for r table           (sp += 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to r           (sp -= 1) */
    lua_setfield(L, -2, "r"); /* lighty.r = {}                   (sp -= 1) */

    /* compatibility with previous mod_magnet interfaces in top of lighty.* */
    lua_getfield(L, -1, "r");                                 /* (sp += 1) */
    /* alias lighty.request -> lighty.r.req_header */
    lua_getfield(L, -1, "req_header");                        /* (sp += 1) */
    lua_setfield(L, -3, "request"); /* request = {}              (sp -= 1) */
    /* alias lighty.env     -> lighty.r.req_attr */
    lua_getfield(L, -1, "req_attr");                          /* (sp += 1) */
    lua_setfield(L, -3, "env"); /* env = {}                      (sp -= 1) */
    /* alias lighty.req_env -> lighty.r.req_env */
    lua_getfield(L, -1, "req_env");                           /* (sp += 1) */
    lua_setfield(L, -3, "req_env"); /* req_env = {}              (sp -= 1) */
    lua_pop(L, 1);                                            /* (sp -= 1) */

    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 4); /* metatable for status table      (sp += 1) */
    lua_pushcfunction(L, magnet_status_get);                  /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_status_set);                  /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_status_pairs);                /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to status      (sp -= 1) */
    lua_setfield(L, -2, "status"); /* status = {}                (sp -= 1) */

    lua_pushinteger(L, MAGNET_RESTART_REQUEST);
    lua_setfield(L, -2, "RESTART_REQUEST");

    lua_pushcfunction(L, magnet_stat);                        /* (sp += 1) */
    lua_setfield(L, -2, "stat"); /* -1 is the env we want to set (sp -= 1) */

    /* add empty 'header' and 'result' tables; ('content' is under 'result') */
    /* (prefer newer lighty.r.resp_header(), lighty.r.resp_body() interfaces) */
    lua_createtable(L, 0, 8); /* {}                              (sp += 1) */
    lua_setfield(L, -2, "header"); /* header = {}                (sp -= 1) */

    lua_createtable(L, 0, 1); /* {}                              (sp += 1) */
    lua_setfield(L, -2, "result"); /* result = {}                (sp -= 1) */

    static const luaL_Reg cmethods[] = {
      { "stat",             magnet_stat }
     ,{ "time",             magnet_time }
     ,{ "rand",             magnet_rand }
     ,{ "md",               magnet_md_once   } /* message digest */
     ,{ "hmac",             magnet_hmac_once } /* HMAC */
     ,{ "digest_eq",        magnet_digest_eq } /* timing-safe eq fixed len */
     ,{ "secret_eq",        magnet_secret_eq } /* timing-safe eq variable len */
     ,{ "b64urldec",        magnet_b64urldec } /* validate and decode base64url */
     ,{ "b64urlenc",        magnet_b64urlenc } /* base64url encode, no padding */
     ,{ "b64dec",           magnet_b64stddec } /* validate and decode base64 */
     ,{ "b64enc",           magnet_b64stdenc } /* base64 encode, no padding */
     ,{ "hexdec",           magnet_hexdec } /* validate and decode hex str */
     ,{ "hexenc",           magnet_hexenc } /* uc; lc w/ lua s = s:lower() */
     ,{ "xmlenc",           magnet_xmlenc } /* xml-encode/html-encode: <>&'\" */
     ,{ "urldec",           magnet_urldec } /* url-decode (path) */
     ,{ "urlenc",           magnet_urlenc } /* url-encode (path) */
     ,{ "urldec_query",     magnet_urldec_query } /* url-decode query-string */
     ,{ "urlenc_query",     magnet_urlenc_query } /* url-encode query-string */
     ,{ "urlenc_normalize", magnet_urlenc_normalize }/* url-enc normalization */
     ,{ "fspath_simplify",  magnet_fspath_simplify } /* simplify fspath */
     ,{ "cookie_tokens",    magnet_cookie_tokens } /* parse cookie tokens */
     ,{ "readdir",          magnet_readdir } /* dir walk */
     ,{ NULL, NULL }
    };

    lua_createtable(L, 0, sizeof(cmethods)/sizeof(luaL_Reg)-1);/*(sp += 1) */
    luaL_setfuncs(L, cmethods, 0);
    lua_createtable(L, 0, 2); /* metatable for c table           (sp += 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to c           (sp -= 1) */
    lua_setfield(L, -2, "c"); /* c = {}                          (sp -= 1) */

    lua_createtable(L, 0, 3); /* metatable for lighty table      (sp += 1) */
    lua_pushcfunction(L, magnet_lighty_result_get);           /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_lighty_result_set);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to lighty      (sp -= 1) */

    /* lighty table (returned on stack) */
}

static void magnet_clear_table(lua_State * const L) {
    for (int n = (int)lua_rawlen(L, -1); n; --n) {
        lua_pushnil(L);
        lua_rawseti(L, -2, n);
    }
}

static void magnet_reset_lighty_table(lua_State * const L) {
    /* clear response tables (release mem if reusing lighty table) */
    lua_getfield(L, -1, "result"); /* lighty.result */
    if (lua_istable(L, -1))
        magnet_clear_table(L);
    else {
        lua_createtable(L, 0, 1);
        lua_setfield(L, -3, "result");
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, "header");  /* lighty.header */
    if (lua_istable(L, -1))
        magnet_clear_table(L);
    else {
        lua_createtable(L, 0, 0);
        lua_setfield(L, -3, "header");
    }
    lua_pop(L, 1);
}

static int traceback(lua_State *L) {
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */
	lua_getglobal(L, "debug");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	return 1;
}

/* push traceback function before calling lua_pcall after narg arguments
 * have been pushed (inserts it before the arguments). returns index for
 * traceback function ("msgh" in lua_pcall)
 */
static int push_traceback(lua_State *L, int narg) {
	int base = lua_gettop(L) - narg;  /* function index */
	lua_pushcfunction(L, traceback);
	lua_insert(L, base);
	return base;
}

static handler_t magnet_attract(request_st * const r, plugin_data * const p, script * const sc) {
	/*(always check at least mtime and size to trigger script reload)*/
	int etag_flags = r->conf.etag_flags | ETAG_USE_MTIME | ETAG_USE_SIZE;
	lua_State * const L = script_cache_check_script(sc, etag_flags);
	int lua_return_value;
	const int func_ndx = 1;
	const int lighty_table_ndx = 2;

	if (NULL == L) {
		log_perror(r->conf.errh, __FILE__, __LINE__,
		  "loading script %s failed", sc->name.ptr);

		if (p->conf.stage != -1) { /* skip for response-start */
			r->http_status = 500;
			r->handler_module = NULL;
		}

		return HANDLER_FINISHED;
	}

	if (lua_isstring(L, -1)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "loading script %s failed: %s", sc->name.ptr, lua_tostring(L, -1));
		lua_pop(L, 1);
		force_assert(lua_gettop(L) == 0); /* only the error should have been on the stack */

		if (p->conf.stage != -1) { /* skip for response-start */
			r->http_status = 500;
			r->handler_module = NULL;
		}

		return HANDLER_FINISHED;
	}

	lua_pushlightuserdata(L, r);
	lua_setfield(L, LUA_REGISTRYINDEX, LUA_RIDX_LIGHTTPD_REQUEST);

	if (lua_gettop(L) == 2) {
		/*force_assert(lua_istable(L, -1));*//* lighty.* table */
	}
	else {
	        /*force_assert(lua_gettop(L) == 1);*/
		/* insert lighty table at index 2 (lighty_table_ndx = 2) */
		magnet_init_lighty_table(L); /* lighty.*             (sp += 1) */
	}

	/**
	 * we want to create empty environment for our script
	 *
	 * setmetatable({}, {__index = _G})
	 *
	 * if a function symbol is not defined in our env, __index will lookup
	 * in the global env.
	 *
	 * all variables created in the script-env will be thrown
	 * away at the end of the script run.
	 */
	lua_createtable(L, 0, 1); /* my empty environment aka {}     (sp += 1) */

	lua_pushvalue(L, lighty_table_ndx);                       /* (sp += 1) */
	lua_setfield(L, -2, "lighty"); /* lighty.*                   (sp -= 1) */

	magnet_mainenv_metatable(L);                              /* (sp += 1) */
	lua_setmetatable(L, -2); /* setmetatable({}, {__index = _G}) (sp -= 1) */

	magnet_setfenv_mainfn(L, 1);                              /* (sp -= 1) */

	/* pcall will destroy the func value, duplicate it */     /* (sp += 1) */
	lua_pushvalue(L, func_ndx);
	{
		int errfunc = push_traceback(L, 0);
		int ret = lua_pcall(L, 0, 1, errfunc);
		lua_remove(L, errfunc);

		/* reset environment */
		lua_pushglobaltable(L);                               /* (sp += 1) */
		magnet_setfenv_mainfn(L, 1);                          /* (sp -= 1) */

		if (0 != ret) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "lua_pcall(): %s", lua_tostring(L, -1));
			lua_pop(L, 1); /* pop error msg */
			/* only the function and lighty table should remain on the stack */
			force_assert(lua_gettop(L) == 2);
			magnet_reset_lighty_table(L);

			if (p->conf.stage != -1) { /* skip for response-start */
				r->http_status = 500;
				r->handler_module = NULL;
			}

			return HANDLER_FINISHED;
		}
	}

	/* we should have the function, the lighty table and the return value on the stack */
	/*force_assert(lua_gettop(L) == 3);*/

	switch (lua_type(L, -1)) {
	case LUA_TNUMBER:
	case LUA_TNIL:
		lua_return_value = (int) luaL_optinteger(L, -1, -1);
		break;
	default:
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "lua_pcall(): unexpected return type: %s", luaL_typename(L, -1));
		lua_return_value = -1;
		break;
	}

	lua_pop(L, 1); /* pop return value */
	/*force_assert(lua_istable(sc->L, -1));*/

	magnet_copy_response_header(L, r);

	{
		handler_t result = HANDLER_GO_ON;

		if (lua_return_value >= 200) {
			r->http_status = lua_return_value;
			r->resp_body_finished = 1;

			if (0 == setjmp(exceptionjmp)) {
				magnet_attach_content(L, r);
				if (!chunkqueue_is_empty(&r->write_queue)) {
					r->handler_module = p->self;
				}
			} else {
				lua_settop(L, 2); /* remove all but function and lighty table */
				r->http_status = 500;
				r->handler_module = NULL;
				http_response_body_clear(r, 0);
			}

			result = HANDLER_FINISHED;
		} else if (lua_return_value >= 100 && p->conf.stage != -1) {
			/*(skip for response-start; send response as-is w/ added headers)*/
			/*(custom lua code should not return 101 Switching Protocols)*/
			r->http_status = lua_return_value;
			result = http_response_send_1xx(r)
			  ? HANDLER_GO_ON
			  : HANDLER_ERROR;
		} else if (MAGNET_RESTART_REQUEST == lua_return_value) {
			/*(could detect restart loops in same way as is done in mod_rewrite,
			 * but using r->env means that we do not need to reset plugin state
			 * at end of every request, as is done in mod_rewrite.  mod_rewrite
			 * always restarts the request processing (if request is rewritten),
			 * whereas mod_magnet can be used in many other ways)*/
			buffer *vb =
			  http_header_env_get(r, CONST_STR_LEN("_L_MAGNET_RESTART"));
			if (NULL == vb) {
				vb =
				  http_header_env_set_ptr(r,CONST_STR_LEN("_L_MAGNET_RESTART"));
				buffer_append_string_len(vb, "0", 1);
			}
			result = HANDLER_COMEBACK;
			if (++*vb->ptr-'0' >= 10) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "too many request restarts (infinite loop?) for %s",
				  sc->name.ptr);
				result = HANDLER_ERROR;
			}
		}

		magnet_reset_lighty_table(L);
		return result;
	}
}

static handler_t magnet_attract_array(request_st * const r, plugin_data * const p, int stage) {
	mod_magnet_patch_config(r, p);
	p->conf.stage = stage;

	script * const *scripts;
	switch (stage) {
	  case  1: scripts = p->conf.url_raw; break;
	  case  0: scripts = p->conf.physical_path; break;
	  case -1: scripts = p->conf.response_start; break;
	  default: scripts = NULL; break;
	}
	if (NULL == scripts) return HANDLER_GO_ON; /* no scripts set */

	r->con->srv->request_env(r);

	/* execute scripts sequentially while HANDLER_GO_ON */
	handler_t rc = HANDLER_GO_ON;
	do {
		rc = magnet_attract(r, p, *scripts);
	} while (rc == HANDLER_GO_ON && *++scripts);

	if (r->error_handler_saved_status) {
		/* retrieve (possibly modified) REDIRECT_STATUS and store as number */
		int x;
		const buffer * const vb = http_header_env_get(r, CONST_STR_LEN("REDIRECT_STATUS"));
		if (vb && (x = http_header_str_to_code(vb->ptr)) != -1)
			r->error_handler_saved_status =
			  r->error_handler_saved_status > 0 ? (int)x : -(int)x;
	}

	return rc;
}

URIHANDLER_FUNC(mod_magnet_uri_handler) {
	return magnet_attract_array(r, p_d, 1);
}

URIHANDLER_FUNC(mod_magnet_physical) {
	return magnet_attract_array(r, p_d, 0);
}

URIHANDLER_FUNC(mod_magnet_response_start) {
	return magnet_attract_array(r, p_d, -1);
}


int mod_magnet_plugin_init(plugin *p);
int mod_magnet_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "magnet";

	p->init        = mod_magnet_init;
	p->handle_uri_clean  = mod_magnet_uri_handler;
	p->handle_physical   = mod_magnet_physical;
	p->handle_response_start = mod_magnet_response_start;
	p->set_defaults  = mod_magnet_set_defaults;
	p->cleanup     = mod_magnet_free;

	return 0;
}
