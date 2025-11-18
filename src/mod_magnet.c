/*
 * mod_magnet - Lua support for lighttpd
 *
 * Largely rewritten from original
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "sys-crypto-md.h"
#include "sys-dirent.h"
#include "algo_hmac.h"
#include "base.h"
#include "base64.h"
#include "burl.h"
#include "log.h"
#include "buffer.h"
#include "chunk.h"
#include "ck.h"
#include "fdevent.h"
#include "http_chunk.h"
#include "http_etag.h"
#include "http_header.h"
#include "http_status.h"
#include "rand.h"
#include "response.h"   /* http_response_send_1xx() */

#include "plugin.h"

#include "mod_magnet_cache.h"
#include "sock_addr.h"
#include "stat_cache.h"

#ifdef _WIN32
#include "fs_win32.h"   /* readlink() */
#else
#include "sys-unistd.h" /* readlink() */
#endif

#include <stdlib.h>
#include <string.h>
/*#include <setjmp.h>*//*(not currently used)*/

#include <lua.h>
#include <lauxlib.h>

#define MAGNET_RESTART_REQUEST      99

/* plugin config for all request/connections */

/*static jmp_buf exceptionjmp;*//*(not currently used)*/

typedef struct {
    script * const *url_raw;
    script * const *physical_path;
    script * const *response_start;
    int stage;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;

    script_cache cache; /* thread-safety todo: refcnt and lock around modify */
} plugin_data;

static plugin_data *mod_magnet_plugin_data;

INIT_FUNC(mod_magnet_init) {
    return (mod_magnet_plugin_data = ck_calloc(1, sizeof(plugin_data)));
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

static void mod_magnet_patch_config(request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_magnet_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
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
                      ck_malloc((cpv->v.a->used+1)*sizeof(script *));
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

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 504
#define lua_newuserdata0(L, sz) lua_newuserdata((L),(sz))
#else
#define lua_newuserdata0(L, sz) lua_newuserdatauv((L),(sz),0)
#endif

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
#define lua_getfield_and_type(L,idx,k) \
       (lua_getfield((L),(idx),(k)), lua_type((L),-1))
#define lua_getglobal_and_type(L,name) \
       (lua_getglobal((L),(name)), lua_type((L),-1))
#else
#define lua_getfield_and_type(L,idx,k) \
        lua_getfield((L),(idx),(k))
#define lua_getglobal_and_type(L,name) \
        lua_getglobal((L),(name))
#endif

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
#ifdef __has_include
#if __has_include(<luajit.h>)
#include <luajit.h>
#endif
#endif
#if !defined(LUAJIT_VERSION_NUM) || LUAJIT_VERSION_NUM < 20005
static lua_Integer
lua_tointegerx (lua_State * const L, int idx, int *isnum)
{
    /*(caller should check for LUA_TNIL if using a default value is desired)*/
    /*(note: return 0 for floating point not convertible to integer)*/
    *isnum = lua_isnumber(L, idx);
    return *isnum ? lua_tointeger(L, idx) : 0;
}
#endif
#endif

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
    /*DIR ** const d = ((DIR **)luaL_checkudata(L, 1, "li.DIR"));*/
    DIR ** const d = lua_touserdata(L, 1);
    if (*d) closedir(*d);
    return 0;
}

static void magnet_readdir_metatable(lua_State * const L) {
    if (luaL_newmetatable(L, "li.DIR")) {                     /* (sp += 1) */
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
        *(DIR **)lua_newuserdata0(L, sizeof(DIR *)) = d;
        magnet_readdir_metatable(L);
        lua_setmetatable(L, -2);
        lua_pushcclosure(L, magnet_readdir_iter, 1);
    }
    else
        lua_pushnil(L);
    return 1;
}


__attribute_cold__
static int magnet_newindex_readonly(lua_State *L) {
    lua_pushliteral(L, "lua table is read-only");
    return lua_error(L);
}

static void magnet_push_cq(lua_State *L, chunkqueue * const cq, log_error_st * const errh) {
    const off_t cqlen = chunkqueue_length(cq);
    if (cqlen) {
        const chunk * const c = chunkqueue_read_squash(cq, errh);
        if (c)
            lua_pushlstring(L, c->mem->ptr+c->offset, cqlen);
        else
            lua_pushnil(L);
    }
    else
        lua_pushlstring(L, "", 0);
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

/* Define a function that will iterate over an array* (in upval 2) using current position (upval 1) */
static int magnet_array_next(lua_State *L) {
	lua_settop(L, 0);
	const uint32_t pos = lua_tointeger(L, lua_upvalueindex(1));
	const array * const a = lua_touserdata(L, lua_upvalueindex(2));
	const data_unset * const du = pos < a->used ? a->data[pos] : NULL;
	if (NULL == du) return 0;

		lua_pushlstring(L, BUF_PTR_LEN(&du->key));
		switch (du->type) {
			case TYPE_STRING:
				magnet_push_buffer(L, &((const data_string *)du)->value);
				break;
			case TYPE_INTEGER:
				lua_pushinteger(L, ((const data_integer *)du)->value);
				break;
			default:
				lua_pushnil(L);
				break;
		}

		/* Update our positional upval to reflect our new current position */
		lua_pushinteger(L, pos+1);
		lua_replace(L, lua_upvalueindex(1));

		/* Returning 2 items on the stack (key, value) */
		return 2;
}

/* Create the closure necessary to iterate over the array *a with the above function */
__attribute_noinline__
static int magnet_array_pairs(lua_State *L, array *a) {
	lua_pushinteger(L, 0); /* Push our current pos (the start) into upval 1 */
	lua_pushlightuserdata(L, a); /* Push our array *a into upval 2 */
	lua_pushcclosure(L, magnet_array_next, 2); /* Push our new closure with 2 upvals */
	return 1;
}

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
#define LUA_RIDX_LIGHTTPD_REQUEST "li.request"
#endif

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
__attribute_noinline__
#endif
static request_st * magnet_get_request(lua_State *L) {
     #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
	lua_getfield(L, LUA_REGISTRYINDEX, LUA_RIDX_LIGHTTPD_REQUEST);
	request_st * const r = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return r;
     #else
	return *(request_st **)lua_getextraspace(L);
     #endif
}

static void magnet_set_request(lua_State *L, request_st * const r) {
     #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
	lua_pushlightuserdata(L, r);
	lua_setfield(L, LUA_REGISTRYINDEX, LUA_RIDX_LIGHTTPD_REQUEST);
     #else
	*(request_st **)lua_getextraspace(L) = r;
     #endif
}

#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM >= 504
__attribute_noinline__
#endif
static buffer * magnet_tmpbuf_acquire(lua_State *L)
{
  #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
    UNUSED(L);
    return chunk_buffer_acquire();
  #else
    request_st * const r = magnet_get_request(L);
    buffer * const tb = r->tmp_buf;
    buffer_clear(tb);
    return tb;
  #endif
}

static void magnet_tmpbuf_release(buffer *b)
{
  #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 503
    chunk_buffer_release(b);
  #else
    UNUSED(b);
  #endif
}

typedef struct {
	const char *ptr;
	size_t len;
} const_buffer;

__attribute_noinline__
static const_buffer magnet_checkconstbuffer(lua_State *L, int idx) {
	const_buffer cb;
	if (!lua_isnoneornil(L, idx))
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


static int magnet_return_upvalue2(lua_State *L) {
    /*(XXX: is there a better way to do this?)*/
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, lua_upvalueindex(2));
    return 2;
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
      case 'h': { /* http-response-send-file */
        if (0 != strcmp(k.ptr, "http-response-send-file")) break;
        request_st * const r = magnet_get_request(L);
        r->http_status = 0;
        http_response_body_clear(r, 0);
        http_response_send_file(r, &sce->name, sce);
        lua_pushinteger(L, r->http_status);
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
            if (0 == strcmp(k.ptr, "st_atim")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_atime));
              #ifdef st_atime /* high-precision timestamp if available */
              #if defined(__APPLE__) && defined(__MACH__)
                lua_pushinteger(L, sce->st.st_atimespec.tv_nsec);
              #else
                lua_pushinteger(L, sce->st.st_atim.tv_nsec);
              #endif
              #else
                lua_pushinteger(L, 0);
              #endif
                lua_pushcclosure(L, magnet_return_upvalue2, 2);
                return 1;
            }
            break;
          case 'c': /* st_ctime */
            if (0 == strcmp(k.ptr, "st_ctime")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_ctime));
                return 1;
            }
            if (0 == strcmp(k.ptr, "st_ctim")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_ctime));
              #ifdef st_ctime /* high-precision timestamp if available */
              #if defined(__APPLE__) && defined(__MACH__)
                lua_pushinteger(L, sce->st.st_ctimespec.tv_nsec);
              #else
                lua_pushinteger(L, sce->st.st_ctim.tv_nsec);
              #endif
              #else
                lua_pushinteger(L, 0);
              #endif
                lua_pushcclosure(L, magnet_return_upvalue2, 2);
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
            if (0 == strcmp(k.ptr, "st_mtim")) {
                lua_pushinteger(L, TIME64_CAST(sce->st.st_mtime));
              #ifdef st_mtime /* high-precision timestamp if available */
              #if defined(__APPLE__) && defined(__MACH__)
                lua_pushinteger(L, sce->st.st_mtimespec.tv_nsec);
              #else
                lua_pushinteger(L, sce->st.st_mtim.tv_nsec);
              #endif
              #else
                lua_pushinteger(L, 0);
              #endif
                lua_pushcclosure(L, magnet_return_upvalue2, 2);
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
    if (luaL_newmetatable(L, "li.stat")) {                      /* (sp += 1) */
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
      lua_newuserdata0(L, sizeof(stat_cache_entry *));
    *udata = sce;

    magnet_stat_metatable(L);                                   /* (sp += 1) */
    lua_setmetatable(L, -2);                                    /* (sp -= 1) */
    return 1;
}


static int magnet_time(lua_State *L) {
    lua_pushinteger(L, (lua_Integer)log_epoch_secs);
    return 1;
}


static int magnet_hrtime(lua_State *L) {
    unix_timespec64_t ts;
    if (0 != log_clock_gettime_realtime(&ts))
        return 0;
    lua_pushinteger(L, (lua_Integer)ts.tv_sec);
    lua_pushinteger(L, (lua_Integer)ts.tv_nsec);
    return 2;
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
        char dighex[MD_DIGEST_LENGTH_MAX*2];
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
        char dighex[MD_DIGEST_LENGTH_MAX*2];
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
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    if (buffer_append_base64_decode(b, s.ptr, s.len, dict))
        lua_pushlstring(L, BUF_PTR_LEN(b));
    else
        lua_pushnil(L);
    magnet_tmpbuf_release(b);
    return 1;
}

static int magnet_b64enc(lua_State *L, base64_charset dict) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    buffer_append_base64_encode_no_padding(b, (uint8_t *)s.ptr, s.len, dict);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
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
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    uint8_t * const p = (uint8_t *)buffer_extend(b, s.len >> 1);
    int rc = li_hex2bin(p, s.len >> 1, s.ptr, s.len);
    if (0 == rc)
        lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
  #ifdef __COVERITY__ /* shut up coverity; li_hex2bin() returns 0 or -1 */
    force_assert(rc <= 0);
  #endif
    return rc+1; /* 1 on success (pushed string); 0 on failure (no value) */
}

static int magnet_hexenc(lua_State *L) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    buffer_append_string_encoded_hex_uc(b, s.ptr, s.len);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
    return 1; /* uppercase hex string; use lua s = s:lower() to lowercase */
}

static int magnet_quoteddec(lua_State *L) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len || s.ptr[0] != '"') {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    char *p = buffer_string_prepare_append(b, s.len);/*(s.len-1 is sufficient)*/
    size_t i = 1;
    for (; i < s.len && s.ptr[i] != '"'; ++i) {
        if (s.ptr[i] == '\\') {
            if (i+2 < s.len)
                ++i;
            else
                break;
        }
        *p++ = s.ptr[i];
    }
    int rc = (i == s.len-1 && s.ptr[i] == '"');
    if (rc)
        lua_pushlstring(L, b->ptr, (size_t)(p - b->ptr));
    magnet_tmpbuf_release(b);
    return rc; /* 1 on success (pushed string); 0 on failure (no value) */
}

static int magnet_quotedenc(lua_State *L) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    char *p = buffer_string_prepare_append(b, 2+(s.len << 1));
    *p++ = '"';
    for (size_t i = 0; i < s.len; ++i) {
        /*(note: not strictly checking for TEXT)*/
        /*(TEXT: any OCTET except CTLs but including LWS)*/
        if (s.ptr[i] == '"' || s.ptr[i] == '\\')
            *p++ = '\\';
        *p++ = s.ptr[i];
    }
    *p++ = '"';
    lua_pushlstring(L, b->ptr, (size_t)(p - b->ptr));
    magnet_tmpbuf_release(b);
    return 1;
}

/*(future: might move to buffer.c:buffer_append_bs_unescaped())*/
static void
magnet_buffer_append_bsdec (buffer * const restrict b,
                            const char * restrict s, const size_t len)
{
    /* decode backslash escapes */
    /*(caller must check result for decoded '\0', if necessary)*/
    char *d = buffer_string_prepare_append(b, len); /*(upper-bound len)*/
    for (const char * const end = s+len; s < end; ++s) {
        const char * const ptr = s;
        while (__builtin_expect( (*s != '\\'), 1) && ++s < end) ;
        if (s - ptr) {
            memcpy(d, ptr, (size_t)(s - ptr));
            d += (size_t)(s - ptr);
        }

        if (s == end)
            break;

        int c;
        switch ((c = ++s != end ? *s : '\\')) { /*(preserve stray '\\' at end)*/
          case '"': case '\\':
          default:
            break;
          case 'x':
            if (s+3 <= end) {
                unsigned char hi = hex2int(((unsigned char *)s)[1]);
                unsigned char lo = hex2int(((unsigned char *)s)[2]);
                if (0xFF != hi && 0xFF != lo) {
                    c = (hi << 4) | lo;
                    s += 2;
                }
            }
            break;
          case 'a':case 'b':case 't':case 'n':case 'v':case 'f':case 'r':
            c = "\a\bcde\fghijklm\nopq\rstu\vwxyz"[c-'a'];
            break;
          case 'u':
            if (s+5 <= end) {
                unsigned char hi = hex2int(((unsigned char *)s)[3]);
                unsigned char lo = hex2int(((unsigned char *)s)[4]);
                if (0xFF == hi || 0xFF == lo)
                    break;
                c = (hi << 4) | lo;
                if (__builtin_expect( (s[1] != '0'), 0)
                    || __builtin_expect( (s[2] != '0'), 0)) {
                    unsigned char hhi = hex2int(((unsigned char *)s)[1]);
                    unsigned char hlo = hex2int(((unsigned char *)s)[2]);
                    if (0xFF == hhi || 0xFF == hlo)
                        break;
                    c |= (int)((hhi << 12) | (hlo << 8));
                    if ((unsigned int)c - 0xd800u < 0x800)
                        break; /* 0xD800 - 0xDFFF ill-formed UTF-8 */
                }
                /* adapted from
                 * https://stackoverflow.com/questions/4607413/is-there-a-c-library-to-convert-unicode-code-points-to-utf-8 */
                if (__builtin_expect( (c > 0x7F), 0)) {
                    if (c < 0x800)
                        *d++ = 0xC0 | (c >> 6);
                    else {
                        *d++ = 0xE0 | (c >> 12);
                        *d++ = 0x80 | ((c >> 6) & 0x3F);
                    }
                    c = 0x80 | (c & 0x3F);
                }
                s += 4;
            }
            break;
          case '0': case '1': case '2': case '3':
            if (s+3 <= end
                /*&& ((unsigned char *)s)[0] - '0' < 4*//* 0-3 */
                && ((unsigned char *)s)[1] - '0' < 8    /* 0-7 */
                && ((unsigned char *)s)[2] - '0' < 8) { /* 0-7 */
                c = ((s[0]-'0') << 6) | ((s[1]-'0') << 3) | (s[2]-'0');
                s += 2;
            }
            else if (*s == '0')
                c = '\0'; /*(special-case "\\0" not part of octal "\\ooo")*/
            break;
        }
        *d++ = c;
    }
    buffer_truncate(b, d - b->ptr);
}

static int magnet_bsdec(lua_State *L) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    const char *ptr = s.ptr;
    size_t len = s.len;
    if (ptr[0] == '"' && ptr[len-1] == '"') {
        /*(ignore double-quotes ('"') surrounding string for convenience)*/
        ++ptr;
        len -= 2;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    magnet_buffer_append_bsdec(b, ptr, len);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
    return 1;
}

static int magnet_bsenc(lua_State *L, const int esc_json) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    if (esc_json)
        buffer_append_bs_escaped(b, s.ptr, s.len);
    else
        buffer_append_bs_escaped_json(b, s.ptr, s.len);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
    return 1;
}

static int magnet_bsenc_default(lua_State *L) {
    return magnet_bsenc(L, 0);
}

static int magnet_bsenc_json(lua_State *L) {
    return magnet_bsenc(L, 1);
}

static int magnet_xmlenc(lua_State *L) {
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
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
    magnet_tmpbuf_release(b);
    return 1;
}

static int magnet_urldec(lua_State *L) {
    /* url-decode and replace non-printable chars with '_'
     * This function should not be used on query-string unless it is used on
     * portions of query-string after splitting on '&', replacing '+' w/ ' ' */
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    buffer_copy_string_len(b, s.ptr, s.len);
    buffer_urldecode_path(b);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
    return 1;
}

static int magnet_urlenc(lua_State *L) {
    /* url-encode path
     * ('?' is encoded, if present)
     *  caller must split string if '?' is part of query-string)
     * ('/' is not encoded; caller must encode if not path separator) */
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    buffer_append_string_encoded(b, s.ptr, s.len, ENCODING_REL_URI);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
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
     *  a table useful for lookups, so this limitation is often acceptable) */
    lua_createtable(L, 0, 0);
    if (lua_isnoneornil(L, 1)) {
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, 1);
    if (0 == s.len) {
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    for (const char *qs = s.ptr, *eq, *amp; *qs; qs = amp+1) {
        for (amp = qs, eq = NULL; *amp && *amp != '&'; ++amp) {
            if (*amp == '=' && !eq) eq = amp;
        }
        if (amp != qs) {
            if (eq) {
                magnet_urldec_query_part(b, qs, (size_t)(eq - qs));
                lua_pushlstring(L, BUF_PTR_LEN(b));
                magnet_urldec_query_part(b, eq+1, (size_t)(amp - (eq+1)));
                lua_pushlstring(L, BUF_PTR_LEN(b));
            }
            else {
                magnet_urldec_query_part(b, qs, (size_t)(amp - qs));
                lua_pushlstring(L, BUF_PTR_LEN(b));
                lua_pushlstring(L, "", 0); /*(lua_pushnil() would delete key)*/
            }
            lua_rawset(L, -3);
        }
        if (*amp == '\0') break;
    }
    magnet_tmpbuf_release(b);
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
    if (!lua_istable(L, 1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    const_buffer s;
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
        if (lua_isstring(L, -2)) {
            if (!buffer_is_blank(b))
                buffer_append_char(b, '&');
            s = magnet_checkconstbuffer(L, -2);
            magnet_urlenc_query_part(b, s.ptr, s.len, 1);
            if (!lua_isnil(L, -1)) {
                s = magnet_checkconstbuffer(L, -1);
                buffer_append_char(b, '=');
                magnet_urlenc_query_part(b, s.ptr, s.len, 0);
            }
        }
    }
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
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
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
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
    magnet_tmpbuf_release(b);
    return 1;
}

static int magnet_fspath_simplify(lua_State *L) {
    /* simplify filesystem path */
    if (lua_isnoneornil(L, -1)) {
        lua_pushlstring(L, "", 0);
        return 1;
    }
    const_buffer s = magnet_checkconstbuffer(L, -1);
    if (0 == s.len) {
        lua_pushvalue(L, -1);
        return 1;
    }
    buffer * const b = magnet_tmpbuf_acquire(L);
    buffer_copy_string_len(b, s.ptr, s.len);
    buffer_path_simplify(b);
    lua_pushlstring(L, BUF_PTR_LEN(b));
    magnet_tmpbuf_release(b);
    return 1;
}

__attribute_pure__
static const char * magnet_scan_quoted_string (const char *s) {
    /* scan to end of of quoted-string (with s starting at '"')
     * loose parse; non-validating
     * - permit missing '"' at end of string (caller should check)
     * - stop at stray '\\' at end of string missing closing '"'
     * - not rejecting non-WS CTL chars
     */
    /*force_assert(*s == '"');*/
    do { ++s; } while (*s && *s != '"' && (*s != '\\' || (s[1] ? ++s : 0)));
    /*do { ++s; } while (*s && *s != '"' && (*s != '\\' || (*++s || (--s, 0))));*/
    return s;
}

static const char * magnet_push_quoted_string_range (lua_State *L, const char *b, const char *s) {
    /* quoted-string is unmodified (except for quoted-string end consistency)
     * including surrounding double-quotes and with quoted-pair unmodified */
    if (__builtin_expect( (*s == '"'), 1))
        lua_pushlstring(L, b, (size_t)(++s-b));
    else { /*(else invalid quoted-string, but handle anyway)*/
        /* append closing '"' for consistency */
        lua_pushlstring(L, b, (size_t)(s-b));
        if (*s != '\\')
            lua_pushlstring(L, "\"", 1);
        else { /* unescaped backslash at end of string; escape and close '"' */
            lua_pushlstring(L, "\\\\\"", 3);
            ++s; /*(now *s == '\0')*/
        }
        lua_concat(L, 2);
    }
    return s;
}

static const char * magnet_push_quoted_string(lua_State *L, const char *s) {
    return magnet_push_quoted_string_range(L, s, magnet_scan_quoted_string(s));
}

static const char * magnet_cookie_param_push_token(lua_State *L, const char *s) {
    const char *b = s;
    while (*s!='=' /*(note: not strictly rejecting all 'separators')*/
            && *s!=';' && *s!=' ' && *s!='\t' && *s!='\r' && *s!='\n' && *s)
        ++s;
    lua_pushlstring(L, b, (size_t)(s-b));
    return s;
}

static int magnet_cookie_tokens(lua_State *L) {
    /*(special-case cookies (';' separator); dup cookie-names overwritten)*/
    lua_createtable(L, 0, 0);
    if (lua_isnoneornil(L, 1))
        return 1;
    const char *s = luaL_checkstring(L, 1);
    do {
        while (*s==';' || *s==' ' || *s=='\t' || *s=='\r' || *s=='\n')
            ++s;
        if (*s == '\0') break;
        s = magnet_cookie_param_push_token(L, s);
        while (           *s==' ' || *s=='\t' || *s=='\r' || *s=='\n')
            ++s;
        if (*s == '=') {
            do {
                ++s;
            } while (     *s==' ' || *s=='\t' || *s=='\r' || *s=='\n');
            if (*s==';' || *s=='\0')
                lua_pushlstring(L, "", 0); /*(lua_pushnil() would delete key)*/
            else if (*s != '"')
                s = magnet_cookie_param_push_token(L, s);
            else
                s = magnet_push_quoted_string(L, s);
        }
        else {
            lua_pushlstring(L, "", 0); /*(lua_pushnil() would delete key)*/
        }
        lua_settable(L, -3);
        while (*s!=';' && *s!='\0') ++s; /* ignore/skip stray tokens */
    } while (*s++);
    return 1;
}

static const char * magnet_push_token(lua_State *L, const char *s) {
    const char *b = s;
    while (               *s!=' ' && *s!='\t' && *s!='\r' && *s!='\n'
           && *s!=',' && *s!=';' && *s!='=' && *s)
        ++s;
    lua_pushlstring(L, b, (size_t)(s-b));
    return s;
}

static int magnet_header_tokens(lua_State *L) {
    /* split into sequence of tokens/words
     *   Intermediate table is then more convenient to walk once quoted-string
     *   parsed into table entries since quoted-string may contain separators.
     *   Each token can be passed to lighty.c.quoteddec()
     *     (lighty.c.quoteddec() returns string as-is if not quoted-string)
     * (note: non-validating;
     *  e.g. existence of '=' token does not mean that next token is value,
     *       and '=' in value which is not part of quoted-string will be
     *       treated as separate token)
     * (note: case is preserved; non-quoted-string tokens are not lower-cased)
     * (words separated by whitespace are separate tokens unless quoted-string)
     *   (if that format not permitted in a specific header, caller must detect)
     * (optional whitespace (OWS) and bad whitespace (BWS) are removed)
     * (caller can create lookup table from sequence table, as appropriate) */
    lua_createtable(L, 0, 0);
    if (lua_isnoneornil(L, 1))
        return 1;
    const char *s = luaL_checkstring(L, 1);
    int i = 0;
    do {
        while (           *s==' ' || *s=='\t' || *s=='\r' || *s=='\n')
            ++s;
        if (*s=='\0') break;
        if (*s==',' || *s==';' || *s=='=')
            lua_pushlstring(L, s++, 1);
        else if (*s != '"')
            s = magnet_push_token(L, s);
        else
            s = magnet_push_quoted_string(L, s);
        lua_rawseti(L, -2, ++i);
    } while (*s);
    return 1;
}

static int magnet_readlink(lua_State *L) {
    const char * const path = luaL_checkstring(L, 1);
    buffer * const b = magnet_tmpbuf_acquire(L);
    ssize_t rd = readlink(path, b->ptr, buffer_string_space(b));
    if (rd > 0 && (size_t)rd < buffer_string_space(b))
        lua_pushlstring(L, b->ptr, (size_t)rd);
    else
        lua_pushnil(L);
    magnet_tmpbuf_release(b);
    return 1;
}

__attribute_noinline__
__attribute_nonnull__()
__attribute_pure__
static int magnet_extended_field_check_value (const const_buffer * const k, const const_buffer * const v, const unsigned int http_header_strict) {
    uint32_t len = v->len;
    if (0 == len) return 1;
    const char *b = v->ptr;
    for (const char *e; (e = memchr(b, '\n', len)); b = e) {
        /* check blank line (could terminate fields)
         * check for '\r' in "\r\n"
         * check that next line repeats same field name k followed by ':' */
        uint32_t n = (uint32_t)(++e - b);
        len -= n;
        if (n < 3 || e[-2] != '\r' || 0 == len)
            return 0;
        if (NULL != http_request_field_check_value(b, n-2, http_header_strict))
            return 0;
        if (*e == ' ' || *e == '\t') /* line folding; deprecated in HTTP */
            continue;   /*(should not be used; might not be handled elsewhere) */
        if (len < k->len + 1)
            return 0;
        if (e[k->len] != ':' || !buffer_eq_icase_ssn(e, k->ptr, k->len))
            return 0;
        e += k->len + 1;
        len -= k->len + 1;
    }
    return (NULL == http_request_field_check_value(b, len, http_header_strict));
    /* 1:success; 0:fail */
}

static int magnet_reqhdr_get(lua_State *L) {
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    const request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    const int id = http_header_hkey_get(k, (uint32_t)klen);
    magnet_push_buffer(L, http_header_request_get(r, id, k, klen));
    return 1;
}

static int magnet_reqhdr_set(lua_State *L) {
    const_buffer k = magnet_checkconstbuffer(L, 2);
    const_buffer v = magnet_checkconstbuffer(L, 3);

    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    enum http_header_e id = http_header_hkey_get(k.ptr, (uint32_t)k.len);
    const unsigned int http_header_strict =
      (r->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);

    switch (id) {
      default:
        break;

      case HTTP_HEADER_HOST:
        /* do not allow Host to be unset, even if HTTP/1.0
         * (change Host to something else, if you must */
        if (0 == v.len) return 0;

        buffer_copy_string_len_lc(r->tmp_buf, v.ptr, v.len);
        if (0 != http_request_host_policy(r->tmp_buf, r->conf.http_parseopts,
                                          r->con->proto_default_port)) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "invalid char attempting to set request header Host: (%.*s)",
              (int)v.len, v.ptr);
            return 0;
        }

        /*(must set r->http_host if r->http_host was not previously set)*/
        /* copied from request.c:http_request_header_set_Host() */
        r->http_host = http_header_request_set_ptr(r, HTTP_HEADER_HOST,
                                                   CONST_STR_LEN("Host"));
        buffer_copy_buffer(r->http_host, r->tmp_buf);
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
         *           (lighty.r.req_item["keep-alive"] = 0)
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

        /* other */

      case HTTP_HEADER_OTHER:
        if (NULL != http_request_field_check_name(k.ptr, k.len,
                                                  http_header_strict)) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "invalid char in request header field name: (%.*s)",
              (int)k.len, k.ptr);
            return 0;
        }
        break;
    }

    if (0 == v.len) {
        http_header_request_unset(r, id, k.ptr, k.len);
        return 0;
    }

    /* check read-only string before overwriting existing response value */
    if (!magnet_extended_field_check_value(&k, &v, http_header_strict)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "invalid char in request header field value for %.*s",
          (int)k.len, k.ptr);
        return 0;
    }

    buffer * const vb = http_header_request_set_ptr(r, id, k.ptr, k.len);
    buffer_copy_string_len(vb, v.ptr, v.len);

    for (char *n = vb->ptr; (n = strchr(n, '\n')); ++n) {
        /* unfold line folding; deprecated in HTTP */
        if (n[1] == ' ' || n[1] == '\t') {
            n[-1] = n[0] = ' ';
            continue;
        }
      #if 0
        /* handle multi-line request headers with HTTP/2
         * (lowercase header name and mark r->rqst_header_repeated)
         * (similar to http_header.c:http_header_response_insert_addtl()) */
        if (r->http_version >= HTTP_VERSION_2) {
            /*r->rqst_header_repeated = 1;*//*(not implemented)*/
            do {
                ++n;
                if (light_isupper(*n)) *n |= 0x20;
            } while (*n != ':' && *n != '\n' && *n != '\0');
            /*(checked in magnet_extended_field_check_value(), so not '\0')*/
        }
      #endif
    }

    return 0;
}

static int magnet_reqhdr_pairs(lua_State *L) {
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    return magnet_array_pairs(L, &r->rqst_headers);
}

static int magnet_resphdr_get(lua_State *L) {
    /* Note: access to lighttpd r->resp_headers here is *independent* from
     * the (pending) changes in the (deprecated) lua lighty.header[] table */
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    const request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    const int id = http_header_hkey_get(k, (uint32_t)klen);
    magnet_push_buffer(L, http_header_response_get(r, id, k, klen));
    return 1;
}

static int magnet_resphdr_set_kv(lua_State *L, request_st * const r) {
    const const_buffer k = magnet_checkconstbuffer(L, -2);
    const const_buffer v = magnet_checkconstbuffer(L, -1);
    const enum http_header_e id = http_header_hkey_get(k.ptr, (uint32_t)k.len);
    const unsigned int http_header_strict =
      (r->conf.http_parseopts & HTTP_PARSEOPT_HEADER_STRICT);

    switch (id) {
      default:
        break;

      case HTTP_HEADER_CONTENT_LENGTH:
        /* lighttpd handles Content-Length or Transfer-Encoding for response */
        return 0; /* silently ignore; do not allow modification */

      /* do not permit modification of hop-by-hop (connection) headers */

      case HTTP_HEADER_CONNECTION:
        /* do not permit modification of Connection, incl add/remove tokens */
        /* future: might provide a different interface to set r->keep_alive = 0,
         *           (lighty.r.req_item["keep-alive"] = 0)
         *         and also handle in context if HTTP/2 */
      case HTTP_HEADER_TRANSFER_ENCODING:
        return 0; /* silently ignore; do not allow modification */

        /* other */

      case HTTP_HEADER_OTHER:
        if (NULL != http_request_field_check_name(k.ptr, k.len,
                                                  http_header_strict)) {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "invalid char in response header field name: (%.*s)",
              (int)k.len, k.ptr);
            return 0;
        }
        break;
    }

    if (0 == v.len) {
        http_header_response_unset(r, id, k.ptr, k.len);
        return 0;
    }

    /* check read-only string before overwriting existing response value */
    if (!magnet_extended_field_check_value(&k, &v, http_header_strict)) {
        log_error(r->conf.errh, __FILE__, __LINE__,
          "invalid char in response header field value for %.*s",
          (int)k.len, k.ptr);
        return 0;
    }

    buffer * const vb = http_header_response_set_ptr(r, id, k.ptr, k.len);
    buffer_copy_string_len(vb, v.ptr, v.len);

    for (char *n = vb->ptr; (n = strchr(n, '\n')); ++n) {
        /* unfold line folding; deprecated in HTTP */
        if (n[1] == ' ' || n[1] == '\t') {
            n[-1] = n[0] = ' ';
            continue;
        }
        /* handle multi-line response headers with HTTP/2
         * (lowercase header name and mark r->resp_header_repeated)
         * (similar to http_header.c:http_header_response_insert_addtl()) */
        if (r->http_version >= HTTP_VERSION_2) {
            r->resp_header_repeated = 1;
            do {
                ++n;
                if (light_isupper(*n)) *n |= 0x20;
            } while (*n != ':' && *n != '\n' && *n != '\0');
            /*(checked in magnet_extended_field_check_value(), so not '\0')*/
        }
    }

    return 0;
}

static int magnet_resphdr_set(lua_State *L) {
    /*const_buffer k = magnet_checkconstbuffer(L, 2);*/
    /*const_buffer v = magnet_checkconstbuffer(L, 3);*/
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    return magnet_resphdr_set_kv(L, r);
}

static int magnet_resphdr_pairs(lua_State *L) {
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    return magnet_array_pairs(L, &r->resp_headers);
}

static int magnet_plugin_stats_get(lua_State *L) {
    const_buffer k = magnet_checkconstbuffer(L, 2);
    lua_pushinteger(L, (lua_Integer)*plugin_stats_get_ptr(k.ptr, k.len));
    return 1;
}

static int magnet_plugin_stats_set(lua_State *L) {
    const_buffer k = magnet_checkconstbuffer(L, 2);
    plugin_stats_set(k.ptr, k.len, luaL_checkinteger(L, 3));
    return 0;
}

static int magnet_plugin_stats_pairs(lua_State *L) {
    return magnet_array_pairs(L, &plugin_stats);
}


static int
magnet_req_item_get (lua_State *L)
{
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    switch (klen) {
      case 8:
        if (0 == memcmp(k, "bytes_in", 8)) {
            lua_pushinteger(L, (lua_Integer)http_request_stats_bytes_in(r));
            return 1;
        }
        break;
      case 9:
        if (0 == memcmp(k, "bytes_out", 9)) {
            lua_pushinteger(L, (lua_Integer)http_request_stats_bytes_out(r));
            return 1;
        }
        if (0 == memcmp(k, "stream_id", 9)) {
            lua_pushinteger(L, (lua_Integer)r->x.h2.id);
            return 1;
        }
        if (0 == memcmp(k, "req_count", 9)) {
            lua_pushinteger(L, (lua_Integer)r->con->request_count);
            return 1;
        }
        break;
      case 10:
        if (0 == memcmp(k, "start_time", 10)) {
            lua_pushinteger(L, (lua_Integer)r->start_hp.tv_sec);
            lua_pushinteger(L, (lua_Integer)r->start_hp.tv_nsec);
            lua_pushcclosure(L, magnet_return_upvalue2, 2);
            return 1;
        }
        if (0 == memcmp(k, "keep_alive", 10)) {
            lua_pushinteger(L, (lua_Integer)r->keep_alive);
            return 1;
        }
        break;
      case 11:
        if (0 == memcmp(k, "http_status", 11)) {
            lua_pushinteger(L, (lua_Integer)r->http_status);
            return 1;
        }
        break;
      case 14:
        if (0 == memcmp(k, "req_header_len", 14)) {
            lua_pushinteger(L, (lua_Integer)r->rqst_header_len);
            return 1;
        }
        break;
      case 15:
        if (0 == memcmp(k, "resp_header_len", 15)) {
            lua_pushinteger(L, (lua_Integer)r->resp_header_len);
            return 1;
        }
        break;
      default:
        break;
    }
    return luaL_error(L, "r.req_item['%s'] invalid", k);
}

static int
magnet_req_item_set (lua_State *L)
{
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    int v = (int)luaL_checkinteger(L, 3);

    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    switch (klen) {
      case 10:
        if (0 == memcmp(k, "keep_alive", 10)) {
            if (v == 0 || v == -1) r->keep_alive = v;
            return 0;
        }
        break;
      default:
        break;
    }
    return luaL_error(L, "r.req_item['%s'] invalid or read-only", k);
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
		MAGNET_ENV_REQUEST_SERVER_NAME,
		MAGNET_ENV_REQUEST_STAGE
	} type;
} magnet_env_t;

/*(NB: coordinate any changes with scan offsets in magnet_env_get_id())*/
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
    { CONST_STR_LEN("request.server-name"),  MAGNET_ENV_REQUEST_SERVER_NAME },
    { CONST_STR_LEN("request.stage"),        MAGNET_ENV_REQUEST_STAGE },

    { NULL, 0, MAGNET_ENV_UNSET }
};

__attribute_cold__
static void
magnet_env_get_uri_path_raw (buffer * const dest, const buffer * const target)
{
    const uint32_t len = buffer_clen(target);
    const char * const qmark = memchr(target->ptr, '?', len);
    buffer_copy_string_len(dest, target->ptr,
                           qmark ? (uint32_t)(qmark - target->ptr) : len);
}

__attribute_cold__
static int
magnet_env_set_uri_path_raw (request_st * const r,
                             const const_buffer * const val)
{
    /* modify uri-path of r->target; preserve query-part, if present */
    /* XXX: should we require that resulting path begin with '/' or %2F ? */
    const uint32_t len = buffer_clen(&r->target);
    const char * const qmark = memchr(r->target.ptr, '?', len);
    if (NULL != qmark)
        buffer_copy_string_len(r->tmp_buf, qmark,
                               len - (uint32_t)(qmark - r->target.ptr));
    buffer_copy_string_len(&r->target, val->ptr, val->len);
    if (NULL != qmark)
        buffer_append_string_buffer(&r->target, r->tmp_buf);
    return 0;
}

__attribute_cold__
__attribute_noinline__
static buffer *
magnet_env_get_laddr_by_id (request_st * const r, const int id)
{
    buffer * const dest = r->tmp_buf;
    const server_socket * const srv_socket = r->con->srv_socket;
    switch (id) {
      case MAGNET_ENV_REQUEST_SERVER_ADDR: /* local IP without port */
        if (sock_addr_is_addr_wildcard(&srv_socket->addr)) {
            sock_addr addrbuf;
            socklen_t addrlen = sizeof(addrbuf);
            const int fd = r->con->fd;
            if (0 == getsockname(fd,(struct sockaddr *)&addrbuf,&addrlen)) {
                char buf[INET6_ADDRSTRLEN + 1];
                const char *s = sock_addr_inet_ntop(&addrbuf, buf, sizeof(buf));
                if (NULL != s) {
                    buffer_copy_string_len(dest, s, strlen(s));
                    break;
                }
            }
        }
        buffer_copy_string_len(dest, srv_socket->srv_token->ptr,
                               srv_socket->srv_token_colon);
        break;
      case MAGNET_ENV_REQUEST_SERVER_PORT:
      {
        const buffer * const srv_token = srv_socket->srv_token;
        const uint32_t tlen = buffer_clen(srv_token);
        uint32_t portoffset = srv_socket->srv_token_colon;
        portoffset = portoffset < tlen ? portoffset+1 : tlen;
        buffer_copy_string_len(dest, srv_token->ptr+portoffset,
                               tlen-portoffset);
        break;
      }
      default:
        break;
    }
    return dest;
}

static buffer *
magnet_env_get_buffer_by_id (request_st * const r, const int id)
{
	buffer *dest = r->tmp_buf;
	buffer_clear(dest);

	switch (id) {
	case MAGNET_ENV_PHYSICAL_PATH: dest = &r->physical.path; break;
	case MAGNET_ENV_PHYSICAL_REL_PATH: dest = &r->physical.rel_path; break;
	case MAGNET_ENV_PHYSICAL_DOC_ROOT: dest = &r->physical.doc_root; break;
	case MAGNET_ENV_PHYSICAL_BASEDIR: dest = &r->physical.basedir; break;

	case MAGNET_ENV_URI_PATH: dest = &r->uri.path; break;
	case MAGNET_ENV_URI_PATH_RAW:
		magnet_env_get_uri_path_raw(dest, &r->target);
		break;
	case MAGNET_ENV_URI_SCHEME: dest = &r->uri.scheme; break;
	case MAGNET_ENV_URI_AUTHORITY: dest = &r->uri.authority; break;
	case MAGNET_ENV_URI_QUERY: dest = &r->uri.query; break;

	case MAGNET_ENV_REQUEST_METHOD:
		http_method_append(dest, r->http_method);
		break;
	case MAGNET_ENV_REQUEST_URI:      dest = &r->target; break;
	case MAGNET_ENV_REQUEST_ORIG_URI: dest = &r->target_orig; break;
	case MAGNET_ENV_REQUEST_PATH_INFO: dest = &r->pathinfo; break;
	case MAGNET_ENV_REQUEST_REMOTE_ADDR: dest = r->dst_addr_buf; break;
	case MAGNET_ENV_REQUEST_REMOTE_PORT:
		buffer_append_int(dest, sock_addr_get_port(r->dst_addr));
		break;
	case MAGNET_ENV_REQUEST_SERVER_ADDR: /* local IP without port */
	case MAGNET_ENV_REQUEST_SERVER_PORT:
		return magnet_env_get_laddr_by_id(r, id);
	case MAGNET_ENV_REQUEST_PROTOCOL:
		http_version_append(dest, r->http_version);
		break;
	case MAGNET_ENV_REQUEST_SERVER_NAME:
		buffer_copy_buffer(dest, r->server_name);
		break;
	case MAGNET_ENV_REQUEST_STAGE:
		if (http_request_state_is_keep_alive(r))
			buffer_append_string_len(dest, CONST_STR_LEN("keep-alive"));
		else
			http_request_state_append(dest, r->state);
		break;

	case MAGNET_ENV_UNSET:
		return NULL;
	}

	return dest;
}

__attribute_pure__
static int magnet_env_get_id(const char * const key, const size_t klen) {
    /*(NB: ensure offsets match position in magnet_env[])*/
    int i; /* magnet_env[] scan offset */
    switch (*key) {
      case 'r': /* request.* or response.* */
        i = klen > 7 && key[7] == '.' ? 9 : 21;
        break;
      case 'u': /* uri.* */
      default:
        i = 4;
        break;
      case 'p': /* physical.* */
        i = 0;
        break;
    }
    for (; i < (int)(sizeof(magnet_env)/sizeof(*magnet_env)); ++i) {
        if (klen == magnet_env[i].nlen
            && 0 == memcmp(key, magnet_env[i].name, klen))
            return magnet_env[i].type;
    }
    return MAGNET_ENV_UNSET;
}

static int magnet_env_get(lua_State *L) {
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    const int env_id = magnet_env_get_id(k, klen);
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    magnet_push_buffer(L, magnet_env_get_buffer_by_id(r, env_id));
    return 1;
}

__attribute_cold__
static int
magnet_env_set_raddr_by_id (lua_State *L, request_st * const r, const int id,
                            const const_buffer * const val)
{
    switch (id) {
      case MAGNET_ENV_REQUEST_REMOTE_ADDR:
       #ifdef HAVE_SYS_UN_H
        if (val->len && *val->ptr == '/'
            && 0 == sock_addr_assign(r->dst_addr, AF_UNIX, 0, val->ptr)) {
        }
        else
       #endif
        {
            sock_addr saddr;
            saddr.plain.sa_family = AF_UNSPEC;
            if (1 == sock_addr_from_str_numeric(&saddr, val->ptr, r->conf.errh)
                && saddr.plain.sa_family != AF_UNSPEC) {
                sock_addr_set_port(&saddr, 0);
                memcpy(r->dst_addr, &saddr, sizeof(sock_addr));
            }
            else {
                return luaL_error(L,
                                  "r.req_attr['remote-addr'] invalid addr: %s",
                                  val->ptr);
            }
        }
        buffer_copy_string_len(r->dst_addr_buf, val->ptr, val->len);
        config_cond_cache_reset_item(r, COMP_HTTP_REMOTE_IP);
        break;
      case MAGNET_ENV_REQUEST_REMOTE_PORT:
        sock_addr_set_port(r->dst_addr, (unsigned short)atoi(val->ptr));
        break;
      default:
        break;
    }
    return 0;
}

__attribute_cold__
static int
magnet_env_set_protocol_downgrade_http10 (request_st * const r,
                                          const const_buffer * const val)
{
    if (r->http_version != HTTP_VERSION_1_1 || 0 != strcmp(val->ptr,"HTTP/1.0"))
        return 0;

    /* downgrading HTTP/1.1 to HTTP/1.0 is a workaround for broken clients
     * - clients sending HTTP/1.1 request but are unable to handle response
     *     sent with Transfer-Encoding: chunked
     * - clients sending HTTP/1.1 request body with unspecified length
     *     (without Content-Length or Transfer-Encoding: chunked)
     *     mod_magnet lua can use this interface to call the sequence
     *       r.req_attr["request.protocol"] = "HTTP/1.0"
     *       local rc = r.req_body.unspecified_len
     * note: even if downgrading HTTP/1.1 to HTTP/1.0, lighttpd may still
     *   support if HTTP/1.1 client sent Transfer-Encoding: chunked
     *   which lighttpd has marked in request with (-1 == r->reqbody_length)*/

    /* reference: response.c:http_response_config() !r->conf.allow_http11 */
    /* (server.protocol_http11 = "disable") */

    r->http_version = HTTP_VERSION_1_0;

    /*(when forcing HTTP/1.0, ignore (unlikely) Connection: keep-alive)*/
    /*r->keep_alive = 0;*//*(disabled; use r.req_item["keep-alive"] = 0)*/

    http_header_request_unset(r, HTTP_HEADER_UPGRADE,
                              CONST_STR_LEN("upgrade"));

    /*(just in case lighty.r.req_env has been initted by prior or current
     * lua script being run, and might be accessed by current or subsequent
     * lua script during this request)*/
    if (http_header_env_get(r, CONST_STR_LEN("SERVER_PROTOCOL"))) {
        http_header_env_set(r, CONST_STR_LEN("SERVER_PROTOCOL"),
                               CONST_STR_LEN("HTTP/1.0"));
        /*(blank it out; slightly more work to extract from array list)*/
        if (http_header_env_get(r, CONST_STR_LEN("HTTP_UPGRADE")))
            http_header_env_set(r, CONST_STR_LEN("HTTP_UPGRADE"),
                                   CONST_STR_LEN(""));
    }
    return 0;
}

#if 0
__attribute_cold__
static int
magnet_env_set_server_name (request_st * const r,
                            const const_buffer * const val)
{
    r->server_name = &r->server_name_buf;
    buffer_copy_string_len(&r->server_name_buf, val->ptr, val->len);
    return 0;
}
#endif

static int magnet_env_set(lua_State *L) {
    size_t klen;
    const char * const key = luaL_checklstring(L, 2, &klen);
    const_buffer val = magnet_checkconstbuffer(L, 3);

    const int env_id = magnet_env_get_id(key, klen);
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);

    switch (env_id) {
      default:
        break;
      case MAGNET_ENV_URI_PATH_RAW:
        return magnet_env_set_uri_path_raw(r, &val);
      case MAGNET_ENV_REQUEST_REMOTE_ADDR:
      case MAGNET_ENV_REQUEST_REMOTE_PORT:
        return magnet_env_set_raddr_by_id(L, r, env_id, &val);
      case MAGNET_ENV_REQUEST_PROTOCOL:
        return magnet_env_set_protocol_downgrade_http10(r, &val);
     #if 0 /*(leave read-only for now; change attempts silently ignored)*/
      case MAGNET_ENV_REQUEST_SERVER_NAME:
        return magnet_env_set_server_name(r, &val);
     #endif
      /*case MAGNET_ENV_REQUEST_STAGE:*//*(change attempts silently ignored)*/
    }

    buffer * const dest = magnet_env_get_buffer_by_id(r, env_id);
    if (NULL == dest)
        return luaL_error(L, "couldn't store '%s' in r.req_attr[]", key);

    if (lua_isnoneornil(L, 3)) {
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
	/* ignore previous key: use upvalue for current pos */
	lua_settop(L, 0);
	const int pos = lua_tointeger(L, lua_upvalueindex(1));

	if (NULL == magnet_env[pos].name) return 0; /* end of list */
	/* Update our positional upval to reflect our new current position */
	lua_pushinteger(L, pos + 1);
	lua_replace(L, lua_upvalueindex(1));

	/* key to return */
	lua_pushlstring(L, magnet_env[pos].name, magnet_env[pos].nlen);

	/* get value */
	request_st * const r = lua_touserdata(L, lua_upvalueindex(2));
	magnet_push_buffer(L, magnet_env_get_buffer_by_id(r, magnet_env[pos].type));

	/* return 2 items on the stack (key, value) */
	return 2;
}

static int magnet_env_pairs(lua_State *L) {
    lua_pushinteger(L, 0); /* Push our current pos (the start) into upval 1 */
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    lua_pushlightuserdata(L, r); /* Push request_st *r into upval 2 */
    lua_pushcclosure(L, magnet_env_next, 2); /* Push new closure with 2 upvals*/
    return 1;
}

static int magnet_envvar_get(lua_State *L) {
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    const request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    magnet_push_buffer(L, http_header_env_get(r, k, klen));
    return 1;
}

static int magnet_envvar_set(lua_State *L) {
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    const_buffer key = magnet_checkconstbuffer(L, 2);
    if (__builtin_expect( (lua_isnil(L, 3)), 0)) {
        buffer * const v = http_header_env_get(r, key.ptr, key.len);
        if (v) buffer_clear(v); /*(unset)*/
        return 0;
    }
    const_buffer val = magnet_checkconstbuffer(L, 3);
    http_header_env_set(r, key.ptr, key.len, val.ptr, val.len);
    return 0;
}

static int magnet_envvar_pairs(lua_State *L) {
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    return magnet_array_pairs(L, &r->env);
}


static int magnet_respbody_add(lua_State *L) {
    request_st * const r = lua_touserdata(L, lua_upvalueindex(1));
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
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    switch (k[0]) {
      case 'a': /* add; r.resp_body.add */
        if (k[1] == 'd' && k[2] == 'd' && k[3] == '\0') {
            lua_pushlightuserdata(L, r);
            lua_pushcclosure(L, magnet_respbody_add, 1);
            return 1;
        }
        break;
      case 'b':
        if (klen == 8 && 0 == memcmp(k, "bytes_in", 8)) {
            lua_pushinteger(L, r->write_queue.bytes_in);
            return 1;
        }
        if (klen == 9 && 0 == memcmp(k, "bytes_out", 9)) {
            lua_pushinteger(L, r->write_queue.bytes_out);
            return 1;
        }
        break;
     #if 0 /*(future: provide pairs() interface to iterate over chunkqueue)*/
           /*(might convert chunks into table of strings, {filename="..."})*/
           /*(what about c->offset into chunk?)*/
     #endif
      case 'g': /* get; r.resp_body.get */
        if (k[1] == 'e' && k[2] == 't' && k[3] == '\0') {
            if (r->resp_body_finished)
                magnet_push_cq(L, &r->write_queue, r->conf.errh);
            else
                lua_pushnil(L); /*(?maybe return -1 instead if len unknown?)*/
            return 1;
        }
        break;
      case 'l': /* len; r.resp_body.len */
        if (k[1] == 'e' && k[2] == 'n' && k[3] == '\0') {
            if (r->resp_body_finished)
                lua_pushinteger(L, chunkqueue_length(&r->write_queue));
            else
                lua_pushnil(L); /*(?maybe return -1 instead if len unknown?)*/
            return 1;
        }
        break;
      case 's': /* set; r.resp_body.set */
        if (k[1] == 'e' && k[2] == 't' && k[3] == '\0') {
            http_response_body_clear(r, 0); /* clear respbody, then add */
            r->resp_body_finished = 1;
            lua_pushlightuserdata(L, r);
            lua_pushcclosure(L, magnet_respbody_add, 1);
            return 1;
        }
        break;
      default:
        break;
    }
    lua_pushliteral(L, "r.resp_body invalid method or param");
    lua_error(L);
    return 0;
}


static int magnet_reqbody_add(lua_State *L) {
    request_st * const r = lua_touserdata(L, lua_upvalueindex(1));
    chunkqueue * const cq = &r->reqbody_queue;
    const int tempfile = (cq->last && cq->last->file.is_temp);
    if (lua_isstring(L, -1)) {
        const_buffer data = magnet_checkconstbuffer(L, -1);
        if (r->reqbody_length <= 65536 && !tempfile)
            chunkqueue_append_mem(cq, data.ptr, data.len);
        else if (chunkqueue_append_mem_to_tempfile(cq, data.ptr, data.len,
                                                   r->conf.errh))
            return 0; /* boolean false */
        r->reqbody_length += data.len;
        return 1; /* boolean true */
    }
    else if (!lua_istable(L, -1))
        return 0; /* boolean false */

    for (int i=1, end=0, n=(int)lua_rawlen(L,-1); !end && i <= n; ++i) {
        lua_rawgeti(L, -1, i);

        if (lua_isstring(L, -1)) {
            const_buffer data = magnet_checkconstbuffer(L, -1);
            if (r->reqbody_length <= 65536 && !tempfile)
                chunkqueue_append_mem(cq, data.ptr, data.len);
            else if (chunkqueue_append_mem_to_tempfile(cq, data.ptr, data.len,
                                                       r->conf.errh))
                return 0; /* boolean false */
            r->reqbody_length += data.len;
        }
        else if (lua_isnil(L, -1)) { /* end of list */
            end = 1;
        }
        else {
            log_error(r->conf.errh, __FILE__, __LINE__,
              "body[%d] table must contain strings", i);
            end = 1;
        }

        lua_pop(L, 1); /* pop the content[...] entry value */
    }

    return 1; /* boolean true */
}


static int magnet_reqbody(lua_State *L) {
    request_st * const r = **(request_st ***)lua_touserdata(L, 1);
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    switch (k[0]) {
      case 'a': /* add; r.req_body.add */
        if (k[1] == 'd' && k[2] == 'd' && k[3] == '\0') {
            chunkqueue * const cq = &r->reqbody_queue;
            if (cq->bytes_in == (off_t)r->reqbody_length) {
                lua_pushlightuserdata(L, r);
                lua_pushcclosure(L, magnet_reqbody_add, 1);
            }
            else /* reqbody not yet collected */
                lua_pushnil(L);
            return 1;
        }
        break;
      case 'b':
        if (klen == 8 && 0 == memcmp(k, "bytes_in", 8)) {
            lua_pushinteger(L, r->reqbody_queue.bytes_in);
            return 1;
        }
        if (klen == 9 && 0 == memcmp(k, "bytes_out", 9)) {
            lua_pushinteger(L, r->reqbody_queue.bytes_out);
            return 1;
        }
        break;
      case 'c': /* collect; r.req_body.collect */
        if (klen == 7 && 0 == memcmp(k, "collect", 7)) {
            chunkqueue * const cq = &r->reqbody_queue;
            if (cq->bytes_in == (off_t)r->reqbody_length)
                lua_pushboolean(L, 1);
            else if (NULL == r->handler_module) {
                r->conf.stream_request_body &=
                  ~(FDEVENT_STREAM_REQUEST|FDEVENT_STREAM_REQUEST_BUFMIN);
                r->conf.stream_request_body |=
                  FDEVENT_STREAM_REQUEST_CONFIGURED;
                r->handler_module = mod_magnet_plugin_data->self;
                lua_pushboolean(L, 0);
            }
            else if (0 == strcmp(r->handler_module->name, "security3")) {
                /*(mod_security3 uses similar technique to collect req body)*/
                lua_pushboolean(L, 0);
            }
            else {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "unable to collect request body (handler already set); "
                  "(prefer to collect in magnet.attract-raw-url-to config) "
                  "(perhaps load mod_magnet earlier in server.modules, "
                  "before mod_%s; or require r.req_env['REMOTE_USER'] before "
                  "attempting r.req_body.collect?)", r->handler_module->name);
                lua_pushnil(L);
            }
            return 1;
        }
        break;
      case 'g': /* get; r.req_body.get */
        if (k[1] == 'e' && k[2] == 't' && k[3] == '\0') {
            chunkqueue * const cq = &r->reqbody_queue;
            if (cq->bytes_in == (off_t)r->reqbody_length)
                magnet_push_cq(L, cq, r->conf.errh);
            else
                lua_pushnil(L); /*(?maybe return -1 instead if len unknown?)*/
            return 1;
        }
        break;
      case 'l': /* len */
        if (k[1] == 'e' && k[2] == 'n' && k[3] == '\0') {
            lua_pushinteger(L, r->reqbody_length);
            return 1;
        }
        break;
      case 's': /* set; r.req_body.set */
        if (k[1] == 'e' && k[2] == 't' && k[3] == '\0') {
            chunkqueue * const cq = &r->reqbody_queue;
            if (cq->bytes_in == (off_t)r->reqbody_length) {
                r->reqbody_length = 0;
                chunkqueue_reset(&r->reqbody_queue);
                lua_pushlightuserdata(L, r);
                lua_pushcclosure(L, magnet_reqbody_add, 1);
            }
            else /* reqbody not yet collected */
                lua_pushnil(L);
            return 1;
        }
        break;
      case 'u': /* unspecified_len; r.req_body.unspecified_len */
        if (klen == 15 && 0 == memcmp(k, "unspecified_len", 15)) {
            /* HTTP/1.0 with unknown request body len might omit Content-Length.
             * If Connection: keep-alive is not provided (so Connection: close),
             * then allow reading until EOF if this method is called, instead of
             * treating request as if Content-Length: 0 was sent (the default).
             * (Implemented by streaming; not performing request offload.) */
            if (HTTP_VERSION_1_0 == r->http_version
                && 0 == r->reqbody_length
                   /*(r->reqbody == -1 if HTTP/1.1 Transfer-Encoding: chunked)*/
                && !r->keep_alive
                && !light_btst(r->rqst_htags, HTTP_HEADER_CONTENT_LENGTH)) {
                http_response_upgrade_read_body_unknown(r);
                lua_pushboolean(L, 1);
            }
            else
                lua_pushboolean(L, 0);
            return 1;
        }
        break;
      default:
        break;
    }
    lua_pushliteral(L, "r.req_body invalid method or param");
    lua_error(L);
    return 0;
}


__attribute_cold__
static int magnet_lighty_result_get(lua_State *L) {
    /* __index: param 1 is the lighty table the value was not found in */
    lua_pushvalue(L, 2);
    lua_rawget(L, lua_upvalueindex(1));
    if (lua_isnil(L, -1)) {
        const_buffer k = magnet_checkconstbuffer(L, 2);
        if (   (k.len == 6 && 0 == memcmp(k.ptr, "header", 6))
            || (k.len == 7 && 0 == memcmp(k.ptr, "content", 7))) {
            lua_pop(L, 1);            /* pop nil */
            lua_createtable(L, 0, 0); /* create "header","content" on demand */
            lua_pushvalue(L, 2);      /* k: "header" or "content" */
            lua_pushvalue(L, -2);     /* v: table */
            lua_rawset(L, lua_upvalueindex(1)); /* set in result table */
        }
    }
    return 1;
}

__attribute_cold__
static int magnet_lighty_result_set(lua_State *L) {
    /* __newindex: param 1 is lighty table the value is supposed to be set in */
    /* assign value to alternate table; replacing existing value, if any */
    lua_rawset(L, lua_upvalueindex(1)); /* set in result table */
    return 0;
}


__attribute_cold__
__attribute_noinline__
static void magnet_copy_response_header(lua_State * const L, request_st * const r) {
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
        if (lua_isstring(L, -1) && lua_isstring(L, -2))
            magnet_resphdr_set_kv(L, r);
    }
}

/**
 * (deprecated API)
 * walk through the content array set by lua script, e.g.
 *   lighty.header["Content-Type"] = "text/html"
 *   lighty.content =
 *     { "<html><body><pre>", { file = "/content" } , "</pre></body></html>" }
 *   return 200
 */
__attribute_cold__
__attribute_noinline__
static void magnet_attach_content(lua_State * const L, request_st * const r) {
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
					/*(luaL_optinteger might raise error, which we want to avoid)*/
					/*off_t off = (off_t) luaL_optinteger(L, -1, 0);*/
					/*off_t len = (off_t) luaL_optinteger(L, -2, -1);*/ /*(-1 as flag to use file size minus offset (below))*/
					int isnum = 1;
					off_t off = lua_isnil(L, -1) ? 0 : (off_t) lua_tointegerx(L, -1, &isnum);
					if (!isnum) {
						off = 0;
						log_error(r->conf.errh, __FILE__, __LINE__,
						  "content[%d] is a table and field \"offset\" must be an integer", i);
					}
					isnum = 1;
					off_t len = lua_isnil(L, -2) ? -1 : (off_t) lua_tointegerx(L, -2, &isnum);
					/*(-1 len as flag to use file size minus offset (below))*/
					if (!isnum) {
						len = -1;
						log_error(r->conf.errh, __FILE__, __LINE__,
						  "content[%d] is a table and field \"length\" must be an integer", i);
					}
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
}

__attribute_cold__
static void magnet_mainenv_metatable(lua_State * const L) {
    if (luaL_newmetatable(L, "li.mainenv")) {                 /* (sp += 1) */
        lua_pushglobaltable(L);                               /* (sp += 1) */
        lua_setfield(L, -2, "__index"); /* { __index = _G }      (sp -= 1) */
        lua_pushboolean(L, 0);                                /* (sp += 1) */
        lua_setfield(L, -2, "__metatable"); /* protect metatable (sp -= 1) */
    }
}

static void
magnet_request_userdata_method (lua_State * const L, request_st ** const rr, const char *meta)
{
    /*(meta is name of cached metatable; meta must start w/ "li." prefix)*/
    *(request_st ***)lua_newuserdata0(L, sizeof(request_st **)) = rr;
  #ifdef __COVERITY__ /* shut up coverity; read the comment below */
    if (luaL_newmetatable(L, meta)) { }
  #else
    luaL_newmetatable(L, meta); /*(should not fail; init'd in script setup)*/
  #endif
    lua_setmetatable(L, -2);
    lua_setfield(L, -2, meta+3); /*(meta+3 to skip over "li." prefix)*/
}

static void
magnet_request_table (lua_State * const L, request_st ** const rr)
{
    /* r table
     *
     * r.req_header[]         HTTP request headers
     * r.req_attr[]           HTTP request attributes / components (strings)
     * r.req_item[]           HTTP request items (struct members, statistics)
     * r.req_env[]            HTTP request environment variables
     * r.req_body.*           HTTP request body accessors
     * r.req_body.bytes_in    HTTP request body chunkqueue bytes_in
     * r.req_body.bytes_out   HTTP request body chunkqueue bytes_out
     * r.resp_header[]        HTTP response headers
     * r.resp_body.*          HTTP response body accessors
     * r.resp_body.len        HTTP response body length
     * r.resp_body.add()      HTTP response body add (string or table)
     * r.resp_body.set()      HTTP response body set (string or table)
     * r.resp_body.bytes_in   HTTP response body chunkqueue bytes_in
     * r.resp_body.bytes_out  HTTP response body chunkqueue bytes_out
     */
    lua_createtable(L, 0, 7);                                 /* (sp += 1) */

    /* userdata methods share ptr-ptr to external object userdata rr
     * (similar functionality to that provided w/ luaL_setfuncs() in lua 5.2+)*/
    magnet_request_userdata_method(L, rr, "li.req_header"); /* req_header */
    magnet_request_userdata_method(L, rr, "li.req_attr");   /* req_attr */
    magnet_request_userdata_method(L, rr, "li.req_item");   /* req_item */
    magnet_request_userdata_method(L, rr, "li.req_env");    /* req_env */
    magnet_request_userdata_method(L, rr, "li.resp_header");/* resp_header */
    magnet_request_userdata_method(L, rr, "li.resp_body");  /* resp_body */
    magnet_request_userdata_method(L, rr, "li.req_body");   /* req_body */

    lua_createtable(L, 0, 2); /* metatable for r table           (sp += 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to r           (sp -= 1) */
}

static int
magnet_request_iter (lua_State *L)
{
    /* upvalue 1: (connection *) in linked list
     * upvalue 2: index into hxcon->r[]
     * upvalue 3: request userdata
     * upvalue 4: request table (references r in userdata) */
    connection *con = lua_touserdata(L, lua_upvalueindex(1));

    /* skip over HTTP/2 and HTTP/3 connections with no active requests */
    while (con && con->hx && 0 == con->hx->rused)
        con = con->next;
    if (NULL == con)
        return 0;

    /* set (request_st *)r */
    int32_t i = -1;
    if (con->hx) {
        /* get index into hxcon->r[] */
        i = lua_tointeger(L, lua_upvalueindex(2));
        /* set (request_st *)r in userdata */
        /* step to next index into hxcon->r[] */
        if (-1 == i) {
            *(request_st **)lua_touserdata(L,lua_upvalueindex(3))=&con->request;
            ++i; /*(rused != 0 checked above)*/
        }
        else {
            *(request_st **)lua_touserdata(L,lua_upvalueindex(3))=con->hx->r[i];
            if ((uint32_t)++i == con->hx->rused) i = -1;
        }
        lua_pushinteger(L, i);
        lua_replace(L, lua_upvalueindex(2));
    }
    else {
        /* set (request_st *) in userdata */
        *(request_st **)lua_touserdata(L, lua_upvalueindex(3)) = &con->request;
    }

    if (-1 == i) {
        /* step to next connection */
        con = con->next;
        lua_pushlightuserdata(L, con);
        lua_replace(L, lua_upvalueindex(1));
    }

    /* return request object (which references (request_st *)r in userdata) */
    lua_pushvalue(L, lua_upvalueindex(4));
    return 1;
}

static int
magnet_irequests (lua_State *L)
{
    /* NB: iterator request object *is invalid* outside of iteration
     * For efficiency, r is stored in userdata as upvalue to iteration
     * and is invalid (and may be cleaned up) outside of iterator loop.
     * A C pointer into userdata is stored in iterator request object methods.
     * The iterator request object is *reused* for each iteration loop and the
     * upvalue to the userdata is changed each iteration to point to next r.
     * The iterator request object *must not* be saved for use outside
     * the iteration loop.  Extract data that must be saved and store data
     * in a persistent object if data is to be used outside iterator loop.
     * (Were it desirable to produce a persistent request object for use outside
     *  the iteration loop, a future enhancement would be to add a method such
     *  as lighty.server.irequests_clone(r) which creates a new request object
     *  pointing into a new userdata, and saving that new userdata in the new
     *  request object table as '_r_userdata')
     * NB: iterator request objects should generally be treated read-only.
     * Modifications may in some cases be unsafe and cause lighttpd to crash. */
    request_st *r = magnet_get_request(L);
    lua_pushlightuserdata(L, r->con->srv->conns);
    lua_pushinteger(L, -1);
    request_st ** const r_userdata =
      (request_st **)lua_newuserdata0(L, sizeof(request_st *));
    magnet_request_table(L, r_userdata);
    lua_pushcclosure(L, magnet_request_iter, 4);
    return 1;
}

static int
magnet_server_stats_get (lua_State *L)
{
    size_t klen;
    const char * const k = luaL_checklstring(L, 2, &klen);
    const request_st * const r = magnet_get_request(L);
    const server * const srv = r->con->srv;
    switch (klen) {
      case 6:
        if (0 == memcmp(k, "uptime", 6)) {
            lua_pushinteger(L, (lua_Integer)(log_epoch_secs - srv->startup_ts));
            return 1;
        }
        break;
      case 7:
        if (0 == memcmp(k, "version", 7)) {
            lua_pushlstring(L, BUF_PTR_LEN(srv->default_server_tag));
            return 1;
        }
        break;
      case 12:
        /*(could calculate from irequests: ++count on remote-addr/port change)*/
        if (0 == memcmp(k, "clients_open", 12)) {
            lua_pushinteger(L, (lua_Integer)
                            (srv->srvconf.max_conns - srv->lim_conns));
            return 1;
        }
        break;
      default:
        break;
    }
    return luaL_error(L, "server.stats['%s'] invalid", k);
}


__attribute_cold__
static void
magnet_req_header_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.req_header") == 0)           /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_reqhdr_get);                  /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_reqhdr_set);                  /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_reqhdr_pairs);                /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static void
magnet_req_attr_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.req_attr") == 0)             /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_env_get);                     /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_env_set);                     /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_env_pairs);                   /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static void
magnet_req_item_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.req_item") == 0)             /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_req_item_get);                /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_req_item_set);                /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static void
magnet_req_env_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.req_env") == 0)              /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_envvar_get);                  /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_envvar_set);                  /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_envvar_pairs);                /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static void
magnet_resp_header_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.resp_header") == 0)          /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_resphdr_get);                 /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_resphdr_set);                 /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_resphdr_pairs);               /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static void
magnet_resp_body_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.resp_body") == 0)            /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_respbody);                    /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static void
magnet_req_body_metatable (lua_State * const L)
{
    if (luaL_newmetatable(L, "li.req_body") == 0)             /* (sp += 1) */
        return;

    lua_pushcfunction(L, magnet_reqbody);                     /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
}

__attribute_cold__
static int magnet_atpanic(lua_State *L) {
	request_st * const r = magnet_get_request(L);
	log_error(r->conf.errh, __FILE__, __LINE__, "(lua-atpanic) %s",
	          lua_isstring(L, 1) ? lua_tostring(L, 1) : "");
	/*longjmp(exceptionjmp, 1);*//*(must be init with setjmp() elsewhere)*/
	return 0;
}

__attribute_cold__
static int magnet_print(lua_State *L) {
	const_buffer cb = magnet_checkconstbuffer(L, 1);
	request_st * const r = magnet_get_request(L);
	log_error(r->conf.errh, __FILE__, __LINE__, "(lua-print) %s", cb.ptr);
	return 0;
}

__attribute_cold__
static void
magnet_plugin_stats_table (lua_State * const L)
{
    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 4); /* metatable for plugin_stats      (sp += 1) */
    lua_pushcfunction(L, magnet_plugin_stats_get);            /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_plugin_stats_set);            /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushcfunction(L, magnet_plugin_stats_pairs);          /* (sp += 1) */
    lua_setfield(L, -2, "__pairs");                           /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2);                                  /* (sp -= 1) */
}

__attribute_cold__
static void
magnet_server_stats_table (lua_State * const L)
{
    lua_createtable(L, 0, 0); /* {}                              (sp += 1) */
    lua_createtable(L, 0, 3); /* metatable for stats             (sp += 1) */
    lua_pushcfunction(L, magnet_server_stats_get);            /* (sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2);                                  /* (sp -= 1) */
}

__attribute_cold__
static void
magnet_server_table (lua_State * const L)
{
    lua_createtable(L, 0, 3); /* {}                              (sp += 1) */
    lua_pushcfunction(L, magnet_irequests);                   /* (sp += 1) */
    lua_setfield(L, -2, "irequests"); /* iterate over requests   (sp -= 1) */
    magnet_plugin_stats_table(L);                             /* (sp += 1) */
    lua_setfield(L, -2, "plugin_stats");                      /* (sp -= 1) */
    magnet_server_stats_table(L);                             /* (sp += 1) */
    lua_setfield(L, -2, "stats");                             /* (sp -= 1) */
    lua_createtable(L, 0, 2); /* metatable for server table      (sp += 1) */
    lua_pushcfunction(L, magnet_newindex_readonly);           /* (sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to server      (sp -= 1) */
}

__attribute_cold__
static void
magnet_script_setup_global_state (lua_State * const L)
{
    lua_atpanic(L, magnet_atpanic);

    lua_pushglobaltable(L);                                   /* (sp += 1) */
    /* override default print() function */
    lua_pushcfunction(L, magnet_print);                       /* (sp += 1) */
    lua_setfield(L, -2, "print");                             /* (sp -= 1) */
  #if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
    /* override default pairs() function to our __pairs capable version */
    lua_getglobal(L, "pairs"); /* push original pairs()          (sp += 1) */
    lua_pushcclosure(L, magnet_pairs, 1);            /* (sp -= 1; sp += 1) */
    lua_setfield(L, -2, "pairs");                             /* (sp -= 1) */
  #endif
    lua_pop(L, 1); /* pop global table */                     /* (sp -= 1) */

    magnet_req_header_metatable(L);    /* init for mem locality  (sp += 1) */
    magnet_req_attr_metatable(L);      /* init for mem locality  (sp += 1) */
    magnet_req_item_metatable(L);      /* init for mem locality  (sp += 1) */
    magnet_req_env_metatable(L);       /* init for mem locality  (sp += 1) */
    magnet_resp_header_metatable(L);   /* init for mem locality  (sp += 1) */
    magnet_resp_body_metatable(L);     /* init for mem locality  (sp += 1) */
    magnet_req_body_metatable(L);      /* init for mem locality  (sp += 1) */
    magnet_stat_metatable(L);    /* init table for mem locality  (sp += 1) */
    magnet_readdir_metatable(L); /* init table for mem locality  (sp += 1) */
    lua_pop(L, 9);               /* pop init'd metatables        (sp -= 9) */
}

__attribute_cold__
static void
magnet_init_lighty_table (lua_State * const L, request_st **rr,
                          const int result_ndx)
{
    /* lighty table
     *
     * lighty.r.*                HTTP request object methods
     * lighty.c.*                lighttpd C methods callable from lua
     * lighty.server.*           lighttpd server object methods
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

    magnet_request_table(L, rr); /* lighty.r                     (sp += 1) */
    lua_setfield(L, -2, "r"); /* lighty.r = {}                   (sp -= 1) */

    magnet_server_table(L); /* lighty.server                     (sp += 1) */
    lua_setfield(L, -2, "server"); /* server = {}                (sp -= 1) */

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

    /* alias lighty.server.stats -> lighty.status */
    lua_getfield(L, -1, "server");                            /* (sp += 1) */
    lua_getfield(L, -1, "plugin_stats");                      /* (sp += 1) */
    lua_setfield(L, -3, "status"); /* status = {}                (sp -= 1) */
    lua_pop(L, 1);                                            /* (sp -= 1) */

    lua_pushinteger(L, MAGNET_RESTART_REQUEST);
    lua_setfield(L, -2, "RESTART_REQUEST");

    /* alias lighty.c.stat -> lighty.stat */
    lua_pushcfunction(L, magnet_stat);                        /* (sp += 1) */
    lua_setfield(L, -2, "stat"); /* -1 is the env we want to set (sp -= 1) */

    static const luaL_Reg cmethods[] = {
      { "stat",             magnet_stat }
     ,{ "time",             magnet_time }
     ,{ "hrtime",           magnet_hrtime }
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
     ,{ "header_tokens",    magnet_header_tokens } /* parse header tokens seq */
     ,{ "readdir",          magnet_readdir } /* dir walk */
     ,{ "readlink",         magnet_readlink } /* symlink target */
     ,{ "quoteddec",        magnet_quoteddec } /* quoted-string decode */
     ,{ "quotedenc",        magnet_quotedenc } /* quoted-string encode */
     ,{ "bsdec",            magnet_bsdec } /* backspace-escape decode */
     ,{ "bsenc",            magnet_bsenc_default } /* backspace-escape encode */
     ,{ "bsenc_json",       magnet_bsenc_json } /* backspace-escape encode json */
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

    /* lighty.* table is read-only;
     * provide alternative scratch table for legacy API, historical (mis)use */
    lua_createtable(L, 0, 3); /* metatable for lighty table      (sp += 1) */
    lua_pushvalue(L, result_ndx);                             /* (sp += 1) */
    lua_pushcclosure(L, magnet_lighty_result_get, 1);/* (sp -= 1; sp += 1) */
    lua_setfield(L, -2, "__index");                           /* (sp -= 1) */
    lua_pushvalue(L, result_ndx);                             /* (sp += 1) */
    lua_pushcclosure(L, magnet_lighty_result_set, 1);/* (sp -= 1; sp += 1) */
    lua_setfield(L, -2, "__newindex");                        /* (sp -= 1) */
    lua_pushboolean(L, 0);                                    /* (sp += 1) */
    lua_setfield(L, -2, "__metatable"); /* protect metatable     (sp -= 1) */
    lua_setmetatable(L, -2); /* tie the metatable to lighty      (sp -= 1) */

    /* lighty table (returned on stack) */
}

static void magnet_clear_table(lua_State * const L, int ndx) {
    /*(avoid lua_absindex() func call since expecting empty result tables for
     * legacy interfaces to lighty.header and .content, though not script-env)*/
    /*ndx = lua_absindex(ndx);*//*(lua 5.2+)*/
    if (ndx < 0) --ndx;
    for (lua_pushnil(L); lua_next(L, ndx); ) {
        lua_pop(L, 1);
        lua_pushvalue(L, -1);
        lua_pushnil(L);
        lua_rawset(L, ndx < 0 ? ndx - 2 : ndx);
    }
}

__attribute_cold__
static int magnet_traceback(lua_State *L) {
	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */
	if (lua_getglobal_and_type(L, "debug") != LUA_TTABLE) {
		lua_pop(L, 1);
		return 1;
	}
	if (lua_getfield_and_type(L, -1, "traceback") != LUA_TFUNCTION) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	return 1;
}

__attribute_cold__
__attribute_noinline__
static int
magnet_script_setup (request_st * const r, plugin_config * const pconf, script * const sc)
{
	lua_State * const L = sc->L;
	const int func_ndx = 1;
	if (lua_isfunction(L, func_ndx)) {
		/* initial setup for global lua_State */
		magnet_script_setup_global_state(L);
		/*force_assert(lua_gettop(L) == 1);*/ /* errfunc_ndx = 2 */
		lua_pushcfunction(L, magnet_traceback);/*errfunc*//* (sp += 1) */
		/* create empty table for script environment (reused)
		 *   setmetatable({}, {__index = _G})
		 *     if a function symbol is not defined in our env,
		 *     __index will lookup in the global env. */
		lua_createtable(L, 0, 1); /* env_ndx = 3 */       /* (sp += 1) */
		magnet_mainenv_metatable(L);                      /* (sp += 1) */
		lua_setmetatable(L, -2);                          /* (sp -= 1) */
		/* set script env in first upvalue (_ENV upvalue) for func */
		lua_pushvalue(L, -1);                             /* (sp += 1) */
		magnet_setfenv_mainfn(L, func_ndx);               /* (sp -= 1) */
		/* result table (modifiable) (for mod_magnet legacy API) */
		/* (prefer lighty.r.resp_header(), lighty.r.resp_body()) */
		lua_createtable(L, 0, 2); /* (result_ndx = 4) */  /* (sp += 1) */
		const int result_ndx = 4;
		/* shared userdata (ud_ndx = 5) */
		request_st ** const r_userdata =                  /* (sp += 1) */
		  (request_st **)lua_newuserdata0(L, sizeof(request_st *));
		/* insert lighty table (lighty_table_ndx = 6) */
		magnet_init_lighty_table(L,r_userdata,result_ndx);/* (sp += 1) */
		return 1;
	}
	else {
		if (lua_isstring(L, func_ndx))
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "loading script %s failed: %s", sc->name.ptr,
			  lua_tostring(L, func_ndx));
		else /*(lua_gettop(L) == 0)*/
			log_perror(r->conf.errh, __FILE__, __LINE__,
			  "loading script %s failed", sc->name.ptr);
		lua_settop(L, 0);

		if (pconf->stage >= 0) /*(before response_start)*/
			http_status_set_err(r, 500); /* Internal Server Error */

		return 0;
	}
}

static handler_t
magnet_attract (request_st * const r, plugin_config * const pconf, script * const sc)
{
	lua_State * const L = sc->L;
	const int func_ndx = 1;
	const int errfunc_ndx = 2;
	const int env_ndx = 3;
	const int result_ndx = 4;
	const int ud_ndx = 5;
	const int lighty_table_ndx = 6;

	if (__builtin_expect( (lua_gettop(L) != lighty_table_ndx), 0)) {
		if (!magnet_script_setup(r, pconf, sc))
			return HANDLER_FINISHED;
	}

	/* set r in global state for L for out-of-band access to r
	 * (r-conf.errh and others) */
        magnet_set_request(L, r);
	/* set r in userdata shared by lighty.r object methods */
	*(request_st **)lua_touserdata(L, ud_ndx) = r;

	/* add lighty table to script-env
	 * script-env is cleared at the end of each script run */
	lua_pushvalue(L, lighty_table_ndx);                       /* (sp += 1) */
	lua_setfield(L, env_ndx, "lighty"); /* lighty.*              (sp -= 1) */

	/* push script func; pcall will consume the func value */
	lua_pushvalue(L, func_ndx);                               /* (sp += 1) */
	int ret = lua_pcall(L, 0, 1, errfunc_ndx);       /* (sp -= 1; sp += 1) */

	handler_t result = HANDLER_GO_ON;
	if (0 != ret) {
			size_t errlen;
			const char * const err = lua_tolstring(L, -1, &errlen);
			log_error_multiline(r->conf.errh, __FILE__, __LINE__,
			                    err, errlen, "lua: ");
			/*lua_pop(L, 1);*/ /* pop error msg */ /* defer to later */
			if (pconf->stage >= 0) /*(before response_start)*/
				result = http_status_set_err(r, 500); /* HANDLER_FINISHED */
	}
	else do {
		/*(luaL_optinteger might raise error, which we want to avoid)*/
		/*lua_return_value = (int) luaL_optinteger(L, -1, -1);*/
		int isnum = 1;
		int lua_return_value = lua_isnil(L, -1)
		  ? 0
		  : (int) lua_tointegerx(L, -1, &isnum);
		if (!isnum) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "lua_pcall(): unexpected non-integer return type: %s",
			  luaL_typename(L, -1));
			break;
		}
		/*lua_pop(L, 1);*/ /* pop return value */ /* defer to later */
		/*force_assert(lua_istable(sc->L, -1));*/

		if (lua_getfield_and_type(L, result_ndx, "header") == LUA_TTABLE) {
			magnet_copy_response_header(L, r); /* deprecated legacy API */
		}
		/*lua_pop(L, 1);*//* defer to later */

		if (lua_return_value >= 200) {
			/*(note: body may already have been set via lighty.r.resp_body.*)*/
			if (lua_getfield_and_type(L, result_ndx, "content") == LUA_TTABLE) {
				magnet_attach_content(L, r); /* deprecated legacy API */
			}
			/*lua_pop(L, 1);*//* defer to later */
			if (!chunkqueue_is_empty(&r->write_queue)) {
				r->handler_module = mod_magnet_plugin_data->self;
			}
			http_status_set_fin(r, lua_return_value);
			result = HANDLER_FINISHED;
		} else if (lua_return_value >= 100) {
			/*(skip for response-start; send response as-is w/ added headers)*/
			if (pconf->stage < 0) break;
			/*(custom lua code should not return 101 Switching Protocols)*/
			http_status_set(r, lua_return_value);
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
				buffer_append_char(vb, '0');
			}
			buffer_reset(&r->physical.path);
			r->handler_module = NULL;
			result = HANDLER_COMEBACK;
			if (++*vb->ptr-'0' >= 10) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "too many request restarts (infinite loop?) for %s",
				  sc->name.ptr);
				result = HANDLER_ERROR;
			}
		}
	} while (0);
	magnet_clear_table(L, env_ndx);
	magnet_clear_table(L, result_ndx);
	/* reset stack to reuse stack up to lighty table; pop the excess */
	lua_settop(L, lighty_table_ndx); /*(handle deferred lua_pop()s)*/
	return result;
}

static handler_t magnet_attract_array(request_st * const r, plugin_data * const p, int stage) {
	plugin_config pconf;
	mod_magnet_patch_config(r, p, &pconf);
	pconf.stage = stage;

	script * const *scripts;
	switch (stage) {
	  case  1: scripts = pconf.url_raw; break;
	  case  0: scripts = pconf.physical_path; break;
	  case -1: scripts = pconf.response_start; break;
	  default: scripts = NULL; break;
	}
	if (NULL == scripts) return HANDLER_GO_ON; /* no scripts set */

	/*(always check at least mtime and size to trigger script reload)*/
	const int etag_flags = r->conf.etag_flags | ETAG_USE_MTIME | ETAG_USE_SIZE;
	int req_env_inited = 0;

	/* execute scripts sequentially while HANDLER_GO_ON */
	handler_t rc = HANDLER_GO_ON;
	do {
		script_cache_check_script(*scripts, etag_flags);
		if ((*scripts)->req_env_init && !req_env_inited) {
			/*(request env init is deferred until needed)*/
			req_env_inited = 1;
			r->con->srv->request_env(r);
		}
		rc = magnet_attract(r, &pconf, *scripts);
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

SUBREQUEST_FUNC(mod_magnet_handle_subrequest) {
    /* read entire request body from network and then restart request */
    UNUSED(p_d);

    if (r->state == CON_STATE_READ_POST) {
        /*(streaming flags were removed when magnet installed this handler)*/
        handler_t rc = r->con->reqbody_read(r);
        if (rc != HANDLER_GO_ON) return rc;
        if (r->state == CON_STATE_READ_POST)
            return HANDLER_WAIT_FOR_EVENT;
    }

    buffer_reset(&r->physical.path);
    r->handler_module = NULL;
    return HANDLER_COMEBACK;
}


__attribute_cold__
__declspec_dllexport__
int mod_magnet_plugin_init(plugin *p);
int mod_magnet_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "magnet";

	p->init        = mod_magnet_init;
	p->handle_uri_clean  = mod_magnet_uri_handler;
	p->handle_physical   = mod_magnet_physical;
	p->handle_response_start = mod_magnet_response_start;
	p->handle_subrequest = mod_magnet_handle_subrequest;
	p->set_defaults  = mod_magnet_set_defaults;
	p->cleanup     = mod_magnet_free;

	return 0;
}
