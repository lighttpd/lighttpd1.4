#ifndef _MOD_MAGNET_CACHE_H_
#define _MOD_MAGNET_CACHE_H_

#include "buffer.h"
#include "base.h"

#ifdef HAVE_LUA_H
#include <lua.h>
#endif


typedef struct {
	buffer *name;
	buffer *etag;

#ifdef HAVE_LUA_H
	lua_State *L;
#endif

	time_t last_used; /* LRU */
} script;

typedef struct {
	script **ptr;

	size_t used;
	size_t size;
} script_cache;

script_cache *script_cache_init(void);
void script_cache_free(script_cache *cache);

lua_State *script_cache_get_script(server *srv, connection *con,
	       	script_cache *cache, buffer *name);

#endif
