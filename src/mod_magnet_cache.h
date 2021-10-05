#ifndef _MOD_MAGNET_CACHE_H_
#define _MOD_MAGNET_CACHE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

#include <lua.h>

typedef struct {
	buffer name;
	buffer etag;

	lua_State *L;
} script;

typedef struct {
	script **ptr;
	uint32_t used;
	uint32_t size;
} script_cache;

#if 0
__attribute_cold__
__attribute_malloc__
__attribute_returns_nonnull__
script_cache *script_cache_init(void);
#endif

__attribute_cold__
void script_cache_free_data(script_cache *cache);

__attribute_cold__
__attribute_nonnull__()
__attribute_returns_nonnull__
script *script_cache_get_script(script_cache *cache, const buffer *name);

__attribute_nonnull__()
lua_State *script_cache_check_script(script * const sc, int etag_flags);

#endif
