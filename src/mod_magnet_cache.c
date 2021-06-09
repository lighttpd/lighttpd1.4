#include "first.h"

#include "mod_magnet_cache.h"
#include "log.h"
#include "stat_cache.h"

#include "sys-time.h"
#include <stdlib.h>

#include <lualib.h>
#include <lauxlib.h>

__attribute_cold__
static script *script_init(void)
{
    script *const sc = calloc(1, sizeof(*sc));
    force_assert(sc);
    return sc;
}

__attribute_cold__
static void script_free(script *sc)
{
    if (!sc) return;
    lua_pop(sc->L, 1); /* the function copy */
    lua_close(sc->L);
    free(sc->name.ptr);
    free(sc->etag.ptr);
    free(sc);
}

#if 0
script_cache *script_cache_init(void)
{
    script_cache *p = calloc(1, sizeof(script_cache));
    force_assert(p);
    return p;
}
#endif

void script_cache_free_data(script_cache *p)
{
    if (!p) return;
    for (uint32_t i = 0; i < p->used; ++i)
        script_free(p->ptr[i]);
    free(p->ptr);
}

lua_State *script_cache_get_script(script_cache *cache, const buffer *name, int etag_flags)
{
	script *sc = NULL;
	stat_cache_entry *sce;

	for (uint32_t i = 0; i < cache->used; ++i, sc = NULL) {
		sc = cache->ptr[i];
		if (!buffer_is_equal(name, &sc->name)) continue;

			if (lua_gettop(sc->L) == 0) break;
			force_assert(lua_gettop(sc->L) == 1);
			sce = stat_cache_get_entry(&sc->name);
			if (NULL == sce) {
				lua_pop(sc->L, 1); /* pop the old function */
				break;
			}

			const buffer *etag = stat_cache_etag_get(sce, etag_flags);
			if (NULL == etag || !buffer_is_equal(&sc->etag, etag)) {
				/* the etag is outdated, reload the function */
				lua_pop(sc->L, 1);
				break;
			}

			force_assert(lua_isfunction(sc->L, -1));

			return sc->L;
	}

	/* if the script was script already loaded but either got changed or
	 * failed to load last time */
	if (sc == NULL) {
		sc = script_init();

		if (cache->used == cache->size) {
			cache->size += 16;
			cache->ptr = realloc(cache->ptr, cache->size * sizeof(*(cache->ptr)));
		}

		cache->ptr[cache->used++] = sc;

		buffer_copy_buffer(&sc->name, name);

		sc->L = luaL_newstate();
		luaL_openlibs(sc->L);
	}
	buffer_clear(&sc->etag);

	if (0 != luaL_loadfile(sc->L, name->ptr)) {
		/* oops, an error, return it */
		return sc->L;
	}

	sce = stat_cache_get_entry(&sc->name);
	if (sce) {
		const buffer *etag = stat_cache_etag_get(sce, etag_flags);
		if (etag)
			buffer_copy_buffer(&sc->etag, etag);
	}

	force_assert(lua_isfunction(sc->L, -1));

	return sc->L;
}
