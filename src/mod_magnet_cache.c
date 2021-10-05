#include "first.h"

#include "mod_magnet_cache.h"
#include "stat_cache.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>     /* read() */

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

__attribute_cold__
__attribute_noinline__
static lua_State *script_cache_load_script(script * const sc, int etag_flags)
{
    /* read file and use luaL_loadbuffer()
     * eliminate TOC-TOU race w/ independent stat() in stat_cache_get_entry() */

    stat_cache_entry * const sce = stat_cache_get_entry_open(&sc->name, 1);
    buffer_clear(&sc->etag);
    if (NULL == sce || sce->fd < 0) {
        /*(sce->fd < 0 might indicate empty file, which is not a valid script)*/
        if (NULL != sce) errno = EBADF;
        return NULL;
    }
    const buffer * const etag = stat_cache_etag_get(sce, etag_flags);
    if (etag)
        buffer_copy_buffer(&sc->etag, etag);

    const off_t sz = sce->st.st_size;
    char * const buf = malloc(sz);
    force_assert(buf);

    ssize_t rd = 0;
    off_t off = 0;
    do {
        rd = read(sce->fd, buf+off, (size_t)(sz-off));
    } while (rd > 0 ? (off += rd) != sz : rd < 0 && errno == EINTR);
    if (off != sz) { /*(file truncated?)*/
        if (rd >= 0) errno = EIO;
        free(buf);
        return NULL;
    }

    int rc = luaL_loadbuffer(sc->L, buf, (size_t)sz, sc->name.ptr);
    free(buf);

    if (0 != rc) {
        /* oops, an error, return it */
        return sc->L;
    }

    force_assert(lua_isfunction(sc->L, -1));
    return sc->L;
}

__attribute_cold__
__attribute_nonnull__()
__attribute_returns_nonnull__
static script *script_cache_new_script(script_cache * const cache, const buffer * const name)
{
    script * const sc = script_init();

    if (cache->used == cache->size) {
        cache->size += 16;
        cache->ptr = realloc(cache->ptr, cache->size * sizeof(*(cache->ptr)));
        force_assert(cache->ptr);
    }
    cache->ptr[cache->used++] = sc;

    buffer_copy_buffer(&sc->name, name);
    sc->L = luaL_newstate();
    luaL_openlibs(sc->L);
    return sc;
}

script *script_cache_get_script(script_cache *cache, const buffer *name)
{
    for (uint32_t i = 0; i < cache->used; ++i) {
        script * const sc = cache->ptr[i];
        if (buffer_is_equal(&sc->name, name))
            return sc;
    }
    return script_cache_new_script(cache, name);
}

lua_State *script_cache_check_script(script * const sc, int etag_flags)
{
    if (lua_gettop(sc->L) == 0)
        return script_cache_load_script(sc, etag_flags);

    /*force_assert(lua_gettop(sc->L) == 2);*/
    /*force_assert(lua_isfunction(sc->L, -2));*/

    stat_cache_entry * const sce = stat_cache_get_entry(&sc->name);
    if (NULL == sce) {
        lua_pop(sc->L, 2); /* pop the old function and lighty table */
        return script_cache_load_script(sc, etag_flags);
    }

    const buffer * const etag = stat_cache_etag_get(sce, etag_flags);
    if (NULL == etag || !buffer_is_equal(&sc->etag, etag)) {
        if (0 == etag_flags)
            return sc->L;
        /* the etag is outdated, reload the function */
        lua_pop(sc->L, 2); /* pop the old function and lighty table */
        return script_cache_load_script(sc, etag_flags);
    }

    return sc->L;
}
