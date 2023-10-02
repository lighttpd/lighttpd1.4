#include "first.h"

#include "mod_magnet_cache.h"
#include "stat_cache.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>     /* strstr() */
#include <unistd.h>     /* lseek() read() */

#include <lualib.h>
#include <lauxlib.h>

__attribute_cold__
__attribute_malloc__
__attribute_returns_nonnull__
static script *script_init(void)
{
    return ck_calloc(1, sizeof(script));
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
    return ck_calloc(1, sizeof(script_cache));
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
    if (NULL == sce || sce->fd < 0 || -1 == lseek(sce->fd, 0, SEEK_SET)) {
        /*(sce->fd < 0 might indicate empty file, which is not a valid script)*/
        if (NULL != sce) errno = EBADF;
        return NULL;
    }
    const buffer * const etag = stat_cache_etag_get(sce, etag_flags);
    if (etag)
        buffer_copy_buffer(&sc->etag, etag);

    const off_t sz = sce->st.st_size;
    char * const buf = ck_malloc(sz+1);

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

    /*(coarse heuristic to detect if script needs req_env initialized)*/
    buf[sz] = '\0'; /* for strstr() */
    sc->req_env_init = (NULL != strstr(buf, "req_env"));

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

    if (!(cache->used & (16-1)))
        ck_realloc_u32((void **)&cache->ptr,cache->used,16,sizeof(*cache->ptr));
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

    /*force_assert(lua_gettop(sc->L) == 4);*/
    /*force_assert(lua_isfunction(sc->L, 1));*/

    stat_cache_entry * const sce = stat_cache_get_entry(&sc->name);
    if (NULL == sce) {
        lua_settop(sc->L, 0); /* pop the old function; clear stack */
        return script_cache_load_script(sc, etag_flags);
    }

    const buffer * const etag = stat_cache_etag_get(sce, etag_flags);
    if (NULL == etag || !buffer_is_equal(&sc->etag, etag)) {
        if (0 == etag_flags)
            return sc->L;
        /* the etag is outdated, reload the function */
        lua_settop(sc->L, 0); /* pop the old function; clear stack */
        return script_cache_load_script(sc, etag_flags);
    }

    return sc->L;
}
