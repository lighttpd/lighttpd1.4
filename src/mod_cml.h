#ifndef _MOD_CACHE_H_
#define _MOD_CACHE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

#include "plugin.h"

#if defined(USE_MEMCACHED)
#include <libmemcached/memcached.h>
#endif

#define plugin_data mod_cache_plugin_data

typedef struct {
    const buffer *ext;
    const buffer *power_magnet;
    /*const buffer *mc_namespace;*//*(unused)*/
  #if defined(USE_MEMCACHED)
    memcached_st *memc;
  #endif
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    buffer basedir;
    buffer baseurl;
    buffer trigger_handler;
} plugin_data;

int cache_parse_lua(request_st *r, plugin_data *p, const buffer *fn);

#endif
