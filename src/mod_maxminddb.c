/*
 * mod_maxminddb - MaxMind GeoIP2 support for lighttpd
 *
 * Copyright(c) 2019 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
/**
 *
 * Name:
 *     mod_maxminddb.c
 *
 * Description:
 *     MaxMind GeoIP2 module (plugin) for lighttpd.
 *
 *     GeoIP2 country db env's:
 *         GEOIP_COUNTRY_CODE
 *         GEOIP_COUNTRY_NAME
 *
 *     GeoIP2 city db env's:
 *         GEOIP_COUNTRY_CODE
 *         GEOIP_COUNTRY_NAME
 *         GEOIP_CITY_NAME
 *         GEOIP_CITY_LATITUDE
 *         GEOIP_CITY_LONGITUDE
 *
 * Usage (configuration options):
 *     maxminddb.db = <path to the geoip or geocity database>
 *         GeoLite2 database filenames end in ".mmdb"
 *     maxminddb.activate = <enable|disable> : default disabled
 *     maxminddb.env = (
 *         "GEOIP_COUNTRY_CODE"   => "country/iso_code",
 *         "GEOIP_COUNTRY_NAME"   => "country/names/en",
 *         "GEOIP_CITY_NAME"      => "city/names/en",
 *         "GEOIP_CITY_LATITUDE"  => "location/latitude",
 *         "GEOIP_CITY_LONGITUDE" => "location/longitude",
 *     )
 *
 * Installation Instructions:
 *     https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_ModGeoip
 *
 * References:
 *   https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_ModGeoip
 *   http://dev.maxmind.com/geoip/legacy/geolite/
 *   http://dev.maxmind.com/geoip/geoip2/geolite2/
 *   http://dev.maxmind.com/geoip/geoipupdate/
 *
 *   GeoLite2 database format
 *   http://maxmind.github.io/MaxMind-DB/
 *   https://github.com/maxmind/libmaxminddb
 *
 * Note: GeoLite2 databases are free IP geolocation databases comparable to,
 *       but less accurate than, MaxMind’s GeoIP2 databases.
 *       If you are a commercial entity, please consider a subscription to the
 *       more accurate databases to support MaxMind.
 *         http://dev.maxmind.com/geoip/geoip2/downloadable/
 */

#include "first.h"      /* first */
#include "sys-socket.h" /* AF_INET AF_INET6 */
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "buffer.h"
#include "http_header.h"
#include "log.h"
#include "sock_addr.h"

#include "plugin.h"

#include <maxminddb.h>

SETDEFAULTS_FUNC(mod_maxminddb_set_defaults);
INIT_FUNC(mod_maxminddb_init);
FREE_FUNC(mod_maxminddb_free);
REQUEST_FUNC(mod_maxminddb_request_env_handler);
CONNECTION_FUNC(mod_maxminddb_handle_con_close);

__attribute_cold__
__declspec_dllexport__
int mod_maxminddb_plugin_init(plugin *p);
int mod_maxminddb_plugin_init(plugin *p) {
    p->version                   = LIGHTTPD_VERSION_ID;
    p->name                      = "maxminddb";

    p->set_defaults              = mod_maxminddb_set_defaults;
    p->init                      = mod_maxminddb_init;
    p->cleanup                   = mod_maxminddb_free;
    p->handle_request_env        = mod_maxminddb_request_env_handler;
    p->handle_connection_close   = mod_maxminddb_handle_con_close;

    return 0;
}

typedef struct {
    int activate;
    const array *env;
    const char ***cenv;
    struct MMDB_s *mmdb;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

typedef struct {
    const array *env;
    const char ***cenv;
} plugin_config_env;

typedef struct {
  #ifdef HAVE_IPV6
    struct sockaddr_in6 addr;
  #else
    struct sockaddr_in addr;
  #endif
    array *env;
} handler_ctx;

INIT_FUNC(mod_maxminddb_init)
{
    return ck_calloc(1, sizeof(plugin_data));
}


FREE_FUNC(mod_maxminddb_free)
{
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 1: /* maxminddb.db */
                if (cpv->vtype == T_CONFIG_LOCAL && NULL != cpv->v.v) {
                    struct MMDB_s *mmdb;
                    *(struct MMDB_s **)&mmdb = cpv->v.v;
                    MMDB_close(mmdb);
                    free(mmdb);
                }
                break;
              case 2: /* maxminddb.env */
                if (cpv->vtype == T_CONFIG_LOCAL && NULL != cpv->v.v) {
                    plugin_config_env * const pcenv = cpv->v.v;
                    const array * const env = pcenv->env;
                    char ***cenv;
                    *(const char ****)&cenv = pcenv->cenv;
                    for (uint32_t k = 0, cused = env->used; k < cused; ++k)
                        free(cenv[k]);
                    free(cenv);
                }
                break;
              default:
                break;
            }
        }
    }
}


static MMDB_s *
mod_maxminddb_open_db (server *srv, const buffer *db_name)
{
    if (db_name->used < sizeof(".mmdb")
        || 0 != memcmp(db_name->ptr+db_name->used-sizeof(".mmdb"),
                       CONST_STR_LEN(".mmdb"))) {
        log_error(srv->errh, __FILE__, __LINE__,
          "GeoIP database is of unsupported type %s)",
          db_name->ptr);
        return NULL;
    }

    MMDB_s * const mmdb = (MMDB_s *)ck_calloc(1, sizeof(MMDB_s));
    int rc = MMDB_open(db_name->ptr, MMDB_MODE_MMAP, mmdb);
    if (MMDB_SUCCESS == rc)
        return mmdb;

    if (MMDB_IO_ERROR == rc)
        log_perror(srv->errh, __FILE__, __LINE__,
          "failed to open GeoIP2 database (%s)",
          db_name->ptr);
    else
        log_error(srv->errh, __FILE__, __LINE__,
          "failed to open GeoIP2 database (%s): %s",
          db_name->ptr, MMDB_strerror(rc));
    free(mmdb);
    return NULL;
}


static plugin_config_env *
mod_maxminddb_prep_cenv (server *srv, const array * const env)
{
    data_string ** const data = (data_string **)env->data;
    char *** const cenv = ck_calloc(env->used, sizeof(char **));
    for (uint32_t j = 0, used = env->used; j < used; ++j) {
        if (data[j]->type != TYPE_STRING) {
            log_error(srv->errh, __FILE__, __LINE__,
              "maxminddb.env must be a list of strings");
            for (uint32_t k = 0; k < j; ++k) free(cenv[k]);
            free(cenv);
            return NULL;
        }
        buffer *value = &data[j]->value;
        if (buffer_is_blank(value)
            || '/' == value->ptr[0]
            || '/' == value->ptr[buffer_clen(value)-1]) {
            log_error(srv->errh, __FILE__, __LINE__,
              "maxminddb.env must be a list of non-empty "
              "strings and must not begin or end with '/'");
            for (uint32_t k = 0; k < j; ++k) free(cenv[k]);
            free(cenv);
            return NULL;
        }
        /* XXX: should strings be lowercased? */
        unsigned int k = 2;
        for (char *t = value->ptr; (t = strchr(t, '/')); ++t) ++k;
        const char **keys =
          (const char **)(cenv[j] = ck_calloc(k, sizeof(char *)));
        k = 0;
        keys[k] = value->ptr;
        for (char *t = value->ptr; (t = strchr(t, '/')); ) {
            *t = '\0';
            keys[++k] = ++t;
        }
        keys[++k] = NULL;
    }

    plugin_config_env * const pcenv = ck_malloc(sizeof(plugin_config_env));
    pcenv->env = env;
    pcenv->cenv = (const char ***)cenv;
    return pcenv;
}


static void
mod_maxminddb_merge_config_cpv(plugin_config * const pconf,
                               const config_plugin_value_t * const cpv)
{
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* maxminddb.activate */
        pconf->activate = (int)cpv->v.u;
        break;
      case 1: /* maxminddb.db */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->mmdb = cpv->v.v;
        break;
      case 2: /* maxminddb.env */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            plugin_config_env * const pcenv = cpv->v.v;
            pconf->env = pcenv->env;
            pconf->cenv = pcenv->cenv;
        }
        break;
      default:/* should not happen */
        return;
    }
}


static void
mod_maxminddb_merge_config (plugin_config * const pconf,
                            const config_plugin_value_t *cpv)
{
    do {
        mod_maxminddb_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_maxminddb_patch_config (request_st * const r,
                            const plugin_data * const p,
                            plugin_config * const pconf)
{
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_maxminddb_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


SETDEFAULTS_FUNC(mod_maxminddb_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("maxminddb.activate"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("maxminddb.db"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("maxminddb.env"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_maxminddb"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* maxminddb.activate */
                break;
              case 1: /* maxminddb.db */
                if (!buffer_is_blank(cpv->v.b)) {
                    cpv->v.v = mod_maxminddb_open_db(srv, cpv->v.b);
                    if (NULL == cpv->v.v) return HANDLER_ERROR;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              case 2: /* maxminddb.env */
                if (cpv->v.a->used) {
                    cpv->v.v = mod_maxminddb_prep_cenv(srv, cpv->v.a);
                    if (NULL == cpv->v.v) return HANDLER_ERROR;
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
            mod_maxminddb_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


static void
geoip2_env_set (request_st * const r, array * const env,
                const buffer * const kb, MMDB_entry_data_s * const data)
{
    /* GeoIP2 database interfaces return pointers directly into database,
     * and these are valid until the database is closed.
     * However, note that the strings *are not* '\0'-terminated */
    char buf[34];
    if (!data->has_data || 0 == data->offset) return;
    const char *v = buf;
    size_t vlen;
    switch (data->type) {
      case MMDB_DATA_TYPE_UTF8_STRING:
        v = data->utf8_string;
        vlen = data->data_size;
        break;
      case MMDB_DATA_TYPE_BOOLEAN:
        v = data->boolean ? "1" : "0";
        vlen = 1;
        break;
      case MMDB_DATA_TYPE_BYTES:
        v = (const char *)data->bytes;
        vlen = data->data_size;
        break;
      case MMDB_DATA_TYPE_DOUBLE:
        vlen = snprintf(buf, sizeof(buf), "%.5f", data->double_value);
        break;
      case MMDB_DATA_TYPE_FLOAT:
        vlen = snprintf(buf, sizeof(buf), "%.5f", data->float_value);
        break;
      case MMDB_DATA_TYPE_INT32:
        vlen = li_itostrn(buf, sizeof(buf), data->int32);
        break;
      case MMDB_DATA_TYPE_UINT32:
        vlen = li_utostrn(buf, sizeof(buf), data->uint32);
        break;
      case MMDB_DATA_TYPE_UINT16:
        vlen = li_utostrn(buf, sizeof(buf), data->uint16);
        break;
      case MMDB_DATA_TYPE_UINT64:
        /* truncated value on 32-bit unless uintmax_t is 64-bit (long long) */
        vlen = li_utostrn(buf, sizeof(buf), data->uint64);
        break;
      case MMDB_DATA_TYPE_UINT128:
        buf[0] = '0';
        buf[1] = 'x';
       #if MMDB_UINT128_IS_BYTE_ARRAY
        li_tohex_uc(buf+2, sizeof(buf)-2, (char *)data->uint128, 16);
       #else
        li_tohex_uc(buf+2, sizeof(buf)-2, (char *)&data->uint128, 16);
       #endif
        vlen = 34;
        break;
      default: /*(ignore unknown data type)*/
        return;
    }

    http_header_env_set(r, BUF_PTR_LEN(kb), v, vlen);
    if (env)
        array_set_key_value(env, BUF_PTR_LEN(kb), v, vlen);
}


static void
mod_maxminddb_geoip2 (request_st * const r, array * const env,
                      const struct sockaddr * const dst_addr,
                      plugin_config * const pconf)
{
    MMDB_lookup_result_s res;
    MMDB_entry_data_s data;
    int rc;

    res = MMDB_lookup_sockaddr(pconf->mmdb, dst_addr, &rc);
    if (MMDB_SUCCESS != rc || !res.found_entry) return;
    MMDB_entry_s * const entry = &res.entry;

    const data_string ** const names = (const data_string **)pconf->env->data;
    const char *** const cenv = pconf->cenv;
    for (size_t i = 0, used = pconf->env->used; i < used; ++i) {
        if (MMDB_SUCCESS == MMDB_aget_value(entry, &data, cenv[i])
            && data.has_data) {
            geoip2_env_set(r, env, &names[i]->key, &data);
        }
    }
}


REQUEST_FUNC(mod_maxminddb_request_env_handler)
{
    plugin_config pconf;
    plugin_data *p = p_d;
    mod_maxminddb_patch_config(r, p, &pconf);
    /* check mod_maxminddb activated, env fields requested, and db is open */
    if (!pconf.activate || NULL == pconf.env || NULL == pconf.mmdb)
        return HANDLER_GO_ON;

    const sock_addr * const dst_addr = r->dst_addr;

  #if 0
    /* future: if mod_extforward is (future) extended for HTTP/2 and
     * load balancers configured to reuse an HTTP/2 connection for more
     * than one client, then might add a configuration option to bypass
     * allocating and caching the db lookup results in env, even for the
     * initial request env */
    if (!pconf.cache) { /*(not implemented)*/
        const int sa_family = sock_addr_get_family(dst_addr);
        if (sa_family == AF_INET && sa_family == AF_INET6)
            mod_maxminddb_geoip2(r, NULL,
                                 (const struct sockaddr *)dst_addr, &pconf);
        return HANDLER_GO_ON;
    }
  #endif

    handler_ctx ** const hctx = (handler_ctx **)&r->con->plugin_ctx[p->id];

    if (*hctx && sock_addr_is_addr_eq((sock_addr *)&(*hctx)->addr, dst_addr)) {
        const array * const env = (*hctx)->env;
        for (uint32_t i = 0; i < env->used; ++i) {
            /* note: replaces values which may have been set by mod_openssl
             *(when mod_extforward listed after mod_openssl in server.modules)*/
            const data_string * const ds = (data_string *)env->data[i];
            http_header_env_set(r, BUF_PTR_LEN(&ds->key),
                                   BUF_PTR_LEN(&ds->value));
        }
        return HANDLER_GO_ON;
    }

    array *env = NULL;
    if (*hctx && r->http_version <= HTTP_VERSION_1_1) {
        env = (*hctx)->env;
        /*array_reset_data_strings(env);*/ /* reuse string allocations */
        env->used = 0;
    }
    else if ((*hctx) == NULL) {
        (*hctx) = ck_malloc(sizeof(handler_ctx));
        (*hctx)->env = env = array_init(pconf.env->used);
    }

    if (env) { /* then (env == (*hctx)->env) else (env == NULL) */
        const int sa_family = sock_addr_get_family(dst_addr);
        if (sa_family != AF_INET && sa_family != AF_INET6)
            return HANDLER_GO_ON;
        if (sa_family == AF_INET)
            memcpy(&(*hctx)->addr, dst_addr, sizeof(dst_addr->ipv4));
      #ifdef HAVE_IPV6
        else
            memcpy(&(*hctx)->addr, dst_addr, sizeof(dst_addr->ipv6));
      #endif
    }

    mod_maxminddb_geoip2(r, env, (const struct sockaddr *)dst_addr, &pconf);

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_maxminddb_handle_con_close)
{
    handler_ctx **hctx =
      (handler_ctx **)&con->plugin_ctx[((plugin_data *)p_d)->id];
    if (NULL != *hctx) {
        array_free((*hctx)->env);
        free(*hctx);
        *hctx = NULL;
    }

    return HANDLER_GO_ON;
}
