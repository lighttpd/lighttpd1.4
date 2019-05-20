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

SETDEFAULTS_FUNC(mod_maxmind_set_defaults);
INIT_FUNC(mod_maxmind_init);
FREE_FUNC(mod_maxmind_free);
CONNECTION_FUNC(mod_maxmind_request_env_handler);
CONNECTION_FUNC(mod_maxmind_handle_con_close);

int mod_maxminddb_plugin_init(plugin *p);
int mod_maxminddb_plugin_init(plugin *p) {
    p->version                   = LIGHTTPD_VERSION_ID;
    p->name                      = buffer_init_string("maxminddb");

    p->set_defaults              = mod_maxmind_set_defaults;
    p->init                      = mod_maxmind_init;
    p->cleanup                   = mod_maxmind_free;
    p->handle_request_env        = mod_maxmind_request_env_handler;
    p->handle_connection_close   = mod_maxmind_handle_con_close;

    p->data                      = NULL;

    return 0;
}

typedef struct {
    int activate;
    array *env;
    const char ***cenv;
    struct MMDB_s *mmdb;
    buffer *db_name;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    int nconfig;
    plugin_config **config_storage;
} plugin_data;


INIT_FUNC(mod_maxmind_init)
{
    return calloc(1, sizeof(plugin_data));
}


FREE_FUNC(mod_maxmind_free)
{
    plugin_data *p = (plugin_data *)p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (int i = 0; i < p->nconfig; ++i) {
            plugin_config * const s = p->config_storage[i];
            if (!s) continue;
            buffer_free(s->db_name);
            if (s->mmdb) { MMDB_close(s->mmdb); free(s->mmdb); }
            for (size_t k = 0, used = s->env->used; k < used; ++k)
                free(s->cenv[k]);
            free(s->cenv);
            array_free(s->env);
        }
        free(p->config_storage);
    }

    free(p);

    UNUSED(srv);
    return HANDLER_GO_ON;
}


SETDEFAULTS_FUNC(mod_maxmind_set_defaults)
{
    static config_values_t cv[] = {
      { "maxminddb.activate",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },
      { "maxminddb.db",        NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION },
      { "maxminddb.env",       NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_CONNECTION },

      { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = (plugin_data *)p_d;
    const size_t n_context = p->nconfig = srv->config_context->used;
    p->config_storage = calloc(p->nconfig, sizeof(plugin_config *));
    force_assert(p->config_storage);

    for (size_t i = 0; i < n_context; ++i) {
        plugin_config * const s = calloc(1, sizeof(plugin_config));
        force_assert(s);
        p->config_storage[i] = s;
        s->db_name = buffer_init();
        s->env = array_init();

        cv[0].destination = &s->activate;
        cv[1].destination = s->db_name;
        cv[2].destination = s->env;

        array * const ca = ((data_config *)srv->config_context->data[i])->value;
        if (0 != config_insert_values_global(srv, ca, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (!buffer_is_empty(s->db_name)) {

            if (s->db_name->used >= sizeof(".mmdb")
                && 0 == memcmp(s->db_name->ptr+s->db_name->used-sizeof(".mmdb"),
                               CONST_STR_LEN(".mmdb"))) {
                MMDB_s * const mmdb = (MMDB_s *)calloc(1, sizeof(MMDB_s));
                int rc = MMDB_open(s->db_name->ptr, MMDB_MODE_MMAP, mmdb);
                if (MMDB_SUCCESS != rc) {
                    if (MMDB_IO_ERROR == rc)
                        log_perror(srv->errh, __FILE__, __LINE__,
                                   "failed to open GeoIP2 database (%.*s)",
                                   BUFFER_INTLEN_PTR(s->db_name));
                    else
                        log_error(srv->errh, __FILE__, __LINE__,
                                  "failed to open GeoIP2 database (%.*s): %s",
                                  BUFFER_INTLEN_PTR(s->db_name),
                                  MMDB_strerror(rc));
                    free(mmdb);
                    return HANDLER_ERROR;
                }
                s->mmdb = mmdb;
            }
            else {
                log_error(srv->errh, __FILE__, __LINE__,
                          "GeoIP database is of unsupported type %.*s)",
                          BUFFER_INTLEN_PTR(s->db_name));
                return HANDLER_ERROR;
            }
        }

        if (s->env->used) {
            data_string **data = (data_string **)s->env->data;
            s->cenv = calloc(s->env->used, sizeof(char **));
            force_assert(s->cenv);
            for (size_t j = 0, used = s->env->used; j < used; ++j) {
                if (data[j]->type != TYPE_STRING) {
                    log_error(srv->errh, __FILE__, __LINE__,
                              "maxminddb.env must be a list of strings");
                    return HANDLER_ERROR;
                }
                buffer *value = data[j]->value;
                if (buffer_string_is_empty(value)
                    || '/' == value->ptr[0]
                    || '/' == value->ptr[buffer_string_length(value)-1]) {
                    log_error(srv->errh, __FILE__, __LINE__,
                              "maxminddb.env must be a list of non-empty "
                              "strings and must not begin or end with '/'");
                    return HANDLER_ERROR;
                }
                /* XXX: should strings be lowercased? */
                unsigned int k = 2;
                for (char *t = value->ptr; (t = strchr(t, '/')); ++t) ++k;
                const char **keys = s->cenv[j] = calloc(k, sizeof(char *));
                force_assert(keys);
                k = 0;
                keys[k] = value->ptr;
                for (char *t = value->ptr; (t = strchr(t, '/')); ) {
                    *t = '\0';
                    keys[++k] = ++t;
                }
                keys[++k] = NULL;
            }
        }
    }

    return HANDLER_GO_ON;
}


static void
geoip2_env_set (array * const env, const char *k, size_t klen,
                MMDB_entry_data_s *data)
{
    /* GeoIP2 database interfaces return pointers directly into database,
     * and these are valid until the database is closed.
     * However, note that the strings *are not* '\0'-terminated */
    char buf[35];
    if (!data->has_data || 0 == data->offset) return;
    switch (data->type) {
      case MMDB_DATA_TYPE_UTF8_STRING:
        array_set_key_value(env, k, klen, data->utf8_string, data->data_size);
        return;
      case MMDB_DATA_TYPE_BOOLEAN:
        array_set_key_value(env, k, klen, data->boolean ? "1" : "0", 1);
        return;
      case MMDB_DATA_TYPE_BYTES:
        array_set_key_value(env, k, klen,
                            (const char *) data->bytes, data->data_size);
        return;
      case MMDB_DATA_TYPE_DOUBLE:
        array_set_key_value(env, k, klen,
                            buf, snprintf(buf, sizeof(buf), "%.5f",
                                          data->double_value));
        return;
      case MMDB_DATA_TYPE_FLOAT:
        array_set_key_value(env, k, klen,
                            buf, snprintf(buf, sizeof(buf), "%.5f",
                                          data->float_value));
        return;
      case MMDB_DATA_TYPE_INT32:
        li_itostrn(buf, sizeof(buf), data->int32);
        break;
      case MMDB_DATA_TYPE_UINT32:
        li_utostrn(buf, sizeof(buf), data->uint32);
        break;
      case MMDB_DATA_TYPE_UINT16:
        li_utostrn(buf, sizeof(buf), data->uint16);
        break;
      case MMDB_DATA_TYPE_UINT64:
        /* truncated value on 32-bit unless uintmax_t is 64-bit (long long) */
        li_utostrn(buf, sizeof(buf), data->uint64);
        break;
      case MMDB_DATA_TYPE_UINT128:
        buf[0] = '0';
        buf[1] = 'x';
       #if MMDB_UINT128_IS_BYTE_ARRAY
        li_tohex_uc(buf+2, sizeof(buf)-2, (char *)data->uint128, 16);
       #else
        li_tohex_uc(buf+2, sizeof(buf)-2, (char *)&data->uint128, 16);
       #endif
        array_set_key_value(env, k, klen, buf, 34);
        return;
      default: /*(ignore unknown data type)*/
        return;
    }

    array_set_key_value(env, k, klen, buf, strlen(buf)); /*(numerical types)*/
}


static void
mod_maxmind_geoip2 (array * const env, sock_addr *dst_addr,
                    plugin_config *pconf)
{
    MMDB_lookup_result_s res;
    MMDB_entry_data_s data;
    int rc;

    res = MMDB_lookup_sockaddr(pconf->mmdb, (struct sockaddr *)dst_addr, &rc);
    if (MMDB_SUCCESS != rc || !res.found_entry) return;
    MMDB_entry_s * const entry = &res.entry;

    const data_string ** const names = (const data_string **)pconf->env->data;
    const char *** const cenv = pconf->cenv;
    for (size_t i = 0, used = pconf->env->used; i < used; ++i) {
        if (MMDB_SUCCESS == MMDB_aget_value(entry, &data, cenv[i])
            && data.has_data) {
            geoip2_env_set(env, CONST_BUF_LEN(names[i]->key), &data);
        }
    }
}


static void
mod_maxmind_patch_connection (server * const srv,
                              connection * const con,
                              const plugin_data * const p,
                              plugin_config * const pconf)
{
    const plugin_config *s = p->config_storage[0];
    memcpy(pconf, s, sizeof(*s));
    if (1 == p->nconfig)
        return;

    data_config ** const context_data =
      (data_config **)srv->config_context->data;

    s = p->config_storage[1]; /* base config (global context) copied above */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = context_data[i];
        if (!config_check_cond(srv, con, dc))
            continue; /* condition did not match */

        s = p->config_storage[i];

        /* merge config */
        #define PATCH(x) pconf->x = s->x;
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("maxminddb.activate"))) {
                PATCH(activate);
            }
            else if (buffer_is_equal_string(du->key, CONST_STR_LEN("maxminddb.db"))) {
                /*PATCH(db_name);*//*(not used)*/
                PATCH(mmdb);
            }
            else if (buffer_is_equal_string(du->key, CONST_STR_LEN("maxminddb.env"))) {
                PATCH(env);
                PATCH(cenv);
            }
        }
        #undef PATCH
    }
}


CONNECTION_FUNC(mod_maxmind_request_env_handler)
{
    const int sa_family = con->dst_addr.plain.sa_family;
    if (sa_family != AF_INET && sa_family != AF_INET6) return HANDLER_GO_ON;

    plugin_config pconf;
    plugin_data *p = p_d;
    mod_maxmind_patch_connection(srv, con, p, &pconf);
    /* check that mod_maxmind is activated and env fields were requested */
    if (!pconf.activate || 0 == pconf.env->used) return HANDLER_GO_ON;

    array *env = con->plugin_ctx[p->id];
    if (NULL == env) {
        env = con->plugin_ctx[p->id] = array_init();
        if (pconf.mmdb)
            mod_maxmind_geoip2(env, &con->dst_addr, &pconf);
    }

    for (size_t i = 0; i < env->used; ++i) {
        /* note: replaces values which may have been set by mod_openssl
         * (when mod_extforward is listed after mod_openssl in server.modules)*/
        data_string *ds = (data_string *)env->data[i];
        http_header_env_set(con,
                            CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
    }

    return HANDLER_GO_ON;
}


CONNECTION_FUNC(mod_maxmind_handle_con_close)
{
    plugin_data *p = p_d;
    array *env = con->plugin_ctx[p->id];
    UNUSED(srv);
    if (NULL != env) {
        array_free(env);
        con->plugin_ctx[p->id] = NULL;
    }

    return HANDLER_GO_ON;
}
