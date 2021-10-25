#include "first.h"

#include <GeoIP.h>
#include <GeoIPCity.h>

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"
#include "plugin.h"

#include <stdlib.h>
#include <string.h>

/**
 *
 * $mod_geoip.c (v2.0) (13.09.2006 00:29:11)
 *
 * Name:
 * 	mod_geoip.c
 *
 * Description:
 * 	GeoIP module (plugin) for lighttpd.
 *	the module loads a geoip database of type "country" or "city" and
 *	sets new ENV vars based on ip record lookups.
 *
 *	country db env's:
 *		GEOIP_COUNTRY_CODE
 *		GEOIP_COUNTRY_CODE3
 *		GEOIP_COUNTRY_NAME
 *
 *	city db env's:
 *		GEOIP_COUNTRY_CODE
 *		GEOIP_COUNTRY_CODE3
 *		GEOIP_COUNTRY_NAME
 *		GEOIP_CITY_NAME
 *		GEOIP_CITY_POSTAL_CODE
 *		GEOIP_CITY_LATITUDE
 *		GEOIP_CITY_LONG_LATITUDE
 *		GEOIP_CITY_DMA_CODE
 *		GEOIP_CITY_AREA_CODE
 *
 * Usage (configuration options):
 *	geoip.db-filename = <path to the geoip or geocity database>
 *	geoip.memory-cache = <enable|disable> : default disabled
 *		if enabled, mod_geoip will load the database binary file to
 *		memory for very fast lookups. the only penalty is memory usage.
 *
 * Author:
 * 	Ami E. Bizamcher (amix)
 *	duke.amix@gmail.com
 *
 * Note:
 * 	GeoIP Library and API must be installed!
 *
 *
 * Fully-rewritten from original
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */


typedef struct {
    GeoIP *gi;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_geoip_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_geoip_free) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* geoip.db-filename */
                if (cpv->vtype == T_CONFIG_LOCAL && NULL != cpv->v.v)
                    GeoIP_delete(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static int mod_geoip_open_db(server *srv, config_plugin_value_t * const cpv, int mem_cache) {
    /* country db filename is required! */
    if (buffer_is_blank(cpv->v.b)) {
        cpv->v.v = NULL;
        return 1;
    }

    /* let's start cooking */
    const int mode = (mem_cache)
      ? GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE
      : GEOIP_STANDARD | GEOIP_CHECK_CACHE;

    GeoIP *gi = GeoIP_open(cpv->v.b->ptr, mode);
    if (NULL == gi) {
        log_error(srv->errh, __FILE__, __LINE__,
          "failed to open GeoIP database!!!");
        return 0;
    }

    /* is the db supported ? */
    if (   gi->databaseType != GEOIP_COUNTRY_EDITION
        && gi->databaseType != GEOIP_CITY_EDITION_REV0
        && gi->databaseType != GEOIP_CITY_EDITION_REV1) {
        log_error(srv->errh, __FILE__, __LINE__,
          "GeoIP database is of unsupported type!!!");
        GeoIP_delete(gi);
        return 0;
    }

    cpv->vtype = T_CONFIG_LOCAL;
    cpv->v.v = gi;
    return 1;
}

static void mod_geoip_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* geoip.db-filename */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->gi = cpv->v.v;
        break;
      case 1: /* geoip.memory-cache */
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_geoip_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_geoip_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_geoip_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_geoip_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_geoip_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("geoip.db-filename"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("geoip.memory-cache"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_geoip"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        config_plugin_value_t *fn = NULL;
        int mem_cache = 0;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* geoip.db-filename */
                fn = cpv;
                break;
              case 1: /* geoip.memory-cache */
                mem_cache = cpv->v.u;
                break;
              default:/* should not happen */
                break;
            }
        }
        if (fn) {
            if (!mod_geoip_open_db(srv, fn, mem_cache))
                return HANDLER_ERROR;
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_geoip_merge_config(&p->defaults, cpv);
    }

    log_error(srv->errh, __FILE__, __LINE__,
      "Warning: mod_%s is deprecated "
      "and will be removed from a future lighttpd release in early 2022. "
      "https://wiki.lighttpd.net/Docs_ConfigurationOptions#Deprecated",
      p->self->name);

    return HANDLER_GO_ON;
}

static handler_t mod_geoip_query (request_st * const r, plugin_data * const p) {
    GeoIPRecord *gir;
    const char *remote_ip = r->con->dst_addr_buf.ptr;

    if (NULL != http_header_env_get(r, CONST_STR_LEN("GEOIP_COUNTRY_CODE"))) {
        return HANDLER_GO_ON;
    }

    if (p->conf.gi->databaseType == GEOIP_COUNTRY_EDITION) {
        const char *returnedCountry;

        if (NULL != (returnedCountry = GeoIP_country_code_by_addr(p->conf.gi, remote_ip))) {
            http_header_env_set(r, CONST_STR_LEN("GEOIP_COUNTRY_CODE"), returnedCountry, strlen(returnedCountry));
        }

        if (NULL != (returnedCountry = GeoIP_country_code3_by_addr(p->conf.gi, remote_ip))) {
            http_header_env_set(r, CONST_STR_LEN("GEOIP_COUNTRY_CODE3"), returnedCountry, strlen(returnedCountry));
        }

        if (NULL != (returnedCountry = GeoIP_country_name_by_addr(p->conf.gi, remote_ip))) {
            http_header_env_set(r, CONST_STR_LEN("GEOIP_COUNTRY_NAME"), returnedCountry, strlen(returnedCountry));
        }

        return HANDLER_GO_ON;
    }

    /* if we are here, geo city is in use */

    if (NULL != (gir = GeoIP_record_by_addr(p->conf.gi, remote_ip))) {

        http_header_env_set(r, CONST_STR_LEN("GEOIP_COUNTRY_CODE"), gir->country_code, strlen(gir->country_code));
        http_header_env_set(r, CONST_STR_LEN("GEOIP_COUNTRY_CODE3"), gir->country_code3, strlen(gir->country_code3));
        http_header_env_set(r, CONST_STR_LEN("GEOIP_COUNTRY_NAME"), gir->country_name, strlen(gir->country_name));
        http_header_env_set(r, CONST_STR_LEN("GEOIP_CITY_REGION"), gir->region, strlen(gir->region));
        http_header_env_set(r, CONST_STR_LEN("GEOIP_CITY_NAME"), gir->city, strlen(gir->city));
        http_header_env_set(r, CONST_STR_LEN("GEOIP_CITY_POSTAL_CODE"), gir->postal_code, strlen(gir->postal_code));

        buffer_append_int(http_header_env_set_ptr(r, CONST_STR_LEN("GEOIP_CITY_DMA_CODE")), (intmax_t)gir->dma_code);
        buffer_append_int(http_header_env_set_ptr(r, CONST_STR_LEN("GEOIP_CITY_AREA_CODE")), (intmax_t)gir->area_code);

        {
            char latitude[32];
            snprintf(latitude, sizeof(latitude), "%f", gir->latitude);
            http_header_env_set(r, CONST_STR_LEN("GEOIP_CITY_LATITUDE"), latitude, strlen(latitude));
        }

        {
            char long_latitude[32];
            snprintf(long_latitude, sizeof(long_latitude), "%f", gir->longitude);
            http_header_env_set(r, CONST_STR_LEN("GEOIP_CITY_LONG_LATITUDE"), long_latitude, strlen(long_latitude));
        }

        GeoIPRecord_delete(gir);
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_geoip_handle_request_env) {
    plugin_data *p = p_d;
    mod_geoip_patch_config(r, p);
    return (p->conf.gi) ? mod_geoip_query(r, p) : HANDLER_GO_ON;
}


int mod_geoip_plugin_init(plugin *p);
int mod_geoip_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "geoip";

	p->init        = mod_geoip_init;
	p->handle_request_env = mod_geoip_handle_request_env;
	p->set_defaults  = mod_geoip_set_defaults;
	p->cleanup     = mod_geoip_free;

	return 0;
}
