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
 */


/* plugin config for all request/connections */

typedef struct {
	unsigned short mem_cache;
	buffer	*db_name;
	GeoIP   *gi;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_geoip_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	return p;
}

/* destroy the plugin data */
FREE_FUNC(mod_geoip_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;

			buffer_free(s->db_name);

			/* clean up */
			if (s->gi) GeoIP_delete(s->gi);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_geoip_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "geoip.db-filename",	NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },	/* 0 */
		{ "geoip.memory-cache",	NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },    /* 1 */
		{ NULL,			NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;
		int mode;

		s = calloc(1, sizeof(plugin_config));

		s->db_name = buffer_init();
		s->mem_cache = 0; /* default: do not load db to cache */
		s->gi = NULL;

		cv[0].destination = s->db_name;
		cv[1].destination = &(s->mem_cache);

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		mode = GEOIP_STANDARD | GEOIP_CHECK_CACHE;

		/* country db filename is requeried! */
		if (!buffer_is_empty(s->db_name)) {

			/* let's start cooking */
			if (s->mem_cache != 0)
				mode = GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE;

			if (NULL == (s->gi = GeoIP_open(s->db_name->ptr, mode))) {
				log_error_write(srv, __FILE__, __LINE__, "s",
					"failed to open GeoIP database!!!");

				return HANDLER_ERROR;
			}

			/* is the db supported ? */
			if (s->gi->databaseType != GEOIP_COUNTRY_EDITION &&
				s->gi->databaseType != GEOIP_CITY_EDITION_REV0 &&
				s->gi->databaseType != GEOIP_CITY_EDITION_REV1) {
				log_error_write(srv, __FILE__, __LINE__, "s",
					"GeoIP database is of unsupported type!!!");
			}
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_geoip_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(db_name);
	PATCH(mem_cache);
	PATCH(gi);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("geoip.db-filename"))) {
				PATCH(db_name);
			}

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("geoip.memory-cache"))) {
				PATCH(mem_cache);
			}
		}
	}

	return 0;
}
#undef PATCH

static handler_t mod_geoip_query (connection *con, plugin_data *p) {
    GeoIPRecord *gir;
    const char *remote_ip = con->dst_addr_buf->ptr;

    if (NULL != http_header_env_get(con, CONST_STR_LEN("GEOIP_COUNTRY_CODE"))) {
        return HANDLER_GO_ON;
    }

    if (p->conf.gi->databaseType == GEOIP_COUNTRY_EDITION) {
        const char *returnedCountry;

        if (NULL != (returnedCountry = GeoIP_country_code_by_addr(p->conf.gi, remote_ip))) {
            http_header_env_set(con, CONST_STR_LEN("GEOIP_COUNTRY_CODE"), returnedCountry, strlen(returnedCountry));
        }

        if (NULL != (returnedCountry = GeoIP_country_code3_by_addr(p->conf.gi, remote_ip))) {
            http_header_env_set(con, CONST_STR_LEN("GEOIP_COUNTRY_CODE3"), returnedCountry, strlen(returnedCountry));
        }

        if (NULL != (returnedCountry = GeoIP_country_name_by_addr(p->conf.gi, remote_ip))) {
            http_header_env_set(con, CONST_STR_LEN("GEOIP_COUNTRY_NAME"), returnedCountry, strlen(returnedCountry));
        }

        return HANDLER_GO_ON;
    }

    /* if we are here, geo city is in use */

    if (NULL != (gir = GeoIP_record_by_addr(p->conf.gi, remote_ip))) {

        http_header_env_set(con, CONST_STR_LEN("GEOIP_COUNTRY_CODE"), gir->country_code, strlen(gir->country_code));
        http_header_env_set(con, CONST_STR_LEN("GEOIP_COUNTRY_CODE3"), gir->country_code3, strlen(gir->country_code3));
        http_header_env_set(con, CONST_STR_LEN("GEOIP_COUNTRY_NAME"), gir->country_name, strlen(gir->country_name));
        http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_REGION"), gir->region, strlen(gir->region));
        http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_NAME"), gir->city, strlen(gir->city));
        http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_POSTAL_CODE"), gir->postal_code, strlen(gir->postal_code));

        {
            char latitude[32];
            snprintf(latitude, sizeof(latitude), "%f", gir->latitude);
            http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_LATITUDE"), latitude, strlen(latitude));
        }

        {
            char long_latitude[32];
            snprintf(long_latitude, sizeof(long_latitude), "%f", gir->longitude);
            http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_LONG_LATITUDE"), long_latitude, strlen(long_latitude));
        }

        {
            char dc[LI_ITOSTRING_LENGTH];
            li_utostrn(dc, sizeof(dc), gir->dma_code);
            http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_DMA_CODE"), dc, strlen(dc));
        }

        {
            char ac[LI_ITOSTRING_LENGTH];
            li_utostrn(ac, sizeof(ac), gir->area_code);
            http_header_env_set(con, CONST_STR_LEN("GEOIP_CITY_AREA_CODE"), ac, strlen(ac));
        }

        GeoIPRecord_delete(gir);
    }

    return HANDLER_GO_ON;
}

CONNECTION_FUNC(mod_geoip_handle_request_env) {
	plugin_data *p = p_d;
	mod_geoip_patch_connection(srv, con, p);
	if (buffer_is_empty(p->conf.db_name)) return HANDLER_GO_ON;

	return mod_geoip_query(con, p);
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_geoip_plugin_init(plugin *p);
int mod_geoip_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("geoip");

	p->init        = mod_geoip_init;
	p->handle_request_env = mod_geoip_handle_request_env;
	p->set_defaults  = mod_geoip_set_defaults;
	p->cleanup     = mod_geoip_free;

	p->data        = NULL;

	return 0;
}
