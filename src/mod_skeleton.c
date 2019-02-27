#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "plugin.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "array.h"

/**
 * this is a skeleton for a lighttpd plugin
 *
 * just replaces every occurrence of 'skeleton' by your plugin name
 *
 * e.g. in vim:
 *
 *   :%s/skeleton/myhandler/
 *
 */


/* plugin config for all request/connections */

typedef struct {
	array *match;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;


#if 0 /* (needed if module keeps state for request) */

typedef struct {
	size_t foo;
} handler_ctx;

static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx = calloc(1, sizeof(*hctx));
	force_assert(hctx);
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	free(hctx);
}

#endif


/* init the plugin data */
INIT_FUNC(mod_skeleton_init) {
	return calloc(1, sizeof(plugin_data));
}

/* destroy the plugin data */
FREE_FUNC(mod_skeleton_free) {
	plugin_data *p = p_d;
	UNUSED(srv);
	if (!p) return HANDLER_GO_ON;
	if (p->config_storage) {
		for (size_t i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			if (NULL == s) continue;
			array_free(s->match);
			free(s);
		}
		free(p->config_storage);
	}
	free(p);
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */
SETDEFAULTS_FUNC(mod_skeleton_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "skeleton.array",             NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));
	force_assert(p->config_storage);

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s = calloc(1, sizeof(plugin_config));
		force_assert(s);
		s->match    = array_init();

		cv[0].destination = s->match;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->match)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for skeleton.array; expected list of \"urlpath\"");
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_skeleton_patch_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];

	PATCH(match);

	/* skip the first, the global context */
	for (size_t i = 1; i < srv->config_context->used; ++i) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (size_t j = 0; j < dc->value->used; ++j) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("skeleton.array"))) {
				PATCH(match);
			}
		}
	}

	return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_skeleton_uri_handler) {
	plugin_data *p = p_d;
	UNUSED(srv);

	/* determine whether or not module participates in request */

	if (con->mode != DIRECT) return HANDLER_GO_ON;
	if (buffer_string_is_empty(con->uri.path)) return HANDLER_GO_ON;

	/* get module config for request */
	mod_skeleton_patch_connection(srv, con, p);

	if (NULL == array_match_value_suffix(p->conf.match, con->uri.path)) {
		return HANDLER_GO_ON;
	}

	/* module participates in request; business logic here */

	con->http_status = 403; /* example: reject request with 403 Forbidden */
	return HANDLER_FINISHED;
}

/* this function is called at dlopen() time and inits the callbacks */
int mod_skeleton_plugin_init(plugin *p);
int mod_skeleton_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("skeleton");
	p->data        = NULL;
	p->init        = mod_skeleton_init;
	p->cleanup     = mod_skeleton_free;
	p->set_defaults= mod_skeleton_set_defaults;

	p->handle_uri_clean = mod_skeleton_uri_handler;

	return 0;
}
