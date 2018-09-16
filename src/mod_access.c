#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	array *access_allow;
	array *access_deny;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

INIT_FUNC(mod_access_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	return p;
}

FREE_FUNC(mod_access_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->access_allow);
			array_free(s->access_deny);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_access_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "url.access-deny",             NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
		{ "url.access-allow",            NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },
		{ NULL,                          NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->access_deny    = array_init();
		s->access_allow   = array_init();

		cv[0].destination = s->access_deny;
		cv[1].destination = s->access_allow;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->access_deny)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for url.access-deny; expected list of \"suffix\"");
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->access_allow)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for url.access-allow; expected list of \"suffix\"");
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_access_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(access_allow);
	PATCH(access_deny);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.access-deny"))) {
				PATCH(access_deny);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.access-allow"))) {
				PATCH(access_allow);
			}
		}
	}

	return 0;
}
#undef PATCH

/**
 * URI handler
 *
 * we will get called twice:
 * - after the clean up of the URL and 
 * - after the pathinfo checks are done
 *
 * this handles the issue of trailing slashes
 */
URIHANDLER_FUNC(mod_access_uri_handler) {
	plugin_data *p = p_d;
	const buffer *match;

	if (buffer_is_empty(con->uri.path)) return HANDLER_GO_ON;

	mod_access_patch_connection(srv, con, p);

	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"-- mod_access_uri_handler called");
	}

	match = (!con->conf.force_lowercase_filenames)
	  ? array_match_value_suffix(p->conf.access_allow, con->uri.path)
	  : array_match_value_suffix_nc(p->conf.access_allow, con->uri.path);
	if (match) return HANDLER_GO_ON; /* allowed */

	if (p->conf.access_allow->used) { /* have access_allow but none matched */
		con->http_status = 403;
		con->mode = DIRECT;

		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
				"url denied as failed to match any from access_allow", con->uri.path);
		}

		return HANDLER_FINISHED;
	}

	match = (!con->conf.force_lowercase_filenames)
	  ? array_match_value_suffix(p->conf.access_deny, con->uri.path)
	  : array_match_value_suffix_nc(p->conf.access_deny, con->uri.path);
	if (match) { /* denied */
			con->http_status = 403;
			con->mode = DIRECT;

			if (con->conf.log_request_handling) {
	 			log_error_write(srv, __FILE__, __LINE__, "sb", 
					"url denied as we match:", match);
			}

			return HANDLER_FINISHED;
	}

	return HANDLER_GO_ON;
}


int mod_access_plugin_init(plugin *p);
int mod_access_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("access");

	p->init        = mod_access_init;
	p->set_defaults = mod_access_set_defaults;
	p->handle_uri_clean = mod_access_uri_handler;
	p->handle_subrequest_start  = mod_access_uri_handler;
	p->cleanup     = mod_access_free;

	p->data        = NULL;

	return 0;
}
