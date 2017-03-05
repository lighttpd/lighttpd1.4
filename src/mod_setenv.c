#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "response.h"

#include <stdlib.h>
#include <string.h>

/* plugin config for all request/connections */

typedef struct {
	array *request_header;
	array *set_request_header;
	array *response_header;
	array *set_response_header;
	array *environment;
	array *set_environment;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

typedef struct {
	int handled; /* make sure that we only apply the headers once */
	plugin_config conf;
} handler_ctx;

static handler_ctx * handler_ctx_init(void) {
	handler_ctx * hctx;

	hctx = calloc(1, sizeof(*hctx));

	hctx->handled = 0;

	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	free(hctx);
}


/* init the plugin data */
INIT_FUNC(mod_setenv_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_setenv_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->request_header);
			array_free(s->response_header);
			array_free(s->environment);
			array_free(s->set_request_header);
			array_free(s->set_response_header);
			array_free(s->set_environment);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_setenv_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "setenv.add-request-header",  NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "setenv.add-response-header", NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "setenv.add-environment",     NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ "setenv.set-request-header",  NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 3 */
		{ "setenv.set-response-header", NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 4 */
		{ "setenv.set-environment",     NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 5 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->request_header   = array_init();
		s->response_header  = array_init();
		s->environment      = array_init();
		s->set_request_header  = array_init();
		s->set_response_header = array_init();
		s->set_environment     = array_init();

		cv[0].destination = s->request_header;
		cv[1].destination = s->response_header;
		cv[2].destination = s->environment;
		cv[3].destination = s->set_request_header;
		cv[4].destination = s->set_response_header;
		cv[5].destination = s->set_environment;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (   !array_is_kvstring(s->request_header)
		    || !array_is_kvstring(s->response_header)
		    || !array_is_kvstring(s->environment)
		    || !array_is_kvstring(s->set_request_header)
		    || !array_is_kvstring(s->set_response_header)
		    || !array_is_kvstring(s->set_environment)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for setenv.xxxxxx; expected list of \"envvar\" => \"value\"");
			return HANDLER_ERROR;
		}

	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_setenv_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(request_header);
	PATCH(set_request_header);
	PATCH(response_header);
	PATCH(set_response_header);
	PATCH(environment);
	PATCH(set_environment);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("setenv.add-request-header"))) {
				PATCH(request_header);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("setenv.set-request-header"))) {
				PATCH(set_request_header);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("setenv.add-response-header"))) {
				PATCH(response_header);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("setenv.set-response-header"))) {
				PATCH(set_response_header);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("setenv.add-environment"))) {
				PATCH(environment);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("setenv.set-environment"))) {
				PATCH(set_environment);
			}
		}
	}

	return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_setenv_uri_handler) {
	plugin_data *p = p_d;
	size_t k;
	handler_ctx *hctx;

	if (con->plugin_ctx[p->id]) {
		hctx = con->plugin_ctx[p->id];
	} else {
		hctx = handler_ctx_init();

		con->plugin_ctx[p->id] = hctx;
	}

	if (hctx->handled) {
		return HANDLER_GO_ON;
	}

	hctx->handled = 1;

	mod_setenv_patch_connection(srv, con, p);
	memcpy(&hctx->conf, &p->conf, sizeof(plugin_config));

	for (k = 0; k < p->conf.request_header->used; k++) {
		data_string *ds = (data_string *)p->conf.request_header->data[k];
		data_string *ds_dst;

		if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
			ds_dst = data_string_init();
		}

		buffer_copy_buffer(ds_dst->key, ds->key);
		buffer_copy_buffer(ds_dst->value, ds->value);

		array_insert_unique(con->request.headers, (data_unset *)ds_dst);
	}

	for (k = 0; k < hctx->conf.set_request_header->used; ++k) {
		data_string *ds = (data_string *)hctx->conf.set_request_header->data[k];
		array_set_key_value(con->request.headers, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
	}

	return HANDLER_GO_ON;
}

CONNECTION_FUNC(mod_setenv_handle_request_env) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	if (NULL == hctx) return HANDLER_GO_ON;
	if (hctx->handled > 1) return HANDLER_GO_ON;
	hctx->handled = 2;
	UNUSED(srv);

	for (size_t k = 0; k < hctx->conf.environment->used; ++k) {
		data_string *ds = (data_string *)hctx->conf.environment->data[k];
		data_string *ds_dst;

		if (NULL == (ds_dst = (data_string *)array_get_unused_element(con->environment, TYPE_STRING))) {
			ds_dst = data_string_init();
		}

		buffer_copy_buffer(ds_dst->key, ds->key);
		buffer_copy_buffer(ds_dst->value, ds->value);

		array_insert_unique(con->environment, (data_unset *)ds_dst);
	}

	for (size_t k = 0; k < hctx->conf.set_environment->used; ++k) {
		data_string *ds = (data_string *)hctx->conf.set_environment->data[k];
		array_set_key_value(con->environment, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
	}

	return HANDLER_GO_ON;
}

CONNECTION_FUNC(mod_setenv_handle_response_start) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	if (NULL == hctx) return HANDLER_GO_ON;

	for (size_t k = 0; k < hctx->conf.response_header->used; ++k) {
		data_string *ds = (data_string *)hctx->conf.response_header->data[k];
		response_header_insert(srv, con, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
	}

	for (size_t k = 0; k < hctx->conf.set_response_header->used; ++k) {
		data_string *ds = (data_string *)hctx->conf.set_response_header->data[k];
		response_header_overwrite(srv, con, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
	}

	return HANDLER_GO_ON;
}

CONNECTION_FUNC(mod_setenv_reset) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (con->plugin_ctx[p->id]) {
		handler_ctx_free(con->plugin_ctx[p->id]);
		con->plugin_ctx[p->id] = NULL;
	}

	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_setenv_plugin_init(plugin *p);
int mod_setenv_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("setenv");

	p->init        = mod_setenv_init;
	p->handle_uri_clean  = mod_setenv_uri_handler;
	p->handle_request_env    = mod_setenv_handle_request_env;
	p->handle_response_start = mod_setenv_handle_response_start;
	p->set_defaults  = mod_setenv_set_defaults;
	p->cleanup     = mod_setenv_free;

	p->connection_reset  = mod_setenv_reset;

	p->data        = NULL;

	return 0;
}
