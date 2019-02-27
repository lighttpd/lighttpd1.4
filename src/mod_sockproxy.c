#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "gw_backend.h"
typedef gw_plugin_config plugin_config;
typedef gw_plugin_data   plugin_data;
typedef gw_handler_ctx   handler_ctx;

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"
#include "status_counter.h"

/**
 *
 * socket proxy (with optional buffering)
 *
 */

SETDEFAULTS_FUNC(mod_sockproxy_set_defaults) {
	plugin_data *p = p_d;
	data_unset *du;
	size_t i = 0;

	config_values_t cv[] = {
		{ "sockproxy.server",          NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "sockproxy.debug",           NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "sockproxy.balance",         NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));
	force_assert(p->config_storage);

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		force_assert(s);
		s->exts          = NULL;
		s->exts_auth     = NULL;
		s->exts_resp     = NULL;
		s->debug         = 0;

		cv[0].destination = NULL; /* T_CONFIG_LOCAL */
		cv[1].destination = &(s->debug);
		cv[2].destination = NULL; /* T_CONFIG_LOCAL */

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		du = array_get_element(config->value, "sockproxy.server");
		if (!gw_set_defaults_backend(srv, (gw_plugin_data *)p, du, i, 0)) {
			return HANDLER_ERROR;
		}

		du = array_get_element(config->value, "sockproxy.balance");
		if (!gw_set_defaults_balance(srv, s, du)) {
			return HANDLER_ERROR;
		}

		/* disable check-local for all exts (default enabled) */
		if (s->exts) { /*(check after gw_set_defaults_backend())*/
			for (size_t j = 0; j < s->exts->used; ++j) {
				gw_extension *ex = s->exts->exts[j];
				for (size_t n = 0; n < ex->used; ++n) {
					ex->hosts[n]->check_local = 0;
				}
			}
		}
	}

	return HANDLER_GO_ON;
}


static handler_t sockproxy_create_env_connect(server *srv, handler_ctx *hctx) {
	connection *con = hctx->remote_conn;
	con->file_started = 1;
	gw_set_transparent(srv, hctx);
	http_response_upgrade_read_body_unknown(srv, con);

	status_counter_inc(srv, CONST_STR_LEN("sockproxy.requests"));
	return HANDLER_GO_ON;
}


#define PATCH(x) \
	p->conf.x = s->x;
static int mod_sockproxy_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(exts);
	PATCH(exts_auth);
	PATCH(exts_resp);
	PATCH(debug);
	PATCH(ext_mapping);
	PATCH(balance);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("sockproxy.server"))) {
				PATCH(exts);
				PATCH(exts_auth);
				PATCH(exts_resp);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("sockproxy.debug"))) {
				PATCH(debug);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("sockproxy.balance"))) {
				PATCH(balance);
			}
		}
	}

	return 0;
}
#undef PATCH

static handler_t mod_sockproxy_connection_accept(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	handler_t rc;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	mod_sockproxy_patch_connection(srv, con, p);
	if (NULL == p->conf.exts) return HANDLER_GO_ON;

	/*(fake con->uri.path for matching purposes in gw_check_extension())*/
	buffer_copy_string_len(con->uri.path, CONST_STR_LEN("/"));

	rc = gw_check_extension(srv, con, p, 1, 0);
	if (HANDLER_GO_ON != rc) return rc;

	if (con->mode == p->id) {
		handler_ctx *hctx = con->plugin_ctx[p->id];
		hctx->opts.backend = BACKEND_PROXY;
		hctx->create_env = sockproxy_create_env_connect;
		hctx->response = chunk_buffer_acquire();
		con->http_status = -1; /*(skip HTTP processing)*/
	}

	return HANDLER_GO_ON;
}


int mod_sockproxy_plugin_init(plugin *p);
int mod_sockproxy_plugin_init(plugin *p) {
	p->version      = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("sockproxy");

	p->init         = gw_init;
	p->cleanup      = gw_free;
	p->set_defaults = mod_sockproxy_set_defaults;
	p->connection_reset        = gw_connection_reset;
	p->handle_connection_accept= mod_sockproxy_connection_accept;
	p->handle_subrequest       = gw_handle_subrequest;
	p->handle_trigger          = gw_handle_trigger;
	p->handle_waitpid          = gw_handle_waitpid_cb;

	p->data         = NULL;

	return 0;
}
