#include "first.h"

#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "gw_backend.h"
typedef gw_plugin_config plugin_config;
typedef gw_plugin_data   plugin_data;
typedef gw_handler_ctx   handler_ctx;

#include "base.h"
#include "buffer.h"
#include "log.h"
#include "plugin.h"
#include "status_counter.h"

#include "sys-endian.h"

enum { LI_PROTOCOL_SCGI, LI_PROTOCOL_UWSGI };

SETDEFAULTS_FUNC(mod_scgi_set_defaults) {
	plugin_data *p = p_d;
	data_unset *du;
	size_t i = 0;

	config_values_t cv[] = {
		{ "scgi.server",              NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "scgi.debug",               NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "scgi.protocol",            NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ "scgi.map-extensions",      NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 3 */
		{ "scgi.balance",             NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 4 */
		{ NULL,                       NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));
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
		s->proto         = LI_PROTOCOL_SCGI;
		s->ext_mapping   = array_init();

		cv[0].destination = s->exts; /* not used; T_CONFIG_LOCAL */
		cv[1].destination = &(s->debug);
		cv[2].destination = NULL;    /* not used; T_CONFIG_LOCAL */
		cv[3].destination = s->ext_mapping;
		cv[4].destination = NULL;    /* not used; T_CONFIG_LOCAL */

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		du = array_get_element(config->value, "scgi.server");
		if (!gw_set_defaults_backend(srv, p, du, i, 1)) {
			return HANDLER_ERROR;
		}

		du = array_get_element(config->value, "scgi.balance");
		if (!gw_set_defaults_balance(srv, s, du)) {
			return HANDLER_ERROR;
		}

		if (NULL != (du = array_get_element(config->value, "scgi.protocol"))) {
			data_string *ds = (data_string *)du;
			if (du->type == TYPE_STRING
			    && buffer_is_equal_string(ds->value, CONST_STR_LEN("scgi"))) {
				s->proto = LI_PROTOCOL_SCGI;
			} else if (du->type == TYPE_STRING
			           && buffer_is_equal_string(ds->value, CONST_STR_LEN("uwsgi"))) {
				s->proto = LI_PROTOCOL_UWSGI;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sss",
						"unexpected type for key: ", "scgi.protocol", "expected \"scgi\" or \"uwsgi\"");

				return HANDLER_ERROR;
			}
		}
	}

	return HANDLER_GO_ON;
}

static int scgi_env_add_scgi(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	buffer *env = venv;
	size_t len;

	if (!key || !val) return -1;

	len = key_len + val_len + 2;

	buffer_string_prepare_append(env, len);

	buffer_append_string_len(env, key, key_len);
	buffer_append_string_len(env, "", 1);
	buffer_append_string_len(env, val, val_len);
	buffer_append_string_len(env, "", 1);

	return 0;
}


#ifdef __LITTLE_ENDIAN__
#define uwsgi_htole16(x) (x)
#else /* __BIG_ENDIAN__ */
#define uwsgi_htole16(x) ((uint16_t) (((x) & 0xff) << 8 | ((x) & 0xff00) >> 8))
#endif


static int scgi_env_add_uwsgi(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	buffer *env = venv;
	size_t len;
	uint16_t uwlen;

	if (!key || !val) return -1;
	if (key_len > USHRT_MAX || val_len > USHRT_MAX) return -1;

	len = 2 + key_len + 2 + val_len;

	buffer_string_prepare_append(env, len);

	uwlen = uwsgi_htole16((uint16_t)key_len);
	buffer_append_string_len(env, (char *)&uwlen, 2);
	buffer_append_string_len(env, key, key_len);
	uwlen = uwsgi_htole16((uint16_t)val_len);
	buffer_append_string_len(env, (char *)&uwlen, 2);
	buffer_append_string_len(env, val, val_len);

	return 0;
}


static handler_t scgi_create_env(server *srv, handler_ctx *hctx) {
	buffer *b;

	buffer *scgi_env = buffer_init();
	gw_host *host = hctx->host;

	connection *con   = hctx->remote_conn;

	http_cgi_opts opts = { 0, 0, host->docroot, NULL };

	http_cgi_header_append_cb scgi_env_add = hctx->conf.proto == LI_PROTOCOL_SCGI
	  ? scgi_env_add_scgi
	  : scgi_env_add_uwsgi;

	buffer_string_prepare_copy(scgi_env, 1023);

	if (0 != http_cgi_headers(srv, con, &opts, scgi_env_add, scgi_env)) {
		buffer_free(scgi_env);
		con->http_status = 400;
		return HANDLER_FINISHED;
	}

	if (hctx->conf.proto == LI_PROTOCOL_SCGI) {
		scgi_env_add(scgi_env, CONST_STR_LEN("SCGI"), CONST_STR_LEN("1"));
		b = buffer_init();
		buffer_append_int(b, buffer_string_length(scgi_env));
		buffer_append_string_len(b, CONST_STR_LEN(":"));
		buffer_append_string_buffer(b, scgi_env);
		buffer_append_string_len(b, CONST_STR_LEN(","));
		buffer_free(scgi_env);
	} else { /* LI_PROTOCOL_UWSGI */
		/* http://uwsgi-docs.readthedocs.io/en/latest/Protocol.html */
		size_t len = buffer_string_length(scgi_env);
		uint32_t uwsgi_header;
		if (len > USHRT_MAX) {
			buffer_free(scgi_env);
			con->http_status = 431; /* Request Header Fields Too Large */
			con->mode = DIRECT;
			return HANDLER_FINISHED;
		}
		b = buffer_init();
		buffer_string_prepare_copy(b, 4 + len);
		uwsgi_header = ((uint32_t)uwsgi_htole16((uint16_t)len)) << 8;
		memcpy(b->ptr, (char *)&uwsgi_header, 4);
		buffer_commit(b, 4);
		buffer_append_string_buffer(b, scgi_env);
		buffer_free(scgi_env);
	}

	hctx->wb_reqlen = buffer_string_length(b);
	chunkqueue_append_buffer(hctx->wb, b);
	buffer_free(b);

	if (con->request.content_length) {
		chunkqueue_append_chunkqueue(hctx->wb, con->request_content_queue);
		if (con->request.content_length > 0)
			hctx->wb_reqlen += con->request.content_length; /* total req size */
		else /* as-yet-unknown total request size (Transfer-Encoding: chunked)*/
			hctx->wb_reqlen = -hctx->wb_reqlen;
	}

	status_counter_inc(srv, CONST_STR_LEN("scgi.requests"));
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int scgi_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(exts);
	PATCH(exts_auth);
	PATCH(exts_resp);
	PATCH(proto);
	PATCH(debug);
	PATCH(ext_mapping);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("scgi.server"))) {
				PATCH(exts);
				PATCH(exts_auth);
				PATCH(exts_resp);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("scgi.protocol"))) {
				PATCH(proto);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("scgi.debug"))) {
				PATCH(debug);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("scgi.map-extensions"))) {
				PATCH(ext_mapping);
			}
		}
	}

	return 0;
}
#undef PATCH


static handler_t scgi_check_extension(server *srv, connection *con, void *p_d, int uri_path_handler) {
	plugin_data *p = p_d;
	handler_t rc;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	scgi_patch_connection(srv, con, p);
	if (NULL == p->conf.exts) return HANDLER_GO_ON;

	rc = gw_check_extension(srv, con, p, uri_path_handler, 0);
	if (HANDLER_GO_ON != rc) return rc;

	if (con->mode == p->id) {
		handler_ctx *hctx = con->plugin_ctx[p->id];
		hctx->opts.backend = BACKEND_SCGI;
		hctx->create_env = scgi_create_env;
		hctx->response = buffer_init();
	}

	return HANDLER_GO_ON;
}

/* uri-path handler */
static handler_t scgi_check_extension_1(server *srv, connection *con, void *p_d) {
	return scgi_check_extension(srv, con, p_d, 1);
}

/* start request handler */
static handler_t scgi_check_extension_2(server *srv, connection *con, void *p_d) {
	return scgi_check_extension(srv, con, p_d, 0);
}



int mod_scgi_plugin_init(plugin *p);
int mod_scgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("scgi");

	p->init         = gw_init;
	p->cleanup      = gw_free;
	p->set_defaults = mod_scgi_set_defaults;
	p->connection_reset        = gw_connection_reset;
	p->handle_uri_clean        = scgi_check_extension_1;
	p->handle_subrequest_start = scgi_check_extension_2;
	p->handle_subrequest       = gw_handle_subrequest;
	p->handle_trigger          = gw_handle_trigger;
	p->handle_waitpid          = gw_handle_waitpid_cb;

	p->data         = NULL;

	return 0;
}
