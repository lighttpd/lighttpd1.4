#include "first.h"

#include "base.h"
#include "keyvalue.h"
#include "log.h"
#include "buffer.h"
#include "burl.h"

#include "plugin.h"
#include "stat_cache.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	pcre_keyvalue_buffer *rewrite;
	pcre_keyvalue_buffer *rewrite_NF;
	data_config *context, *context_NF; /* to which apply me */
	int rewrite_repeat_idx, rewrite_NF_repeat_idx;
} plugin_config;

typedef struct {
	enum { REWRITE_STATE_UNSET, REWRITE_STATE_FINISHED} state;
	int loops;
} handler_ctx;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

static handler_ctx * handler_ctx_init(void) {
	handler_ctx * hctx;

	hctx = calloc(1, sizeof(*hctx));

	hctx->state = REWRITE_STATE_UNSET;
	hctx->loops = 0;

	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	free(hctx);
}

INIT_FUNC(mod_rewrite_init) {
	return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_rewrite_free) {
	plugin_data *p = p_d;
	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			if (NULL == s) continue;
			pcre_keyvalue_buffer_free(s->rewrite);
			pcre_keyvalue_buffer_free(s->rewrite_NF);
			free(s);
		}
		free(p->config_storage);
	}

	free(p);
	return HANDLER_GO_ON;
}

static int parse_config_entry(server *srv, array *ca, pcre_keyvalue_buffer *kvb, const char *option, size_t olen) {
	data_unset *du;

	if (NULL != (du = array_get_element_klen(ca, option, olen))) {
		data_array *da;
		size_t j;

		da = (data_array *)du;

		if (du->type != TYPE_ARRAY || !array_is_kvstring(da->value)) {
			log_error_write(srv, __FILE__, __LINE__, "SSS",
					"unexpected value for ", option, "; expected list of \"regex\" => \"subst\"");
			return HANDLER_ERROR;
		}

		for (j = 0; j < da->value->used; j++) {
			data_string *ds = (data_string *)da->value->data[j];
			if (srv->srvconf.http_url_normalize) {
				pcre_keyvalue_burl_normalize_key(ds->key, srv->tmp_buf);
				pcre_keyvalue_burl_normalize_value(ds->value, srv->tmp_buf);
			}
			if (0 != pcre_keyvalue_buffer_append(srv, kvb, ds->key, ds->value)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"pcre-compile failed for", ds->key);
				return HANDLER_ERROR;
			}
		}
	}

	return 0;
}

SETDEFAULTS_FUNC(mod_rewrite_set_defaults) {
	size_t i = 0;
	config_values_t cv[] = {
		{ "url.rewrite-repeat",        NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "url.rewrite-once",          NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 1 */

		/* these functions only rewrite if the target is not already in the filestore
		 *
		 * url.rewrite-repeat-if-not-file is the equivalent of url.rewrite-repeat
		 * url.rewrite-if-not-file is the equivalent of url.rewrite-once
		 *
		 */
		{ "url.rewrite-repeat-if-not-file", NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
		{ "url.rewrite-if-not-file",        NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 3 */

		/* old names, still supported
		 *
		 * url.rewrite remapped to url.rewrite-once
		 * url.rewrite-final    is url.rewrite-once
		 *
		 */
		{ "url.rewrite",               NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
		{ "url.rewrite-final",         NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 5 */
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	plugin_data *p = p_d;

	if (!p) return HANDLER_ERROR;

	/* 0 */
	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->rewrite = pcre_keyvalue_buffer_init();
		s->rewrite_NF = pcre_keyvalue_buffer_init();
		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		parse_config_entry(srv, config->value, s->rewrite, CONST_STR_LEN("url.rewrite-once"));
		parse_config_entry(srv, config->value, s->rewrite, CONST_STR_LEN("url.rewrite-final"));
		parse_config_entry(srv, config->value, s->rewrite_NF, CONST_STR_LEN("url.rewrite-if-not-file"));
		s->rewrite_NF_repeat_idx = (int)s->rewrite_NF->used;
		parse_config_entry(srv, config->value, s->rewrite_NF, CONST_STR_LEN("url.rewrite-repeat-if-not-file"));
		parse_config_entry(srv, config->value, s->rewrite, CONST_STR_LEN("url.rewrite"));
		s->rewrite_repeat_idx = (int)s->rewrite->used;
		parse_config_entry(srv, config->value, s->rewrite, CONST_STR_LEN("url.rewrite-repeat"));
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_rewrite_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(rewrite);
	PATCH(rewrite_NF);
	p->conf.context = NULL;
	p->conf.context_NF = NULL;
	PATCH(rewrite_repeat_idx);
	PATCH(rewrite_NF_repeat_idx);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite"))) {
				PATCH(rewrite);
				p->conf.context = dc;
				PATCH(rewrite_repeat_idx);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-once"))) {
				PATCH(rewrite);
				p->conf.context = dc;
				PATCH(rewrite_repeat_idx);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-repeat"))) {
				PATCH(rewrite);
				p->conf.context = dc;
				PATCH(rewrite_repeat_idx);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-if-not-file"))) {
				PATCH(rewrite_NF);
				p->conf.context_NF = dc;
				PATCH(rewrite_NF_repeat_idx);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-repeat-if-not-file"))) {
				PATCH(rewrite_NF);
				p->conf.context_NF = dc;
				PATCH(rewrite_NF_repeat_idx);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-final"))) {
				PATCH(rewrite);
				p->conf.context = dc;
				PATCH(rewrite_repeat_idx);
			}
		}
	}

	return 0;
}

URIHANDLER_FUNC(mod_rewrite_con_reset) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (con->plugin_ctx[p->id]) {
		handler_ctx_free(con->plugin_ctx[p->id]);
		con->plugin_ctx[p->id] = NULL;
	}

	return HANDLER_GO_ON;
}

static handler_t process_rewrite_rules(server *srv, connection *con, plugin_data *p, pcre_keyvalue_buffer *kvb, int repeat_idx) {
	handler_ctx *hctx;
	struct burl_parts_t burl;
	pcre_keyvalue_ctx ctx;
	handler_t rc;

	if (con->plugin_ctx[p->id]) {
		hctx = con->plugin_ctx[p->id];

		if (hctx->loops++ > 100) {
			data_config *dc = p->conf.context;
			if (NULL == dc) {
				log_error_write(srv, __FILE__, __LINE__,  "s",
						"ENDLESS LOOP IN rewrite-rule DETECTED ... aborting request");
				return HANDLER_ERROR;
			}
			log_error_write(srv, __FILE__, __LINE__,  "SbbSBS",
					"ENDLESS LOOP IN rewrite-rule DETECTED ... aborting request, perhaps you want to use url.rewrite-once instead of url.rewrite-repeat ($", dc->comp_key, dc->op, "\"", dc->string, "\")");

			return HANDLER_ERROR;
		}

		if (hctx->state == REWRITE_STATE_FINISHED) return HANDLER_GO_ON;
	}

	ctx.cache = p->conf.context ? &con->cond_cache[p->conf.context->context_ndx] : NULL;
	ctx.burl = &burl;
	burl.scheme    = con->uri.scheme;
	burl.authority = con->uri.authority;
	burl.port      = sock_addr_get_port(&con->srv_socket->addr);
	burl.path      = con->uri.path_raw;
	burl.query     = con->uri.query;
	if (buffer_string_is_empty(burl.authority))
		burl.authority = con->server_name;

	rc = pcre_keyvalue_buffer_process(kvb, &ctx, con->request.uri, srv->tmp_buf);
	if (HANDLER_FINISHED == rc && !buffer_is_empty(srv->tmp_buf) && srv->tmp_buf->ptr[0] == '/') {
		buffer_copy_buffer(con->request.uri, srv->tmp_buf);
		if (con->plugin_ctx[p->id] == NULL) {
			hctx = handler_ctx_init();
			con->plugin_ctx[p->id] = hctx;
		} else {
			hctx = con->plugin_ctx[p->id];
		}
		if (ctx.m < repeat_idx) hctx->state = REWRITE_STATE_FINISHED;
		buffer_reset(con->physical.path);
		rc = HANDLER_COMEBACK;
	}
	else if (HANDLER_FINISHED == rc) {
		rc = HANDLER_ERROR;
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"mod_rewrite invalid result (not beginning with '/') while processing uri:",
				con->request.uri);
	}
	else if (HANDLER_ERROR == rc) {
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"pcre_exec() error while processing uri:",
				con->request.uri);
	}
	return rc;
}

URIHANDLER_FUNC(mod_rewrite_physical) {
	plugin_data *p = p_d;
	stat_cache_entry *sce;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	mod_rewrite_patch_connection(srv, con, p);
	p->conf.context = p->conf.context_NF;
	if (!p->conf.rewrite_NF->used) return HANDLER_GO_ON;

	/* skip if physical.path is a regular file */
	sce = NULL;
	if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
		if (S_ISREG(sce->st.st_mode)) return HANDLER_GO_ON;
	}

	return process_rewrite_rules(srv, con, p, p->conf.rewrite_NF, p->conf.rewrite_NF_repeat_idx);
}

URIHANDLER_FUNC(mod_rewrite_uri_handler) {
	plugin_data *p = p_d;

	mod_rewrite_patch_connection(srv, con, p);
	if (!p->conf.rewrite->used) return HANDLER_GO_ON;

	return process_rewrite_rules(srv, con, p, p->conf.rewrite, p->conf.rewrite_repeat_idx);
}

int mod_rewrite_plugin_init(plugin *p);
int mod_rewrite_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("rewrite");

	p->init        = mod_rewrite_init;
	/* it has to stay _raw as we are matching on uri + querystring
	 */

	p->handle_uri_raw = mod_rewrite_uri_handler;
	p->handle_physical = mod_rewrite_physical;
	p->cleanup     = mod_rewrite_free;
	p->connection_reset = mod_rewrite_con_reset;
	p->set_defaults = mod_rewrite_set_defaults;

	p->data        = NULL;

	return 0;
}
