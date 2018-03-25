#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"
#include "response.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

typedef struct {
	pcre_keyvalue_buffer *redirect;
	data_config *context; /* to which apply me */

	unsigned short redirect_code;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	buffer *location;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

INIT_FUNC(mod_redirect_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->location = buffer_init();

	return p;
}

FREE_FUNC(mod_redirect_free) {
	plugin_data *p = p_d;

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			pcre_keyvalue_buffer_free(s->redirect);

			free(s);
		}
		free(p->config_storage);
	}


	buffer_free(p->location);

	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_redirect_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "url.redirect",               NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "url.redirect-code",          NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	/* 0 */
	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;
		size_t j;
		data_unset *du;
		data_array *da;

		s = calloc(1, sizeof(plugin_config));
		s->redirect   = pcre_keyvalue_buffer_init();
		s->redirect_code = 301;

		cv[0].destination = s->redirect;
		cv[1].destination = &(s->redirect_code);

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (NULL == (du = array_get_element(config->value, "url.redirect"))) {
			/* no url.redirect defined */
			continue;
		}

		da = (data_array *)du;

		if (du->type != TYPE_ARRAY || !array_is_kvstring(da->value)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for url.redirect; expected list of \"regex\" => \"redirect\"");
			return HANDLER_ERROR;
		}

		for (j = 0; j < da->value->used; j++) {
			if (0 != pcre_keyvalue_buffer_append(srv, s->redirect,
							     ((data_string *)(da->value->data[j]))->key->ptr,
							     ((data_string *)(da->value->data[j]))->value->ptr)) {

				log_error_write(srv, __FILE__, __LINE__, "sb",
						"pcre-compile failed for", da->value->data[j]->key);
				return HANDLER_ERROR;
			}
		}
	}

	return HANDLER_GO_ON;
}
#ifdef HAVE_PCRE_H
static int mod_redirect_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	p->conf.redirect = s->redirect;
	p->conf.redirect_code = s->redirect_code;
	p->conf.context = NULL;

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (0 == strcmp(du->key->ptr, "url.redirect")) {
				p->conf.redirect = s->redirect;
				p->conf.context = dc;
			} else if (0 == strcmp(du->key->ptr, "url.redirect-code")) {
				p->conf.redirect_code = s->redirect_code;
			}
		}
	}

	return 0;
}
#endif
static handler_t mod_redirect_uri_handler(server *srv, connection *con, void *p_data) {
#ifdef HAVE_PCRE_H
	plugin_data *p = p_data;
	cond_cache_t *cache;
	size_t i;

	/*
	 * REWRITE URL
	 *
	 * e.g. redirect /base/ to /index.php?section=base
	 *
	 */

	mod_redirect_patch_connection(srv, con, p);
	cache = p->conf.context ? &con->cond_cache[p->conf.context->context_ndx] : NULL;

	for (i = 0; i < p->conf.redirect->used; i++) {
		pcre_keyvalue *kv = p->conf.redirect->kv[i];
# define N 10
		int ovec[N * 3];
		int n = pcre_exec(kv->key, kv->key_extra, CONST_BUF_LEN(con->request.uri), 0, 0, ovec, 3 * N);

		if (n < 0) {
			if (n != PCRE_ERROR_NOMATCH) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"execution error while matching: ", n);
				return HANDLER_ERROR;
			}
		} else if (0 == buffer_string_length(kv->value)) {
			/* short-circuit if blank replacement pattern
			 * (do not attempt to match against remaining redirect rules) */
			return HANDLER_GO_ON;
		} else {
			const char **list;

			/* it matched */
			pcre_get_substring_list(con->request.uri->ptr, ovec, n, &list);

			pcre_keyvalue_buffer_subst(p->location, kv->value, list, n, cache);

			pcre_free(list);

			response_header_insert(srv, con, CONST_STR_LEN("Location"), CONST_BUF_LEN(p->location));

			con->http_status = p->conf.redirect_code > 99 && p->conf.redirect_code < 1000 ? p->conf.redirect_code : 301;
			con->mode = DIRECT;
			con->file_finished = 1;

			return HANDLER_FINISHED;
		}
	}
#undef N

#else
	UNUSED(srv);
	UNUSED(con);
	UNUSED(p_data);
#endif

	return HANDLER_GO_ON;
}


int mod_redirect_plugin_init(plugin *p);
int mod_redirect_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("redirect");

	p->init        = mod_redirect_init;
	p->handle_uri_clean  = mod_redirect_uri_handler;
	p->set_defaults  = mod_redirect_set_defaults;
	p->cleanup     = mod_redirect_free;

	p->data        = NULL;

	return 0;
}
