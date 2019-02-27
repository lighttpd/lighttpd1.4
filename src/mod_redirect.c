#include "first.h"

#include "base.h"
#include "keyvalue.h"
#include "log.h"
#include "buffer.h"
#include "burl.h"
#include "http_header.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	pcre_keyvalue_buffer *redirect;
	data_config *context; /* to which apply me */
	unsigned short redirect_code;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

INIT_FUNC(mod_redirect_init) {
	return calloc(1, sizeof(plugin_data));
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
	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

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

		if (s->redirect_code < 100 || s->redirect_code >= 1000) s->redirect_code = 301;

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
			data_string *ds = (data_string *)da->value->data[j];
			if (srv->srvconf.http_url_normalize) {
				pcre_keyvalue_burl_normalize_key(ds->key, srv->tmp_buf);
				pcre_keyvalue_burl_normalize_value(ds->value, srv->tmp_buf);
			}
			if (0 != pcre_keyvalue_buffer_append(srv, s->redirect, ds->key, ds->value)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"pcre-compile failed for", ds->key);
				return HANDLER_ERROR;
			}
		}
	}

	return HANDLER_GO_ON;
}

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

URIHANDLER_FUNC(mod_redirect_uri_handler) {
    plugin_data *p = p_d;
    struct burl_parts_t burl;
    pcre_keyvalue_ctx ctx;
    handler_t rc;

    mod_redirect_patch_connection(srv, con, p);
    if (!p->conf.redirect->used) return HANDLER_GO_ON;
    ctx.cache = p->conf.context
      ? &con->cond_cache[p->conf.context->context_ndx]
      : NULL;
    ctx.burl = &burl;
    burl.scheme    = con->uri.scheme;
    burl.authority = con->uri.authority;
    burl.port      = sock_addr_get_port(&con->srv_socket->addr);
    burl.path      = con->uri.path_raw;
    burl.query     = con->uri.query;
    if (buffer_string_is_empty(burl.authority))
        burl.authority = con->server_name;

    /* redirect URL on match
     * e.g. redirect /base/ to /index.php?section=base
     */
    rc = pcre_keyvalue_buffer_process(p->conf.redirect, &ctx,
                                      con->request.uri, srv->tmp_buf);
    if (HANDLER_FINISHED == rc) {
        http_header_response_set(con, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 CONST_BUF_LEN(srv->tmp_buf));
        con->http_status = p->conf.redirect_code;
        con->mode = DIRECT;
        con->file_finished = 1;
    }
    else if (HANDLER_ERROR == rc) {
        log_error_write(srv, __FILE__, __LINE__, "sb",
                        "pcre_exec() error while processing uri:",
                        con->request.uri);
    }
    return rc;
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
