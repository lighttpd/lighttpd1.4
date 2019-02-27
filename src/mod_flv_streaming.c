#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_chunk.h"
#include "http_header.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

/* plugin config for all request/connections */

typedef struct {
	array *extensions;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_flv_streaming_init) {
	return calloc(1, sizeof(plugin_data));
}

/* detroy the plugin data */
FREE_FUNC(mod_flv_streaming_free) {
	plugin_data *p = p_d;
	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		for (size_t i = 0; i < srv->config_context->used; ++i) {
			plugin_config *s = p->config_storage[i];
			if (NULL == s) continue;
			array_free(s->extensions);
			free(s);
		}
		free(p->config_storage);
	}
	free(p);
	UNUSED(srv);
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_flv_streaming_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "flv-streaming.extensions",   NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->extensions     = array_init();

		cv[0].destination = s->extensions;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->extensions)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for flv-streaming.extensions; expected list of \"ext\"");
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_flv_streaming_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(extensions);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("flv-streaming.extensions"))) {
				PATCH(extensions);
			}
		}
	}

	return 0;
}
#undef PATCH

static int split_get_params(array *get_params, buffer *qrystr) {
	size_t is_key = 1, klen = 0;
	char *key = qrystr->ptr, *val = NULL;

	if (buffer_string_is_empty(qrystr)) return 0;
	for (size_t i = 0, len = buffer_string_length(qrystr); i <= len; ++i) {
		switch(qrystr->ptr[i]) {
		case '=':
			if (is_key) {
				val = qrystr->ptr + i + 1;
				klen = (size_t)(qrystr->ptr + i - key);
				is_key = 0;
			}

			break;
		case '&':
		case '\0': /* fin symbol */
			if (!is_key) {
				/* we need at least a = since the last & */
				array_insert_key_value(get_params, key, klen, val, qrystr->ptr + i - val);
			}

			key = qrystr->ptr + i + 1;
			val = NULL;
			is_key = 1;
			break;
		}
	}

	return 0;
}

URIHANDLER_FUNC(mod_flv_streaming_path_handler) {
	plugin_data *p = p_d;

	if (con->mode != DIRECT) return HANDLER_GO_ON;
	if (buffer_string_is_empty(con->physical.path)) return HANDLER_GO_ON;

	mod_flv_streaming_patch_connection(srv, con, p);

	if (!array_match_value_suffix(p->conf.extensions, con->physical.path)) {
		/* not found */
		return HANDLER_GO_ON;
	}

	{
			data_string *get_param;
			off_t start = 0, len = -1;
			char *err = NULL;
			/* if there is a start=[0-9]+ in the header use it as start,
			 * otherwise set start to beginning of file */
			/* if there is a end=[0-9]+ in the header use it as end pos,
			 * otherwise send rest of file, starting from start */

			array_reset_data_strings(srv->split_vals);
			split_get_params(srv->split_vals, con->uri.query);

			if (NULL != (get_param = (data_string *)array_get_element_klen(srv->split_vals, CONST_STR_LEN("start")))) {
				if (buffer_string_is_empty(get_param->value)) return HANDLER_GO_ON;
				start = strtoll(get_param->value->ptr, &err, 10);
				if (*err != '\0') return HANDLER_GO_ON;
				if (start < 0) return HANDLER_GO_ON;
			}

			if (NULL != (get_param = (data_string *)array_get_element_klen(srv->split_vals, CONST_STR_LEN("end")))) {
				off_t end;
				if (buffer_string_is_empty(get_param->value)) return HANDLER_GO_ON;
				end = strtoll(get_param->value->ptr, &err, 10);
				if (*err != '\0') return HANDLER_GO_ON;
				if (end < 0) return HANDLER_GO_ON;
				len = (start < end ? end - start : start - end) + 1;
			}
			else if (0 == start) {
				return HANDLER_GO_ON;
			}

			/* let's build a flv header */
			http_chunk_append_mem(srv, con, CONST_STR_LEN("FLV\x1\x1\0\0\0\x9\0\0\0\x9"));
			if (0 != http_chunk_append_file_range(srv, con, con->physical.path, start, len)) {
				chunkqueue_reset(con->write_queue);
				return HANDLER_GO_ON;
			}

			http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("video/x-flv"));
			con->file_finished = 1;
			return HANDLER_FINISHED;
	}
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_flv_streaming_plugin_init(plugin *p);
int mod_flv_streaming_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("flv_streaming");

	p->init        = mod_flv_streaming_init;
	p->handle_physical = mod_flv_streaming_path_handler;
	p->set_defaults  = mod_flv_streaming_set_defaults;
	p->cleanup     = mod_flv_streaming_free;

	p->data        = NULL;

	return 0;
}
