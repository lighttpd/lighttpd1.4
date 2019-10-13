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

			if (buffer_is_equal_string(&du->key, CONST_STR_LEN("flv-streaming.extensions"))) {
				PATCH(extensions);
			}
		}
	}

	return 0;
}
#undef PATCH

static off_t get_param_value(buffer *qb, const char *m, size_t mlen) {
    const char * const q = qb->ptr;
    size_t len = buffer_string_length(qb);
    if (len < mlen+2) return -1;
    len -= (mlen+2);
    for (size_t i = 0; i <= len; ++i) {
        if (0 == memcmp(q+i, m, mlen) && q[i+mlen] == '=') {
            char *err;
            off_t n = strtoll(q+i+mlen+1, &err, 10);
            return (*err == '\0' || *err == '&') ? n : -1;
        }
        do { ++i; } while (i < len && q[i] != '&');
    }
    return -1;
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

	off_t start = get_param_value(con->uri.query, CONST_STR_LEN("start"));
	off_t end = get_param_value(con->uri.query, CONST_STR_LEN("end"));
	off_t len = -1;
	if (start < 0) start = 0;
	if (start < end)
		len = end - start + 1;
	else if (0 == start)
		return HANDLER_GO_ON; /* let mod_staticfile send whole file */

			/* if there is a start=[0-9]+ in the header use it as start,
			 * otherwise set start to beginning of file */
			/* if there is a end=[0-9]+ in the header use it as end pos,
			 * otherwise send rest of file, starting from start */

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
