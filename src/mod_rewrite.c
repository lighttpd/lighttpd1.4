#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

typedef struct {
#ifdef HAVE_PCRE_H
	pcre *key;
#endif

	buffer *value;

	int once;
} rewrite_rule;

typedef struct {
	rewrite_rule **ptr;

	size_t used;
	size_t size;
} rewrite_rule_buffer;

typedef struct {
	rewrite_rule_buffer *rewrite;
	data_config *context; /* to which apply me */
} plugin_config;

typedef struct {
	enum { REWRITE_STATE_UNSET, REWRITE_STATE_FINISHED} state;
	int loops;
} handler_ctx;

typedef struct {
	PLUGIN_DATA;
	buffer *match_buf;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx;

	hctx = calloc(1, sizeof(*hctx));

	hctx->state = REWRITE_STATE_UNSET;
	hctx->loops = 0;

	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	free(hctx);
}

rewrite_rule_buffer *rewrite_rule_buffer_init(void) {
	rewrite_rule_buffer *kvb;

	kvb = calloc(1, sizeof(*kvb));

	return kvb;
}

int rewrite_rule_buffer_append(rewrite_rule_buffer *kvb, buffer *key, buffer *value, int once) {
#ifdef HAVE_PCRE_H
	size_t i;
	const char *errptr;
	int erroff;

	if (!key) return -1;

	if (kvb->size == 0) {
		kvb->size = 4;
		kvb->used = 0;

		kvb->ptr = malloc(kvb->size * sizeof(*kvb->ptr));

		for(i = 0; i < kvb->size; i++) {
			kvb->ptr[i] = calloc(1, sizeof(**kvb->ptr));
		}
	} else if (kvb->used == kvb->size) {
		kvb->size += 4;

		kvb->ptr = realloc(kvb->ptr, kvb->size * sizeof(*kvb->ptr));

		for(i = kvb->used; i < kvb->size; i++) {
			kvb->ptr[i] = calloc(1, sizeof(**kvb->ptr));
		}
	}

	if (NULL == (kvb->ptr[kvb->used]->key = pcre_compile(key->ptr,
							    0, &errptr, &erroff, NULL))) {

		return -1;
	}

	kvb->ptr[kvb->used]->value = buffer_init();
	buffer_copy_string_buffer(kvb->ptr[kvb->used]->value, value);
	kvb->ptr[kvb->used]->once = once;

	kvb->used++;

	return 0;
#else
	UNUSED(kvb);
	UNUSED(value);
	UNUSED(once);
	UNUSED(key);

	return -1;
#endif
}

void rewrite_rule_buffer_free(rewrite_rule_buffer *kvb) {
#ifdef HAVE_PCRE_H
	size_t i;

	for (i = 0; i < kvb->size; i++) {
		if (kvb->ptr[i]->key) pcre_free(kvb->ptr[i]->key);
		if (kvb->ptr[i]->value) buffer_free(kvb->ptr[i]->value);
		free(kvb->ptr[i]);
	}

	if (kvb->ptr) free(kvb->ptr);
#endif

	free(kvb);
}


INIT_FUNC(mod_rewrite_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->match_buf = buffer_init();

	return p;
}

FREE_FUNC(mod_rewrite_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	buffer_free(p->match_buf);
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			rewrite_rule_buffer_free(s->rewrite);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

static int parse_config_entry(server *srv, plugin_config *s, array *ca, const char *option, int once) {
	data_unset *du;

	if (NULL != (du = array_get_element(ca, option))) {
		data_array *da = (data_array *)du;
		size_t j;

		if (du->type != TYPE_ARRAY) {
			log_error_write(srv, __FILE__, __LINE__, "sss",
					"unexpected type for key: ", option, "array of strings");

			return HANDLER_ERROR;
		}

		da = (data_array *)du;

		for (j = 0; j < da->value->used; j++) {
			if (da->value->data[j]->type != TYPE_STRING) {
				log_error_write(srv, __FILE__, __LINE__, "sssbs",
						"unexpected type for key: ",
						option,
						"[", da->value->data[j]->key, "](string)");

				return HANDLER_ERROR;
			}

			if (0 != rewrite_rule_buffer_append(s->rewrite,
							    ((data_string *)(da->value->data[j]))->key,
							    ((data_string *)(da->value->data[j]))->value,
							    once)) {
#ifdef HAVE_PCRE_H
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"pcre-compile failed for", da->value->data[j]->key);
#else
				log_error_write(srv, __FILE__, __LINE__, "s",
						"pcre support is missing, please install libpcre and the headers");
#endif
			}
		}
	}

	return 0;
}

SETDEFAULTS_FUNC(mod_rewrite_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "url.rewrite-repeat",        NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "url.rewrite-once",          NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 1 */

		/* old names, still supported
		 *
		 * url.rewrite remapped to url.rewrite-once
		 * url.rewrite-final    is url.rewrite-once
		 *
		 */
		{ "url.rewrite",               NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
		{ "url.rewrite-final",         NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 3 */
		{ NULL,                        NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	/* 0 */
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		array *ca;

		s = calloc(1, sizeof(plugin_config));
		s->rewrite   = rewrite_rule_buffer_init();

		cv[0].destination = s->rewrite;
		cv[1].destination = s->rewrite;
		cv[2].destination = s->rewrite;

		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;

		if (0 != config_insert_values_global(srv, ca, cv)) {
			return HANDLER_ERROR;
		}

		parse_config_entry(srv, s, ca, "url.rewrite-once",   1);
		parse_config_entry(srv, s, ca, "url.rewrite-final",  1);
		parse_config_entry(srv, s, ca, "url.rewrite",        1);
		parse_config_entry(srv, s, ca, "url.rewrite-repeat", 0);
	}

	return HANDLER_GO_ON;
}
#ifdef HAVE_PCRE_H
static int mod_rewrite_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	p->conf.rewrite = s->rewrite;
	p->conf.context = NULL;

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		if (COMP_HTTP_URL == dc->comp) continue;

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite"))) {
				p->conf.rewrite = s->rewrite;
				p->conf.context = dc;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-once"))) {
				p->conf.rewrite = s->rewrite;
				p->conf.context = dc;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-repeat"))) {
				p->conf.rewrite = s->rewrite;
				p->conf.context = dc;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("url.rewrite-final"))) {
				p->conf.rewrite = s->rewrite;
				p->conf.context = dc;
			}
		}
	}

	return 0;
}
#endif
URIHANDLER_FUNC(mod_rewrite_con_reset) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (con->plugin_ctx[p->id]) {
		handler_ctx_free(con->plugin_ctx[p->id]);
		con->plugin_ctx[p->id] = NULL;
	}

	return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_rewrite_uri_handler) {
#ifdef HAVE_PCRE_H
	plugin_data *p = p_d;
	size_t i;
	handler_ctx *hctx;

	/*
	 * REWRITE URL
	 *
	 * e.g. rewrite /base/ to /index.php?section=base
	 *
	 */

	if (con->plugin_ctx[p->id]) {
		hctx = con->plugin_ctx[p->id];

		if (hctx->loops++ > 100) {
			log_error_write(srv, __FILE__, __LINE__,  "s",
					"ENDLESS LOOP IN rewrite-rule DETECTED ... aborting request, perhaps you want to use url.rewrite-once instead of url.rewrite-repeat");

			return HANDLER_ERROR;
		}

		if (hctx->state == REWRITE_STATE_FINISHED) return HANDLER_GO_ON;
	}

	mod_rewrite_patch_connection(srv, con, p);

	if (!p->conf.rewrite) return HANDLER_GO_ON;

	buffer_copy_string_buffer(p->match_buf, con->request.uri);

	for (i = 0; i < p->conf.rewrite->used; i++) {
		pcre *match;
		const char *pattern;
		size_t pattern_len;
		int n;
		rewrite_rule *rule = p->conf.rewrite->ptr[i];
# define N 10
		int ovec[N * 3];

		match       = rule->key;
		pattern     = rule->value->ptr;
		pattern_len = rule->value->used - 1;

		if ((n = pcre_exec(match, NULL, p->match_buf->ptr, p->match_buf->used - 1, 0, 0, ovec, 3 * N)) < 0) {
			if (n != PCRE_ERROR_NOMATCH) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"execution error while matching: ", n);
				return HANDLER_ERROR;
			}
		} else {
			const char **list;
			size_t start, end;
			size_t k;

			/* it matched */
			pcre_get_substring_list(p->match_buf->ptr, ovec, n, &list);

			/* search for $[0-9] */

			buffer_reset(con->request.uri);

			start = 0; end = pattern_len;
			for (k = 0; k < pattern_len; k++) {
				if (pattern[k] == '$' || pattern[k] == '%') {
					/* got one */

					size_t num = pattern[k + 1] - '0';

					end = k;

					buffer_append_string_len(con->request.uri, pattern + start, end - start);

					if (!isdigit((unsigned char)pattern[k + 1])) {
						/* enable escape: "%%" => "%", "%a" => "%a", "$$" => "$" */
						buffer_append_string_len(con->request.uri, pattern+k, pattern[k] == pattern[k+1] ? 1 : 2);
					} else if (pattern[k] == '$') {
						/* n is always > 0 */
						if (num < (size_t)n) {
							buffer_append_string(con->request.uri, list[num]);
						}
					} else if (p->conf.context == NULL) {
						/* we have no context, we are global */
						log_error_write(srv, __FILE__, __LINE__, "sb",
								"used a redirect containing a %[0-9]+ in the global scope, ignored:",
								rule->value);

					} else {
						config_append_cond_match_buffer(con, p->conf.context, con->request.uri, num);
					}

					k++;
					start = k + 1;
				}
			}

			buffer_append_string_len(con->request.uri, pattern + start, pattern_len - start);

			pcre_free(list);

			if (con->plugin_ctx[p->id] == NULL) {
				hctx = handler_ctx_init();
				con->plugin_ctx[p->id] = hctx;
			} else {
				hctx = con->plugin_ctx[p->id];
			}

			if (rule->once) hctx->state = REWRITE_STATE_FINISHED;

			return HANDLER_COMEBACK;
		}
	}
#undef N

#else
	UNUSED(srv);
	UNUSED(con);
	UNUSED(p_d);
#endif

	return HANDLER_GO_ON;
}

int mod_rewrite_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("rewrite");

	p->init        = mod_rewrite_init;
	/* it has to stay _raw as we are matching on uri + querystring
	 */

	p->handle_uri_raw = mod_rewrite_uri_handler;
	p->set_defaults = mod_rewrite_set_defaults;
	p->cleanup     = mod_rewrite_free;
	p->connection_reset = mod_rewrite_con_reset;

	p->data        = NULL;

	return 0;
}
