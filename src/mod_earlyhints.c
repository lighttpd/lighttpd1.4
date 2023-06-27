#include "first.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "plugin.h"

#include "log.h"
#include "buffer.h"
#include "array.h"
#include "request.h"
#include "response.h"
#include "http_header.h"
#include "stat_cache.h"

/**
 * mod_earlyhints.c - Support for 103 Early hints responses
 *
 * Copyright(c) 2023 Alexandre Janon <alex14fr at gmail.com>
 *
 * This aim of this module is to send the responses defined in RFC 8297 Early hints
 * when, for some reason, your backend is unable to send multiple responses to a single HTTP
 * requests (e.g., PHP-FPM <https://bugs.php.net/bug.php?id=78487>).
 *
 * The headers to send are defined by the "earlyhints.headers" parameter in lighttpd configuration file.
 *
 * Example:
 *
 * $HTTP["url"]=^"/slowbackend/" {
 * 	earlyhints.headers=("Link"=>"</style.css>; rel=preload; as=style")
 * }
 *
 * The header value supports "file mtime substitution"; for example if you have:
 *
 * $HTTP["url"]=^"/slowbackend/" {
 * 	earlyhints.headers=("Link"=>"</style.css?{style.css}>; rel=preload; as=style")
 * }
 *
 * and if <document-root>/style.css has a modification time whose Unix timestamp is 123456789, then
 *
 *     Link: </style.css?123456789>; rel=preload; as=style
 *
 * will be sent as Early hint header for any request with URI starting with "/slowbackend/".
 * This is useful if you use "cache busting".
 *
 */


/* plugin config for all request/connections */

typedef struct {
	const array *headers;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	plugin_config conf;
} plugin_data;


#if 0 /* (needed if module keeps state for request) */

typedef struct {
	size_t foo;
} handler_ctx;

static handler_ctx * handler_ctx_init(void) {
	return ck_calloc(1, sizeof(handler_ctx));
}

static void handler_ctx_free(handler_ctx *hctx) {
	free(hctx);
}

#endif


/* init the plugin data */
INIT_FUNC(mod_earlyhints_init) {
	return ck_calloc(1, sizeof(plugin_data));
}

/* handle plugin config and check values */

static void mod_earlyhints_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
	switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
		case 0: /* earlyhints.array */
			pconf->headers = cpv->v.a;
			if(pconf->headers) {
				for(uint32_t i=0; i<pconf->headers->used; ++i) {
					data_string * const ds = (data_string *)pconf->headers->data[i];
					ds->ext = http_header_hkey_get(BUF_PTR_LEN(&ds->key));
				}
			}
			break;
		default:/* should not happen */
			return;
	}
}

static void mod_earlyhints_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
	do {
		mod_earlyhints_merge_config_cpv(pconf, cpv);
	} while ((++cpv)->k_id != -1);
}

static void mod_earlyhints_patch_config(request_st * const r, plugin_data * const p) {
	p->conf = p->defaults; /* copy small struct instead of memcpy() */
	/*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
	for (int i = 1, used = p->nconfig; i < used; ++i) {
		if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
			mod_earlyhints_merge_config(&p->conf, p->cvlist+p->cvlist[i].v.u2[0]);
	}
}

SETDEFAULTS_FUNC(mod_earlyhints_set_defaults) {
	static const config_plugin_keys_t cpk[] = {
		{ CONST_STR_LEN("earlyhints.headers"),
			T_CONFIG_ARRAY_KVSTRING,
			T_CONFIG_SCOPE_CONNECTION }
		,{ NULL, 0,
			T_CONFIG_UNSET,
			T_CONFIG_SCOPE_UNSET }
	};

	plugin_data * const p = p_d;
	if (!config_plugin_values_init(srv, p, cpk, "mod_earlyhints"))
		return HANDLER_ERROR;

	/* initialize p->defaults from global config context */
	if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
		const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
		if (-1 != cpv->k_id)
			mod_earlyhints_merge_config(&p->defaults, cpv);
	}

	return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_earlyhints_uri_handler) {
	plugin_data * const p = p_d;

	/* determine whether or not module participates in request */
	if (NULL != r->handler_module) return HANDLER_GO_ON;
	if (buffer_is_blank(&r->uri.path)) return HANDLER_GO_ON;

	/* get module config for request */
	mod_earlyhints_patch_config(r, p);

	const array * const h = p->conf.headers;

	if (NULL == h || 0 == h->used)
		return HANDLER_GO_ON;

	/* module participates in request; business logic here */
	r->http_status = 103;
	for (uint32_t k = 0; k<h->used; ++k) {
		/* loop through added headers */
		const data_string * const ds = (const data_string *)h->data[k];
		/* check if mtime substitution is used */
		const char * entry = strchr (ds->value.ptr, '{');
		int subs_mtime = 0;
		if (entry) {
			/* ds->value.ptr has len1 bytes before '{' */
			const size_t len1 = entry - ds->value.ptr;
			entry++;
			const char * const entry2 = strchr (entry, '}');
			const size_t len2 = entry2 - entry;
			/* entry points to file name of length len2; entry2 points at } after end of file name */
			/* build full file path in t and stat() it */
			buffer * const t = r->tmp_buf;
			buffer_copy_path_len2(t, BUF_PTR_LEN((r->conf).document_root), entry, len2);
			const stat_cache_entry * const sce = stat_cache_get_entry(t);
			if(sce != NULL) {
				/* file found; create correct header value in t; first part  */
				buffer_copy_string_len(t, ds->value.ptr, len1);
				/* then the mtime as Unix timestamp ASCII value */
				char mti[20];
				const size_t len3 = snprintf(mti, 20, "%ld", sce->st.st_mtime);
				buffer_append_string_len(t, mti, len3);
				/* and the rest of the header */
				buffer_append_string(t, entry2+1);
				/* add header */
				http_header_response_insert(r, ds->ext, BUF_PTR_LEN(&ds->key), BUF_PTR_LEN(t));
				subs_mtime = 1;
			}
	}
	if (!subs_mtime) {
		/* no mtime substitution or file not found, send header value as is */
		http_header_response_insert(r, ds->ext, BUF_PTR_LEN(&ds->key), BUF_PTR_LEN(&ds->value));
	}
}
http_response_send_1xx (r);
return HANDLER_GO_ON;
}


/* this function is called at dlopen() time and inits the callbacks */
__attribute_cold__
__declspec_dllexport__
int mod_earlyhints_plugin_init(plugin *p);
int mod_earlyhints_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "earlyhints";
	p->init        = mod_earlyhints_init;
	p->set_defaults= mod_earlyhints_set_defaults;

	p->handle_uri_clean = mod_earlyhints_uri_handler;

	return 0;
}
