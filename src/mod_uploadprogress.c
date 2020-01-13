#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

/**
 * this is a uploadprogress for a lighttpd plugin
 *
 */

typedef struct {
	buffer     *r_id;
	request_st *r;
} request_map_entry;

typedef struct {
	request_map_entry **ptr;

	uint32_t used;
	uint32_t size;
} request_map;

typedef struct {
    const buffer *progress_url;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    request_map request_map;
} plugin_data;

/**
 *
 * request maps
 *
 */

static void request_map_free_data(request_map *rm) {
	for (uint32_t i = 0; i < rm->size; ++i) {
		request_map_entry *rme = rm->ptr[i];

		if (!rme) break;

		if (rme->r_id) {
			buffer_free(rme->r_id);
		}
		free(rme);
	}
}

static int request_map_insert(request_map *rm, request_st * const r, const char *r_id, size_t idlen) {
	request_map_entry *rme;

	if (rm->used == rm->size) {
		rm->size = rm->size ? (rm->size << 1) : 16;
		force_assert(rm->size);
		rm->ptr = realloc(rm->ptr, rm->size * sizeof(*(rm->ptr)));
		memset(rm->ptr+rm->used, 0, (rm->size - rm->used)*sizeof(*(rm->ptr)));
	}

	if (rm->ptr[rm->used]) {
		/* is already alloced, just reuse it */
		rme = rm->ptr[rm->used];
	} else {
		rme = malloc(sizeof(*rme));
		rme->r_id = buffer_init();
	}
	buffer_copy_string_len(rme->r_id, r_id, idlen);
	rme->r = r;

	rm->ptr[rm->used++] = rme;

	return 0;
}

static request_st * request_map_get_request(request_map *rm, const char *r_id, size_t idlen) {
	for (uint32_t i = 0; i < rm->used; ++i) {
		request_map_entry *rme = rm->ptr[i];

		if (buffer_is_equal_string(rme->r_id, r_id, idlen)) {
			return rme->r; /* found request */
		}
	}
	return NULL;
}

static int request_map_remove_request(request_map * const rm, const request_st * const r) {
	for (uint32_t i = 0; i < rm->used; ++i) {
		request_map_entry *rme = rm->ptr[i];

		if (rme->r == r) {
			/* found request */

			buffer_clear(rme->r_id);
			rme->r = NULL;

			rm->used--;

			/* swap positions with the last entry */
			if (rm->used) {
				rm->ptr[i] = rm->ptr[rm->used];
				rm->ptr[rm->used] = rme;
			}

			return 1;
		}
	}

	return 0;
}

INIT_FUNC(mod_uploadprogress_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_uploadprogress_free) {
    plugin_data *p = p_d;
    request_map_free_data(&p->request_map);
}

static void mod_uploadprogress_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* upload-progress.progress-url */
        pconf->progress_url = cpv->v.b;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_uploadprogress_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_uploadprogress_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_uploadprogress_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_uploadprogress_merge_config(&p->conf,
                                            p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_uploadprogress_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("upload-progress.progress-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_uploadprogress"))
        return HANDLER_ERROR;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_uploadprogress_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

/**
 *
 * the idea:
 *
 * for the first request we check if it is a post-request
 *
 * if no, move out, don't care about them
 *
 * if yes, take the connection structure and register it locally
 * in the progress-struct together with an session-id (md5 ... )
 *
 * if the connections closes, cleanup the entry in the progress-struct
 *
 * a second request can now get the info about the size of the upload,
 * the received bytes
 *
 */

URIHANDLER_FUNC(mod_uploadprogress_uri_handler) {
	plugin_data *p = p_d;
	size_t len;
	char *id;
	buffer *b;
	request_st *post_r;
	int pathinfo = 0;

	if (buffer_string_is_empty(&r->uri.path)) return HANDLER_GO_ON;
	switch(r->http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST: break;
	default:               return HANDLER_GO_ON;
	}

	mod_uploadprogress_patch_config(r, p);
	if (buffer_string_is_empty(p->conf.progress_url)) return HANDLER_GO_ON;

	if (r->http_method == HTTP_METHOD_GET) {
		if (!buffer_is_equal(&r->uri.path, p->conf.progress_url)) {
			return HANDLER_GO_ON;
		}
	}

	const buffer *h = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("X-Progress-ID"));
	if (NULL != h) {
		id = h->ptr;
	} else if (!buffer_string_is_empty(&r->uri.query)
		   && (id = strstr(r->uri.query.ptr, "X-Progress-ID="))) {
		/* perhaps the POST request is using the query-string to pass the X-Progress-ID */
		id += sizeof("X-Progress-ID=")-1;
	} else {
		/*(path-info is not known at this point in request)*/
		id = r->uri.path.ptr;
		len = buffer_string_length(&r->uri.path);
		if (len >= 33 && id[len-33] == '/') {
			id += len - 32;
			pathinfo = 1;
		} else {
			return HANDLER_GO_ON;
		}
	}

	/* the request has to contain a 32byte ID */
	for (len = 0; light_isxdigit(id[len]); ++len) ;
	if (len != 32) {
		if (!pathinfo) { /*(reduce false positive noise in error log)*/
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "invalid progress-id; non-xdigit or len != 32: %s", id);
		}
		return HANDLER_GO_ON;
	}

	/* check if this is a POST request */
	switch(r->http_method) {
	case HTTP_METHOD_POST:

		request_map_insert(&p->request_map, r, id, len);

		return HANDLER_GO_ON;
	case HTTP_METHOD_GET:
		buffer_reset(&r->physical.path);

		r->resp_body_started = 1;
		r->resp_body_finished = 1;

		r->http_status = 200;
		r->handler_module = NULL;

		/* get the connection */
		if (NULL == (post_r = request_map_get_request(&p->request_map, id, len))) {
			log_error(r->conf.errh, __FILE__, __LINE__, "ID not known: %s", id);

			chunkqueue_append_mem(r->write_queue, CONST_STR_LEN("not in progress"));

			return HANDLER_FINISHED;
		}

		http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml"));

		/* just an attempt the force the IE/proxies to NOT cache the request ... doesn't help :( */
		http_header_response_set(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Pragma"), CONST_STR_LEN("no-cache"));
		http_header_response_set(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Expires"), CONST_STR_LEN("Thu, 19 Nov 1981 08:52:00 GMT"));
		http_header_response_set(r, HTTP_HEADER_CACHE_CONTROL, CONST_STR_LEN("Cache-Control"), CONST_STR_LEN("no-store, no-cache, must-revalidate, post-check=0, pre-check=0"));

		/* prepare XML */
		b = r->tmp_buf;
		buffer_copy_string_len(b, CONST_STR_LEN(
			"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
			"<upload>"
			"<size>"));
		buffer_append_int(b, post_r->reqbody_length);
		buffer_append_string_len(b, CONST_STR_LEN(
			"</size>"
			"<received>"));
		buffer_append_int(b, post_r->reqbody_queue->bytes_in);
		buffer_append_string_len(b, CONST_STR_LEN(
			"</received>"
			"</upload>"));
		chunkqueue_append_mem(r->write_queue, CONST_BUF_LEN(b));
		return HANDLER_FINISHED;
	default:
		break;
	}

	return HANDLER_GO_ON;
}

REQUESTDONE_FUNC(mod_uploadprogress_request_done) {
	plugin_data *p = p_d;

	if (r->http_method != HTTP_METHOD_POST) return HANDLER_GO_ON;
	if (buffer_string_is_empty(&r->uri.path)) return HANDLER_GO_ON;

	if (request_map_remove_request(&p->request_map, r)) {
		/* removed */
	}

	return HANDLER_GO_ON;
}


int mod_uploadprogress_plugin_init(plugin *p);
int mod_uploadprogress_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "uploadprogress";

	p->init        = mod_uploadprogress_init;
	p->handle_uri_clean  = mod_uploadprogress_uri_handler;
	p->connection_reset  = mod_uploadprogress_request_done;
	p->set_defaults  = mod_uploadprogress_set_defaults;
	p->cleanup     = mod_uploadprogress_free;

	return 0;
}
