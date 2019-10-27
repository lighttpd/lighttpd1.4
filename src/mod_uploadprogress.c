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
	buffer     *con_id;
	connection *con;
} connection_map_entry;

typedef struct {
	connection_map_entry **ptr;

	uint32_t used;
	uint32_t size;
} connection_map;

typedef struct {
    const buffer *progress_url;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    connection_map con_map;
} plugin_data;

/**
 *
 * connection maps
 *
 */

static void connection_map_free_data(connection_map *cm) {
	for (uint32_t i = 0; i < cm->size; ++i) {
		connection_map_entry *cme = cm->ptr[i];

		if (!cme) break;

		if (cme->con_id) {
			buffer_free(cme->con_id);
		}
		free(cme);
	}
}

static int connection_map_insert(connection_map *cm, connection *con, const char *con_id, size_t idlen) {
	connection_map_entry *cme;

	if (cm->used == cm->size) {
		cm->size = cm->size ? (cm->size << 1) : 16;
		force_assert(cm->size);
		cm->ptr = realloc(cm->ptr, cm->size * sizeof(*(cm->ptr)));
		memset(cm->ptr+cm->used, 0, (cm->size - cm->used)*sizeof(*(cm->ptr)));
	}

	if (cm->ptr[cm->used]) {
		/* is already alloced, just reuse it */
		cme = cm->ptr[cm->used];
	} else {
		cme = malloc(sizeof(*cme));
		cme->con_id = buffer_init();
	}
	buffer_copy_string_len(cme->con_id, con_id, idlen);
	cme->con = con;

	cm->ptr[cm->used++] = cme;

	return 0;
}

static connection *connection_map_get_connection(connection_map *cm, const char *con_id, size_t idlen) {
	for (uint32_t i = 0; i < cm->used; ++i) {
		connection_map_entry *cme = cm->ptr[i];

		if (buffer_is_equal_string(cme->con_id, con_id, idlen)) {
			/* found connection */

			return cme->con;
		}
	}
	return NULL;
}

static int connection_map_remove_connection(connection_map *cm, connection *con) {
	for (uint32_t i = 0; i < cm->used; ++i) {
		connection_map_entry *cme = cm->ptr[i];

		if (cme->con == con) {
			/* found connection */

			buffer_clear(cme->con_id);
			cme->con = NULL;

			cm->used--;

			/* swap positions with the last entry */
			if (cm->used) {
				cm->ptr[i] = cm->ptr[cm->used];
				cm->ptr[cm->used] = cme;
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
    if (!p) return HANDLER_GO_ON;
    UNUSED(srv);

    connection_map_free_data(&p->con_map);

    free(p->cvlist);
    free(p);

    return HANDLER_GO_ON;
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

static void mod_uploadprogress_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
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
	connection *post_con = NULL;
	int pathinfo = 0;

	if (buffer_string_is_empty(con->uri.path)) return HANDLER_GO_ON;
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST: break;
	default:               return HANDLER_GO_ON;
	}

	mod_uploadprogress_patch_config(con, p);
	if (buffer_string_is_empty(p->conf.progress_url)) return HANDLER_GO_ON;

	if (con->request.http_method == HTTP_METHOD_GET) {
		if (!buffer_is_equal(con->uri.path, p->conf.progress_url)) {
			return HANDLER_GO_ON;
		}
	}

	const buffer *h = http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("X-Progress-ID"));
	if (NULL != h) {
		id = h->ptr;
	} else if (!buffer_string_is_empty(con->uri.query)
		   && (id = strstr(con->uri.query->ptr, "X-Progress-ID="))) {
		/* perhaps the POST request is using the query-string to pass the X-Progress-ID */
		id += sizeof("X-Progress-ID=")-1;
	} else {
		/*(path-info is not known at this point in request)*/
		id = con->uri.path->ptr;
		len = buffer_string_length(con->uri.path);
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
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"invalid progress-id; non-xdigit or len != 32:", id);
		}
		return HANDLER_GO_ON;
	}

	/* check if this is a POST request */
	switch(con->request.http_method) {
	case HTTP_METHOD_POST:

		connection_map_insert(&p->con_map, con, id, len);

		return HANDLER_GO_ON;
	case HTTP_METHOD_GET:
		buffer_reset(con->physical.path);

		con->file_started = 1;
		con->file_finished = 1;

		con->http_status = 200;
		con->mode = DIRECT;

		/* get the connection */
		if (NULL == (post_con = connection_map_get_connection(&p->con_map, id, len))) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"ID not known:", id);

			chunkqueue_append_mem(con->write_queue, CONST_STR_LEN("not in progress"));

			return HANDLER_FINISHED;
		}

		http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml"));

		/* just an attempt the force the IE/proxies to NOT cache the request ... doesn't help :( */
		http_header_response_set(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Pragma"), CONST_STR_LEN("no-cache"));
		http_header_response_set(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Expires"), CONST_STR_LEN("Thu, 19 Nov 1981 08:52:00 GMT"));
		http_header_response_set(con, HTTP_HEADER_CACHE_CONTROL, CONST_STR_LEN("Cache-Control"), CONST_STR_LEN("no-store, no-cache, must-revalidate, post-check=0, pre-check=0"));

		/* prepare XML */
		b = srv->tmp_buf;
		buffer_copy_string_len(b, CONST_STR_LEN(
			"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
			"<upload>"
			"<size>"));
		buffer_append_int(b, post_con->request.content_length);
		buffer_append_string_len(b, CONST_STR_LEN(
			"</size>"
			"<received>"));
		buffer_append_int(b, post_con->request_content_queue->bytes_in);
		buffer_append_string_len(b, CONST_STR_LEN(
			"</received>"
			"</upload>"));
		chunkqueue_append_mem(con->write_queue, CONST_BUF_LEN(b));
		return HANDLER_FINISHED;
	default:
		break;
	}

	return HANDLER_GO_ON;
}

REQUESTDONE_FUNC(mod_uploadprogress_request_done) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (con->request.http_method != HTTP_METHOD_POST) return HANDLER_GO_ON;
	if (buffer_string_is_empty(con->uri.path)) return HANDLER_GO_ON;

	if (connection_map_remove_connection(&p->con_map, con)) {
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
