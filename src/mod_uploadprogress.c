#include "first.h"

#include "algo_splaytree.h"
#include "log.h"
#include "buffer.h"
#include "request.h"
#include "http_header.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

/**
 * this is a uploadprogress for a lighttpd plugin
 *
 */

typedef struct {
    buffer r_id;
    request_st *r;
    int ndx;
} request_map_entry;

typedef struct {
    const buffer *progress_url;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    splay_tree *request_map;
} plugin_data;

/**
 *
 * request maps
 *
 */

static request_map_entry *
request_map_entry_init (request_st * const r, const char *r_id, size_t idlen)
{
    request_map_entry * const rme = calloc(1, sizeof(request_map_entry));
    force_assert(rme);
    rme->r = r;
    rme->ndx = splaytree_djbhash(r_id, idlen);
    buffer_copy_string_len(&rme->r_id, r_id, idlen);
    return rme;
}

static void
request_map_entry_free (request_map_entry *rme)
{
    free(rme->r_id.ptr);
    free(rme);
}

static void
request_map_remove (plugin_data * const p, request_map_entry * const rme)
{
    splay_tree ** const sptree = &p->request_map;
    *sptree = splaytree_splay(*sptree, rme->ndx);
    if (NULL != *sptree && (*sptree)->key == rme->ndx) {
        request_map_entry_free((*sptree)->data);
        *sptree = splaytree_delete(*sptree, (*sptree)->key);
    }
}

static request_map_entry *
request_map_insert (plugin_data * const p, request_map_entry * const rme)
{
    splay_tree ** const sptree = &p->request_map;
    *sptree = splaytree_splay(*sptree, rme->ndx);
    if (NULL == *sptree || (*sptree)->key != rme->ndx) {
        *sptree = splaytree_insert(*sptree, rme->ndx, rme);
        return rme;
    }
    else { /* collision (not expected); leave old entry and forget new */
        /*(old entry is referenced elsewhere, so new entry is freed here)*/
        request_map_entry_free(rme);
        return NULL;
    }
}

__attribute_pure__
static request_st *
request_map_get_request (plugin_data * const p, const char * const r_id,  const size_t idlen)
{
    splay_tree ** const sptree = &p->request_map;
    int ndx = splaytree_djbhash(r_id, idlen);
    *sptree = splaytree_splay(*sptree, ndx);
    if (NULL != *sptree && (*sptree)->key == ndx) {
        request_map_entry * const rme = (*sptree)->data;
        if (buffer_eq_slen(&rme->r_id, r_id, idlen))
            return rme->r;
    }
    return NULL;
}

static void
request_map_free (plugin_data * const p)
{
    splay_tree *sptree = p->request_map;
    p->request_map = NULL;
    while (sptree) {
        request_map_entry_free(sptree->data);
        sptree = splaytree_delete(sptree, sptree->key);
    }
}

INIT_FUNC(mod_uploadprogress_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_uploadprogress_free) {
    request_map_free((plugin_data *)p_d);
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

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* upload-progress.progress-url */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_uploadprogress_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

#define REQID_LEN 32

static const char * mod_uploadprogress_get_reqid (request_st * const r) {
    const char *idstr;
    uint32_t len;
    int pathinfo = 0;
    const buffer *h = http_header_request_get(r, HTTP_HEADER_OTHER,
                                              CONST_STR_LEN("X-Progress-ID"));
    if (NULL != h)
        idstr = h->ptr;
    else if (!buffer_is_blank(&r->uri.query)
             && (idstr = strstr(r->uri.query.ptr, "X-Progress-ID=")))
        idstr += sizeof("X-Progress-ID=")-1;
    else { /*(path-info is not known at this point in request)*/
        idstr = r->uri.path.ptr;
        len = buffer_clen(&r->uri.path);
        if (len > REQID_LEN && idstr[len-REQID_LEN-1] == '/') {
            pathinfo = 1;
            idstr += len - REQID_LEN;
        }
        else
            return NULL;
    }

    /* request must contain ID of REQID_LEN bytes */
    for (len = 0; light_isxdigit(idstr[len]); ++len) ;
    if (len != REQID_LEN) {
        if (!pathinfo) { /*(reduce false positive noise in error log)*/
            log_error(r->conf.errh, __FILE__, __LINE__,
              "invalid progress-id; non-xdigit or len != %d: %s",
              REQID_LEN, idstr);
        }
        return NULL;
    }

    return idstr;
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

	switch(r->http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST: break;
	default:               return HANDLER_GO_ON;
	}

	mod_uploadprogress_patch_config(r, p);
	if (!p->conf.progress_url) return HANDLER_GO_ON;

	if (r->http_method == HTTP_METHOD_GET
	    && !buffer_is_equal(&r->uri.path, p->conf.progress_url))
		return HANDLER_GO_ON;

	const char * const idstr = mod_uploadprogress_get_reqid(r);
	if (NULL == idstr) return HANDLER_GO_ON;

	if (r->http_method == HTTP_METHOD_POST) {
		r->plugin_ctx[p->id] =
		  request_map_insert(p, request_map_entry_init(r, idstr, REQID_LEN));
		return HANDLER_GO_ON;
	} /* else r->http_method == HTTP_METHOD_GET */


		r->resp_body_started = 1;
		r->resp_body_finished = 1;

		r->http_status = 200;
		r->handler_module = NULL;

		/* get the connection */
		request_st * const post_r = request_map_get_request(p,idstr,REQID_LEN);
		if (NULL == post_r) {
			log_error(r->conf.errh, __FILE__, __LINE__, "ID not known: %.*s", REQID_LEN, idstr);
			/* XXX: why is this not an XML response, too?
			 * (At least Content-Type is not set to text/xml) */
			chunkqueue_append_mem(&r->write_queue, CONST_STR_LEN("not in progress"));
			return HANDLER_FINISHED;
		}

		http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml"));

		/* just an attempt the force the IE/proxies to NOT cache the request ... doesn't help :( */
		http_header_response_set(r, HTTP_HEADER_PRAGMA, CONST_STR_LEN("Pragma"), CONST_STR_LEN("no-cache"));
		http_header_response_set(r, HTTP_HEADER_EXPIRES, CONST_STR_LEN("Expires"), CONST_STR_LEN("Thu, 19 Nov 1981 08:52:00 GMT"));
		http_header_response_set(r, HTTP_HEADER_CACHE_CONTROL, CONST_STR_LEN("Cache-Control"), CONST_STR_LEN("no-store, no-cache, must-revalidate, post-check=0, pre-check=0"));

		/* prepare XML */
		buffer * const b = chunkqueue_append_buffer_open(&r->write_queue);
		buffer_copy_string_len(b, CONST_STR_LEN(
			"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
			"<upload>"
			"<size>"));
		buffer_append_int(b, post_r->reqbody_length);
		buffer_append_string_len(b, CONST_STR_LEN(
			"</size>"
			"<received>"));
		buffer_append_int(b, post_r->reqbody_queue.bytes_in);
		buffer_append_string_len(b, CONST_STR_LEN(
			"</received>"
			"</upload>"));
		chunkqueue_append_buffer_commit(&r->write_queue);
		return HANDLER_FINISHED;
}

REQUESTDONE_FUNC(mod_uploadprogress_request_done) {
	plugin_data *p = p_d;
	request_map_entry * const rme = r->plugin_ctx[p->id];
	if (rme) {
		r->plugin_ctx[p->id] = NULL;
		request_map_remove(p, rme);
	}
	return HANDLER_GO_ON;
}


int mod_uploadprogress_plugin_init(plugin *p);
int mod_uploadprogress_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "uploadprogress";

	p->init        = mod_uploadprogress_init;
	p->handle_uri_clean  = mod_uploadprogress_uri_handler;
	p->handle_request_reset = mod_uploadprogress_request_done;
	p->set_defaults  = mod_uploadprogress_set_defaults;
	p->cleanup     = mod_uploadprogress_free;

	return 0;
}
