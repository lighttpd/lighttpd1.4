#include "first.h"

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "gw_backend.h"
typedef gw_plugin_config plugin_config;
typedef gw_plugin_data   plugin_data;
typedef gw_handler_ctx   handler_ctx;

#include "base.h"
#include "buffer.h"
#include "http_cgi.h"
#include "http_status.h"
#include "log.h"

enum { LI_PROTOCOL_SCGI, LI_PROTOCOL_UWSGI };

static void mod_scgi_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* scgi.server */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            gw_plugin_config * const gw = cpv->v.v;
            pconf->exts      = gw->exts;
            pconf->exts_auth = gw->exts_auth;
            pconf->exts_resp = gw->exts_resp;
        }
        break;
      case 1: /* scgi.balance */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->balance = (int)cpv->v.u;
        break;
      case 2: /* scgi.debug */
        pconf->debug = (int)cpv->v.u;
        break;
      case 3: /* scgi.map-extensions */
        pconf->ext_mapping = cpv->v.a;
        break;
      case 4: /* scgi.protocol */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->proto = (int)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_scgi_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_scgi_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_scgi_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_scgi_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_scgi_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("scgi.server"),
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.balance"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.debug"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.map-extensions"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.protocol"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_scgi"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0:{/* scgi.server */
                gw_plugin_config *gw = ck_calloc(1, sizeof(gw_plugin_config));
                if (!gw_set_defaults_backend(srv, p, cpv->v.a, gw, 1,
                                             cpk[cpv->k_id].k)) {
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                cpv->v.v = gw;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              }
              case 1: /* scgi.balance */
                cpv->v.u = (unsigned int)gw_get_defaults_balance(srv, cpv->v.b);
                break;
              case 2: /* scgi.debug */
              case 3: /* scgi.map-extensions */
                break;
              case 4: /* scgi.protocol */
                if (buffer_eq_slen(cpv->v.b, CONST_STR_LEN("scgi")))
                    cpv->v.u = LI_PROTOCOL_SCGI;
                else if (buffer_eq_slen(cpv->v.b, CONST_STR_LEN("uwsgi")))
                    cpv->v.u = LI_PROTOCOL_UWSGI;
                else {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected type for key: %s"
                      "expected \"scgi\" or \"uwsgi\"", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* default is 0 */
    /*p->defaults.balance = (unsigned int)gw_get_defaults_balance(srv, NULL);*/
    /*p->defaults.proto   = LI_PROTOCOL_SCGI;*//*(default)*/

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_scgi_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static int scgi_env_add_scgi(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	buffer *env = venv;
	size_t len;

	if (!key || (!val && val_len)) return -1;

	len = key_len + val_len + 2;

	char *dst = buffer_extend(env, len);
	memcpy(dst, key, key_len);
	dst[key_len] = '\0';
	dst += key_len + 1;
	memcpy(dst, val, val_len);
	dst[val_len] = '\0';

	return 0;
}


static int scgi_env_add_uwsgi(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	if (!key || (!val && val_len)) return -1;
	if (key_len > USHRT_MAX || val_len > USHRT_MAX) return -1;

	char *dst = buffer_extend(venv, 2 + key_len + 2 + val_len);
	dst[0] =  key_len       & 0xff; /* little-endian */
	dst[1] = (key_len >> 8) & 0xff;
	memcpy(dst + 2, key, key_len);
	dst += 2+key_len;
	dst[0] =  val_len       & 0xff; /* little-endian */
	dst[1] = (val_len >> 8) & 0xff;
	memcpy(dst + 2, val, val_len);

	return 0;
}


static handler_t scgi_create_env(handler_ctx *hctx) {
	gw_host *host = hctx->host;
	request_st * const r = hctx->r;
	http_cgi_opts opts = { 0, 0, host->docroot, NULL };
	http_cgi_header_append_cb scgi_env_add = hctx->conf.proto == LI_PROTOCOL_SCGI
	  ? scgi_env_add_scgi
	  : scgi_env_add_uwsgi;
	size_t offset;
	size_t rsz = (size_t)(r->read_queue.bytes_out - hctx->wb.bytes_in);
	if (rsz >= 65536) rsz = r->rqst_header_len;
	buffer * const b = chunkqueue_prepend_buffer_open_sz(&hctx->wb, rsz);

        /* save space for 9 digits (plus ':'), though incoming HTTP request
	 * currently limited to 64k (65535, so 5 chars) */
	buffer_copy_string_len(b, CONST_STR_LEN("          "));

	if (0 != http_cgi_headers(r, &opts, scgi_env_add, b)) {
		buffer_clear(b);
		chunkqueue_remove_finished_chunks(&hctx->wb);
		return http_status_set_err(r, 400); /* Bad Request */
	}

	if (hctx->conf.proto == LI_PROTOCOL_SCGI) {
		buffer * const tb = r->tmp_buf;
		size_t len;
		scgi_env_add(b, CONST_STR_LEN("SCGI"), CONST_STR_LEN("1"));
		buffer_clear(tb);
		buffer_append_int(tb, buffer_clen(b)-10);
		buffer_append_char(tb, ':');
		len = buffer_clen(tb);
		offset = 10 - len;
		memcpy(b->ptr+offset, tb->ptr, len);
		buffer_append_char(b, ',');
	} else { /* LI_PROTOCOL_UWSGI */
		/* http://uwsgi-docs.readthedocs.io/en/latest/Protocol.html */
		size_t len = buffer_clen(b)-10;
		if (len > USHRT_MAX) {
			buffer_clear(b);
			chunkqueue_remove_finished_chunks(&hctx->wb);
			return http_status_set_err(r, 431); /* Request Header Fields Too Large */
		}
		offset = 10 - 4;
		b->ptr[offset]   = 0;
		b->ptr[offset+1] =  len       & 0xff; /* little-endian */
		b->ptr[offset+2] = (len >> 8) & 0xff;
		b->ptr[offset+3] = 0;
	}

	hctx->wb_reqlen = buffer_clen(b) - offset;
	chunkqueue_prepend_buffer_commit(&hctx->wb);
	chunkqueue_mark_written(&hctx->wb, offset);
	hctx->wb.bytes_in  -= (off_t)offset;
	hctx->wb.bytes_out -= (off_t)offset;

	if (r->reqbody_length) {
		chunkqueue_append_chunkqueue(&hctx->wb, &r->reqbody_queue);
		if (r->reqbody_length > 0)
			hctx->wb_reqlen += r->reqbody_length; /* total req size */
		else /* as-yet-unknown total request size (Transfer-Encoding: chunked)*/
			hctx->wb_reqlen = -hctx->wb_reqlen;
	}

	plugin_stats_inc("scgi.requests");
	return HANDLER_GO_ON;
}


static handler_t scgi_check_extension(request_st * const r, void *p_d, int uri_path_handler) {
	if (NULL != r->handler_module) return HANDLER_GO_ON;

	plugin_config pconf;
	mod_scgi_patch_config(r, p_d, &pconf);
	if (NULL == pconf.exts) return HANDLER_GO_ON;

	handler_t rc = gw_check_extension(r, &pconf, p_d, uri_path_handler, 0);
	if (HANDLER_GO_ON != rc) return rc;

	const plugin_data * const p = p_d;
	if (r->handler_module == p->self) {
		handler_ctx *hctx = r->plugin_ctx[p->id];
		hctx->opts.backend = BACKEND_SCGI;
		hctx->create_env = scgi_create_env;
		hctx->response = chunk_buffer_acquire();
	}

	return HANDLER_GO_ON;
}

/* uri-path handler */
static handler_t scgi_check_extension_1(request_st * const r, void *p_d) {
	return scgi_check_extension(r, p_d, 1);
}

/* start request handler */
static handler_t scgi_check_extension_2(request_st * const r, void *p_d) {
	return scgi_check_extension(r, p_d, 0);
}


__attribute_cold__
__declspec_dllexport__
int mod_scgi_plugin_init(plugin *p);
int mod_scgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name         = "scgi";

	p->init         = gw_init;
	p->cleanup      = gw_free;
	p->set_defaults = mod_scgi_set_defaults;
	p->handle_request_reset    = gw_handle_request_reset;
	p->handle_uri_clean        = scgi_check_extension_1;
	p->handle_subrequest_start = scgi_check_extension_2;
	p->handle_subrequest       = gw_handle_subrequest;
	p->handle_trigger          = gw_handle_trigger;
	p->handle_waitpid          = gw_handle_waitpid_cb;

	return 0;
}
