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
#include "log.h"
#include "status_counter.h"

#include "sys-endian.h"

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

static void mod_scgi_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_scgi_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_scgi_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("scgi.server"),
        T_CONFIG_ARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.balance"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.debug"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("scgi.map-extensions"),
        T_CONFIG_ARRAY,
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
                gw_plugin_config *gw = calloc(1, sizeof(gw_plugin_config));
                force_assert(gw);
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
                break;
              case 3: /* scgi.map-extensions */
                if (!array_is_kvstring(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s; "
                      "expected list of \"suffix\" => \"subst\"",
                      cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
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
	char *dst;
	size_t len;

	if (!key || !val) return -1;

	len = key_len + val_len + 2;

	if (buffer_string_space(env) < len) {
		size_t extend = env->size * 2 - buffer_string_length(env);
		extend = extend > len ? extend : len + 4095;
		buffer_string_prepare_append(env, extend);
	}

	dst = buffer_string_prepare_append(env, len);
	memcpy(dst, key, key_len);
	dst[key_len] = '\0';
	memcpy(dst + key_len + 1, val, val_len);
	dst[key_len + 1 + val_len] = '\0';
	buffer_commit(env, len);

	return 0;
}


#ifdef __LITTLE_ENDIAN__
#define uwsgi_htole16(x) (x)
#else /* __BIG_ENDIAN__ */
#define uwsgi_htole16(x) ((uint16_t) (((x) & 0xff) << 8 | ((x) & 0xff00) >> 8))
#endif


static int scgi_env_add_uwsgi(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	buffer *env = venv;
	char *dst;
	size_t len;
	uint16_t uwlen;

	if (!key || !val) return -1;
	if (key_len > USHRT_MAX || val_len > USHRT_MAX) return -1;

	len = 2 + key_len + 2 + val_len;

	if (buffer_string_space(env) < len) {
		size_t extend = env->size * 2 - buffer_string_length(env);
		extend = extend > len ? extend : len + 4095;
		buffer_string_prepare_append(env, extend);
	}

	dst = buffer_string_prepare_append(env, len);
	uwlen = uwsgi_htole16((uint16_t)key_len);
	memcpy(dst, (char *)&uwlen, 2);
	memcpy(dst + 2, key, key_len);
	uwlen = uwsgi_htole16((uint16_t)val_len);
	memcpy(dst + 2 + key_len, (char *)&uwlen, 2);
	memcpy(dst + 2 + key_len + 2, val, val_len);
	buffer_commit(env, len);

	return 0;
}


static handler_t scgi_create_env(handler_ctx *hctx) {
	gw_host *host = hctx->host;
	connection *con = hctx->remote_conn;
	http_cgi_opts opts = { 0, 0, host->docroot, NULL };
	http_cgi_header_append_cb scgi_env_add = hctx->conf.proto == LI_PROTOCOL_SCGI
	  ? scgi_env_add_scgi
	  : scgi_env_add_uwsgi;
	size_t offset;
	size_t rsz = (size_t)(con->read_queue->bytes_out - hctx->wb->bytes_in);
	buffer * const b = chunkqueue_prepend_buffer_open_sz(hctx->wb, rsz < 65536 ? rsz : con->header_len);

        /* save space for 9 digits (plus ':'), though incoming HTTP request
	 * currently limited to 64k (65535, so 5 chars) */
	buffer_copy_string_len(b, CONST_STR_LEN("          "));

	if (0 != http_cgi_headers(con, &opts, scgi_env_add, b)) {
		con->http_status = 400;
		con->mode = DIRECT;
		buffer_clear(b);
		chunkqueue_remove_finished_chunks(hctx->wb);
		return HANDLER_FINISHED;
	}

	if (hctx->conf.proto == LI_PROTOCOL_SCGI) {
		buffer * const tb = con->srv->tmp_buf;
		size_t len;
		scgi_env_add(b, CONST_STR_LEN("SCGI"), CONST_STR_LEN("1"));
		buffer_clear(tb);
		buffer_append_int(tb, buffer_string_length(b)-10);
		buffer_append_string_len(tb, CONST_STR_LEN(":"));
		len = buffer_string_length(tb);
		offset = 10 - len;
		memcpy(b->ptr+offset, tb->ptr, len);
		buffer_append_string_len(b, CONST_STR_LEN(","));
	} else { /* LI_PROTOCOL_UWSGI */
		/* http://uwsgi-docs.readthedocs.io/en/latest/Protocol.html */
		size_t len = buffer_string_length(b)-10;
		uint32_t uwsgi_header;
		if (len > USHRT_MAX) {
			con->http_status = 431; /* Request Header Fields Too Large */
			con->mode = DIRECT;
			buffer_clear(b);
			chunkqueue_remove_finished_chunks(hctx->wb);
			return HANDLER_FINISHED;
		}
		offset = 10 - 4;
		uwsgi_header = ((uint32_t)uwsgi_htole16((uint16_t)len)) << 8;
		memcpy(b->ptr+offset, (char *)&uwsgi_header, 4);
	}

	hctx->wb_reqlen = buffer_string_length(b) - offset;
	chunkqueue_prepend_buffer_commit(hctx->wb);
      #if 0
	hctx->wb->first->offset += (off_t)offset;
	hctx->wb->bytes_in -= (off_t)offset;
      #else
	chunkqueue_mark_written(hctx->wb, offset);
      #endif

	if (con->request.content_length) {
		chunkqueue_append_chunkqueue(hctx->wb, con->request_content_queue);
		if (con->request.content_length > 0)
			hctx->wb_reqlen += con->request.content_length; /* total req size */
		else /* as-yet-unknown total request size (Transfer-Encoding: chunked)*/
			hctx->wb_reqlen = -hctx->wb_reqlen;
	}

	status_counter_inc(CONST_STR_LEN("scgi.requests"));
	return HANDLER_GO_ON;
}


static handler_t scgi_check_extension(connection *con, void *p_d, int uri_path_handler) {
	plugin_data *p = p_d;
	handler_t rc;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	mod_scgi_patch_config(con, p);
	if (NULL == p->conf.exts) return HANDLER_GO_ON;

	rc = gw_check_extension(con, p, uri_path_handler, 0);
	if (HANDLER_GO_ON != rc) return rc;

	if (con->mode == p->id) {
		handler_ctx *hctx = con->plugin_ctx[p->id];
		hctx->opts.backend = BACKEND_SCGI;
		hctx->create_env = scgi_create_env;
		hctx->response = chunk_buffer_acquire();
	}

	return HANDLER_GO_ON;
}

/* uri-path handler */
static handler_t scgi_check_extension_1(connection *con, void *p_d) {
	return scgi_check_extension(con, p_d, 1);
}

/* start request handler */
static handler_t scgi_check_extension_2(connection *con, void *p_d) {
	return scgi_check_extension(con, p_d, 0);
}



int mod_scgi_plugin_init(plugin *p);
int mod_scgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name         = "scgi";

	p->init         = gw_init;
	p->cleanup      = gw_free;
	p->set_defaults = mod_scgi_set_defaults;
	p->connection_reset        = gw_connection_reset;
	p->handle_uri_clean        = scgi_check_extension_1;
	p->handle_subrequest_start = scgi_check_extension_2;
	p->handle_subrequest       = gw_handle_subrequest;
	p->handle_trigger          = gw_handle_trigger;
	p->handle_waitpid          = gw_handle_waitpid_cb;

	return 0;
}
