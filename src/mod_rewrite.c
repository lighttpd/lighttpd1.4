#include "first.h"

#include "base.h"
#include "keyvalue.h"
#include "log.h"
#include "buffer.h"
#include "burl.h"

#include "plugin.h"
#include "stat_cache.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    pcre_keyvalue_buffer *rewrite;
    pcre_keyvalue_buffer *rewrite_NF;
} plugin_config;

enum { REWRITE_STATE_REWRITTEN = 1024, REWRITE_STATE_FINISHED = 2048}; /*flags*/

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

INIT_FUNC(mod_rewrite_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_rewrite_free) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        /* kvb value might be copied in multiple directives; free only once */
        pcre_keyvalue_buffer *kvb = NULL, *kvb_NF = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* url.rewrite-once */
              case 1: /* url.rewrite-final */
              case 2: /* url.rewrite */
              case 3: /* url.rewrite-repeat */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    kvb = cpv->v.v;
                break;
              case 4: /* url.rewrite-if-not-file */
              case 5: /* url.rewrite-repeat-if-not-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    kvb_NF = cpv->v.v;
              default:
                break;
            }
        }
        if (kvb)    pcre_keyvalue_buffer_free(kvb);
        if (kvb_NF) pcre_keyvalue_buffer_free(kvb_NF);
    }
}

static void mod_rewrite_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* url.rewrite-once */
      case 1: /* url.rewrite-final */
      case 2: /* url.rewrite */
      case 3: /* url.rewrite-repeat */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here in mod_rewrite*/
            pconf->rewrite = cpv->v.v;
        break;
      case 4: /* url.rewrite-if-not-file */
      case 5: /* url.rewrite-repeat-if-not-file */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here in mod_rewrite*/
            pconf->rewrite_NF = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_rewrite_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_rewrite_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_rewrite_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_rewrite_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static pcre_keyvalue_buffer * mod_rewrite_parse_list(server *srv, const array *a, pcre_keyvalue_buffer *kvb, const int condidx) {
    const int pcre_jit = config_feature_bool(srv, "server.pcre_jit", 1);
    int allocated = 0;
    if (NULL == kvb) {
        allocated = 1;
        kvb = pcre_keyvalue_buffer_init();
        kvb->cfgidx = condidx;
    }

    buffer * const tb = srv->tmp_buf;
    int percent = 0;
    for (uint32_t j = 0; j < a->used; ++j) {
        data_string *ds = (data_string *)a->data[j];
        if (srv->srvconf.http_url_normalize) {
            pcre_keyvalue_burl_normalize_key(&ds->key, tb);
            pcre_keyvalue_burl_normalize_value(&ds->value, tb);
        }
        for (const char *s = ds->value.ptr; (s = strchr(s, '%')); ++s) {
            if (s[1] == '%')
                ++s;
            else if (light_isdigit(s[1]) || s[1] == '{') {
                percent |= 1;
                break;
            }
        }
        if (!pcre_keyvalue_buffer_append(srv->errh, kvb, &ds->key, &ds->value,
                                         pcre_jit)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "pcre-compile failed for %s", ds->key.ptr);
            if (allocated) pcre_keyvalue_buffer_free(kvb);
            return NULL;
        }
    }
    if (percent && 0 == kvb->x0)
        kvb->x0 = config_capture(srv, condidx);

    return kvb;
}

SETDEFAULTS_FUNC(mod_rewrite_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("url.rewrite-once"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("url.rewrite-final"),  /* old name => url.rewrite-once */
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("url.rewrite"),        /* old name => url.rewrite-once */
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("url.rewrite-repeat"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("url.rewrite-if-not-file"), /* rewrite-once if ENOENT */
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("url.rewrite-repeat-if-not-file"), /* repeat if ENOENT */
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_rewrite"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        /* parse directives in specific order to encode repeat_idx in kvb->x1 */
        config_plugin_value_t *rewrite_once = NULL, *rewrite_repeat = NULL,
                              *rewrite_NF = NULL,   *rewrite_repeat_NF = NULL,
                              *rewrite = NULL,      *rewrite_final = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* url.rewrite-once */
                rewrite_once = cpv;
                break;
              case 1: /* url.rewrite-final */
                rewrite_final = cpv;
                break;
              case 2: /* url.rewrite */
                rewrite = cpv;
                break;
              case 3: /* url.rewrite-repeat */
                rewrite_repeat = cpv;
                break;
              case 4: /* url.rewrite-if-not-file */
                rewrite_NF = cpv;
                break;
              case 5: /* url.rewrite-repeat-if-not-file */
                rewrite_repeat_NF = cpv;
                break;
              default:/* should not happen */
                break;
            }
        }

        const int condidx = p->cvlist[i].k_id;
        pcre_keyvalue_buffer *kvb = NULL, *kvb_NF = NULL;

        if ((cpv = rewrite_once)) {
            cpv->v.v = mod_rewrite_parse_list(srv, cpv->v.a, kvb, condidx);
            if (NULL == cpv->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
            kvb = cpv->v.v;
        }

        if ((cpv = rewrite_final)) {
            cpv->v.v = mod_rewrite_parse_list(srv, cpv->v.a, kvb, condidx);
            if (NULL == cpv->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
            kvb = cpv->v.v;
        }

        if ((cpv = rewrite)) {
            cpv->v.v = mod_rewrite_parse_list(srv, cpv->v.a, kvb, condidx);
            if (NULL == cpv->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
            kvb = cpv->v.v;
        }

        if (kvb) kvb->x1 = (int)kvb->used; /* repeat_idx */

        if ((cpv = rewrite_repeat)) {
            cpv->v.v = mod_rewrite_parse_list(srv, cpv->v.a, kvb, condidx);
            if (NULL == cpv->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
            /*kvb = cpv->v.v;*/
        }

        if ((cpv = rewrite_NF)) {
            cpv->v.v = mod_rewrite_parse_list(srv, cpv->v.a, kvb_NF, condidx);
            if (NULL == cpv->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
            kvb_NF = cpv->v.v;
        }

        if (kvb_NF) kvb_NF->x1 = (int)kvb_NF->used; /* repeat_idx */

        if ((cpv = rewrite_repeat_NF)) {
            cpv->v.v = mod_rewrite_parse_list(srv, cpv->v.a, kvb_NF, condidx);
            if (NULL == cpv->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
            /*kvb_NF = cpv->v.v;*/
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_rewrite_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

__attribute_cold__
static handler_t process_rewrite_rules_loop_error(request_st * const r, const int cfgidx) {
    if (0 != cfgidx) {
        config_cond_info cfginfo;
        config_get_config_cond_info(&cfginfo, (uint32_t)cfgidx);
        log_error(r->conf.errh, __FILE__, __LINE__,
          "ENDLESS LOOP IN rewrite-rule DETECTED ... aborting request, "
          "perhaps you want to use url.rewrite-once instead of "
          "url.rewrite-repeat (%s)", cfginfo.comp_key);
    }
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
          "ENDLESS LOOP IN rewrite-rule DETECTED ... aborting request");

    return HANDLER_ERROR;
}

URIHANDLER_FUNC(mod_rewrite_con_reset) {
    r->plugin_ctx[((plugin_data *)p_d)->id] = NULL;
    return HANDLER_GO_ON;
}

static handler_t process_rewrite_rules(request_st * const r, const int plid, const pcre_keyvalue_buffer *kvb) {
	struct burl_parts_t burl;
	pcre_keyvalue_ctx ctx;
	handler_t rc;

	if (r->plugin_ctx[plid]) {
		uintptr_t * const hctx = (uintptr_t *)(r->plugin_ctx + plid);
		if (((++*hctx) & 0x1FF) > 100) {
			return process_rewrite_rules_loop_error(r, kvb->cfgidx);
		}
		if (*hctx & REWRITE_STATE_FINISHED) return HANDLER_GO_ON;
	}

	ctx.cache = NULL;
	if (kvb->x0) { /*(kvb->x0 is capture_idx)*/
		ctx.cache = r->cond_match[kvb->x0 - 1];
        }
	ctx.burl = &burl;
	burl.scheme    = &r->uri.scheme;
	burl.authority = &r->uri.authority;
	burl.port      = sock_addr_get_port(&r->con->srv_socket->addr);
	burl.path      = &r->target; /*(uri-encoded and includes query-part)*/
	burl.query     = &r->uri.query;
	if (buffer_is_blank(burl.authority))
		burl.authority = r->server_name;

	buffer * const tb = r->tmp_buf;
	rc = pcre_keyvalue_buffer_process(kvb, &ctx, &r->target, tb);
	if (HANDLER_FINISHED == rc && !buffer_is_blank(tb) && tb->ptr[0] == '/') {
		buffer_copy_buffer(&r->target, tb);
		uintptr_t * const hctx = (uintptr_t *)(r->plugin_ctx + plid);
		*hctx |= REWRITE_STATE_REWRITTEN;
		/*(kvb->x1 is repeat_idx)*/
		if (ctx.m < kvb->x1) *hctx |= REWRITE_STATE_FINISHED;
		buffer_reset(&r->physical.path);
		rc = HANDLER_COMEBACK;
	}
	else if (HANDLER_FINISHED == rc) {
		rc = HANDLER_ERROR;
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "mod_rewrite invalid result (not beginning with '/') "
		  "while processing uri: %s", r->target.ptr);
	}
	else if (HANDLER_ERROR == rc) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "pcre_exec() error "
		  "while processing uri: %s", r->target.ptr);
	}
	return rc;
}

static handler_t mod_rewrite_process (request_st * const r, const plugin_data * const p, const int uri) {
    plugin_config pconf;
    mod_rewrite_patch_config(r, p, &pconf);

    if (uri) {
        if (!pconf.rewrite || !pconf.rewrite->used) return HANDLER_GO_ON;

        return process_rewrite_rules(r, p->id, pconf.rewrite);
    }
    else { /* physical */
        if (!pconf.rewrite_NF || !pconf.rewrite_NF->used) return HANDLER_GO_ON;

        /* skip if physical.path is a regular file */
        const stat_cache_st * const st =
          stat_cache_path_stat(&r->physical.path);
        if (st && S_ISREG(st->st_mode)) return HANDLER_GO_ON;

        return process_rewrite_rules(r, p->id, pconf.rewrite_NF);
    }
}

URIHANDLER_FUNC(mod_rewrite_physical) {
    return NULL != r->handler_module
      ? HANDLER_GO_ON
      : mod_rewrite_process(r, p_d, 0);
}

URIHANDLER_FUNC(mod_rewrite_uri_handler) {
    return mod_rewrite_process(r, p_d, 1);
}


__attribute_cold__
__declspec_dllexport__
int mod_rewrite_plugin_init(plugin *p);
int mod_rewrite_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "rewrite";

	p->init        = mod_rewrite_init;
	/* it has to stay _raw as we are matching on uri + querystring
	 */

	p->handle_uri_raw = mod_rewrite_uri_handler;
	p->handle_physical = mod_rewrite_physical;
	p->cleanup     = mod_rewrite_free;
	p->handle_request_reset = mod_rewrite_con_reset;
	p->set_defaults = mod_rewrite_set_defaults;

	return 0;
}
