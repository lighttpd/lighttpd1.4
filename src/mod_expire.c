#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"
#include "http_date.h"
#include "http_header.h"

#include "plugin.h"
#include "stat_cache.h"

#include "sys-time.h"
#include <stdlib.h>
#include <string.h>

/**
 * set HTTP headers Cache-Control and Expires
 */

typedef struct {
    const array *expire_url;
    const array *expire_mimetypes;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    time_t *toffsets;
    uint32_t tused;
} plugin_data;

INIT_FUNC(mod_expire_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_expire_free) {
    plugin_data * const p = p_d;
    free(p->toffsets);
}

__attribute_noinline__
static time_t mod_expire_get_offset (const char *ts, time_t *mod) {
    /* (access|now|modification) [plus] {<num> <unit>}*
     * e.g. 'access 3 months' */

    *mod = 0;
    if (0 == strncmp(ts, "access ", 7))
        ts   += 7;
    else if (0 == strncmp(ts, "now ", 4))
        ts   += 4;
    else if ((*mod = (0 == strncmp(ts, "modification ", 13))))
        ts   += 13;
    else
        return (*mod = -1);

    if (0 == strncmp(ts, "plus ", 5))
        ts   += 5; /* skip optional plus */

    static const struct expire_units {
      const char *str;
      uint32_t len;
      int32_t mult;
    } expire_units[] = { /*(list longest match first)*/
      { "year",   sizeof("year")-1,   60 * 60 * 24 * 365 }
     ,{ "month",  sizeof("month")-1,  60 * 60 * 24 * 30 }
     ,{ "week",   sizeof("week")-1,   60 * 60 * 24 * 7 }
     ,{ "day",    sizeof("day")-1,    60 * 60 * 24 }
     ,{ "hour",   sizeof("hour")-1,   60 * 60 }
     ,{ "minute", sizeof("minute")-1, 60 }
     ,{ "min",    sizeof("min")-1,    60 }
     ,{ "second", sizeof("second")-1, 1 }
     ,{ "sec",    sizeof("sec")-1,    1 }
     ,{ NULL,     0,                  0 }
    };

    /* <num> (years|months|weeks|days|hours|minutes|seconds) */
    time_t offset = 0;
    do {
        /*(note: not checking num validity; missing num treated as 0)*/
        /*(note: not enforcing space between nums and units)*/
        char *err;
        long num = strtol(ts, &err, 10);
        ts = err;
        while (*ts == ' ') ++ts;
        const struct expire_units *units = expire_units;
        while (units->str && 0 != strncmp(ts, units->str, units->len)) ++units;
        if (units->str == NULL)
            return (*mod = -1);
        offset += num * units->mult;
        ts += units->len;
        if (*ts == 's') ++ts; /* strip plural */
        while (*ts == ' ') ++ts;
    } while (*ts);
    return offset;
}

static void mod_expire_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* expire.url */
        pconf->expire_url = cpv->v.a;
        break;
      case 1: /* expire.mimetypes */
        pconf->expire_mimetypes = cpv->v.a;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_expire_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_expire_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_expire_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_expire_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_expire_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("expire.url"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("expire.mimetypes"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_expire"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            const array *a = NULL;
            switch (cpv->k_id) {
              case 0: /* expire.url */
                a = cpv->v.a;
                break;
              case 1: /* expire.mimetypes */
                for (uint32_t k = 0; k < cpv->v.a->used; ++k) {
                    data_string *ds = (data_string *)cpv->v.a->data[k];
                    /*(omit trailing '*', if present, from prefix match)*/
                    /*(not usually a good idea to modify array keys
                     * since doing so might break array_get_element_klen()
                     * search; config should be consistent in using * or not)*/
                    size_t klen = buffer_clen(&ds->key);
                    if (klen && ds->key.ptr[klen-1] == '*')
                        buffer_truncate(&ds->key, klen-1);
                }
                a = cpv->v.a;
                if (!array_get_element_klen(a, CONST_STR_LEN("text/javascript"))
                    && !array_get_element_klen(a, CONST_STR_LEN("text/"))) {
                    array *m;
                    *(const array **)&m = a;
                    data_unset * const du =
                      array_extract_element_klen(m,
                        CONST_STR_LEN("application/javascript"));
                    if (du) {
                        buffer_copy_string_len(&du->key, "text/javascript", 15);
                        array_replace(m, du);
                    }
                }
                break;
              default:/* should not happen */
                continue;
            }

            /* parse array values into structured data */
            if (NULL != a && a->used) {
                ck_realloc_u32((void **)&p->toffsets, p->tused,
                               a->used*2, sizeof(*p->toffsets));
                time_t *toff = p->toffsets + p->tused;
                for (uint32_t k = 0; k < a->used; ++k, toff+=2, p->tused+=2) {
                    buffer *v = &((data_string *)a->data[k])->value;
                    toff[1] = mod_expire_get_offset(v->ptr, &toff[0]);
                    if ((time_t)-1 == *toff) {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "invalid %s = \"%s\"", cpk[cpv->k_id].k, v->ptr);
                        return HANDLER_ERROR;
                    }
                    /* overwrite v->used with offset int p->toffsets
                     * as v->ptr is not used by this module after config */
                    v->used = (uint32_t)p->tused;
                }
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_expire_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static handler_t
mod_expire_set_header (request_st * const r, const time_t * const off)
{
    const unix_time64_t cur_ts = log_epoch_secs;
    unix_time64_t expires = off[1];
    if (0 == off[0]) { /* access */
        expires += cur_ts;
    }
    else {             /* modification */
      #if 1
        const stat_cache_st * const st = stat_cache_path_stat(&r->physical.path);
      #else
        /* do not use r->tmp_sce here; r->tmp_sce could have been
         * invalidated between request start and response start */
        const stat_cache_st * const st =
	  (r->tmp_sce && buffer_is_equal(&r->tmp_sce->name, &r->physical.path))
	  ? &r->tmp_sce->st
	  : stat_cache_path_stat(&r->physical.path);
      #endif
        /* can't set modification-based expire if mtime is not available */
        if (NULL == st) return HANDLER_GO_ON;
        expires += TIME64_CAST(st->st_mtime);
        /* expires should be at least cur_ts */
        if (expires < cur_ts) expires = cur_ts;
    }

    /* HTTP/1.1 dictates that Cache-Control overrides Expires if both present.
     * Therefore, send only Cache-Control to HTTP/1.1 requests.  This means
     * that if an intermediary upgraded the request to HTTP/1.1, and the actual
     * client sent HTTP/1.0, then the actual client might not understand
     * Cache-Control when it may have understood Expires.  RFC 2616 HTTP/1.1
     * was released June 1999, almost 22 years ago (as this comment is written).
     * If a client today is sending HTTP/1.0, chances are the client does not
     * cache.  Avoid the overhead of formatting time for Expires to send both
     * Cache-Control and Expires when the majority of clients are HTTP/1.1 or
     * HTTP/2 (or later). */
    buffer *vb;
    if (r->http_version > HTTP_VERSION_1_0) {
        vb = http_header_response_set_ptr(r, HTTP_HEADER_CACHE_CONTROL,
                                          CONST_STR_LEN("Cache-Control"));
        buffer_append_string_len(vb, CONST_STR_LEN("max-age="));
        buffer_append_int(vb, expires - cur_ts);
    }
    else { /* HTTP/1.0 */
        vb = http_header_response_set_ptr(r, HTTP_HEADER_EXPIRES,
                                          CONST_STR_LEN("Expires"));
        http_date_time_append(vb, expires);
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_expire_handler) {
	buffer *vb;
	const data_string *ds;

	/* Add caching headers only to http_status 200 OK or 206 Partial Content */
	if (r->http_status != 200 && r->http_status != 206)
		return HANDLER_GO_ON;
	/* Add caching headers only to GET, HEAD, QUERY requests */
	if (!http_method_get_head_query(r->http_method)) return HANDLER_GO_ON;
	/* Add caching headers only if not already present */
	if (light_btst(r->resp_htags, HTTP_HEADER_CACHE_CONTROL))
		return HANDLER_GO_ON;

	plugin_config pconf;
	mod_expire_patch_config(r, p_d, &pconf);

	/* check expire.url */
	ds = pconf.expire_url
	  ? (const data_string *)array_match_key_prefix(pconf.expire_url, &r->uri.path)
	  : NULL;
	/* check expire.mimetypes (if no match with expire.url) */
	if (NULL == ds) {
		if (NULL == pconf.expire_mimetypes) return HANDLER_GO_ON;
		vb = http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"));
		if (NULL != vb)
			ds = (const data_string *)
			     array_match_key_prefix(pconf.expire_mimetypes, vb);
		if (NULL == ds) {
			ds = (const data_string *)
			     array_get_element_klen(pconf.expire_mimetypes,
			                            CONST_STR_LEN(""));
			if (NULL == ds) return HANDLER_GO_ON;
		}
	}

	const plugin_data * const p = p_d;
	return mod_expire_set_header(r, p->toffsets + ds->value.used);
}


__attribute_cold__
__declspec_dllexport__
int mod_expire_plugin_init(plugin *p);
int mod_expire_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "expire";

	p->init        = mod_expire_init;
	p->cleanup     = mod_expire_free;
	p->set_defaults= mod_expire_set_defaults;
	p->handle_response_start = mod_expire_handler;

	return 0;
}
