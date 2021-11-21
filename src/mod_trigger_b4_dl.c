#include "first.h"

#include "plugin.h"


#if defined(HAVE_GDBM_H) || defined(USE_MEMCACHED) /* at least one required */


#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"
#include "keyvalue.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_GDBM_H)
#include "fdevent.h"
# include <gdbm.h>
#endif

#if defined(USE_MEMCACHED)
# include <libmemcached/memcached.h>
#endif

/**
 * this is a trigger_b4_dl for a lighttpd plugin
 *
 */

typedef struct {
    const buffer *deny_url;
    pcre_keyvalue_buffer *trigger_regex;
    pcre_keyvalue_buffer *download_regex;
  #if defined(HAVE_GDBM_H)
    GDBM_FILE db;
  #endif
  #if defined(USE_MEMCACHED)
    memcached_st *memc;
    const buffer *mc_namespace;
  #endif
    unsigned short trigger_timeout;
    unsigned short debug;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_trigger_b4_dl_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_trigger_b4_dl_free) {
    plugin_data *p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
             #if defined(HAVE_GDBM_H)
              case 0: /* trigger-before-download.gdbm-filename */
                gdbm_close(cpv->v.v);
                break;
             #endif
              case 1: /* trigger-before-download.trigger-url */
                pcre_keyvalue_buffer_free(cpv->v.v);
                break;
              case 2: /* trigger-before-download.download-url */
                pcre_keyvalue_buffer_free(cpv->v.v);
                break;
             #if defined(USE_MEMCACHED)
              case 5: /* trigger-before-download.memcache-hosts */
                memcached_free(cpv->v.v);
                break;
             #endif
              default:
                break;
            }
        }
    }
}

static int mod_trigger_b4_dl_init_gdbm(server * const srv, config_plugin_value_t * const cpv) {
    if (buffer_is_blank(cpv->v.b)) {
        cpv->v.v = NULL;
        return 1;
    }

  #if defined(HAVE_GDBM_H)

    GDBM_FILE db = gdbm_open(cpv->v.b->ptr, 4096, GDBM_WRCREAT | GDBM_NOLOCK,
                             S_IRUSR | S_IWUSR, 0);

    if (db) {
        cpv->v.v = db;
        cpv->vtype = T_CONFIG_LOCAL;
        fdevent_setfd_cloexec(gdbm_fdesc(db));
        return 1;
    }
    else {
        log_error(srv->errh, __FILE__, __LINE__,
                  "gdbm-open failed %s", cpv->v.b->ptr);
        return 0;
    }

  #else

    UNUSED(srv);
    return 1;

  #endif
}

static int mod_trigger_b4_dl_init_memcached(server * const srv, config_plugin_value_t * const cpv) {
    const array * const mc_hosts = cpv->v.a;
    if (0 == mc_hosts->used) {
        cpv->v.v = NULL;
        return 1;
    }

  #if defined(USE_MEMCACHED)

    buffer * const opts = srv->tmp_buf;
    buffer_clear(opts);
    for (uint32_t k = 0; k < mc_hosts->used; ++k) {
        const data_string * const ds = (const data_string *)mc_hosts->data[k];
        buffer_append_str2(opts, CONST_STR_LEN(" --SERVER="),
                                 BUF_PTR_LEN(&ds->value));
    }

    cpv->v.v = memcached(opts->ptr+1, buffer_clen(opts)-1);

    if (cpv->v.v) {
        cpv->vtype = T_CONFIG_LOCAL;
        return 1;
    }
    else {
        log_error(srv->errh, __FILE__, __LINE__,
          "configuring memcached failed for option string: %s", opts->ptr);
        return 0;
    }

  #else

    log_error(srv->errh, __FILE__, __LINE__,
      "memcache support is not compiled in but "
      "trigger-before-download.memcache-hosts is set; aborting");
    return 0;

  #endif
}

static int mod_trigger_b4_dl_init_regex(server * const srv, config_plugin_value_t * const cpv, const char * const str) {
    const buffer * const b = cpv->v.b;
    if (buffer_is_blank(b)) {
        cpv->v.v = NULL;
        return 1;
    }

    const int pcre_jit = config_feature_bool(srv, "server.pcre_jit", 1);
    pcre_keyvalue_buffer * const kvb = pcre_keyvalue_buffer_init();
    buffer empty = { NULL, 0, 0 };
    if (!pcre_keyvalue_buffer_append(srv->errh, kvb, b, &empty, pcre_jit)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "pcre_compile failed for %s %s", str, b->ptr);
        pcre_keyvalue_buffer_free(kvb);
        return 0;
    }
    cpv->v.v = kvb;
    cpv->vtype = T_CONFIG_LOCAL;
    return 1;
}

#ifdef __COVERITY__
#include "burl.h"
#endif

static int mod_trigger_b4_dl_match(pcre_keyvalue_buffer * const kvb, const buffer * const input) {
    /*(re-use keyvalue.[ch] for match-only;
     *  must have been configured with empty kvb 'value' during init)*/
    pcre_keyvalue_ctx ctx = { NULL, NULL, -1, 0, NULL, NULL };
  #ifdef __COVERITY__
    /*(again, must have been configured w/ empty kvb 'value' during init)*/
    struct cond_match_t cache;
    memset(&cache, 0, sizeof(cache));
    struct burl_parts_t bp;
    memset(&bp, 0, sizeof(bp));
    ctx.cache = &cache;
    ctx.burl = &bp;
  #endif
    return HANDLER_GO_ON == pcre_keyvalue_buffer_process(kvb, &ctx, input, NULL)
        && -1 != ctx.m;
}

static void mod_trigger_b4_dl_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* trigger-before-download.gdbm-filename */
       #if defined(HAVE_GDBM_H)
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->db = cpv->v.v;
       #endif
        break;
      case 1: /* trigger-before-download.trigger-url */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->trigger_regex = cpv->v.v;
        break;
      case 2: /* trigger-before-download.download-url */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->download_regex = cpv->v.v;
        break;
      case 3: /* trigger-before-download.deny-url */
        pconf->deny_url = cpv->v.b;
        break;
      case 4: /* trigger-before-download.trigger-timeout */
        pconf->trigger_timeout = cpv->v.shrt;
        break;
      case 5: /* trigger-before-download.memcache-hosts */
       #if defined(USE_MEMCACHED)
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->memc = cpv->v.v;
       #endif
        break;
      case 6: /* trigger-before-download.memcache-namespace */
       #if defined(USE_MEMCACHED)
        pconf->mc_namespace = cpv->v.b;
       #endif
        break;
      case 7: /* trigger-before-download.debug */
        pconf->debug = cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_trigger_b4_dl_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_trigger_b4_dl_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_trigger_b4_dl_patch_config(request_st * const r, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_trigger_b4_dl_merge_config(&p->conf,
                                           p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_trigger_b4_dl_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("trigger-before-download.gdbm-filename"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.trigger-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.download-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.deny-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.trigger-timeout"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.memcache-hosts"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.memcache-namespace"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("trigger-before-download.debug"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_trigger_b4_dl"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* trigger-before-download.gdbm-filename */
                if (!mod_trigger_b4_dl_init_gdbm(srv, cpv))
                    return HANDLER_ERROR;
                break;
              case 1: /* trigger-before-download.trigger-url */
                if (!mod_trigger_b4_dl_init_regex(srv, cpv, "trigger-url"))
                    return HANDLER_ERROR;
                break;
              case 2: /* trigger-before-download.download-url */
                if (!mod_trigger_b4_dl_init_regex(srv, cpv, "download-url"))
                    return HANDLER_ERROR;
                break;
              case 3: /* trigger-before-download.deny-url */
              case 4: /* trigger-before-download.trigger-timeout */
                break;
              case 5: /* trigger-before-download.memcache-hosts */
                if (!mod_trigger_b4_dl_init_memcached(srv, cpv))
                    return HANDLER_ERROR;
                break;
              case 6: /* trigger-before-download.memcache-namespace */
              case 7: /* trigger-before-download.debug */
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
            mod_trigger_b4_dl_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

#if defined(USE_MEMCACHED)
static void mod_trigger_b4_dl_memcached_key(buffer * const b, const plugin_data * const p, const buffer * const remote_ip) {
    buffer_clear(b);
    if (p->conf.mc_namespace)
        buffer_copy_buffer(b, p->conf.mc_namespace);
    buffer_append_string_buffer(b, remote_ip);

    /* memcached can't handle spaces */
    for (size_t i = 0, len = buffer_clen(b); i < len; ++i) {
        if (b->ptr[i] == ' ') b->ptr[i] = '-';
    }
}
#endif

static handler_t mod_trigger_b4_dl_deny(request_st * const r, const plugin_data * const p) {
    if (p->conf.deny_url) {
        http_header_response_set(r, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 BUF_PTR_LEN(p->conf.deny_url));
        r->http_status = 307;
    }
    else {
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "trigger-before-download.deny-url not configured");
        r->http_status = 500;
    }
    r->resp_body_finished = 1;
    return HANDLER_FINISHED;
}

URIHANDLER_FUNC(mod_trigger_b4_dl_uri_handler) {
	plugin_data *p = p_d;

	if (NULL != r->handler_module) return HANDLER_GO_ON;

	mod_trigger_b4_dl_patch_config(r, p);

	if (!p->conf.trigger_regex || !p->conf.download_regex) return HANDLER_GO_ON;

# if !defined(HAVE_GDBM_H) && !defined(USE_MEMCACHED)
	return HANDLER_GO_ON;
# elif defined(HAVE_GDBM_H) && defined(USE_MEMCACHED)
	if (!p->conf.db && !p->conf.memc) return HANDLER_GO_ON;
	if (p->conf.db && p->conf.memc) {
		/* can't decide which one */

		return HANDLER_GO_ON;
	}
# elif defined(HAVE_GDBM_H)
	if (!p->conf.db) return HANDLER_GO_ON;
# else
	if (!p->conf.memc) return HANDLER_GO_ON;
# endif

	/* X-Forwarded-For contains the ip behind the proxy */
	const buffer *remote_ip =
	  http_header_request_get(r, HTTP_HEADER_X_FORWARDED_FOR,
	                          CONST_STR_LEN("X-Forwarded-For"));
	if (NULL == remote_ip) {
		remote_ip = &r->con->dst_addr_buf;
	}

	if (p->conf.debug) {
		log_error(r->conf.errh, __FILE__, __LINE__, "(debug) remote-ip: %s", remote_ip->ptr);
	}

	const unix_time64_t cur_ts = log_epoch_secs;

	/* check if URL is a trigger -> insert IP into DB */
	if (mod_trigger_b4_dl_match(p->conf.trigger_regex, &r->uri.path)) {
		/* the trigger matched */
# if defined(HAVE_GDBM_H)
		if (p->conf.db) {
			datum key, val;

			*(const char **)&key.dptr = remote_ip->ptr;
			key.dsize = buffer_clen(remote_ip);

			val.dptr = (char *)&cur_ts;
			val.dsize = sizeof(cur_ts);

			if (0 != gdbm_store(p->conf.db, key, val, GDBM_REPLACE)) {
				log_error(r->conf.errh, __FILE__, __LINE__, "insert failed");
			}
		}
# endif
# if defined(USE_MEMCACHED)
		if (p->conf.memc) {
			buffer * const b = r->tmp_buf;
			mod_trigger_b4_dl_memcached_key(b, p, remote_ip);

			if (p->conf.debug) {
				log_error(r->conf.errh, __FILE__, __LINE__, "(debug) triggered IP: %s", b->ptr);
			}

			if (MEMCACHED_SUCCESS != memcached_set(p->conf.memc,
					BUF_PTR_LEN(b),
					(const char *)&cur_ts, sizeof(cur_ts),
					p->conf.trigger_timeout, 0)) {
				log_error(r->conf.errh, __FILE__, __LINE__, "insert failed");
			}
		}
# endif
	}

	/* check if URL is a download -> check IP in DB, update timestamp */
	if (mod_trigger_b4_dl_match(p->conf.download_regex, &r->uri.path)) {
		/* the download uri matched */
# if defined(HAVE_GDBM_H)
		if (p->conf.db) {
			datum key, val;
			unix_time64_t last_hit = 0;

			*(const char **)&key.dptr = remote_ip->ptr;
			key.dsize = buffer_clen(remote_ip);

			val = gdbm_fetch(p->conf.db, key);

			if (val.dptr == NULL) {
				/* not found, redirect */
				return mod_trigger_b4_dl_deny(r, p);
			}

			if (val.dsize == sizeof(last_hit))
				memcpy(&last_hit, val.dptr, val.dsize);
			else if (val.dsize == 4) {
				int32_t t;
				memcpy(&t, val.dptr, val.dsize);
				last_hit = t;
			}

			free(val.dptr);

			if (cur_ts - last_hit > p->conf.trigger_timeout) {
				/* found, but timeout, redirect */

				if (p->conf.db) {
					if (0 != gdbm_delete(p->conf.db, key)) {
						log_error(r->conf.errh, __FILE__, __LINE__, "delete failed");
					}
				}

				return mod_trigger_b4_dl_deny(r, p);
			}

			val.dptr = (char *)&cur_ts;
			val.dsize = sizeof(cur_ts);

			if (0 != gdbm_store(p->conf.db, key, val, GDBM_REPLACE)) {
				log_error(r->conf.errh, __FILE__, __LINE__, "insert failed");
			}
		}
# endif
# if defined(USE_MEMCACHED)
		if (p->conf.memc) {
			buffer * const b = r->tmp_buf;
			mod_trigger_b4_dl_memcached_key(b, p, remote_ip);

			if (p->conf.debug) {
				log_error(r->conf.errh, __FILE__, __LINE__, "(debug) checking IP: %s", b->ptr);
			}

			/**
			 *
			 * memcached is do expiration for us, as long as we can fetch it every thing is ok
			 * and the timestamp is updated
			 *
			 */
			if (MEMCACHED_SUCCESS != memcached_exist(p->conf.memc, BUF_PTR_LEN(b))) {
				return mod_trigger_b4_dl_deny(r, p);
			}

			/* set a new timeout */
			if (MEMCACHED_SUCCESS != memcached_set(p->conf.memc,
					BUF_PTR_LEN(b),
					(const char *)&cur_ts, sizeof(cur_ts),
					p->conf.trigger_timeout, 0)) {
				log_error(r->conf.errh, __FILE__, __LINE__, "insert failed");
			}
		}
# endif
	}

	return HANDLER_GO_ON;
}

#if defined(HAVE_GDBM_H)
static void mod_trigger_b4_dl_trigger_gdbm(GDBM_FILE db, const unix_time64_t cur_ts, const int trigger_timeout) {
		datum key, val, okey;
		okey.dptr = NULL;

		/* according to the manual this loop + delete does delete all entries on its way
		 *
		 * we don't care as the next round will remove them. We don't have to perfect here.
		 */
		for (key = gdbm_firstkey(db); key.dptr; key = gdbm_nextkey(db, okey)) {
			unix_time64_t last_hit = 0;
			if (okey.dptr) {
				free(okey.dptr);
				okey.dptr = NULL;
			}

			val = gdbm_fetch(db, key);

			if (val.dsize == sizeof(last_hit))
				memcpy(&last_hit, val.dptr, val.dsize);
			else if (val.dsize == 4) {
				int32_t t;
				memcpy(&t, val.dptr, val.dsize);
				last_hit = t;
			}

			free(val.dptr);

			if (cur_ts - last_hit > trigger_timeout) {
				gdbm_delete(db, key);
			}

			okey = key;
		}
		if (okey.dptr) free(okey.dptr);

		/* reorg once a day */
		if ((cur_ts % (60 * 60 * 24) == 0)) gdbm_reorganize(db);
}

TRIGGER_FUNC(mod_trigger_b4_dl_handle_trigger) {
    /* check DB each minute */
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts % 60 != 0) return HANDLER_GO_ON;
    UNUSED(srv);

    plugin_data * const p = p_d;

    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        void *db = NULL;
        int timeout = (int)p->defaults.trigger_timeout;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* trigger-before-download.gdbm-filename */
                if (cpv->vtype == T_CONFIG_LOCAL && NULL != cpv->v.v)
                    db = cpv->v.v;
                break;
              case 4: /* trigger-before-download.trigger-timeout */
                timeout = (int)cpv->v.shrt;
                break;
              default:
                break;
            }
        }
        if (db)
            mod_trigger_b4_dl_trigger_gdbm(db, cur_ts, timeout);
    }

    return HANDLER_GO_ON;
}
#endif


#endif /* defined(HAVE_GDBM_H) || defined(USE_MEMCACHED) */


int mod_trigger_b4_dl_plugin_init(plugin *p);
int mod_trigger_b4_dl_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "trigger_b4_dl";

#if defined(HAVE_GDBM_H) || defined(USE_MEMCACHED) /* at least one required */

	p->init        = mod_trigger_b4_dl_init;
	p->handle_uri_clean  = mod_trigger_b4_dl_uri_handler;
	p->set_defaults  = mod_trigger_b4_dl_set_defaults;
#if defined(HAVE_GDBM_H)
	p->handle_trigger  = mod_trigger_b4_dl_handle_trigger;
#endif
	p->cleanup     = mod_trigger_b4_dl_free;

#endif

	return 0;
}
