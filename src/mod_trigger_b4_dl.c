#include "first.h"

#include "plugin.h"


#if defined(HAVE_PCRE_H)                /* do nothing if PCRE not available */
#if defined(HAVE_GDBM_H) || defined(USE_MEMCACHED) /* at least one required */


#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_header.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_GDBM_H)
#include "fdevent.h"
# include <gdbm.h>
#endif

#if defined(HAVE_PCRE_H)
# include <pcre.h>
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
    pcre *trigger_regex;
    pcre *download_regex;
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

static void mod_trigger_b4_dl_free_config(plugin_data * const p) {
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
                pcre_free(cpv->v.v);
                break;
              case 2: /* trigger-before-download.download-url */
                pcre_free(cpv->v.v);
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
    if (buffer_string_is_empty(cpv->v.b)) {
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
        buffer_append_string_len(opts, CONST_STR_LEN(" --SERVER="));
        buffer_append_string_buffer(opts, &ds->value);
    }

    cpv->v.v = memcached(opts->ptr+1, buffer_string_length(opts)-1);

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
    if (buffer_string_is_empty(b)) {
        cpv->v.v = NULL;
        return 1;
    }

    const char *errptr;
    int erroff;
    cpv->v.v = pcre_compile(b->ptr, 0, &errptr, &erroff, NULL);

    if (cpv->v.v) {
        cpv->vtype = T_CONFIG_LOCAL;
        return 1;
    }
    else {
        log_error(srv->errh, __FILE__, __LINE__,
          "compiling regex for %s failed: %s pos: %d",
          str, b->ptr, erroff);
        return 0;
    }
}

FREE_FUNC(mod_trigger_b4_dl_free) {
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;
    UNUSED(srv);

    mod_trigger_b4_dl_free_config(p);

    free(p->cvlist);
    free(p);

    return HANDLER_GO_ON;
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

static void mod_trigger_b4_dl_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
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
        T_CONFIG_ARRAY,
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
                if (!array_is_vlist(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s; "
                      "expected list of \"host\"", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
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
    for (size_t i = 0, len = buffer_string_length(b); i < len; ++i) {
        if (b->ptr[i] == ' ') b->ptr[i] = '-';
    }
}
#endif

static handler_t mod_trigger_b4_dl_deny(connection * const con, const plugin_data * const p) {
    if (p->conf.deny_url) {
        http_header_response_set(con, HTTP_HEADER_LOCATION,
                                 CONST_STR_LEN("Location"),
                                 CONST_BUF_LEN(p->conf.deny_url));
        con->http_status = 307;
    }
    else {
        log_error(con->errh, __FILE__, __LINE__,
                  "trigger-before-download.deny-url not configured");
        con->http_status = 500;
    }
    con->file_finished = 1;
    return HANDLER_FINISHED;
}

URIHANDLER_FUNC(mod_trigger_b4_dl_uri_handler) {
	plugin_data *p = p_d;

	int n;
# define N 10
	int ovec[N * 3];

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	if (buffer_is_empty(con->uri.path)) return HANDLER_GO_ON;

	mod_trigger_b4_dl_patch_config(con, p);

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
	  http_header_request_get(con, HTTP_HEADER_X_FORWARDED_FOR,
	                          CONST_STR_LEN("X-Forwarded-For"));
	if (NULL == remote_ip) {
		remote_ip = con->dst_addr_buf;
	}

	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "(debug) remote-ip:", remote_ip);
	}

	/* check if URL is a trigger -> insert IP into DB */
	if ((n = pcre_exec(p->conf.trigger_regex, NULL, CONST_BUF_LEN(con->uri.path), 0, 0, ovec, 3 * N)) < 0) {
		if (n != PCRE_ERROR_NOMATCH) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"execution error while matching:", n);

			return HANDLER_ERROR;
		}
	} else {
# if defined(HAVE_GDBM_H)
		if (p->conf.db) {
			/* the trigger matched */
			datum key, val;

			*(const char **)&key.dptr = remote_ip->ptr;
			key.dsize = buffer_string_length(remote_ip);

			val.dptr = (char *)&(srv->cur_ts);
			val.dsize = sizeof(srv->cur_ts);

			if (0 != gdbm_store(p->conf.db, key, val, GDBM_REPLACE)) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"insert failed");
			}
		}
# endif
# if defined(USE_MEMCACHED)
		if (p->conf.memc) {
			buffer * const b = srv->tmp_buf;
			mod_trigger_b4_dl_memcached_key(b, p, remote_ip);

			if (p->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "(debug) triggered IP:", b);
			}

			if (MEMCACHED_SUCCESS != memcached_set(p->conf.memc,
					CONST_BUF_LEN(b),
					(const char *)&(srv->cur_ts), sizeof(srv->cur_ts),
					p->conf.trigger_timeout, 0)) {
				log_error_write(srv, __FILE__, __LINE__, "s",
					"insert failed");
			}
		}
# endif
	}

	/* check if URL is a download -> check IP in DB, update timestamp */
	if ((n = pcre_exec(p->conf.download_regex, NULL, CONST_BUF_LEN(con->uri.path), 0, 0, ovec, 3 * N)) < 0) {
		if (n != PCRE_ERROR_NOMATCH) {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"execution error while matching: ", n);
			return HANDLER_ERROR;
		}
	} else {
		/* the download uri matched */
# if defined(HAVE_GDBM_H)
		if (p->conf.db) {
			datum key, val;
			time_t last_hit;

			*(const char **)&key.dptr = remote_ip->ptr;
			key.dsize = buffer_string_length(remote_ip);

			val = gdbm_fetch(p->conf.db, key);

			if (val.dptr == NULL) {
				/* not found, redirect */
				return mod_trigger_b4_dl_deny(con, p);
			}

			memcpy(&last_hit, val.dptr, sizeof(time_t));

			free(val.dptr);

			if (srv->cur_ts - last_hit > p->conf.trigger_timeout) {
				/* found, but timeout, redirect */

				if (p->conf.db) {
					if (0 != gdbm_delete(p->conf.db, key)) {
						log_error_write(srv, __FILE__, __LINE__, "s",
								"delete failed");
					}
				}

				return mod_trigger_b4_dl_deny(con, p);
			}

			val.dptr = (char *)&(srv->cur_ts);
			val.dsize = sizeof(srv->cur_ts);

			if (0 != gdbm_store(p->conf.db, key, val, GDBM_REPLACE)) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"insert failed");
			}
		}
# endif
# if defined(USE_MEMCACHED)
		if (p->conf.memc) {
			buffer * const b = srv->tmp_buf;
			mod_trigger_b4_dl_memcached_key(b, p, remote_ip);

			if (p->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "(debug) checking IP:", b);
			}

			/**
			 *
			 * memcached is do expiration for us, as long as we can fetch it every thing is ok
			 * and the timestamp is updated
			 *
			 */
			if (MEMCACHED_SUCCESS != memcached_exist(p->conf.memc, CONST_BUF_LEN(b))) {
				return mod_trigger_b4_dl_deny(con, p);
			}

			/* set a new timeout */
			if (MEMCACHED_SUCCESS != memcached_set(p->conf.memc,
					CONST_BUF_LEN(b),
					(const char *)&(srv->cur_ts), sizeof(srv->cur_ts),
					p->conf.trigger_timeout, 0)) {
				log_error_write(srv, __FILE__, __LINE__, "s",
					"insert failed");
			}
		}
# endif
	}

	return HANDLER_GO_ON;
}

#if defined(HAVE_GDBM_H)
static void mod_trigger_b4_dl_trigger_gdbm(GDBM_FILE db, const time_t cur_ts, const int trigger_timeout) {
		datum key, val, okey;
		okey.dptr = NULL;

		/* according to the manual this loop + delete does delete all entries on its way
		 *
		 * we don't care as the next round will remove them. We don't have to perfect here.
		 */
		for (key = gdbm_firstkey(db); key.dptr; key = gdbm_nextkey(db, okey)) {
			time_t last_hit;
			if (okey.dptr) {
				free(okey.dptr);
				okey.dptr = NULL;
			}

			val = gdbm_fetch(db, key);

			memcpy(&last_hit, val.dptr, sizeof(time_t));

			free(val.dptr);

			if (cur_ts - last_hit > trigger_timeout) {
				gdbm_delete(db, key);
			}

			okey = key;
		}
		if (okey.dptr) free(okey.dptr);

		/* reorg once a day */
		if ((cur_ts % (60 * 60 * 24) != 0)) gdbm_reorganize(db);
}

TRIGGER_FUNC(mod_trigger_b4_dl_handle_trigger) {
    /* check DB each minute */
    const time_t cur_ts = srv->cur_ts;
    if (cur_ts % 60 != 0) return HANDLER_GO_ON;

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


#endif /* defined(HAVE_PCRE_H) */
#endif /* defined(HAVE_GDBM_H) || defined(USE_MEMCACHED) */


int mod_trigger_b4_dl_plugin_init(plugin *p);
int mod_trigger_b4_dl_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "trigger_b4_dl";

#if defined(HAVE_PCRE_H)                /* do nothing if PCRE not available */
#if defined(HAVE_GDBM_H) || defined(USE_MEMCACHED) /* at least one required */

	p->init        = mod_trigger_b4_dl_init;
	p->handle_uri_clean  = mod_trigger_b4_dl_uri_handler;
	p->set_defaults  = mod_trigger_b4_dl_set_defaults;
#if defined(HAVE_GDBM_H)
	p->handle_trigger  = mod_trigger_b4_dl_handle_trigger;
#endif
	p->cleanup     = mod_trigger_b4_dl_free;

#endif
#endif

	return 0;
}
