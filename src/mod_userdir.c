#include "first.h"

#include "array.h"
#include "buffer.h"
#include "log.h"
#include "request.h"
#include "response.h"
#include "stat_cache.h"

#include "plugin.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

typedef struct {
    const array *exclude_user;
    const array *include_user;
    const buffer *path;
    const buffer *basepath;
    unsigned short letterhomes;
    unsigned short active;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    unix_time64_t cache_ts[2];
    buffer cache_user[2];
    buffer cache_path[2];
} plugin_data;

INIT_FUNC(mod_userdir_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_userdir_free) {
    plugin_data * const p = p_d;
    free(p->cache_user[0].ptr);
    free(p->cache_user[1].ptr);
    free(p->cache_path[0].ptr);
    free(p->cache_path[1].ptr);
}

static void mod_userdir_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* userdir.path */
        pconf->path = cpv->v.b;
        break;
      case 1: /* userdir.exclude-user */
        pconf->exclude_user = cpv->v.a;
        break;
      case 2: /* userdir.include-user */
        pconf->include_user = cpv->v.a;
        break;
      case 3: /* userdir.basepath */
        pconf->basepath = cpv->v.b;
        break;
      case 4: /* userdir.letterhomes */
        pconf->letterhomes = cpv->v.u;
        break;
      case 5: /* userdir.active */
        pconf->active = cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_userdir_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_userdir_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_userdir_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_userdir_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_userdir_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("userdir.path"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.exclude-user"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.include-user"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.basepath"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.letterhomes"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.active"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_userdir"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* userdir.path */
              case 1: /* userdir.exclude-user */
              case 2: /* userdir.include-user */
                break;
              case 3: /* userdir.basepath */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 4: /* userdir.letterhomes */
              case 5: /* userdir.active */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* enabled by default for backward compatibility;
     * if userdir.path isn't set userdir is disabled too,
     * but you can't disable it by setting it to an empty string. */
    p->defaults.active = 1;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_userdir_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static int mod_userdir_in_vlist_nc(const array * const a, const char * const k, const size_t klen) {
    for (uint32_t i = 0, used = a->used; i < used; ++i) {
        const data_string * const ds = (const data_string *)a->data[i];
        if (buffer_eq_icase_slen(&ds->value, k, klen)) return 1;
    }
    return 0;
}

static int mod_userdir_in_vlist(const array * const a, const char * const k, const size_t klen) {
    for (uint32_t i = 0, used = a->used; i < used; ++i) {
        const data_string * const ds = (const data_string *)a->data[i];
        if (buffer_eq_slen(&ds->value, k, klen)) return 1;
    }
    return 0;
}

__attribute_noinline__
static handler_t mod_userdir_docroot_construct(request_st * const r, plugin_data * const p, const plugin_config * const pconf, const char * const uptr, const size_t ulen) {
    char u[256];
    if (ulen >= sizeof(u)) return HANDLER_GO_ON;

    memcpy(u, uptr, ulen);
    u[ulen] = '\0';

    /* we build the physical path */
    buffer * const b = r->tmp_buf;

    if (!pconf->basepath) {
      #ifndef HAVE_PWD_H
        UNUSED(p);
      #endif
      #ifdef HAVE_PWD_H
        /* getpwnam() lookup is expensive; first check 2-element cache */
        /* thread-safety todo: p->cache(s) */
        const unix_time64_t cur_ts = log_monotonic_secs;
        int cached = -1;
        const int cache_sz =(int)(sizeof(p->cache_user)/sizeof(*p->cache_user));
        for (int i = 0; i < cache_sz; ++i) {
            if (cur_ts - p->cache_ts[i] < 60 && p->cache_user[i].used
                && buffer_eq_slen(&p->cache_user[i], u, ulen)) {
                cached = i;
                break;
            }
        }
        struct passwd *pwd;
        if (cached >= 0) {
            buffer_copy_path_len2(b, BUF_PTR_LEN(&p->cache_path[cached]),
                                     BUF_PTR_LEN(pconf->path));
        }
        else if ((pwd = getpwnam(u))) {
            const size_t plen = strlen(pwd->pw_dir);
            buffer_copy_path_len2(b, pwd->pw_dir, plen,
                                     BUF_PTR_LEN(pconf->path));
            if (!stat_cache_path_isdir(b)) {
                return HANDLER_GO_ON;
            }
            /* update cache, replacing oldest entry */
            cached = 0;
            unix_time64_t cache_ts = p->cache_ts[0];
            for (int i = 1; i < cache_sz; ++i) {
                if (cache_ts > p->cache_ts[i]) {
                    cache_ts = p->cache_ts[i];
                    cached = i;
                }
            }
            p->cache_ts[cached] = cur_ts;
            buffer_copy_string_len(&p->cache_path[cached], b->ptr, plen);
            buffer_copy_string_len(&p->cache_user[cached], u, ulen);
        }
        else /* user not found */
      #endif
            return HANDLER_GO_ON;
    } else {
        /* check if the username is valid
         * a request for /~../ should lead to a directory traversal
         * limiting to [-_a-z0-9.] should fix it */
        if (ulen <= 2 && (u[0] == '.' && (1 == ulen || u[1] == '.'))) {
            return HANDLER_GO_ON;
        }

        for (size_t i = 0; i < ulen; ++i) {
            const int c = u[i];
            if (!(light_isalnum(c) || c == '-' || c == '_' || c == '.')) {
                return HANDLER_GO_ON;
            }
        }

        if (r->conf.force_lowercase_filenames) {
            for (size_t i = 0; i < ulen; ++i) {
                if (light_isupper(u[i])) u[i] |= 0x20;
            }
        }

        buffer_copy_buffer(b, pconf->basepath);
        if (pconf->letterhomes) {
            if (u[0] == '.') return HANDLER_GO_ON;
            buffer_append_path_len(b, u, 1);
        }
        buffer_append_path_len(b, u, ulen);
        buffer_append_path_len(b, BUF_PTR_LEN(pconf->path));
    }

    buffer_copy_buffer(&r->physical.basedir, b);
    buffer_copy_buffer(&r->physical.path, b);

    /* the physical rel_path is basically the same as uri.path;
     * but it is converted to lowercase in case of force_lowercase_filenames
     * and some special handling for trailing '.', ' ' and '/' on windows
     * we assume that no docroot/physical handler changed this
     * (docroot should only set the docroot/server name, physical should only
     *  change the physical.path) */
    buffer_append_slash(&r->physical.path);
    /* if no second '/' is found, we assume that it was stripped from the
     * uri.path for the special handling on windows.  we do not care about the
     * trailing slash here on windows, as we already ensured it is a directory
     *
     * TODO: what to do with trailing dots in usernames on windows?
     * they may result in the same directory as a username without them.
     */
    char *rel_url;
    if (NULL != (rel_url = strchr(r->physical.rel_path.ptr + 2, '/'))) {
        buffer_append_string(&r->physical.path, rel_url + 1); /* skip the / */
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_userdir_docroot_handler) {
    /* /~user/foo.html -> /home/user/public_html/foo.html */

  #ifdef __COVERITY__
    if (buffer_is_blank(&r->uri.path)) return HANDLER_GO_ON;
  #endif

    if (r->uri.path.ptr[0] != '/' ||
        r->uri.path.ptr[1] != '~') return HANDLER_GO_ON;

    plugin_config pconf;
    mod_userdir_patch_config(r, p_d, &pconf);

    /* enforce the userdir.path to be set in the config, ugly fix for #1587;
     * should be replaced with a clean .enabled option in 1.5
     */
    if (!pconf.active || !pconf.path) return HANDLER_GO_ON;

    const char * const uptr = r->uri.path.ptr + 2;
    const char * const rel_url = strchr(uptr, '/');
    if (NULL == rel_url) {
        if (!*uptr) return HANDLER_GO_ON; /* "/~" is not a valid userdir path */
        /* / is missing -> redirect to .../ as we are a user - DIRECTORY ! :) */
        http_response_redirect_to_directory(r, 301);
        return HANDLER_FINISHED;
    }

    /* /~/ is a empty username, catch it directly */
    const size_t ulen = (size_t)(rel_url - uptr);
    if (0 == ulen) return HANDLER_GO_ON;

    /* vlists could be turned into sorted array at config time,
     * but these lists are expected to be relatively short in most cases
     * so there is not a huge benefit to doing so in the common case */

    if (pconf.exclude_user) {
        /* use case-insensitive comparison for exclude list
         * if r->conf.force_lowercase_filenames */
        if (!r->conf.force_lowercase_filenames
            ? mod_userdir_in_vlist(pconf.exclude_user, uptr, ulen)
            : mod_userdir_in_vlist_nc(pconf.exclude_user, uptr, ulen))
            return HANDLER_GO_ON; /* user in exclude list */
    }

    if (pconf.include_user) {
        if (!mod_userdir_in_vlist(pconf.include_user, uptr, ulen))
            return HANDLER_GO_ON; /* user not in include list */
    }

    return mod_userdir_docroot_construct(r, p_d, &pconf, uptr, ulen);
}


__attribute_cold__
__declspec_dllexport__
int mod_userdir_plugin_init(plugin *p);
int mod_userdir_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "userdir";

	p->init           = mod_userdir_init;
	p->cleanup        = mod_userdir_free;
	p->handle_physical = mod_userdir_docroot_handler;
	p->set_defaults   = mod_userdir_set_defaults;

	return 0;
}
