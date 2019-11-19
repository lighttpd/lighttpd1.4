#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"
#include "response.h"

#include "plugin.h"

#include <sys/types.h>
#include <sys/stat.h>

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
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_userdir_init) {
    return calloc(1, sizeof(plugin_data));
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

static void mod_userdir_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_userdir_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_userdir_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("userdir.path"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.exclude-user"),
        T_CONFIG_ARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("userdir.include-user"),
        T_CONFIG_ARRAY,
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
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* userdir.path */
                break;
              case 1: /* userdir.exclude-user */
              case 2: /* userdir.include-user */
                if (!array_is_vlist(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s; "
                      "expected list of \"suffix\"", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                break;
              case 3: /* userdir.basepath */
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
static handler_t mod_userdir_docroot_construct(connection * const con, plugin_data * const p, const char * const uptr, const size_t ulen) {
    char u[256];
    if (ulen >= sizeof(u)) return HANDLER_GO_ON;

    memcpy(u, uptr, ulen);
    u[ulen] = '\0';

    /* we build the physical path */
    buffer * const b = con->srv->tmp_buf;

    if (buffer_string_is_empty(p->conf.basepath)) {
      #ifdef HAVE_PWD_H
        /* XXX: future: might add cache; getpwnam() lookup is expensive */
        struct passwd *pwd = getpwnam(u);
        if (pwd) {
            struct stat st;
            buffer_copy_string(b, pwd->pw_dir);
            buffer_append_path_len(b, CONST_BUF_LEN(p->conf.path));
            if (0 != stat(b->ptr, &st) || !S_ISDIR(st.st_mode)) {
                return HANDLER_GO_ON;
            }
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

        if (con->conf.force_lowercase_filenames) {
            for (size_t i = 0; i < ulen; ++i) {
                if (u[i] >= 'A' && u[i] <= 'Z') u[i] |= 0x20;
            }
        }

        buffer_copy_buffer(b, p->conf.basepath);
        if (p->conf.letterhomes) {
            if (u[0] == '.') return HANDLER_GO_ON;
            buffer_append_path_len(b, u, 1);
        }
        buffer_append_path_len(b, u, ulen);
        buffer_append_path_len(b, CONST_BUF_LEN(p->conf.path));
    }

    buffer_copy_buffer(con->physical.basedir, b);
    buffer_copy_buffer(con->physical.path, b);

    /* the physical rel_path is basically the same as uri.path;
     * but it is converted to lowercase in case of force_lowercase_filenames
     * and some special handling for trailing '.', ' ' and '/' on windows
     * we assume that no docroot/physical handler changed this
     * (docroot should only set the docroot/server name, phyiscal should only
     *  change the physical.path;
     *  the exception mod_secdownload doesn't work with userdir anyway)
     */
    buffer_append_slash(con->physical.path);
    /* if no second '/' is found, we assume that it was stripped from the
     * uri.path for the special handling on windows.  we do not care about the
     * trailing slash here on windows, as we already ensured it is a directory
     *
     * TODO: what to do with trailing dots in usernames on windows?
     * they may result in the same directory as a username without them.
     */
    char *rel_url;
    if (NULL != (rel_url = strchr(con->physical.rel_path->ptr + 2, '/'))) {
        buffer_append_string(con->physical.path, rel_url + 1); /* skip the / */
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_userdir_docroot_handler) {
    /* /~user/foo.html -> /home/user/public_html/foo.html */

    if (buffer_is_empty(con->uri.path)) return HANDLER_GO_ON;

    if (con->uri.path->ptr[0] != '/' ||
        con->uri.path->ptr[1] != '~') return HANDLER_GO_ON;

    plugin_data * const p = p_d;
    mod_userdir_patch_config(con, p);

    /* enforce the userdir.path to be set in the config, ugly fix for #1587;
     * should be replaced with a clean .enabled option in 1.5
     */
    if (!p->conf.active || buffer_is_empty(p->conf.path)) return HANDLER_GO_ON;

    const char * const uptr = con->uri.path->ptr + 2;
    const char * const rel_url = strchr(uptr, '/');
    if (NULL == rel_url) {
        /* / is missing -> redirect to .../ as we are a user - DIRECTORY ! :) */
        http_response_redirect_to_directory(srv, con, 301);
        return HANDLER_FINISHED;
    }

    /* /~/ is a empty username, catch it directly */
    const size_t ulen = (size_t)(rel_url - uptr);
    if (0 == ulen) return HANDLER_GO_ON;

    /* vlists could be turned into sorted array at config time,
     * but these lists are expected to be relatively short in most cases
     * so there is not a huge benefit to doing so in the common case */

    if (p->conf.exclude_user) {
        /* use case-insensitive comparison for exclude list
         * if con->conf.force_lowercase_filenames */
        if (!con->conf.force_lowercase_filenames
            ? mod_userdir_in_vlist(p->conf.exclude_user, uptr, ulen)
            : mod_userdir_in_vlist_nc(p->conf.exclude_user, uptr, ulen))
            return HANDLER_GO_ON; /* user in exclude list */
    }

    if (p->conf.include_user) {
        if (!mod_userdir_in_vlist(p->conf.include_user, uptr, ulen))
            return HANDLER_GO_ON; /* user not in include list */
    }

    return mod_userdir_docroot_construct(con, p, uptr, ulen);
}


int mod_userdir_plugin_init(plugin *p);
int mod_userdir_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "userdir";

	p->init           = mod_userdir_init;
	p->handle_physical = mod_userdir_docroot_handler;
	p->set_defaults   = mod_userdir_set_defaults;

	return 0;
}
