#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"

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
	array *exclude_user;
	array *include_user;
	buffer *path;
	buffer *basepath;
	unsigned short letterhomes;
	unsigned short active;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

INIT_FUNC(mod_userdir_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	return p;
}

FREE_FUNC(mod_userdir_free) {
	plugin_data *p = p_d;

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->include_user);
			array_free(s->exclude_user);
			buffer_free(s->path);
			buffer_free(s->basepath);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_userdir_set_defaults) {
	plugin_data *p = p_d;
	size_t i;

	config_values_t cv[] = {
		{ "userdir.path",               NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "userdir.exclude-user",       NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "userdir.include-user",       NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ "userdir.basepath",           NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 3 */
		{ "userdir.letterhomes",        NULL, T_CONFIG_BOOLEAN,T_CONFIG_SCOPE_CONNECTION },       /* 4 */
		{ "userdir.active",             NULL, T_CONFIG_BOOLEAN,T_CONFIG_SCOPE_CONNECTION },       /* 5 */
		{ NULL,                         NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->exclude_user = array_init();
		s->include_user = array_init();
		s->path = buffer_init();
		s->basepath = buffer_init();
		s->letterhomes = 0;
		/* enabled by default for backward compatibility; if userdir.path isn't set userdir is disabled too,
		 * but you can't disable it by setting it to an empty string. */
		s->active = 1;

		cv[0].destination = s->path;
		cv[1].destination = s->exclude_user;
		cv[2].destination = s->include_user;
		cv[3].destination = s->basepath;
		cv[4].destination = &(s->letterhomes);
		cv[5].destination = &(s->active);

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->exclude_user)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for userdir.exclude-user; expected list of \"suffix\"");
			return HANDLER_ERROR;
		}

		if (!array_is_vlist(s->include_user)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for userdir.include-user; expected list of \"suffix\"");
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_userdir_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(path);
	PATCH(exclude_user);
	PATCH(include_user);
	PATCH(basepath);
	PATCH(letterhomes);
	PATCH(active);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		if (!config_check_cond(con, i)) continue; /* condition not matched */

		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(&du->key, CONST_STR_LEN("userdir.path"))) {
				PATCH(path);
			} else if (buffer_is_equal_string(&du->key, CONST_STR_LEN("userdir.exclude-user"))) {
				PATCH(exclude_user);
			} else if (buffer_is_equal_string(&du->key, CONST_STR_LEN("userdir.include-user"))) {
				PATCH(include_user);
			} else if (buffer_is_equal_string(&du->key, CONST_STR_LEN("userdir.basepath"))) {
				PATCH(basepath);
			} else if (buffer_is_equal_string(&du->key, CONST_STR_LEN("userdir.letterhomes"))) {
				PATCH(letterhomes);
			} else if (buffer_is_equal_string(&du->key, CONST_STR_LEN("userdir.active"))) {
				PATCH(active);
			}
		}
	}

	return 0;
}
#undef PATCH

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
    mod_userdir_patch_connection(srv, con, p);

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
	p->cleanup        = mod_userdir_free;

	return 0;
}
