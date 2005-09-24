#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "response.h"

#include "plugin.h"

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

/* plugin config for all request/connections */
typedef struct {
	array *exclude_user;
	array *include_user;
	buffer *path;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	buffer *username;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_userdir_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->username = buffer_init();
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_userdir_free) {
	plugin_data *p = p_d;
	
	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			array_free(s->include_user);
			array_free(s->exclude_user);
			buffer_free(s->path);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	buffer_free(p->username);
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_userdir_set_defaults) {
	plugin_data *p = p_d;
	size_t i;
	
	config_values_t cv[] = { 
		{ "userdir.path",               NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "userdir.exclude-user",       NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "userdir.include-user",       NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		s->exclude_user = array_init();
		s->include_user = array_init();
		s->path = buffer_init();
	
		cv[0].destination = s->path;
		cv[1].destination = s->exclude_user;
		cv[2].destination = s->include_user;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
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
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("userdir.path"))) {
				PATCH(path);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("userdir.exclude-user"))) {
				PATCH(exclude_user);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("userdir.include-user"))) {
				PATCH(include_user);
			}
		}
	}
	
	return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_userdir_docroot_handler) {
	plugin_data *p = p_d;
	int uri_len;
	size_t k;
	char *rel_url;
	struct passwd *pwd;
	
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
#ifdef HAVE_PWD_H	
	mod_userdir_patch_connection(srv, con, p);
	
	uri_len = con->uri.path->used - 1;
	
	/* /~user/foo.html -> /home/user/public_html/foo.html */
	
	if (con->uri.path->ptr[0] != '/' ||
	    con->uri.path->ptr[1] != '~') return HANDLER_GO_ON;
	
	if (NULL == (rel_url = strchr(con->uri.path->ptr + 2, '/'))) {
		/* / is missing -> redirect to .../ as we are a user - DIRECTORY ! :) */
		http_response_redirect_to_directory(srv, con);
		
		return HANDLER_FINISHED;
	}
	buffer_copy_string_len(p->username, con->uri.path->ptr + 2, rel_url - (con->uri.path->ptr + 2));
	
	if (NULL == (pwd = getpwnam(p->username->ptr))) {
		/* user not found */
		return HANDLER_GO_ON;
	}
	
	for (k = 0; k < p->conf.exclude_user->used; k++) {
		data_string *ds = (data_string *)p->conf.exclude_user->data[k];
		
		if (buffer_is_equal(ds->value, p->username)) {
			/* user in exclude list */
			return HANDLER_GO_ON;
		}
	}
	
	if (p->conf.include_user->used) {
		int found_user = 0;
		for (k = 0; k < p->conf.include_user->used; k++) {
			data_string *ds = (data_string *)p->conf.include_user->data[k];
			
			if (buffer_is_equal(ds->value, p->username)) {
				/* user in exclude list */
				found_user = 1;
				break;
			}
		}
		
		if (!found_user) return HANDLER_GO_ON;
	}
	
	/* we build the physical path */	
	buffer_copy_string(con->physical.path, pwd->pw_dir);
	BUFFER_APPEND_SLASH(con->physical.path);
	buffer_append_string_buffer(con->physical.path, p->conf.path); /* skip the / */
	BUFFER_APPEND_SLASH(con->physical.path);
	buffer_append_string(con->physical.path, rel_url + 1); /* skip the / */
	
	return HANDLER_GO_ON;
#else
	return HANDLER_ERROR;
#endif
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_userdir_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("userdir");
	
	p->init           = mod_userdir_init;
	p->handle_physical = mod_userdir_docroot_handler;
	p->set_defaults   = mod_userdir_set_defaults;
	p->cleanup        = mod_userdir_free;
	
	p->data        = NULL;
	
	return 0;
}
