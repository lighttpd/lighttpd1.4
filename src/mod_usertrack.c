#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#ifdef USE_OPENSSL
# include <openssl/md5.h>
#else
# include "md5_global.h"
# include "md5.h"
#endif

/* plugin config for all request/connections */

typedef struct {
	buffer *cookie_name;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_usertrack_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_usertrack_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);
	
	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			buffer_free(s->cookie_name);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_usertrack_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ "usertrack.cookiename",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = malloc(srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = malloc(sizeof(plugin_config));
		s->cookie_name    = buffer_init();
		
		cv[0].destination = s->cookie_name;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	
		if (s->cookie_name->used == 0) {
			buffer_copy_string(s->cookie_name, "TRACKID");
		} else {
			size_t j;
			for (j = 0; j < s->cookie_name->used - 1; j++) {
				char c = s->cookie_name->ptr[j] | 32;
				if (c < 'a' || c > 'z') {
					log_error_write(srv, __FILE__, __LINE__, "sb", 
							"invalid character in usertrack.cookiename:", 
							s->cookie_name);
					
					return HANDLER_ERROR;
				}
			}
		}
	}
		
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_usertrack_patch_connection(server *srv, connection *con, plugin_data *p, const char *stage, size_t stage_len) {
	size_t i, j;
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		plugin_config *s = p->config_storage[i];
		
		/* not our stage */
		if (!buffer_is_equal_string(dc->comp_key, stage, stage_len)) continue;
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("usertrack.cookiename"))) {
				PATCH(cookie_name);
			}
		}
	}
	
	return 0;
}

static int mod_usertrack_setup_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	UNUSED(srv);
	UNUSED(con);
		
	PATCH(cookie_name);
	
	return 0;
}
#undef PATCH



URIHANDLER_FUNC(mod_usertrack_uri_handler) {
	plugin_data *p = p_d;
	data_string *ds;
	unsigned char h[16];
	MD5_CTX Md5Ctx;
	char hh[32];
	size_t i;
	
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	
	mod_usertrack_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		mod_usertrack_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Cookie"))) {
		char *g;
		/* we have a cookie, does it contain a valid name ? */
		
		/* parse the cookie 
		 * 
		 * check for cookiename + (WS | '=')
		 * 
		 */
		
		if (NULL != (g = strstr(ds->value->ptr, p->conf.cookie_name->ptr))) {
			char *nc;
			
			/* skip WS */
			for (nc = g + p->conf.cookie_name->used-1; *nc == ' ' || *nc == '\t'; nc++);
			
			if (*nc == '=') {
				/* ok, found the key of our own cookie */
				
				if (strlen(nc) > 32) {
					/* i'm lazy */
					return HANDLER_GO_ON;
				}
			}
		}
	} 
	
	/* set a cookie */
	if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
		ds = data_response_init();
	}
	buffer_copy_string(ds->key, "Set-Cookie");
	buffer_copy_string_buffer(ds->value, p->conf.cookie_name);
	buffer_append_string(ds->value, "=");
	

	/* taken from mod_auth.c */
	
	/* generate shared-secret */
	MD5_Init(&Md5Ctx);
	MD5_Update(&Md5Ctx, (unsigned char *)con->uri.path->ptr, con->uri.path->used - 1);
	MD5_Update(&Md5Ctx, (unsigned char *)"+", 1);
	
	/* we assume sizeof(time_t) == 4 here, but if not it ain't a problem at all */
	ltostr(hh, srv->cur_ts);
	MD5_Update(&Md5Ctx, (unsigned char *)hh, strlen(hh));
	ltostr(hh, rand());
	MD5_Update(&Md5Ctx, (unsigned char *)hh, strlen(hh));
	
	MD5_Final(h, &Md5Ctx);
	
	buffer_append_string_hex(ds->value, (char *)h, 16);
	buffer_append_string(ds->value, "; path=/");
	
	array_insert_unique(con->response.headers, (data_unset *)ds);
	
	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_usertrack_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("usertrack");
	
	p->init        = mod_usertrack_init;
	p->handle_uri_clean  = mod_usertrack_uri_handler;
	p->set_defaults  = mod_usertrack_set_defaults;
	p->cleanup     = mod_usertrack_free;
	
	p->data        = NULL;
	
	return 0;
}
