#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <lua.h>
#include <lauxlib.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "mod_magnet_cache.h"
#include "response.h"
#include "stat_cache.h"


#define MAGNET_CONFIG_RAW_URL       "magnet.attract-raw-url-to"
#define MAGNET_CONFIG_PHYSICAL_PATH "magnet.attract-physical-path-to"

/* plugin config for all request/connections */

typedef struct {
	buffer *url_raw;
	buffer *physical_path;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	script_cache *cache;

	buffer *encode_buf;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_magnet_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->cache = script_cache_init();
	p->encode_buf = buffer_init();
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_magnet_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;
			
			buffer_free(s->url_raw);
			buffer_free(s->physical_path);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	script_cache_free(p->cache);
	buffer_free(p->encode_buf);
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_magnet_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ MAGNET_CONFIG_RAW_URL,       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ MAGNET_CONFIG_PHYSICAL_PATH, NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ NULL,                           NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		s->url_raw  = buffer_init();
		s->physical_path = buffer_init();
		
		cv[0].destination = s->url_raw;
		cv[1].destination = s->physical_path;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}
	
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_magnet_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	
	PATCH(url_raw);
	PATCH(physical_path);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN(MAGNET_CONFIG_RAW_URL))) {
				PATCH(url_raw);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(MAGNET_CONFIG_PHYSICAL_PATH))) {
				PATCH(physical_path);
			}
		}
	}
	
	return 0;
}
#undef PATCH

static int magnet_print(lua_State *L) {
	const char *s = luaL_checkstring(L, 1);
	server *srv;

	lua_pushstring(L, "lighty.srv");
	lua_gettable(L, LUA_REGISTRYINDEX);
	srv = lua_touserdata(L, -1);
	lua_pop(L, 1);

	log_error_write(srv, __FILE__, __LINE__, "ss", 
			"(lua-print)", s);

	return 0;
}

/**
 * copy all header-vars to the env
 *
 * 
 */
static int magnet_add_request_header(server *srv, connection *con, plugin_data *p, lua_State *L) {
	size_t i;

	for (i = 0; i < con->request.headers->used; i++) {
		data_string *ds;
		
		ds = (data_string *)con->request.headers->data[i];

		if (ds->value->used && ds->key->used) {
			size_t j;
			buffer_reset(p->encode_buf);
			
			if (0 != strcasecmp(ds->key->ptr, "CONTENT-TYPE")) {
				BUFFER_COPY_STRING_CONST(p->encode_buf, "HTTP_");
				p->encode_buf->used--;
			}
			
			buffer_prepare_append(p->encode_buf, ds->key->used + 2);
			for (j = 0; j < ds->key->used - 1; j++) {
				char c = '_';
				if (light_isalpha(ds->key->ptr[j])) {
					/* upper-case */
					c = ds->key->ptr[j] & ~32;
				} else if (light_isdigit(ds->key->ptr[j])) {
					/* copy */
					c = ds->key->ptr[j];
				}
				p->encode_buf->ptr[p->encode_buf->used++] = c;
			}
			p->encode_buf->ptr[p->encode_buf->used++] = '\0';
			
			lua_pushstring(L, ds->value->ptr);     /* -1 <value> */
			lua_setfield(L, -2, p->encode_buf->ptr);
		}
	}
	
	return 0;
}
static int magnet_copy_response_header(server *srv, connection *con, plugin_data *p, lua_State *L) {
	/**
	 * get the environment of the function
	 */

	lua_getfenv(L, -1); /* -1 is the function */

	lua_getfield(L, -1, "header"); /* -1 is now the header table */
	if (lua_istable(L, -1)) {
		/* header is found, and is a table */

		lua_pushnil(L);
		while (lua_next(L, -2) != 0) {
			if (lua_isstring(L, -1) && lua_isstring(L, -2)) {
				const char *key, *val;
				size_t key_len, val_len;

				key = lua_tolstring(L, -2, &key_len);
				val = lua_tolstring(L, -1, &val_len);

				response_header_overwrite(srv, con, key, key_len, val, val_len);
			}

			lua_pop(L, 1);
		}
	}

	lua_pop(L, 1); /* pop the header-table */
	lua_pop(L, 1); /* pop the function env */

	return 0;
}

/**
 * walk through the content array 
 *
 * content[0] = { type : "string", string : "foobar" } 
 * content[1] = { type : "file", filename : "...", [ offset : 0 [, length : ...] ] } 
 */
static int magnet_attach_content(server *srv, connection *con, plugin_data *p, lua_State *L) {
	/**
	 * get the environment of the function
	 */

	assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1); /* -1 is the function */

	lua_getfield(L, -1, "content"); /* -1 is now the header table */
	if (lua_istable(L, -1)) {
		int i;
		/* header is found, and is a table */

		for (i = 0; ; i++) {
			lua_rawgeti(L, -1, i);

			/* we don't need the index */

			/* -1 is the value and should be the value ... aka a table */
			if (lua_istable(L, -1)) {
				int is_file = -1;

				lua_getfield(L, -1, "type");
				if (lua_isstring(L, -1)) {
					if (0 == strcmp("file", lua_tostring(L, -1))) {
						is_file = 1;
					} else if (0 == strcmp("string", lua_tostring(L, -1))) {
						is_file = 0;
					}
				}
				lua_pop(L, 1);

				if (0 == is_file) { /* a string */
					lua_getfield(L, -1, "string");

					if (lua_isstring(L, -1)) {
						size_t s_len = 0;
						const char *s = lua_tolstring(L, -1, &s_len);

						chunkqueue_append_mem(con->write_queue, s, s_len + 1);
					}

					lua_pop(L, 1);
				} else if (1 == is_file) { /* a file */
					lua_getfield(L, -1, "filename");
					lua_getfield(L, -2, "length");
					lua_getfield(L, -3, "offset");

					if (lua_isstring(L, -3)) { /* filename has to be a string */
						buffer *fn = buffer_init();
						stat_cache_entry *sce;
						off_t off = 0;
						off_t len = 0;

						if (lua_isnumber(L, -1)) {
							off = lua_tonumber(L, -1);
						}

						if (lua_isnumber(L, -2)) {
							len = lua_tonumber(L, -2);
						}

						buffer_copy_string(fn, lua_tostring(L, -3));

						if (HANDLER_GO_ON == stat_cache_get_entry(srv, con, fn, &sce)) {
							chunkqueue_append_file(con->write_queue, fn, off, sce->st.st_size);
						}

						buffer_free(fn);
					}

					lua_pop(L, 3);
				} /* ignore invalid types */ 
			} else if (lua_isnil(L, -1)) {
				/* oops, end of list */

				lua_pop(L, 1);

				break;
			} 

			lua_pop(L, 1); /* pop the content[...] table */
		}
	}
	lua_pop(L, 1); /* pop the header-table */
	lua_pop(L, 1); /* php the function env */

	return 0;
}

static handler_t magnet_attract(server *srv, connection *con, plugin_data *p, buffer *name) {
	lua_State *L;
	int lua_return_value = -1;
	/* get the script-context */


	L = script_cache_get_script(srv, con, p->cache, name);

	if (lua_isstring(L, -1)) {
		log_error_write(srv, __FILE__, __LINE__, 
				"sbss",
				"loading script",
				name,
				"failed:",
				lua_tostring(L, -1));

		lua_pop(L, 1);
		
		assert(lua_gettop(L) == 0); /* only the function should be on the stack */

		con->http_status = 500;

		return HANDLER_FINISHED;
	}

	lua_pushstring(L, "lighty.srv"); 
	lua_pushlightuserdata(L, srv);
	lua_settable(L, LUA_REGISTRYINDEX); /* registery[<id>] = srv */

	/**
	 * we want to create empty environment for our script 
	 * 
	 * setmetatable({}, {__index = _G})
	 * 
	 * if a function, symbol is not defined in our env, __index will lookup 
	 * in the global env.
	 *
	 * all variables created in the script-env will be thrown 
	 * away at the end of the script run.
	 */
	lua_newtable(L); /* my empty environment aka {}              (sp += 1) */

	/* we have to overwrite the print function */
	lua_pushcfunction(L, magnet_print);                       /* (sp += 1) */
	lua_setfield(L, -2, "print"); /* -1 is the env we want to set(sp -= 1) */

	lua_newtable(L); /*  {}                                      (sp += 1) */
	magnet_add_request_header(srv, con, p, L);
	lua_setfield(L, -2, "request"); /* content = {}              (sp -= 1) */

	/* add empty 'content' and 'header' tables */
	lua_newtable(L); /*  {}                                      (sp += 1) */
	lua_setfield(L, -2, "content"); /* content = {}              (sp -= 1) */

	lua_newtable(L); /*  {}                                      (sp += 1) */
	lua_setfield(L, -2, "header"); /* header = {}                (sp -= 1) */
	
	lua_newtable(L); /* the meta-table for the new env           (sp += 1) */
	lua_pushvalue(L, LUA_GLOBALSINDEX);                       /* (sp += 1) */
	lua_setfield(L, -2, "__index"); /* { __index = _G }          (sp += 1) */
	lua_setmetatable(L, -2); /* setmetatable({}, {__index = _G}) (sp -= 2) */
	

	lua_setfenv(L, -2); /* on the stack should be a modified env (sp -= 2) */


	if (lua_pcall(L, 0, 1, 0)) {
		log_error_write(srv, __FILE__, __LINE__, 
			"sbss", 
			"lua_pcall() failed for",
			name,
			"with:",
			lua_tostring(L, -1));
		lua_pop(L, 1); /* remove the error-msg and the function copy from the stack */

		assert(lua_gettop(L) == 1); /* only the function should be on the stack */

		con->http_status = 500;

		return HANDLER_FINISHED;
	}

	/* we should have the function-copy and the return value on the stack */
	assert(lua_gettop(L) == 2);

	if (lua_isnumber(L, -1)) {
		/* if the ret-value is a number, take it */
		lua_return_value = (int)lua_tonumber(L, -1);
	}
	lua_pop(L, 1); /* pop the ret-value */

	magnet_copy_response_header(srv, con, p, L);

	if (lua_return_value > 99) {
		con->http_status = lua_return_value;
		con->file_finished = 1;
		
		magnet_attach_content(srv, con, p, L);
	
		assert(lua_gettop(L) == 1); /* only the function should be on the stack */

		/* we are finished */
		return HANDLER_FINISHED;
	}

	assert(lua_gettop(L) == 1); /* only the function should be on the stack */
	
	return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_magnet_uri_handler) {
	plugin_data *p = p_d;
	
	mod_magnet_patch_connection(srv, con, p);

	if (buffer_is_empty(p->conf.url_raw)) return HANDLER_GO_ON;

	/* looks like we have a handler for this request */

	return magnet_attract(srv, con, p, p->conf.url_raw);
}

URIHANDLER_FUNC(mod_magnet_physical) {
	plugin_data *p = p_d;
	
	mod_magnet_patch_connection(srv, con, p);

	if (buffer_is_empty(p->conf.physical_path)) return HANDLER_GO_ON;

	/* looks like we have a handler for this request */

	return magnet_attract(srv, con, p, p->conf.physical_path);
}


/* this function is called at dlopen() time and inits the callbacks */

int mod_magnet_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("magnet");
	
	p->init        = mod_magnet_init;
	p->handle_uri_clean  = mod_magnet_uri_handler;
	p->handle_physical   = mod_magnet_physical;
	p->set_defaults  = mod_magnet_set_defaults;
	p->cleanup     = mod_magnet_free;
	
	p->data        = NULL;
	
	return 0;
}
