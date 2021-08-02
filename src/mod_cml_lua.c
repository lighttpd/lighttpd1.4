#include "first.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <errno.h>
#include <string.h>

#include "mod_cml_funcs.h"
#include "mod_cml.h"

#include "chunk.h"
#include "log.h"
#include "http_header.h"
#include "request.h"
#include "response.h"
#include "stat_cache.h"

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];

static int lua_to_c_get_string(lua_State *L, const char *varname, buffer *b) {
	int curelem = lua_gettop(L);
	int result;

	lua_getglobal(L, varname);

	if (lua_isstring(L, curelem)) {
		buffer_copy_string(b, lua_tostring(L, curelem));
		result = 0;
	} else {
		result = -1;
	}

	lua_pop(L, 1);
	force_assert(curelem == lua_gettop(L));
	return result;
}

static int lua_to_c_is_table(lua_State *L, const char *varname) {
	int curelem = lua_gettop(L);
	int result;

	lua_getglobal(L, varname);

	result = lua_istable(L, curelem) ? 1 : 0;

	lua_pop(L, 1);
	force_assert(curelem == lua_gettop(L));
	return result;
}

static int c_to_lua_push(lua_State *L, int tbl, const char *key, size_t key_len, const char *val, size_t val_len) {
	lua_pushlstring(L, key, key_len);
	lua_pushlstring(L, val, val_len);
	lua_settable(L, tbl);

	return 0;
}

static int cache_export_get_params(lua_State *L, int tbl, buffer *qrystr) {
	size_t is_key = 1;
	size_t i, len, klen = 0;
	char *key = NULL, *val = NULL;

	if (buffer_is_blank(qrystr)) return 0;
	key = qrystr->ptr;

	/* we need the \0 */
	len = buffer_clen(qrystr);
	for (i = 0; i <= len; i++) {
		switch(qrystr->ptr[i]) {
		case '=':
			if (is_key) {
				val = qrystr->ptr + i + 1;
				klen = (size_t)(val - key - 1);
				is_key = 0;
			}

			break;
		case '&':
		case '\0': /* fin symbol */
			if (!is_key) {
				/* we need at least a = since the last & */
				c_to_lua_push(L, tbl,
					key, klen,
					val, (size_t)(qrystr->ptr + i - val));
			}

			key = qrystr->ptr + i + 1;
			val = NULL;
			is_key = 1;
			break;
		}
	}

	return 0;
}

int cache_parse_lua(request_st * const r, plugin_data * const p, const buffer * const fn) {
	lua_State *L;
	int ret;
	buffer *b;

	b = buffer_init();
	/* push the lua file to the interpreter and see what happends */
	L = luaL_newstate();
	luaL_openlibs(L);

	/* register functions */
	lua_register(L, "md5", f_crypto_md5);
	lua_register(L, "file_mtime", f_file_mtime);
	lua_register(L, "file_isreg", f_file_isreg);
	lua_register(L, "file_isdir", f_file_isreg);
	lua_register(L, "dir_files", f_dir_files);

#ifdef USE_MEMCACHED
	lua_pushlightuserdata(L, p->conf.memc);
	lua_pushcclosure(L, f_memcache_get_long, 1);
	lua_setglobal(L, "memcache_get_long");

	lua_pushlightuserdata(L, p->conf.memc);
	lua_pushcclosure(L, f_memcache_get_string, 1);
	lua_setglobal(L, "memcache_get_string");

	lua_pushlightuserdata(L, p->conf.memc);
	lua_pushcclosure(L, f_memcache_exists, 1);
	lua_setglobal(L, "memcache_exists");
#endif

	/* register CGI environment */
	lua_newtable(L);
	{
		int header_tbl = lua_gettop(L);

		c_to_lua_push(L, header_tbl, CONST_STR_LEN("REQUEST_URI"), BUF_PTR_LEN(&r->target_orig));
		c_to_lua_push(L, header_tbl, CONST_STR_LEN("SCRIPT_NAME"), BUF_PTR_LEN(&r->uri.path));
		c_to_lua_push(L, header_tbl, CONST_STR_LEN("SCRIPT_FILENAME"), BUF_PTR_LEN(&r->physical.path));
		c_to_lua_push(L, header_tbl, CONST_STR_LEN("DOCUMENT_ROOT"), BUF_PTR_LEN(&r->physical.basedir));
		if (!buffer_is_blank(&r->pathinfo)) {
			c_to_lua_push(L, header_tbl, CONST_STR_LEN("PATH_INFO"), BUF_PTR_LEN(&r->pathinfo));
		}

		c_to_lua_push(L, header_tbl, CONST_STR_LEN("CWD"), BUF_PTR_LEN(&p->basedir));
		c_to_lua_push(L, header_tbl, CONST_STR_LEN("BASEURL"), BUF_PTR_LEN(&p->baseurl));
	}
	lua_setglobal(L, "request");

	/* register GET parameter */
	lua_newtable(L);
	cache_export_get_params(L, lua_gettop(L), &r->uri.query);
	lua_setglobal(L, "get");

	/* 2 default constants */
	lua_pushinteger(L, 0);
	lua_setglobal(L, "CACHE_HIT");

	lua_pushinteger(L, 1);
	lua_setglobal(L, "CACHE_MISS");

	/* load lua program */
	ret = luaL_loadfile(L, fn->ptr);
	if (0 != ret) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "failed loading cml_lua script %s: %s",
		  fn->ptr, lua_tostring(L, -1));
		goto error;
	}

	if (lua_pcall(L, 0, 1, 0)) {
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "failed running cml_lua script %s: %s",
		  fn->ptr, lua_tostring(L, -1));
		goto error;
	}

	/* get return value */
	ret = (int)lua_tointeger(L, -1);
	lua_pop(L, 1);

	/* fetch the data from lua */
	lua_to_c_get_string(L, "trigger_handler", &p->trigger_handler);

	if (0 == lua_to_c_get_string(L, "output_contenttype", b)) {
		http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), BUF_PTR_LEN(b));
	}

	if (ret == 0) {
		/* up to now it is a cache-hit, check if all files exist */

		int curelem;
		unix_time64_t mtime = 0;

		if (!lua_to_c_is_table(L, "output_include")) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "output_include is missing or not a table");
			ret = -1;

			goto error;
		}

		lua_getglobal(L, "output_include");
		curelem = lua_gettop(L);

		/* HOW-TO build a etag ?
		 * as we don't just have one file we have to take the stat()
		 * from all base files, merge them and build the etag from
		 * it later.
		 *
		 * The mtime of the content is the mtime of the freshest base file
		 *
		 * */

		lua_pushnil(L);  /* first key */
		while (lua_next(L, curelem) != 0) {
			/* key' is at index -2 and value' at index -1 */

			if (lua_isstring(L, -1)) {
				size_t slen;
				const char * const s = lua_tolstring(L, -1, &slen);
				struct stat st;
				int fd;

				/* the file is relative, make it absolute */
				if (s[0] != '/') {
					buffer_copy_path_len2(b, BUF_PTR_LEN(&p->basedir),
					                         s, slen);
				} else {
					buffer_copy_string_len(b, s, (uint32_t)slen);
				}

				fd = stat_cache_open_rdonly_fstat(b, &st, r->conf.follow_symlink);
				if (fd < 0) {
					/* stat failed */

					switch(errno) {
					case ENOENT:
						/* a file is missing, call the handler to generate it */
						if (!buffer_is_blank(&p->trigger_handler)) {
							ret = 1; /* cache-miss */

							log_error(r->conf.errh, __FILE__, __LINE__,
							  "a file is missing, calling handler");

							break;
						} else {
							/* handler not set -> 500 */
							ret = -1;

							log_error(r->conf.errh, __FILE__, __LINE__,
							  "a file missing and no handler set");

							break;
						}
						break;
					default:
						break;
					}
				} else {
					chunkqueue_append_file_fd(&r->write_queue, b, fd, 0, st.st_size);
					if (mtime < TIME64_CAST(st.st_mtime))
						mtime = TIME64_CAST(st.st_mtime);
				}
			} else {
				/* not a string */
				ret = -1;
				log_error(r->conf.errh, __FILE__, __LINE__, "not a string");
				break;
			}

			lua_pop(L, 1);  /* removes value'; keeps key' for next iteration */
		}

		lua_settop(L, curelem - 1);

		if (ret == 0) {
			const buffer *vb = http_header_response_get(r, HTTP_HEADER_LAST_MODIFIED, CONST_STR_LEN("Last-Modified"));
			if (NULL == vb) { /* no Last-Modified specified */
				if (0 == mtime) mtime = log_epoch_secs; /* default last-modified to now */
				vb = http_response_set_last_modified(r, mtime);
			}

			r->resp_body_finished = 1;

			if (HANDLER_FINISHED == http_response_handle_cachable(r, vb, mtime)) {
				/* ok, the client already has our content,
				 * no need to send it again */

				chunkqueue_reset(&r->write_queue);
				ret = 0; /* cache-hit */
			}
		} else {
			chunkqueue_reset(&r->write_queue);
		}
	}

	if (ret == 1 && !buffer_is_blank(&p->trigger_handler)) {
		/* cache-miss */
		buffer_clear(&r->uri.path);
		buffer_append_str2(&r->uri.path,
		                   BUF_PTR_LEN(&p->baseurl),
		                   BUF_PTR_LEN(&p->trigger_handler));

		buffer_copy_path_len2(&r->physical.path,
		                      BUF_PTR_LEN(&p->basedir),
		                      BUF_PTR_LEN(&p->trigger_handler));

		chunkqueue_reset(&r->write_queue);
	}

error:
	lua_close(L);

	buffer_free(b);

	return ret /* cache-error */;
}
