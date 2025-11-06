#include "first.h"

#include "plugins.h"
#include "plugin.h"
#include "base.h"
#include "array.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif

#ifndef LIGHTTPD_STATIC
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#endif
/*
 *
 * if you change this enum to add a new callback, be sure
 * - that PLUGIN_FUNC_SIZEOF is the last entry
 * - that you add:
 *   1. PLUGIN_CALL_... as callback-dispatcher
 *   2. count and assignment in plugins_call_init()
 *
 */

typedef enum {
	PLUGIN_FUNC_HANDLE_URI_CLEAN,
	PLUGIN_FUNC_HANDLE_DOCROOT,
	PLUGIN_FUNC_HANDLE_PHYSICAL,
	PLUGIN_FUNC_HANDLE_SUBREQUEST_START,
	/* PLUGIN_FUNC_HANDLE_SUBREQUEST, *//* max one handler_module per req */
	PLUGIN_FUNC_HANDLE_RESPONSE_START,
	PLUGIN_FUNC_HANDLE_REQUEST_DONE,
	PLUGIN_FUNC_HANDLE_REQUEST_RESET,
	PLUGIN_FUNC_HANDLE_REQUEST_ENV,
	PLUGIN_FUNC_HANDLE_CONNECTION_ACCEPT,
	PLUGIN_FUNC_HANDLE_CONNECTION_SHUT_WR,
	PLUGIN_FUNC_HANDLE_CONNECTION_CLOSE,
	PLUGIN_FUNC_HANDLE_TRIGGER,
	PLUGIN_FUNC_HANDLE_WAITPID,
	PLUGIN_FUNC_HANDLE_SIGHUP,
	/* PLUGIN_FUNC_INIT, *//* handled here in plugin.c */
	/* PLUGIN_FUNC_CLEANUP, *//* handled here in plugin.c */
	PLUGIN_FUNC_SET_DEFAULTS,
	PLUGIN_FUNC_WORKER_INIT,

	PLUGIN_FUNC_SIZEOF
} plugin_t;

__attribute_malloc__
__attribute_returns_nonnull__
static plugin *plugin_init(void) {
	return ck_calloc(1, sizeof(plugin));
}

static void plugin_free(plugin *p) {
    if (NULL == p) return; /*(should not happen w/ current usage)*/
  #if !defined(LIGHTTPD_STATIC)
    if (p->lib) {
     #if defined(HAVE_VALGRIND_VALGRIND_H)
     /*if (!RUNNING_ON_VALGRIND) */
     #endif
      #ifdef _WIN32
        FreeLibrary(p->lib);
      #else
        dlclose(p->lib);
      #endif
    }
  #endif

    free(p);
}

/**
 *
 *
 *
 */

#if defined(LIGHTTPD_STATIC)

/* pre-declare functions, as there is no header for them */
#define PLUGIN_INIT(x)\
	int x ## _plugin_init(plugin *p);

#include "plugin-static.h"

#undef PLUGIN_INIT

/* build NULL-terminated table of name + init-function */

typedef struct {
	const char* name;
	int (*plugin_init)(plugin *p);
} plugin_load_functions;

static const plugin_load_functions load_functions[] = {
#define PLUGIN_INIT(x) \
	{ #x, &x ## _plugin_init },

#include "plugin-static.h"

	{ NULL, NULL }
#undef PLUGIN_INIT
};

int plugins_load(server *srv) {
	ck_realloc_u32(&srv->plugins.ptr, 0,
	               srv->srvconf.modules->used, sizeof(plugin *));

	for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
		data_string *ds = (data_string *)srv->srvconf.modules->data[i];
		char *module = ds->value.ptr;

		uint32_t j;
		for (j = 0; load_functions[j].name; ++j) {
			if (0 == strcmp(load_functions[j].name, module)) {
				plugin * const p = plugin_init();
				if ((*load_functions[j].plugin_init)(p)) {
					log_error(srv->errh, __FILE__, __LINE__, "%s plugin init failed", module);
					plugin_free(p);
					return -1;
				}
				((plugin **)srv->plugins.ptr)[srv->plugins.used++] = p;
				break;
			}
		}
		if (!load_functions[j].name) {
			if (srv->srvconf.compat_module_load) {
				if (buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_deflate")))
					continue;
			}
			if (buffer_eq_slen(&ds->value, CONST_STR_LEN("mod_h2"))) {
				srv->srvconf.h2proto = 0;
				continue;
			}
			log_error(srv->errh, __FILE__, __LINE__, "%s plugin not found", module);
			return -1;
		}
	}

	return 0;
}

#else /* defined(LIGHTTPD_STATIC) */

int plugins_load(server *srv) {
	ck_realloc_u32(&srv->plugins.ptr, 0,
	               srv->srvconf.modules->used, sizeof(plugin *));

	buffer * const tb = srv->tmp_buf;
  #ifdef _WIN32
	int (WINAPI *init)(plugin *pl);
  #else
	int (*init)(plugin *pl);
  #endif

	for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
		const buffer * const module = &((data_string *)srv->srvconf.modules->data[i])->value;
		void *lib = NULL;

		/* check if module is built-in to main executable */
		buffer_clear(tb);
		buffer_append_str2(tb, BUF_PTR_LEN(module),
		                       CONST_STR_LEN("_plugin_init"));
	  #ifdef _WIN32
		init = (int(WINAPI *)(plugin *))(intptr_t)
		  GetProcAddress(GetModuleHandle(NULL), tb->ptr);
	  #else
		init = (int (*)(plugin *))(intptr_t)dlsym(RTLD_DEFAULT, tb->ptr);
	  #endif

	  if (NULL == init) {
		buffer_copy_string(tb, srv->srvconf.modules_dir);
		buffer_append_path_len(tb, BUF_PTR_LEN(module));

	  #ifdef _WIN32
		buffer_append_string_len(tb, CONST_STR_LEN(".dll"));
		if (NULL == (lib = LoadLibrary(tb->ptr))) {
			if (srv->srvconf.compat_module_load) {
				if (buffer_eq_slen(module, CONST_STR_LEN("mod_deflate")))
					continue;
			}
			if (buffer_eq_slen(module, CONST_STR_LEN("mod_h2"))) {
				srv->srvconf.h2proto = 0;
				continue;
			}
			log_perror(srv->errh, __FILE__, __LINE__,
			  "LoadLibrary() %s", tb->ptr);
			return -1;
		}
		buffer_copy_buffer(tb, module);
		buffer_append_string_len(tb, CONST_STR_LEN("_plugin_init"));
		init = (int(WINAPI *)(plugin *))(intptr_t)GetProcAddress(lib, tb->ptr);
		if (init == NULL) {
			log_perror(srv->errh, __FILE__, __LINE__,
			  "GetProcAddress() %s", tb->ptr);
		        FreeLibrary(lib);
			return -1;
		}
	  #else
	   #if defined(__CYGWIN__)
		buffer_append_string_len(tb, CONST_STR_LEN(".dll"));
	   #else
		buffer_append_string_len(tb, CONST_STR_LEN(".so"));
	   #endif
		if (NULL == (lib = dlopen(tb->ptr, RTLD_NOW|RTLD_GLOBAL))) {
			if (srv->srvconf.compat_module_load) {
				if (buffer_eq_slen(module, CONST_STR_LEN("mod_deflate")))
					continue;
			}
			if (buffer_eq_slen(module, CONST_STR_LEN("mod_h2"))) {
				srv->srvconf.h2proto = 0;
				continue;
			}
			log_error(srv->errh, __FILE__, __LINE__,
			  "dlopen() failed for: %s %s", tb->ptr, dlerror());
			return -1;
		}
		buffer_clear(tb);
		buffer_append_str2(tb, BUF_PTR_LEN(module),
                                       CONST_STR_LEN("_plugin_init"));
		init = (int (*)(plugin *))(intptr_t)dlsym(lib, tb->ptr);
		if (NULL == init) {
			const char *error = dlerror();
			if (error != NULL) {
				log_error(srv->errh, __FILE__, __LINE__, "dlsym: %s", error);
			} else {
				log_error(srv->errh, __FILE__, __LINE__, "dlsym symbol not found: %s", tb->ptr);
			}
		        dlclose(lib);
			return -1;
		}
	  #endif
	  }

		plugin *p = plugin_init();
		p->lib = lib;
		if ((*init)(p)) {
			log_error(srv->errh, __FILE__, __LINE__, "%s plugin init failed", module->ptr);
			plugin_free(p);
			return -1;
		}
		((plugin **)srv->plugins.ptr)[srv->plugins.used++] = p;
	}

	return 0;
}

#endif /* defined(LIGHTTPD_STATIC) */

typedef handler_t(*pl_cb_t)(void *, void *);

/*(alternative to multiple structs would be union for fn ptr type)*/

typedef struct {
  pl_cb_t fn;
  plugin_data_base *data;
} plugin_fn_data;

typedef struct {
  handler_t(*fn)(request_st *, void *);
  plugin_data_base *data;
} plugin_fn_req_data;

typedef struct {
  handler_t(*fn)(connection *, void *);
  plugin_data_base *data;
} plugin_fn_con_data;

typedef struct {
  handler_t(*fn)(server *, void *);
  plugin_data_base *data;
} plugin_fn_srv_data;

typedef struct {
  handler_t(*fn)(server *, void *, pid_t, int);
  plugin_data_base *data;
} plugin_fn_waitpid_data;

__attribute_hot__
static handler_t plugins_call_fn_req_data(request_st * const r, const int e) {
    const void * const plugin_slots = r->con->plugin_slots;
    const uint32_t offset = ((const uint16_t *)plugin_slots)[e];
    if (0 == offset) return HANDLER_GO_ON;
    const plugin_fn_req_data *plfd = (const plugin_fn_req_data *)
      (((uintptr_t)plugin_slots) + offset);
    handler_t rc = HANDLER_GO_ON;
    while (plfd->fn && (rc = plfd->fn(r, plfd->data)) == HANDLER_GO_ON)
        ++plfd;
    return rc;
}

__attribute_hot__
static handler_t plugins_call_fn_con_data(connection * const con, const int e) {
    const void * const plugin_slots = con->plugin_slots;
    const uint32_t offset = ((const uint16_t *)plugin_slots)[e];
    if (0 == offset) return HANDLER_GO_ON;
    const plugin_fn_con_data *plfd = (const plugin_fn_con_data *)
      (((uintptr_t)plugin_slots) + offset);
    handler_t rc = HANDLER_GO_ON;
    while (plfd->fn && (rc = plfd->fn(con, plfd->data)) == HANDLER_GO_ON)
        ++plfd;
    return rc;
}

static handler_t plugins_call_fn_srv_data(server * const srv, const int e) {
    const uint32_t offset = ((const uint16_t *)srv->plugin_slots)[e];
    if (0 == offset) return HANDLER_GO_ON;
    const plugin_fn_srv_data *plfd = (const plugin_fn_srv_data *)
      (((uintptr_t)srv->plugin_slots) + offset);
    handler_t rc = HANDLER_GO_ON;
    while (plfd->fn && (rc = plfd->fn(srv,plfd->data)) == HANDLER_GO_ON)
        ++plfd;
    return rc;
}

static void plugins_call_fn_srv_data_all(server * const srv, const int e) {
    const uint32_t offset = ((const uint16_t *)srv->plugin_slots)[e];
    if (0 == offset) return;
    const plugin_fn_srv_data *plfd = (const plugin_fn_srv_data *)
      (((uintptr_t)srv->plugin_slots) + offset);
    for (; plfd->fn; ++plfd)
        plfd->fn(srv, plfd->data);
}

/**
 * plugins that use
 *
 * - request_st *r
 * - void *p_d (plugin_data *)
 */

#define PLUGIN_CALL_FN_REQ_DATA(x, y) \
    handler_t plugins_call_##y(request_st * const r) {\
        return plugins_call_fn_req_data(r, x); \
    }

#if 0 /*(handled differently in http_response_prepare())*/
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_URI_CLEAN, handle_uri_clean)
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_DOCROOT, handle_docroot)
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_PHYSICAL, handle_physical)
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_SUBREQUEST_START, handle_subrequest_start)
#endif
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_RESPONSE_START, handle_response_start)
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_REQUEST_DONE, handle_request_done)
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_REQUEST_RESET, handle_request_reset)
PLUGIN_CALL_FN_REQ_DATA(PLUGIN_FUNC_HANDLE_REQUEST_ENV, handle_request_env)

/**
 * plugins that use
 *
 * - connection *con
 * - void *p_d (plugin_data *)
 */

#define PLUGIN_CALL_FN_CON_DATA(x, y) \
    handler_t plugins_call_##y(connection *con) {\
        return plugins_call_fn_con_data(con, x); \
    }

PLUGIN_CALL_FN_CON_DATA(PLUGIN_FUNC_HANDLE_CONNECTION_ACCEPT, handle_connection_accept)
PLUGIN_CALL_FN_CON_DATA(PLUGIN_FUNC_HANDLE_CONNECTION_SHUT_WR, handle_connection_shut_wr)
PLUGIN_CALL_FN_CON_DATA(PLUGIN_FUNC_HANDLE_CONNECTION_CLOSE, handle_connection_close)

#undef PLUGIN_CALL_FN_SRV_CON_DATA

/**
 * plugins that use
 *
 * - server *srv
 * - void *p_d (plugin_data *)
 */

handler_t plugins_call_set_defaults(server *srv) {
    return plugins_call_fn_srv_data(srv, PLUGIN_FUNC_SET_DEFAULTS);
}

handler_t plugins_call_worker_init(server *srv) {
    return plugins_call_fn_srv_data(srv, PLUGIN_FUNC_WORKER_INIT);
}

void plugins_call_handle_trigger(server *srv) {
    plugins_call_fn_srv_data_all(srv, PLUGIN_FUNC_HANDLE_TRIGGER);
}

void plugins_call_handle_sighup(server *srv) {
    plugins_call_fn_srv_data_all(srv, PLUGIN_FUNC_HANDLE_SIGHUP);
}

handler_t plugins_call_handle_waitpid(server *srv, pid_t pid, int status) {
    const uint32_t offset =
      ((const uint16_t *)srv->plugin_slots)[PLUGIN_FUNC_HANDLE_WAITPID];
    if (0 == offset) return HANDLER_GO_ON;
    const plugin_fn_waitpid_data *plfd = (const plugin_fn_waitpid_data *)
      (((uintptr_t)srv->plugin_slots) + offset);
    handler_t rc = HANDLER_GO_ON;
    while (plfd->fn&&(rc=plfd->fn(srv,plfd->data,pid,status))==HANDLER_GO_ON)
        ++plfd;
    return rc;
}

static void plugins_call_cleanup(server * const srv) {
    plugin ** const ps = srv->plugins.ptr;
    for (uint32_t i = 0; i < srv->plugins.used; ++i) {
        plugin *p = ps[i];
        if (NULL == p) continue;
        if (NULL != p->data) {
            plugin_data_base *pd = p->data;
            if (p->cleanup)
                p->cleanup(p->data);
            free(pd->cvlist);
            free(pd);
            p->data = NULL;
        }
    }
}

__attribute_cold__
static void plugins_call_init_reverse(server *srv, const uint32_t offset) {
    if (0 == offset) return;
    plugin_fn_data *a = (plugin_fn_data *)
      (((uintptr_t)srv->plugin_slots) + offset);
    plugin_fn_data *b = a;
    while (b->fn) ++b;
    for (; a < --b; ++a) { /* swap to reverse list */
        plugin_fn_data tmp = *a;
        *a = *b;
        *b = tmp;
    }
}

__attribute_cold__
static void plugins_call_init_slot(server *srv, pl_cb_t fn, void *data, const uint32_t offset) {
    if (fn) {
        plugin_fn_data *plfd = (plugin_fn_data *)
          (((uintptr_t)srv->plugin_slots) + offset);
        while (plfd->fn) ++plfd;
        plfd->fn = fn;
        plfd->data = data;
    }
}

handler_t plugins_call_init(server *srv) {
	plugin ** const ps = srv->plugins.ptr;
	uint16_t offsets[PLUGIN_FUNC_SIZEOF];
	memset(offsets, 0, sizeof(offsets));

	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		/* check which calls are supported */

		plugin *p = ps[i];

		if (p->init) {
			if (NULL == (p->data = p->init())) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "plugin-init failed for mod_%s", p->name);
				return HANDLER_ERROR;
			}

			((plugin_data_base *)(p->data))->self = p;
			((plugin_data_base *)(p->data))->id = i + 1;

			if (p->version != LIGHTTPD_VERSION_ID) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "plugin-version doesn't match lighttpd-version for mod_%s", p->name);
				return HANDLER_ERROR;
			}
		}

		if (p->priv_defaults && HANDLER_ERROR==p->priv_defaults(srv, p->data)) {
			return HANDLER_ERROR;
		}

		if (p->handle_uri_clean)
			++offsets[PLUGIN_FUNC_HANDLE_URI_CLEAN];
		if (p->handle_uri_raw && !p->handle_uri_clean)
			++offsets[PLUGIN_FUNC_HANDLE_URI_CLEAN]; /*(same as above)*/
		if (p->handle_request_env)
			++offsets[PLUGIN_FUNC_HANDLE_REQUEST_ENV];
		if (p->handle_request_done)
			++offsets[PLUGIN_FUNC_HANDLE_REQUEST_DONE];
		if (p->handle_connection_accept)
			++offsets[PLUGIN_FUNC_HANDLE_CONNECTION_ACCEPT];
		if (p->handle_connection_shut_wr)
			++offsets[PLUGIN_FUNC_HANDLE_CONNECTION_SHUT_WR];
		if (p->handle_connection_close)
			++offsets[PLUGIN_FUNC_HANDLE_CONNECTION_CLOSE];
		if (p->handle_trigger)
			++offsets[PLUGIN_FUNC_HANDLE_TRIGGER];
		if (p->handle_sighup)
			++offsets[PLUGIN_FUNC_HANDLE_SIGHUP];
		if (p->handle_waitpid)
			++offsets[PLUGIN_FUNC_HANDLE_WAITPID];
		if (p->handle_subrequest_start)
			++offsets[PLUGIN_FUNC_HANDLE_SUBREQUEST_START];
		if (p->handle_response_start)
			++offsets[PLUGIN_FUNC_HANDLE_RESPONSE_START];
		if (p->handle_docroot)
			++offsets[PLUGIN_FUNC_HANDLE_DOCROOT];
		if (p->handle_physical)
			++offsets[PLUGIN_FUNC_HANDLE_PHYSICAL];
		if (p->handle_request_reset)
			++offsets[PLUGIN_FUNC_HANDLE_REQUEST_RESET];
		if (p->set_defaults)
			++offsets[PLUGIN_FUNC_SET_DEFAULTS];
		if (p->worker_init)
			++offsets[PLUGIN_FUNC_WORKER_INIT];
	}

	/* allocate first space for response.c:http_response_config() */
	++offsets[PLUGIN_FUNC_HANDLE_URI_CLEAN];

	uint32_t nslots =
	  (sizeof(offsets)+sizeof(plugin_fn_data)-1) / sizeof(plugin_fn_data);
	for (uint32_t i = 0; i < PLUGIN_FUNC_SIZEOF; ++i) {
		/* note: allocate at least one slot for
		 *   PLUGIN_FUNC_HANDLE_URI_CLEAN
		 *   PLUGIN_FUNC_HANDLE_DOCROOT
		 *   PLUGIN_FUNC_HANDLE_PHYSICAL
		 *   PLUGIN_FUNC_HANDLE_SUBREQUEST_START
		 * in order to be able to overwrite NULL w/ fn ptr in response.c
		 */
		if (offsets[i] || i <= PLUGIN_FUNC_HANDLE_SUBREQUEST_START) {
			uint32_t offset = nslots;
			nslots += offsets[i]+1; /* +1 to mark end of each list */
			force_assert(offset * sizeof(plugin_fn_data) <= USHRT_MAX);
			offsets[i] = (uint16_t)(offset * sizeof(plugin_fn_data));
		}
	}

	/* allocate and fill slots of two dimensional array */
	srv->plugin_slots = ck_calloc(nslots, sizeof(plugin_fn_data));
	memcpy(srv->plugin_slots, offsets, sizeof(offsets));

	/* allocate first space for response.c:http_response_config() */
	plugins_call_init_slot(srv, (pl_cb_t)(uintptr_t)1, NULL,
				offsets[PLUGIN_FUNC_HANDLE_URI_CLEAN]);

	/* add handle_uri_raw before handle_uri_clean, but in same slot */
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		plugin * const p = ps[i];
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_uri_raw, p->data,
					offsets[PLUGIN_FUNC_HANDLE_URI_CLEAN]);
	}

	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		plugin * const p = ps[i];

		if (!p->handle_uri_raw)
			plugins_call_init_slot(srv, (pl_cb_t)p->handle_uri_clean, p->data,
						offsets[PLUGIN_FUNC_HANDLE_URI_CLEAN]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_request_env, p->data,
					offsets[PLUGIN_FUNC_HANDLE_REQUEST_ENV]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_request_done, p->data,
					offsets[PLUGIN_FUNC_HANDLE_REQUEST_DONE]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_connection_accept, p->data,
					offsets[PLUGIN_FUNC_HANDLE_CONNECTION_ACCEPT]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_connection_shut_wr, p->data,
					offsets[PLUGIN_FUNC_HANDLE_CONNECTION_SHUT_WR]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_connection_close, p->data,
					offsets[PLUGIN_FUNC_HANDLE_CONNECTION_CLOSE]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_trigger, p->data,
					offsets[PLUGIN_FUNC_HANDLE_TRIGGER]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_sighup, p->data,
					offsets[PLUGIN_FUNC_HANDLE_SIGHUP]);
		plugins_call_init_slot(srv, (pl_cb_t)(uintptr_t)p->handle_waitpid, p->data,
					offsets[PLUGIN_FUNC_HANDLE_WAITPID]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_subrequest_start, p->data,
					offsets[PLUGIN_FUNC_HANDLE_SUBREQUEST_START]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_response_start, p->data,
					offsets[PLUGIN_FUNC_HANDLE_RESPONSE_START]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_docroot, p->data,
					offsets[PLUGIN_FUNC_HANDLE_DOCROOT]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_physical, p->data,
					offsets[PLUGIN_FUNC_HANDLE_PHYSICAL]);
		plugins_call_init_slot(srv, (pl_cb_t)p->handle_request_reset, p->data,
					offsets[PLUGIN_FUNC_HANDLE_REQUEST_RESET]);
		plugins_call_init_slot(srv, (pl_cb_t)p->set_defaults, p->data,
					offsets[PLUGIN_FUNC_SET_DEFAULTS]);
		plugins_call_init_slot(srv, (pl_cb_t)p->worker_init, p->data,
					offsets[PLUGIN_FUNC_WORKER_INIT]);
	}

	/* reverse cleanup lists to balance ctor/dtor-like plugin behaviors */
	plugins_call_init_reverse(srv,offsets[PLUGIN_FUNC_HANDLE_REQUEST_RESET]);
	plugins_call_init_reverse(srv,offsets[PLUGIN_FUNC_HANDLE_CONNECTION_CLOSE]);

	return HANDLER_GO_ON;
}

void plugins_free(server *srv) {
	if (srv->plugin_slots) {
		plugins_call_cleanup(srv);
		free(srv->plugin_slots);
		srv->plugin_slots = NULL;
	}

	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		plugin_free(((plugin **)srv->plugins.ptr)[i]);
	}
	free(srv->plugins.ptr);
	srv->plugins.ptr = NULL;
	srv->plugins.used = 0;
	array_free_data(&plugin_stats);
}
