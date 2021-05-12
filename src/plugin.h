#ifndef _PLUGIN_H_
#define _PLUGIN_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "plugin_config.h"


/**
 * The status array can carry all the status information you want
 * the key to the array is <module-prefix>.<name>
 * and the values are counters
 *
 * example:
 *   fastcgi.backends        = 10
 *   fastcgi.active-backends = 6
 *   fastcgi.backend.<key>.load = 24
 *   fastcgi.backend.<key>....
 *
 *   fastcgi.backend.<key>.disconnects = ...
 */
extern array plugin_stats;


#define SERVER_FUNC(x) \
		static handler_t x(server *srv, void *p_d)

#define CONNECTION_FUNC(x) \
		static handler_t x(connection *con, void *p_d)

#define REQUEST_FUNC(x) \
		static handler_t x(request_st *r, void *p_d)

#define INIT_FUNC(x) \
		__attribute_cold__ \
		static void *x(void)

#define FREE_FUNC(x) \
		__attribute_cold__ \
		static void x(void *p_d)

#define SETDEFAULTS_FUNC   __attribute_cold__ SERVER_FUNC
#define SIGHUP_FUNC        __attribute_cold__ SERVER_FUNC
#define TRIGGER_FUNC       SERVER_FUNC

#define SUBREQUEST_FUNC    REQUEST_FUNC
#define PHYSICALPATH_FUNC  REQUEST_FUNC
#define REQUESTDONE_FUNC   REQUEST_FUNC
#define URIHANDLER_FUNC    REQUEST_FUNC

#define PLUGIN_DATA        int id; \
                           int nconfig; \
                           config_plugin_value_t *cvlist; \
                           struct plugin *self

typedef struct {
	PLUGIN_DATA;
} plugin_data_base;

struct plugin {
	void *data;
	                                                                      /* is called ... */
	handler_t (* handle_uri_raw)           (request_st *r, void *p_d);  /* after uri_raw is set */
	handler_t (* handle_uri_clean)         (request_st *r, void *p_d);  /* after uri is set */
	handler_t (* handle_docroot)           (request_st *r, void *p_d);  /* getting the document-root */
	handler_t (* handle_physical)          (request_st *r, void *p_d);  /* mapping url to physical path */
	handler_t (* handle_request_env)       (request_st *r, void *p_d);  /* (deferred env populate) */
	handler_t (* handle_request_done)      (request_st *r, void *p_d);  /* at the end of a request */
	handler_t (* handle_subrequest_start)  (request_st *r, void *p_d);  /* when handler for request not found yet */
	handler_t (* handle_subrequest)        (request_st *r, void *p_d);  /* handler for request (max one per request) */
	handler_t (* handle_response_start)    (request_st *r, void *p_d);  /* before response headers are written */
	handler_t (* handle_request_reset)     (request_st *r, void *p_d);  /* after request done or request abort */

	handler_t (* handle_connection_accept) (connection *con, void *p_d);  /* after accept() socket */
	handler_t (* handle_connection_shut_wr)(connection *con, void *p_d);  /* done writing to socket */
	handler_t (* handle_connection_close)  (connection *con, void *p_d);  /* before close() of socket */

	handler_t (* handle_trigger)         (server *srv, void *p_d);        /* once a second */
	handler_t (* handle_sighup)          (server *srv, void *p_d);        /* at a sighup */
	handler_t (* handle_waitpid)         (server *srv, void *p_d, pid_t pid, int status); /* upon a child process exit */

	void *(* init)                       ();
	handler_t (* priv_defaults)          (server *srv, void *p_d);
	handler_t (* set_defaults)           (server *srv, void *p_d);
	handler_t (* worker_init)            (server *srv, void *p_d); /* at server startup (each worker after fork()) */
	void (* cleanup)                     (void *p_d);

	const char *name;/* name of the plugin */
	size_t version;
	void *lib;       /* dlopen handle */
};

__attribute_cold__
int plugins_load(server *srv);

__attribute_cold__
void plugins_free(server *srv);

handler_t plugins_call_handle_uri_clean(request_st *r);
handler_t plugins_call_handle_subrequest_start(request_st *r);
handler_t plugins_call_handle_response_start(request_st *r);
handler_t plugins_call_handle_request_env(request_st *r);
handler_t plugins_call_handle_request_done(request_st *r);
handler_t plugins_call_handle_docroot(request_st *r);
handler_t plugins_call_handle_physical(request_st *r);
handler_t plugins_call_handle_request_reset(request_st *r);

handler_t plugins_call_handle_connection_accept(connection *con);
handler_t plugins_call_handle_connection_shut_wr(connection *con);
handler_t plugins_call_handle_connection_close(connection *con);

void plugins_call_handle_trigger(server *srv);
handler_t plugins_call_handle_waitpid(server *srv, pid_t pid, int status);

__attribute_cold__
void plugins_call_handle_sighup(server *srv);

__attribute_cold__
handler_t plugins_call_init(server *srv);

__attribute_cold__
handler_t plugins_call_set_defaults(server *srv);

__attribute_cold__
handler_t plugins_call_worker_init(server *srv);

#endif
