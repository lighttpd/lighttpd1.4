#ifndef INCLUDED_GW_BACKEND_H
#define INCLUDED_GW_BACKEND_H

#include "first.h"

#include <sys/types.h>
#include "sys-socket.h"

#include "array.h"
#include "buffer.h"

typedef struct {
    char **ptr;

    size_t size;
    size_t used;
} char_array;

typedef struct gw_proc {
    size_t id; /* id will be between 1 and max_procs */
    buffer *unixsocket; /* config.socket + "-" + id */
    unsigned port;  /* config.port + pno */
    socklen_t saddrlen;
    struct sockaddr *saddr;

    /* either tcp:<host>:<port> or unix:<socket> for debugging purposes */
    buffer *connection_name;

    pid_t pid;   /* PID of the spawned process (0 if not spawned locally) */


    size_t load; /* number of requests waiting on this process */

    time_t last_used; /* see idle_timeout */
    size_t requests;  /* see max_requests */
    struct gw_proc *prev, *next; /* see first */

    time_t disabled_until; /* proc disabled until given time */

    int is_local;

    enum {
        PROC_STATE_RUNNING,    /* alive */
        PROC_STATE_OVERLOADED, /* listen-queue is full */
        PROC_STATE_DIED_WAIT_FOR_PID, /* */
        PROC_STATE_DIED,       /* marked as dead, should be restarted */
        PROC_STATE_KILLED      /* killed (signal sent to proc) */
    } state;
} gw_proc;

typedef struct {
    /* the key that is used to reference this value */
    buffer *id;

    /* list of processes handling this extension
     * sorted by lowest load
     *
     * whenever a job is done move it up in the list
     * until it is sorted, move it down as soon as the
     * job is started
     */
    gw_proc *first;
    gw_proc *unused_procs;

    /*
     * spawn at least min_procs, at max_procs.
     *
     * as soon as the load of the first entry
     * is max_load_per_proc we spawn a new one
     * and add it to the first entry and give it
     * the load
     *
     */

    unsigned short min_procs;
    unsigned short max_procs;
    size_t num_procs;    /* how many procs are started */
    size_t active_procs; /* how many procs in state PROC_STATE_RUNNING */

    unsigned short max_load_per_proc;

    /*
     * kick the process from the list if it was not
     * used for idle_timeout until min_procs is
     * reached. this helps to get the processlist
     * small again we had a small peak load.
     *
     */

    unsigned short idle_timeout;

    /*
     * time after a disabled remote connection is tried to be re-enabled
     *
     *
     */

    unsigned short disable_time;

    /*
     * some gw processes get a little bit larger
     * than wanted. max_requests_per_proc kills a
     * process after a number of handled requests.
     *
     */
    size_t max_requests_per_proc;


    /* config */

    /*
     * host:port
     *
     * if host is one of the local IP adresses the
     * whole connection is local
     *
     * if port is not 0, and host is not specified,
     * "localhost" (INADDR_LOOPBACK) is assumed.
     *
     */
    buffer *host;
    unsigned short port;
    unsigned short family; /* sa_family_t */

    /*
     * Unix Domain Socket
     *
     * instead of TCP/IP we can use Unix Domain Sockets
     * - more secure (you have fileperms to play with)
     * - more control (on locally)
     * - more speed (no extra overhead)
     */
    buffer *unixsocket;

    /* if socket is local we can start the gw process ourself
     *
     * bin-path is the path to the binary
     *
     * check min_procs and max_procs for the number
     * of process to start up
     */
    buffer *bin_path;

    /* bin-path is set bin-environment is taken to
     * create the environement before starting the
     * FastCGI process
     *
     */
    array *bin_env;

    array *bin_env_copy;

    /*
     * docroot-translation between URL->phys and the
     * remote host
     *
     * reasons:
     * - different dir-layout if remote
     * - chroot if local
     *
     */
    buffer *docroot;

    /*
     * check_local tells you if the phys file is stat()ed
     * or not. FastCGI doesn't care if the service is
     * remote. If the web-server side doesn't contain
     * the FastCGI-files we should not stat() for them
     * and say '404 not found'.
     */
    unsigned short check_local;

    /*
     * append PATH_INFO to SCRIPT_FILENAME
     *
     * php needs this if cgi.fix_pathinfo is provided
     *
     */

    unsigned short break_scriptfilename_for_php;

    /*
     * workaround for program when prefix="/"
     *
     * rule to build PATH_INFO is hardcoded for when check_local is disabled
     * enable this option to use the workaround
     *
     */

    unsigned short fix_root_path_name;

    /*
     * If the backend includes X-Sendfile in the response
     * we use the value as filename and ignore the content.
     *
     */
    unsigned short xsendfile_allow;
    array *xsendfile_docroot;

    ssize_t load;

    size_t max_id; /* corresponds most of the time to num_procs */

    buffer *strip_request_uri;

    unsigned short kill_signal; /* we need a setting for this as libfcgi
                                   applications prefer SIGUSR1 while the
                                   rest of the world would use SIGTERM
                                   *sigh* */

    int listen_backlog;
    int refcount;

    char_array args;
} gw_host;

/*
 * one extension can have multiple hosts assigned
 * one host can spawn additional processes on the same
 *   socket (if we control it)
 *
 * ext -> host -> procs
 *    1:n     1:n
 *
 * if the gw process is remote that whole goes down
 * to
 *
 * ext -> host -> procs
 *    1:n     1:1
 *
 * in case of PHP and FCGI_CHILDREN we have again a procs
 * but we don't control it directly.
 *
 */

typedef struct {
    buffer *key; /* like .php */

    int note_is_sent;
    int last_used_ndx;

    gw_host **hosts;

    size_t used;
    size_t size;
} gw_extension;

typedef struct {
    gw_extension **exts;

    size_t used;
    size_t size;
} gw_exts;




#include "base.h"
#include "plugin.h"
#include "response.h"

typedef struct gw_plugin_config {
    gw_exts *exts;
    gw_exts *exts_auth;
    gw_exts *exts_resp;

    array *ext_mapping;

    int balance;
    int proto;
    int debug;
} gw_plugin_config;

/* generic plugin data, shared between all connections */
typedef struct gw_plugin_data {
    PLUGIN_DATA;
    gw_plugin_config **config_storage;

    gw_plugin_config conf; /* used only as long as no gw_handler_ctx is setup */
    pid_t srv_pid;
} gw_plugin_data;

/* connection specific data */
typedef enum {
    GW_STATE_INIT,
    GW_STATE_CONNECT_DELAYED,
    GW_STATE_PREPARE_WRITE,
    GW_STATE_WRITE,
    GW_STATE_READ
} gw_connection_state_t;

#define GW_RESPONDER  1
#define GW_AUTHORIZER 2
#define GW_FILTER     3  /*(not implemented)*/

typedef struct gw_handler_ctx {
    gw_proc *proc;
    gw_host *host;
    gw_extension *ext;
    gw_extension *ext_auth; /* (future: might allow multiple authorizers)*/
    unsigned short gw_mode; /* mode: GW_AUTHORIZER or GW_RESPONDER */

    gw_connection_state_t state;
    time_t   state_timestamp;

    chunkqueue *rb; /* read queue */
    chunkqueue *wb; /* write queue */
    off_t     wb_reqlen;

    buffer   *response;

    int       fd;        /* fd to the gw process */
    int       fde_ndx;   /* index into the fd-event buffer */

    pid_t     pid;
    int       reconnects; /* number of reconnect attempts */

    int       request_id;
    int       send_content_body;

    http_response_opts opts;
    gw_plugin_config conf;

    connection *remote_conn;     /* dumb pointer */
    gw_plugin_data *plugin_data; /* dumb pointer */
    handler_t(*stdin_append)(server *srv, struct gw_handler_ctx *hctx);
    handler_t(*create_env)(server *srv, struct gw_handler_ctx *hctx);
    void(*backend_error)(struct gw_handler_ctx *hctx);
    void(*handler_ctx_free)(void *hctx);
} gw_handler_ctx;


void * gw_init(void);
void gw_plugin_config_free(gw_plugin_config *s);
handler_t gw_free(server *srv, void *p_d);
int gw_set_defaults_backend(server *srv, gw_plugin_data *p, data_unset *du, size_t i, int sh_exec);
int gw_set_defaults_balance(server *srv, gw_plugin_config *s, data_unset *du);
handler_t gw_check_extension(server *srv, connection *con, gw_plugin_data *p, int uri_path_handler, size_t hctx_sz);
handler_t gw_connection_reset(server *srv, connection *con, void *p_d);
handler_t gw_handle_subrequest(server *srv, connection *con, void *p_d);
handler_t gw_handle_trigger(server *srv, void *p_d);
handler_t gw_handle_waitpid_cb(server *srv, void *p_d, pid_t pid, int status);

void gw_set_transparent(server *srv, gw_handler_ctx *hctx);

#endif
