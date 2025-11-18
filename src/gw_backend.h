#ifndef INCLUDED_GW_BACKEND_H
#define INCLUDED_GW_BACKEND_H

#include "first.h"

#include <sys/types.h>
#include "sys-socket.h"

#include "array.h"
#include "buffer.h"

typedef struct {
    char **ptr;
    uint32_t used;
} char_array;

typedef struct gw_proc {
    struct gw_proc *next; /* see first */
    enum {
        PROC_STATE_RUNNING,    /* alive */
        PROC_STATE_OVERLOADED, /* listen-queue is full */
        PROC_STATE_DIED_WAIT_FOR_PID, /* */
        PROC_STATE_DIED,       /* marked as dead, should be restarted */
        PROC_STATE_KILLED      /* killed (signal sent to proc) */
    } state;
    uint32_t load; /* number of requests waiting on this process */
    unix_time64_t last_used; /* see idle_timeout */
    int *stats_load;
    int *stats_connected;
    pid_t pid;   /* PID of the spawned process (0 if not spawned locally) */
    int is_local;
    uint32_t id; /* id will be between 1 and max_procs */
    socklen_t saddrlen;
    struct sockaddr *saddr;

    unix_time64_t disabled_until; /* proc disabled until given time */
    struct gw_proc *prev; /* see first */

    /* either tcp:<host>:<port> or unix:<socket> for debugging purposes */
    buffer *connection_name;
    buffer *unixsocket; /* config.socket + "-" + id */
    unsigned short port;  /* config.port + pno */
} gw_proc;

struct gw_handler_ctx;  /* declaration */

typedef struct {
    /* list of processes handling this extension
     * sorted by lowest load
     *
     * whenever a job is done move it up in the list
     * until it is sorted, move it down as soon as the
     * job is started
     */
    gw_proc *first;

    uint32_t active_procs; /* how many procs in state PROC_STATE_RUNNING */
    uint32_t gw_hash;

    int32_t load;
    int *stats_load;
    int *stats_global_active;

    /*
     * host:port
     *
     * if host is one of the local IP addresses the
     * whole connection is local
     *
     * if port is not 0, and host is not specified,
     * "localhost" (INADDR_LOOPBACK) is assumed.
     *
     */
    unsigned short port;
    unsigned short family; /* sa_family_t */
    const buffer *host;

    /* the key that is used to reference this value */
    const buffer *id;
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
    uint32_t num_procs;    /* how many procs are started */

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

    unsigned short read_timeout;
    unsigned short write_timeout;
    unsigned short connect_timeout;
    struct gw_handler_ctx *hctxs;

    /*
     * some gw processes get a little bit larger
     * than wanted. max_requests_per_proc kills a
     * process after a number of handled requests.
     *
     */
    /*uint32_t max_requests_per_proc;*//* not implemented */


    /* config */

    /*
     * Unix Domain Socket
     *
     * instead of TCP/IP we can use Unix Domain Sockets
     * - more secure (you have fileperms to play with)
     * - more control (on locally)
     * - more speed (no extra overhead)
     */
    const buffer *unixsocket;

    /* if socket is local we can start the gw process ourself
     *
     * bin-path is the path to the binary
     *
     * check min_procs and max_procs for the number
     * of process to start up
     */
    const buffer *bin_path;

    /* bin-path is set bin-environment is taken to
     * create the environment before starting the
     * FastCGI process
     *
     */
    const array *bin_env;

    const array *bin_env_copy;

    /*
     * docroot-translation between URL->phys and the
     * remote host
     *
     * reasons:
     * - different dir-layout if remote
     * - chroot if local
     *
     */
    const buffer *docroot;

    /*
     * append PATH_INFO to SCRIPT_FILENAME
     *
     * php needs this if cgi.fix_pathinfo is provided
     *
     */

    unsigned short break_scriptfilename_for_php;

    /*
     * check_local tells you if the phys file is stat()ed
     * or not. FastCGI doesn't care if the service is
     * remote. If the web-server side doesn't contain
     * the FastCGI-files we should not stat() for them
     * and say '404 not found'.
     */
    unsigned short check_local;

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
    const array *xsendfile_docroot;

    uint32_t max_id; /* corresponds most of the time to num_procs */

    const buffer *strip_request_uri;

    uint8_t upgrade;
    uint8_t tcp_fin_propagate;
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
    const buffer key; /* like .php */

    int note_is_sent;
    int last_used_ndx;

    gw_host **hosts;
    uint32_t used;
    uint32_t size;
} gw_extension;

typedef struct {
    gw_extension *exts;
    uint32_t used;
    uint32_t size;
} gw_exts;




#include "base_decls.h"
#include "chunk.h"
#include "plugin.h"
#include "response.h"

typedef struct gw_plugin_config {
    gw_exts *exts;
    gw_exts *exts_auth;
    gw_exts *exts_resp;
    const array *ext_mapping;
    int balance;
    int proto;
    int debug;
    int upgrade;
} gw_plugin_config;

/* generic plugin data, shared between all connections */
typedef struct gw_plugin_data {
    PLUGIN_DATA;
    pid_t srv_pid; /* must precede gw_plugin_config for mods w/ larger struct */
    gw_plugin_config defaults;/*(must not be used by gw_backend.c: lg struct) */
} gw_plugin_data;

/* connection specific data */
typedef enum {
    GW_STATE_INIT,
    GW_STATE_CONNECT_DELAYED,
    GW_STATE_PREPARE_WRITE,
    GW_STATE_WRITE,
    GW_STATE_READ
} gw_connection_state_t;

struct fdevents;        /* declaration */

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

    chunkqueue *rb; /* read queue */
    off_t     wb_reqlen;
    chunkqueue wb; /* write queue */

    buffer   *response;

    struct fdevents *ev;
    fdnode   *fdn;       /* fdevent (fdnode *) object */
    int       fd;        /* fd to the gw process */
    int       revents;   /* ready events on fd */

    pid_t     pid;
    int       reconnects; /* number of reconnect attempts */

    int       request_id;
    int       send_content_body;

    http_response_opts opts;
    gw_plugin_config conf;

    request_st *r;               /* dumb pointer */
    connection *con;             /* dumb pointer */
    gw_plugin_data *plugin_data; /* dumb pointer */
    unix_time64_t read_ts;
    unix_time64_t write_ts;
    handler_t(*stdin_append)(struct gw_handler_ctx *hctx);
    handler_t(*create_env)(struct gw_handler_ctx *hctx);
    struct gw_handler_ctx *prev;
    struct gw_handler_ctx *next;
    void(*backend_error)(struct gw_handler_ctx *hctx);
    void(*handler_ctx_free)(void *hctx);
} gw_handler_ctx;


__attribute_cold__
__attribute_malloc__
__attribute_returns_nonnull__
void * gw_init(void);

__attribute_cold__
void gw_plugin_config_free(gw_plugin_config *s);

__attribute_cold__
void gw_free(void *p_d);

__attribute_cold__
void gw_exts_clear_check_local(gw_exts *exts);

__attribute_cold__
int gw_set_defaults_backend(server *srv, gw_plugin_data *p, const array *a, gw_plugin_config *s, int sh_exec, const char *cpkkey);

__attribute_cold__
int gw_get_defaults_balance(server *srv, const buffer *b);

__attribute_cold__
void gw_backend_error_trace(const gw_handler_ctx * hctx, const request_st *r, const char *msg);

handler_t gw_check_extension(request_st *r, gw_plugin_config *pconf, gw_plugin_data *p, int uri_path_handler, size_t hctx_sz);
handler_t gw_handle_request_reset(request_st *r, void *p_d);
handler_t gw_handle_subrequest(request_st *r, void *p_d);
handler_t gw_handle_trigger(server *srv, void *p_d);
handler_t gw_handle_waitpid_cb(server *srv, void *p_d, pid_t pid, int status);

void gw_set_transparent(gw_handler_ctx *hctx);

int gw_upgrade_policy (request_st *r, int auth_mode, int upgrade);
int gw_incremental_policy (request_st *r, int upgrade);

#endif
