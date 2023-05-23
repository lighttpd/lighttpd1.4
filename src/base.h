#ifndef _BASE_H_
#define _BASE_H_
#include "first.h"

#include "sys-time.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "chunk.h"
#include "http_kv.h"
#include "request.h"
#include "sock_addr.h"

#ifdef _WIN32 /* quick kludges; revisit */
typedef int gid_t;
/*typedef int uid_t;*/
#ifndef __uid_t_defined
#define __uid_t_defined 1
typedef unsigned __uid_t;
typedef __uid_t uid_t;
#endif /* __uid_t_defined */
#endif

struct fdevents;        /* declaration */
struct server_socket;   /* declaration */
struct http_dispatch;   /* declaration */


struct connection {

	request_st request;
	hxcon *hx;

	int fd;                      /* the FD for this connection */
	fdnode *fdn;                 /* fdevent (fdnode *) object */
	connection *jqnext;

	/* fd states */
	signed char is_readable;
	signed char is_writable;
	char is_ssl_sock;
	char traffic_limit_reached;
	uint16_t revents_err;
	uint16_t proto_default_port;

	chunkqueue *write_queue;      /* a large queue for low-level write ( HTTP response ) [ file, mem ] */
	chunkqueue *read_queue;       /* a small queue for low-level read ( HTTP request ) [ mem ] */

	off_t bytes_written_cur_second; /* used by rate-limiting and mod_status */

	int (* network_write)(struct connection *con, chunkqueue *cq, off_t max_bytes);
	int (* network_read)(struct connection *con, chunkqueue *cq, off_t max_bytes);
	handler_t (* reqbody_read)(struct request_st *r);
	const struct http_dispatch *fn;

	server *srv;
	void *plugin_slots;
	void **plugin_ctx;           /* plugin connection specific config */
	void *config_data_base;

	sock_addr dst_addr;
	buffer dst_addr_buf;
	const struct server_socket *srv_socket;   /* reference to the server-socket */

	/* timestamps */
	unix_time64_t read_idle_ts;
	unix_time64_t close_timeout_ts;
	unix_time64_t write_request_ts;
	unix_time64_t connection_start;

	uint32_t request_count;      /* number of requests handled in this connection */
	int keep_alive_idle;         /* remember max_keep_alive_idle from config */

	connection *next;
	connection *prev;
};

/* log_con_jqueue is in log.c to be defined in shared object */
#define joblist_append(con) connection_jq_append(con)
__declspec_dllimport__
extern connection *log_con_jqueue;
static inline void connection_jq_append(connection * const restrict con);
static inline void connection_jq_append(connection * const restrict con)
{
    if (!con->jqnext) {
        con->jqnext = log_con_jqueue;
        log_con_jqueue = con;
    }
}

typedef struct {
	/*(used sparsely, if at all, after config at startup)*/

	uint32_t max_request_field_size;
	unsigned char log_request_header_on_error;
	unsigned char http_header_strict;
	unsigned char http_host_strict;
	unsigned char http_host_normalize;
	unsigned char http_method_get_body;
	unsigned char high_precision_timestamps;
	unsigned char h2proto;
	unsigned char absolute_dir_redirect;
	unsigned short http_url_normalize;

	unsigned short max_worker;
	unsigned short max_fds;
	unsigned short max_conns;
	unsigned short port;

	unsigned int upload_temp_file_size;
	array *upload_tempdirs;

	unsigned char dont_daemonize;
	unsigned char preflight_check;
	unsigned char enable_cores;
	unsigned char compat_module_load;
	unsigned char config_deprecated;
	unsigned char config_unsupported;
	unsigned char systemd_socket_activation;
	unsigned char errorlog_use_syslog;
	const buffer *syslog_facility;
	const buffer *bindhost;
	const buffer *changeroot;
	const buffer *username;
	const buffer *groupname;
	const buffer *network_backend;
	const array *feature_flags;
	const char *event_handler;
	const char *modules_dir;
	buffer *pid_file;
	array *modules;
	array *config_touched;
	array mimetypes_default;
} server_config;

typedef struct server_socket {
	sock_addr addr;
	int       fd;

	uint8_t is_ssl;
	uint8_t srv_token_colon;
	unsigned short sidx;

	fdnode *fdn;
	server *srv;
	buffer *srv_token;
} server_socket;

typedef struct {
	server_socket **ptr;
	uint32_t used;
} server_socket_array;

struct server {
	void *plugin_slots;
	array *config_context;
	int config_captures;

	struct fdevents *ev;
	int (* network_backend_write)(int fd, chunkqueue *cq, off_t max_bytes, log_error_st *errh);
	handler_t (* request_env)(request_st *r);

	/* buffers */
	buffer *tmp_buf;

	int max_fds;    /* max possible fds */
	int max_fds_lowat;/* low  watermark */
	int max_fds_hiwat;/* high watermark */
	int cur_fds;    /* currently used fds */
	int sockets_disabled;

	uint32_t lim_conns;
	connection *conns;
	connection *conns_pool;

	log_error_st *errh;

	unix_time64_t loadts;
	double loadavg[3];

	/* members used at start-up or rarely used */

	handler_t (* plugins_request_reset)(request_st *r);/*(for cgi.local-redir)*/

	server_config srvconf;
	void *config_data_base;

	server_socket_array srv_sockets;
	server_socket_array srv_sockets_inherited;
	struct { void *ptr; uint32_t used; } plugins;

	unix_time64_t startup_ts;
	unix_time64_t graceful_expire_ts;

	uid_t uid;
	gid_t gid;
	pid_t pid;
	int stdin_fd;

	const buffer *default_server_tag;
	char **argv;
  #ifdef HAVE_PCRE2_H
	void *match_data; /*(shared and reused)*/
  #endif
};


#endif
