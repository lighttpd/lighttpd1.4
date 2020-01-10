#ifndef _BASE_H_
#define _BASE_H_
#include "first.h"

#include <sys/types.h>
#include <sys/time.h>

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "chunk.h"
#include "http_kv.h"
#include "request.h"
#include "sock_addr.h"

struct fdevents;        /* declaration */

#define DIRECT 0        /* con->mode */


typedef struct {
	off_t   content_length;
	unsigned int htags; /* bitfield of flagged headers present in response */
	array headers;
	char send_chunked;
	char resp_body_started;
	char resp_body_finished;
	uint32_t resp_header_len;
} response;

typedef struct {
	buffer *scheme; /* scheme without colon or slashes ( "http" or "https" ) */

	/* authority with optional portnumber ("site.name" or "site.name:8080" ) NOTE: without "username:password@" */
	buffer *authority;

	/* path including leading slash ("/" or "/index.html") - urldecoded, and sanitized  ( buffer_path_simplify() && buffer_urldecode_path() ) */
	buffer *path;
	buffer *path_raw; /* raw path, as sent from client. no urldecoding or path simplifying */
	buffer *query; /* querystring ( everything after "?", ie: in "/index.php?foo=1", query is "foo=1" ) */
} request_uri;

typedef struct {
	buffer *path;
	buffer *basedir; /* path = "(basedir)(.*)" */

	buffer *doc_root; /* path = doc_root + rel_path */
	buffer *rel_path;

	buffer *etag;
} physical;

struct connection {
	/* timestamps */
	time_t read_idle_ts;
	time_t close_timeout_ts;
	time_t write_request_ts;

	time_t connection_start;
	uint32_t request_count;      /* number of requests handled in this connection */
	int keep_alive_idle;         /* remember max_keep_alive_idle from config */

	fdnode *fdn;                 /* fdevent (fdnode *) object */
	int fd;                      /* the FD for this connection */
	int ndx;                     /* reverse mapping to server->connection[ndx] */

	/* fd states */
	int is_readable;
	int is_writable;
	int is_ssl_sock;

	chunkqueue *write_queue;      /* a large queue for low-level write ( HTTP response ) [ file, mem ] */
	chunkqueue *read_queue;       /* a small queue for low-level read ( HTTP request ) [ mem ] */

	int traffic_limit_reached;

	off_t bytes_written;          /* used by mod_accesslog, mod_rrd */
	off_t bytes_written_cur_second; /* used by mod_accesslog, mod_rrd */
	off_t bytes_read;             /* used by mod_accesslog, mod_rrd */

	sock_addr dst_addr;
	buffer *dst_addr_buf;

	/* request */
	int http_status;

	request_st request;
	request_uri uri;
	physical physical;
	response response;

	int mode;                    /* DIRECT (0) or plugin id */

	server *srv;

	void *plugin_slots;

	request_config conf;
	void *config_data_base;

	uint16_t proto_default_port;

	struct server_socket *srv_socket;   /* reference to the server-socket */
	int (* network_write)(struct connection *con, chunkqueue *cq, off_t max_bytes);
	int (* network_read)(struct connection *con, chunkqueue *cq, off_t max_bytes);
};

typedef struct {
	connection **ptr;
	uint32_t size;
	uint32_t used;
} connections;

typedef struct {
	void *ptr;
	uint32_t used;
	uint32_t size;
} buffer_plugin;

typedef struct {
	/*(used sparsely, if at all, after config at startup)*/

	uint32_t max_request_field_size;
	unsigned char log_state_handling;
	unsigned char log_request_header_on_error;
	unsigned char http_header_strict;
	unsigned char http_host_strict;
	unsigned char http_host_normalize;
	unsigned char http_method_get_body;
	unsigned char high_precision_timestamps;
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
	const char *event_handler;
	buffer *pid_file;
	buffer *modules_dir;
	array *modules;
	array *config_touched;
	array empty_array;
} server_config;

typedef struct server_socket {
	sock_addr addr;
	int       fd;

	unsigned short is_ssl;
	unsigned short sidx;

	fdnode *fdn;
	server *srv;
	buffer *srv_token;
} server_socket;

typedef struct {
	server_socket **ptr;

	uint32_t size;
	uint32_t used;
} server_socket_array;

struct server {
	void *plugin_slots;
	array *config_context;

	struct fdevents *ev;
	int (* network_backend_write)(int fd, chunkqueue *cq, off_t max_bytes, log_error_st *errh);
	handler_t (* request_env)(connection *con);

	/* buffers */
	buffer *tmp_buf;

	connections conns;
	connections joblist;
	connections fdwaitqueue;

	/* counters */
	int con_opened;
	int con_read;
	int con_written;
	int con_closed;

	int max_fds;    /* max possible fds */
	int max_fds_lowat;/* low  watermark */
	int max_fds_hiwat;/* high watermark */
	int cur_fds;    /* currently used fds */
	int sockets_disabled;

	uint32_t max_conns;

	log_error_st *errh;

	time_t loadts;
	double loadavg[3];

	/* members used at start-up or rarely used */

	server_config srvconf;
	void *config_data_base;

	server_socket_array srv_sockets;
	server_socket_array srv_sockets_inherited;
	buffer_plugin plugins;

	time_t startup_ts;

	uid_t uid;
	gid_t gid;
	pid_t pid;
};


#endif
