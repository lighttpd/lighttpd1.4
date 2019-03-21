#ifndef _BASE_H_
#define _BASE_H_
#include "first.h"

#include "settings.h"

#include <sys/types.h>
#include <sys/time.h>

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "chunk.h"
#include "http_kv.h"
#include "sock_addr.h"
#include "etag.h"

struct fdevents;        /* declaration */
struct stat_cache;      /* declaration */

#define DIRECT 0        /* con->mode */


typedef struct {
	/** HEADER */
	/* the request-line */
	buffer *request;
	buffer *uri;

	buffer *orig_uri;

	http_method_t  http_method;
	http_version_t http_version;

	/* strings to the header */
	buffer *http_host; /* not alloced */

	unsigned int htags; /* bitfield of flagged headers present in request */
	array  *headers;

	/* CONTENT */
	off_t content_length; /* returned by strtoll() */
	off_t te_chunked;

	/* internal */
	buffer *pathinfo;
} request;

typedef struct {
	off_t   content_length;
	unsigned int htags; /* bitfield of flagged headers present in response */
	array  *headers;
	int send_chunked;
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

typedef struct {
	array *mimetypes;

	/* virtual-servers */
	buffer *document_root;
	buffer *server_name;
	buffer *error_handler;
	buffer *error_handler_404;
	buffer *server_tag;
	buffer *dirlist_encoding;
	buffer *errorfile_prefix;
	buffer *socket_perms;

	unsigned short high_precision_timestamps;
	unsigned short max_keep_alive_requests;
	unsigned short max_keep_alive_idle;
	unsigned short max_read_idle;
	unsigned short max_write_idle;
	unsigned short use_xattr;
	unsigned short follow_symlink;
	unsigned short range_requests;
	unsigned short stream_request_body;
	unsigned short stream_response_body;
	unsigned short error_intercept;

	/* debug */

	unsigned short log_file_not_found;
	unsigned short log_request_header;
	unsigned short log_request_handling;
	unsigned short log_response_header;
	unsigned short log_condition_handling;
	unsigned short log_timeouts;


	/* server wide */
	unsigned short use_ipv6, set_v6only; /* set_v6only is only a temporary option */
	unsigned short defer_accept;
	unsigned short ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
	unsigned short allow_http11;
	unsigned short etag_use_inode;
	unsigned short etag_use_mtime;
	unsigned short etag_use_size;
	unsigned short force_lowercase_filenames; /* if the FS is case-insensitive, force all files to lower-case */
	unsigned int http_parseopts;
	unsigned int max_request_size;
	int listen_backlog;

	unsigned short kbytes_per_second; /* connection kb/s limit */

	/* configside */
	unsigned short global_kbytes_per_second; /*  */

	off_t  global_bytes_per_second_cnt;
	/* server-wide traffic-shaper
	 *
	 * each context has the counter which is inited once
	 * a second by the global_kbytes_per_second config-var
	 *
	 * as soon as global_kbytes_per_second gets below 0
	 * the connected conns are "offline" a little bit
	 *
	 * the problem:
	 * we somehow have to loose our "we are writable" signal
	 * on the way.
	 *
	 */
	off_t *global_bytes_per_second_cnt_ptr; /*  */

#if defined(__FreeBSD__) || defined(__NetBSD__) \
 || defined(__OpenBSD__) || defined(__DragonFly__)
	buffer *bsd_accept_filter;
#endif

} specific_config;

/* the order of the items should be the same as they are processed
 * read before write as we use this later */
typedef enum {
	CON_STATE_CONNECT,
	CON_STATE_REQUEST_START,
	CON_STATE_READ,
	CON_STATE_REQUEST_END,
	CON_STATE_READ_POST,
	CON_STATE_HANDLE_REQUEST,
	CON_STATE_RESPONSE_START,
	CON_STATE_WRITE,
	CON_STATE_RESPONSE_END,
	CON_STATE_ERROR,
	CON_STATE_CLOSE
} connection_state_t;

typedef enum {
	/* condition not active at the moment because itself or some
	 * pre-condition depends on data not available yet
	 */
	COND_RESULT_UNSET,

	/* special "unset" for branches not selected due to pre-conditions
	 * not met (but pre-conditions are not "unset" anymore)
	 */
	COND_RESULT_SKIP,

	/* actually evaluated the condition itself */
	COND_RESULT_FALSE, /* not active */
	COND_RESULT_TRUE   /* active */
} cond_result_t;

typedef struct cond_cache_t {
	/* current result (with preconditions) */
	cond_result_t result;
	/* result without preconditions (must never be "skip") */
	cond_result_t local_result;
	int patterncount;
	int matches[3 * 10];
	buffer *comp_value; /* just a pointer */
} cond_cache_t;

struct connection {
	connection_state_t state;

	/* timestamps */
	time_t read_idle_ts;
	time_t close_timeout_ts;
	time_t write_request_ts;

	time_t connection_start;
	time_t request_start;
	struct timespec request_start_hp;

	size_t request_count;        /* number of requests handled in this connection */
	size_t loops_per_request;    /* to catch endless loops in a single request
				      *
				      * used by mod_rewrite, mod_fastcgi, ... and others
				      * this is self-protection
				      */

	fdnode *fdn;                 /* fdevent (fdnode *) object */
	int fd;                      /* the FD for this connection */
	int ndx;                     /* reverse mapping to server->connection[ndx] */

	/* fd states */
	int is_readable;
	int is_writable;
	int is_ssl_sock;

	int keep_alive;              /* only request.c can enable it, all other just disable */
	int keep_alive_idle;         /* remember max_keep_alive_idle from config */

	int file_started;
	int file_finished;

	chunkqueue *write_queue;      /* a large queue for low-level write ( HTTP response ) [ file, mem ] */
	chunkqueue *read_queue;       /* a small queue for low-level read ( HTTP request ) [ mem ] */
	chunkqueue *request_content_queue; /* takes request-content into tempfile if necessary [ tempfile, mem ]*/

	int traffic_limit_reached;

	off_t bytes_written;          /* used by mod_accesslog, mod_rrd */
	off_t bytes_written_cur_second; /* used by mod_accesslog, mod_rrd */
	off_t bytes_read;             /* used by mod_accesslog, mod_rrd */
	off_t bytes_header;

	int http_status;

	sock_addr dst_addr;
	buffer *dst_addr_buf;

	/* request */
	request  request;
	request_uri uri;
	physical physical;
	response response;

	size_t header_len;

	array  *environment; /* used to pass lighttpd internal stuff to the FastCGI/CGI apps, setenv does that */

	unsigned int mode;           /* DIRECT (0) or plugin id */
	int async_callback;

	log_error_st *errh;

	void **plugin_ctx;           /* plugin connection specific config */

	specific_config conf;        /* global connection specific config */
	cond_cache_t *cond_cache;

	buffer *server_name;
	buffer *proto;

	/* error-handler */
	int error_handler_saved_status;
	http_method_t error_handler_saved_method;

	struct server_socket *srv_socket;   /* reference to the server-socket */
	int (* network_write)(struct server *srv, struct connection *con, chunkqueue *cq, off_t max_bytes);
	int (* network_read)(struct server *srv, struct connection *con, chunkqueue *cq, off_t max_bytes);

	/* etag handling */
	etag_flags_t etag_flags;

	int8_t conditional_is_valid[16]; /* MUST be >= COMP_LAST_ELEMENT] */
};

typedef struct {
	connection **ptr;
	size_t size;
	size_t used;
} connections;

typedef struct {
	time_t  mtime;  /* the key */
	buffer *str;    /* a buffer for the string represenation */
} mtime_cache_type;

typedef struct {
	void  *ptr;
	size_t used;
	size_t size;
} buffer_plugin;

typedef struct {
	unsigned short port;
	buffer *bindhost;

	buffer *errorlog_file;
	unsigned short errorlog_use_syslog;
	buffer *breakagelog_file;

	unsigned short dont_daemonize;
	unsigned short preflight_check;
	buffer *changeroot;
	buffer *username;
	buffer *groupname;

	buffer *pid_file;

	buffer *event_handler;

	buffer *modules_dir;
	buffer *network_backend;
	array *modules;
	array *upload_tempdirs;
	unsigned int upload_temp_file_size;
	unsigned int max_request_field_size;

	unsigned short max_worker;
	unsigned short max_fds;
	unsigned short max_conns;

	unsigned short log_request_header_on_error;
	unsigned short log_state_handling;

	int stat_cache_engine;
	unsigned short enable_cores;
	unsigned short reject_expect_100_with_417;
	buffer *xattr_name;

	unsigned short http_header_strict;
	unsigned short http_host_strict;
	unsigned short http_host_normalize;
	unsigned short http_url_normalize;
	unsigned short http_method_get_body;
	unsigned short high_precision_timestamps;
	time_t loadts;
	double loadavg[3];
	buffer *syslog_facility;

	unsigned short compat_module_load;
	unsigned short systemd_socket_activation;
} server_config;

typedef struct server_socket {
	sock_addr addr;
	int       fd;

	unsigned short is_ssl;
	unsigned short sidx;

	fdnode *fdn;
	buffer *srv_token;
} server_socket;

typedef struct {
	server_socket **ptr;

	size_t size;
	size_t used;
} server_socket_array;

struct server {
	server_socket_array srv_sockets;

	struct fdevents *ev;

	buffer_plugin plugins;
	void *plugin_slots;

	/* counters */
	int con_opened;
	int con_read;
	int con_written;
	int con_closed;

	int max_fds;    /* max possible fds */
	int max_fds_lowat;/* low  watermark */
	int max_fds_hiwat;/* high watermark */
	int cur_fds;    /* currently used fds */
	int want_fds;   /* waiting fds */
	int sockets_disabled;

	size_t max_conns;

	/* buffers */
	buffer *parse_full_path;
	buffer *response_header;
	buffer *response_range;
	buffer *tmp_buf;

	buffer *tmp_chunk_len;

	buffer *empty_string; /* is necessary for cond_match */

	buffer *cond_check_buf;

	/* caches */
	mtime_cache_type mtime_cache[FILE_CACHE_MAX];

	array *split_vals;

	log_error_st *errh;

	/* Timestamps */
	time_t cur_ts;
	time_t last_generated_date_ts;
	time_t last_generated_debug_ts;
	time_t startup_ts;

	buffer *ts_debug_str;
	buffer *ts_date_str;

	/* config-file */
	array *config_touched;

	array *config_context;
	specific_config **config_storage;

	server_config  srvconf;

	short int config_deprecated;
	short int config_unsupported;

	connections *conns;
	connections *joblist;
	connections *fdwaitqueue;

	struct stat_cache *stat_cache;

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
	array *status;

	int event_handler;

	int (* network_backend_write)(struct server *srv, int fd, chunkqueue *cq, off_t max_bytes);
	handler_t (* request_env)(struct server *srv, connection *con);

	uid_t uid;
	gid_t gid;
	pid_t pid;

	server_socket_array srv_sockets_inherited;
};


#endif
