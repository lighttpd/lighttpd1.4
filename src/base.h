#ifndef _BASE_H_
#define _BASE_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "config.h"

#include <limits.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include "buffer.h"
#include "array.h"
#include "chunk.h"
#include "keyvalue.h"
#include "settings.h"
#include "fdevent.h"
#include "sys-socket.h"


#if defined HAVE_LIBSSL && defined HAVE_OPENSSL_SSL_H
# define USE_OPENSSL
# include <openssl/ssl.h> 
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

#ifndef SIZE_MAX
# ifdef SIZE_T_MAX
#  define SIZE_MAX SIZE_T_MAX
# else
#  define SIZE_MAX ((size_t)~0)
# endif
#endif

#ifndef SSIZE_MAX
# define SSIZE_MAX ((size_t)~0 >> 1)
#endif

#ifdef __APPLE__
#include <crt_externs.h>
#define environ (* _NSGetEnviron())
#else
extern char **environ;
#endif

/* for solaris 2.5 and NetBSD 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* solaris and NetBSD 1.3.x again */
#if (!defined(HAVE_STDINT_H)) && (!defined(HAVE_INTTYPES_H)) && (!defined(uint32_t))
# define uint32_t u_int32_t
#endif


#ifndef SHUT_WR
# define SHUT_WR 1
#endif

#include "settings.h"

typedef enum { T_CONFIG_UNSET, 
		T_CONFIG_STRING, 
		T_CONFIG_SHORT, 
		T_CONFIG_BOOLEAN, 
		T_CONFIG_ARRAY, 
		T_CONFIG_LOCAL, 
		T_CONFIG_DEPRECATED
} config_values_type_t;

typedef enum { T_CONFIG_SCOPE_UNSET, 
		T_CONFIG_SCOPE_SERVER, 
		T_CONFIG_SCOPE_CONNECTION
} config_scope_type_t;

typedef struct {
	const char *key;
	void *destination;
	
	config_values_type_t type;
	config_scope_type_t scope;
} config_values_t;

typedef enum { DIRECT, EXTERNAL } connection_type;

typedef struct {
	char *key;
	connection_type type;
	char *value;
} request_handler;

typedef struct {
	char *key;
	char *host;
	unsigned short port;
	int used;
	short factor;
} fcgi_connections;


typedef union {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
#endif
	struct sockaddr_in ipv4;
	struct sockaddr plain;
} sock_addr;

/* fcgi_response_header contains ... */
#define HTTP_STATUS         BV(0)
#define HTTP_CONNECTION     BV(1)
#define HTTP_CONTENT_LENGTH BV(2)
#define HTTP_DATE           BV(3)
#define HTTP_LOCATION       BV(4)

typedef struct {
	/** HEADER */
	/* the request-line */
	buffer *request;
	buffer *uri;
	
	buffer *orig_uri;
	
	http_method_t  http_method;
	http_version_t http_version;
	
	buffer *request_line;
	
	/* strings to the header */
	buffer *http_host; /* not alloced */
	const char   *http_range;
	const char   *http_content_type;
	const char   *http_if_modified_since;
	const char   *http_if_none_match;
	
	array  *headers;
	
	/* CONTENT */
	buffer *content;
	size_t content_length; /* returned by strtoul() */
	
	/* internal representation */
	int     accept_encoding;
	
	/* internal */
	buffer *pathinfo;
} request;

typedef struct {
	off_t   content_length;
	int     keep_alive;               /* used by  the subrequests in proxy, cgi and fcgi to say the subrequest was keep-alive or not */
	
	array  *headers;
	
	enum { 
		HTTP_TRANSFER_ENCODING_IDENTITY, HTTP_TRANSFER_ENCODING_CHUNKED
	} transfer_encoding;
} response;

typedef struct {
	buffer *name;
	buffer *etag;
	
	struct stat st;
	
	int    fd;
	int    fde_ndx;
	
	char   *mmap_p;
	size_t mmap_length;
	off_t  mmap_offset;
	
	size_t in_use;
	size_t is_dirty;
	
	time_t stat_ts;
	buffer *content_type;
} file_cache_entry;

typedef struct {
	buffer *scheme;
	buffer *authority;
	buffer *path;
	buffer *path_raw;
	buffer *query;
} request_uri;

typedef struct {
	buffer *path;
	
	buffer *doc_root; /* path = doc_root + rel_path */
	buffer *rel_path;
	
	buffer *etag;
} physical;

typedef struct {
	file_cache_entry **ptr;
	
	size_t size;
	size_t used;
	
	buffer *dir_name;
} file_cache;

typedef struct {
	array *indexfiles;
	array *mimetypes;
	
	/* virtual-servers */
	buffer *document_root;
	buffer *server_name;
	buffer *error_handler;
	buffer *server_tag;
	buffer *dirlist_css;
	buffer *dirlist_encoding;
	buffer *errorfile_prefix;
	
	unsigned short dir_listing;
	unsigned short hide_dotfiles;
	unsigned short max_keep_alive_requests;
	unsigned short max_keep_alive_idle;
	unsigned short max_read_idle;
	unsigned short max_write_idle;
	unsigned short use_xattr;
	unsigned short follow_symlink;
	
	/* debug */
	
	unsigned short log_file_not_found;
	unsigned short log_request_header;
	unsigned short log_request_handling;
	unsigned short log_response_header;
	
	
	/* server wide */
	buffer *ssl_pemfile;
	buffer *ssl_ca_file;
	unsigned short use_ipv6;
	unsigned short is_ssl;
	unsigned short allow_http11;
	unsigned short max_request_size;

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
	
#ifdef USE_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
} specific_config;

typedef enum { CON_STATE_CONNECT, CON_STATE_REQUEST_START, CON_STATE_READ, CON_STATE_REQUEST_END, CON_STATE_READ_POST, CON_STATE_HANDLE_REQUEST, CON_STATE_RESPONSE_START, CON_STATE_WRITE, CON_STATE_RESPONSE_END, CON_STATE_ERROR, CON_STATE_CLOSE } connection_state_t;

typedef struct {
	connection_state_t state;
	
	/* timestamps */
	time_t read_idle_ts;
	time_t close_timeout_ts;
	time_t write_request_ts;
	
	time_t connection_start;
	time_t request_start;
	
	struct timeval start_tv;
	
	size_t request_count;        /* number of requests handled in this connection */
	
	int fd;                      /* the FD for this connection */
	int fde_ndx;                 /* index for the fdevent-handler */
	int ndx;                     /* reverse mapping to server->connection[ndx] */
	
	/* fd states */
	int is_readable;
	int is_writable;
	
	int     keep_alive;           /* only request.c can enable it, all other just disable */
	
	int file_started;
	int file_finished;
	
	chunkqueue *write_queue;
	chunkqueue *read_queue;
	
	int traffic_limit_reached;
	
	off_t bytes_written;          /* used by mod_accesslog, mod_rrd */
	off_t bytes_written_cur_second; /* used by mod_accesslog, mod_rrd */
	off_t bytes_read;             /* used by mod_accesslog, mod_rrd */
	off_t bytes_header;
	
	int http_status;
	
	sock_addr dst_addr;

	/* request */
	buffer *parse_request;
	unsigned int parsed_response; /* bitfield which contains the important header-fields of the parsed response header */
	
	request  request;
	request_uri uri;
	physical physical; 
	response response;
	
	size_t header_len;
	
	buffer *authed_user;
	array  *environment; /* used to pass lighttpd internal stuff to the FastCGI/CGI apps, setenv does that */
	
	/* response */
	int    got_response;
	
	int    in_joblist;
	
	connection_type mode;
	
	file_cache_entry *fce;       /* filecache entry for the selected file */
	
	void **plugin_ctx;           /* plugin connection specific config */
	
	specific_config conf;        /* global connection specific config */
	
	buffer *server_name;
	
	/* error-handler */
	buffer *error_handler;
	int error_handler_saved_status;
	int in_error_handler;
	
	void *srv_socket;   /* reference to the server-socket (typecast to server_socket) */
	
#ifdef USE_OPENSSL
	SSL *ssl;
#endif
} connection;

typedef struct {
	connection **ptr;
	size_t size;
	size_t used;
} connections;


#ifdef HAVE_IPV6
typedef struct {
	int family;
	union {
		struct in6_addr ipv6;
		struct in_addr  ipv4;
	} addr;
	char b2[INET6_ADDRSTRLEN + 1];
	time_t ts;
} inet_ntop_cache_type;
#endif


typedef struct {
	buffer *uri;
	time_t mtime;
	int http_status;
} realpath_cache_type;

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
	buffer *error_logfile;
	unsigned short dont_daemonize;
	buffer *changeroot;
	buffer *username;
	buffer *groupname;
	
	buffer *license;
	buffer *pid_file;
	
	buffer *event_handler;
	
	array *modules;
	
	unsigned short max_worker;
	unsigned short max_fds;
	
	unsigned short log_request_header_on_error;
	unsigned short log_state_handling;
} server_config;

typedef struct {
	sock_addr addr;
	int       fd;
	int       fde_ndx;
	
	buffer *ssl_pemfile;
	buffer *ssl_ca_file;
	unsigned short use_ipv6;
	unsigned short is_ssl;
	unsigned short max_request_size;
	
	buffer *srv_token;
	
#ifdef USE_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
} server_socket;

typedef struct {
	server_socket **ptr;
	
	size_t size;
	size_t used;
} server_socket_array;

typedef struct {
	server_socket_array srv_sockets;
	
	int log_error_fd;
	int log_using_syslog;
	fdevents *ev, *ev_ins;
	
	buffer_plugin plugins;
	void *plugin_slots;
	
	int con_opened;
	int con_read;
	int con_written;
	int con_closed;
	
	int ssl_is_init;
	
	int max_fds;    /* max possible fds */
	int cur_fds;    /* currently used fds */
	int want_fds;   /* waiting fds */
	int sockets_disabled;
	
	/* buffers */
	buffer *parse_full_path;
	buffer *response_header;
	buffer *error_log;
	buffer *response_range;
	buffer *tmp_buf;
	
	buffer *tmp_chunk_len;
	
	buffer *range_buf;
	
	buffer *empty_string; /* is necessary for cond_match */
	
	/* caches */
#ifdef HAVE_IPV6
	inet_ntop_cache_type inet_ntop_cache[INET_NTOP_CACHE_MAX];
#endif
	mtime_cache_type mtime_cache[FILE_CACHE_MAX];

	array *split_vals;
	
	/* Timestamps */
	time_t cur_ts;
	time_t last_generated_date_ts;
	time_t last_generated_debug_ts;
	time_t startup_ts;
	
	buffer *ts_debug_str;
	buffer *ts_date_str;
	
	/* config-file */
	array *config;
	array *config_touched;
	
	array *config_context;
	specific_config **config_storage;
	
	server_config  srvconf;
	
	int config_deprecated;
	
	connections *conns;
	connections *joblist;
	connections *fdwaitqueue;
	
	file_cache  *file_cache;
	buffer      *file_cache_etag;
	
	buffer_array *config_patches;
	
	fdevent_handler_t event_handler;
} server;


#endif
