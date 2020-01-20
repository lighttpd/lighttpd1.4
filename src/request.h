#ifndef _REQUEST_H_
#define _REQUEST_H_
#include "first.h"

#include <time.h>       /* (struct timespec) */

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "http_kv.h"

struct log_error_st;    /* declaration */
struct chunkqueue;      /* declaration */
struct cond_cache_t;    /* declaration */
struct cond_match_t;    /* declaration */

typedef struct {
    unsigned int http_parseopts;
    uint32_t max_request_field_size;
    const array *mimetypes;

    /* virtual-servers */
    const buffer *document_root;
    const buffer *server_name;
    const buffer *server_tag;
    struct log_error_st *errh;

    unsigned int max_request_size;
    unsigned short max_keep_alive_requests;
    unsigned short max_keep_alive_idle;
    unsigned short max_read_idle;
    unsigned short max_write_idle;
    unsigned short stream_request_body;
    unsigned short stream_response_body;
    unsigned char high_precision_timestamps;
    unsigned char allow_http11;
    unsigned char follow_symlink;
    unsigned char etag_flags;
    unsigned char force_lowercase_filenames; /*(case-insensitive file systems)*/
    unsigned char use_xattr;
    unsigned char range_requests;
    unsigned char error_intercept;

    /* debug */
    unsigned char log_file_not_found;
    unsigned char log_request_header;
    unsigned char log_request_handling;
    unsigned char log_response_header;
    unsigned char log_condition_handling;
    unsigned char log_timeouts;
    unsigned char log_state_handling;
    unsigned char log_request_header_on_error;

    unsigned int bytes_per_second; /* connection bytes/sec limit */
    unsigned int global_bytes_per_second;/*total bytes/sec limit for scope*/

    /* server-wide traffic-shaper
     *
     * each context has the counter which is inited once
     * a second by the global_bytes_per_second config-var
     *
     * as soon as global_bytes_per_second gets below 0
     * the connected conns are "offline" a little bit
     *
     * the problem:
     * we somehow have to lose our "we are writable" signal on the way.
     *
     */
    off_t *global_bytes_per_second_cnt_ptr; /*  */

    const buffer *error_handler;
    const buffer *error_handler_404;
    const buffer *errorfile_prefix;
    struct log_error_st *serrh; /* script errh */
} request_config;

typedef struct {
    buffer scheme; /* scheme without colon or slashes ( "http" or "https" ) */

    /* authority with optional portnumber ("site.name" or "site.name:8080" ) NOTE: without "username:password@" */
    buffer authority;

    /* path including leading slash ("/" or "/index.html") - urldecoded, and sanitized  ( buffer_path_simplify() && buffer_urldecode_path() ) */
    buffer path;
    buffer path_raw; /* raw path, as sent from client. no urldecoding or path simplifying */
    buffer query; /* querystring ( everything after "?", ie: in "/index.php?foo=1", query is "foo=1" ) */
} request_uri;

typedef struct {
    buffer path;
    buffer basedir; /* path = "(basedir)(.*)" */

    buffer doc_root; /* path = doc_root + rel_path */
    buffer rel_path;

    buffer etag;
} physical;

/* the order of the items should be the same as they are processed
 * read before write as we use this later e.g. <= CON_STATE_REQUEST_END */
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
} request_state_t;

struct request_st {
    request_state_t state; /*(modules should not modify request state)*/
    int http_status;

    http_method_t http_method;
    http_version_t http_version;

    const plugin *handler_module;
    void **plugin_ctx;           /* plugin connection specific config */
    connection *con;

    /* config conditions (internal) */
    uint32_t conditional_is_valid;
    struct cond_cache_t *cond_cache;
    struct cond_match_t *cond_match;

    request_config conf;

    /* request */
    uint32_t rqst_htags;/* bitfield of flagged headers present in request */
    uint32_t rqst_header_len;
    array rqst_headers;

    request_uri uri;
    physical physical;
    array env; /* used to pass lighttpd internal stuff */

    off_t reqbody_length; /* request Content-Length */
    off_t te_chunked;
    struct chunkqueue *reqbody_queue; /*(might use tempfiles)*/

    buffer *http_host; /* copy of array value buffer ptr; not alloc'ed */
    const buffer *server_name;

    buffer target;
    buffer target_orig;

    buffer pathinfo;
    buffer server_name_buf;

    /* response */
    off_t content_length;
    uint32_t resp_htags; /*bitfield of flagged headers present in response*/
    uint32_t resp_header_len;
    array resp_headers;
    char resp_body_finished;
    char resp_body_started;
    char resp_send_chunked;

    char loops_per_request;  /* catch endless loops in a single request */
    char keep_alive; /* only request.c can enable it, all other just disable */
    char async_callback;

    struct chunkqueue *write_queue;     /* HTTP response queue [ file, mem ] */
    struct chunkqueue *read_queue;      /* HTTP request queue  [ mem ] */
    buffer *tmp_buf;                    /* shared; same as srv->tmp_buf */

    struct timespec start_hp;
    time_t start_ts;

    int error_handler_saved_status; /* error-handler */
    http_method_t error_handler_saved_method; /* error-handler */
};


int http_request_parse(request_st * restrict r, char * restrict hdrs, const unsigned short * restrict hloffsets, int scheme_port);
int http_request_parse_target(request_st *r, int scheme_port);
int http_request_host_normalize(buffer *b, int scheme_port);
int http_request_host_policy(buffer *b, unsigned int http_parseopts, int scheme_port);

#endif
