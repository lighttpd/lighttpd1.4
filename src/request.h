#ifndef _REQUEST_H_
#define _REQUEST_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "http_kv.h"

struct log_error_st;    /* declaration */

typedef struct {
    const array *mimetypes;

    /* virtual-servers */
    const buffer *document_root;
    const buffer *server_name;
    const buffer *server_tag;
    struct log_error_st *errh;

    uint32_t max_request_field_size;
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

    unsigned int http_parseopts;
    unsigned int max_request_size;

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

struct request_st {
    request_config *conf;
    connection *con;

    /** HEADER */
    buffer *uri;
    buffer *orig_uri;

    http_method_t  http_method;
    http_version_t http_version;

    /* strings to the header */
    buffer *http_host; /* not alloced */

    unsigned int htags; /* bitfield of flagged headers present in request */
    array headers;

    /* CONTENT */
    off_t content_length; /* returned by strtoll() */
    off_t te_chunked;

    int keep_alive; /* only request.c can enable it, all other just disable */

    /* internal */
    buffer *pathinfo;
};


int http_request_parse(request_st *r, char *hdrs, const unsigned short *hloffsets, int scheme_port);
int http_request_host_normalize(buffer *b, int scheme_port);
int http_request_host_policy(buffer *b, unsigned int http_parseopts, int scheme_port);

#endif
