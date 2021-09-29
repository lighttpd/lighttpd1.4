#ifndef LI_H2_H
#define LI_H2_H
#include "first.h"

#include "sys-time.h"

#include "base_decls.h"
#include "buffer.h"

#include "ls-hpack/lshpack.h"

struct chunkqueue;      /* declaration */

typedef enum {
    H2_FTYPE_DATA          = 0x00,
    H2_FTYPE_HEADERS       = 0x01,
    H2_FTYPE_PRIORITY      = 0x02,
    H2_FTYPE_RST_STREAM    = 0x03,
    H2_FTYPE_SETTINGS      = 0x04,
    H2_FTYPE_PUSH_PROMISE  = 0x05,
    H2_FTYPE_PING          = 0x06,
    H2_FTYPE_GOAWAY        = 0x07,
    H2_FTYPE_WINDOW_UPDATE = 0x08,
    H2_FTYPE_CONTINUATION  = 0x09
} request_h2ftype_t;

typedef enum {
    H2_SETTINGS_HEADER_TABLE_SIZE      = 0x01,
    H2_SETTINGS_ENABLE_PUSH            = 0x02,
    H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    H2_SETTINGS_INITIAL_WINDOW_SIZE    = 0x04,
    H2_SETTINGS_MAX_FRAME_SIZE         = 0x05,
    H2_SETTINGS_MAX_HEADER_LIST_SIZE   = 0x06
} request_h2settings_t;

typedef enum {
    H2_FLAG_END_STREAM  = 0x01,  /* DATA HEADERS */
    H2_FLAG_END_HEADERS = 0x04,  /*      HEADERS PUSH_PROMISE CONTINUATION */
    H2_FLAG_PADDED      = 0x08,  /* DATA HEADERS PUSH_PROMISE */
    H2_FLAG_PRIORITY    = 0x20,  /*      HEADERS */
    H2_FLAG_ACK         = 0x01   /* PING SETTINGS*/
} request_h2flag_t;

typedef enum {
    H2_E_NO_ERROR            = 0x00,
    H2_E_PROTOCOL_ERROR      = 0x01,
    H2_E_INTERNAL_ERROR      = 0x02,
    H2_E_FLOW_CONTROL_ERROR  = 0x03,
    H2_E_SETTINGS_TIMEOUT    = 0x04,
    H2_E_STREAM_CLOSED       = 0x05,
    H2_E_FRAME_SIZE_ERROR    = 0x06,
    H2_E_REFUSED_STREAM      = 0x07,
    H2_E_CANCEL              = 0x08,
    H2_E_COMPRESSION_ERROR   = 0x09,
    H2_E_CONNECT_ERROR       = 0x0a,
    H2_E_ENHANCE_YOUR_CALM   = 0x0b,
    H2_E_INADEQUATE_SECURITY = 0x0c,
    H2_E_HTTP_1_1_REQUIRED   = 0x0d
} request_h2error_t;

typedef enum {
    H2_STATE_IDLE,
    H2_STATE_RESERVED_LOCAL,
    H2_STATE_RESERVED_REMOTE,
    H2_STATE_OPEN,
    H2_STATE_HALF_CLOSED_LOCAL,
    H2_STATE_HALF_CLOSED_REMOTE,
    H2_STATE_CLOSED
} request_h2state_t;

struct h2con {
    request_st *r[8];
    uint32_t rused;

    uint32_t h2_cid;
    uint32_t h2_sid;
     int32_t sent_goaway;
    unix_time64_t sent_settings;
    uint32_t s_header_table_size;      /* SETTINGS_HEADER_TABLE_SIZE      */
    uint32_t s_enable_push;            /* SETTINGS_ENABLE_PUSH            */
    uint32_t s_max_concurrent_streams; /* SETTINGS_MAX_CONCURRENT_STREAMS */
     int32_t s_initial_window_size;    /* SETTINGS_INITIAL_WINDOW_SIZE    */
    uint32_t s_max_frame_size;         /* SETTINGS_MAX_FRAME_SIZE         */
    uint32_t s_max_header_list_size;   /* SETTINGS_MAX_HEADER_LIST_SIZE   */
    struct lshpack_dec decoder;
    struct lshpack_enc encoder;
    unix_time64_t half_closed_ts;
};

void h2_send_goaway (connection *con, request_h2error_t e);

int h2_parse_frames (connection *con);

int h2_want_read (connection *con);

void h2_init_con (request_st * restrict h2r, connection * restrict con, const buffer * restrict http2_settings);

int h2_send_1xx (request_st *r, connection *con);

void h2_send_100_continue (request_st *r, connection *con);

void h2_send_headers (request_st *r, connection *con);

uint32_t h2_send_cqdata (request_st *r, connection *con, struct chunkqueue *cq, uint32_t dlen);

void h2_send_end_stream (request_st *r, connection *con);

void h2_retire_stream (request_st *r, connection *con);

void h2_retire_con (request_st *h2r, connection *con);

__attribute_cold__
__attribute_noinline__
int h2_check_con_upgrade_h2c (request_st *r);

#endif
