/* mod_deflate
 *
 *
 * bug fix on Robert Jakabosky from alphatrade.com's lighttp 1.4.10 mod_deflate patch
 *
 * Bug fix and new features:
 * 1) fix loop bug when content-length is bigger than work-block-size*k
 *
 * -------
 *
 * lighttpd-1.4.26.mod_deflate.patch from
 *   https://redmine.lighttpd.net/projects/1/wiki/Docs_ModDeflate
 *
 * -------
 *
 * Patch further modified in this incarnation.
 *
 * Note: this patch only handles completed responses
 *         (r->resp_body_finished)
 *       this patch does not currently handle streaming dynamic responses,
 *       and therefore also does not worry about Transfer-Encoding: chunked
 *       (or having separate con->output_queue for chunked-encoded output)
 *       (or using separate buffers per connection instead of p->tmp_buf)
 *       (or handling interactions with block buffering and write timeouts)
 *
 * Bug fix:
 * - fixed major bug with compressing chunks with offset > 0
 *     x-ref:
 *       "Response breaking in mod_deflate"
 *       https://redmine.lighttpd.net/issues/986
 * - fix broken (in some cases) chunk accounting in deflate_compress_response()
 * - fix broken bzip2
 *     x-ref:
 *       "mod_deflate's bzip2 broken by default"
 *       https://redmine.lighttpd.net/issues/2035
 * - fix mismatch with current chunk interfaces
 *     x-ref:
 *       "Weird things in chunk.c (functions only handling specific cases, unexpected behaviour)"
 *       https://redmine.lighttpd.net/issues/1510
 *
 * Behavior changes from prior patch:
 * - deflate.mimetypes must now be configured to enable compression
 *     deflate.mimetypes = ( )          # compress nothing (disabled; default)
 *     deflate.mimetypes = ( "" )       # compress all mimetypes
 *     deflate.mimetypes = ( "text/" )  # compress text/... mimetypes
 *     x-ref:
 *       "mod_deflate enabled by default"
 *       https://redmine.lighttpd.net/issues/1394
 * - deflate.enabled directive removed (see new behavior of deflate.mimetypes)
 * - deflate.debug removed (was developer debug trace, not end-user debug)
 * - deflate.bzip2 replaced with deflate.allowed-encodings (like mod_compress)
 *     x-ref:
 *       "mod_deflate should allow limiting of compression algorithm from the configuration file"
 *       https://redmine.lighttpd.net/issues/996
 *       "mod_compress disabling methods"
 *       https://redmine.lighttpd.net/issues/1773
 * - deflate.nocompress-url removed since disabling compression for a URL
 *   can now easily be done by setting to a blank list either directive
 *   deflate.accept_encodings = () or deflate.mimetypes = () in a conditional
 *   block, e.g. $HTTP["url"] =~ "....." { deflate.mimetypes = ( ) }
 * - deflate.sync-flush removed; controlled by r->conf.stream_response_body
 *     (though streaming compression not currently implemented in mod_deflate)
 * - inactive directives in this patch
 *       (since r->resp_body_finished required)
 *     deflate.work-block-size
 *     deflate.output-buffer-size
 * - remove weak file size check; SIGBUS is trapped, file that shrink will error
 *     x-ref:
 *       "mod_deflate: filesize check is too weak"
 *       https://redmine.lighttpd.net/issues/1512
 * - change default deflate.min-compress-size from 0 to now be 256
 *   http://webmasters.stackexchange.com/questions/31750/what-is-recommended-minimum-object-size-for-gzip-performance-benefits
 *   Apache 2.4 mod_deflate minimum is 68 bytes
 *   Akamai recommends minimum 860 bytes
 *   Google recommends minimum be somewhere in range between 150 and 1024 bytes
 * - deflate.max-compress-size new directive (in kb like compress.max_filesize)
 * - deflate.mem-level removed (too many knobs for little benefit)
 * - deflate.window-size removed (too many knobs for little benefit)
 *
 * Future:
 * - config directives may be changed, renamed, or removed
 *   e.g. A set of reasonable defaults might be chosen
 *        instead of making them configurable.
 *     deflate.min-compress-size
 * - might add deflate.mimetypes-exclude = ( ... ) for list of mimetypes
 *   to avoid compressing, even if a broader deflate.mimetypes matched,
 *   e.g. to compress all "text/" except "text/special".
 *
 * Implementation notes:
 * - http_chunk_append_mem() used instead of http_chunk_append_buffer()
 *   so that p->tmp_buf can be large and re-used.  This results in an extra copy
 *   of compressed data before data is sent to network, though if the compressed
 *   size is larger than 64k, it ends up being sent to a temporary file on
 *   disk without suffering an extra copy in memory, and without extra chunk
 *   create and destroy.  If this is ever changed to give away buffers, then use
 *   a unique hctx->output buffer per hctx; do not reuse p->tmp_buf across
 *   multiple requests being handled in parallel.
 */
#include "first.h"

#include <sys/types.h>
#include "sys-mmap.h"
#ifdef HAVE_MMAP
#include "sys-setjmp.h"
#endif
#include "sys-stat.h"
#include "sys-time.h"
#include "sys-unistd.h" /* <unistd.h> getpid() read() unlink() write() */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "base.h"
#include "ck.h"
#include "fdevent.h"
#include "log.h"
#include "buffer.h"
#include "http_chunk.h"
#include "http_etag.h"
#include "http_header.h"
#include "http_status.h"
#include "response.h"
#include "stat_cache.h"

#include "plugin.h"

#if defined HAVE_ZLIB_H && defined HAVE_LIBZ
# define USE_ZLIB
# include <zlib.h>
#endif
#ifndef Z_DEFAULT_COMPRESSION
#define Z_DEFAULT_COMPRESSION -1
#endif
#ifndef MAX_WBITS
#define MAX_WBITS 15
#endif

#if defined HAVE_BZLIB_H && defined HAVE_LIBBZ2
# define USE_BZ2LIB
/* we don't need stdio interface */
# define BZ_NO_STDIO
# include <bzlib.h>
#endif

#if defined HAVE_BROTLI_ENCODE_H && defined HAVE_BROTLI
# define USE_BROTLI
# include <brotli/encode.h>
#endif

#if defined HAVE_ZSTD_H && defined HAVE_ZSTD
# define USE_ZSTD
# include <zstd.h>
#endif

#ifndef HAVE_LIBZ
#undef HAVE_LIBDEFLATE
#endif

/* request: accept-encoding */
#define HTTP_ACCEPT_ENCODING_IDENTITY BV(0)
#define HTTP_ACCEPT_ENCODING_GZIP     BV(1)
#define HTTP_ACCEPT_ENCODING_DEFLATE  BV(2)
#define HTTP_ACCEPT_ENCODING_COMPRESS BV(3)
#define HTTP_ACCEPT_ENCODING_BZIP2    BV(4)
#define HTTP_ACCEPT_ENCODING_X_GZIP   BV(5)
#define HTTP_ACCEPT_ENCODING_X_BZIP2  BV(6)
#define HTTP_ACCEPT_ENCODING_BR       BV(7)
#define HTTP_ACCEPT_ENCODING_ZSTD     BV(8)

typedef struct {
	struct {
		int clevel;       /*(compression level)*/
		int windowBits;
		int memLevel;
		int strategy;
	} gzip;
	struct {
		uint32_t quality; /*(compression level)*/
		uint32_t window;
		uint32_t mode;
	} brotli;
	struct {
		int clevel;       /*(compression level)*/
		int strategy;
		int windowLog;
	} zstd;
	struct {
		int clevel;       /*(compression level)*/
	} bzip2;
} encparms;

typedef struct {
	const array	*mimetypes;
	const buffer    *cache_dir;
	unsigned int	max_compress_size;
	unsigned short	min_compress_size;
	unsigned short	output_buffer_size;
	unsigned short	work_block_size;
	unsigned short	sync_flush;
	short		compression_level;
	uint16_t *	allowed_encodings;
	double		max_loadavg;
	const encparms *params;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;

    buffer tmp_buf;
} plugin_data;

typedef struct {
	union {
	      #ifdef USE_ZLIB
		z_stream z;
	      #endif
	      #ifdef USE_BZ2LIB
		bz_stream bz;
	      #endif
	      #ifdef USE_BROTLI
		BrotliEncoderState *br;
	      #endif
	      #ifdef USE_ZSTD
		ZSTD_CStream *cctx;
	      #endif
		int dummy;
	} u;
	off_t bytes_in;
	off_t bytes_out;
	buffer *output;
	struct {
		unsigned short	sync_flush;
		short		compression_level;
		const encparms *params;
	} conf;
	request_st *r;
	int compression_type;
	int cache_fd;
	char *cache_fn;
	chunkqueue in_queue;
} handler_ctx;

__attribute_returns_nonnull__
static handler_ctx *handler_ctx_init (request_st * const r, const plugin_config * const pconf, int compression_type) {
	handler_ctx * const hctx = ck_calloc(1, sizeof(*hctx));
	chunkqueue_init(&hctx->in_queue);
	hctx->cache_fd = -1;
	hctx->compression_type = compression_type;
	hctx->r = r;
	/*(selective copy rather than entire plugin_config)*/
	hctx->conf.sync_flush = pconf->sync_flush;
	hctx->conf.compression_level = pconf->compression_level;
	hctx->conf.params = pconf->params;
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	if (hctx->cache_fn) {
		unlink(hctx->cache_fn);
		free(hctx->cache_fn);
	}
	if (-1 != hctx->cache_fd)
		close(hctx->cache_fd);
      #if 0
	if (hctx->output != &p->tmp_buf) {
		buffer_free(hctx->output);
	}
      #endif
	chunkqueue_reset(&hctx->in_queue);
	free(hctx);
}

INIT_FUNC(mod_deflate_init) {
    plugin_data * const p = ck_calloc(1, sizeof(plugin_data));
  #ifdef USE_ZSTD
    buffer_string_prepare_copy(&p->tmp_buf, ZSTD_CStreamOutSize());
  #else
    buffer_string_prepare_copy(&p->tmp_buf, 65536);
  #endif
    return p;
}

FREE_FUNC(mod_deflate_free) {
    plugin_data *p = p_d;
    free(p->tmp_buf.ptr);
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 1: /* deflate.allowed-encodings */
              case 14:/* deflate.params */
                free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static int mkdir_for_file (char *fn) {
    for (char *p = fn; (p = strchr(p + 1, '/')) != NULL; ) {
        if (p[1] == '\0') return 0; /* ignore trailing slash */
        *p = '\0';
        int rc = mkdir(fn, 0700);
        *p = '/';
        if (0 != rc && errno != EEXIST) return -1;
    }
    return 0;
}

#ifndef _WIN32 /* disable on _WIN32 */
static int mkdir_recursive (char *dir) {
    return 0 == mkdir_for_file(dir) && (0 == mkdir(dir,0700) || errno == EEXIST)
      ? 0
      : -1;
}
#endif

static buffer * mod_deflate_cache_file_name(request_st * const r, const buffer *cache_dir, const buffer * const etag) {
    /* XXX: future: for shorter paths into the cache, we could checksum path,
     *      and then shard it to avoid a huge single directory.
     *      Alternatively, could use &r->uri.path, minus any
     *      (matching) &r->pathinfo suffix, with result url-encoded
     *      Alternative, we could shard etag which is already our "checksum" */
  #ifdef __COVERITY__ /* coverity misses etaglen already checked >= 2 earlier */
    force_assert(buffer_clen(etag) >= 2);
  #endif
    buffer * const tb = r->tmp_buf;
    buffer_copy_path_len2(tb, BUF_PTR_LEN(cache_dir),
                              BUF_PTR_LEN(&r->physical.path));
    buffer_append_str2(tb, CONST_STR_LEN("-"), /*(strip surrounding '"')*/
                           etag->ptr+1, buffer_clen(etag)-2);
    /* translate any '/' (and backslash on Windows) in appended etag to '~' */
    char *ptr = tb->ptr + buffer_clen(tb) - (buffer_clen(etag)-2) - 1;
    while (*++ptr) {
      #if defined(_WIN32) || defined(__CYGWIN__)
        if (*ptr == '/' || *ptr == '\\') *ptr = '~';
      #else
        if (*ptr == '/') *ptr = '~';
      #endif
    }
    return tb;
}

static void mod_deflate_cache_file_open (handler_ctx * const hctx, const buffer * const fn) {
    /* race exists whereby up to # workers might attempt to compress same
     * file at same time if requested at same time, but this is unlikely
     * and resolves itself by atomic rename into place when done */
    const uint32_t fnlen = buffer_clen(fn);
    hctx->cache_fn = ck_malloc(fnlen+1+LI_ITOSTRING_LENGTH+1);
    memcpy(hctx->cache_fn, fn->ptr, fnlen);
    hctx->cache_fn[fnlen] = '.';
    const size_t ilen =
      li_itostrn(hctx->cache_fn+fnlen+1, LI_ITOSTRING_LENGTH, getpid());
    hctx->cache_fn[fnlen+1+ilen] = '\0';
    hctx->cache_fd = fdevent_open_cloexec(hctx->cache_fn, 1, O_RDWR|O_CREAT, 0600);
    if (-1 == hctx->cache_fd) {
        free(hctx->cache_fn);
        hctx->cache_fn = NULL;
    }
}

static int mod_deflate_cache_file_finish (request_st * const r, handler_ctx * const hctx, const buffer * const fn) {
    if (0 != fdevent_rename(hctx->cache_fn, fn->ptr))
        return -1;
    free(hctx->cache_fn);
    hctx->cache_fn = NULL;
    chunkqueue_reset(&r->write_queue);
    int rc = http_chunk_append_file_fd(r, fn, hctx->cache_fd, hctx->bytes_out);
    hctx->cache_fd = -1;
    return rc;
}

static void mod_deflate_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* deflate.mimetypes */
        pconf->mimetypes = cpv->v.a;
        break;
      case 1: /* deflate.allowed-encodings */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->allowed_encodings = cpv->v.v;
        break;
      case 2: /* deflate.max-compress-size */
        pconf->max_compress_size = cpv->v.u;
        break;
      case 3: /* deflate.min-compress-size */
        pconf->min_compress_size = cpv->v.shrt;
        break;
      case 4: /* deflate.compression-level */
        pconf->compression_level = (short)cpv->v.shrt;
        break;
      case 5: /* deflate.output-buffer-size */
        pconf->output_buffer_size = cpv->v.shrt;
        break;
      case 6: /* deflate.work-block-size */
        pconf->work_block_size = cpv->v.shrt;
        break;
      case 7: /* deflate.max-loadavg */
        pconf->max_loadavg = cpv->v.d;
        break;
      case 8: /* deflate.cache-dir */
       #ifndef _WIN32 /* disable on _WIN32 */
        pconf->cache_dir = cpv->v.b;
       #endif
        break;
    #if 0 /*(cpv->k_id remapped in mod_deflate_set_defaults())*/
      case 9: /* compress.filetype */
        pconf->mimetypes = cpv->v.a;
        break;
      case 10:/* compress.allowed-encodings */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->allowed_encodings = cpv->v.v;
        break;
      case 11:/* compress.cache-dir */
        pconf->cache_dir = cpv->v.b;
        break;
      case 12:/* compress.max-filesize */
        pconf->max_compress_size = cpv->v.u;
        break;
      case 13:/* compress.max-loadavg */
        pconf->max_loadavg = cpv->v.d;
        break;
    #endif
      case 14:/* deflate.params */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->params = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_deflate_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_deflate_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_deflate_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_deflate_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static encparms * mod_deflate_parse_params(const array * const a, log_error_st * const errh) {
    encparms * const params = ck_calloc(1, sizeof(encparms));

    /* set defaults */
  #ifdef USE_ZLIB
    params->gzip.clevel = 0; /*(unset)*/
    params->gzip.windowBits = MAX_WBITS;
    params->gzip.memLevel = 8;
    params->gzip.strategy = Z_DEFAULT_STRATEGY;
  #endif
  #ifdef USE_BROTLI
    /* BROTLI_DEFAULT_QUALITY is 11 and can be *very* time-consuming */
    params->brotli.quality = 5;
    params->brotli.window = BROTLI_DEFAULT_WINDOW;
    params->brotli.mode = BROTLI_MODE_GENERIC;
  #endif
  #ifdef USE_ZSTD
    params->zstd.clevel = ZSTD_CLEVEL_DEFAULT;
    params->zstd.strategy = 0; /*(use default strategy)*/
    params->zstd.windowLog = 0;/*(use default windowLog)*/
  #endif
  #ifdef USE_BZ2LIB
    params->bzip2.clevel = 0; /*(unset)*/
  #endif

    for (uint32_t i = 0; i < a->used; ++i) {
        const data_unset * const du = a->data[i];
      #if defined(USE_ZLIB) || defined(USE_BZ2LIB) || defined(USE_BROTLI) \
       || defined(USE_ZSTD)
        int32_t v = config_plugin_value_to_int32(du, -1);
      #endif
      #ifdef USE_BROTLI
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("BROTLI_PARAM_QUALITY"))) {
            /*(future: could check for string and then look for and translate
             * BROTLI_DEFAULT_QUALITY BROTLI_MIN_QUALITY BROTLI_MAX_QUALITY)*/
            if (BROTLI_MIN_QUALITY <= v && v <= BROTLI_MAX_QUALITY)
                params->brotli.quality = (uint32_t)v; /* 0 .. 11 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for BROTLI_PARAM_QUALITY");
            continue;
        }
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("BROTLI_PARAM_LGWIN"))) {
            /*(future: could check for string and then look for and translate
             * BROTLI_DEFAULT_WINDOW
             * BROTLI_MIN_WINDOW_BITS BROTLI_MAX_WINDOW_BITS)*/
            if (BROTLI_MIN_WINDOW_BITS <= v && v <= BROTLI_MAX_WINDOW_BITS)
                params->brotli.window = (uint32_t)v; /* 10 .. 24 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for BROTLI_PARAM_LGWIN");
            continue;
        }
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("BROTLI_PARAM_MODE"))) {
            /*(future: could check for string and then look for and translate
             * BROTLI_MODE_GENERIC BROTLI_MODE_TEXT BROTLI_MODE_FONT)*/
            if (0 <= v && v <= 2)
                params->brotli.mode = (uint32_t)v; /* 0 .. 2 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for BROTLI_PARAM_MODE");
            continue;
        }
      #endif
      #ifdef USE_ZSTD
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("ZSTD_c_compressionLevel"))) {
            params->zstd.clevel = v;
            /*(not warning if number parse error.  future: to detect, could
             * use absurd default to config_plugin_value_to_int32 to detect)*/
            continue;
        }
       #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
        /*(XXX: (selected) experimental API params in zstd v1.4.0)*/
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("ZSTD_c_strategy"))) {
            /*(future: could check for string and then look for and translate
             * enum ZSTD_strategy ZSTD_STRATEGY_MIN ZSTD_STRATEGY_MAX)*/
            #ifndef ZSTD_STRATEGY_MIN
            #define ZSTD_STRATEGY_MIN 1
            #endif
            #ifndef ZSTD_STRATEGY_MAX
            #define ZSTD_STRATEGY_MAX 9
            #endif
            if (ZSTD_STRATEGY_MIN <= v && v <= ZSTD_STRATEGY_MAX)
                params->zstd.strategy = v; /* 1 .. 9 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for ZSTD_c_strategy");
            continue;
        }
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("ZSTD_c_windowLog"))) {
            /*(future: could check for string and then look for and translate
             * ZSTD_WINDOWLOG_MIN ZSTD_WINDOWLOG_MAX)*/
            #ifndef ZSTD_WINDOWLOG_MIN
            #define ZSTD_WINDOWLOG_MIN 10
            #endif
            #ifndef ZSTD_WINDOWLOG_MAX_32
            #define ZSTD_WINDOWLOG_MAX_32 30
            #endif
            #ifndef ZSTD_WINDOWLOG_MAX_64
            #define ZSTD_WINDOWLOG_MAX_64 31
            #endif
            #ifndef ZSTD_WINDOWLOG_MAX
            #define ZSTD_WINDOWLOG_MAX \
             (sizeof(size_t)==4 ? ZSTD_WINDOWLOG_MAX_32 : ZSTD_WINDOWLOG_MAX_64)
            #endif
            if (ZSTD_WINDOWLOG_MIN <= v && v <= ZSTD_WINDOWLOG_MAX) {
                params->zstd.windowLog = v;/* 10 .. 31 *//*(30 max for 32-bit)*/
                /* RFC8878 recommends 8 MB max window size for HTTP encoders
                 * and a future RFC will require 8 MB zstd window size limit */
                if (v > 23) params->zstd.windowLog = 23; /*(8 MB limit)*/
            }
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for ZSTD_c_windowLog");
            continue;
        }
       #endif
      #endif
      #ifdef USE_ZLIB
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("gzip.level"))) {
            if (1 <= v && v <= 9)
                params->gzip.clevel = v; /* 1 .. 9 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for gzip.level");
            continue;
        }
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("gzip.windowBits"))) {
            if (9 <= v && v <= 15)
                params->gzip.windowBits = v; /* 9 .. 15 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for gzip.windowBits");
            continue;
        }
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("gzip.memLevel"))) {
            if (1 <= v && v <= 9)
                params->gzip.memLevel = v; /* 1 .. 9 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for gzip.memLevel");
            continue;
        }
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("gzip.strategy"))) {
            /*(future: could check for string and then look for and translate
             * Z_DEFAULT_STRATEGY Z_FILTERED Z_HUFFMAN_ONLY Z_RLE Z_FIXED)*/
            if (0 <= v && v <= 4)
                params->gzip.strategy = v; /* 0 .. 4 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for gzip.strategy");
            continue;
        }
      #endif
      #ifdef USE_BZ2LIB
        if (buffer_eq_icase_slen(&du->key,
                                 CONST_STR_LEN("bzip2.blockSize100k"))) {
            if (1 <= v && v <= 9) /*(bzip2 blockSize100k param)*/
                params->bzip2.clevel = v; /* 1 .. 9 */
            else
                log_error(errh, __FILE__, __LINE__,
                          "invalid value for bzip2.blockSize100k");
            continue;
        }
      #endif
        log_error(errh, __FILE__, __LINE__,
                  "unrecognized param: %s", du->key.ptr);
    }

    return params;
}

static uint16_t * mod_deflate_encodings_to_flags(const array *encodings) {
    if (encodings->used) {
        uint16_t * const x = ck_calloc(encodings->used+1, sizeof(short));
        int i = 0;
        for (uint32_t j = 0; j < encodings->used; ++j) {
          #if defined(USE_ZLIB) || defined(USE_BZ2LIB) || defined(USE_BROTLI) \
           || defined(USE_ZSTD)
            data_string *ds = (data_string *)encodings->data[j];
          #endif
          #ifdef USE_ZLIB /* "gzip", "x-gzip" */
            if (NULL != strstr(ds->value.ptr, "gzip"))
                x[i++] = HTTP_ACCEPT_ENCODING_GZIP
                       | HTTP_ACCEPT_ENCODING_X_GZIP;
            if (NULL != strstr(ds->value.ptr, "deflate"))
                x[i++] = HTTP_ACCEPT_ENCODING_DEFLATE;
            /*
            if (NULL != strstr(ds->value.ptr, "compress"))
                x[i++] = HTTP_ACCEPT_ENCODING_COMPRESS;
            */
          #endif
          #ifdef USE_BZ2LIB /* "bzip2", "x-bzip2" */
            if (NULL != strstr(ds->value.ptr, "bzip2"))
                x[i++] = HTTP_ACCEPT_ENCODING_BZIP2
                       | HTTP_ACCEPT_ENCODING_X_BZIP2;
          #endif
          #ifdef USE_BROTLI /* "br" (also accepts "brotli") */
            if (NULL != strstr(ds->value.ptr, "br"))
                x[i++] = HTTP_ACCEPT_ENCODING_BR;
          #endif
          #ifdef USE_ZSTD
            if (NULL != strstr(ds->value.ptr, "zstd"))
                x[i++] = HTTP_ACCEPT_ENCODING_ZSTD;
          #endif
        }
        x[i] = 0; /* end of list */
        return x;
    }
    else {
        /* default encodings */
        uint16_t * const x = ck_calloc(4+1, sizeof(short));
        int i = 0;
      #ifdef USE_ZSTD
        x[i++] = HTTP_ACCEPT_ENCODING_ZSTD;
      #endif
      #ifdef USE_BROTLI
        x[i++] = HTTP_ACCEPT_ENCODING_BR;
      #endif
      #ifdef USE_ZLIB
        x[i++] = HTTP_ACCEPT_ENCODING_GZIP
               | HTTP_ACCEPT_ENCODING_X_GZIP
               | HTTP_ACCEPT_ENCODING_DEFLATE;
      #endif
      #ifdef USE_BZ2LIB
        x[i++] = HTTP_ACCEPT_ENCODING_BZIP2
               | HTTP_ACCEPT_ENCODING_X_BZIP2;
      #endif
        x[i] = 0; /* end of list */
        return x;
    }
}

SETDEFAULTS_FUNC(mod_deflate_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("deflate.mimetypes"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.allowed-encodings"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.max-compress-size"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.min-compress-size"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.compression-level"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.output-buffer-size"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.work-block-size"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.max-loadavg"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.cache-dir"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("compress.filetype"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("compress.allowed-encodings"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("compress.cache-dir"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("compress.max-filesize"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("compress.max-loadavg"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("deflate.params"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_deflate"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 9: /* compress.filetype */
                log_warn(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: %s replaced with deflate.mimetypes",
                  cpk[cpv->k_id].k);
                cpv->k_id = 0; /* deflate.mimetypes */
                __attribute_fallthrough__
              case 0: /* deflate.mimetypes */
                /* mod_deflate matches mimetype as prefix of Content-Type
                 * so ignore '*' at end of mimetype for end-user flexibility
                 * in specifying trailing wildcard to grouping of mimetypes */
                for (uint32_t m = 0; m < cpv->v.a->used; ++m) {
                    buffer *mimetype=&((data_string *)cpv->v.a->data[m])->value;
                    size_t len = buffer_clen(mimetype);
                    if (len > 2 && mimetype->ptr[len-1] == '*')
                        buffer_truncate(mimetype, len-1);
                    if (buffer_eq_slen(mimetype,
                                       CONST_STR_LEN("application/javascript")))
                        buffer_copy_string_len(mimetype, "text/javascript", 15);
                }
                if (0 == cpv->v.a->used) cpv->v.a = NULL;
                break;
              case 10:/* compress.allowed-encodings */
                log_warn(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: %s replaced with deflate.allowed-encodings",
                  cpk[cpv->k_id].k);
                cpv->k_id = 1; /* deflate.allowed-encodings */
                __attribute_fallthrough__
              case 1: /* deflate.allowed-encodings */
                cpv->v.v = mod_deflate_encodings_to_flags(cpv->v.a);
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 12:/* compress.max-filesize */
                log_warn(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: %s replaced with deflate.max-compress-size",
                  cpk[cpv->k_id].k);
                cpv->k_id = 2; /* deflate.max-compress-size */
                __attribute_fallthrough__
              case 2: /* deflate.max-compress-size */
              case 3: /* deflate.min-compress-size */
                break;
              case 4: /* deflate.compression-level */
                if ((cpv->v.shrt < 1 || cpv->v.shrt > 9)
                    && *(short *)&cpv->v.shrt != -1) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "compression-level must be between 1 and 9: %hu",
                      cpv->v.shrt);
                    return HANDLER_ERROR;
                }
                break;
              case 5: /* deflate.output-buffer-size */
              case 6: /* deflate.work-block-size */
                break;
              case 13:/* compress.max-loadavg */
                log_warn(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: %s replaced with deflate.max-loadavg",
                  cpk[cpv->k_id].k);
                cpv->k_id = 7; /* deflate.max-loadavg */
                __attribute_fallthrough__
              case 7: /* deflate.max-loadavg */
                cpv->v.d = (!buffer_is_blank(cpv->v.b))
                  ? strtod(cpv->v.b->ptr, NULL)
                  : 0.0;
                break;
              case 11:/* compress.cache-dir */
                log_warn(srv->errh, __FILE__, __LINE__,
                  "DEPRECATED: %s replaced with deflate.cache-dir",
                  cpk[cpv->k_id].k);
                cpv->k_id = 8; /* deflate.cache-dir */
                __attribute_fallthrough__
              case 8: /* deflate.cache-dir */
               #ifndef _WIN32 /* disable on _WIN32 */
                if (!buffer_is_blank(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    const uint32_t len = buffer_clen(b);
                    if (len > 0 && '/' == b->ptr[len-1])
                        buffer_truncate(b, len-1); /*remove end slash*/
                    struct stat st;
                    if (0 != stat(b->ptr,&st) && 0 != mkdir_recursive(b->ptr)) {
                        log_perror(srv->errh, __FILE__, __LINE__,
                          "can't stat %s %s", cpk[cpv->k_id].k, b->ptr);
                        return HANDLER_ERROR;
                    }
                }
                else
               #endif
                    cpv->v.b = NULL;
                break;
             #if 0    /*(handled further above)*/
              case 9: /* compress.filetype */
              case 10:/* compress.allowed-encodings */
              case 11:/* compress.cache-dir */
              case 12:/* compress.max-filesize */
              case 13:/* compress.max-loadavg */
                break;
             #endif
              case 14:/* deflate.params */
                cpv->v.v = mod_deflate_parse_params(cpv->v.a, srv->errh);
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.max_compress_size = 128*1024; /*(128 MB measured as num KB)*/
    p->defaults.min_compress_size = 256;
    p->defaults.compression_level = -1;
    p->defaults.output_buffer_size = 0;
    p->defaults.work_block_size = 2048;
    p->defaults.max_loadavg = 0.0;
    p->defaults.sync_flush = 0;

    static const uint16_t available_encodings[] = {
      #ifdef USE_ZSTD
        HTTP_ACCEPT_ENCODING_ZSTD,
      #endif
      #ifdef USE_BROTLI
        HTTP_ACCEPT_ENCODING_BR,
      #endif
      #ifdef USE_ZLIB
        HTTP_ACCEPT_ENCODING_GZIP,
        HTTP_ACCEPT_ENCODING_X_GZIP,
        HTTP_ACCEPT_ENCODING_DEFLATE,
      #endif
      #ifdef USE_BZ2LIB
        HTTP_ACCEPT_ENCODING_BZIP2,
        HTTP_ACCEPT_ENCODING_X_BZIP2,
      #endif
        0
    };
    *(const uint16_t **)&p->defaults.allowed_encodings = available_encodings;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_deflate_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


#if defined(USE_ZLIB) || defined(USE_BZ2LIB) || defined(USE_BROTLI) \
 || defined(USE_ZSTD)
static int mod_deflate_cache_file_append (handler_ctx * const hctx, const char *out, size_t len) {
    ssize_t wr;
    do {
        wr = write(hctx->cache_fd, out, len);
    } while (wr > 0 ? ((out += wr), (len -= (size_t)wr)) : errno == EINTR);
    return (0 == len) ? 0 : -1;
}

static int stream_http_chunk_append_mem(handler_ctx * const hctx, const char * const out, size_t len) {
    if (0 == len) return 0;
    return (-1 == hctx->cache_fd)
      ? http_chunk_append_mem(hctx->r, out, len)
      : mod_deflate_cache_file_append(hctx, out, len);
}
#endif


#ifdef USE_ZLIB

static int stream_deflate_init(handler_ctx *hctx) {
	z_stream * const z = &hctx->u.z;
	z->zalloc = Z_NULL;
	z->zfree = Z_NULL;
	z->opaque = Z_NULL;
	z->total_in = 0;
	z->total_out = 0;
	z->next_out = (unsigned char *)hctx->output->ptr;
	z->avail_out = hctx->output->size;

	const encparms * const params = hctx->conf.params;
	const int clevel = (NULL != params)
	  ? params->gzip.clevel
	  : hctx->conf.compression_level;
	const int wbits = (NULL != params)
	  ? params->gzip.windowBits
	  : MAX_WBITS;

	if (Z_OK != deflateInit2(z,
				 clevel > 0 ? clevel : Z_DEFAULT_COMPRESSION,
				 Z_DEFLATED,
				 (hctx->compression_type == HTTP_ACCEPT_ENCODING_GZIP)
				  ? (wbits | 16) /*(0x10 flags gzip header, trailer)*/
				  :  wbits,
				 params ? params->gzip.memLevel : 8,/*default memLevel*/
				 params ? params->gzip.strategy : Z_DEFAULT_STRATEGY)) {
		return -1;
	}

	return 0;
}

static int stream_deflate_compress(handler_ctx * const hctx, const unsigned char * const start, off_t st_size) {
	z_stream * const z = &(hctx->u.z);
	size_t len;

	/*(unknown whether or not linked zlib was built with ZLIB_CONST defined)*/
	*((const unsigned char **)&z->next_in) = start;
	z->avail_in = st_size;
	hctx->bytes_in += st_size;

	/* compress data */
	do {
		if (Z_OK != deflate(z, Z_NO_FLUSH)) return -1;

		if (z->avail_out == 0 || z->avail_in > 0) {
			len = hctx->output->size - z->avail_out;
			hctx->bytes_out += len;
			if (0 != stream_http_chunk_append_mem(hctx, hctx->output->ptr, len))
				return -1;
			z->next_out = (unsigned char *)hctx->output->ptr;
			z->avail_out = hctx->output->size;
		}
	} while (z->avail_in > 0);

	return 0;
}

static int stream_deflate_flush(handler_ctx * const hctx, int end) {
	z_stream * const z = &(hctx->u.z);
	size_t len;
	int rc = 0;
	int done;

	/* compress data */
	do {
		done = 1;
		if (end) {
			rc = deflate(z, Z_FINISH);
			if (rc == Z_OK) {
				done = 0;
			} else if (rc != Z_STREAM_END) {
				return -1;
			}
		} else {
			if (hctx->conf.sync_flush) {
				rc = deflate(z, Z_SYNC_FLUSH);
				if (rc != Z_OK) return -1;
			} else if (z->avail_in > 0) {
				rc = deflate(z, Z_NO_FLUSH);
				if (rc != Z_OK) return -1;
			}
		}

		len = hctx->output->size - z->avail_out;
		if (z->avail_out == 0 || (len > 0 && (end || hctx->conf.sync_flush))) {
			hctx->bytes_out += len;
			if (0 != stream_http_chunk_append_mem(hctx, hctx->output->ptr, len))
				return -1;
			z->next_out = (unsigned char *)hctx->output->ptr;
			z->avail_out = hctx->output->size;
		}
	} while (z->avail_in != 0 || !done);

	return 0;
}

static int stream_deflate_end(handler_ctx *hctx) {
	z_stream * const z = &(hctx->u.z);
	int rc = deflateEnd(z);
	if (Z_OK == rc || Z_DATA_ERROR == rc) return 0;

	if (z->msg != NULL) {
		log_error(hctx->r->conf.errh, __FILE__, __LINE__,
		  "deflateEnd error ret=%d, msg=%s", rc, z->msg);
	} else {
		log_error(hctx->r->conf.errh, __FILE__, __LINE__,
		  "deflateEnd error ret=%d", rc);
	}
	return -1;
}

#endif


#ifdef USE_BZ2LIB

static int stream_bzip2_init(handler_ctx *hctx) {
	bz_stream * const bz = &hctx->u.bz;
	bz->bzalloc = NULL;
	bz->bzfree = NULL;
	bz->opaque = NULL;
	bz->total_in_lo32 = 0;
	bz->total_in_hi32 = 0;
	bz->total_out_lo32 = 0;
	bz->total_out_hi32 = 0;
	bz->next_out = hctx->output->ptr;
	bz->avail_out = hctx->output->size;

	const encparms * const params = hctx->conf.params;
	const int clevel = (NULL != params)
	  ? params->bzip2.clevel
	  : hctx->conf.compression_level;

	if (BZ_OK != BZ2_bzCompressInit(bz,
					clevel > 0
					 ? hctx->conf.compression_level
					 : 9, /* blocksize = 900k */
					0,    /* verbosity */
					0)) { /* workFactor: default */
		return -1;
	}

	return 0;
}

static int stream_bzip2_compress(handler_ctx * const hctx, const unsigned char * const start, off_t st_size) {
	bz_stream * const bz = &(hctx->u.bz);
	size_t len;

	bz->next_in = (char *)start;
	bz->avail_in = st_size;
	hctx->bytes_in += st_size;

	/* compress data */
	do {
		if (BZ_RUN_OK != BZ2_bzCompress(bz, BZ_RUN)) return -1;

		if (bz->avail_out == 0 || bz->avail_in > 0) {
			len = hctx->output->size - bz->avail_out;
			hctx->bytes_out += len;
			if (0 != stream_http_chunk_append_mem(hctx, hctx->output->ptr, len))
				return -1;
			bz->next_out = hctx->output->ptr;
			bz->avail_out = hctx->output->size;
		}
	} while (bz->avail_in > 0);

	return 0;
}

static int stream_bzip2_flush(handler_ctx * const hctx, int end) {
	bz_stream * const bz = &(hctx->u.bz);
	size_t len;
	int rc;
	int done;

	/* compress data */
	do {
		done = 1;
		if (end) {
			rc = BZ2_bzCompress(bz, BZ_FINISH);
			if (rc == BZ_FINISH_OK) {
				done = 0;
			} else if (rc != BZ_STREAM_END) {
				return -1;
			}
		} else if (bz->avail_in > 0) {
			/* hctx->conf.sync_flush not implemented here,
			 * which would loop on BZ_FLUSH while BZ_FLUSH_OK
			 * until BZ_RUN_OK returned */
			rc = BZ2_bzCompress(bz, BZ_RUN);
			if (rc != BZ_RUN_OK) {
				return -1;
			}
		}

		len = hctx->output->size - bz->avail_out;
		if (bz->avail_out == 0 || (len > 0 && (end || hctx->conf.sync_flush))) {
			hctx->bytes_out += len;
			if (0 != stream_http_chunk_append_mem(hctx, hctx->output->ptr, len))
				return -1;
			bz->next_out = hctx->output->ptr;
			bz->avail_out = hctx->output->size;
		}
	} while (bz->avail_in != 0 || !done);

	return 0;
}

static int stream_bzip2_end(handler_ctx *hctx) {
	bz_stream * const bz = &(hctx->u.bz);
	int rc = BZ2_bzCompressEnd(bz);
	if (BZ_OK == rc || BZ_DATA_ERROR == rc) return 0;

	log_error(hctx->r->conf.errh, __FILE__, __LINE__,
	  "BZ2_bzCompressEnd error ret=%d", rc);
	return -1;
}

#endif


#ifdef USE_BROTLI

static int stream_br_init(handler_ctx *hctx) {
    BrotliEncoderState * const br = hctx->u.br =
      BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (NULL == br) return -1;

    /*(note: we ignore any errors while tuning parameters here)*/
    const encparms * const params = hctx->conf.params;
    const uint32_t quality = (NULL != params)
      ? params->brotli.quality
      : (hctx->conf.compression_level >= 0) /* 0 .. 11 are valid values */
        ? (uint32_t)hctx->conf.compression_level
        : 5;
        /* BROTLI_DEFAULT_QUALITY is 11 and can be *very* time-consuming */
    if (quality != BROTLI_DEFAULT_QUALITY)
        BrotliEncoderSetParameter(br, BROTLI_PARAM_QUALITY, quality);

    if (params && params->brotli.window != BROTLI_DEFAULT_WINDOW)
        BrotliEncoderSetParameter(br, BROTLI_PARAM_LGWIN,params->brotli.window);

    const buffer *vb;
    if (params && params->brotli.mode != BROTLI_MODE_GENERIC)
        BrotliEncoderSetParameter(br, BROTLI_PARAM_MODE, params->brotli.mode);
    else if ((vb = http_header_response_get(hctx->r, HTTP_HEADER_CONTENT_TYPE,
                                            CONST_STR_LEN("Content-Type")))) {
        /* BROTLI_MODE_GENERIC vs BROTLI_MODE_TEXT or BROTLI_MODE_FONT */
        const uint32_t len = buffer_clen(vb);
        if (0 == strncmp(vb->ptr, "text/", sizeof("text/")-1)
            || (0 == strncmp(vb->ptr, "application/", sizeof("application/")-1)
                && (0 == strncmp(vb->ptr+12,"javascript",sizeof("javascript")-1)
                 || 0 == strncmp(vb->ptr+12,"json",      sizeof("json")-1)
                 || 0 == strncmp(vb->ptr+12,"xml",       sizeof("xml")-1)))
            || (len > 4
                && (0 == strncmp(vb->ptr+len-5, "+json", sizeof("+json")-1)
                 || 0 == strncmp(vb->ptr+len-4, "+xml",  sizeof("+xml")-1))))
            BrotliEncoderSetParameter(br, BROTLI_PARAM_MODE, BROTLI_MODE_TEXT);
        else if (0 == strncmp(vb->ptr, "font/", sizeof("font/")-1))
            BrotliEncoderSetParameter(br, BROTLI_PARAM_MODE, BROTLI_MODE_FONT);
    }

    return 0;
}

static int stream_br_compress(handler_ctx * const hctx, const unsigned char * const start, off_t st_size) {
    const uint8_t *in = (uint8_t *)start;
    BrotliEncoderState * const br = hctx->u.br;
    hctx->bytes_in += st_size;
    while (st_size || BrotliEncoderHasMoreOutput(br)) {
        size_t insz = ((off_t)((~(uint32_t)0) >> 1) > st_size)
          ? (size_t)st_size
          : ((~(uint32_t)0) >> 1);
        size_t outsz = 0;
        BrotliEncoderCompressStream(br, BROTLI_OPERATION_PROCESS,
                                    &insz, &in, &outsz, NULL, NULL);
        const uint8_t *out = BrotliEncoderTakeOutput(br, &outsz);
        st_size -= (st_size - (off_t)insz);
        if (outsz) {
            hctx->bytes_out += (off_t)outsz;
            if (0 != stream_http_chunk_append_mem(hctx, (char *)out, outsz))
                return -1;
        }
    }
    return 0;
}

static int stream_br_flush(handler_ctx * const hctx, int end) {
    const int brmode = end ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_FLUSH;
    BrotliEncoderState * const br = hctx->u.br;
    do {
        size_t insz = 0;
        size_t outsz = 0;
        BrotliEncoderCompressStream(br, brmode,
                                    &insz, NULL, &outsz, NULL, NULL);
        const uint8_t *out = BrotliEncoderTakeOutput(br, &outsz);
        if (outsz) {
            hctx->bytes_out += (off_t)outsz;
            if (0 != stream_http_chunk_append_mem(hctx, (char *)out, outsz))
                return -1;
        }
    } while (BrotliEncoderHasMoreOutput(br));
    return 0;
}

static int stream_br_end(handler_ctx *hctx) {
    BrotliEncoderState * const br = hctx->u.br;
    BrotliEncoderDestroyInstance(br);
    return 0;
}

#endif


#ifdef USE_ZSTD

static int stream_zstd_init(handler_ctx *hctx) {
    ZSTD_CStream * const cctx = hctx->u.cctx = ZSTD_createCStream();
    if (NULL == cctx) return -1;
    hctx->output->used = 0;

    /*(note: we ignore any errors while tuning parameters here)*/
    const encparms * const params = hctx->conf.params;
    if (params) {
        if (params->zstd.clevel && params->zstd.clevel != ZSTD_CLEVEL_DEFAULT) {
            const int level = params->zstd.clevel;
          #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
          #else
            ZSTD_initCStream(cctx, level);
          #endif
        }
      #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
        if (params->zstd.strategy)
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_strategy,
                                   params->zstd.strategy);
        if (params->zstd.windowLog)
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog,
                                   params->zstd.windowLog);
      #endif
    }
    else if (hctx->conf.compression_level >= 0) { /* -1 here is "unset" */
        int level = hctx->conf.compression_level;
      #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_strategy, level);
      #else
        ZSTD_initCStream(cctx, level);
      #endif
    }
    return 0;
}

static int stream_zstd_compress(handler_ctx * const hctx, const unsigned char * const start, off_t st_size) {
    ZSTD_CStream * const cctx = hctx->u.cctx;
    ZSTD_inBuffer zib = { start, (size_t)st_size, 0 };
    ZSTD_outBuffer zob = { hctx->output->ptr,
                           hctx->output->size,
                           hctx->output->used };
    hctx->output->used = 0;
    hctx->bytes_in += st_size;
    while (zib.pos < zib.size) {
      #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
        const size_t rv = ZSTD_compressStream2(cctx,&zob,&zib,ZSTD_e_continue);
      #else
        const size_t rv = ZSTD_compressStream(cctx, &zob, &zib);
      #endif
        if (ZSTD_isError(rv)) return -1;
        if (zib.pos == zib.size) break; /* defer flush */
        hctx->bytes_out += (off_t)zob.pos;
        if (0 != stream_http_chunk_append_mem(hctx, zob.dst, zob.pos))
            return -1;
        zob.pos = 0;
    }
    hctx->output->used = (uint32_t)zob.pos;
    return 0;
}

static int stream_zstd_flush(handler_ctx * const hctx, int end) {
    ZSTD_CStream * const cctx = hctx->u.cctx;
  #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
    const ZSTD_EndDirective endOp = end ? ZSTD_e_end : ZSTD_e_flush;
    ZSTD_inBuffer zib = { NULL, 0, 0 };
  #endif
    ZSTD_outBuffer zob = { hctx->output->ptr,
                           hctx->output->size,
                           hctx->output->used };
    size_t rv;
    do {
      #if ZSTD_VERSION_NUMBER >= 10000+400+0 /* v1.4.0 */
        rv = ZSTD_compressStream2(cctx, &zob, &zib, endOp);
      #else
        rv = end
           ? ZSTD_endStream(cctx, &zob)
           : ZSTD_flushStream(cctx, &zob);
      #endif
        if (ZSTD_isError(rv)) return -1;
        hctx->bytes_out += (off_t)zob.pos;
        if (0 != stream_http_chunk_append_mem(hctx, zob.dst, zob.pos))
            return -1;
        zob.pos = 0;
    } while (0 != rv);
    return 0;
}

static int stream_zstd_end(handler_ctx *hctx) {
    ZSTD_CStream * const cctx = hctx->u.cctx;
    ZSTD_freeCStream(cctx);
    return 0;
}

#endif


static int mod_deflate_stream_init(handler_ctx *hctx) {
	switch(hctx->compression_type) {
#ifdef USE_ZLIB
	case HTTP_ACCEPT_ENCODING_GZIP:
	case HTTP_ACCEPT_ENCODING_DEFLATE:
		return stream_deflate_init(hctx);
#endif
#ifdef USE_BZ2LIB
	case HTTP_ACCEPT_ENCODING_BZIP2:
		return stream_bzip2_init(hctx);
#endif
#ifdef USE_BROTLI
	case HTTP_ACCEPT_ENCODING_BR:
		return stream_br_init(hctx);
#endif
#ifdef USE_ZSTD
	case HTTP_ACCEPT_ENCODING_ZSTD:
		return stream_zstd_init(hctx);
#endif
	default:
		return -1;
	}
}

static int mod_deflate_compress(handler_ctx * const hctx, const unsigned char * const start, off_t st_size) {
	if (0 == st_size) return 0;
	switch(hctx->compression_type) {
#ifdef USE_ZLIB
	case HTTP_ACCEPT_ENCODING_GZIP:
	case HTTP_ACCEPT_ENCODING_DEFLATE:
		return stream_deflate_compress(hctx, start, st_size);
#endif
#ifdef USE_BZ2LIB
	case HTTP_ACCEPT_ENCODING_BZIP2:
		return stream_bzip2_compress(hctx, start, st_size);
#endif
#ifdef USE_BROTLI
	case HTTP_ACCEPT_ENCODING_BR:
		return stream_br_compress(hctx, start, st_size);
#endif
#ifdef USE_ZSTD
	case HTTP_ACCEPT_ENCODING_ZSTD:
		return stream_zstd_compress(hctx, start, st_size);
#endif
	default:
		UNUSED(start);
		return -1;
	}
}

static int mod_deflate_stream_flush(handler_ctx * const hctx, int end) {
	if (0 == hctx->bytes_in) return 0;
	switch(hctx->compression_type) {
#ifdef USE_ZLIB
	case HTTP_ACCEPT_ENCODING_GZIP:
	case HTTP_ACCEPT_ENCODING_DEFLATE:
		return stream_deflate_flush(hctx, end);
#endif
#ifdef USE_BZ2LIB
	case HTTP_ACCEPT_ENCODING_BZIP2:
		return stream_bzip2_flush(hctx, end);
#endif
#ifdef USE_BROTLI
	case HTTP_ACCEPT_ENCODING_BR:
		return stream_br_flush(hctx, end);
#endif
#ifdef USE_ZSTD
	case HTTP_ACCEPT_ENCODING_ZSTD:
		return stream_zstd_flush(hctx, end);
#endif
	default:
		UNUSED(end);
		return -1;
	}
}

static void mod_deflate_note_ratio(request_st * const r, const off_t bytes_out, const off_t bytes_in) {
    /* store compression ratio in environment
     * for possible logging by mod_accesslog
     * (late in response handling, so not seen by most other modules) */
    /*(should be called only at end of successful response compression)*/
    if (0 == bytes_in) return;
    buffer_append_int(
      http_header_env_set_ptr(r, CONST_STR_LEN("ratio")),
      bytes_out * 100 / bytes_in);
}

static int mod_deflate_stream_end(handler_ctx *hctx) {
	switch(hctx->compression_type) {
#ifdef USE_ZLIB
	case HTTP_ACCEPT_ENCODING_GZIP:
	case HTTP_ACCEPT_ENCODING_DEFLATE:
		return stream_deflate_end(hctx);
#endif
#ifdef USE_BZ2LIB
	case HTTP_ACCEPT_ENCODING_BZIP2:
		return stream_bzip2_end(hctx);
#endif
#ifdef USE_BROTLI
	case HTTP_ACCEPT_ENCODING_BR:
		return stream_br_end(hctx);
#endif
#ifdef USE_ZSTD
	case HTTP_ACCEPT_ENCODING_ZSTD:
		return stream_zstd_end(hctx);
#endif
	default:
		return -1;
	}
}

static handler_t mod_deflate_finished(request_st * const r, handler_ctx * const hctx, const buffer * const tb) {
  #ifdef __COVERITY__
    /* coverity misses if hctx->cache_fd is not -1, then tb is not NULL */
    force_assert(-1 == hctx->cache_fd || NULL != tb);
  #endif
    if (-1 != hctx->cache_fd && 0 != mod_deflate_cache_file_finish(r, hctx, tb))
        return HANDLER_ERROR;

  #if 1 /* unnecessary if deflate.min-compress-size is set to a reasonable value */
    if (hctx->bytes_in < hctx->bytes_out)
        log_error(r->conf.errh, __FILE__, __LINE__,
          "uri %s in=%lld smaller than out=%lld", r->target.ptr,
          (long long)hctx->bytes_in, (long long)hctx->bytes_out);
  #endif

    mod_deflate_note_ratio(r, hctx->bytes_out, hctx->bytes_in);
    return HANDLER_GO_ON;
}


#ifdef HAVE_LIBDEFLATE
#include <libdeflate.h>

__attribute_cold__
__attribute_noinline__
static int mod_deflate_using_libdeflate_err (handler_ctx * const hctx, buffer * const fn, const int fd)
{
    if (-1 == fd) {
    }
    else if (fd == hctx->cache_fd) {
        if (0 != ftruncate(fd, 0))
            log_perror(hctx->r->conf.errh, __FILE__, __LINE__, "ftruncate");
        if (0 != lseek(fd, 0, SEEK_SET))
            log_perror(hctx->r->conf.errh, __FILE__, __LINE__, "lseek");
    }
    else {
        if (0 != unlink(fn->ptr))
            log_perror(hctx->r->conf.errh, __FILE__, __LINE__, "unlink");
        close(fd);
    }
    buffer_clear(fn); /*(&p->tmp_buf)*/
    return 0;
}


static int mod_deflate_using_libdeflate_sm (handler_ctx * const hctx)
{
    const encparms * const params = hctx->conf.params;
    const int clevel = (NULL != params)
      ? params->gzip.clevel
      : hctx->conf.compression_level;
    struct libdeflate_compressor * const compressor =
      libdeflate_alloc_compressor(clevel > 0 ? clevel : 6);
      /* Z_DEFAULT_COMPRESSION -1 not supported */
    if (NULL == compressor)
        return 0;

    char * const in = hctx->r->write_queue.first->mem->ptr;
    const size_t in_nbytes = (size_t)hctx->bytes_in;
    buffer * const addrb = hctx->output; /*(&p->tmp_buf)*/
    size_t sz = buffer_string_space(addrb)+1;
    sz = (hctx->compression_type == HTTP_ACCEPT_ENCODING_GZIP)
      ? libdeflate_gzip_compress(compressor, in, in_nbytes, addrb->ptr, sz)
      : libdeflate_zlib_compress(compressor, in, in_nbytes, addrb->ptr, sz);
    libdeflate_free_compressor(compressor);

    if (0 == sz) {
        buffer_clear(addrb);
        return 0;
    }

    chunkqueue_reset(&hctx->r->write_queue);
    hctx->bytes_out = (off_t)sz;
    if (0 != stream_http_chunk_append_mem(hctx, addrb->ptr, sz))
        return mod_deflate_using_libdeflate_err(hctx, addrb, hctx->cache_fd);

    buffer * const vb =
      http_header_response_set_ptr(hctx->r, HTTP_HEADER_CONTENT_LENGTH,
                                   CONST_STR_LEN("Content-Length"));
    buffer_append_int(vb, hctx->bytes_out);
    return 1;
}


#ifdef HAVE_MMAP
#if defined(_LP64) || defined(__LP64__) || defined(_WIN64)

struct mod_deflate_setjmp_params {
    struct libdeflate_compressor *compressor;
    void *out;
    size_t outsz;
};

static off_t mod_deflate_using_libdeflate_setjmp_cb (void *dst, const void *src, off_t len)
{
    const struct mod_deflate_setjmp_params * const params = dst;
    const handler_ctx * const hctx = src;
    const chunk * const c = hctx->r->write_queue.first;
    const char *in = chunk_file_view_dptr(c->file.view, c->offset);
    return (off_t)((hctx->compression_type == HTTP_ACCEPT_ENCODING_GZIP)
      ? libdeflate_gzip_compress(params->compressor, in, (size_t)len,
                                 params->out, params->outsz)
      : libdeflate_zlib_compress(params->compressor, in, (size_t)len,
                                 params->out, params->outsz));
}


static int mod_deflate_using_libdeflate (handler_ctx * const hctx)
{
    buffer * const fn = hctx->output; /*(&p->tmp_buf)*/
    int fd = hctx->cache_fd;
    if (-1 == fd) {
        /* create temp file in temp chunkqueue and pluck from chunkqueue */
        #if 0
        chunkqueue tq = {0,0,0,0,0,0}; /*(fake cq for tempfile creation)*/
        chunkqueue_init(&tq);
        #else
        chunkqueue * const cq = &hctx->r->write_queue;
        chunkqueue tq = *cq; /* copy struct, including tempdir state */
        tq.first = tq.last = NULL; /* discard duplicated chunks from orig cq */
        #endif
        if (0 != chunkqueue_append_mem_to_tempfile(&tq,"",0,hctx->r->conf.errh))
            return 0;
        /* copy temp file fd and fn from temp chunkqueue tq and then reset tq */
        chunk * const c = tq.last;
        fd = c->file.fd;
        c->file.fd = -1;
        buffer_copy_buffer(fn, c->mem);
        buffer_clear(c->mem);
        chunkqueue_reset(&tq);
    }

    const size_t sz =
      libdeflate_zlib_compress_bound(NULL, (size_t)hctx->bytes_in);
    /*(XXX: consider trying posix_fallocate() first,
     * with fallback to ftrunctate() if EOPNOTSUPP)*/
    if (0 != ftruncate(fd, (off_t)sz)) {
        log_perror(hctx->r->conf.errh, __FILE__, __LINE__, "ftruncate");
        return mod_deflate_using_libdeflate_err(hctx, fn, fd);
    }

    /*void *addr = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);*/
    void * const addr = mmap(NULL, sz, PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == addr) {
        log_perror(hctx->r->conf.errh, __FILE__, __LINE__, "mmap");
        return mod_deflate_using_libdeflate_err(hctx, fn, fd);
    }

    const encparms * const params = hctx->conf.params;
    const int clevel = (NULL != params)
      ? params->gzip.clevel
      : hctx->conf.compression_level;
    struct libdeflate_compressor * const compressor =
      libdeflate_alloc_compressor(clevel > 0 ? clevel : 6);
      /* Z_DEFAULT_COMPRESSION -1 not supported */
    if (NULL != compressor) {
        struct mod_deflate_setjmp_params outparams = { compressor, addr, sz };
        hctx->bytes_out =
          sys_setjmp_eval3(mod_deflate_using_libdeflate_setjmp_cb,
                           &outparams, hctx, hctx->bytes_in);
        libdeflate_free_compressor(compressor);
    }

    /*(XXX: we theoretically could assign mmap to FILE_CHUNK in output
     * r->write_queue, for potential use by TLS modules, or if not using
     * sendfile in network_write.c, but we do not (easily) know if either
     * are configured or in use for this request.  Might consider heuristic:
     * (*srv->srvconf.network_backend->ptr == 'w') (writev or write), or
     * to check con->is_ssl_sock.)  These files would be safe to pass to
     * TLS modules to read from mmap without catching SIGBUS since these files
     * are created by lighttpd, either in deflate cache or as temporary file */
    if (0 != munmap(addr, sz))
        log_perror(hctx->r->conf.errh, __FILE__, __LINE__, "munmap");

    if (0 == hctx->bytes_out) {
        const chunk * const c = hctx->r->write_queue.first;
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "SIGBUS in mmap: %s %d", c->mem->ptr, c->file.fd);
    }
    else if (0 != ftruncate(fd, hctx->bytes_out))
        hctx->bytes_out = 0;

    if (0 == hctx->bytes_out)
        return mod_deflate_using_libdeflate_err(hctx, fn, fd);

    if (fd != hctx->cache_fd) {
        chunkqueue * const cq = &hctx->r->write_queue;
        chunkqueue_reset(cq);
        http_chunk_append_file_fd_range(hctx->r, fn, fd, 0, hctx->bytes_out);
        cq->last->file.is_temp = 1;
    }

    buffer * const vb =
      http_header_response_set_ptr(hctx->r, HTTP_HEADER_CONTENT_LENGTH,
                                   CONST_STR_LEN("Content-Length"));
    buffer_append_int(vb, hctx->bytes_out);
    return 1;
}

#endif /* defined(_LP64) || defined(__LP64__) || defined(_WIN64) */
#endif /* HAVE_MMAP */

#endif /* HAVE_LIBDEFLATE */


static off_t mod_deflate_file_chunk_no_mmap(request_st * const r, handler_ctx * const hctx, const chunk * const c, off_t n)
{
    const off_t insz = n;
    const size_t psz = (n < 2*1024*1024) ? (size_t)n : 2*1024*1024;
    char * const p = malloc(psz);
    if (NULL == p) {
        log_perror(r->conf.errh, __FILE__, __LINE__, "malloc");
        return -1;
    }

    ssize_t rd = 0;
    for (n = 0; n < insz; n += rd) {
        rd = chunk_file_pread(c->file.fd, p, (size_t)psz, c->offset+n);
        if (__builtin_expect( (rd > 0), 1)) {
            if (0 == mod_deflate_compress(hctx, (unsigned char *)p, rd))
                continue;
            /*(else error trace printed upon return)*/
        }
        else if (-1 == rd)
            log_perror(r->conf.errh, __FILE__, __LINE__,
              "reading %s failed", c->mem->ptr);
        else /*(0 == rd)*/
            log_error(r->conf.errh, __FILE__, __LINE__,
              "file truncated %s", c->mem->ptr);
        n = -1;
        break;
    }

    free(p);
    return n;
}


#if 0

static off_t mod_deflate_file_chunk_setjmp_cb (void *dst, const void *src, off_t len)
{
    return mod_deflate_compress(dst, (const unsigned char *)src, len);
}


static off_t mod_deflate_file_chunk_mmap(request_st * const r, handler_ctx * const hctx, chunk * const c, off_t n)
{
    /* n is length of entire file since server blocks while compressing
     * (mod_deflate is not recommended for large files;
     *  mod_deflate default upper limit is 128MB; deflate.max-compress-size) */

    const chunk_file_view * const restrict cfv = (!c->file.is_temp)
      ? chunkqueue_chunk_file_view(c, n, r->conf.errh)
      : NULL;
    if (NULL == cfv)
        return mod_deflate_file_chunk_no_mmap(r, hctx, c, n);

    const char * const p = chunk_file_view_dptr(cfv, c->offset);
    off_t len = chunk_file_view_dlen(cfv, c->offset);
    if (len > n) len = n;
    off_t rc = sys_setjmp_eval3(mod_deflate_file_chunk_setjmp_cb, hctx, p, len);
    if (__builtin_expect( (rc < 0), 0)) {
        if (errno == EFAULT)
            log_error(r->conf.errh, __FILE__, __LINE__,
              "SIGBUS in mmap: %s %d", c->mem->ptr, c->file.fd);
        else
            log_error(r->conf.errh, __FILE__, __LINE__, "compress failed.");
        len = -1; /*return -1;*/
    }
    return len;
}

#endif


static off_t mod_deflate_file_chunk(request_st * const r, handler_ctx * const hctx, chunk * const c, off_t n) {
    if (-1 == c->file.fd) {  /* open the file if not already open */
        if (-1 == (c->file.fd = fdevent_open_cloexec(c->mem->ptr, r->conf.follow_symlink, O_RDONLY, 0))) {
            log_perror(r->conf.errh, __FILE__, __LINE__, "open failed %s", c->mem->ptr);
            return -1;
        }
    }
  #if 0
    return mod_deflate_file_chunk_mmap(r, hctx, c, n);
  #else
    return mod_deflate_file_chunk_no_mmap(r, hctx, c, n);
  #endif
}


static handler_t deflate_compress_response(request_st * const r, handler_ctx * const hctx) {
	off_t len, max;
	int close_stream;

	/* move all chunk from write_queue into our in_queue, then adjust
	 * counters since r->write_queue is reused for compressed output */
	chunkqueue * const cq = &r->write_queue;
	len = chunkqueue_length(cq);
	chunkqueue_remove_finished_chunks(cq);
	chunkqueue_append_chunkqueue(&hctx->in_queue, cq);
	cq->bytes_in  -= len;
	cq->bytes_out -= len;

	max = chunkqueue_length(&hctx->in_queue);
      #if 0
	/* calculate max bytes to compress for this call */
	if (hctx->conf.sync_flush && max > (len = hctx->conf.work_block_size << 10)) {
		max = len;
	}
      #endif

	/* Compress chunks from in_queue into chunks for write_queue */
	while (max) {
		chunk *c = hctx->in_queue.first;

		switch(c->type) {
		case MEM_CHUNK:
			len = buffer_clen(c->mem) - c->offset;
			if (len > max) len = max;
			if (mod_deflate_compress(hctx, (unsigned char *)c->mem->ptr+c->offset, len) < 0) {
				log_error(r->conf.errh, __FILE__, __LINE__, "compress failed.");
				return HANDLER_ERROR;
			}
			break;
		case FILE_CHUNK:
			len = c->file.length - c->offset;
			if (len > max) len = max;
			if ((len = mod_deflate_file_chunk(r, hctx, c, len)) < 0) {
				log_error(r->conf.errh, __FILE__, __LINE__,
				  "compress file chunk failed %s", c->mem->ptr);
				return HANDLER_ERROR;
			}
			break;
		default:
			log_error(r->conf.errh, __FILE__, __LINE__, "%d type not known", c->type);
			return HANDLER_ERROR;
		}

		max -= len;
		chunkqueue_mark_written(&hctx->in_queue, len);
	}

	/*(currently should always be true)*/
	/*(current implementation requires response be complete)*/
	close_stream = (r->resp_body_finished
                        && chunkqueue_is_empty(&hctx->in_queue));
	if (mod_deflate_stream_flush(hctx, close_stream) < 0) {
		log_error(r->conf.errh, __FILE__, __LINE__, "flush error");
		return HANDLER_ERROR;
	}

	return close_stream ? HANDLER_FINISHED : HANDLER_GO_ON;
}


static int mod_deflate_choose_encoding (const char *value, const plugin_config * const pconf, const char **label) {
	/* get client side support encodings */
	int accept_encoding = 0;
      #if !defined(USE_ZLIB) && !defined(USE_BZ2LIB) && !defined(USE_BROTLI) \
       && !defined(USE_ZSTD)
	UNUSED(value);
	UNUSED(label);
      #else
        for (; *value; ++value) {
            const char *v;
            while (*value == ' ' || *value == ',') ++value;
            v = value;
            while (*value!=' ' && *value!=',' && *value!=';' && *value!='\0')
                ++value;
            switch (value - v) {
              case 2:
               #ifdef USE_BROTLI
                if (0 == memcmp(v, "br", 2))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_BR;
               #endif
                break;
              case 4:
               #ifdef USE_ZLIB
                if (0 == memcmp(v, "gzip", 4))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_GZIP;
               #endif
               #ifdef USE_ZSTD
                #ifdef USE_ZLIB
                else
                #endif
                if (0 == memcmp(v, "zstd", 4))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_ZSTD;
               #endif
                break;
              case 5:
               #ifdef USE_BZ2LIB
                if (0 == memcmp(v, "bzip2", 5))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_BZIP2;
               #endif
                break;
              case 6:
               #ifdef USE_ZLIB
                if (0 == memcmp(v, "x-gzip", 6))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_X_GZIP;
               #endif
                break;
              case 7:
               #ifdef USE_ZLIB
                if (0 == memcmp(v, "deflate", 7))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_DEFLATE;
               #endif
               #ifdef USE_BZ2LIB
                if (0 == memcmp(v, "x-bzip2", 7))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_X_BZIP2;
               #endif
                break;
             #if 0
              case 8:
                if (0 == memcmp(v, "identity", 8))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_IDENTITY;
                else if (0 == memcmp(v, "compress", 8))
                    accept_encoding |= HTTP_ACCEPT_ENCODING_COMPRESS;
                break;
             #endif
              default:
                break;
            }
            if (*value == ';') {
                while (*value != ',' && *value != '\0') ++value;
            }
            if (*value == '\0') break;
        }
      #endif

	/* select best matching encoding */
	const uint16_t *x = pconf->allowed_encodings;
	if (NULL == x) return 0;
	while (*x && !(*x & accept_encoding)) ++x;
	accept_encoding &= *x;
#ifdef USE_ZSTD
	if (accept_encoding & HTTP_ACCEPT_ENCODING_ZSTD) {
		*label = "zstd";
		return HTTP_ACCEPT_ENCODING_ZSTD;
	} else
#endif
#ifdef USE_BROTLI
	if (accept_encoding & HTTP_ACCEPT_ENCODING_BR) {
		*label = "br";
		return HTTP_ACCEPT_ENCODING_BR;
	} else
#endif
#ifdef USE_ZLIB
	if (accept_encoding & HTTP_ACCEPT_ENCODING_GZIP) {
		*label = "gzip";
		return HTTP_ACCEPT_ENCODING_GZIP;
	} else if (accept_encoding & HTTP_ACCEPT_ENCODING_X_GZIP) {
		*label = "x-gzip";
		return HTTP_ACCEPT_ENCODING_GZIP;
	} else if (accept_encoding & HTTP_ACCEPT_ENCODING_DEFLATE) {
		*label = "deflate";
		return HTTP_ACCEPT_ENCODING_DEFLATE;
	} else
#endif
#ifdef USE_BZ2LIB
	if (accept_encoding & HTTP_ACCEPT_ENCODING_BZIP2) {
		*label = "bzip2";
		return HTTP_ACCEPT_ENCODING_BZIP2;
	} else if (accept_encoding & HTTP_ACCEPT_ENCODING_X_BZIP2) {
		*label = "x-bzip2";
		return HTTP_ACCEPT_ENCODING_BZIP2;
	} else
#endif
	if (0 == accept_encoding) {
		return 0;
	} else {
		return 0;
	}
}

REQUEST_FUNC(mod_deflate_handle_response_start) {
	const buffer *vbro;
	buffer *vb;
	handler_ctx *hctx;
	const char *label;
	off_t len;
	uint32_t etaglen;
	int compression_type;
	handler_t rc;
	int had_vary = 0;

	/*(current implementation requires response be complete)*/
	if (!r->resp_body_finished) return HANDLER_GO_ON;
	if (r->http_method == HTTP_METHOD_HEAD) return HANDLER_GO_ON;
	if (light_btst(r->resp_htags, HTTP_HEADER_TRANSFER_ENCODING))
		return HANDLER_GO_ON;
	if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_ENCODING))
		return HANDLER_GO_ON;

	/* disable compression for some http status types. */
	if (r->http_status < 200)
		return HANDLER_GO_ON; /* r->http_status is 1xx intermed response */
	switch(r->http_status) {
	case 200: /* common case */
	default:
		break;
	case 204:
	case 205:
	case 304:
		/* disable compression as we have no response entity */
		return HANDLER_GO_ON;
	}

	plugin_config pconf;
	mod_deflate_patch_config(r, p_d, &pconf);

	/* check if deflate configured for any mimetypes */
	if (NULL == pconf.mimetypes) return HANDLER_GO_ON;

	/* check if size of response is below min-compress-size or exceeds max*/
	/* (r->resp_body_finished checked at top of routine) */
	len = chunkqueue_length(&r->write_queue);
	if (len <= (off_t)pconf.min_compress_size) return HANDLER_GO_ON;
	if (pconf.max_compress_size /*(max_compress_size in KB)*/
	    && len > ((off_t)pconf.max_compress_size << 10)) {
		return HANDLER_GO_ON;
	}

	/* Check Accept-Encoding for supported encoding. */
	vbro = http_header_request_get(r, HTTP_HEADER_ACCEPT_ENCODING, CONST_STR_LEN("Accept-Encoding"));
	if (NULL == vbro) return HANDLER_GO_ON;

	/* find matching encodings */
	compression_type = mod_deflate_choose_encoding(vbro->ptr, &pconf, &label);
	if (!compression_type) return HANDLER_GO_ON;

	/* Check mimetype in response header "Content-Type" */
	if (NULL != (vbro = http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type")))) {
		if (NULL == array_match_value_prefix(pconf.mimetypes, vbro)) return HANDLER_GO_ON;
	} else {
		/* If no Content-Type set, compress only if first pconf.mimetypes value is "" */
		data_string *mimetype = (data_string *)pconf.mimetypes->data[0];
		if (!buffer_is_blank(&mimetype->value)) return HANDLER_GO_ON;
	}

	/* Vary: Accept-Encoding (response might change according to request Accept-Encoding) */
	if (NULL != (vb = http_header_response_get(r, HTTP_HEADER_VARY, CONST_STR_LEN("Vary")))) {
		had_vary = 1;
		if (!http_header_str_contains_token(BUF_PTR_LEN(vb),
		                                    CONST_STR_LEN("Accept-Encoding")))
			buffer_append_string_len(vb, CONST_STR_LEN(",Accept-Encoding"));
	} else {
		http_header_response_append(r, HTTP_HEADER_VARY,
					    CONST_STR_LEN("Vary"),
					    CONST_STR_LEN("Accept-Encoding"));
	}

	/* check ETag as is done in http_response_handle_cachable()
	 * (slightly imperfect (close enough?) match of ETag "000000" to "000000-gzip") */
	vb = http_header_response_get(r, HTTP_HEADER_ETAG, CONST_STR_LEN("ETag"));
	etaglen = vb ? buffer_clen(vb) : 0;
	if (etaglen && light_btst(r->rqst_htags, HTTP_HEADER_IF_NONE_MATCH)) {
		const buffer *if_none_match = http_header_request_get(r, HTTP_HEADER_IF_NONE_MATCH, CONST_STR_LEN("If-None-Match"));
		if (   r->http_status < 300 /*(want 2xx only)*/
		    && NULL != if_none_match
		    && 0 == strncmp(if_none_match->ptr, vb->ptr, etaglen-1)
		    && if_none_match->ptr[etaglen-1] == '-'
		    && 0 == strncmp(if_none_match->ptr+etaglen, label, strlen(label))) {

			if (http_method_get_head_query(r->http_method)) {
				/* modify ETag response header in-place to remove '"' and append '-label"' */
				vb->ptr[etaglen-1] = '-'; /*(overwrite end '"')*/
				buffer_append_string(vb, label);
				buffer_append_char(vb, '"');
				r->http_status = 304;
			} else {
				r->http_status = 412;
			}
			http_status_set_fin(r, r->http_status);

			/* response_start hook occurs after error docs have been handled.
			 * For now, send back empty response body.
			 * In the future, might extract the error doc code so that it
			 * might be run again if response_start hooks return with
			 * changed http_status and r->handler_module NULL */
			/* clear content length even if 304 since compressed length unknown */
			http_response_body_clear(r, 0);
			return HANDLER_GO_ON;
		}
	}

	if (0.0 < pconf.max_loadavg && pconf.max_loadavg < r->con->srv->loadavg[0]) {
		return HANDLER_GO_ON;
	}

	/* update ETag, if ETag response header is set */
	if (etaglen) {
		/* modify ETag response header in-place to remove '"' and append '-label"' */
		vb->ptr[etaglen-1] = '-'; /*(overwrite end '"')*/
		buffer_append_string(vb, label);
		buffer_append_char(vb, '"');
	}

	/* set Content-Encoding to show selected compression type */
	http_header_response_set(r, HTTP_HEADER_CONTENT_ENCODING, CONST_STR_LEN("Content-Encoding"), label, strlen(label));

	/* clear Content-Length and r->write_queue if HTTP HEAD request
	 * (alternatively, could return original Content-Length with HEAD
	 *  request if ETag not modified and Content-Encoding not added)
	 * (see top of this func where short-circuit is done on HTTP HEAD) */
	if (HTTP_METHOD_HEAD == r->http_method) {
		/* ensure that uncompressed Content-Length is not sent in HEAD response */
		http_response_body_clear(r, 0);
		r->resp_body_finished = 1;
		return HANDLER_GO_ON;
	}

	/* restrict items eligible for cache of compressed responses
	 * (This module does not aim to be a full caching proxy)
	 * response must be complete (not streaming response)
	 * must not have prior Vary response header (before Accept-Encoding added)
	 * must have ETag
	 * must be file
	 * must be single FILE_CHUNK in chunkqueue
	 * must not be chunkqueue temporary file
	 * must be whole file, not partial content
	 * must not be HTTP status 206 Partial Content
	 * must not have Cache-Control 'private' or 'no-store'
	 * Note: small files (< 32k (see http_chunk.c)) will have been read into
	 *       memory (if streaming HTTP/1.1 chunked response) and will end up
	 *       getting stream-compressed rather than cached on disk as compressed
	 *       file
	 */
	buffer *tb = NULL;
	if (pconf.cache_dir
	    && !had_vary
	    && etaglen > 2
	    && r->resp_body_finished
	    && r->write_queue.first == r->write_queue.last
	    && r->write_queue.first->type == FILE_CHUNK
	    && r->write_queue.first->offset == 0
	    && !r->write_queue.first->file.is_temp
	    && r->http_status != 206
	    && (!(vbro = http_header_response_get(r, HTTP_HEADER_CACHE_CONTROL,
	                                          CONST_STR_LEN("Cache-Control")))
	        || (!http_header_str_contains_token(BUF_PTR_LEN(vbro),
	                                            CONST_STR_LEN("private"))
	            && !http_header_str_contains_token(BUF_PTR_LEN(vbro),
	                                               CONST_STR_LEN("no-store"))))
	   ) {
		tb = mod_deflate_cache_file_name(r, pconf.cache_dir, vb);
		/*(checked earlier and skipped if Transfer-Encoding had been set)*/
		stat_cache_entry *sce = stat_cache_get_entry_open(tb, 1);
		if (NULL != sce) {
			chunkqueue_reset(&r->write_queue);
			if (sce->fd < 0 || 0 != http_chunk_append_file_ref(r, sce))
				return HANDLER_ERROR;
			if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH))
				http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH,
				                           CONST_STR_LEN("Content-Length"));
			mod_deflate_note_ratio(r, sce->st.st_size, len);
			return HANDLER_GO_ON;
		}
		/* sanity check that response was whole file;
		 * (racy since using stat_cache, but cache file only if match) */
		sce = stat_cache_get_entry(r->write_queue.first->mem);
		if (NULL == sce || sce->st.st_size != len)
			tb = NULL;
		else if (0 != mkdir_for_file(tb->ptr))
			tb = NULL;
	}

	/* enable compression */
	pconf.sync_flush =
	  ((r->conf.stream_response_body
	    & (FDEVENT_STREAM_RESPONSE | FDEVENT_STREAM_RESPONSE_BUFMIN))
	   && 0 == pconf.output_buffer_size);
	hctx = handler_ctx_init(r, &pconf, compression_type);
	/* setup output buffer */
        /* thread-safety todo: p->tmp_buf per-thread */
	plugin_data *p = p_d;
	buffer_clear(&p->tmp_buf);
	hctx->output = &p->tmp_buf;
	/* open cache file if caching compressed file */
	if (tb) mod_deflate_cache_file_open(hctx, tb);

  #ifdef HAVE_LIBDEFLATE
	chunk * const c = r->write_queue.first; /*(invalid after compression)*/
  #ifdef HAVE_MMAP
  #if defined(_LP64) || defined(__LP64__) || defined(_WIN64)
	/* optimization to compress single file in one-shot to writeable mmap */
	/*(future: might extend to other compression types)*/
	/*(chunkqueue_chunk_file_view() current min size for mmap is 128k)*/
	if (len > 131072 /* XXX: TBD what should min size be for optimization?*/
	    && (hctx->compression_type == HTTP_ACCEPT_ENCODING_GZIP
	        || hctx->compression_type == HTTP_ACCEPT_ENCODING_DEFLATE)
	    && c == r->write_queue.last
	    && c->type == FILE_CHUNK
	    && chunkqueue_chunk_file_view(c, len, r->conf.errh)
	    && chunk_file_view_dlen(c->file.view, c->offset) >= len) { /*(cfv)*/
		hctx->bytes_in = len;
		if (mod_deflate_using_libdeflate(hctx)) {
			rc = mod_deflate_finished(r, hctx, tb);
			handler_ctx_free(hctx);
			return rc;
		}
		hctx->bytes_in = hctx->bytes_out = 0;
	}
	else
  #endif
  #endif
	if (len <= 65536 /*(p->tmp_buf is at least 64k)*/
	    && (hctx->compression_type == HTTP_ACCEPT_ENCODING_GZIP
	        || hctx->compression_type == HTTP_ACCEPT_ENCODING_DEFLATE)
	    && c == r->write_queue.last
	    && c->type == MEM_CHUNK) {
		/*(skip if FILE_CHUNK; not worth mmap/munmap overhead on small file)*/
		hctx->bytes_in = len;
		if (mod_deflate_using_libdeflate_sm(hctx)) {
			rc = mod_deflate_finished(r, hctx, tb);
			handler_ctx_free(hctx);
			return rc;
		}
		hctx->bytes_in = hctx->bytes_out = 0;
	}
  #endif /* HAVE_LIBDEFLATE */

	if (0 != mod_deflate_stream_init(hctx)) {
		/*(should not happen unless ENOMEM)*/
		handler_ctx_free(hctx);
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "Failed to initialize compression %s", label);
		/* restore prior Etag and unset Content-Encoding */
		if (etaglen) {
			vb->ptr[etaglen-1] = '"'; /*(overwrite '-')*/
			buffer_truncate(vb, etaglen);
		}
		http_header_response_unset(r, HTTP_HEADER_CONTENT_ENCODING, CONST_STR_LEN("Content-Encoding"));
		return HANDLER_GO_ON;
	}

  #ifdef USE_BROTLI
	if (r->resp_body_finished
	    && (hctx->compression_type & HTTP_ACCEPT_ENCODING_BR)
	    && (len >> 1) < (off_t)((~(uint32_t)0u) >> 1))
		BrotliEncoderSetParameter(hctx->u.br, BROTLI_PARAM_SIZE_HINT, (uint32_t)len);
  #endif

	if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LENGTH)) {
		http_header_response_unset(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
	}

	rc = deflate_compress_response(r, hctx);
	if (HANDLER_GO_ON == rc)
		r->plugin_ctx[p->id] = hctx;
	else {
		if (mod_deflate_stream_end(hctx) < 0)
			rc = HANDLER_ERROR;
		else if (HANDLER_FINISHED == rc)
			rc = mod_deflate_finished(r, hctx, tb);
		handler_ctx_free(hctx);
	}
	return rc;
}

static handler_t mod_deflate_cleanup(request_st * const r, void *p_d) {
	plugin_data *p = p_d;
	handler_ctx *hctx = r->plugin_ctx[p->id];

	if (NULL != hctx) {
		r->plugin_ctx[p->id] = NULL;
		mod_deflate_stream_end(hctx);
		handler_ctx_free(hctx);
	}

	return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_deflate_plugin_init(plugin *p);
int mod_deflate_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "deflate";

	p->init		= mod_deflate_init;
	p->cleanup	= mod_deflate_free;
	p->set_defaults	= mod_deflate_set_defaults;
	p->handle_request_reset = mod_deflate_cleanup;
	p->handle_response_start	= mod_deflate_handle_response_start;

	return 0;
}
