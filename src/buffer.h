#ifndef _BUFFER_H_
#define _BUFFER_H_
#include "first.h"

struct tm;              /* declaration */

/**
 * max size of a buffer which will just be reset
 * to ->used = 0 instead of really freeing the buffer
 */
#define BUFFER_MAX_REUSE_SIZE 4096

/* generic string + binary data container; contains a terminating 0 in both
 * cases
 *
 * used == 0 indicates a special "empty" state (unset config values);
 * ptr might be NULL, too.
 *
 * copy/append functions will ensure used >= 1
 * (i.e. never leave it in the special empty state)
 */
typedef struct {
	char *ptr;

	/* "used" includes a terminating 0 */
	uint32_t used;
	/* size of allocated buffer at *ptr */
	uint32_t size;
} buffer;

/* create new buffer; either empty or copy given data */
__attribute_malloc__
__attribute_returns_nonnull__
buffer* buffer_init(void);

void buffer_free(buffer *b); /* b can be NULL */

/* reset b. if NULL != b && NULL != src, move src content to b. reset src. */
__attribute_nonnull__()
void buffer_move(buffer * restrict b, buffer * restrict src);

/* make sure buffer is large enough to store a string of given size
 * and a terminating zero.
 * sets b to an empty string, and may drop old content.
 * @return b->ptr
 */
__attribute_nonnull__()
__attribute_returns_nonnull__
char* buffer_string_prepare_copy(buffer *b, size_t size);

/* allocate buffer large enough to be able to append a string of given size
 * if b was empty (used == 0) it will contain an empty string (used == 1)
 * afterwards
 * "used" data is preserved; if not empty buffer must contain a
 * zero terminated string.
 */
__attribute_nonnull__()
__attribute_returns_nonnull__
char* buffer_string_prepare_append(buffer *b, size_t size);

/* extend and modify buffer for immediate addition of x bytes (differs from
 * buffer_string_prepare_append() which only ensures space is available)
 * returns pointer to which callers should immediately write x bytes
 */
__attribute_nonnull__()
__attribute_returns_nonnull__
char* buffer_extend(buffer * const restrict b, size_t x);

/* use after prepare_(copy,append) when you have written data to the buffer
 * to increase the buffer length by size. also sets the terminating zero.
 * requires enough space is present for the terminating zero (prepare with the
 * same size to be sure).
 */
__attribute_nonnull__()
void buffer_commit(buffer *b, size_t size);

/* clear buffer
 * - invalidate buffer contents
 * - unsets used chars but does not modify existing ptr contents
 *   (b->ptr *is not* set to an empty, '\0'-terminated string "")
 */
__attribute_nonnull__()
static inline void buffer_clear(buffer *b);

/* reset buffer
 * - invalidate buffer contents
 * - unsets used chars
 * - keeps smaller buffer (unmodified) for reuse
 *   (b->ptr *is not* set to an empty, '\0'-terminated string "")
 * - frees larger buffer (b->size > BUFFER_MAX_REUSE_SIZE)
 */
__attribute_nonnull__()
static inline void buffer_reset(buffer *b);

/* free buffer ptr
 * - invalidate buffer contents; free ptr; reset ptr, used, size to 0
 */
__attribute_cold__
__attribute_nonnull__()
void buffer_free_ptr(buffer *b);

void buffer_copy_string(buffer * restrict b, const char * restrict s);
void buffer_copy_string_len(buffer * restrict b, const char * restrict s, size_t len);
void buffer_copy_string_len_lc(buffer * restrict b, const char * restrict s, size_t len);

void buffer_append_string(buffer * restrict b, const char * restrict s);
void buffer_append_string_len(buffer * restrict b, const char * restrict s, size_t len);
void buffer_append_str2(buffer * restrict b, const char *s1, size_t len1, const char *s2, size_t len2);
void buffer_append_str3(buffer * restrict b, const char *s1, size_t len1, const char *s2, size_t len2, const char *s3, size_t len3);

#ifndef LI_CONST_IOVEC
#define LI_CONST_IOVEC
struct const_iovec {
  const void *iov_base;
  size_t iov_len;
};
#endif

__attribute_nonnull__()
void buffer_append_iovec(buffer * restrict b, const struct const_iovec *iov, size_t n);

#define buffer_append_uint_hex(b,len) buffer_append_uint_hex_lc((b),(len))
__attribute_nonnull__()
void buffer_append_uint_hex_lc(buffer *b, uintmax_t len);
__attribute_nonnull__()
void buffer_append_int(buffer *b, intmax_t val);

void buffer_append_strftime(buffer * restrict b, const char * restrict format, const struct tm * restrict tm);

/* '-', log_10 (2^bits) = bits * log 2 / log 10 < bits * 0.31, terminating 0 */
#define LI_ITOSTRING_LENGTH (2 + (8 * sizeof(intmax_t) * 31 + 99) / 100)

__attribute_nonnull__()
size_t li_itostrn(char *buf, size_t buf_len, intmax_t val);
__attribute_nonnull__()
size_t li_utostrn(char *buf, size_t buf_len, uintmax_t val);

/* buf must be (at least) 2*s_len big. uses lower-case hex letters. */
#define li_tohex(buf,buf_len,s,s_len) li_tohex_lc((buf),(buf_len),(s),(s_len))
__attribute_nonnull__()
void li_tohex_lc(char * restrict buf, size_t buf_len, const char * restrict s, size_t s_len);
__attribute_nonnull__()
void li_tohex_uc(char * restrict buf, size_t buf_len, const char * restrict s, size_t s_len);

__attribute_nonnull__()
__attribute_pure__
int buffer_eq_icase_ssn(const char * const a, const char * const b, const size_t len);

__attribute_nonnull__()
__attribute_pure__
int buffer_eq_icase_ss(const char * const a, const size_t alen, const char * const b, const size_t blen);

__attribute_nonnull__()
__attribute_pure__
int buffer_eq_icase_slen(const buffer * const b, const char * const s, const size_t slen);

__attribute_nonnull__()
__attribute_pure__
int buffer_eq_slen(const buffer * const b, const char * const s, const size_t slen);

__attribute_nonnull__()
__attribute_pure__
int buffer_is_equal(const buffer *a, const buffer *b);

__attribute_nonnull__()
void buffer_substr_replace (buffer * restrict b, size_t offset, size_t len, const buffer * restrict replace);

__attribute_nonnull__()
void buffer_append_string_encoded_hex_lc(buffer * restrict b, const char * restrict s, size_t len);
__attribute_nonnull__()
void buffer_append_string_encoded_hex_uc(buffer * restrict b, const char * restrict s, size_t len);

typedef enum {
	ENCODING_REL_URI, /* for coding a rel-uri (/with space/and%percent) nicely as part of a href */
	ENCODING_REL_URI_PART, /* same as ENC_REL_URL plus coding / too as %2F */
	ENCODING_HTML,         /* & becomes &amp; and so on */
	ENCODING_MINIMAL_XML   /* minimal encoding for xml */
} buffer_encoding_t;

void buffer_append_string_encoded(buffer * restrict b, const char * restrict s, size_t s_len, buffer_encoding_t encoding);

/* escape non-printable characters; simple escapes for \t, \r, \n; fallback to \xCC */
__attribute_nonnull__()
void buffer_append_string_c_escaped(buffer * restrict b, const char * restrict s, size_t s_len);

/* escape non-printable chars, '"', '\\', and chars which high bit set */
void buffer_append_bs_escaped (buffer * restrict b, const char * restrict s, size_t len);
void buffer_append_bs_escaped_json (buffer * restrict b, const char * restrict s, size_t len);

__attribute_nonnull__()
void buffer_urldecode_path(buffer *b);

__attribute_nonnull__()
__attribute_pure__
int buffer_is_valid_UTF8(const buffer *b);

__attribute_nonnull__()
void buffer_path_simplify(buffer *b);

__attribute_nonnull__()
void buffer_to_lower(buffer *b);
__attribute_nonnull__()
void buffer_to_upper(buffer *b);


/** deprecated */
__attribute_const__
char hex2int(unsigned char c);

int li_hex2bin (unsigned char *bin, size_t binlen, const char *hexstr, size_t len);

__attribute_pure__
static inline int light_isdigit(int c);
static inline int light_isdigit(int c) {
	return ((uint32_t)c-'0' <= '9'-'0');
}

__attribute_pure__
static inline int light_isxdigit(int c);
static inline int light_isxdigit(int c) {
	return light_isdigit(c) || (((uint32_t)c | 0x20)-'a' <= 'f'-'a');
}

__attribute_pure__
static inline int light_isalpha(int c);
static inline int light_isalpha(int c) {
	return (((uint32_t)c | 0x20)-'a' <= 'z'-'a');
}

__attribute_pure__
static inline int light_isalnum(int c);
static inline int light_isalnum(int c) {
	return light_isdigit(c) || light_isalpha(c);
}

#define light_isupper(c) ((uint32_t)(c)-'A' <= 'Z'-'A')
#define light_islower(c) ((uint32_t)(c)-'a' <= 'z'-'a')

#define light_bshift(b)           ((uint64_t)1uL << (b))
#define light_btst(a,b)  ((a) &   ((uint64_t)1uL << (b)))
#define light_bclr(a,b)  ((a) &= ~((uint64_t)1uL << (b)))
#define light_bset(a,b)  ((a) |=  ((uint64_t)1uL << (b)))


void buffer_append_path_len(buffer * restrict b, const char * restrict a, size_t alen); /* join strings with '/', if '/' not present */
void buffer_copy_path_len2(buffer * restrict b, const char * restrict s1, size_t len1, const char * restrict s2, size_t len2);

__attribute_nonnull__()
__attribute_pure__
static inline int buffer_has_slash_suffix (const buffer * const b);

__attribute_nonnull__()
__attribute_pure__
static inline int buffer_has_pathsep_suffix (const buffer * const b);

#define BUFFER_INTLEN_PTR(x) (int)buffer_clen(x), (x)->ptr
#define BUF_PTR_LEN(x)       (x)->ptr, buffer_clen(x)

#define CONST_LEN_STR(x) (uint32_t)sizeof(x)-1, x
#define CONST_STR_LEN(x) x, (uint32_t)sizeof(x) - 1


/* inline implementations */

__attribute_nonnull__()
__attribute_pure__
static inline int buffer_is_unset(const buffer *b);
static inline int buffer_is_unset(const buffer *b) {
    return 0 == b->used;
}

__attribute_nonnull__()
__attribute_pure__
static inline int buffer_is_blank(const buffer *b);
static inline int buffer_is_blank(const buffer *b) {
    return b->used < 2; /* buffer_is_blank() || buffer_is_unset() */
}

/* buffer "C" len (bytes) */
__attribute_nonnull__()
__attribute_pure__
static inline uint32_t buffer_clen (const buffer *b);
static inline uint32_t buffer_clen (const buffer *b) {
    return b->used - (0 != b->used);
}

/* buffer space remaining to append string without reallocating */
__attribute_nonnull__()
__attribute_pure__
static inline uint32_t buffer_string_space(const buffer *b);
static inline uint32_t buffer_string_space(const buffer *b) {
    return b->size ? b->size - (b->used | (0 == b->used)) : 0;
}

__attribute_nonnull__()
static inline void buffer_copy_buffer(buffer * restrict b, const buffer * restrict src);
static inline void buffer_copy_buffer(buffer * restrict b, const buffer * restrict src) {
    buffer_copy_string_len(b, BUF_PTR_LEN(src));
}

__attribute_nonnull__()
static inline void buffer_append_buffer(buffer * restrict b, const buffer * restrict src);
static inline void buffer_append_buffer(buffer * restrict b, const buffer * restrict src) {
    buffer_append_string_len(b, BUF_PTR_LEN(src));
}

__attribute_nonnull__()
static inline void buffer_truncate(buffer *b, uint32_t len);
static inline void buffer_truncate(buffer *b, uint32_t len) {
    b->ptr[len] = '\0'; /* b->ptr must exist; use buffer_blank() for trunc 0 */
    b->used = len + 1;
}

__attribute_nonnull__()
static inline void buffer_blank(buffer *b);
static inline void buffer_blank(buffer *b) {
    b->ptr ? buffer_truncate(b, 0) : (void)buffer_extend(b, 0);
}

__attribute_nonnull__()
static inline void buffer_append_char (buffer *b, char c);
static inline void buffer_append_char (buffer *b, char c) {
    *(buffer_extend(b, 1)) = c;
}

/* append '/' to non-empty strings not ending in '/' */
__attribute_nonnull__()
static inline void buffer_append_slash(buffer *b);
static inline void buffer_append_slash(buffer *b) {
    const uint32_t len = buffer_clen(b);
    if (len > 0 && '/' != b->ptr[len-1])
        buffer_append_char(b, '/');
}

static inline void buffer_clear(buffer *b) {
	b->used = 0;
}

static inline void buffer_reset(buffer *b) {
	b->used = 0;
	/* release buffer larger than BUFFER_MAX_REUSE_SIZE bytes */
	if (b->size > BUFFER_MAX_REUSE_SIZE) buffer_free_ptr(b);
}

static inline int buffer_has_slash_suffix (const buffer * const b) {
    return (b->used > 1 && b->ptr[b->used-2] == '/');
}

static inline int buffer_has_pathsep_suffix (const buffer * const b) {
    return (b->used > 1 && b->ptr[b->used-2] == '/');
}


/* backwards compat (deprecated; older interfaces) */

#define buffer_append_string_buffer buffer_append_buffer
#define buffer_is_equal_caseless_string buffer_eq_icase_slen
#define buffer_is_equal_string buffer_eq_slen

#define BUFFER_APPEND_STRING_CONST(x, y) \
	buffer_append_string_len(x, y, sizeof(y) - 1)

#define BUFFER_COPY_STRING_CONST(x, y) \
	buffer_copy_string_len(x, y, sizeof(y) - 1)

#define CONST_BUF_LEN(x) ((x) ? (x)->ptr : NULL), buffer_string_length(x)

/* NULL buffer or empty buffer (used == 0);
 * unset "string" (buffer) config options are initialized to used == 0,
 * while setting an empty string leads to used == 1
 */
__attribute_pure__
static inline int buffer_is_empty(const buffer *b);
static inline int buffer_is_empty(const buffer *b) {
	return NULL == b || buffer_is_unset(b);
}
/* NULL buffer, empty buffer (used == 0) or empty string (used == 1) */
__attribute_pure__
static inline int buffer_string_is_empty(const buffer *b);
static inline int buffer_string_is_empty(const buffer *b) {
	return NULL == b || buffer_is_blank(b);
}

/* buffer string length without terminating 0 */
__attribute_pure__
static inline uint32_t buffer_string_length(const buffer *b);
static inline uint32_t buffer_string_length(const buffer *b) {
	return NULL != b ? buffer_clen(b) : 0;
}

/* sets string length:
 * - deprecated; use buffer_truncate() or buffer_extend() instead
 * - always stores a terminating zero to terminate the "new" string
 * - does not modify the string data apart from terminating zero
 * - reallocates the buffer iff needed
 */
__attribute_nonnull__()
static inline void buffer_string_set_length(buffer *b, uint32_t len);
static inline void buffer_string_set_length(buffer *b, uint32_t len) {
    if (len < b->size)
        buffer_truncate(b, len);
    else
        buffer_extend(b, len - buffer_clen(b));
}


#include "ck.h"
#define force_assert(x) ck_assert(x)
#define log_failed_assert(file,line,msg) ck_bt_abort((file),(line),(msg))
#define SEGFAULT() ck_bt_abort(__FILE__, __LINE__, "aborted")


#endif
