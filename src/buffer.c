#include "first.h"

#include "buffer.h"

#include <stdlib.h>
#include <string.h>
#include "sys-time.h"   /* strftime() */

static const char hex_chars_lc[] = "0123456789abcdef";
static const char hex_chars_uc[] = "0123456789ABCDEF";


__attribute_noinline__
buffer* buffer_init(void) {
  #if 0 /* buffer_init() and chunk_init() can be hot,
	 * so avoid the additional hop of indirection */
	return ck_calloc(1, sizeof(buffer));
  #else
	buffer * const b = calloc(1, sizeof(*b));
	force_assert(b);
	return b;
  #endif
}

void buffer_free(buffer *b) {
	if (NULL == b) return;
	free(b->ptr);
	free(b);
}

void buffer_free_ptr(buffer *b) {
	free(b->ptr);
	b->ptr = NULL;
	b->used = 0;
	b->size = 0;
}

void buffer_move(buffer * restrict b, buffer * restrict src) {
	buffer tmp;
	buffer_clear(b);
	tmp = *src; *src = *b; *b = tmp;
}

/* make sure buffer is at least "size" big + 1 for '\0'. keep old data */
__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
__attribute_returns_nonnull__
static char* buffer_realloc(buffer * const restrict b, const size_t len) {
    #define BUFFER_PIECE_SIZE 64uL  /*(must be power-of-2)*/
    size_t sz = (len + 1 + BUFFER_PIECE_SIZE-1) & ~(BUFFER_PIECE_SIZE-1);
    force_assert(sz > len);
    if ((sz & (sz-1)) && sz < INT_MAX) {/* not power-2; huge val not expected */
        /*(optimizer should recognize this and use ffs or clz or equivalent)*/
        const size_t psz = sz;
        for (sz = 256; sz < psz; sz <<= 1) ;
    }
    sz |= 1; /*(extra +1 for '\0' when needed buffer size is exact power-2)*/

    b->size = sz;
    b->ptr = realloc(b->ptr, sz);

    force_assert(NULL != b->ptr);
    return b->ptr;
}

__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
__attribute_returns_nonnull__
static char* buffer_alloc_replace(buffer * const restrict b, const size_t size) {
    /*(discard old data so realloc() does not copy)*/
    if (NULL != b->ptr) {
        free(b->ptr);
        b->ptr = NULL;
    }
    /*(note: if size larger than one lshift, use size instead of power-2)*/
    const size_t bsize2x = (b->size & ~1uL) << 1;
    return buffer_realloc(b, bsize2x > size ? bsize2x-1 : size);
}

char* buffer_string_prepare_copy(buffer * const b, const size_t size) {
    b->used = 0;
  #ifdef __COVERITY__ /*(b->ptr is not NULL if b->size is not 0)*/
    force_assert(size >= b->size || b->ptr);
  #endif
    return (size < b->size)
      ? b->ptr
      : buffer_alloc_replace(b, size);
}

__attribute_cold__
__attribute_noinline__
__attribute_nonnull__()
__attribute_returns_nonnull__
static char* buffer_string_prepare_append_resize(buffer * const restrict b, const size_t size) {
    if (b->used < 2) {  /* buffer_is_blank(b) */
        char * const s = buffer_string_prepare_copy(b, size);
        *s = '\0'; /*(for case (1 == b->used))*/
        return s;
    }

    /* not empty, b->used already includes a terminating 0 */
    /*(note: if size larger than one lshift, use size instead of power-2)*/
    const size_t bsize2x = (b->size & ~1uL) << 1;
    const size_t req_size = (bsize2x - b->used > size)
      ? bsize2x-1
      : b->used + size;

    /* check for overflow: unsigned overflow is defined to wrap around */
    force_assert(req_size >= b->used);

    return buffer_realloc(b, req_size) + b->used - 1;
}

char* buffer_string_prepare_append(buffer * const b, const size_t size) {
    const uint32_t len = b->used ? b->used-1 : 0;
    return (b->size - len >= size + 1)
      ? b->ptr + len
      : buffer_string_prepare_append_resize(b, size);
}

/*(prefer smaller code than inlining buffer_extend in many places in buffer.c)*/
__attribute_noinline__
char*
buffer_extend (buffer * const b, const size_t x)
{
    /* extend buffer to append x (reallocate by power-2 (or larger), if needed)
     * (combine buffer_string_prepare_append() and buffer_commit())
     * (future: might make buffer.h static inline func for HTTP/1.1 performance)
     * pre-sets '\0' byte and b->used (unlike buffer_string_prepare_append())*/
  #if 0
    char * const s = buffer_string_prepare_append(b, x);
    b->used += x + (0 == b->used);
  #else
    const uint32_t len = b->used ? b->used-1 : 0;
    char * const s = (b->size - len >= x + 1)
      ? b->ptr + len
      : buffer_string_prepare_append_resize(b, x);
    b->used = len+x+1;
  #endif
    s[x] = '\0';
    return s;
}

void buffer_commit(buffer *b, size_t size)
{
	size_t sz = b->used;
	if (0 == sz) sz = 1;

  #if __has_builtin(__builtin_add_overflow)
	if (__builtin_add_overflow(size, sz, &sz))
		ck_assert_failed(__FILE__, __LINE__, "add overflow");
  #else
	if (size > 0) {
		/* check for overflow: unsigned overflow is defined to wrap around */
		sz += size;
		force_assert(sz > size);
	}
  #endif

	b->used = sz;
	b->ptr[sz - 1] = '\0';
}

__attribute_cold__ /*(reduce code size due to inlining)*/
void buffer_copy_string(buffer * restrict b, const char * restrict s) {
    if (__builtin_expect( (NULL == s), 0)) s = "";
    buffer_copy_string_len(b, s, strlen(s));
}

void buffer_copy_string_len(buffer * const restrict b, const char * const restrict s, const size_t len) {
    b->used = len + 1;
    char * const restrict d = (len < b->size)
      ? b->ptr
      : buffer_alloc_replace(b, len);
    d[len] = '\0';
    memcpy(d, s, len);
}

__attribute_cold__ /*(reduce code size due to inlining)*/
void buffer_append_string(buffer * restrict b, const char * restrict s) {
    if (__builtin_expect( (NULL == s), 0)) s = "";
    buffer_append_string_len(b, s, strlen(s));
}

/**
 * append a string to the end of the buffer
 *
 * the resulting buffer is terminated with a '\0'
 * s is treated as a un-terminated string (a \0 is handled a normal character)
 *
 * @param b a buffer
 * @param s the string
 * @param s_len size of the string (without the terminating \0)
 */

void buffer_append_string_len(buffer * const restrict b, const char * const restrict s, const size_t len) {
    memcpy(buffer_extend(b, len), s, len);
}

void buffer_append_str2(buffer * const restrict b, const char * const s1, const size_t len1, const char * const s2, const size_t len2) {
    char * const restrict s = buffer_extend(b, len1+len2);
  #ifdef HAVE_MEMPCPY
    mempcpy(mempcpy(s, s1, len1), s2, len2);
  #else
    memcpy(s,      s1, len1);
    memcpy(s+len1, s2, len2);
  #endif
}

void buffer_append_str3(buffer * const restrict b, const char * const s1, const size_t len1, const char * const s2, const size_t len2, const char * const s3, const size_t len3) {
    char * restrict s = buffer_extend(b, len1+len2+len3);
  #ifdef HAVE_MEMPCPY
    mempcpy(mempcpy(mempcpy(s, s1, len1), s2, len2), s3, len3);
  #else
    memcpy(s,         s1, len1);
    memcpy((s+=len1), s2, len2);
    memcpy((s+=len2), s3, len3);
  #endif
}

void buffer_append_iovec(buffer * const restrict b, const struct const_iovec * const iov, const size_t n) {
    size_t len = 0;
    for (size_t i = 0; i < n; ++i)
        len += iov[i].iov_len;
    char *s = buffer_extend(b, len);
    for (size_t i = 0; i < n; ++i) {
        if (0 == iov[i].iov_len) continue;
      #ifdef HAVE_MEMPCPY
        s = mempcpy(s, iov[i].iov_base, iov[i].iov_len);
      #else
        memcpy(s, iov[i].iov_base, iov[i].iov_len);
        s += iov[i].iov_len;
      #endif
    }
}

void buffer_append_path_len(buffer * restrict b, const char * restrict a, size_t alen) {
    char * restrict s = buffer_string_prepare_append(b, alen+1);
  #ifdef _WIN32
    const int aslash = (alen && (a[0] == '/' || a[0] == '\\'));
    if (b->used > 1 && (s[-1] == '/' || s[-1] == '\\'))
  #else
    const int aslash = (alen && a[0] == '/');
    if (b->used > 1 && s[-1] == '/')
  #endif
    {
        if (aslash) {
            ++a;
            --alen;
        }
    }
    else {
        if (0 == b->used) b->used = 1;
        if (!aslash) {
            *s++ = '/';
            ++b->used;
        }
    }
    b->used += alen;
    s[alen] = '\0';
    memcpy(s, a, alen);
}

void
buffer_copy_path_len2 (buffer * const restrict b, const char * const restrict s1, size_t len1, const char * const restrict s2, size_t len2)
{
    /*(similar to buffer_copy_string_len(b, s1, len1) but combined allocation)*/
    memcpy(buffer_string_prepare_copy(b, len1+len2+1), s1, len1);
    b->used = len1 + 1;                    /*('\0' byte will be written below)*/

    buffer_append_path_len(b, s2, len2);/*(choice: not inlined, special-cased)*/
}

void
buffer_copy_string_len_lc (buffer * const restrict b, const char * const restrict s, const size_t len)
{
    char * const restrict d = buffer_string_prepare_copy(b, len);
    b->used = len+1;
    d[len] = '\0';
    for (size_t i = 0; i < len; ++i)
        d[i] = (!light_isupper(s[i])) ? s[i] : s[i] | 0x20;
}

void buffer_append_uint_hex_lc(buffer *b, uintmax_t value) {
	char *buf;
	unsigned int shift = 0;

	{
		uintmax_t copy = value;
		do {
			copy >>= 8;
			shift += 8; /* counting bits */
		} while (0 != copy);
	}

	buf = buffer_extend(b, shift >> 2); /*nibbles (4 bits)*/

	while (shift > 0) {
		shift -= 4;
		*(buf++) = hex_chars_lc[(value >> shift) & 0x0F];
	}
}

__attribute_nonnull__()
__attribute_returns_nonnull__
static char* utostr(char buf[LI_ITOSTRING_LENGTH], uintmax_t val) {
	char *cur = buf+LI_ITOSTRING_LENGTH;
	uintmax_t x;
	do {
		*(--cur) = (char) ('0' + (int)(val - (x = val/10) * 10));
	} while (0 != (val = x));           /* val % 10 */
	return cur;
}

__attribute_nonnull__()
__attribute_returns_nonnull__
static char* itostr(char buf[LI_ITOSTRING_LENGTH], intmax_t val) {
	/* absolute value not defined for INTMAX_MIN, but can take absolute
	 * value of any negative number via twos complement cast to unsigned.
	 * negative sign is prepended after (now unsigned) value is converted
	 * to string */
	uintmax_t uval = val >= 0 ? (uintmax_t)val : ((uintmax_t)~val) + 1;
	char *cur = utostr(buf, uval);
	if (val < 0) *(--cur) = '-';

	return cur;
}

void buffer_append_int(buffer *b, intmax_t val) {
	char buf[LI_ITOSTRING_LENGTH];
	const char * const str = itostr(buf, val);
	buffer_append_string_len(b, str, buf+sizeof(buf) - str);
}

void buffer_append_strftime(buffer * const restrict b, const char * const restrict format, const struct tm * const restrict tm) {
    /*(localtime_r() or gmtime_r() producing tm should not have failed)*/
    if (__builtin_expect( (NULL == tm), 0)) return;

    /*(expecting typical format strings to result in < 64 bytes needed;
     * skipping buffer_string_space() calculation and providing fixed size)*/
    size_t rv = strftime(buffer_string_prepare_append(b, 63), 64, format, tm);

    /* 0 (in some apis) signals the string may have been too small;
     * but the format could also just have lead to an empty string */
    if (__builtin_expect( (0 == rv), 0) || __builtin_expect( (rv > 63), 0)) {
        /* unexpected; give it a second try with a larger string */
        rv = strftime(buffer_string_prepare_append(b, 4095), 4096, format, tm);
        if (__builtin_expect( (rv > 4095), 0))/*(input format was ridiculous)*/
            return;
    }

    /*buffer_commit(b, rv);*/
    b->used += (uint32_t)rv + (0 == b->used);
}


size_t li_itostrn(char *buf, size_t buf_len, intmax_t val) {
	char p_buf[LI_ITOSTRING_LENGTH];
	char* const str = itostr(p_buf, val);
	size_t len = (size_t)(p_buf+sizeof(p_buf)-str);
	force_assert(len <= buf_len);
	memcpy(buf, str, len);
	return len;
}

size_t li_utostrn(char *buf, size_t buf_len, uintmax_t val) {
	char p_buf[LI_ITOSTRING_LENGTH];
	char* const str = utostr(p_buf, val);
	size_t len = (size_t)(p_buf+sizeof(p_buf)-str);
	force_assert(len <= buf_len);
	memcpy(buf, str, len);
	return len;
}

#define li_ntox_lc(n) ((n) <= 9 ? (n) + '0' : (n) + 'a' - 10)

/* c (char) and n (nibble) MUST be unsigned integer types */
#define li_cton(c,n) \
  (((n) = (c) - '0') <= 9 || (((n) = ((c)&0xdf) - 'A') <= 5 ? ((n) += 10) : 0))

/* converts hex char (0-9, A-Z, a-z) to decimal.
 * returns 0xFF on invalid input.
 */
char hex2int(unsigned char hex) {
	unsigned char n;
	return li_cton(hex,n) ? (char)n : 0xFF;
}

int li_hex2bin (unsigned char * const bin, const size_t binlen, const char * const hexstr, const size_t len)
{
    /* validate and transform 32-byte MD5 hex string to 16-byte binary MD5,
     * or 64-byte SHA-256 or SHA-512-256 hex string to 32-byte binary digest */
    if (len > (binlen << 1)) return -1;
    for (int i = 0, ilen = (int)len; i < ilen; i+=2) {
        int hi = hexstr[i];
        int lo = hexstr[i+1];
        if ('0' <= hi && hi <= '9')                    hi -= '0';
        else if ((uint32_t)(hi |= 0x20)-'a' <= 'f'-'a')hi += -'a' + 10;
        else                                           return -1;
        if ('0' <= lo && lo <= '9')                    lo -= '0';
        else if ((uint32_t)(lo |= 0x20)-'a' <= 'f'-'a')lo += -'a' + 10;
        else                                           return -1;
        bin[(i >> 1)] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}


__attribute_noinline__
int buffer_eq_icase_ssn(const char * const a, const char * const b, const size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned int ca = ((unsigned char *)a)[i];
        unsigned int cb = ((unsigned char *)b)[i];
        if (ca != cb && ((ca ^ cb) != 0x20 || !light_isalpha(ca))) return 0;
    }
    return 1;
}

int buffer_eq_icase_ss(const char * const a, const size_t alen, const char * const b, const size_t blen) {
    /* 1 = equal; 0 = not equal */ /* short string sizes expected (< INT_MAX) */
    return (alen == blen) ? buffer_eq_icase_ssn(a, b, blen) : 0;
}

int buffer_eq_icase_slen(const buffer * const b, const char * const s, const size_t slen) {
    /* Note: b must be initialized, i.e. 0 != b->used; uninitialized is not eq*/
    /* 1 = equal; 0 = not equal */ /* short string sizes expected (< INT_MAX) */
    return (b->used == slen + 1) ? buffer_eq_icase_ssn(b->ptr, s, slen) : 0;
}

int buffer_eq_slen(const buffer * const b, const char * const s, const size_t slen) {
    /* Note: b must be initialized, i.e. 0 != b->used; uninitialized is not eq*/
    /* 1 = equal; 0 = not equal */ /* short string sizes expected (< INT_MAX) */
    return (b->used == slen + 1 && 0 == memcmp(b->ptr, s, slen));
}


/**
 * check if two buffer contain the same data
 */

int buffer_is_equal(const buffer *a, const buffer *b) {
	/* 1 = equal; 0 = not equal */
	return (a->used == b->used && 0 == memcmp(a->ptr, b->ptr, a->used));
}


void li_tohex_lc(char * const restrict buf, size_t buf_len, const char * const restrict s, size_t s_len) {
	force_assert(s_len <= (buf_len >> 1));

	for (size_t i = 0; i < s_len; ++i) {
		buf[2*i]   = hex_chars_lc[(s[i] >> 4) & 0x0F];
		buf[2*i+1] = hex_chars_lc[s[i] & 0x0F];
	}
}

void li_tohex_uc(char * const restrict buf, size_t buf_len, const char * const restrict s, size_t s_len) {
	force_assert(s_len <= (buf_len >> 1));

	for (size_t i = 0; i < s_len; ++i) {
		buf[2*i]   = hex_chars_uc[(s[i] >> 4) & 0x0F];
		buf[2*i+1] = hex_chars_uc[s[i] & 0x0F];
	}
}


void buffer_substr_replace (buffer * const restrict b, const size_t offset,
                            const size_t len, const buffer * const restrict replace)
{
    const size_t blen = buffer_clen(b);
    const size_t rlen = buffer_clen(replace);

    if (rlen > len) {
        buffer_extend(b, rlen-len);
        memmove(b->ptr+offset+rlen, b->ptr+offset+len, blen-offset-len);
    }

    memcpy(b->ptr+offset, replace->ptr, rlen);

    if (rlen < len) {
        memmove(b->ptr+offset+rlen, b->ptr+offset+len, blen-offset-len);
        buffer_truncate(b, blen-len+rlen);
    }
}


void buffer_append_string_encoded_hex_lc(buffer * const restrict b, const char * const restrict s, size_t len) {
    unsigned char * const p = (unsigned char *)buffer_extend(b, len*2);
    for (size_t i = 0; i < len; ++i) {
        p[(i<<1)]   = hex_chars_lc[(s[i] >> 4) & 0x0F];
        p[(i<<1)+1] = hex_chars_lc[(s[i])      & 0x0F];
    }
}

void buffer_append_string_encoded_hex_uc(buffer * const restrict b, const char * const restrict s, size_t len) {
    unsigned char * const p = (unsigned char *)buffer_extend(b, len*2);
    for (size_t i = 0; i < len; ++i) {
        p[(i<<1)]   = hex_chars_uc[(s[i] >> 4) & 0x0F];
        p[(i<<1)+1] = hex_chars_uc[(s[i])      & 0x0F];
    }
}


/* everything except: ! ( ) * - . 0-9 A-Z _ a-z */
static const char encoded_chars_rel_uri_part[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1,  /*  20 -  2F space " # $ % & ' + , / */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,  /*  30 -  3F : ; < = > ? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,  /*  70 -  7F { | } DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

/* everything except: ! ( ) * - . / 0-9 A-Z _ a-z */
static const char encoded_chars_rel_uri[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0,  /*  20 -  2F space " # $ % & ' + , */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,  /*  30 -  3F : ; < = > ? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,  /*  70 -  7F { | } DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

static const char encoded_chars_html[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F " & ' */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  /*  70 -  7F DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

static const char encoded_chars_minimal_xml[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F " & ' */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  /*  70 -  7F DEL */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  80 -  8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  90 -  9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  A0 -  AF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  B0 -  BF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  C0 -  CF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  D0 -  DF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  E0 -  EF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  F0 -  FF */
};



void buffer_append_string_encoded(buffer * const restrict b, const char * const restrict s, size_t s_len, buffer_encoding_t encoding) {
	unsigned char *ds, *d;
	size_t d_len, ndx;
	const char *map = NULL;

	switch(encoding) {
	case ENCODING_REL_URI:
		map = encoded_chars_rel_uri;
		break;
	case ENCODING_REL_URI_PART:
		map = encoded_chars_rel_uri_part;
		break;
	case ENCODING_HTML:
		map = encoded_chars_html;
		break;
	case ENCODING_MINIMAL_XML:
		map = encoded_chars_minimal_xml;
		break;
	}

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds & 0xFF]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d_len += 3;
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d_len += 6;
				break;
			}
		} else {
			d_len++;
		}
	}

	d = (unsigned char*) buffer_extend(b, d_len);

	if (d_len == s_len) { /*(short-circuit; nothing to encoded)*/
		memcpy(d, s, s_len);
		return;
	}

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds & 0xFF]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d[d_len++] = '%';
				d[d_len++] = hex_chars_uc[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars_uc[(*ds) & 0x0F];
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d[d_len++] = '&';
				d[d_len++] = '#';
				d[d_len++] = 'x';
				d[d_len++] = hex_chars_uc[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars_uc[(*ds) & 0x0F];
				d[d_len++] = ';';
				break;
			}
		} else {
			d[d_len++] = *ds;
		}
	}
}

void buffer_append_string_c_escaped(buffer * const restrict b, const char * const restrict s, size_t s_len) {
	unsigned char *ds, *d;
	size_t d_len, ndx;

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (__builtin_expect( (*ds >= ' ' && *ds <= '~'), 1))
			d_len++;
		else { /* CTLs or non-ASCII characters */
			switch (*ds) {
			case '\t':
			case '\r':
			case '\n':
				d_len += 2;
				break;
			default:
				d_len += 4; /* \xCC */
				break;
			}
		}
	}

	d = (unsigned char*) buffer_extend(b, d_len);

	if (d_len == s_len) { /*(short-circuit; nothing to encoded)*/
		memcpy(d, s, s_len);
		return;
	}

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (__builtin_expect( (*ds >= ' ' && *ds <= '~'), 1))
			d[d_len++] = *ds;
		else { /* CTLs or non-ASCII characters */
			d[d_len++] = '\\';
			switch (*ds) {
			case '\t':
				d[d_len++] = 't';
				break;
			case '\r':
				d[d_len++] = 'r';
				break;
			case '\n':
				d[d_len++] = 'n';
				break;
			default:
				d[d_len++] = 'x';
				d[d_len++] = hex_chars_lc[(*ds) >> 4];
				d[d_len++] = hex_chars_lc[(*ds) & 0x0F];
				break;
			}
		}
	}
}


void
buffer_append_bs_escaped (buffer * const restrict b,
                          const char * restrict s, const size_t len)
{
    /* replaces non-printable chars with escaped string
     * default: \xHH where HH is the hex representation of the byte
     * exceptions: " => \", \ => \\, whitespace chars => \n \t etc. */
    /* Intended for use escaping string to be surrounded by double-quotes */
    /* Performs single pass over string and is optimized for ASCII;
     * non-ASCII escaping might be slightly sped up by walking input twice,
     * first to calculate escaped length and extend the destination b, and
     * second to do the escaping. (This non-ASCII optim is not done here) */
    buffer_string_prepare_append(b, len);
    for (const char * const end = s+len; s < end; ++s) {
        unsigned int c;
        const char * const ptr = s;
        do {
            c = *(const unsigned char *)s;
        } while (c >= ' ' && c <= '~' && c != '"' && c != '\\' && ++s < end);
        if (s - ptr) buffer_append_string_len(b, ptr, s - ptr);

        if (s == end)
            return;

        /* ('\a', '\v' shortcuts are technically not json-escaping) */
        /* ('\0' is also omitted due to the possibility of string corruption if
         *  the receiver supports decoding octal escapes (\000) and the escaped
         *  string contains \0 followed by two digits not part of escaping)*/

        char *d;
        switch (c) {
          case '\a':case '\b':case '\t':case '\n':case '\v':case '\f':case '\r':
            c = "0000000abtnvfr"[c];
            __attribute_fallthrough__
          case '"': case '\\':
            d = buffer_extend(b, 2);
            d[0] = '\\';
            d[1] = c;
            break;
          default:
            /* non printable char => \xHH */
            d = buffer_extend(b, 4);
            d[0] = '\\';
            d[1] = 'x';
            d[2] = hex_chars_uc[c >> 4];
            d[3] = hex_chars_uc[c & 0xF];
            break;
        }
    }
}


void
buffer_append_bs_escaped_json (buffer * const restrict b,
                               const char * restrict s, const size_t len)
{
    /* replaces non-printable chars with escaped string
     * json: \u00HH where HH is the hex representation of the byte
     * exceptions: " => \", \ => \\, whitespace chars => \n \t etc. */
    /* Intended for use escaping string to be surrounded by double-quotes */
    buffer_string_prepare_append(b, len);
    for (const char * const end = s+len; s < end; ++s) {
        unsigned int c;
        const char * const ptr = s;
        do {
            c = *(const unsigned char *)s;
        } while (c >= ' ' && c != '"' && c != '\\' && ++s < end);
        if (s - ptr) buffer_append_string_len(b, ptr, s - ptr);

        if (s == end)
            return;

        /* ('\a', '\v' shortcuts are technically not json-escaping) */
        /* ('\0' is also omitted due to the possibility of string corruption if
         *  the receiver supports decoding octal escapes (\000) and the escaped
         *  string contains \0 followed by two digits not part of escaping)*/

        char *d;
        switch (c) {
          case '\a':case '\b':case '\t':case '\n':case '\v':case '\f':case '\r':
            c = "0000000abtnvfr"[c];
            __attribute_fallthrough__
          case '"': case '\\':
            d = buffer_extend(b, 2);
            d[0] = '\\';
            d[1] = c;
            break;
          default:
            d = buffer_extend(b, 6);
            d[0] = '\\';
            d[1] = 'u';
            d[2] = '0';
            d[3] = '0';
            d[4] = hex_chars_uc[c >> 4];
            d[5] = hex_chars_uc[c & 0xF];
            break;
        }
    }
}


/* decodes url-special-chars inplace.
 * replaces non-printable characters with '_'
 * (If this is used on a portion of query string, then query string should be
 *  split on '&', and '+' replaced with ' ' before calling this routine)
 */

void buffer_urldecode_path(buffer * const b) {
    const size_t len = buffer_clen(b);
    char *src = len ? memchr(b->ptr, '%', len) : NULL;
    if (NULL == src) return;

    char *dst = src;
    do {
        /* *src == '%' */
        unsigned char high = ((unsigned char *)src)[1];
        unsigned char low = high ? hex2int(((unsigned char *)src)[2]) : 0xFF;
        if (0xFF != (high = hex2int(high)) && 0xFF != low) {
            high = (high << 4) | low;   /* map ctrls to '_' */
            *dst = (high >= 32 && high != 127) ? high : '_';
            src += 2;
        } /* else ignore this '%'; leave as-is and move on */

        while ((*++dst = *++src) != '%' && *src) ;
    } while (*src);
    b->used = (dst - b->ptr) + 1;
}

int buffer_is_valid_UTF8(const buffer *b) {
    /* https://www.w3.org/International/questions/qa-forms-utf-8 */
    /*assert(b->used);*//*(b->ptr must exist and be '\0'-terminated)*/
    const unsigned char *c = (unsigned char *)b->ptr;
    while (*c) {

        /*(note: includes ctrls)*/
        if (                         c[0] <  0x80 ) { ++c;  continue; }

        if (         0xc2 <= c[0] && c[0] <= 0xdf
            &&       0x80 <= c[1] && c[1] <= 0xbf ) { c+=2; continue; }

        if ( (   (   0xe0 == c[0]
                  && 0xa0 <= c[1] && c[1] <= 0xbf)
              || (   0xe1 <= c[0] && c[0] <= 0xef && c[0] != 0xed
                  && 0x80 <= c[1] && c[1] <= 0xbf)
              || (   0xed == c[0]
                  && 0x80 <= c[1] && c[1] <= 0x9f)   )
            &&       0x80 <= c[2] && c[2] <= 0xbf ) { c+=3; continue; }

        if ( (   (   0xf0 == c[0]
                  && 0x90 <= c[1] && c[1] <= 0xbf)
              || (   0xf1 <= c[0] && c[0] <= 0xf3
                  && 0x80 <= c[1] && c[1] <= 0xbf)
              || (   0xf4 == c[0]
                  && 0x80 <= c[1] && c[1] <= 0x8f)   )
            &&       0x80 <= c[2] && c[2] <= 0xbf
            &&       0x80 <= c[3] && c[3] <= 0xbf ) { c+=4; continue; }

        return 0; /* invalid */
    }
    return 1; /* valid */
}

/* - special case: empty string returns empty string
 * - on windows or cygwin: replace \ with /
 * - strip leading spaces
 * - prepends "/" if not present already
 * - resolve "/../", "//" and "/./" the usual way:
 *   the first one removes a preceding component, the other two
 *   get compressed to "/".
 * - "/." and "/.." at the end are similar, but always leave a trailing
 *   "/"
 *
 * /blah/..         gets  /
 * /blah/../foo     gets  /foo
 * /abc/./xyz       gets  /abc/xyz
 * /abc//xyz        gets  /abc/xyz
 */

void buffer_path_simplify(buffer *b)
{
    char *out = b->ptr;
    char * const end = b->ptr + b->used - 1;

    if (__builtin_expect( (buffer_is_blank(b)), 0)) {
        buffer_blank(b);
        return;
    }

  #if defined(_WIN32) || defined(__CYGWIN__)
    /* cygwin is treating \ and / the same, so we have to that too */
    for (char *p = b->ptr; *p; p++) {
        if (*p == '\\') *p = '/';
    }
  #endif

    *end = '/'; /*(end of path modified to avoid need to check '\0')*/

    char *walk = out;
    if (__builtin_expect( (*walk == '/'), 1)) {
        /* scan to detect (potential) need for path simplification
         * (repeated '/' or "/.") */
        do {
            if (*++walk == '.' || *walk == '/')
                break;
            do { ++walk; } while (*walk != '/');
        } while (walk != end);
        if (__builtin_expect( (walk == end), 1)) {
            /* common case: no repeated '/' or "/." */
            *end = '\0'; /* overwrite extra '/' added to end of path */
            return;
        }
        out = walk-1;
    }
    else {
        if (walk[0] == '.' && walk[1] == '/')
            *out = *++walk;
        else if (walk[0] == '.' && walk[1] == '.' && walk[2] == '/')
            *out = *(walk += 2);
        else {
            while (*++walk != '/') ;
            out = walk;
        }
        ++walk;
    }

    while (walk <= end) {
        /* previous char is '/' at this point (or start of string w/o '/') */
        if (__builtin_expect( (walk[0] == '/'), 0)) {
            /* skip repeated '/' (e.g. "///" -> "/") */
            if (++walk < end)
                continue;
            else {
                ++out;
                break;
            }
        }
        else if (__builtin_expect( (walk[0] == '.'), 0)) {
            /* handle "./" and "../" */
            if (walk[1] == '.' && walk[2] == '/') {
                /* handle "../" */
                while (out > b->ptr && *--out != '/') ;
                *out = '/'; /*(in case path had not started with '/')*/
                if ((walk += 3) >= end) {
                    ++out;
                    break;
                }
                else
                continue;
            }
            else if (walk[1] == '/') {
                /* handle "./" */
                if ((walk += 2) >= end) {
                    ++out;
                    break;
                }
                continue;
            }
            else {
                /* accept "." if not part of "../" or "./" */
                *++out = '.';
                ++walk;
            }
        }

        while ((*++out = *walk++) != '/') ;
    }
    *out = *end = '\0'; /* overwrite extra '/' added to end of path */
    b->used = (out - b->ptr) + 1;
    /*buffer_truncate(b, out - b->ptr);*/
}

void buffer_to_lower(buffer * const b) {
    unsigned char * const restrict s = (unsigned char *)b->ptr;
    const uint_fast32_t used = b->used;
    for (uint_fast32_t i = 0; i < used; ++i) {
        if (light_isupper(s[i])) s[i] |= 0x20;
    }
}


void buffer_to_upper(buffer * const b) {
    unsigned char * const restrict s = (unsigned char *)b->ptr;
    const uint_fast32_t used = b->used;
    for (uint_fast32_t i = 0; i < used; ++i) {
        if (light_islower(s[i])) s[i] &= 0xdf;
    }
}
