#include "first.h"

#include "buffer.h"
#include "settings.h"   /* BUFFER_MAX_REUSE_SIZE */

#include <stdlib.h>
#include <string.h>
#include <time.h>       /* strftime() */

static const char hex_chars_lc[] = "0123456789abcdef";
static const char hex_chars_uc[] = "0123456789ABCDEF";

/**
 * init the buffer
 *
 */

buffer* buffer_init(void) {
	buffer *b;

	b = malloc(sizeof(*b));
	force_assert(b);

	b->ptr = NULL;
	b->size = 0;
	b->used = 0;

	return b;
}

buffer *buffer_init_buffer(const buffer *src) {
	buffer *b = buffer_init();
	buffer_copy_buffer(b, src);
	return b;
}

buffer *buffer_init_string(const char *str) {
	buffer *b = buffer_init();
	buffer_copy_string(b, str);
	return b;
}

void buffer_free(buffer *b) {
	if (NULL == b) return;

	free(b->ptr);
	free(b);
}

__attribute_cold__
static void buffer_free_ptr(buffer *b) {
	free(b->ptr);
	b->ptr = NULL;
	b->used = 0;
	b->size = 0;
}

void buffer_reset(buffer *b) {
	force_assert(NULL != b);
	b->used = 0;
	/* release buffer larger than ... bytes */
	if (b->size > BUFFER_MAX_REUSE_SIZE) buffer_free_ptr(b);
}

void buffer_move(buffer *b, buffer *src) {
	buffer tmp;
	force_assert(NULL != b);
	force_assert(NULL != src);

	buffer_clear(b);
	tmp = *src; *src = *b; *b = tmp;
}

/* make sure buffer is at least "size" big + 1 for '\0'. keep old data */
__attribute_cold__
static void buffer_realloc(buffer *b, size_t len) {
    #define BUFFER_PIECE_SIZE 64uL  /*(must be power-of-2)*/
    const size_t sz = (len + 1 + BUFFER_PIECE_SIZE-1) & ~(BUFFER_PIECE_SIZE-1);
    force_assert(sz > len);

    b->size = sz;
    b->ptr = realloc(b->ptr, sz);

    force_assert(NULL != b->ptr);
}

__attribute_cold__
static void buffer_alloc_replace(buffer *b, size_t size) {
    /*(discard old data so realloc() does not copy)*/
    if (NULL != b->ptr) {
        free(b->ptr);
        b->ptr = NULL;
    }
    buffer_realloc(b, size);
}

char* buffer_string_prepare_copy(buffer *b, size_t size) {
	force_assert(NULL != b);

	if (size >= b->size) buffer_alloc_replace(b, size);

	b->used = 0;
	return b->ptr;
}

char* buffer_string_prepare_append(buffer *b, size_t size) {
	force_assert(NULL !=  b);

	if (b->used && size < b->size - b->used)
		return b->ptr + b->used - 1;

	if (buffer_string_is_empty(b)) {
		return buffer_string_prepare_copy(b, size);
	} else {
		/* not empty, b->used already includes a terminating 0 */
		size_t req_size = b->used + size;

		/* check for overflow: unsigned overflow is defined to wrap around */
		force_assert(req_size >= b->used);

		buffer_realloc(b, req_size);

		return b->ptr + b->used - 1;
	}
}

void buffer_string_set_length(buffer *b, size_t len) {
	force_assert(NULL != b);

	if (len >= b->size) buffer_realloc(b, len);

	b->used = len + 1;
	b->ptr[len] = '\0';
}

void buffer_commit(buffer *b, size_t size)
{
	force_assert(NULL != b);
	force_assert(b->size > 0);

	if (0 == b->used) b->used = 1;

	if (size > 0) {
		/* check for overflow: unsigned overflow is defined to wrap around */
		size_t sz = b->used + size;
		force_assert(sz > b->used);
		force_assert(sz <= b->size);
		b->used = sz;
	}

	b->ptr[b->used - 1] = '\0';
}

void buffer_copy_string(buffer *b, const char *s) {
	buffer_copy_string_len(b, s, NULL != s ? strlen(s) : 0);
}

void buffer_copy_string_len(buffer *b, const char *s, size_t s_len) {
	force_assert(NULL != b);
	force_assert(NULL != s || s_len == 0);

	if (s_len >= b->size) buffer_string_prepare_copy(b, s_len);

	if (0 != s_len) memcpy(b->ptr, s, s_len); /*(s might be NULL)*/
	b->ptr[s_len] = '\0';
	b->used = s_len + 1;
}

void buffer_append_string(buffer *b, const char *s) {
	buffer_append_string_len(b, s, NULL != s ? strlen(s) : 0);
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

void buffer_append_string_len(buffer *b, const char *s, size_t s_len) {
	char *target_buf;

	force_assert(NULL != b);
	force_assert(NULL != s || s_len == 0);

	target_buf = buffer_string_prepare_append(b, s_len);
	if (0 == b->used) ++b->used; /*(must include '\0' for append below)*/

	/*(s might be NULL if 0 == s_len)*/
	if (s_len) memcpy(target_buf, s, s_len);
	target_buf[s_len] = '\0';
	b->used += s_len;
}

void buffer_append_path_len(buffer *b, const char *a, size_t alen) {
    size_t blen = buffer_string_length(b);
    int aslash = (alen && a[0] == '/');
    buffer_string_prepare_append(b, alen+2); /*(+ '/' and + '\0' if 0 == blen)*/
    if (blen && b->ptr[blen-1] == '/') {
        if (aslash) --b->used;
    }
    else {
        if (!b->used) ++b->used;
        if (!aslash) b->ptr[++b->used - 2] = '/';
    }
    memcpy(b->ptr+b->used-1, a, alen);
    b->ptr[(b->used += alen)-1] = '\0';
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

	buf = buffer_string_prepare_append(b, shift >> 2); /*nibbles (4 bits)*/
	buffer_commit(b, shift >> 2); /* will fill below */

	while (shift > 0) {
		shift -= 4;
		*(buf++) = hex_chars_lc[(value >> shift) & 0x0F];
	}
}

static char* utostr(char * const buf_end, uintmax_t val) {
	char *cur = buf_end;
	do {
		int mod = val % 10;
		val /= 10;
		/* prepend digit mod */
		*(--cur) = (char) ('0' + mod);
	} while (0 != val);
	return cur;
}

static char* itostr(char * const buf_end, intmax_t val) {
	/* absolute value not defined for INTMAX_MIN, but can take absolute
	 * value of any negative number via twos complement cast to unsigned.
	 * negative sign is prepended after (now unsigned) value is converted
	 * to string */
	uintmax_t uval = val >= 0 ? (uintmax_t)val : ((uintmax_t)~val) + 1;
	char *cur = utostr(buf_end, uval);
	if (val < 0) *(--cur) = '-';

	return cur;
}

void buffer_append_int(buffer *b, intmax_t val) {
	char buf[LI_ITOSTRING_LENGTH];
	char* const buf_end = buf + sizeof(buf);
	char *str;

	force_assert(NULL != b);

	str = itostr(buf_end, val);
	force_assert(buf_end > str && str >= buf);

	buffer_append_string_len(b, str, buf_end - str);
}

void buffer_copy_int(buffer *b, intmax_t val) {
	force_assert(NULL != b);

	b->used = 0;
	buffer_append_int(b, val);
}

void buffer_append_strftime(buffer *b, const char *format, const struct tm *tm) {
	size_t r;
	char* buf;
	force_assert(NULL != b);
	force_assert(NULL != format);
	force_assert(NULL != tm);

	buf = buffer_string_prepare_append(b, 255);
	r = strftime(buf, buffer_string_space(b), format, tm);

	/* 0 (in some apis buffer_string_space(b)) signals the string may have
	 * been too small; but the format could also just have lead to an empty
	 * string
	 */
	if (0 == r || r >= buffer_string_space(b)) {
		/* give it a second try with a larger string */
		buf = buffer_string_prepare_append(b, 4095);
		r = strftime(buf, buffer_string_space(b), format, tm);
	}

	if (r >= buffer_string_space(b)) r = 0;

	buffer_commit(b, r);
}


void li_itostrn(char *buf, size_t buf_len, intmax_t val) {
	char p_buf[LI_ITOSTRING_LENGTH];
	char* const p_buf_end = p_buf + sizeof(p_buf);
	char* str = p_buf_end - 1;
	*str = '\0';

	str = itostr(str, val);
	force_assert(p_buf_end > str && str >= p_buf);

	force_assert(buf_len >= (size_t) (p_buf_end - str));
	memcpy(buf, str, p_buf_end - str);
}

void li_utostrn(char *buf, size_t buf_len, uintmax_t val) {
	char p_buf[LI_ITOSTRING_LENGTH];
	char* const p_buf_end = p_buf + sizeof(p_buf);
	char* str = p_buf_end - 1;
	*str = '\0';

	str = utostr(str, val);
	force_assert(p_buf_end > str && str >= p_buf);

	force_assert(buf_len >= (size_t) (p_buf_end - str));
	memcpy(buf, str, p_buf_end - str);
}

#define li_ntox_lc(n) ((n) <= 9 ? (n) + '0' : (n) + 'a' - 10)

char int2hex(char c) {
	/*return li_ntox_lc(c & 0xF);*/
	return hex_chars_lc[(c & 0x0F)];
}

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


int buffer_eq_icase_ssn(const char * const a, const char * const b, const size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned int ca = ((unsigned char *)a)[i];
        unsigned int cb = ((unsigned char *)b)[i];
        if (ca != cb) {
            ca |= 0x20;
            cb |= 0x20;
            if (ca       !=       cb) return 0;
            if (ca < 'a' || 'z' < ca) return 0;
            if (cb < 'a' || 'z' < cb) return 0;
        }
    }
    return 1;
}

int buffer_eq_icase_ss(const char * const a, const size_t alen, const char * const b, const size_t blen) {
    /* 1 = equal; 0 = not equal */ /* short string sizes expected (< INT_MAX) */
    return (alen == blen && buffer_eq_icase_ssn(a, b, blen));
}

int buffer_eq_icase_slen(const buffer * const b, const char * const s, const size_t slen) {
    /* Note: b must be initialized, i.e. 0 != b->used; uninitialized is not eq*/
    /* 1 = equal; 0 = not equal */ /* short string sizes expected (< INT_MAX) */
    return (b->used == slen + 1 && buffer_eq_icase_ssn(b->ptr, s, slen));
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
	force_assert(NULL != a && NULL != b);

	/* 1 = equal; 0 = not equal */
	return (a->used == b->used && 0 == memcmp(a->ptr, b->ptr, a->used));
}

int buffer_is_equal_string(const buffer *a, const char *s, size_t b_len) {
	force_assert(NULL != a && NULL != s);
	force_assert(b_len + 1 > b_len);

	/* 1 = equal; 0 = not equal */
	return (a->used == b_len + 1 && 0 == memcmp(a->ptr, s, b_len));
}

/* buffer_is_equal_caseless_string(b, CONST_STR_LEN("value")) */
int buffer_is_equal_caseless_string(const buffer *a, const char *s, size_t b_len) {
	force_assert(NULL != a && NULL != s);
	force_assert(b_len + 1 > b_len);
	/* 1 = equal; 0 = not equal */
	return buffer_eq_icase_slen(a, s, b_len);
}

int buffer_is_equal_right_len(const buffer *b1, const buffer *b2, size_t len) {
	/* no len -> equal */
	if (len == 0) return 1;

	/* len > 0, but empty buffers -> not equal */
	if (b1->used == 0 || b2->used == 0) return 0;

	/* buffers too small -> not equal */
	if (b1->used - 1 < len || b2->used - 1 < len) return 0;

	return 0 == memcmp(b1->ptr + b1->used - 1 - len, b2->ptr + b2->used - 1 - len, len);
}


void li_tohex_lc(char *buf, size_t buf_len, const char *s, size_t s_len) {
	force_assert(2 * s_len > s_len);
	force_assert(2 * s_len < buf_len);

	for (size_t i = 0; i < s_len; ++i) {
		buf[2*i]   = hex_chars_lc[(s[i] >> 4) & 0x0F];
		buf[2*i+1] = hex_chars_lc[s[i] & 0x0F];
	}
	buf[2*s_len] = '\0';
}

void li_tohex_uc(char *buf, size_t buf_len, const char *s, size_t s_len) {
	force_assert(2 * s_len > s_len);
	force_assert(2 * s_len < buf_len);

	for (size_t i = 0; i < s_len; ++i) {
		buf[2*i]   = hex_chars_uc[(s[i] >> 4) & 0x0F];
		buf[2*i+1] = hex_chars_uc[s[i] & 0x0F];
	}
	buf[2*s_len] = '\0';
}


void buffer_substr_replace (buffer * const b, const size_t offset,
                            const size_t len, const buffer * const replace)
{
    const size_t blen = buffer_string_length(b);
    const size_t rlen = buffer_string_length(replace);

    if (rlen > len) {
        buffer_string_set_length(b, blen-len+rlen);
        memmove(b->ptr+offset+rlen, b->ptr+offset+len, blen-offset-len);
    }

    memcpy(b->ptr+offset, replace->ptr, rlen);

    if (rlen < len) {
        memmove(b->ptr+offset+rlen, b->ptr+offset+len, blen-offset-len);
        buffer_string_set_length(b, blen-len+rlen);
    }
}


void buffer_append_string_encoded_hex_lc(buffer *b, const char *s, size_t len) {
    unsigned char * const p =
      (unsigned char*) buffer_string_prepare_append(b, len*2);
    buffer_commit(b, len*2); /* fill below */
    for (size_t i = 0; i < len; ++i) {
        p[(i<<1)]   = hex_chars_lc[(s[i] >> 4) & 0x0F];
        p[(i<<1)+1] = hex_chars_lc[(s[i])      & 0x0F];
    }
}

void buffer_append_string_encoded_hex_uc(buffer *b, const char *s, size_t len) {
    unsigned char * const p =
      (unsigned char*) buffer_string_prepare_append(b, len*2);
    buffer_commit(b, len*2); /* fill below */
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



void buffer_append_string_encoded(buffer *b, const char *s, size_t s_len, buffer_encoding_t encoding) {
	unsigned char *ds, *d;
	size_t d_len, ndx;
	const char *map = NULL;

	force_assert(NULL != b);
	force_assert(NULL != s || 0 == s_len);

	if (0 == s_len) return;

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

	force_assert(NULL != map);

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds]) {
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

	d = (unsigned char*) buffer_string_prepare_append(b, d_len);
	buffer_commit(b, d_len); /* fill below */

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds]) {
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

void buffer_append_string_c_escaped(buffer *b, const char *s, size_t s_len) {
	unsigned char *ds, *d;
	size_t d_len, ndx;

	force_assert(NULL != b);
	force_assert(NULL != s || 0 == s_len);

	if (0 == s_len) return;

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if ((*ds < 0x20) /* control character */
				|| (*ds >= 0x7f)) { /* DEL + non-ASCII characters */
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
		} else {
			d_len++;
		}
	}

	d = (unsigned char*) buffer_string_prepare_append(b, d_len);
	buffer_commit(b, d_len); /* fill below */

	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if ((*ds < 0x20) /* control character */
				|| (*ds >= 0x7f)) { /* DEL + non-ASCII characters */
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
				d[d_len++] = hex_chars_lc[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars_lc[(*ds) & 0x0F];
				break;
			}
		} else {
			d[d_len++] = *ds;
		}
	}
}


void buffer_copy_string_encoded_cgi_varnames(buffer *b, const char *s, size_t s_len, int is_http_header) {
	size_t i, j = 0;

	force_assert(NULL != b);
	force_assert(NULL != s || 0 == s_len);

	buffer_string_prepare_copy(b, s_len + 5);

	if (is_http_header) {
		if (s_len == 12 && buffer_eq_icase_ssn(s, "Content-Type", 12)) {
			buffer_copy_string_len(b, CONST_STR_LEN("CONTENT_TYPE"));
			return;
		}
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP_"));
		j = 5; /* "HTTP_" */
	}

	for (i = 0; i < s_len; ++i) {
		unsigned char cr = s[i];
		if (light_isalpha(cr)) {
			/* upper-case */
			cr &= ~32;
		} else if (!light_isdigit(cr)) {
			cr = '_';
		}
		b->ptr[j++] = cr;
	}
	b->used = j;
	b->ptr[b->used++] = '\0';
}

/* decodes url-special-chars inplace.
 * replaces non-printable characters with '_'
 */

static void buffer_urldecode_internal(buffer *url, int is_query) {
	unsigned char high, low;
	char *src;
	char *dst;

	force_assert(NULL != url);
	if (buffer_string_is_empty(url)) return;

	force_assert('\0' == url->ptr[url->used-1]);

	src = (char*) url->ptr;

	while ('\0' != *src) {
		if ('%' == *src) break;
		if (is_query && '+' == *src) *src = ' ';
		src++;
	}
	dst = src;

	while ('\0' != *src) {
		if (is_query && *src == '+') {
			*dst = ' ';
		} else if (*src == '%') {
			*dst = '%';

			high = hex2int(*(src + 1));
			if (0xFF != high) {
				low = hex2int(*(src + 2));
				if (0xFF != low) {
					high = (high << 4) | low;

					/* map control-characters out */
					if (high < 32 || high == 127) high = '_';

					*dst = high;
					src += 2;
				}
			}
		} else {
			*dst = *src;
		}

		dst++;
		src++;
	}

	*dst = '\0';
	url->used = (dst - url->ptr) + 1;
}

void buffer_urldecode_path(buffer *url) {
	buffer_urldecode_internal(url, 0);
}

void buffer_urldecode_query(buffer *url) {
	buffer_urldecode_internal(url, 1);
}

int buffer_is_valid_UTF8(const buffer *b) {
    /* https://www.w3.org/International/questions/qa-forms-utf-8 */
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
 *
 * NOTE: src and dest can point to the same buffer, in which case,
 *       the operation is performed in-place.
 */

void buffer_path_simplify(buffer *dest, buffer *src)
{
	/* current character, the one before, and the one before that from input */
	char c, pre1, pre2;
	char *start, *slash, *walk, *out;

	force_assert(NULL != dest && NULL != src);

	if (buffer_string_is_empty(src)) {
		buffer_copy_string_len(dest, CONST_STR_LEN(""));
		return;
	}

	force_assert('\0' == src->ptr[src->used-1]);

#if defined(__WIN32) || defined(__CYGWIN__)
	/* cygwin is treating \ and / the same, so we have to that too */
	{
		char *p;
		for (p = src->ptr; *p; p++) {
			if (*p == '\\') *p = '/';
		}
	}
#endif

	walk  = src->ptr;
	start = dest->ptr;
	out   = dest->ptr;
	slash = dest->ptr;

	/* skip leading spaces */
	while (*walk == ' ') {
		walk++;
	}
	if (*walk == '.') {
		if (walk[1] == '/' || walk[1] == '\0')
			++walk;
		else if (walk[1] == '.' && (walk[2] == '/' || walk[2] == '\0'))
			walk+=2;
	}

	pre1 = 0;
	c = *(walk++);

	while (c != '\0') {
		/* assert((src != dest || out <= walk) && slash <= out); */
		/* the following comments about out and walk are only interesting if
		 * src == dest; otherwise the memory areas don't overlap anyway.
		 */
		pre2 = pre1;
		pre1 = c;

		/* possibly: out == walk - need to read first */
		c    = *walk;
		*out = pre1;

		out++;
		walk++;
		/* (out <= walk) still true; also now (slash < out) */

		if (c == '/' || c == '\0') {
			const size_t toklen = out - slash;
			if (toklen == 3 && pre2 == '.' && pre1 == '.' && *slash == '/') {
				/* "/../" or ("/.." at end of string) */
				out = slash;
				/* if there is something before "/..", there is at least one
				 * component, which needs to be removed */
				if (out > start) {
					out--;
					while (out > start && *out != '/') out--;
				}

				/* don't kill trailing '/' at end of path */
				if (c == '\0') out++;
				/* slash < out before, so out_new <= slash + 1 <= out_before <= walk */
			} else if (toklen == 1 || (pre2 == '/' && pre1 == '.')) {
				/* "//" or "/./" or (("/" or "/.") at end of string) */
				out = slash;
				/* don't kill trailing '/' at end of path */
				if (c == '\0') out++;
				/* slash < out before, so out_new <= slash + 1 <= out_before <= walk */
			}

			slash = out;
		}
	}

	buffer_string_set_length(dest, out - start);
}

void buffer_to_lower(buffer *b) {
	size_t i;

	for (i = 0; i < b->used; ++i) {
		char c = b->ptr[i];
		if (c >= 'A' && c <= 'Z') b->ptr[i] |= 0x20;
	}
}


void buffer_to_upper(buffer *b) {
	size_t i;

	for (i = 0; i < b->used; ++i) {
		char c = b->ptr[i];
		if (c >= 'a' && c <= 'z') b->ptr[i] &= ~0x20;
	}
}


#include <stdio.h>

#ifdef HAVE_LIBUNWIND
# define UNW_LOCAL_ONLY
# include <libunwind.h>

static void print_backtrace(FILE *file) {
	unw_cursor_t cursor;
	unw_context_t context;
	int ret;
	unsigned int frame = 0;

	if (0 != (ret = unw_getcontext(&context))) goto error;
	if (0 != (ret = unw_init_local(&cursor, &context))) goto error;

	fprintf(file, "Backtrace:\n");

	while (0 < (ret = unw_step(&cursor))) {
		unw_word_t proc_ip = 0;
		unw_proc_info_t procinfo;
		char procname[256];
		unw_word_t proc_offset = 0;

		if (0 != (ret = unw_get_reg(&cursor, UNW_REG_IP, &proc_ip))) goto error;

		if (0 == proc_ip) {
			/* without an IP the other functions are useless; unw_get_proc_name would return UNW_EUNSPEC */
			++frame;
			fprintf(file, "%u: (nil)\n", frame);
			continue;
		}

		if (0 != (ret = unw_get_proc_info(&cursor, &procinfo))) goto error;

		if (0 != (ret = unw_get_proc_name(&cursor, procname, sizeof(procname), &proc_offset))) {
			switch (-ret) {
			case UNW_ENOMEM:
				memset(procname + sizeof(procname) - 4, '.', 3);
				procname[sizeof(procname) - 1] = '\0';
				break;
			case UNW_ENOINFO:
				procname[0] = '?';
				procname[1] = '\0';
				proc_offset = 0;
				break;
			default:
				snprintf(procname, sizeof(procname), "?? (unw_get_proc_name error %d)", -ret);
				break;
			}
		}

		++frame;
		fprintf(file, "%u: %s (+0x%x) [%p]\n",
			frame,
			procname,
			(unsigned int) proc_offset,
			(void*)(uintptr_t)proc_ip);
	}

	if (0 != ret) goto error;

	return;

error:
	fprintf(file, "Error while generating backtrace: unwind error %i\n", (int) -ret);
}
#else
static void print_backtrace(FILE *file) {
	UNUSED(file);
}
#endif

void log_failed_assert(const char *filename, unsigned int line, const char *msg) {
	/* can't use buffer here; could lead to recursive assertions */
	fprintf(stderr, "%s.%u: %s\n", filename, line, msg);
	print_backtrace(stderr);
	fflush(stderr);
	abort();
}
