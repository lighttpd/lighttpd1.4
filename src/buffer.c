#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include "buffer.h"


static const char hex_chars[] = "0123456789abcdef";


/**
 * init the buffer 
 * 
 */

buffer* buffer_init(void) {
	buffer *b;
	
	b = malloc(sizeof(*b));
	assert(b);
	
	b->ptr = NULL;
	b->size = 0;
	b->used = 0;
	
	return b;
}

/**
 * free the buffer 
 * 
 */

void buffer_free(buffer *b) {
	if (!b) return;
	
	if (b->size) {
		free(b->ptr);
		b->size = 0;
		b->used = 0;
	}
	free(b);
}

void buffer_reset(buffer *b) {
	if (!b) return;
	
	/* limit don't reuse buffer larger than ... bytes */
	if (b->size > BUFFER_MAX_REUSE_SIZE) {
		free(b->ptr);
		b->ptr = NULL;
		b->size = 0;
	}
	
	b->used = 0;
}


/**
 * 
 * allocate (if neccessary) enough space for 'size' bytes and 
 * set the 'used' coutner to 0
 * 
 */

#define BUFFER_PIECE_SIZE 64

int buffer_prepare_copy(buffer *b, size_t size) {
	if (!b) return -1;
	
	if ((0 == b->size) || 
	    (size > b->size)) {
		if (b->size) free(b->ptr);
		
		b->size = size;
		
		/* always allocate a multiply of BUFFER_PIECE_SIZE */
		b->size += BUFFER_PIECE_SIZE - (b->size % BUFFER_PIECE_SIZE);
		
		b->ptr = malloc(b->size);
		assert(b->ptr);
	}
	b->used = 0;
	return 0;
}

/**
 * 
 * increase the internal buffer (if neccessary) to append another 'size' byte
 * ->used isn't changed
 * 
 */

int buffer_prepare_append(buffer *b, size_t size) {
	if (!b) return -1;
	
	if (0 == b->size) {
		b->size = size;
		
		/* always allocate a multiply of BUFFER_PIECE_SIZE */
		b->size += BUFFER_PIECE_SIZE - (b->size % BUFFER_PIECE_SIZE);
		
		b->ptr = malloc(b->size);
		b->used = 0;
		assert(b->ptr);
	} else if (b->used + size > b->size) {
		b->size += size;
		
		/* always allocate a multiply of BUFFER_PIECE_SIZE */
		b->size += BUFFER_PIECE_SIZE - (b->size % BUFFER_PIECE_SIZE);
		
		b->ptr = realloc(b->ptr, b->size);
		assert(b->ptr);
	}
	return 0;
}

int buffer_copy_string(buffer *b, const char *s) {
	size_t s_len;
	
	if (!s || !b) return -1;
	
	s_len = strlen(s);
	if (buffer_prepare_copy(b, s_len + 1)) return -1;
	
	memcpy(b->ptr, s, s_len + 1);
	b->used = s_len + 1;
	
	return 0;
}

int buffer_copy_string_len(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
#if 0	
	/* removed optimization as we have to keep the empty string 
	 * in some cases for the config handling
	 * 
	 * url.access-deny = ( "" )
	 */
	if (s_len == 0) return 0;
#endif	
	if (buffer_prepare_copy(b, s_len + 1)) return -1;
	
	memcpy(b->ptr, s, s_len);
	b->ptr[s_len] = '\0';
	b->used = s_len + 1;
	
	return 0;
}

int buffer_copy_string_buffer(buffer *b, const buffer *src) {
	if (!src) return 0;
	
	if (src->used == 0) {
		b->used = 0;
		return 0;
	}
	return buffer_copy_string_len(b, src->ptr, src->used - 1);
}

int buffer_append_string(buffer *b, const char *s) {
	size_t s_len;
	
	if (!s || !b) return -1;
	
	/* the buffer is empty, fallback to copy */
	if (b->used == 0) {
		return buffer_copy_string(b, s);
	}
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	s_len = strlen(s);
	if (buffer_prepare_append(b, s_len)) return -1;
	
	memcpy(b->ptr + b->used - 1, s, s_len + 1);
	b->used += s_len;
	
	return 0;
}

int buffer_append_string_rfill(buffer *b, const char *s, size_t maxlen) {
	size_t s_len;
	size_t m;
	ssize_t fill_len;
	
	if (!s || !b) return -1;
	
	/* the buffer is empty, fallback to copy */
	if (b->used == 0) {
		return buffer_copy_string(b, s);
	}
	
	if (b->ptr[b->used - 1] != '\0') {
		/* seg-fault */
		SEGFAULT();
	}
	
	s_len = strlen(s);
	
	m = s_len > maxlen + 1 ? s_len : maxlen + 1;
	
	if (buffer_prepare_append(b, m)) return -1;
	
	fill_len = maxlen - s_len;
	
	if (fill_len > 0) {
		memcpy(b->ptr + b->used - 1, s, s_len);
		memset(b->ptr + b->used + s_len - 1, ' ', fill_len);
		*(b->ptr + b->used + s_len + fill_len - 1) = '\0';
		b->used += s_len + fill_len;
	} else {
		memcpy(b->ptr + b->used - 1, s, s_len + 1);
		b->used += s_len;
	}
	
	return 0;
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

int buffer_append_string_len(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
	
	if (s_len == 0) return 0;
	
	/* the buffer is empty, fallback to copy */
	if (b->used == 0) {
		return buffer_copy_string_len(b, s, s_len);
	}
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	if (buffer_prepare_append(b, s_len)) return -1;
	
	memcpy(b->ptr + b->used - 1, s, s_len);
	b->ptr[b->used + s_len - 1] = '\0';
	b->used += s_len;
	
	return 0;
}

int buffer_append_string_buffer(buffer *b, const buffer *src) {
	if (!src) return 0;
	if (src->used == 0) return 0;
	
	return buffer_append_string_len(b, src->ptr, src->used - 1);
}

int buffer_append_memory(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
	
	if (s_len == 0) return 0;
	
	if (buffer_prepare_append(b, s_len)) return -1;
	
	memcpy(b->ptr + b->used, s, s_len);
	b->used += s_len;
	
	return 0;
}

int buffer_copy_memory(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
	
	b->used = 0;
	
	return buffer_append_memory(b, s, s_len);
}

int buffer_append_hex(buffer *b, unsigned long value) {
	char *buf;
	int shift = 0;
	unsigned long copy = value;

	while (copy) {
		copy >>= 4;
		shift++;
	}
	if (shift == 0)
		shift++;
	if (shift & 0x01)
		shift++;

	buffer_prepare_append(b, shift + 1);
	buf = b->ptr + b->used;
	b->used += shift + 1;

	shift <<= 2;
	while (shift > 0) {
		shift -= 4;
		*(buf++) = hex_chars[(value >> shift) & 0x0F];
	}
	*buf = '\0';

	return 0;
}


int ltostr(char *s, long l) {
	int i, sign = 0;
	
	if (l < 0) {
		sign = 1;
		l = -l;
	}
	
	for (i = 0; l > 9; l /= 10, i++) {
		s[i] = '0' + (l % 10);
	}
	
	s[i] = '0' + l;
	if (sign) {
		s[++i] = '-';
	}
	s[i+1] = '\0';
	
	/* swap bytes again :) */
	if (i > 0) {
		int li = i;
		for (; i > li / 2; i--) {
			char c;
			
			c = s[i];
			s[i] = s[li - i];
			s[li - i] = c;
		}
	}
	
	return 0;
}

int buffer_copy_long(buffer *b, long l) {
	int i, sign = 0;
	char *s;
	
	if (!b) return -1;
	
	b->used = 0;
	
	if (buffer_prepare_append(b, 32)) return -1;
	
	s = b->ptr + b->used;
	
	if (l < 0) {
		sign = 1;
		l = -l;
	}
	
	for (i = 0; l > 9; l /= 10, i++) {
		s[i] = '0' + (l % 10);
	}
	
	s[i] = '0' + l;
	if (sign) {
		s[++i] = '-';
	}
	s[i+1] = '\0';
	b->used = i + 2;
	
	/* swap bytes again :) */
	if (i > 0) {
		int li = i;
		for (; i > li / 2; i--) {
			char c;
			
			c = s[i];
			s[i] = s[li - i];
			s[li - i] = c;
		}
	}
	
	return 0;
}

int buffer_append_long(buffer *b, long l) {
	int i, sign = 0;
	char *s;
	
	if (!b) return -1;
	
	/* the buffer is empty, fallback to copy */
	if (b->used == 0) {
		SEGFAULT();
	}
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	if (buffer_prepare_append(b, 32)) return -1;
	
	s = b->ptr + b->used - 1;
	
	if (l < 0) {
		sign = 1;
		l = -l;
	}
	
	for (i = 0; l > 9; l /= 10, i++) {
		s[i] = '0' + (l % 10);
	}
	
	s[i] = '0' + l;
	if (sign) {
		s[++i] = '-';
	}
	s[i+1] = '\0';
	b->used += i + 1;
	
	/* swap bytes again :) */
	if (i > 0) {
		int li = i;
		for (; i > li / 2; i--) {
			char c;
			
			c = s[i];
			s[i] = s[li - i];
			s[li - i] = c;
		}
	}
	
	return 0;
}


int buffer_copy_off_t(buffer *b, off_t l) {
	int i, sign = 0;
	char *s;
	
	/* a 32bit off_t is handled by _long directly */
	if (sizeof(l) == 4) return buffer_copy_long(b, l);
	
	if (!b) return -1;
	
	b->used = 0;
	
	if (buffer_prepare_append(b, 32)) return -1;
	
	s = b->ptr + b->used;
	
	if (l < 0) {
		sign = 1;
		l = -l;
	}
	
	for (i = 0; l > 9; l /= 10, i++) {
		s[i] = '0' + (l % 10);
	}
	
	s[i] = '0' + l;
	if (sign) {
		s[++i] = '-';
	}
	s[i+1] = '\0';
	b->used = i + 2;
	
	/* swap bytes again :) */
	if (i > 0) {
		int li = i;
		for (; i > li / 2; i--) {
			char c;
			
			c = s[i];
			s[i] = s[li - i];
			s[li - i] = c;
		}
	}
	
	return 0;
}

int buffer_append_off_t(buffer *b, off_t l) {
	int i, sign = 0;
	char *s;
	
	/* a 32bit off_t is handled by _long directly */
	if (sizeof(l) == 4) return buffer_append_long(b, l);
	
	if (!b) return -1;
	
	/* the buffer is empty, fallback to copy */
	if (b->used == 0) {
		SEGFAULT();
	}
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	if (buffer_prepare_append(b, 32)) return -1;
	
	s = b->ptr + b->used - 1;
	
	if (l < 0) {
		sign = 1;
		l = -l;
	}
	
	for (i = 0; l > 9; l /= 10, i++) {
		s[i] = '0' + (l % 10);
	}
	
	s[i] = '0' + l;
	if (sign) {
		s[++i] = '-';
	}
	s[i+1] = '\0';
	b->used += i + 1;
	
	/* swap bytes again :) */
	if (i > 0) {
		int li = i;
		for (; i > li / 2; i--) {
			char c;
			
			c = s[i];
			s[i] = s[li - i];
			s[li - i] = c;
		}
	}
	
	return 0;
}

char int2hex(char c) {
	return hex_chars[(c & 0x0F)];
}

/* converts hex char (0-9, A-Z, a-z) to decimal.
 * returns 0xFF on invalid input.
 */
char hex2int(unsigned char hex) {
	hex = hex - '0';
	if (hex > 9) {
		hex = (hex + '0' - 1) | 0x20;
		hex = hex - 'a' + 11;
	}
	if (hex > 15)
		hex = 0xFF;

	return hex;
}


/**
 * init the buffer 
 * 
 */

buffer_array* buffer_array_init(void) {
	buffer_array *b;
	
	b = malloc(sizeof(*b));
	
	assert(b);
	b->ptr = NULL;
	b->size = 0;
	b->used = 0;
	
	return b;
}

/**
 * free the buffer_array 
 * 
 */

void buffer_array_free(buffer_array *b) {
	size_t i;
	if (!b) return;
	
	for (i = 0; i < b->size; i++) {
		if (b->ptr[i]) buffer_free(b->ptr[i]);
	}
	free(b->ptr);
	free(b);
}

buffer *buffer_array_append_get_buffer(buffer_array *b) {
	size_t i;
	if (b->size == 0) {
		b->size = 16;
		b->ptr = malloc(sizeof(*b->ptr) * b->size);
		assert(b->ptr);
		for (i = 0; i < b->size; i++) {
			b->ptr[i] = NULL;
		}
	} else if (b->size == b->used) {
		b->size += 16;
		b->ptr = realloc(b->ptr, sizeof(*b->ptr) * b->size);
		assert(b->ptr);
		for (i = b->used; i < b->size; i++) {
			b->ptr[i] = NULL;
		}
	}
	
	if (b->ptr[b->used] == NULL) {
		b->ptr[b->used] = buffer_init();
	}
	
	b->ptr[b->used]->used = 0;
	
	return b->ptr[b->used++];
}


char * buffer_search_string_len(buffer *b, const char *needle, size_t len) {
	size_t i;
	if (len == 0) return NULL;
	if (needle == NULL) return NULL;
	
	if (b->used < len) return NULL;
	
	for(i = 0; i < b->used - len; i++) {
		if (0 == memcmp(b->ptr + i, needle, len)) {
			return b->ptr + i;
		}
	}
	
	return NULL;
}

buffer *buffer_init_string(const char *str) {
	buffer *b = buffer_init();
	
	buffer_copy_string(b, str);
	
	return b;
}

int buffer_is_empty(buffer *b) {
	return (b->used == 0);
}

/**
 * check if two buffer contain the same data
 * 
 * this is a optimized 32/64bit compare function.
 * 
 * it is assumed that the leftmost byte have the most equality. 
 * That why the comparision is done right to left
 * 
 */

int buffer_is_equal(buffer *a, buffer *b) {
	size_t i;
	
	if (a->used != b->used) return 0;
	if (a->used == 0) return 1;

	for (i = a->used - 1; i < a->used && i % (sizeof(size_t)); i --) {
		if (a->ptr[i] != b->ptr[i]) return 0;
	}
	
	for (i -= (sizeof(size_t)); i < a->used; i -= (sizeof(size_t))) {
		if (*((size_t *)(a->ptr + i)) != 
		    *((size_t *)(b->ptr + i))) return 0;
	}

	return 1;
}

int buffer_is_equal_string(buffer *a, const char *s, size_t b_len) {
	buffer b;
	
	b.ptr = (char *)s;
	b.used = b_len + 1;
	
	return buffer_is_equal(a, &b);
}

/* simple-assumption:
 * 
 * most parts are equal and doing a case conversion needs time
 * 
 */
int buffer_caseless_compare(const char *a, size_t a_len, const char *b, size_t b_len) {
	size_t ndx = 0, max_ndx;
	size_t *al, *bl;
	size_t mask = sizeof(*al) - 1;
	
	al = (size_t *)a;
	bl = (size_t *)b;
	
	/* is the alignment correct ? */
	if ( ((size_t)al & mask) == 0 &&
	     ((size_t)bl & mask) == 0 ) {
		
		max_ndx = ((a_len < b_len) ? a_len : b_len) & ~mask;
		
		for (; ndx < max_ndx; ndx += sizeof(*al)) {
			if (*al != *bl) break;
			al++; bl++;
			
		}
		
	}
	
	a = (char *)al;
	b = (char *)bl;
	
	max_ndx = ((a_len < b_len) ? a_len : b_len);
	
	for (; ndx < max_ndx; ndx++) {
		char a1 = *a++, b1 = *b++;
		
		if (a1 != b1) {
			if ((a1 >= 'A' && a1 <= 'Z') && (b1 >= 'a' && b1 <= 'z'))
				a1 |= 32;
			else if ((a1 >= 'a' && a1 <= 'z') && (b1 >= 'A' && b1 <= 'Z'))
				b1 |= 32;
			if ((a1 - b1) != 0) return (a1 - b1);
			
		}
	}
	
	return 0;
}


/**
 * check if the rightmost bytes of the string are equal.
 * 
 * 
 */

int buffer_is_equal_right_len(buffer *b1, buffer *b2, size_t len) {
	/* no, len -> equal */
	if (len == 0) return 1;
	
	/* len > 0, but empty buffers -> not equal */
	if (b1->used == 0 || b2->used == 0) return 0;
	
	/* buffers too small -> not equal */
	if (b1->used - 1 < len || b1->used - 1 < len) return 0;
	
	if (0 == strncmp(b1->ptr + b1->used - 1 - len, 
			 b2->ptr + b2->used - 1 - len, len)) {
		return 1;
	}
	
	return 0;
}

int buffer_copy_string_hex(buffer *b, const char *in, size_t in_len) {
	size_t i;
	
	/* BO protection */
	if (in_len * 2 < in_len) return -1;
	
	buffer_prepare_copy(b, in_len * 2 + 1);
	
	for (i = 0; i < in_len; i++) {
		b->ptr[b->used++] = hex_chars[(in[i] >> 4) & 0x0F];
		b->ptr[b->used++] = hex_chars[in[i] & 0x0F];
	}
	b->ptr[b->used++] = '\0';
	
	return 0;
}


int buffer_append_string_hex(buffer *b, const char *in, size_t in_len) {
	size_t i;
	
	/* BO protection */
	if (in_len * 2 < in_len) return -1;
	
	if (b->used > 0) {
		if (b->ptr[b->used-1] == '\0') b->used--;
	}
	
	buffer_prepare_append(b, in_len * 2 + 1);
	
	for (i = 0; i < in_len; i++) {
		b->ptr[b->used++] = hex_chars[(in[i] >> 4) & 0x0F];
		b->ptr[b->used++] = hex_chars[in[i] & 0x0F];
	}
	b->ptr[b->used++] = '\0';
	
	return 0;
}

int buffer_append_string_url_encoded(buffer *b, const char *s) {
	unsigned char *ds, *d;
	size_t d_len;
	
	if (!s || !b) return -1;
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	
	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0; *ds; ds++) {
		if (*ds < 32 || *ds > 126) {
			d_len += 3;
		} else {
			switch (*ds) {
			case '$':
			case '&':
			case '+':
			case ',':
			case '/':
			case ':':
			case ';':
			case '=':
			case '?':
			case '@':
			case ' ':
			case '#':
			case '%':
			case '<':
			case '>':
			case '"':
			case '\'':
				d_len += 3;
				break;
			default:
				d_len ++;
				break;
			}
		}
	}
	
	if (buffer_prepare_append(b, d_len)) return -1;
	
	for (ds = (unsigned char *)s, d = (unsigned char *)b->ptr + b->used - 1, d_len = 0; *ds; ds++) {
		if (*ds < 32 || *ds > 126) {
			d[d_len++] = '%';
			d[d_len++] = hex_chars[((*ds) >> 4) & 0x0F];
			d[d_len++] = hex_chars[(*ds) & 0x0F];
		} else {
			switch (*ds) {
			case '$':
			case '&':
			case '+':
			case ',':
			case '/':
			case ':':
			case ';':
			case '=':
			case '?':
			case '@':
			case ' ':
			case '#':
			case '%':
			case '<':
			case '>':
			case '"':
			case '\'':
				d[d_len++] = '%';
				d[d_len++] = hex_chars[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars[(*ds) & 0x0F];
				break;
			default:
				d[d_len++] = *ds;
				break;
			}
		}
	}
	
	b->ptr[b->used + d_len - 1] = '\0';
	
	b->used += d_len;
	
	return 0;
}

int buffer_append_string_html_encoded(buffer *b, const char *s) {
	unsigned char *ds, *d;
	size_t d_len;
	
	if (!s || !b) return -1;
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	
	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0; *ds; ds++) {
		switch (*ds) {
		case '>':
		case '<':
			d_len += 4;
			break;
		case '&':
			d_len += 5;
			break;
		default:
			d_len++;
			break;
		}
	}
	
	if (buffer_prepare_append(b, d_len)) return -1;
	
	for (ds = (unsigned char *)s, d = (unsigned char *)b->ptr + b->used - 1, d_len = 0; *ds; ds++) {
		switch (*ds) {
		case '>':
			d[d_len++] = '&';
			d[d_len++] = 'g';
			d[d_len++] = 't';
			d[d_len++] = ';';
			
			break;
		case '<':
			d[d_len++] = '&';
			d[d_len++] = 'l';
			d[d_len++] = 't';
			d[d_len++] = ';';
			
			break;
		case '&':
			d[d_len++] = '&';
			d[d_len++] = 'a';
			d[d_len++] = 'm';
			d[d_len++] = 'p';
			d[d_len++] = ';';
			
			break;
				
		default:
			d[d_len++] = *ds;
			break;
		}
	}
	
	b->ptr[b->used + d_len - 1] = '\0';
	b->used += d_len;
	
	return 0;
}

/* decodes url-special-chars inplace.
 * ignores %00 (null-byte).
 */
int buffer_urldecode(buffer *url) {
	unsigned char high, low;
	const char *src;
	char *dst;

	if (!url || !url->ptr) return -1;

	src = (const char*) url->ptr;
	dst = (char*) url->ptr;

	while ((*src) != '\0') {
#if 1
		if (*src == '+') {
			*dst = ' ';
		} else 
#endif
		if (*src == '%') {
			*dst = '%';

			high = hex2int(*(src + 1));
			if (high != 0xFF) {
				low = hex2int(*(src + 2));
				if (low != 0xFF) {
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

	return 0;
}

int buffer_path_simplify(dot_stack *stack, buffer *out, buffer *in) {
	char *last_slash, *slash;
	size_t i;
	
	/*
	 * /./ -> /
	 * ^/../ -> /
	 * /abc/../ -> /
	 */
	
	stack->used = 0;
	
	for (last_slash = in->ptr; NULL != (slash = strchr(last_slash, '/')); last_slash = slash + 1) {
		int n;
		
		n = slash - last_slash;
		
		if ((n == 0) || /* // */
		    (n == 1 && *last_slash == '.') || /* /./ */
		    (n == 2 && *last_slash == '.' && *(last_slash+1) == '.')) /* /../ */ {
			if (n == 2 && stack->used > 0) stack->used--;
		} else {
			if (stack->size == 0) {
				stack->size = 16;
				stack->ptr = malloc(stack->size * sizeof(*stack->ptr));
				assert(stack->ptr);
				
				stack->used = 0;
				for (i = 0; i < stack->size; i++) {
					stack->ptr[i] = malloc(sizeof(**stack->ptr));
					assert(stack->ptr[i]);
				}
			} else if (stack->size == stack->used) {
				stack->size += 16;
				stack->ptr = realloc(stack->ptr, stack->size * sizeof(*stack->ptr));
				assert(stack->ptr);
				
				for (i = stack->used; i < stack->size; i++) {
					stack->ptr[i] = malloc(sizeof(**stack->ptr));
					assert(stack->ptr[i]);
				}
			}
			
			stack->ptr[stack->used]->start = last_slash;
			stack->ptr[stack->used]->len = n + 1;
			
			stack->used++;
		}
	}
	
	if (stack->size == 0) {
		stack->size = 16;
		stack->ptr = malloc(stack->size * sizeof(*stack->ptr));
		assert(stack->ptr);
		
		stack->used = 0;
		for (i = 0; i < stack->size; i++) {
			stack->ptr[i] = malloc(sizeof(**stack->ptr));
			assert(stack->ptr[i]);
		}
	} else if (stack->size == stack->used) {
		stack->size += 16;
		stack->ptr = realloc(stack->ptr, stack->size * sizeof(*stack->ptr));
		assert(stack->ptr);
		
		for (i = stack->used; i < stack->size; i++) {
			stack->ptr[i] = malloc(sizeof(**stack->ptr));
			assert(stack->ptr[i]);
		}
	}
	
	stack->ptr[stack->used]->start = last_slash;
	stack->ptr[stack->used]->len = in->used - (last_slash - in->ptr) - 1;
	
	stack->used++;
	
	BUFFER_COPY_STRING_CONST(out, "/");
	
	for (i = 0; i < stack->used; i++) {
		buffer_append_string_len(out, stack->ptr[i]->start, stack->ptr[i]->len);
	}
	
	return 0;
}

inline int light_isdigit(int c) {
	return (c >= '0' && c <= '9');
}

inline int light_isxdigit(int c) {
	if (light_isdigit(c)) return 1;
	
	c |= 32;
	return (c >= 'a' && c <= 'f');
}

inline int light_isalpha(int c) {
	c |= 32;
	return (c >= 'a' && c <= 'z');
}

inline int light_isalnum(int c) {
	return light_isdigit(c) || light_isalpha(c);
}
