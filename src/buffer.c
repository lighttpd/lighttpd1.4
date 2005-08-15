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

buffer *buffer_init_buffer(buffer *src) {
	buffer *b = buffer_init();
	buffer_copy_string_buffer(b, src);
	return b;
}

/**
 * free the buffer 
 * 
 */

void buffer_free(buffer *b) {
	if (!b) return;

	free(b->ptr);
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
 * set the 'used' counter to 0
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

	s_len = strlen(s) + 1;
	buffer_prepare_copy(b, s_len);

	memcpy(b->ptr, s, s_len);
	b->used = s_len;

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
	buffer_prepare_copy(b, s_len + 1);
	
	memcpy(b->ptr, s, s_len);
	b->ptr[s_len] = '\0';
	b->used = s_len + 1;
	
	return 0;
}

int buffer_copy_string_buffer(buffer *b, const buffer *src) {
	if (!src) return -1;
	
	if (src->used == 0) {
		b->used = 0;
		return 0;
	}
	return buffer_copy_string_len(b, src->ptr, src->used - 1);
}

int buffer_append_string(buffer *b, const char *s) {
	size_t s_len;

	if (!s || !b) return -1;

	s_len = strlen(s);
	buffer_prepare_append(b, s_len + 1);
	if (b->used == 0)
		b->used++;

	memcpy(b->ptr + b->used - 1, s, s_len + 1);
	b->used += s_len;

	return 0;
}

int buffer_append_string_rfill(buffer *b, const char *s, size_t maxlen) {
	size_t s_len;

	if (!s || !b) return -1;

	s_len = strlen(s);
	buffer_prepare_append(b, maxlen + 1);
	if (b->used == 0)
		b->used++;

	memcpy(b->ptr + b->used - 1, s, s_len);
	if (maxlen > s_len) {
		memset(b->ptr + b->used - 1 + s_len, ' ', maxlen - s_len);
	}

	b->used += maxlen;
	b->ptr[b->used - 1] = '\0';
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

	buffer_prepare_append(b, s_len + 1);
	if (b->used == 0)
		b->used++;

	memcpy(b->ptr + b->used - 1, s, s_len);
	b->used += s_len;
	b->ptr[b->used - 1] = '\0';

	return 0;
}

int buffer_append_string_buffer(buffer *b, const buffer *src) {
	if (!src) return -1;
	if (src->used == 0) return 0;
	
	return buffer_append_string_len(b, src->ptr, src->used - 1);
}

int buffer_append_memory(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
	if (s_len == 0) return 0;

	buffer_prepare_append(b, s_len);
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
	if (b->used == 0)
		b->used++;
	buf = b->ptr + (b->used - 1);
	b->used += shift;

	shift <<= 2;
	while (shift > 0) {
		shift -= 4;
		*(buf++) = hex_chars[(value >> shift) & 0x0F];
	}
	*buf = '\0';

	return 0;
}


int ltostr(char *buf, long val) {
	char swap;
	char *end;
	int len = 1;

	if (val < 0) {
		len++;
		*(buf++) = '-';
		val = -val;
	}

	end = buf;
	while (val > 9) {
		*(end++) = '0' + (val % 10);
		val = val / 10;
	}
	*(end) = '0' + val;
	*(end + 1) = '\0';
	len += end - buf;

	while (buf < end) {
		swap = *end;
		*end = *buf;
		*buf = swap;

		buf++;
		end--;
	}

	return len;
}

int buffer_append_long(buffer *b, long val) {
	if (!b) return -1;

	buffer_prepare_append(b, 32);
	if (b->used == 0)
		b->used++;

	b->used += ltostr(b->ptr + (b->used - 1), val);
	return 0;
}

int buffer_copy_long(buffer *b, long val) {
	if (!b) return -1;

	b->used = 0;
	return buffer_append_long(b, val);
}

#if !defined(SIZEOF_LONG) || (SIZEOF_LONG != SIZEOF_OFF_T)
int buffer_append_off_t(buffer *b, off_t val) {
	char swap;
	char *end;
	char *start;
	int len = 1;

	if (!b) return -1;

	buffer_prepare_append(b, 32);
	if (b->used == 0)
		b->used++;

	start = b->ptr + (b->used - 1);
	if (val < 0) {
		len++;
		*(start++) = '-';
		val = -val;
	}

	end = start;
	while (val > 9) {
		*(end++) = '0' + (val % 10);
		val = val / 10;
	}
	*(end) = '0' + val;
	*(end + 1) = '\0';
	len += end - start;

	while (start < end) {
		swap   = *end;
		*end   = *start;
		*start = swap;

		start++;
		end--;
	}

	b->used += len;
	return 0;
}

int buffer_copy_off_t(buffer *b, off_t val) {
	if (!b) return -1;

	b->used = 0;
	return buffer_append_off_t(b, val);
}
#endif /* !defined(SIZEOF_LONG) || (SIZEOF_LONG != SIZEOF_OFF_T) */

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

void buffer_array_reset(buffer_array *b) {
	size_t i;
	
	if (!b) return;
	
	/* if they are too large, reduce them */
	for (i = 0; i < b->used; i++) {
		buffer_reset(b->ptr[i]);
	}
	
	b->used = 0;
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

	/* we are unsigned, if i < 0 it will flip to MAX_SIZE_T and will be > a->used */
	for (i = a->used - 1; i < a->used && i % (sizeof(size_t)); i--) {
		if (a->ptr[i] != b->ptr[i]) return 0;
	}
	
	/* compare the single char itself which was kicked us out of the loop */ 
	if (i < a->used && a->ptr[i] != b->ptr[i]) return 0;
	
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
	
	if (b->used > 0 && b->ptr[b->used - 1] == '\0') {
		b->used--;
	}
	
	buffer_prepare_append(b, in_len * 2 + 1);
	
	for (i = 0; i < in_len; i++) {
		b->ptr[b->used++] = hex_chars[(in[i] >> 4) & 0x0F];
		b->ptr[b->used++] = hex_chars[in[i] & 0x0F];
	}
	b->ptr[b->used++] = '\0';
	
	return 0;
}

int buffer_append_string_url_encoded(buffer *b, const char *s, size_t s_len) {
	unsigned char *ds, *d;
	size_t d_len;
	
	if (!s || !b) return -1;
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	if (s_len == 0) return 0;
	
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
	
	buffer_prepare_append(b, d_len);
	
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

int buffer_append_string_html_encoded(buffer *b, const char *s, size_t s_len) {
	unsigned char *ds, *d;
	size_t d_len;
	
	if (!s || !b) return -1;
	
	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}
	
	/* nothing to append */
	if (s_len == 0) return 0;
	
	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0; *ds; ds++) {
		d_len++;
		if (*ds == '<' || *ds == '>')
			d_len += 4 - 1;
		else if (*ds == '&')
			d_len += 5 - 1;
	}

	buffer_prepare_append(b, d_len);
	
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
 * replaces non-printable characters with '_'
 */

static int buffer_urldecode_internal(buffer *url, int is_query) {
	unsigned char high, low;
	const char *src;
	char *dst;

	if (!url || !url->ptr) return -1;

	src = (const char*) url->ptr;
	dst = (char*) url->ptr;

	while ((*src) != '\0') {
		if (is_query && *src == '+') {
			*dst = ' ';
		} else if (*src == '%') {
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

int buffer_urldecode_path(buffer *url) {
	return buffer_urldecode_internal(url, 0);
}

int buffer_urldecode_query(buffer *url) {
	return buffer_urldecode_internal(url, 1);
}

/* Remove "/../", "//", "/./" parts from path.
 *
 * /blah/..         gets  /
 * /blah/../foo     gets  /foo
 * /abc/./xyz       gets  /abc/xyz
 * /abc//xyz        gets  /abc/xyz
 *
 * NOTE: src and dest can point to the same buffer, in which case,
 *       the operation is performed in-place.
 */

int buffer_path_simplify(buffer *dest, buffer *src)
{
	int toklen;
	char c, pre1;
	char *start, *slash, *walk, *out;
	unsigned short pre;

	if (src == NULL || src->ptr == NULL || dest == NULL)
		return -1;

	if (src == dest)
		buffer_prepare_append(dest, 1);
	else
		buffer_prepare_copy(dest, src->used + 1);

	walk  = src->ptr;
	start = dest->ptr;
	out   = dest->ptr;
	slash = dest->ptr;
	while (*walk == ' ') {
		walk++;
	}

	pre1 = *(walk++);
	c    = *(walk++);
	pre  = pre1;
	if (pre1 != '/') {
		pre = ('/' << 8) | pre1;
		*(out++) = '/';
	}
	*(out++) = pre1;

	while (1) {
		if (c == '/' || c == '\0') {
			toklen = out - slash;
			if (toklen == 3 && pre == (('.' << 8) | '.')) {
				out = slash;
				if (out > start) {
					out--;
					while (out > start && *out != '/') {
						out--;
					}
				}

				if (c == '\0')
					out++;
			} else if (toklen == 1 || pre == (('/' << 8) | '.')) {
				out = slash;
				if (c == '\0')
					out++;
			}

			slash = out;
		}

		if (c == '\0')
			break;

		pre1 = c;
		pre  = (pre << 8) | pre1;
		c    = *walk;
		*out = pre1;

		out++;
		walk++;
	}

	*out = '\0';
	dest->used = (out - start) + 1;

	return 0;
}

int light_isdigit(int c) {
	return (c >= '0' && c <= '9');
}

int light_isxdigit(int c) {
	if (light_isdigit(c)) return 1;
	
	c |= 32;
	return (c >= 'a' && c <= 'f');
}

int light_isalpha(int c) {
	c |= 32;
	return (c >= 'a' && c <= 'z');
}

int light_isalnum(int c) {
	return light_isdigit(c) || light_isalpha(c);
}

int buffer_to_lower(buffer *b) {
	char *c;
	
	if (b->used == 0) return 0;
	
	for (c = b->ptr; *c; c++) {
		if (*c >= 'A' && *c <= 'Z') {
			*c |= 32;
		}
	}
	
	return 0;
}


int buffer_to_upper(buffer *b) {
	char *c;
	
	if (b->used == 0) return 0;
	
	for (c = b->ptr; *c; c++) {
		if (*c >= 'a' && *c <= 'z') {
			*c &= ~32;
		}
	}
	
	return 0;
}
