#include "first.h"

#include "base64.h"

/* reverse mapping:
 * >= 0: base64 value
 * -1: invalid character
 * -2: skip character (whitespace/control)
 * -3: padding
 */

/* BASE64_STANDARD: "A-Z a-z 0-9 + /" maps to 0-63, pad with "=" */
static const char base64_standard_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static const signed char base64_standard_reverse_table[] = {
/*	 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
	-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, /* 0x00 - 0x0F */
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, /* 0x10 - 0x1F */
	-2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 0x20 - 0x2F */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -3, -1, -1, /* 0x30 - 0x3F */
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 0x40 - 0x4F */
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 0x50 - 0x5F */
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 0x60 - 0x6F */
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 0x70 - 0x7F */
};

/* BASE64_URL: "A-Z a-z 0-9 - _" maps to 0-63, pad with "=" */
static const char base64_url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
static const signed char base64_url_reverse_table[] = {
/*	 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
	-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, /* 0x00 - 0x0F */
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, /* 0x10 - 0x1F */
	-2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, /* 0x20 - 0x2F */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -3, -1, -1, /* 0x30 - 0x3F */
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 0x40 - 0x4F */
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, /* 0x50 - 0x5F */
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 0x60 - 0x6F */
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 0x70 - 0x7F */
};

size_t li_base64_dec(unsigned char * const result, const size_t out_length, const char * const in, const size_t in_length, const base64_charset charset) {
    size_t i;
    const signed char * const base64_reverse_table = (charset)
      ? base64_url_reverse_table                     /* BASE64_URL */
      : base64_standard_reverse_table;               /* BASE64_STANDARD */

    int_fast32_t ch = 0;
    int_fast32_t out4 = 0;
    size_t out_pos = 0;
    for (i = 0; i < in_length; i++) {
        const uint_fast32_t c = ((unsigned char *)in)[i];
        ch = (c < 128) ? base64_reverse_table[c] : -1;
        if (__builtin_expect( (ch < 0), 0)) {
            /* skip formatted base64; skip whitespace ('\r' '\n' '\t' ' ')*/
            if (-2 == ch) /*(loose check; skip ' ', all ctrls not \127 or \0)*/
                continue; /* skip character */
            break;
        }

        out4 = (out4 << 6) | ch;
        if ((i & 3) == 3) {
            result[out_pos]   = (out4 >> 16) & 0xFF;
            result[out_pos+1] = (out4 >>  8) & 0xFF;
            result[out_pos+2] = (out4      ) & 0xFF;
            out_pos += 3;
            out4 = 0;
        }
    }

    /* permit base64 string ending with pad chars (ch == -3); not checking
     * for one or two pad chars + optional whitespace reaches in_length) */
    /* permit base64 string truncated before in_length (in[i] == '\0') */
    switch (i == in_length || ch == -3 || in[i] != '\0' ? (i & 3) : 1) {
      case 3:
        result[out_pos++] = (out4 >> 10);
        out4 <<= 2;
        __attribute_fallthrough__
      case 2:
        result[out_pos++] = (out4 >> 4) & 0xFF;
        __attribute_fallthrough__
      case 0:
        force_assert(out_pos <= out_length);
        return out_pos;
      case 1: /* pad char or str end can only come after 2+ base64 chars */
      default:
        return 0; /* invalid character, abort */
    }
}

size_t li_base64_enc(char * const restrict out, const size_t out_length, const unsigned char * const restrict in, const size_t in_length, const base64_charset charset, const int pad) {
	size_t i;
	size_t out_pos = 0;
	uint_fast32_t v;
	const char* const base64_table = (charset)
	  ? base64_url_table             /* BASE64_URL */
	  : base64_standard_table;       /* BASE64_STANDARD */
	const char padchar = base64_table[64]; /* padding char */

	/* check overflows */
	/* 1073741823 is max num full_tuples to avoid overflow in uint32_t;
	 * and (1 GB - 1) is ridiculously large for base64-encoded data */
	force_assert(in_length <= 3221225469); /* (3221225469+2) / 3 * 4 < UINT32_MAX */
	force_assert((in_length+2)/3*4 <= out_length);

	for (i = 2; i < in_length; i += 3) {
		v = (in[i-2] << 16) | (in[i-1] << 8) | in[i];
		out[out_pos+0] = base64_table[(v >> 18) & 0x3f];
		out[out_pos+1] = base64_table[(v >> 12) & 0x3f];
		out[out_pos+2] = base64_table[(v >>  6) & 0x3f];
		out[out_pos+3] = base64_table[(v      ) & 0x3f];
		out_pos += 4;
	}

	switch (in_length - (i-2)) {
	case 0:
	default:
		break;
	case 1:
		{
			/* pretend in[i-1] = in[i] = 0, don't write last two (out_pos+3, out_pos+2) characters */
			v = (in[i-2] << 4);
			out[out_pos+0] = base64_table[(v >> 6) & 0x3f];
			out[out_pos+1] = base64_table[(v     ) & 0x3f];
			if (pad) {
				out[out_pos+2] = out[out_pos+3] = padchar;
				out_pos += 4;
			}
			else
				out_pos += 2;
		}
		break;
	case 2:
		{
			/* pretend in[i] = 0, don't write last (out_pos+3) character */
			v = (in[i-2] << 10) | (in[i-1] << 2);
			out[out_pos+0] = base64_table[(v >> 12) & 0x3f];
			out[out_pos+1] = base64_table[(v >>  6) & 0x3f];
			out[out_pos+2] = base64_table[(v      ) & 0x3f];
			if (pad) {
				out[out_pos+3] = padchar;
				out_pos += 4;
			}
			else
				out_pos += 3;
		}
		break;
	}

	return out_pos;
}


char* buffer_append_base64_enc(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset, int pad) {
    const size_t reserve = (in_length+2)/3*4;
    char * const result = buffer_string_prepare_append(out, reserve);
    const size_t out_pos =
      li_base64_enc(result, reserve, in, in_length, charset, pad);

    buffer_commit(out, out_pos);

    return result;
}


unsigned char* buffer_append_base64_decode(buffer *out, const char* in, size_t in_length, base64_charset charset) {
    const size_t reserve = 3*(in_length/4) + 3;
    unsigned char * const result = (unsigned char *)
      buffer_string_prepare_append(out, reserve);
    const size_t out_pos =
      li_base64_dec(result, reserve, in, in_length, charset);

    buffer_commit(out, out_pos);

    return (out_pos || !in_length) ? result : NULL;
}
