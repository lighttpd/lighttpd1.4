#ifndef _BASE64_H_
#define _BASE64_H_
#include "first.h"

#include "buffer.h"

typedef enum {
	BASE64_STANDARD,
	BASE64_URL,
} base64_charset;

size_t li_base64_dec(unsigned char *result, size_t out_length, const char *in, size_t in_length, base64_charset charset);

unsigned char* buffer_append_base64_decode(buffer *out, const char* in, size_t in_length, base64_charset charset);

size_t li_base64_enc(char* restrict out, size_t out_length, const unsigned char* restrict in, size_t in_length, base64_charset charset, int pad);
#define li_to_base64_no_padding(out, out_length, in, in_length, charset) \
        li_base64_enc((out), (out_length), (in), (in_length), (charset), 0)
#define li_to_base64(out, out_length, in, in_length, charset) \
        li_base64_enc((out), (out_length), (in), (in_length), (charset), 1)

__attribute_nonnull__()
__attribute_returns_nonnull__
char* buffer_append_base64_enc(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset, int pad);

#define buffer_append_base64_encode_no_padding(out, in, in_length, charset) \
        buffer_append_base64_enc((out), (in), (in_length), (charset), 0)
#define buffer_append_base64_encode(out, in, in_length, charset) \
        buffer_append_base64_enc((out), (in), (in_length), (charset), 1)

#endif
