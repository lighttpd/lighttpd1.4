#ifndef _BASE64_H_
#define _BASE64_H_
#include "first.h"

#include "buffer.h"

typedef enum {
	BASE64_STANDARD,
	BASE64_URL,
} base64_charset;

unsigned char* buffer_append_base64_decode(buffer *out, const char* in, size_t in_length, base64_charset charset);

size_t li_to_base64_no_padding(char* out, size_t out_length, const unsigned char* in, size_t in_length, base64_charset charset);
size_t li_to_base64(char* out, size_t out_length, const unsigned char* in, size_t in_length, base64_charset charset);

__attribute_nonnull__
__attribute_returns_nonnull__
char* buffer_append_base64_encode_opt(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset, int pad);

__attribute_nonnull__
__attribute_returns_nonnull__
static inline char* buffer_append_base64_encode_no_padding(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset);
static inline char* buffer_append_base64_encode_no_padding(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset) {
    return buffer_append_base64_encode_opt(out, in, in_length, charset, 0);
}

__attribute_nonnull__
__attribute_returns_nonnull__
static inline char* buffer_append_base64_encode(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset);
static inline char* buffer_append_base64_encode(buffer *out, const unsigned char* in, size_t in_length, base64_charset charset) {
    return buffer_append_base64_encode_opt(out, in, in_length, charset, 1);
}

#endif
