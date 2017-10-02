#include "first.h"

#include "base64.h"

static const base64_charset encs[] = { BASE64_STANDARD, BASE64_URL };
static buffer *check;

inline
static void check_base64 (char *out, const size_t out_sz, const char *in, const size_t in_len, const base64_charset enc) {
	force_assert(out_sz == li_to_base64_no_padding(out, out_sz, (const unsigned char *)in, in_len, enc));

	buffer_reset(check);
	force_assert(NULL != buffer_append_base64_decode(check, out, out_sz, enc));
	force_assert(buffer_is_equal_string(check, in, in_len));
}

static void check_all_len_0 (const base64_charset enc) {
	check_base64(NULL, 0, "", 0, enc);
}

static void check_all_len_1 (const base64_charset enc) {
	unsigned int c1;
	for (c1 = 0; c1 < 256; ++c1) {
			unsigned char in[] = { c1 };
			char out[2] = { 0, 0 };
			check_base64(out, sizeof(out), (char *)in, sizeof(in), enc);
	}
}

static void check_all_len_2 (const base64_charset enc) {
	unsigned int c1, c2;
	for (c1 = 0; c1 < 256; ++c1) for (c2 = 0; c2 < 256; ++c2) {
			unsigned char in[] = { c1, c2 };
			char out[3] = { 0, 0, 0 };
			check_base64(out, sizeof(out), (char *)in, sizeof(in), enc);
	}
}

static void check_all_len_3 (const base64_charset enc) {
	unsigned int c1, c2, c3;
	for (c1 = 0; c1 < 256; ++c1) for (c2 = 0; c2 < 256; ++c2) for (c3 = 0; c3 < 256; ++c3) {
			unsigned char in[] = { c1, c2, c3 };
			char out[4] = { 0, 0, 0, 0 };
			check_base64(out, sizeof(out), (char *)in, sizeof(in), enc);
	}
}

int main() {
	check = buffer_init();

	for (unsigned int enc = 0; enc < sizeof(encs)/sizeof(*encs); ++enc) {
		check_all_len_0(encs[enc]);
		check_all_len_1(encs[enc]);
		check_all_len_2(encs[enc]);
		check_all_len_3(encs[enc]);
	}

	buffer_free(check);
	return 0;
}
