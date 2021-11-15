#include "first.h"

#include "base64.c"

static const base64_charset encs[] = { BASE64_STANDARD, BASE64_URL };
static buffer *check;

inline
static void check_base64 (size_t out_exp, const char *in, const size_t in_len, const base64_charset enc) {
	char out[4] = { 0, 0, 0, 0 };
	force_assert(out_exp == li_to_base64_no_padding(out, sizeof(out), (const unsigned char *)in, in_len, enc));

	buffer_clear(check);
	force_assert(NULL != buffer_append_base64_decode(check, out, out_exp, enc));
	force_assert(buffer_eq_slen(check, in, in_len));
}

static void check_all_len_0 (const base64_charset enc) {
	check_base64(0, "", 0, enc);
}

static void check_all_len_1 (const base64_charset enc) {
	unsigned int c1;
	for (c1 = 0; c1 < 256; ++c1) {
			unsigned char in[] = { c1 };
			check_base64(2, (char *)in, sizeof(in), enc);
	}
}

static void check_all_len_2 (const base64_charset enc) {
	unsigned int c1, c2;
	for (c1 = 0; c1 < 256; ++c1) for (c2 = 0; c2 < 256; ++c2) {
			unsigned char in[] = { c1, c2 };
			check_base64(3, (char *)in, sizeof(in), enc);
	}
}

static void check_all_len_3 (const base64_charset enc) {
	unsigned int c1, c2, c3;
	for (c1 = 0; c1 < 256; c1+=255) for (c2 = 0; c2 < 256; ++c2) for (c3 = 0; c3 < 256; ++c3) {
			unsigned char in[] = { c1, c2, c3 };
			check_base64(4, (char *)in, sizeof(in), enc);
	}
}

void test_base64 (void);
void test_base64 (void)
{
	check = buffer_init();

	for (unsigned int enc = 0; enc < sizeof(encs)/sizeof(*encs); ++enc) {
		check_all_len_0(encs[enc]);
		check_all_len_1(encs[enc]);
		check_all_len_2(encs[enc]);
		check_all_len_3(encs[enc]);
	}

	buffer_free(check);
}
