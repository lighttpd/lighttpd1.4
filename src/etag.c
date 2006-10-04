#include <string.h>

#include "buffer.h"
#include "etag.h"

int etag_is_equal(buffer *etag, const char *matches) {
	if (0 == strcmp(etag->ptr, matches)) return 1;
	return 0;
}

int etag_create(buffer *etag, struct stat *st) {
	buffer_copy_off_t(etag, st->st_ino);
	buffer_append_string_len(etag, CONST_STR_LEN("-"));
	buffer_append_off_t(etag, st->st_size);
	buffer_append_string_len(etag, CONST_STR_LEN("-"));
	buffer_append_long(etag, st->st_mtime);

	return 0;
}

int etag_mutate(buffer *mut, buffer *etag) {
	size_t h, i;

	for (h=0, i=0; i < etag->used; ++i) h = (h<<5)^(h>>27)^(etag->ptr[i]);

	buffer_reset(mut);
	buffer_copy_string_len(mut, CONST_STR_LEN("\""));
	buffer_append_long(mut, h);
	buffer_append_string_len(mut, CONST_STR_LEN("\""));

	return 0;
}
