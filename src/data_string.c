#include "first.h"

#include "array.h"
#include "buffer.h"

#include <stdlib.h>

__attribute_cold__
static data_unset *data_string_copy(const data_unset *s) {
	data_string *src = (data_string *)s;
	data_string *ds = data_string_init();

	if (!buffer_is_empty(&src->key)) buffer_copy_buffer(&ds->key, &src->key);
	buffer_copy_buffer(&ds->value, &src->value);
	return (data_unset *)ds;
}

static void data_string_free(data_unset *d) {
	data_string *ds = (data_string *)d;

	free(ds->key.ptr);
	free(ds->value.ptr);

	free(d);
}

__attribute_cold__
static int data_string_insert_dup(data_unset *dst, data_unset *src) {
	data_string *ds_dst = (data_string *)dst;
	data_string *ds_src = (data_string *)src;

	if (!buffer_is_empty(&ds_dst->value))
		buffer_append_str2(&ds_dst->value, CONST_STR_LEN(", "),
		                                   CONST_BUF_LEN(&ds_src->value));
	else
		buffer_copy_buffer(&ds_dst->value, &ds_src->value);

	src->fn->free(src);

	return 0;
}

data_string *data_string_init(void) {
	static const struct data_methods fn = {
		data_string_copy,
		data_string_free,
		data_string_insert_dup,
	};
	data_string *ds;

	ds = calloc(1, sizeof(*ds));
	force_assert(NULL != ds);

	ds->type = TYPE_STRING;
	ds->fn = &fn;

	return ds;
}
