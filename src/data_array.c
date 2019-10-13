#include "first.h"

#include "array.h"

#include <string.h>
#include <stdlib.h>

__attribute_cold__
static data_unset *data_array_copy(const data_unset *s) {
	data_array *src = (data_array *)s;
	data_array *ds = data_array_init();

	if (!buffer_is_empty(&src->key)) buffer_copy_buffer(&ds->key, &src->key);
	array_copy_array(&ds->value, &src->value);
	return (data_unset *)ds;
}

static void data_array_free(data_unset *d) {
	data_array *ds = (data_array *)d;

	free(ds->key.ptr);
	array_free_data(&ds->value);

	free(d);
}

__attribute_cold__
static int data_array_insert_dup(data_unset *dst, data_unset *src) {
	UNUSED(dst);

	src->fn->free(src);

	return 0;
}

__attribute_cold__
static void data_array_print(const data_unset *d, int depth) {
	data_array *ds = (data_array *)d;

	array_print(&ds->value, depth);
}

data_array *data_array_init(void) {
	static const struct data_methods fn = {
		data_array_copy,
		data_array_free,
		data_array_insert_dup,
		data_array_print,
	};
	data_array *ds;

	ds = calloc(1, sizeof(*ds));
	force_assert(NULL != ds);

	ds->type = TYPE_ARRAY;
	ds->fn = &fn;

	return ds;
}
