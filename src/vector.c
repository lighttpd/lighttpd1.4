#include "first.h"

#include "vector.h"

#include <stdlib.h>
#include <string.h>

static inline size_t vector_align_size(size_t s) {
	size_t a = (s + 15) & ~(size_t)15uL;
	return (a < s) ? s : a;
}

void vector_free(void *data) { free(data); }

void *vector_resize(void *data, size_t elem_size, size_t *size, size_t used, size_t x) {
	ck_assert(used < SIZE_MAX - p);
	*size = vector_align_size(used + p);
	ck_assert(*size <= SIZE_MAX / elem_size);
	const size_t total_size = elem_size * *size;
	const size_t used_size = elem_size * used;
	void *odata = data; /*(save ptr to avoid static analyzer realloc warn)*/
	data = realloc(odata, total_size);
	ck_assert(NULL != data);

	/* clear new memory */
	memset(((char*)data) + used_size, 0, total_size - used_size);

	return data;
}
