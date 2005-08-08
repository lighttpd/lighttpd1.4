#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <errno.h>
#include <assert.h>

#include "array.h"
#include "buffer.h"

array *array_init(void) {
	array *a;
	
	a = calloc(1, sizeof(*a));
	assert(a);
	
	a->next_power_of_2 = 1;
	
	return a;
}

void array_free(array *a) {
	size_t i;
	if (!a) return;
	
	for (i = 0; i < a->size; i++) {
		if (a->data[i]) a->data[i]->free(a->data[i]);
	}
	
	if (a->data) free(a->data);
	if (a->sorted) free(a->sorted);
	
	free(a);
}

void array_reset(array *a) {
	size_t i;
	if (!a) return;
	
	for (i = 0; i < a->used; i++) {
		a->data[i]->reset(a->data[i]);
	}
	
	a->used = 0;
}

data_unset *array_pop(array *a) {
	data_unset *du;

	assert(a->used != 0);

	a->used --;
	du = a->data[a->used];
	a->data[a->used] = NULL;

	return du;
}

static int array_get_index(array *a, const char *key, size_t keylen, int *rndx) {
	int ndx = -1;
	int i, pos = 0;
	
	if (key == NULL) return -1;
	
	/* try to find the string */
	for (i = pos = a->next_power_of_2 / 2; ; i >>= 1) {
		int cmp;
		
		if (pos < 0) {
			pos += i;
		} else if (pos >= (int)a->used) {
			pos -= i;
		} else {
			cmp = buffer_caseless_compare(key, keylen, a->data[a->sorted[pos]]->key->ptr, a->data[a->sorted[pos]]->key->used);
			
			if (cmp == 0) {
				/* found */
				ndx = a->sorted[pos];
				break;
			} else if (cmp < 0) {
				pos -= i;
			} else {
				pos += i;
			}
		}
		if (i == 0) break;
	}
	
	if (rndx) *rndx = pos;
	
	return ndx;
}

data_unset *array_get_element(array *a, const char *key) {
	int ndx;
	
	if (-1 != (ndx = array_get_index(a, key, strlen(key) + 1, NULL))) {
		/* found, leave here */
		
		return a->data[ndx];
	} 
	
	return NULL;
}

data_unset *array_get_unused_element(array *a, data_type_t t) {
	data_unset *ds = NULL;
	
	UNUSED(t);

	if (a->size == 0) return NULL;
	
	if (a->used == a->size) return NULL;

	if (a->data[a->used]) {
		ds = a->data[a->used];
		
		a->data[a->used] = NULL;
	}
	
	return ds;
}

int array_insert_unique(array *a, data_unset *str) {
	int ndx = -1;
	int pos = 0;
	size_t j;
	
	/* generate unique index if neccesary */
	if (str->key->used == 0) {
		buffer_copy_long(str->key, a->unique_ndx++);
	}
	
	/* try to find the string */
	
	if (-1 != (ndx = array_get_index(a, str->key->ptr, str->key->used, &pos))) {
		/* found, leave here */
		if (a->data[ndx]->type == str->type) {
			str->insert_dup(a->data[ndx], str);
		} else {
			fprintf(stderr, "a\n");
		}
		return 0;
	}
	
	/* insert */
	
	if (a->used+1 > INT_MAX) {
		/* we can't handle more then INT_MAX entries: see array_get_index() */
		return -1;
	}
	
	if (a->size == 0) {
		a->size   = 16;
		a->data   = malloc(sizeof(*a->data)     * a->size);
		a->sorted = malloc(sizeof(*a->sorted)   * a->size);
		assert(a->data);
		assert(a->sorted);
		for (j = a->used; j < a->size; j++) a->data[j] = NULL;
	} else if (a->size == a->used) {
		a->size  += 16;
		a->data   = realloc(a->data,   sizeof(*a->data)   * a->size);
		a->sorted = realloc(a->sorted, sizeof(*a->sorted) * a->size);
		assert(a->data);
		assert(a->sorted);
		for (j = a->used; j < a->size; j++) a->data[j] = NULL;
	}
	
	ndx = (int) a->used;
	
	a->data[a->used++] = str;
	
	if (pos != ndx &&
	    ((pos < 0) || 
	     buffer_caseless_compare(str->key->ptr, str->key->used, a->data[a->sorted[pos]]->key->ptr, a->data[a->sorted[pos]]->key->used) > 0)) {
		pos++;
	} 
	
	/* move everything on step to the right */
	if (pos != ndx) {
		memmove(a->sorted + (pos + 1), a->sorted + (pos), (ndx - pos) * sizeof(*a->sorted));
	}
	
	/* insert */
	a->sorted[pos] = ndx;
	
	if (a->next_power_of_2 == (size_t)ndx) a->next_power_of_2 <<= 1;
	
	return 0;
}

void array_print_indent(int depth) {
	int i;
	for (i = 0; i < depth; i ++) {
		fprintf(stderr, "  ");
	}
}

int array_print(array *a, int depth) {
	size_t i;
	
	for (i = 0; i < a->used; i++) {
		array_print_indent(depth);
		fprintf(stderr, "%d: ", i);
		a->data[i]->print(a->data[i], depth + 1);
		fprintf(stderr, "\n");
	}
	
	return 0;
}

#ifdef DEBUG_ARRAY
int main (int argc, char **argv) {
	array *a;
	data_string *ds;
	data_count *dc;
	
	UNUSED(argc);
	UNUSED(argv);

	a = array_init();
	
	ds = data_string_init();
	buffer_copy_string(ds->key, "abc");
	buffer_copy_string(ds->value, "alfrag");
	
	array_insert_unique(a, (data_unset *)ds);
	
	ds = data_string_init();
	buffer_copy_string(ds->key, "abc");
	buffer_copy_string(ds->value, "hameplman");
	
	array_insert_unique(a, (data_unset *)ds);
	
	ds = data_string_init();
	buffer_copy_string(ds->key, "123");
	buffer_copy_string(ds->value, "alfrag");
	
	array_insert_unique(a, (data_unset *)ds);
	
	dc = data_count_init();
	buffer_copy_string(dc->key, "def");
	
	array_insert_unique(a, (data_unset *)dc);
	
	dc = data_count_init();
	buffer_copy_string(dc->key, "def");
	
	array_insert_unique(a, (data_unset *)dc);
	
	array_print(a, 0);
	
	array_free(a);
	
	fprintf(stderr, "%d\n",
	       buffer_caseless_compare(CONST_STR_LEN("Content-Type"), CONST_STR_LEN("Content-type")));
	
	return 0;
}
#endif
