#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"

static data_unset *data_config_copy(const data_unset *s) {
	data_config *src = (data_config *)s;
	data_config *ds = data_config_init();

	buffer_copy_string_buffer(ds->key, src->key);
	buffer_copy_string_buffer(ds->comp_key, src->comp_key);
	array_free(ds->value);
	ds->value = array_init_array(src->value);
	return (data_unset *)ds;
}

static void data_config_free(data_unset *d) {
	data_config *ds = (data_config *)d;
	
	buffer_free(ds->key);
	buffer_free(ds->op);
	buffer_free(ds->comp_key);
	
	array_free(ds->value);
	array_free(ds->childs);
	
	if (ds->string) buffer_free(ds->string);
#ifdef HAVE_PCRE_H
	if (ds->regex) pcre_free(ds->regex);
	if (ds->regex_study) pcre_free(ds->regex_study);
#endif
	
	free(d);
}

static void data_config_reset(data_unset *d) {
	data_config *ds = (data_config *)d;
	
	/* reused array elements */
	buffer_reset(ds->key);
	buffer_reset(ds->comp_key);
	array_reset(ds->value);
}

static int data_config_insert_dup(data_unset *dst, data_unset *src) {
	UNUSED(dst);
	
	src->free(src);
	
	return 0;
}

static void data_config_print(const data_unset *d, int depth) {
	data_config *ds = (data_config *)d;
	size_t i;
	
	if (0 == ds->context_ndx) {
		fprintf(stderr, "config {\n");
	}
	else {
		fprintf(stderr, "$%s %s \"%s\" {\n",
				ds->comp_key->ptr, ds->op->ptr, ds->string->ptr);
	}
	array_print_indent(depth + 1);
	fprintf(stderr, "context_ndx: %d\n", ds->context_ndx);
	array_print_indent(depth + 1);
	fprintf(stderr, "context: ");
	array_print(ds->value, depth + 1);
	fprintf(stderr, "\n");

	if (ds->childs) {
		for (i = 0; i < ds->childs->used; i ++) {
			data_unset *du = ds->childs->data[i];

			/* only the 1st block of chaining */
			if (NULL == ((data_config *)du)->prev) {
				fprintf(stderr, "\n");
				array_print_indent(depth + 1);
				du->print(du, depth + 1);
				fprintf(stderr, "\n");
			}
		}
	}

	array_print_indent(depth);
	fprintf(stderr, "}");

	if (ds->next) {
		fprintf(stderr, "\n");
		array_print_indent(depth);
		fprintf(stderr, "else ");
		ds->next->print((data_unset *)ds->next, depth);
	}
}

data_config *data_config_init(void) {
	data_config *ds;
	
	ds = calloc(1, sizeof(*ds));
	
	ds->key = buffer_init();
	ds->op = buffer_init();
	ds->comp_key = buffer_init();
	ds->value = array_init();
	ds->childs = array_init();
	ds->childs->is_weakref = 1;
	
	ds->copy = data_config_copy;
	ds->free = data_config_free;
	ds->reset = data_config_reset;
	ds->insert_dup = data_config_insert_dup;
	ds->print = data_config_print;
	ds->type = TYPE_CONFIG;
	
	return ds;
}
