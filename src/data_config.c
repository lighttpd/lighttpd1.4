#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"

static data_unset *data_config_copy(const data_unset *s) {
	data_config *src = (data_config *)s;
	data_config *ds = data_config_init();

	ds->key = buffer_init_buffer(src->key);
	ds->comp_key = buffer_init_buffer(src->comp_key);
	ds->value = array_init_array(src->value);
	return (data_unset *)ds;
}

static void data_config_free(data_unset *d) {
	data_config *ds = (data_config *)d;
	
	buffer_free(ds->key);
	buffer_free(ds->comp_key);
	
	array_free(ds->value);
	
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
	
	array_print_indent(depth);
	fprintf(stderr, "{%s:\n", ds->key->ptr);
	array_print(ds->value, depth + 1);
	array_print_indent(depth);
	fprintf(stderr, "}");
}


data_config *data_config_init(void) {
	data_config *ds;
	
	ds = calloc(1, sizeof(*ds));
	
	ds->key = buffer_init();
	ds->comp_key = buffer_init();
	ds->value = array_init();
	
	ds->copy = data_config_copy;
	ds->free = data_config_free;
	ds->reset = data_config_reset;
	ds->insert_dup = data_config_insert_dup;
	ds->print = data_config_print;
	ds->type = TYPE_CONFIG;
	
	return ds;
}
