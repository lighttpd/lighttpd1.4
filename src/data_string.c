#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "array.h"

static void data_string_free(data_unset *d) {
	data_string *ds = (data_string *)d;
	
	buffer_free(ds->key);
	buffer_free(ds->value);
	
	free(d);
}

static void data_string_reset(data_unset *d) {
	data_string *ds = (data_string *)d;
	
	/* reused array elements */
	buffer_reset(ds->key);
	buffer_reset(ds->value);
}

static int data_string_insert_dup(data_unset *dst, data_unset *src) {
	data_string *ds_dst = (data_string *)dst;
	data_string *ds_src = (data_string *)src;
	
	if (ds_dst->value->used) {
		buffer_append_string(ds_dst->value, ", ");
		buffer_append_string_buffer(ds_dst->value, ds_src->value);
	} else {
		buffer_copy_string_buffer(ds_dst->value, ds_src->value);
	}
	
	src->free(src);
	
	return 0;
}

static int data_response_insert_dup(data_unset *dst, data_unset *src) {
	data_string *ds_dst = (data_string *)dst;
	data_string *ds_src = (data_string *)src;
	
	if (ds_dst->value->used) {
		buffer_append_string(ds_dst->value, "\r\n");
		buffer_append_string_buffer(ds_dst->value, ds_dst->key);
		buffer_append_string(ds_dst->value, ": ");
		buffer_append_string_buffer(ds_dst->value, ds_src->value);
	} else {
		buffer_copy_string_buffer(ds_dst->value, ds_src->value);
	}
	
	src->free(src);
	
	return 0;
}


static void data_string_print(data_unset *d) {
	data_string *ds = (data_string *)d;
	
	fprintf(stderr, "{%s: %s}", ds->key->ptr, ds->value->used ? ds->value->ptr : "");
}


data_string *data_string_init(void) {
	data_string *ds;
	
	ds = calloc(1, sizeof(*ds));
	assert(ds);
	
	ds->key = buffer_init();
	ds->value = buffer_init();
	
	ds->free = data_string_free;
	ds->reset = data_string_reset;
	ds->insert_dup = data_string_insert_dup;
	ds->print = data_string_print;
	ds->type = TYPE_STRING;
	
	return ds;
}

data_string *data_response_init(void) {
	data_string *ds;
	
	ds = data_string_init();
	ds->insert_dup = data_response_insert_dup;
	
	return ds;
}
