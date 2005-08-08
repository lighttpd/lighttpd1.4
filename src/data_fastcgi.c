#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"
#include "fastcgi.h"

static void data_fastcgi_free(data_unset *d) {
	data_fastcgi *ds = (data_fastcgi *)d;
	
	buffer_free(ds->key);
	buffer_free(ds->host);
	
	free(d);
}

static void data_fastcgi_reset(data_unset *d) {
	data_fastcgi *ds = (data_fastcgi *)d;
	
	buffer_reset(ds->key);
	buffer_reset(ds->host);
	
}

static int data_fastcgi_insert_dup(data_unset *dst, data_unset *src) {
	UNUSED(dst);

	src->free(src);
	
	return 0;
}

static void data_fastcgi_print(data_unset *d, int depth) {
	data_fastcgi *ds = (data_fastcgi *)d;
	
	array_print_indent(depth);
	printf("{%s: %s}", ds->key->ptr, ds->host->ptr);
}


data_fastcgi *data_fastcgi_init(void) {
	data_fastcgi *ds;
	
	ds = calloc(1, sizeof(*ds));
	
	ds->key = buffer_init();
	ds->host = buffer_init();
	ds->port = 0;
	ds->is_disabled = 0;
	
	ds->free = data_fastcgi_free;
	ds->reset = data_fastcgi_reset;
	ds->insert_dup = data_fastcgi_insert_dup;
	ds->print = data_fastcgi_print;
	ds->type = TYPE_FASTCGI;
	
	return ds;
}
