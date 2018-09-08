#include "first.h"

#include "status_counter.h"
#include "base.h"

/**
 * The status array can carry all the status information you want
 * the key to the array is <module-prefix>.<name>
 * and the values are counters
 *
 * example:
 *   fastcgi.backends        = 10
 *   fastcgi.active-backends = 6
 *   fastcgi.backend.<key>.load = 24
 *   fastcgi.backend.<key>....
 *
 *   fastcgi.backend.<key>.disconnects = ...
 */

int *status_counter_get_counter(server *srv, const char *s, size_t len) {
	data_integer *di;

	if (NULL == (di = (data_integer *)array_get_element_klen(srv->status, s, len))) {
		/* not found, create it */
		di = data_integer_init();
		buffer_copy_string_len(di->key, s, len);
		di->value = 0;
		array_insert_unique(srv->status, (data_unset *)di);
	}
	return &di->value;
}

/* dummies of the statistic framework functions
 * they will be moved to a statistics.c later */
void status_counter_inc(server *srv, const char *s, size_t len) {
	++(*status_counter_get_counter(srv, s, len));
}

void status_counter_dec(server *srv, const char *s, size_t len) {
	int *i = status_counter_get_counter(srv, s, len);
	if (*i > 0) --(*i);
}

void status_counter_set(server *srv, const char *s, size_t len, int val) {
	*status_counter_get_counter(srv, s, len) = val;
}

