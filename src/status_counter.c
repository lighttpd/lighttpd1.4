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
	return array_get_int_ptr(srv->status, s, len);
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

