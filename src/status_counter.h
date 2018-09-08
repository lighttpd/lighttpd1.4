#ifndef _STATUS_COUNTER_H_
#define _STATUS_COUNTER_H_
#include "first.h"

#include "base_decls.h"

int *status_counter_get_counter(server *srv, const char *s, size_t len);
void status_counter_inc(server *srv, const char *s, size_t len);
void status_counter_dec(server *srv, const char *s, size_t len);
void status_counter_set(server *srv, const char *s, size_t len, int val);

#endif
