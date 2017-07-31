#ifndef _STATUS_COUNTER_H_
#define _STATUS_COUNTER_H_
#include "first.h"

#include <sys/types.h>

#include "base_decls.h"
#include "array.h"

data_integer *status_counter_get_counter(server *srv, const char *s, size_t len);
int status_counter_inc(server *srv, const char *s, size_t len);
int status_counter_dec(server *srv, const char *s, size_t len);
int status_counter_set(server *srv, const char *s, size_t len, int val);

#endif
