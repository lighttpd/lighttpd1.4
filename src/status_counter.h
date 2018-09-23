#ifndef _STATUS_COUNTER_H_
#define _STATUS_COUNTER_H_
#include "first.h"

#include "base_decls.h"

static inline
int *status_counter_get_counter(server *srv, const char *s, size_t len);
static inline
void status_counter_inc(server *srv, const char *s, size_t len);
static inline
void status_counter_dec(server *srv, const char *s, size_t len);
static inline
void status_counter_set(server *srv, const char *s, size_t len, int val);

/* inline status counter routines */

#include "base.h"       /* (srv->status) */
#include "array.h"

static inline
int *status_counter_get_counter(server *srv, const char *s, size_t len) {
    return array_get_int_ptr(srv->status, s, len);
}

static inline
void status_counter_inc(server *srv, const char *s, size_t len) {
    ++(*array_get_int_ptr(srv->status, s, len));
}

static inline
void status_counter_dec(server *srv, const char *s, size_t len) {
    --(*array_get_int_ptr(srv->status, s, len));
}

static inline
void status_counter_set(server *srv, const char *s, size_t len, int val) {
    *array_get_int_ptr(srv->status, s, len) = val;
}


#endif
