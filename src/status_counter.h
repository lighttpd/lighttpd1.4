#ifndef _STATUS_COUNTER_H_
#define _STATUS_COUNTER_H_
#include "first.h"

#include "base_decls.h"

__attribute_returns_nonnull__
static inline
int *status_counter_get_counter(const char *s, size_t len);
static inline
void status_counter_inc(const char *s, size_t len);
static inline
void status_counter_dec(const char *s, size_t len);
static inline
void status_counter_set(const char *s, size_t len, int val);

/* inline status counter routines */

#include "array.h"
#include "plugin.h"

static inline
int *status_counter_get_counter(const char *s, size_t len) {
    return array_get_int_ptr(&plugin_stats, s, len);
}

static inline
void status_counter_inc(const char *s, size_t len) {
    ++(*array_get_int_ptr(&plugin_stats, s, len));
}

static inline
void status_counter_dec(const char *s, size_t len) {
    --(*array_get_int_ptr(&plugin_stats, s, len));
}

static inline
void status_counter_set(const char *s, size_t len, int val) {
    *array_get_int_ptr(&plugin_stats, s, len) = val;
}


#endif
