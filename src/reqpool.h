#ifndef LI_REQPOOL_H
#define LI_REQPOOL_H
#include "first.h"

#include "base_decls.h"

void request_init_data (request_st *r, connection *con, server *srv);
void request_reset (request_st *r);
void request_reset_ex (request_st *r);
void request_release (request_st *r);
request_st * request_acquire (connection *con);

__attribute_cold__
void request_free_data (request_st *r);

__attribute_cold__
void request_pool_init (uint32_t sz);

__attribute_cold__
void request_pool_free (void);

#endif
