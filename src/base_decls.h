#ifndef INCLUDED_BASE_DECLS_H
#define INCLUDED_BASE_DECLS_H

#include "first.h"

struct server;
typedef struct server server;

struct connection;
typedef struct connection connection;

union sock_addr;
typedef union sock_addr sock_addr;

struct fdnode_st;
typedef struct fdnode_st fdnode;

struct log_error_st;
typedef struct log_error_st log_error_st;

enum handler_t {
  HANDLER_UNSET,
  HANDLER_GO_ON,
  HANDLER_FINISHED,
  HANDLER_COMEBACK,
  HANDLER_WAIT_FOR_EVENT,
  HANDLER_ERROR,
  HANDLER_WAIT_FOR_FD
};
typedef enum handler_t handler_t;

#define BV(x) (1 << x)


#endif
