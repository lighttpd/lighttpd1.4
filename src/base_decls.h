#ifndef INCLUDED_BASE_DECLS_H
#define INCLUDED_BASE_DECLS_H

#include "first.h"

struct server;
typedef struct server server;

struct connection;
typedef struct connection connection;

struct h2con;
typedef struct h2con h2con;

struct plugin;
typedef struct plugin plugin;

struct request_st;
typedef struct request_st request_st;

union sock_addr;
typedef union sock_addr sock_addr;

struct fdnode_st;
typedef struct fdnode_st fdnode;

struct fdlog_st;
typedef struct fdlog_st fdlog_st;
typedef struct fdlog_st log_error_st;

enum handler_t {
  HANDLER_GO_ON,
  HANDLER_FINISHED,
  HANDLER_COMEBACK,
  HANDLER_WAIT_FOR_EVENT,
  HANDLER_ERROR
};
typedef enum handler_t handler_t;

#define BV(x) (1 << x)


#endif
