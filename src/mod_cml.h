#ifndef _MOD_CACHE_H_
#define _MOD_CACHE_H_

#include "buffer.h"
#include "server.h"
#include "response.h"

#include "stream.h"

#if defined(HAVE_MEMCACHE_H)
#include <memcache.h>
#endif

#define plugin_data mod_cache_plugin_data

typedef enum { UNSET, PART, TIMES, MINUS, PLUS, OR, AND, GT, LT, GE, LE, EQ, NE } tnode_op_t;

typedef enum { T_NODE_VALUE_UNSET, T_NODE_VALUE_LONG, T_NODE_VALUE_STRING } tnode_val_t;

typedef struct {
	tnode_val_t type;
	
	union {
		buffer *str;
		long    lon;
	} data;
} tnode_val;

#define VAL_LONG(x) x->value.data.lon
#define VAL_STRING(x) x->value.data.str

#define IS_LONG(x) ((x->op == UNSET) && (x->value.type == T_NODE_VALUE_LONG))
#define IS_STRING(x) ((x->op == UNSET) && (x->value.type == T_NODE_VALUE_STRING))

typedef struct tnode {
	tnode_val value;
	tnode_op_t op;
	
	struct tnode *l, *r;
} tnode;

typedef struct  {
	tnode_val **ptr;
	
	size_t size;
	size_t used;
} tnode_val_array;

typedef struct {
	buffer *ext;
	
	array  *mc_hosts;
	buffer *mc_namespace;
#if defined(HAVE_MEMCACHE_H) 
	struct memcache *mc;
#endif
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	buffer *basedir;
	
	buffer *trigger_handler;
	
	buffer *session_id;
	
	buffer_array *eval;
	buffer_array *trigger_if;
	buffer_array *output_include;
	
	tnode_val_array *params;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

typedef struct {
	char *name;
	size_t params;
	int (*func)(server *srv, connection *con, plugin_data *p, tnode *result);
} cache_trigger_functions;

int cache_parse_parameters(server *srv, connection *con, plugin_data *p, const char *params, size_t param_len, tnode_val_array *res);
int cache_parse(server *srv, connection *con, plugin_data *p, buffer *fn);
int tnode_prepare_long(tnode *t);
int tnode_prepare_string(tnode *t);

tnode_val_array *tnode_val_array_init();
void tnode_val_array_free(tnode_val_array *tva);
void tnode_val_array_reset(tnode_val_array *tva);

#define CACHE_FUNC_PROTO(x) int x(server *srv, connection *con, plugin_data *p, tnode *result)

CACHE_FUNC_PROTO(f_unix_time_now);
CACHE_FUNC_PROTO(f_file_mtime);
CACHE_FUNC_PROTO(f_memcache_exists);
CACHE_FUNC_PROTO(f_memcache_get_string);
CACHE_FUNC_PROTO(f_memcache_get_long);

#endif
