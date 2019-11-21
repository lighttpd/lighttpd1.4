#ifndef INCLUDE_PLUGIN_CONFIG_H
#define INCLUDE_PLUGIN_CONFIG_H
#include "first.h"

#include "base_decls.h"
#include "array.h"
#include "buffer.h"

/**
 * possible compare ops in the configfile parser
 */
typedef enum {
	CONFIG_COND_UNSET,
	CONFIG_COND_EQ,      /** == */
	CONFIG_COND_MATCH,   /** =~ */
	CONFIG_COND_NE,      /** != */
	CONFIG_COND_NOMATCH, /** !~ */
	CONFIG_COND_ELSE     /** (always true if reached) */
} config_cond_t;

/**
 * possible fields to match against
 */
typedef enum {
	COMP_UNSET,
	COMP_SERVER_SOCKET,
	COMP_HTTP_URL,
	COMP_HTTP_HOST,
	COMP_HTTP_REFERER,        /*(subsumed by COMP_HTTP_REQUEST_HEADER)*/
	COMP_HTTP_USER_AGENT,     /*(subsumed by COMP_HTTP_REQUEST_HEADER)*/
	COMP_HTTP_LANGUAGE,       /*(subsumed by COMP_HTTP_REQUEST_HEADER)*/
	COMP_HTTP_COOKIE,         /*(subsumed by COMP_HTTP_REQUEST_HEADER)*/
	COMP_HTTP_REMOTE_IP,
	COMP_HTTP_QUERY_STRING,
	COMP_HTTP_SCHEME,
	COMP_HTTP_REQUEST_METHOD,
	COMP_HTTP_REQUEST_HEADER,

	COMP_LAST_ELEMENT
} comp_key_t;

typedef struct {
	comp_key_t comp;
	config_cond_t cond;
	const buffer *string;
	const buffer *comp_tag;
	const buffer *comp_key;
	const char *op;
} config_cond_info;

__attribute_cold__
void config_get_config_cond_info(server *srv, uint32_t idx, config_cond_info *cfginfo);

__attribute_cold__
void config_init(server *srv);

__attribute_cold__
void config_print(server *srv);

__attribute_cold__
int config_read(server *srv, const char *fn);

__attribute_cold__
int config_set_defaults(server *srv);

__attribute_cold__
int config_finalize(server *srv, const buffer *default_server_tag);

__attribute_cold__
void config_free(server *srv);

void config_reset_config_bytes_sec(void *p);

void config_reset_config(server *srv, connection *con);
void config_patch_config(server *srv, connection *con);

void config_cond_cache_reset(server *srv, connection *con);
void config_cond_cache_reset_item(server *srv, connection *con, comp_key_t item);

typedef enum { T_CONFIG_UNSET,
		T_CONFIG_STRING,
		T_CONFIG_SHORT,
		T_CONFIG_INT,
		T_CONFIG_BOOL,
		T_CONFIG_ARRAY,
		T_CONFIG_LOCAL,
		T_CONFIG_DEPRECATED,
		T_CONFIG_UNSUPPORTED
} config_values_type_t;

typedef enum { T_CONFIG_SCOPE_UNSET,
		T_CONFIG_SCOPE_SERVER,
		T_CONFIG_SCOPE_CONNECTION
} config_scope_type_t;

typedef struct config_plugin_value {
    int k_id;
    config_values_type_t vtype;
    union v_u {
      void *v;
      const array *a;
      const buffer *b;
      const char *s;
      unsigned int u;
      unsigned short int shrt;
      double d;
      off_t o;
      uint32_t u2[2];
    } v;
} config_plugin_value_t;

typedef struct {
    const char *k;
    uint32_t klen;
    /*uint32_t k_id;*//*(array index is used for k_id)*/
    config_values_type_t ktype;
    config_scope_type_t scope;
} config_plugin_keys_t;

__attribute_cold__
int config_plugin_values_init_block(server * const srv, const array * const ca, const config_plugin_keys_t * const cpk, const char * const mname, config_plugin_value_t *cpv);

__attribute_cold__
int config_plugin_values_init(server *srv, void *p_d, const config_plugin_keys_t *cpk, const char *mname);

typedef enum {
    /* condition not active at the moment because itself or some
     * pre-condition depends on data not available yet
     */
    COND_RESULT_UNSET,

    /* special "unset" for branches not selected due to pre-conditions
     * not met (but pre-conditions are not "unset" anymore)
     */
    COND_RESULT_SKIP,

    /* actually evaluated the condition itself */
    COND_RESULT_FALSE, /* not active */
    COND_RESULT_TRUE   /* active */
} cond_result_t;

typedef struct cond_cache_t {
    /* current result (with preconditions) */
    int8_t result;        /*(cond_result_t)*/
    /* result without preconditions (must never be "skip") */
    int8_t local_result;  /*(cond_result_t)*/
    int16_t patterncount;
} cond_cache_t; /* 8 bytes (2^3) */

typedef struct cond_match_t {
    const buffer *comp_value; /* just a pointer */
  #if !(defined(_LP64) || defined(__LP64__) || defined(_WIN64)) /*(not 64-bit)*/
    int dummy_alignment; /*(for alignment in 32-bit)*/
  #endif
    int matches[3 * 10];
} cond_match_t; /* 128 bytes (2^7) */

int config_check_cond(connection *con, int context_ndx);

#endif
