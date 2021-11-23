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
	const char *comp_key;
} config_cond_info;

__attribute_cold__
void config_get_config_cond_info(config_cond_info *cfginfo, uint32_t idx);

__attribute_cold__
int config_capture(server *srv, int idx);

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

__attribute_cold__
int config_log_error_open(server *srv);

__attribute_cold__
void config_log_error_close(server *srv);

void config_reset_config_bytes_sec(void *p);

/*void config_reset_config(request_st *r);*//* moved to request_config_reset()*/
void config_patch_config(request_st *r);

void config_cond_cache_reset(request_st *r);
void config_cond_cache_reset_item(request_st *r, comp_key_t item);

typedef enum { T_CONFIG_UNSET,
		T_CONFIG_STRING,
		T_CONFIG_SHORT,
		T_CONFIG_INT,
		T_CONFIG_BOOL,
		T_CONFIG_ARRAY,
		T_CONFIG_ARRAY_KVANY,
		T_CONFIG_ARRAY_KVARRAY,
		T_CONFIG_ARRAY_KVSTRING,
		T_CONFIG_ARRAY_VLIST,
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
    uint8_t klen;    /* directives must be <= 255 chars */
    /*uint8_t k_id;*//*(array index is used for k_id)*/
    uint8_t ktype;   /* config_values_type_t */
    uint8_t scope;   /* config_scope_type_t */
} config_plugin_keys_t;

__attribute_cold__
__attribute_pure__
int config_plugin_value_tobool(const data_unset *du, int default_value);

__attribute_cold__
__attribute_pure__
int32_t config_plugin_value_to_int32 (const data_unset *du, int32_t default_value);

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
} cond_cache_t; /* 2 bytes (2^1) */

#ifdef HAVE_PCRE2_H
struct pcre2_real_match_data_8; /* declaration */
#endif

typedef struct cond_match_t {
    const buffer *comp_value; /* just a pointer */
 #ifdef HAVE_PCRE2_H
    struct pcre2_real_match_data_8 *match_data;
 #endif
    int captures;
    void *matches; /* pcre2:(PCRE2_SIZE *), pcre:(int *) */
} cond_match_t;

int config_check_cond(request_st *r, int context_ndx);

__attribute_cold__
__attribute_pure__
int config_feature_bool (const server *srv, const char *feature, int default_value);

__attribute_cold__
__attribute_pure__
int32_t config_feature_int (const server *srv, const char *feature, int32_t default_value);

#endif
