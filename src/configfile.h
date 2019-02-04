#ifndef _CONFIG_PARSER_H_
#define _CONFIG_PARSER_H_
#include "first.h"

#include "base_decls.h"
#include "array.h"
#include "buffer.h"
#include "vector.h"

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

/* $HTTP["host"] ==    "incremental.home.kneschke.de" { ... }
 * for print:   comp_key      op    string
 * for compare: comp          cond  string/regex
 */

#ifdef HAVE_PCRE_H
struct pcre_extra;      /* declaration */
#endif

typedef struct data_config data_config;
DEFINE_TYPED_VECTOR_NO_RELEASE(config_weak, data_config*);

struct data_config {
	DATA_UNSET;

	array *value;

	buffer *comp_tag;
	buffer *comp_key;
	comp_key_t comp;

	config_cond_t cond;
	buffer *op;

	int context_ndx; /* more or less like an id */
	vector_config_weak children;
	/* nested */
	data_config *parent;
	/* for chaining only */
	data_config *prev;
	data_config *next;

	buffer *string;
#ifdef HAVE_PCRE_H
	void *regex;
	struct pcre_extra *regex_study;
#endif
};

struct cond_cache_t;    /* declaration */

__attribute_cold__
data_config *data_config_init(void);

__attribute_cold__
int data_config_pcre_compile(data_config *dc);

int data_config_pcre_exec(data_config *dc, struct cond_cache_t *cache, buffer *b);

typedef struct {
	server *srv;
	int     ok;
	array  *all_configs;
	vector_config_weak configs_stack; /* to parse nested block */
	data_config *current; /* current started with { */
	buffer *basedir;
} config_t;

__attribute_cold__
int config_read(server *srv, const char *fn);

__attribute_cold__
int config_set_defaults(server *srv);

__attribute_cold__
void *configparserAlloc(void *(*mallocProc)(size_t));

__attribute_cold__
void configparserFree(void *p, void (*freeProc)(void*));

__attribute_cold__
void configparser(void *yyp, int yymajor, buffer *yyminor, config_t *ctx);

__attribute_cold__
int config_parse_file(server *srv, config_t *context, const char *fn);

__attribute_cold__
int config_parse_cmd(server *srv, config_t *context, const char *cmd);

int config_setup_connection(server *srv, connection *con);
int config_patch_connection(server *srv, connection *con);

void config_cond_cache_reset(server *srv, connection *con);
void config_cond_cache_reset_item(server *srv, connection *con, comp_key_t item);

typedef enum { T_CONFIG_UNSET,
		T_CONFIG_STRING,
		T_CONFIG_SHORT,
		T_CONFIG_INT,
		T_CONFIG_BOOLEAN,
		T_CONFIG_ARRAY,
		T_CONFIG_LOCAL,
		T_CONFIG_DEPRECATED,
		T_CONFIG_UNSUPPORTED
} config_values_type_t;

typedef enum { T_CONFIG_SCOPE_UNSET,
		T_CONFIG_SCOPE_SERVER,
		T_CONFIG_SCOPE_CONNECTION
} config_scope_type_t;

typedef struct {
	const char *key;
	void *destination;

	config_values_type_t type;
	config_scope_type_t scope;
} config_values_t;

__attribute_cold__
int config_insert_values_global(server *srv, array *ca, const config_values_t *cv, config_scope_type_t scope);

__attribute_cold__
int config_insert_values_internal(server *srv, array *ca, const config_values_t *cv, config_scope_type_t scope);

int config_check_cond(server *srv, connection *con, data_config *dc);

#endif
