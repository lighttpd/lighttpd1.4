#ifndef _CONFIG_PARSER_H_
#define _CONFIG_PARSER_H_
#include "first.h"

#include "base_decls.h"
#include "plugin_config.h"
#include "array.h"
#include "buffer.h"
#include "vector.h"

/* $HTTP["host"] ==    "incremental.home.kneschke.de" { ... }
 * for print:   comp_key      op    string
 * for compare: comp          cond  string/regex
 */

#ifdef HAVE_PCRE2_H
struct pcre2_real_match_data_8; /* declaration */
#elif defined(HAVE_PCRE_H)
struct pcre_extra;      /* declaration */
#endif

typedef struct data_config data_config;
DEFINE_TYPED_VECTOR_NO_RELEASE(config_weak, data_config*);

struct data_config {
	DATA_UNSET;
	int context_ndx; /* more or less like an id */
	comp_key_t comp;
	config_cond_t cond;

	/* nested */
	data_config *parent;
	/* for chaining only */
	data_config *prev;
	data_config *next;

	buffer string;
  #ifdef HAVE_PCRE2_H
	void *code;
	struct pcre2_real_match_data_8 *match_data;
  #elif defined(HAVE_PCRE_H)
	void *regex;
	struct pcre_extra *regex_study;
	int ovec_nelts;
  #endif
	int capture_idx;
	int ext;
	buffer comp_tag;
	const char *comp_key;

	vector_config_weak children;
	array *value;
};

__attribute_cold__
__attribute_returns_nonnull__
data_config *data_config_init(void);

__attribute_cold__
int data_config_pcre_compile(data_config *dc, int pcre_jit, log_error_st *errh);
/*struct cond_cache_t;*/    /* declaration */ /*(moved to plugin_config.h)*/
/*int data_config_pcre_exec(const data_config *dc, struct cond_cache_t *cache, buffer *b);*/

typedef struct {
	server *srv;
	int     ok;
	array  *all_configs;
	vector_config_weak configs_stack; /* to parse nested block */
	data_config *current; /* current started with { */
	buffer *basedir;
} config_t;

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

__attribute_cold__
int config_remoteip_normalize(buffer *b, buffer *tb);

#endif
