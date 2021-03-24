#ifndef _MOD_SSI_H_
#define _MOD_SSI_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"
#include "array.h"
#include "chunk.h"

#include "plugin.h"

typedef struct {
	const array *ssi_extension;
	const buffer *content_type;
	unsigned short conditional_requests;
	unsigned short ssi_exec;
	unsigned short ssi_recursion_max;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	plugin_config conf;
	array *ssi_vars;
	array *ssi_cgi_env;
	buffer stat_fn;
	buffer timefmt;
} plugin_data;

typedef struct {
	array *ssi_vars;
	array *ssi_cgi_env;
	buffer *stat_fn;
	buffer *timefmt;
	int sizefmt;

	int if_level, if_is_false_level, if_is_false, if_is_false_endif;
	unsigned short ssi_recursion_depth;

	chunkqueue wq;
	log_error_st *errh;
	plugin_config conf;
} handler_ctx;

int ssi_eval_expr(handler_ctx *p, const char *expr);

#endif
