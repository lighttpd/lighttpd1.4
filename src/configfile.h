#ifndef _CONFIG_PARSER_H_
#define _CONFIG_PARSER_H_

#include "array.h"
#include "buffer.h"

typedef struct {
	int     ok;
	array  *config;
	buffer *ctx_name;
	array  *ctx_config;
} config_t;

void *configparserAlloc(void *(*mallocProc)(size_t));
void configparserFree(void *p, void (*freeProc)(void*));
void configparser(void *yyp, int yymajor, buffer *yyminor, config_t *ctx);

#endif
