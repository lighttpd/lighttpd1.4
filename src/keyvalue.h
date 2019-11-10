#ifndef _KEY_VALUE_H_
#define _KEY_VALUE_H_
#include "first.h"

#include "base_decls.h"
#include "buffer.h"

struct burl_parts_t;    /* declaration */
struct cond_cache_t;    /* declaration */
struct pcre_keyvalue;   /* declaration */

typedef struct pcre_keyvalue_ctx {
  struct cond_cache_t *cache;
  struct burl_parts_t *burl;
  int m;
} pcre_keyvalue_ctx;

typedef struct {
	struct pcre_keyvalue *kv;
	uint32_t used;
	uint16_t x0;
	uint16_t x1;
} pcre_keyvalue_buffer;

__attribute_cold__
pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void);

__attribute_cold__
int pcre_keyvalue_buffer_append(log_error_st *errh, pcre_keyvalue_buffer *kvb, const buffer *key, const buffer *value);

__attribute_cold__
void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb);

handler_t pcre_keyvalue_buffer_process(const pcre_keyvalue_buffer *kvb, pcre_keyvalue_ctx *ctx, const buffer *input, buffer *result);

__attribute_cold__
void pcre_keyvalue_burl_normalize_key(buffer *k, buffer *t);

__attribute_cold__
void pcre_keyvalue_burl_normalize_value(buffer *v, buffer *t);

#endif
