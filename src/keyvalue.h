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
	struct pcre_keyvalue **kv;
	size_t used;
	size_t size;
} pcre_keyvalue_buffer;

pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void);
int pcre_keyvalue_buffer_append(struct server *srv, pcre_keyvalue_buffer *kvb, buffer *key, buffer *value);
void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb);
handler_t pcre_keyvalue_buffer_process(pcre_keyvalue_buffer *kvb, pcre_keyvalue_ctx *ctx, buffer *input, buffer *result);
void pcre_keyvalue_burl_normalize_key(buffer *k, buffer *t);
void pcre_keyvalue_burl_normalize_value(buffer *v, buffer *t);

#endif
