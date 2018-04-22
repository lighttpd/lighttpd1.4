#include "first.h"

#include "keyvalue.h"
#include "base.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

typedef struct pcre_keyvalue {
#ifdef HAVE_PCRE_H
	pcre *key;
	pcre_extra *key_extra;
#endif
	buffer *value;
} pcre_keyvalue;

pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void) {
	pcre_keyvalue_buffer *kvb;

	kvb = calloc(1, sizeof(*kvb));
	force_assert(NULL != kvb);

	return kvb;
}

int pcre_keyvalue_buffer_append(server *srv, pcre_keyvalue_buffer *kvb, buffer *key, buffer *value) {
#ifdef HAVE_PCRE_H
	size_t i;
	const char *errptr;
	int erroff;
	pcre_keyvalue *kv;

	if (!key) return -1;

	if (kvb->size == 0) {
		kvb->size = 4;
		kvb->used = 0;

		kvb->kv = malloc(kvb->size * sizeof(*kvb->kv));
		force_assert(NULL != kvb->kv);

		for(i = 0; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
			force_assert(NULL != kvb->kv[i]);
		}
	} else if (kvb->used == kvb->size) {
		kvb->size += 4;

		kvb->kv = realloc(kvb->kv, kvb->size * sizeof(*kvb->kv));
		force_assert(NULL != kvb->kv);

		for(i = kvb->used; i < kvb->size; i++) {
			kvb->kv[i] = calloc(1, sizeof(**kvb->kv));
			force_assert(NULL != kvb->kv[i]);
		}
	}

	kv = kvb->kv[kvb->used];
	if (NULL == (kv->key = pcre_compile(key->ptr,
					  0, &errptr, &erroff, NULL))) {

		log_error_write(srv, __FILE__, __LINE__, "SS",
			"rexexp compilation error at ", errptr);
		return -1;
	}

	if (NULL == (kv->key_extra = pcre_study(kv->key, 0, &errptr)) &&
			errptr != NULL) {
		return -1;
	}

	kv->value = buffer_init_buffer(value);

	kvb->used++;

#else
	static int logged_message = 0;
	if (logged_message) return 0;
	logged_message = 1;
	log_error_write(srv, __FILE__, __LINE__, "s",
			"pcre support is missing, please install libpcre and the headers");
	UNUSED(kvb);
	UNUSED(key);
	UNUSED(value);
#endif

	return 0;
}

void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb) {
#ifdef HAVE_PCRE_H
	size_t i;
	pcre_keyvalue *kv;

	for (i = 0; i < kvb->size; i++) {
		kv = kvb->kv[i];
		if (kv->key) pcre_free(kv->key);
		if (kv->key_extra) pcre_free(kv->key_extra);
		if (kv->value) buffer_free(kv->value);
		free(kv);
	}

	if (kvb->kv) free(kvb->kv);
#endif

	free(kvb);
}

#ifdef HAVE_PCRE_H
static void pcre_keyvalue_buffer_subst(buffer *b, const buffer *patternb, const char **list, int n, pcre_keyvalue_ctx *ctx) {
	const char *pattern = patternb->ptr;
	const size_t pattern_len = buffer_string_length(patternb);
	size_t start = 0;

	/* search for $... or %... pattern substitutions */

	buffer_reset(b);

	for (size_t k = 0; k + 1 < pattern_len; ++k) {
		if (pattern[k] == '$' || pattern[k] == '%') {
			size_t num = pattern[k + 1] - '0';

			buffer_append_string_len(b, pattern + start, k - start);

			if (!light_isdigit((unsigned char)pattern[k + 1])) {
				/* enable escape: "%%" => "%", "%a" => "%a", "$$" => "$" */
				buffer_append_string_len(b, pattern+k, pattern[k] == pattern[k+1] ? 1 : 2);
			} else if (pattern[k] == '$') {
				/* n is always > 0 */
				if (num < (size_t)n) {
					buffer_append_string(b, list[num]);
				}
			} else if (ctx->cache) {
				const struct cond_cache_t * const cache = ctx->cache;
				if (num < (size_t)cache->patterncount) {
					num <<= 1; /* n *= 2 */
					buffer_append_string_len(b,
						cache->comp_value->ptr + cache->matches[num],
						cache->matches[num + 1] - cache->matches[num]);
				}
			} else {
			      #if 0
				/* we have no context, we are global */
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"used a redirect/rewrite containing a %[0-9]+ in the global scope, ignored:",
						pattern);
			      #endif
			}

			k++;
			start = k + 1;
		}
	}

	buffer_append_string_len(b, pattern + start, pattern_len - start);
}

handler_t pcre_keyvalue_buffer_process(pcre_keyvalue_buffer *kvb, pcre_keyvalue_ctx *ctx, buffer *input, buffer *result) {
    for (int i = 0, used = (int)kvb->used; i < used; ++i) {
        pcre_keyvalue * const kv = kvb->kv[i];
        #define N 10
        int ovec[N * 3];
        #undef N
        int n = pcre_exec(kv->key, kv->key_extra, CONST_BUF_LEN(input),
                          0, 0, ovec, sizeof(ovec)/sizeof(int));
        if (n < 0) {
            if (n != PCRE_ERROR_NOMATCH) {
                return HANDLER_ERROR;
            }
        }
        else if (buffer_string_is_empty(kv->value)) {
            /* short-circuit if blank replacement pattern
             * (do not attempt to match against remaining kvb rules) */
            ctx->m = i;
            return HANDLER_GO_ON;
        }
        else { /* it matched */
            const char **list;
            ctx->m = i;
            pcre_get_substring_list(input->ptr, ovec, n, &list);
            pcre_keyvalue_buffer_subst(result, kv->value, list, n, ctx);
            pcre_free(list);
            return HANDLER_FINISHED;
        }
    }

    return HANDLER_GO_ON;
}
#else
handler_t pcre_keyvalue_buffer_process(pcre_keyvalue_buffer *kvb, pcre_keyvalue_ctx *ctx, buffer *input, buffer *result) {
    UNUSED(kvb);
    UNUSED(ctx);
    UNUSED(input);
    UNUSED(result);
    return HANDLER_GO_ON;
}
#endif
