#include "first.h"

#include "keyvalue.h"
#include "base.h"
#include "burl.h"
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

	if (kvb->used == kvb->size) {
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
static void pcre_keyvalue_buffer_append_match(buffer *b, const char **list, int n, unsigned int num, int flags) {
    if (num < (unsigned int)n) { /* n is always > 0 */
        burl_append(b, list[num], strlen(list[num]), flags);
    }
}

static void pcre_keyvalue_buffer_append_ctxmatch(buffer *b, pcre_keyvalue_ctx *ctx, unsigned int num, int flags) {
    const struct cond_cache_t * const cache = ctx->cache;
    if (!cache) return; /* no enclosing match context */
    if ((int)num < cache->patterncount) {
        const int off = cache->matches[(num <<= 1)]; /*(num *= 2)*/
        const int len = cache->matches[num+1] - off;
        burl_append(b, cache->comp_value->ptr + off, (size_t)len, flags);
    }
}

static int pcre_keyvalue_buffer_subst_ext(buffer *b, const char *pattern, const char **list, int n, pcre_keyvalue_ctx *ctx) {
    const unsigned char *p = (unsigned char *)pattern+2;/* +2 past ${} or %{} */
    int flags = 0;
    while (!light_isdigit(*p) && *p != '}' && *p != '\0') {
        if (0) {
        }
        else if (p[0] == 'e' && p[1] == 's' && p[2] == 'c') {
            p+=3;
            if (p[0] == ':') {
                flags |= BURL_ENCODE_ALL;
                p+=1;
            }
            else if (0 == strncmp((const char *)p, "ape:", 4)) {
                flags |= BURL_ENCODE_ALL;
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "nde:", 4)) {
                flags |= BURL_ENCODE_NDE;
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "psnde:", 6)) {
                flags |= BURL_ENCODE_PSNDE;
                p+=6;
            }
            else { /* skip unrecognized esc... */
                p = (const unsigned char *)strchr((const char *)p, ':');
                if (NULL == p) return -1;
                ++p;
            }
        }
        else if (p[0] == 'n' && p[1] == 'o') {
            p+=2;
            if (0 == strncmp((const char *)p, "esc:", 4)) {
                flags |= BURL_ENCODE_NONE;
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "escape:", 7)) {
                flags |= BURL_ENCODE_NONE;
                p+=7;
            }
            else { /* skip unrecognized no... */
                p = (const unsigned char *)strchr((const char *)p, ':');
                if (NULL == p) return -1;
                ++p;
            }
        }
        else if (p[0] == 't' && p[1] == 'o') {
            p+=2;
            if (0 == strncmp((const char *)p, "lower:", 6)) {
                flags |= BURL_TOLOWER;
                p+=6;
            }
            else if (0 == strncmp((const char *)p, "upper:", 6)) {
                flags |= BURL_TOLOWER;
                p+=6;
            }
            else { /* skip unrecognized to... */
                p = (const unsigned char *)strchr((const char *)p, ':');
                if (NULL == p) return -1;
                ++p;
            }
        }
        else if (p[0] == 'u' && p[1] == 'r' && p[2] == 'l' && p[3] == '.') {
            p+=4;
            if (0 == strncmp((const char *)p, "scheme}", 7)) {
                burl_append(b, CONST_BUF_LEN(ctx->burl->scheme), flags);
                p+=6;
            }
            else if (0 == strncmp((const char *)p, "authority}", 10)) {
                burl_append(b, CONST_BUF_LEN(ctx->burl->authority), flags);
                p+=9;
            }
            else if (0 == strncmp((const char *)p, "port}", 5)) {
                buffer_append_int(b, (int)ctx->burl->port);
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "path}", 5)) {
                burl_append(b, CONST_BUF_LEN(ctx->burl->path), flags);
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "query}", 6)) {
                burl_append(b, CONST_BUF_LEN(ctx->burl->query), flags);
                p+=5;
            }
            else { /* skip unrecognized url.* */
                p = (const unsigned char *)strchr((const char *)p, '}');
                if (NULL == p) return -1;
            }
            break;
        }
        else if (p[0] == 'q' && p[1] == 's' && p[2] == 'a' && p[3] == '}') {
            const buffer *qs = ctx->burl->query;
            if (!buffer_is_empty(qs)) {
                if (NULL != strchr(b->ptr, '?')) {
                    if (!buffer_string_is_empty(qs))
                        buffer_append_string_len(b, CONST_STR_LEN("&"));
                }
                else {
                    buffer_append_string_len(b, CONST_STR_LEN("?"));
                }
                burl_append(b, CONST_BUF_LEN(qs), flags);
            }
            p+=3;
            break;
        }
        else if (p[0] == 'e' && p[1] == 'n' && p[2] == 'c'
                 && 0 == strncmp((const char *)p+3, "b64u:", 5)) {
            flags |= BURL_ENCODE_B64U;
            p+=8;
        }
        else if (p[0] == 'd' && p[1] == 'e' && p[2] == 'c'
                 && 0 == strncmp((const char *)p+3, "b64u:", 5)) {
            flags |= BURL_DECODE_B64U;
            p+=8;
        }
        else ++p;  /* skip unrecognized char */
    }
    if (*p == '\0') return -1;
    if (*p != '}') { /* light_isdigit(*p) */
        unsigned int num = *p - '0';
        ++p;
        if (light_isdigit(*p)) num = num * 10 + (*p++ - '0');
        if (*p != '}') {
            p = (const unsigned char *)strchr((const char *)p, '}');
            if (NULL == p) return -1;
        }
        if (0 == flags) flags = BURL_ENCODE_PSNDE; /* default */
        pattern[0] == '$' /*(else '%')*/
          ? pcre_keyvalue_buffer_append_match(b, list, n, num, flags)
          : pcre_keyvalue_buffer_append_ctxmatch(b, ctx, num, flags);
    }
    return (int)(p + 1 - (unsigned char *)pattern - 2);
}

static void pcre_keyvalue_buffer_subst(buffer *b, const buffer *patternb, const char **list, int n, pcre_keyvalue_ctx *ctx) {
	const char *pattern = patternb->ptr;
	const size_t pattern_len = buffer_string_length(patternb);
	size_t start = 0;

	/* search for $... or %... pattern substitutions */

	buffer_clear(b);

	for (size_t k = 0; k + 1 < pattern_len; ++k) {
		if (pattern[k] == '$' || pattern[k] == '%') {

			buffer_append_string_len(b, pattern + start, k - start);

			if (pattern[k + 1] == '{') {
				int num = pcre_keyvalue_buffer_subst_ext(b, pattern+k, list, n, ctx);
				if (num < 0) return; /* error; truncate result */
				k += (size_t)num;
			} else if (light_isdigit(((unsigned char *)pattern)[k + 1])) {
				unsigned int num = (unsigned int)pattern[k + 1] - '0';
				pattern[k] == '$' /*(else '%')*/
				  ? pcre_keyvalue_buffer_append_match(b, list, n, num, 0)
				  : pcre_keyvalue_buffer_append_ctxmatch(b, ctx, num, 0);
			} else {
				/* enable escape: "%%" => "%", "%a" => "%a", "$$" => "$" */
				buffer_append_string_len(b, pattern+k, pattern[k] == pattern[k+1] ? 1 : 2);
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
        #define N 20
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


/* modified from burl_normalize_basic() to handle %% extra encoding layer */

/* c (char) and n (nibble) MUST be unsigned integer types */
#define li_cton(c,n) \
  (((n) = (c) - '0') <= 9 || (((n) = ((c)&0xdf) - 'A') <= 5 ? ((n) += 10) : 0))

static void pcre_keyvalue_burl_percent_toupper (buffer *b)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    const int used = (int)buffer_string_length(b);
    unsigned int n1, n2;
    for (int i = 0; i < used; ++i) {
        if (s[i]=='%' && li_cton(s[i+1],n1) && li_cton(s[i+2],n2)) {
            if (s[i+1] >= 'a') b->ptr[i+1] &= 0xdf; /* uppercase hex */
            if (s[i+2] >= 'a') b->ptr[i+2] &= 0xdf; /* uppercase hex */
            i+=2;
        }
    }
}

static void pcre_keyvalue_burl_percent_percent_toupper (buffer *b)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    const int used = (int)buffer_string_length(b);
    unsigned int n1, n2;
    for (int i = 0; i < used; ++i) {
        if (s[i] == '%' && s[i+1]=='%'
            && li_cton(s[i+2],n1) && li_cton(s[i+3],n2)) {
            if (s[i+2] >= 'a') b->ptr[i+2] &= 0xdf; /* uppercase hex */
            if (s[i+3] >= 'a') b->ptr[i+3] &= 0xdf; /* uppercase hex */
            i+=3;
        }
    }
}

static const char hex_chars_uc[] = "0123456789ABCDEF";

static void pcre_keyvalue_burl_percent_high_UTF8 (buffer *b, buffer *t)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    unsigned char *p;
    const int used = (int)buffer_string_length(b);
    unsigned int count = 0, j = 0;
    for (int i = 0; i < used; ++i) {
        if (s[i] > 0x7F) ++count;
    }
    if (0 == count) return;

    p = (unsigned char *)buffer_string_prepare_copy(t, used+(count*2));
    for (int i = 0; i < used; ++i, ++j) {
        if (s[i] <= 0x7F)
            p[j] = s[i];
        else {
            p[j]   = '%';
            p[++j] = hex_chars_uc[(s[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[s[i] & 0xF];
        }
    }
    buffer_commit(t, j);
    buffer_copy_buffer(b, t);
}

static void pcre_keyvalue_burl_percent_percent_high_UTF8 (buffer *b, buffer *t)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    unsigned char *p;
    const int used = (int)buffer_string_length(b);
    unsigned int count = 0, j = 0;
    for (int i = 0; i < used; ++i) {
        if (s[i] > 0x7F) ++count;
    }
    if (0 == count) return;

    p = (unsigned char *)buffer_string_prepare_copy(t, used+(count*3));
    for (int i = 0; i < used; ++i, ++j) {
        if (s[i] <= 0x7F)
            p[j] = s[i];
        else {
            p[j]   = '%';
            p[++j] = '%';
            p[++j] = hex_chars_uc[(s[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[s[i] & 0xF];
        }
    }
    buffer_commit(t, j);
    buffer_copy_buffer(b, t);
}

/* Basic normalization of regex and regex replacement to mirror some of
 * the normalizations performed on request URI (for better compatibility).
 * Note: not currently attempting to replace unnecessary percent-encoding
 * (would need to know if regex was intended to match url-path or
 *  query-string or both, and then would have to regex-escape if those
 *  chars where special regex chars such as . * + ? ( ) [ ] | and more)
 * Not attempting to percent-encode chars which should be encoded, again
 * since regex might target url-path, query-string, or both, and we would
 * have to avoid percent-encoding special regex chars.
 * Also not attempting to detect unnecessarily regex-escape in, e.g. %\x\x
 * Preserve improper %-encoded sequences which are not %XX (using hex chars)
 * Intentionally not performing path simplification (e.g. ./ ../)
 * If regex-specific normalizations begin to be made to k here,
 * must revisit callers, e.g. one configfile.c use on non-regex string.
 * "%%" (percent_percent) is used in regex replacement strings since
 * otherwise "%n" is used to indicate regex backreference where n is number.
 */

void pcre_keyvalue_burl_normalize_key (buffer *k, buffer *t)
{
    pcre_keyvalue_burl_percent_toupper(k);
    pcre_keyvalue_burl_percent_high_UTF8(k, t);
}

void pcre_keyvalue_burl_normalize_value (buffer *v, buffer *t)
{
    pcre_keyvalue_burl_percent_percent_toupper(v);
    pcre_keyvalue_burl_percent_percent_high_UTF8(v, t);
}
