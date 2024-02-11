/*
 * keyvalue - PCRE matching and substitution for mod_redirect and mod_rewrite
 *
 * Fully-rewritten from original
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "keyvalue.h"
#include "plugin_config.h" /* struct cond_match_t */
#include "burl.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_PCRE2_H
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#elif defined(HAVE_PCRE_H)
#include <pcre.h>
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#define pcre_free_study(x) pcre_free(x)
#endif
#endif

#ifdef HAVE_PCRE2_H
static struct pcre2_real_match_data_8 *keyvalue_match_data;
#endif

typedef struct pcre_keyvalue {
  #ifdef HAVE_PCRE2_H
	pcre2_code *code;
	struct pcre2_real_match_data_8 *match_data;
  #elif defined(HAVE_PCRE_H)
	pcre *key;
	pcre_extra *key_extra;
  #endif
	buffer value;
} pcre_keyvalue;

pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void) {
	return ck_calloc(1, sizeof(pcre_keyvalue_buffer));
}

int pcre_keyvalue_buffer_append(log_error_st *errh, pcre_keyvalue_buffer *kvb, const buffer *key, const buffer *value, const int pcre_jit) {

	pcre_keyvalue *kv;

	if (!(kvb->used & (4-1))) /*(allocate in groups of 4)*/
		ck_realloc_u32((void **)&kvb->kv,kvb->used,4,sizeof(*kvb->kv));

	kv = kvb->kv + kvb->used++;

        /* copy persistent config data, and elide free() in free_data below */
	memcpy(&kv->value, value, sizeof(buffer));
	/*buffer_copy_buffer(&kv->value, value);*/

  #ifdef HAVE_PCRE

   #ifdef HAVE_PCRE2_H

	int errcode;
	PCRE2_SIZE erroff;
	PCRE2_UCHAR errbuf[1024];

	kv->code = pcre2_compile((PCRE2_SPTR)BUF_PTR_LEN(key),
	                         PCRE2_UTF, &errcode, &erroff, NULL);
	if (NULL == kv->code) {
		pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
		log_error(errh, __FILE__, __LINE__,
		          "pcre2_compile: %s at offset %zu, regex: %s",
		          (char *)errbuf, erroff, key->ptr);
		return 0;
	}

	if (pcre_jit) {
		errcode = pcre2_jit_compile(kv->code, PCRE2_JIT_COMPLETE);
		if (0 != errcode && errcode != PCRE2_ERROR_JIT_BADOPTION) {
			pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
			log_error(errh, __FILE__, __LINE__,
			  "pcre2_jit_compile: %s, regex: %s", (char *)errbuf, key->ptr);
			/*return 0;*/
		}
	}

	uint32_t captures;
	errcode = pcre2_pattern_info(kv->code, PCRE2_INFO_CAPTURECOUNT, &captures);
	if (0 != errcode) {
		pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
		log_error(errh, __FILE__, __LINE__,
		  "pcre2_pattern_info: %s, regex: %s", (char *)errbuf, key->ptr);
		return 0;
	}
	else if (captures > 19) {
		log_error(errh, __FILE__, __LINE__,
		  "Too many captures in regex, "
		  "use (?:...) instead of (...): %s", key->ptr);
		return 0;
	}

    #if 1 /*(share single keyvalue_match_data among all keyvalue regexes)*/
	if (NULL == keyvalue_match_data) {
		keyvalue_match_data = pcre2_match_data_create(20, NULL);
		force_assert(keyvalue_match_data);
	}
	kv->match_data = keyvalue_match_data;
    #else
	kv->match_data = pcre2_match_data_create_from_pattern(kv->code, NULL);
	force_assert(kv->match_data);
    #endif

   #elif defined(HAVE_PCRE_H)

	const char *errptr;
	int erroff;

	kv->key_extra = NULL;

	if (NULL == (kv->key = pcre_compile(key->ptr,
					  0, &errptr, &erroff, NULL))) {

		log_error(errh, __FILE__, __LINE__,
		  "rexexp compilation error at %s", errptr);
		return 0;
	}

	const int study_options = pcre_jit ? PCRE_STUDY_JIT_COMPILE : 0;
	if (NULL == (kv->key_extra = pcre_study(kv->key, study_options, &errptr))
	    && errptr != NULL) {
		log_error(errh, __FILE__, __LINE__,
		  "studying regex failed: %s -> %s\n",
		  key->ptr, errptr);
		return 0;
	}

   #endif

  #else  /* !HAVE_PCRE */

    if (!buffer_is_blank(key)) {
	static int logged_message = 0;
	if (logged_message) return 1;
	logged_message = 1;
	log_error(errh, __FILE__, __LINE__,
	  "pcre support is missing, please install libpcre and the headers");
	UNUSED(pcre_jit);
    }

  #endif /* !HAVE_PCRE */

	return 1;
}

void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb) {
  #ifdef HAVE_PCRE
	pcre_keyvalue *kv = kvb->kv;
	for (int i = 0, used = (int)kvb->used; i < used; ++i, ++kv) {
	  #ifdef HAVE_PCRE2_H
		if (kv->code) pcre2_code_free(kv->code);
	   #if 1
		if (keyvalue_match_data) {
			pcre2_match_data_free(keyvalue_match_data);
			keyvalue_match_data = NULL;
		}
	   #else
		if (kv->match_data) pcre2_match_data_free(kv->match_data);
	   #endif
	  #elif defined(HAVE_PCRE_H)
		if (kv->key) pcre_free(kv->key);
		if (kv->key_extra) pcre_free_study(kv->key_extra);
		/*free (kv->value.ptr);*//*(see pcre_keyvalue_buffer_append)*/
	  #endif
	}
  #endif

	if (kvb->kv) free(kvb->kv);
	free(kvb);
}

#ifdef HAVE_PCRE

static void pcre_keyvalue_buffer_append_match(buffer *b, const pcre_keyvalue_ctx *ctx, unsigned int num, int flags) {
    if (num < (unsigned int)ctx->n) { /* n is always > 0 */
      #ifdef HAVE_PCRE2_H
        const PCRE2_SIZE *ovec = (PCRE2_SIZE *)ctx->ovec;
      #elif defined(HAVE_PCRE_H)
        const int *ovec = (int *)ctx->ovec;
      #endif
        const size_t off = (size_t)ovec[(num <<= 1)]; /*(num *= 2)*/
        const size_t len = (size_t)ovec[num+1] - off;
        burl_append(b, ctx->subject + off, len, flags);
    }
}

static void pcre_keyvalue_buffer_append_ctxmatch(buffer *b, const pcre_keyvalue_ctx *ctx, unsigned int num, int flags) {
    const struct cond_match_t * const cache = ctx->cache;
    if (!cache) return; /* no enclosing match context */
    if ((int)num < cache->captures) {/* ->captures might be -1 if no captures */
      #ifdef HAVE_PCRE2_H
        const PCRE2_SIZE *ovec = (PCRE2_SIZE *)cache->matches;
      #elif defined(HAVE_PCRE_H)
        const int *ovec = (int *)cache->matches;
      #endif
        const size_t off = (size_t)ovec[(num <<= 1)]; /*(num *= 2)*/
        const size_t len = (size_t)ovec[num+1] - off;
        burl_append(b, cache->comp_value->ptr + off, len, flags);
    }
}

#endif /* HAVE_PCRE */

static int pcre_keyvalue_buffer_subst_ext(buffer *b, const char *pattern, const pcre_keyvalue_ctx *ctx) {
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
            const struct burl_parts_t * const burl = ctx->burl;
            p+=4;
            if (0 == strncmp((const char *)p, "scheme}", 7)) {
                if (burl->scheme)
                    burl_append(b, BUF_PTR_LEN(burl->scheme), flags);
                p+=6;
            }
            else if (0 == strncmp((const char *)p, "authority}", 10)) {
                if (burl->authority)
                    burl_append(b, BUF_PTR_LEN(burl->authority), flags);
                p+=9;
            }
            else if (0 == strncmp((const char *)p, "port}", 5)) {
                buffer_append_int(b, (int)burl->port);
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "path}", 5)) {
                const buffer * const target = burl->path;
                const uint32_t len = buffer_clen(target);
                const char * const ptr = target->ptr;
                const char * const qmark = memchr(ptr, '?', len);
                burl_append(b, ptr, qmark ? (uint32_t)(qmark-ptr) : len, flags);
                p+=4;
            }
            else if (0 == strncmp((const char *)p, "query}", 6)) {
                if (burl->query)
                    burl_append(b, BUF_PTR_LEN(burl->query), flags);
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
            if (qs && !buffer_is_unset(qs)) {
                if (NULL != strchr(b->ptr, '?')) {
                    if (!buffer_is_blank(qs))
                        buffer_append_char(b, '&');
                }
                else {
                    buffer_append_char(b, '?');
                }
                burl_append(b, BUF_PTR_LEN(qs), flags);
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
      #ifdef HAVE_PCRE
        pattern[0] == '$' /*(else '%')*/
          ? pcre_keyvalue_buffer_append_match(b, ctx, num, flags)
          : pcre_keyvalue_buffer_append_ctxmatch(b, ctx, num, flags);
      #endif
    }
    return (int)(p + 1 - (unsigned char *)pattern - 2);
}

static void pcre_keyvalue_buffer_subst(buffer *b, const buffer *patternb, const pcre_keyvalue_ctx *ctx) {
	const char *pattern = patternb->ptr;
	const size_t pattern_len = buffer_clen(patternb);
	size_t start = 0;

	/* search for $... or %... pattern substitutions */

	buffer_clear(b);

	for (size_t k = 0; k + 1 < pattern_len; ++k) {
		if (pattern[k] == '$' || pattern[k] == '%') {

			buffer_append_string_len(b, pattern + start, k - start);

			if (pattern[k + 1] == '{') {
				int num = pcre_keyvalue_buffer_subst_ext(b, pattern+k, ctx);
				if (num < 0) return; /* error; truncate result */
				k += (size_t)num;
			} else if (light_isdigit(((unsigned char *)pattern)[k + 1])) {
			  #ifdef HAVE_PCRE
				unsigned int num = (unsigned int)pattern[k + 1] - '0';
				pattern[k] == '$' /*(else '%')*/
				  ? pcre_keyvalue_buffer_append_match(b, ctx, num, 0)
				  : pcre_keyvalue_buffer_append_ctxmatch(b, ctx, num, 0);
			  #endif
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

handler_t pcre_keyvalue_buffer_process(const pcre_keyvalue_buffer *kvb, pcre_keyvalue_ctx *ctx, const buffer *input, buffer *result) {
    const pcre_keyvalue *kv = kvb->kv;
    for (int i = 0, used = (int)kvb->used; i < used; ++i, ++kv) {
     #ifdef HAVE_PCRE
      #ifdef HAVE_PCRE2_H
        int n = pcre2_match(kv->code, (PCRE2_SPTR)BUF_PTR_LEN(input),
                            0, 0, kv->match_data, NULL);
      #else
        #define N 20
        int ovec[N * 3];
        #undef N
        int n = pcre_exec(kv->key, kv->key_extra, BUF_PTR_LEN(input),
                          0, 0, ovec, sizeof(ovec)/sizeof(int));
      #endif
     #else
        int n = 1;
     #endif
        if (n < 0) {
         #ifdef HAVE_PCRE
          #ifdef HAVE_PCRE2_H
            if (n != PCRE2_ERROR_NOMATCH)
          #else
            if (n != PCRE_ERROR_NOMATCH)
          #endif
         #endif
                return HANDLER_ERROR;
        }
        else if (buffer_is_blank(&kv->value)) {
            /* short-circuit if blank replacement pattern
             * (do not attempt to match against remaining kvb rules) */
            ctx->m = i;
            return HANDLER_GO_ON;
        }
        else { /* it matched */
            ctx->m = i;
            ctx->n = n;
            ctx->subject = input->ptr;
         #ifdef HAVE_PCRE
          #ifdef HAVE_PCRE2_H
            ctx->ovec = pcre2_get_ovector_pointer(kv->match_data);
          #else
            ctx->ovec = ovec;
          #endif
         #endif
            pcre_keyvalue_buffer_subst(result, &kv->value, ctx);
            return HANDLER_FINISHED;
        }
    }

    return HANDLER_GO_ON;
}


/* modified from burl_normalize_basic() to handle %% extra encoding layer */

/* c (char) and n (nibble) MUST be unsigned integer types */
#define li_cton(c,n) \
  (((n) = (c) - '0') <= 9 || (((n) = ((c)&0xdf) - 'A') <= 5 ? ((n) += 10) : 0))

static void pcre_keyvalue_burl_percent_toupper (buffer *b)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    const int used = (int)buffer_clen(b);
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
    const int used = (int)buffer_clen(b);
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
    const int used = (int)buffer_clen(b);
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
    buffer_copy_string_len(b, (char *)p, (size_t)j);
}

static void pcre_keyvalue_burl_percent_percent_high_UTF8 (buffer *b, buffer *t)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    unsigned char *p;
    const int used = (int)buffer_clen(b);
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
    buffer_copy_string_len(b, (char *)p, (size_t)j);
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
