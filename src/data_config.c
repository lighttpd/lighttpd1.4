#include "first.h"

#include "base.h"       /* (cond_cache_t) */
#include "array.h"
#include "configfile.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

static data_unset *data_config_copy(const data_unset *s) {
	data_config *src = (data_config *)s;
	data_config *ds = data_config_init();

	ds->comp = src->comp;
	buffer_copy_buffer(ds->key, src->key);
	buffer_copy_buffer(ds->comp_tag, src->comp_tag);
	buffer_copy_buffer(ds->comp_key, src->comp_key);
	array_free(ds->value);
	ds->value = array_init_array(src->value);
	return (data_unset *)ds;
}

static void data_config_free(data_unset *d) {
	data_config *ds = (data_config *)d;

	buffer_free(ds->key);
	buffer_free(ds->op);
	buffer_free(ds->comp_tag);
	buffer_free(ds->comp_key);

	array_free(ds->value);
	vector_config_weak_clear(&ds->children);

	if (ds->string) buffer_free(ds->string);
#ifdef HAVE_PCRE_H
	if (ds->regex) pcre_free(ds->regex);
	if (ds->regex_study) pcre_free(ds->regex_study);
#endif

	free(d);
}

static void data_config_reset(data_unset *d) {
	data_config *ds = (data_config *)d;

	/* reused array elements */
	buffer_clear(ds->key);
	buffer_clear(ds->comp_tag);
	buffer_clear(ds->comp_key);
	array_reset(ds->value);
}

static int data_config_insert_dup(data_unset *dst, data_unset *src) {
	UNUSED(dst);

	src->fn->free(src);

	return 0;
}

static void data_config_print(const data_unset *d, int depth) {
	data_config *ds = (data_config *)d;
	array *a = (array *)ds->value;
	size_t i;
	size_t maxlen;

	if (0 == ds->context_ndx) {
		fprintf(stdout, "config {\n");
	}
	else {
		if (ds->cond != CONFIG_COND_ELSE) {
			fprintf(stdout, "$%s %s \"%s\" {\n",
					ds->comp_key->ptr, ds->op->ptr, ds->string->ptr);
		} else {
			fprintf(stdout, "{\n");
		}
		array_print_indent(depth + 1);
		fprintf(stdout, "# block %d\n", ds->context_ndx);
	}
	depth ++;

	maxlen = array_get_max_key_length(a);
	for (i = 0; i < a->used; i ++) {
		data_unset *du = a->data[i];
		size_t len = buffer_string_length(du->key);
		size_t j;

		array_print_indent(depth);
		fprintf(stdout, "%s", du->key->ptr);
		for (j = maxlen - len; j > 0; j --) {
			fprintf(stdout, " ");
		}
		fprintf(stdout, " = ");
		du->fn->print(du, depth);
		fprintf(stdout, "\n");
	}

	fprintf(stdout, "\n");
	for (i = 0; i < ds->children.used; i ++) {
		data_config *dc = ds->children.data[i];

		/* only the 1st block of chaining */
		if (NULL == dc->prev) {
			fprintf(stdout, "\n");
			array_print_indent(depth);
			dc->fn->print((data_unset *) dc, depth);
			fprintf(stdout, "\n");
		}
	}

	depth --;
	array_print_indent(depth);
	fprintf(stdout, "}");
	if (0 != ds->context_ndx) {
		if (ds->cond != CONFIG_COND_ELSE) {
			fprintf(stdout, " # end of $%s %s \"%s\"",
					ds->comp_key->ptr, ds->op->ptr, ds->string->ptr);
		} else {
			fprintf(stdout, " # end of else");
		}
	}

	if (ds->next) {
		fprintf(stdout, "\n");
		array_print_indent(depth);
		fprintf(stdout, "else ");
		ds->next->fn->print((data_unset *)ds->next, depth);
	}
}

data_config *data_config_init(void) {
	static const struct data_methods fn = {
		data_config_reset,
		data_config_copy,
		data_config_free,
		data_config_insert_dup,
		data_config_print,
	};
	data_config *ds;

	ds = calloc(1, sizeof(*ds));

	ds->key = buffer_init();
	ds->op = buffer_init();
	ds->comp_tag = buffer_init();
	ds->comp_key = buffer_init();
	ds->value = array_init();
	vector_config_weak_init(&ds->children);

	ds->type = TYPE_CONFIG;
	ds->fn = &fn;

	return ds;
}

int data_config_pcre_compile(data_config *dc) {
#ifdef HAVE_PCRE_H
    /* (use fprintf() on error, as this is called from configparser.y) */
    const char *errptr;
    int erroff, captures;

    if (dc->regex) pcre_free(dc->regex);
    if (dc->regex_study) pcre_free(dc->regex_study);

    dc->regex = pcre_compile(dc->string->ptr, 0, &errptr, &erroff, NULL);
    if (NULL == dc->regex) {
        fprintf(stderr, "parsing regex failed: %s -> %s at offset %d\n",
                dc->string->ptr, errptr, erroff);
        return 0;
    }

    dc->regex_study = pcre_study(dc->regex, 0, &errptr);
    if (NULL == dc->regex_study && errptr != NULL) {
        fprintf(stderr, "studying regex failed: %s -> %s\n",
                dc->string->ptr, errptr);
        return 0;
    }

    erroff = pcre_fullinfo(dc->regex, dc->regex_study, PCRE_INFO_CAPTURECOUNT,
                           &captures);
    if (0 != erroff) {
        fprintf(stderr, "getting capture count for regex failed: %s\n",
                dc->string->ptr);
        return 0;
    } else if (captures > 9) {
        fprintf(stderr, "Too many captures in regex, use (?:...) instead of (...): %s\n",
                dc->string->ptr);
        return 0;
    }
    return 1;
#else
    fprintf(stderr, "can't handle '$%s[%s] =~ ...' as you compiled without pcre support. \n"
                    "(perhaps just a missing pcre-devel package ?) \n",
                    dc->comp_key->ptr, dc->comp_tag->ptr);
    return 0;
#endif
}

int data_config_pcre_exec(data_config *dc, cond_cache_t *cache, buffer *b) {
#ifdef HAVE_PCRE_H
    #ifndef elementsof
    #define elementsof(x) (sizeof(x) / sizeof(x[0]))
    #endif
    cache->patterncount =
      pcre_exec(dc->regex, dc->regex_study, CONST_BUF_LEN(b), 0, 0,
                cache->matches, elementsof(cache->matches));
    if (cache->patterncount > 0)
        cache->comp_value = b; /* holds pointer to b (!) for pattern subst */
    return cache->patterncount;
#else
    UNUSED(dc);
    UNUSED(cache);
    UNUSED(b);
    return 0;
#endif
}
