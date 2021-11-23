#include "first.h"

#include "array.h"
#include "configfile.h"

#include <string.h>
#include <stdlib.h>

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

__attribute_cold__
static data_unset *data_config_copy(const data_unset *s) {
	data_config *src = (data_config *)s;
	data_config *ds = data_config_init();

	ds->comp = src->comp;
	if (!buffer_is_unset(&src->key)) {
		buffer_copy_buffer(&ds->key, &src->key);
		ds->comp_key = ds->key.ptr + (src->comp_key - src->key.ptr);
	}
	buffer_copy_buffer(&ds->comp_tag, &src->comp_tag);
	array_copy_array(ds->value, src->value);
	return (data_unset *)ds;
}

__attribute_cold__
static void data_config_free(data_unset *d) {
	data_config *ds = (data_config *)d;

	free(ds->key.ptr);
	free(ds->comp_tag.ptr);

	array_free(ds->value);
	vector_config_weak_clear(&ds->children);

	free(ds->string.ptr);
  #ifdef HAVE_PCRE2_H
        if (ds->code) pcre2_code_free(ds->code);
   #if 0 /*(see config_finalize())*/
        if (ds->match_data) pcre2_match_data_free(ds->match_data);
   #endif
  #elif defined(HAVE_PCRE_H)
	if (ds->regex) pcre_free(ds->regex);
	if (ds->regex_study) pcre_free_study(ds->regex_study);
  #endif

	free(d);
}

data_config *data_config_init(void) {
	static const struct data_methods fn = {
		data_config_copy,
		data_config_free,
		NULL
	};
	data_config *ds;

	ds = calloc(1, sizeof(*ds));
	force_assert(ds);

	ds->comp_key = "";
	ds->value = array_init(4);
	vector_config_weak_init(&ds->children);

	ds->type = TYPE_CONFIG;
	ds->fn = &fn;

	return ds;
}

#include "log.h"

int data_config_pcre_compile(data_config * const dc, const int pcre_jit, log_error_st * const errh) {

  #ifdef HAVE_PCRE2_H

    int errcode;
    PCRE2_SIZE erroff;
    PCRE2_UCHAR errbuf[1024];

    dc->code = pcre2_compile((PCRE2_SPTR)BUF_PTR_LEN(&dc->string),
                             PCRE2_UTF, &errcode, &erroff, NULL);
    if (NULL == dc->code) {
        pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
        log_error(errh, __FILE__, __LINE__,
                  "pcre2_compile: %s at offset %zu, regex: %s",
                  (char *)errbuf, erroff, dc->string.ptr);
        return 0;
    }

    if (pcre_jit) {
        errcode = pcre2_jit_compile(dc->code, PCRE2_JIT_COMPLETE);
        if (0 != errcode) {
            pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
            log_error(errh, __FILE__, __LINE__,
                      "pcre2_jit_compile: %s, regex: %s",
                      (char *)errbuf, dc->string.ptr);
        }
        /*return 0;*/
    }

    uint32_t captures;
    errcode = pcre2_pattern_info(dc->code, PCRE2_INFO_CAPTURECOUNT, &captures);
    if (0 != errcode) {
        pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
        log_error(errh, __FILE__, __LINE__,
          "pcre2_pattern_info: %s, regex: %s", (char *)errbuf, dc->string.ptr);
        return 0;
    }
    else if (captures > 9) {
        log_error(errh, __FILE__, __LINE__,
          "Too many captures in regex, use (?:...) instead of (...): %s",
          dc->string.ptr);
        return 0;
    }

   #if 0 /*(see config_finalize())*/
    dc->match_data = pcre2_match_data_create_from_pattern(dc->code, NULL);
    force_assert(dc->match_data);
   #endif

    return 1;

  #elif defined(HAVE_PCRE_H)

    const char *errptr;
    int erroff, captures;

    dc->regex = pcre_compile(dc->string.ptr, 0, &errptr, &erroff, NULL);
    if (NULL == dc->regex) {
        log_error(errh, __FILE__, __LINE__,
                  "parsing regex failed: %s -> %s at offset %d\n",
                  dc->string.ptr, errptr, erroff);
        return 0;
    }

    const int study_options = pcre_jit ? PCRE_STUDY_JIT_COMPILE : 0;
    dc->regex_study = pcre_study(dc->regex, study_options, &errptr);
    if (NULL == dc->regex_study && errptr != NULL) {
        log_error(errh, __FILE__, __LINE__,
                  "studying regex failed: %s -> %s\n",
                  dc->string.ptr, errptr);
        return 0;
    }

    erroff = pcre_fullinfo(dc->regex, dc->regex_study, PCRE_INFO_CAPTURECOUNT,
                           &captures);
    if (0 != erroff) {
        log_error(errh, __FILE__, __LINE__,
                  "getting capture count for regex failed: %s\n",
                  dc->string.ptr);
        return 0;
    }
    else if (captures > 9) {
        log_error(errh, __FILE__, __LINE__,
                  "Too many captures in regex, use (?:...) instead of (...): %s\n",
                  dc->string.ptr);
        return 0;
    }
    dc->ovec_nelts = 3 * (captures + 1);
    return 1;

  #else

    UNUSED(pcre_jit);
    log_error(errh, __FILE__, __LINE__,
              "can't handle '%s' as you compiled without pcre support. \n"
              "(perhaps just a missing pcre-devel package ?) \n",
              dc->comp_key);
    return 0;

  #endif
}
