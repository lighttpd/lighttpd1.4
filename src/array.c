#include "first.h"

#include "array.h"
#include "buffer.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>


__attribute_cold__
static data_unset *array_data_string_copy(const data_unset *s) {
    data_string *src = (data_string *)s;
    data_string *ds = array_data_string_init();
    if (!buffer_is_unset(&src->key)) buffer_copy_buffer(&ds->key, &src->key);
    buffer_copy_buffer(&ds->value, &src->value);
    return (data_unset *)ds;
}

__attribute_cold__
static void array_data_string_insert_dup(data_unset *dst, data_unset *src) {
    data_string *ds_dst = (data_string *)dst;
    data_string *ds_src = (data_string *)src;
    if (!buffer_is_blank(&ds_dst->value))
        buffer_append_str2(&ds_dst->value, CONST_STR_LEN(", "),
                                           BUF_PTR_LEN(&ds_src->value));
    else
        buffer_copy_buffer(&ds_dst->value, &ds_src->value);
}

static void array_data_string_free(data_unset *du) {
    data_string *ds = (data_string *)du;
    free(ds->key.ptr);
    free(ds->value.ptr);
    free(ds);
}

__attribute_noinline__
data_string *array_data_string_init(void) {
    static const struct data_methods fn = {
        array_data_string_copy,
        array_data_string_free,
        array_data_string_insert_dup,
    };
    data_string *ds = calloc(1, sizeof(*ds));
    force_assert(NULL != ds);
    ds->type = TYPE_STRING;
    ds->fn = &fn;
    return ds;
}


__attribute_cold__
static data_unset *array_data_integer_copy(const data_unset *s) {
    data_integer *src = (data_integer *)s;
    data_integer *di = array_data_integer_init();
    if (!buffer_is_unset(&src->key)) buffer_copy_buffer(&di->key, &src->key);
    di->value = src->value;
    return (data_unset *)di;
}

static void array_data_integer_free(data_unset *du) {
    data_integer *di = (data_integer *)du;
    free(di->key.ptr);
    free(di);
}

__attribute_noinline__
data_integer *array_data_integer_init(void) {
    static const struct data_methods fn = {
        array_data_integer_copy,
        array_data_integer_free,
        NULL
    };
    data_integer *di = calloc(1, sizeof(*di));
    force_assert(NULL != di);
    di->type = TYPE_INTEGER;
    di->fn = &fn;
    return di;
}


__attribute_cold__
static data_unset *array_data_array_copy(const data_unset *s) {
    data_array *src = (data_array *)s;
    data_array *da = array_data_array_init();
    if (!buffer_is_unset(&src->key)) buffer_copy_buffer(&da->key, &src->key);
    array_copy_array(&da->value, &src->value);
    return (data_unset *)da;
}

static void array_data_array_free(data_unset *du) {
    data_array *da = (data_array *)du;
    free(da->key.ptr);
    array_free_data(&da->value);
    free(da);
}

__attribute_noinline__
data_array *array_data_array_init(void) {
    static const struct data_methods fn = {
        array_data_array_copy,
        array_data_array_free,
        NULL
    };
    data_array *da = calloc(1, sizeof(*da));
    force_assert(NULL != da);
    da->type = TYPE_ARRAY;
    da->fn = &fn;
    return da;
}


__attribute_cold__
static void array_extend(array * const a, uint32_t n) {
    /* This data structure should not be used for nearly so many entries */
    force_assert(a->size <= INT32_MAX-n);
    a->size  += n;
    a->data   = realloc(a->data,   sizeof(*a->data)   * a->size);
    a->sorted = realloc(a->sorted, sizeof(*a->sorted) * a->size);
    force_assert(a->data);
    force_assert(a->sorted);
    memset(a->data+a->used, 0, (a->size-a->used)*sizeof(*a->data));
}

array *array_init(uint32_t n) {
	array *a;

	a = calloc(1, sizeof(*a));
	force_assert(a);
	if (n) array_extend(a, n);

	return a;
}

void array_free_data(array * const a) {
	if (a->sorted) free(a->sorted);
	data_unset ** const data = a->data;
	const uint32_t sz = a->size;
	for (uint32_t i = 0; i < sz; ++i) {
		if (data[i]) data[i]->fn->free(data[i]);
	}
	free(data);
	a->data = NULL;
	a->sorted = NULL;
	a->used = 0;
	a->size = 0;
}

void array_copy_array(array * const dst, const array * const src) {
	array_free_data(dst);
	if (0 == src->size) return;

	array_extend(dst, src->size);
	for (uint32_t i = 0; i < src->used; ++i) {
		array_insert_unique(dst, src->data[i]->fn->copy(src->data[i]));
	}
}

void array_free(array * const a) {
	if (!a) return;
	array_free_data(a);
	free(a);
}

void array_reset_data_strings(array * const a) {
	if (!a) return;

	data_string ** const data = (data_string **)a->data;
	const uint32_t used = a->used;
	a->used = 0;
	for (uint32_t i = 0; i < used; ++i) {
		data_string * const ds = data[i];
		/*force_assert(ds->type == TYPE_STRING);*/
		buffer_reset(&ds->key);
		buffer_reset(&ds->value);
	}
}

#if 0 /*(unused; see array_extract_element_klen())*/
data_unset *array_pop(array * const a) {
	data_unset *du;

	force_assert(a->used != 0);

	a->used --;
	du = a->data[a->used];
	force_assert(a->sorted[a->used] == du); /* only works on "simple" lists */
	a->data[a->used] = NULL;

	return du;
}
#endif

__attribute_pure__
static int array_caseless_compare(const char * const a, const char * const b, const uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
        unsigned int ca = ((unsigned char *)a)[i];
        unsigned int cb = ((unsigned char *)b)[i];
        if (ca == cb) continue;

        /* always lowercase for transitive results */
        if (light_isupper(ca)) ca |= 0x20;
        if (light_isupper(cb)) cb |= 0x20;

        if (ca == cb) continue;
        return (int)(ca - cb);
    }
    return 0;
}

__attribute_pure__
static int array_keycmp(const char * const a, const uint32_t alen, const char * const b, const uint32_t blen) {
    return alen < blen ? -1 : alen > blen ? 1 : array_caseless_compare(a, b, blen);
}

__attribute_cold__
__attribute_pure__
static int array_keycmpb(const char * const k, const uint32_t klen, const buffer * const b) {
    /* key is non-empty (0==b->used), though possibly blank (1==b->used)
     * if inserted into key-value array */
    /*force_assert(b && b->used);*/
    return array_keycmp(k, klen, b->ptr, b->used-1);
    /*return array_keycmp(k, klen, BUF_PTR_LEN(b));*/
}

/* returns pos into a->sorted[] which contains copy of data (ptr) in a->data[]
 * if pos >= 0, or returns -pos-1 if that is the position-1 in a->sorted[]
 * where the key needs to be inserted (-1 to avoid -0)
 */
__attribute_hot__
__attribute_pure__
static int32_t array_get_index_ext(const array * const a, const int ext, const char * const k, const uint32_t klen) {
    /* invariant: [lower-1] < probe < [upper]
     * invariant: 0 <= lower <= upper <= a->used
     */
    uint_fast32_t lower = 0, upper = a->used;
    while (lower != upper) {
        const uint_fast32_t probe = (lower + upper) / 2;
        const int x = ((data_string *)a->sorted[probe])->ext;
        /* (compare strings only if ext is 0 for both)*/
        const int e = (ext|x)
          ? ext
          : array_keycmpb(k, klen, &a->sorted[probe]->key);
        if (e < x)             /* e < [probe] */
            upper = probe;     /* still: lower <= upper */
        else if (e > x)        /* e > [probe] */
            lower = probe + 1; /* still: lower <= upper */
        else  /*(e == x)*/     /* found */
            return (int32_t)probe;
    }
    /* not found: [lower-1] < key < [upper] = [lower] ==> insert at [lower] */
    return -(int)lower - 1;
}

data_unset *array_get_element_klen_ext(const array * const a, const int ext, const char *key, const uint32_t klen) {
    const int32_t ipos = array_get_index_ext(a, ext, key, klen);
    return ipos >= 0 ? a->sorted[ipos] : NULL;
}

/* returns pos into a->sorted[] which contains copy of data (ptr) in a->data[]
 * if pos >= 0, or returns -pos-1 if that is the position-1 in a->sorted[]
 * where the key needs to be inserted (-1 to avoid -0)
 */
__attribute_hot__
__attribute_pure__
static int32_t array_get_index(const array * const a, const char * const k, const uint32_t klen) {
    /* invariant: [lower-1] < probe < [upper]
     * invariant: 0 <= lower <= upper <= a->used
     */
    uint_fast32_t lower = 0, upper = a->used;
    while (lower != upper) {
        uint_fast32_t probe = (lower + upper) / 2;
        const buffer * const b = &a->sorted[probe]->key;
        /* key is non-empty (0==b->used), though possibly blank (1==b->used),
         * if inserted into key-value array */
        /*force_assert(b && b->used);*/
        int cmp = array_keycmp(k, klen, b->ptr, b->used-1);
        /*int cmp = array_keycmp(k, klen, BUF_PTR_LEN(b));*/
        if (cmp < 0)           /* key < [probe] */
            upper = probe;     /* still: lower <= upper */
        else if (cmp > 0)      /* key > [probe] */
            lower = probe + 1; /* still: lower <= upper */
        else  /*(cmp == 0)*/   /* found */
            return (int32_t)probe;
    }
    /* not found: [lower-1] < key < [upper] = [lower] ==> insert at [lower] */
    return -(int)lower - 1;
}

__attribute_hot__
const data_unset *array_get_element_klen(const array * const a, const char *key, const uint32_t klen) {
    const int32_t ipos = array_get_index(a, key, klen);
    return ipos >= 0 ? a->sorted[ipos] : NULL;
}

/* non-const (data_config *) for configparser.y (not array_get_element_klen())*/
data_unset *array_get_data_unset(const array * const a, const char *key, const uint32_t klen) {
    const int32_t ipos = array_get_index(a, key, klen);
    return ipos >= 0 ? a->sorted[ipos] : NULL;
}

data_unset *array_extract_element_klen(array * const a, const char *key, const uint32_t klen) {
    const int32_t ipos = array_get_index(a, key, klen);
    if (ipos < 0) return NULL;

    /* remove entry from a->sorted: move everything after pos one step left */
    data_unset * const entry = a->sorted[ipos];
    const uint32_t last_ndx = --a->used;
    if (last_ndx != (uint32_t)ipos) {
        data_unset ** const d = a->sorted + ipos;
        memmove(d, d+1, (last_ndx - (uint32_t)ipos) * sizeof(*d));
    }

    if (entry != a->data[last_ndx]) {
        /* walk a->data[] to find data ptr */
        /* (not checking (ndx <= last_ndx) since entry must be in a->data[]) */
        uint32_t ndx = 0;
        while (entry != a->data[ndx]) ++ndx;
        a->data[ndx] = a->data[last_ndx]; /* swap with last element */
    }
    a->data[last_ndx] = NULL;
    return entry;
}

static data_unset *array_get_unused_element(array * const a, const data_type_t t) {
    /* After initial startup and config, most array usage is of homogeneous types
     * and arrays are cleared once per request, so check only the first unused
     * element to see if it can be reused */
  #if 1
    data_unset * const du = (a->used < a->size) ? a->data[a->used] : NULL;
    if (NULL != du && du->type == t) {
        a->data[a->used] = NULL;/* make empty slot at a->used for next insert */
        return du;
    }
    return NULL;
  #else
	data_unset ** const data = a->data;
	for (uint32_t i = a->used, sz = a->size; i < sz; ++i) {
		if (data[i] && data[i]->type == t) {
			data_unset * const ds = data[i];

			/* make empty slot at a->used for next insert */
			data[i] = data[a->used];
			data[a->used] = NULL;

			return ds;
		}
	}

	return NULL;
  #endif
}

__attribute_hot__
static data_unset * array_insert_data_at_pos(array * const a, data_unset * const entry, const uint_fast32_t pos) {
    if (a->used < a->size) {
        data_unset * const prev = a->data[a->used];
        if (__builtin_expect( (prev != NULL), 0))
            prev->fn->free(prev); /* free prior data, if any, from slot */
    }
    else {
        array_extend(a, 16);
    }

    uint_fast32_t ndx = a->used++;
    a->data[ndx] = entry;

    /* move everything one step to the right */
    ndx -= pos;
    data_unset ** const d = a->sorted + pos;
    if (__builtin_expect( (ndx), 1))
        memmove(d+1, d, ndx * sizeof(*a->sorted));
    *d = entry;
    return entry;
}

static data_integer * array_insert_integer_at_pos(array * const a, const uint_fast32_t pos) {
  #if 0 /*(not currently used by lighttpd in way that reuse would occur)*/
    data_integer *di = (data_integer *)array_get_unused_element(a,TYPE_INTEGER);
    if (NULL == di) di = array_data_integer_init();
  #else
    data_integer * const di = array_data_integer_init();
  #endif
    return (data_integer *)array_insert_data_at_pos(a, (data_unset *)di, pos);
}

__attribute_hot__
static data_string * array_insert_string_at_pos(array * const a, const uint_fast32_t pos) {
    data_string *ds = (data_string *)array_get_unused_element(a, TYPE_STRING);
    if (NULL == ds) ds = array_data_string_init();
    return (data_string *)array_insert_data_at_pos(a, (data_unset *)ds, pos);
}

__attribute_hot__
buffer * array_get_buf_ptr_ext(array * const a, const int ext, const char * const k, const uint32_t klen) {
    int32_t ipos = array_get_index_ext(a, ext, k, klen);
    if (ipos >= 0) return &((data_string *)a->sorted[ipos])->value;

    data_string * const ds = array_insert_string_at_pos(a, (uint32_t)(-ipos-1));
    ds->ext = ext;
    buffer_copy_string_len(&ds->key, k, klen);
    buffer_clear(&ds->value);
    return &ds->value;
}

int * array_get_int_ptr(array * const a, const char * const k, const uint32_t klen) {
    int32_t ipos = array_get_index(a, k, klen);
    if (ipos >= 0) return &((data_integer *)a->sorted[ipos])->value;

    data_integer * const di =array_insert_integer_at_pos(a,(uint32_t)(-ipos-1));
    buffer_copy_string_len(&di->key, k, klen);
    di->value = 0;
    return &di->value;
}

buffer * array_get_buf_ptr(array * const a, const char * const k, const uint32_t klen) {
    int32_t ipos = array_get_index(a, k, klen);
    if (ipos >= 0) return &((data_string *)a->sorted[ipos])->value;

    data_string * const ds = array_insert_string_at_pos(a, (uint32_t)(-ipos-1));
    buffer_copy_string_len(&ds->key, k, klen);
    buffer_clear(&ds->value);
    return &ds->value;
}

void array_insert_value(array * const a, const char * const v, const uint32_t vlen) {
    data_string * const ds = array_insert_string_at_pos(a, a->used);
    buffer_clear(&ds->key);
    buffer_copy_string_len(&ds->value, v, vlen);
}

/* if entry already exists return pointer to existing entry, otherwise insert entry and return NULL */
__attribute_cold__
static data_unset **array_find_or_insert(array * const a, data_unset * const entry) {
    force_assert(NULL != entry);

    /* push value onto end of array if there is no key */
    if (buffer_is_unset(&entry->key)) {
        array_insert_data_at_pos(a, entry, a->used);
        return NULL;
    }

    /* try to find the entry */
    const int32_t ipos = array_get_index(a, BUF_PTR_LEN(&entry->key));
    if (ipos >= 0) return &a->sorted[ipos];

    array_insert_data_at_pos(a, entry, (uint32_t)(-ipos - 1));
    return NULL;
}

/* replace or insert data (free existing entry) */
void array_replace(array * const a, data_unset * const entry) {
    if (NULL == array_find_or_insert(a, entry)) return;

    /* find the entry (array_find_or_insert() returned non-NULL) */
    const int32_t ipos = array_get_index(a, BUF_PTR_LEN(&entry->key));
    force_assert(ipos >= 0);
    data_unset *old = a->sorted[ipos];
    force_assert(old != entry);
    a->sorted[ipos] = entry;

    uint32_t i = 0;
    while (i < a->used && a->data[i] != old) ++i;
    force_assert(i != a->used);
    a->data[i] = entry;

    old->fn->free(old);
}

void array_insert_unique(array * const a, data_unset * const entry) {
	data_unset **old;

	if (NULL != (old = array_find_or_insert(a, entry))) {
		if (entry->fn->insert_dup) {
			force_assert((*old)->type == entry->type);
			entry->fn->insert_dup(*old, entry);
		}
		entry->fn->free(entry);
	}
}

int array_is_vlist(const array * const a) {
	for (uint32_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (!buffer_is_unset(&du->key) || du->type != TYPE_STRING) return 0;
	}
	return 1;
}

int array_is_kvany(const array * const a) {
	for (uint32_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (buffer_is_unset(&du->key)) return 0;
	}
	return 1;
}

int array_is_kvarray(const array * const a) {
	for (uint32_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (buffer_is_unset(&du->key) || du->type != TYPE_ARRAY) return 0;
	}
	return 1;
}

int array_is_kvstring(const array * const a) {
	for (uint32_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (buffer_is_unset(&du->key) || du->type != TYPE_STRING) return 0;
	}
	return 1;
}

/* array_match_*() routines follow very similar pattern, but operate on slightly
 * different data: array key/value, prefix/suffix match, case-insensitive or not
 * While these could be combined into fewer routines with flags to modify the
 * behavior, the interface distinctions are useful to add clarity to the code,
 * and the specialized routines run slightly faster */

data_unset *
array_match_key_prefix_klen (const array * const a, const char * const s, const uint32_t slen)
{
    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const key = &a->data[i]->key;
        const uint32_t klen = buffer_clen(key);
        if (klen <= slen && 0 == memcmp(s, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

data_unset *
array_match_key_prefix_nc_klen (const array * const a, const char * const s, const uint32_t slen)
{
    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const key = &a->data[i]->key;
        const uint32_t klen = buffer_clen(key);
        if (klen <= slen && buffer_eq_icase_ssn(s, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

data_unset *
array_match_key_prefix (const array * const a, const buffer * const b)
{
  #ifdef __clang_analyzer__
    force_assert(b);
  #endif
    return array_match_key_prefix_klen(a, BUF_PTR_LEN(b));
}

data_unset *
array_match_key_prefix_nc (const array * const a, const buffer * const b)
{
    return array_match_key_prefix_nc_klen(a, BUF_PTR_LEN(b));
}

const buffer *
array_match_value_prefix (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);

    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const value = &((data_string *)a->data[i])->value;
        const uint32_t vlen = buffer_clen(value);
        if (vlen <= blen && 0 == memcmp(b->ptr, value->ptr, vlen))
            return value;
    }
    return NULL;
}

const buffer *
array_match_value_prefix_nc (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);

    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const value = &((data_string *)a->data[i])->value;
        const uint32_t vlen = buffer_clen(value);
        if (vlen <= blen && buffer_eq_icase_ssn(b->ptr, value->ptr, vlen))
            return value;
    }
    return NULL;
}

data_unset *
array_match_key_suffix (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);
    const char * const end = b->ptr + blen;

    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const key = &a->data[i]->key;
        const uint32_t klen = buffer_clen(key);
        if (klen <= blen && 0 == memcmp(end - klen, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

data_unset *
array_match_key_suffix_nc (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);
    const char * const end = b->ptr + blen;

    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const key = &a->data[i]->key;
        const uint32_t klen = buffer_clen(key);
        if (klen <= blen && buffer_eq_icase_ssn(end - klen, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

const buffer *
array_match_value_suffix (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);
    const char * const end = b->ptr + blen;

    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const value = &((data_string *)a->data[i])->value;
        const uint32_t vlen = buffer_clen(value);
        if (vlen <= blen && 0 == memcmp(end - vlen, value->ptr, vlen))
            return value;
    }
    return NULL;
}

const buffer *
array_match_value_suffix_nc (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);
    const char * const end = b->ptr + blen;

    for (uint32_t i = 0; i < a->used; ++i) {
        const buffer * const value = &((data_string *)a->data[i])->value;
        const uint32_t vlen = buffer_clen(value);
        if (vlen <= blen && buffer_eq_icase_ssn(end - vlen, value->ptr, vlen))
            return value;
    }
    return NULL;
}

data_unset *
array_match_path_or_ext (const array * const a, const buffer * const b)
{
    const uint32_t blen = buffer_clen(b);

    for (uint32_t i = 0; i < a->used; ++i) {
        /* check extension in the form "^/path" or ".ext$" */
        const buffer * const key = &a->data[i]->key;
        const uint32_t klen = buffer_clen(key);
        if (klen <= blen
            && 0 == memcmp((*(key->ptr) == '/' ? b->ptr : b->ptr + blen - klen),
                           key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}
