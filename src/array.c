#include "first.h"

#include "array.h"
#include "buffer.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <errno.h>
#include <assert.h>

#define ARRAY_NOT_FOUND ((size_t)(-1))

array *array_init(void) {
	array *a;

	a = calloc(1, sizeof(*a));
	force_assert(a);

	return a;
}

array *array_init_array(array *src) {
	size_t i;
	array *a = array_init();

	if (0 == src->size) return a;

	a->used = src->used;
	a->size = src->size;
	a->unique_ndx = src->unique_ndx;

	a->data = malloc(sizeof(*src->data) * src->size);
	force_assert(NULL != a->data);
	for (i = 0; i < src->size; i++) {
		if (src->data[i]) a->data[i] = src->data[i]->fn->copy(src->data[i]);
		else a->data[i] = NULL;
	}

	a->sorted = malloc(sizeof(*src->sorted) * src->size);
	force_assert(NULL != a->sorted);
	memcpy(a->sorted, src->sorted, sizeof(*src->sorted) * src->size);
	return a;
}

void array_free(array *a) {
	size_t i;
	if (!a) return;

	for (i = 0; i < a->size; i++) {
		if (a->data[i]) a->data[i]->fn->free(a->data[i]);
	}

	if (a->data) free(a->data);
	if (a->sorted) free(a->sorted);

	free(a);
}

void array_reset(array *a) {
	size_t i;
	if (!a) return;

	for (i = 0; i < a->used; i++) {
		a->data[i]->fn->reset(a->data[i]);
		a->data[i]->is_index_key = 0;
	}

	a->used = 0;
	a->unique_ndx = 0;
}

void array_reset_data_strings(array *a) {
	if (!a) return;

	for (size_t i = 0; i < a->used; ++i) {
		data_string * const ds = (data_string *)a->data[i];
		/*force_assert(ds->type == TYPE_STRING);*/
		ds->is_index_key = 0;
		buffer_reset(ds->key);
		buffer_reset(ds->value);
	}

	a->used = 0;
	a->unique_ndx = 0;
}

data_unset *array_pop(array *a) {
	data_unset *du;

	force_assert(a->used != 0);

	a->used --;
	du = a->data[a->used];
	force_assert(a->sorted[a->used] == a->used); /* only works on "simple" lists */
	a->data[a->used] = NULL;

	return du;
}

__attribute_pure__
static int array_caseless_compare(const char * const a, const char * const b, const size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned int ca = ((unsigned char *)a)[i];
        unsigned int cb = ((unsigned char *)b)[i];
        if (ca == cb) continue;

        /* always lowercase for transitive results */
        if (ca >= 'A' && ca <= 'Z') ca |= 32;
        if (cb >= 'A' && cb <= 'Z') cb |= 32;

        if (ca == cb) continue;
        return (int)(ca - cb);
    }
    return 0;
}

__attribute_pure__
static int array_keycmp(const char *a, size_t alen, const char *b, size_t blen) {
    return alen < blen ? -1 : alen > blen ? 1 : array_caseless_compare(a, b, blen);
}

/* returns index of element or ARRAY_NOT_FOUND
 * if rndx != NULL it stores the position in a->sorted[] where the key needs
 * to be inserted
 */
static size_t array_get_index(const array *a, const char *key, size_t keylen, size_t *rndx) {
	/* invariant: [lower-1] < key < [upper]
	 * "virtual elements": [-1] = -INFTY, [a->used] = +INFTY
	 * also an invariant: 0 <= lower <= upper <= a->used
	 */
	size_t lower = 0, upper = a->used;
	force_assert(upper <= SSIZE_MAX); /* (lower + upper) can't overflow */

	while (lower != upper) {
		size_t probe = (lower + upper) / 2;
		const buffer *b = a->data[a->sorted[probe]]->key;
		int cmp = array_keycmp(key, keylen, CONST_BUF_LEN(b));

		if (cmp == 0) {
			/* found */
			if (rndx) *rndx = probe;
			return a->sorted[probe];
		} else if (cmp < 0) {
			/* key < [probe] */
			upper = probe; /* still: lower <= upper */
		} else {
			/* key > [probe] */
			lower = probe + 1; /* still: lower <= upper */
		}
	}

	/* not found: [lower-1] < key < [upper] = [lower] ==> insert at [lower] */
	if (rndx) *rndx = lower;
	return ARRAY_NOT_FOUND;
}

data_unset *array_get_element_klen(const array *a, const char *key, size_t klen) {
	size_t ndx;
	force_assert(NULL != key);

	if (ARRAY_NOT_FOUND != (ndx = array_get_index(a, key, klen, NULL))) {
		/* found, return it */
		return a->data[ndx];
	}

	return NULL;
}

data_unset *array_extract_element_klen(array *a, const char *key, size_t klen) {
	size_t ndx, pos;
	force_assert(NULL != key);

	if (ARRAY_NOT_FOUND != (ndx = array_get_index(a, key, klen, &pos))) {
		/* found */
		const size_t last_ndx = a->used - 1;
		data_unset *entry = a->data[ndx];

		/* now we need to swap it with the last element (if it isn't already the last element) */
		if (ndx != last_ndx) {
			/* to swap we also need to modify the index in a->sorted - find pos of last_elem there */
			size_t last_elem_pos;
			/* last element must be present at the expected position */
			force_assert(last_ndx == array_get_index(a, CONST_BUF_LEN(a->data[last_ndx]->key), &last_elem_pos));

			/* move entry from last_ndx to ndx */
			a->data[ndx] = a->data[last_ndx];
			a->data[last_ndx] = NULL;

			/* fix index entry for moved entry */
			a->sorted[last_elem_pos] = ndx;
		} else {
			a->data[ndx] = NULL;
		}

		/* remove entry in a->sorted: move everything after pos one step to the left */
		if (pos != last_ndx) {
			memmove(a->sorted + pos, a->sorted + pos + 1, (last_ndx - pos) * sizeof(*a->sorted));
		}
		a->sorted[last_ndx] = ARRAY_NOT_FOUND;
		--a->used;

		return entry;
	}

	return NULL;
}

static data_unset *array_get_unused_element(array *a, data_type_t t) {
	data_unset *ds = NULL;
	unsigned int i;

	for (i = a->used; i < a->size; i++) {
		if (a->data[i] && a->data[i]->type == t) {
			ds = a->data[i];

			/* make empty slot at a->used for next insert */
			a->data[i] = a->data[a->used];
			a->data[a->used] = NULL;

			return ds;
		}
	}

	return NULL;
}

void array_set_key_value(array *hdrs, const char *key, size_t key_len, const char *value, size_t val_len) {
	data_string *ds;

	if (NULL != (ds = (data_string *)array_get_element_klen(hdrs, key, key_len))) {
		buffer_copy_string_len(ds->value, value, val_len);
		return;
	}

	array_insert_key_value(hdrs, key, key_len, value, val_len);
}

void array_insert_key_value(array *hdrs, const char *key, size_t key_len, const char *value, size_t val_len) {
	data_string *ds;

	if (NULL == (ds = (data_string *)array_get_unused_element(hdrs, TYPE_STRING))) {
		ds = data_string_init();
	}

	buffer_copy_string_len(ds->key, key, key_len);
	buffer_copy_string_len(ds->value, value, val_len);
	array_insert_unique(hdrs, (data_unset *)ds);
}

void array_insert_value(array *hdrs, const char *value, size_t val_len) {
	data_string *ds;

	if (NULL == (ds = (data_string *)array_get_unused_element(hdrs, TYPE_STRING))) {
		ds = data_string_init();
	}

	buffer_copy_string_len(ds->value, value, val_len);
	array_insert_unique(hdrs, (data_unset *)ds);
}

int * array_get_int_ptr(array *a, const char *k, size_t klen) {
	data_integer *di = (data_integer *)array_get_element_klen(a, k, klen);

	if (NULL == di) {
		di = (data_integer *)array_get_unused_element(a, TYPE_INTEGER);
		if (NULL == di) di = data_integer_init();
		buffer_copy_string_len(di->key, k, klen);
		array_insert_unique(a, (data_unset *)di);
	}

	return &di->value;
}

/* if entry already exists return pointer to existing entry, otherwise insert entry and return NULL */
static data_unset **array_find_or_insert(array *a, data_unset *entry) {
	size_t ndx, pos, j;

	/* generate unique index if neccesary */
	if (buffer_is_empty(entry->key) || entry->is_index_key) {
		buffer_copy_int(entry->key, a->unique_ndx++);
		entry->is_index_key = 1;
		force_assert(0 != a->unique_ndx); /* must not wrap or we'll get problems */
	}

	/* try to find the entry */
	if (ARRAY_NOT_FOUND != (ndx = array_get_index(a, CONST_BUF_LEN(entry->key), &pos))) {
		/* found collision, return it */
		return &a->data[ndx];
	}

	/* insert */

	/* there couldn't possibly be enough memory to store so many entries */
	force_assert(a->used + 1 <= SSIZE_MAX);

	if (a->size == a->used) {
		a->size  += 16;
		a->data   = realloc(a->data,   sizeof(*a->data)   * a->size);
		a->sorted = realloc(a->sorted, sizeof(*a->sorted) * a->size);
		force_assert(a->data);
		force_assert(a->sorted);
		for (j = a->used; j < a->size; j++) a->data[j] = NULL;
	}

	ndx = a->used;

	/* make sure there is nothing here */
	if (a->data[ndx]) a->data[ndx]->fn->free(a->data[ndx]);

	a->data[a->used++] = entry;

	/* move everything one step to the right */
	if (pos != ndx) {
		memmove(a->sorted + (pos + 1), a->sorted + (pos), (ndx - pos) * sizeof(*a->sorted));
	}

	/* insert */
	a->sorted[pos] = ndx;

	return NULL;
}

/* replace or insert data (free existing entry) */
void array_replace(array *a, data_unset *entry) {
	data_unset **old;

	force_assert(NULL != entry);
	if (NULL != (old = array_find_or_insert(a, entry))) {
		force_assert(*old != entry);
		(*old)->fn->free(*old);
		*old = entry;
	}
}

void array_insert_unique(array *a, data_unset *entry) {
	data_unset **old;

	force_assert(NULL != entry);
	if (NULL != (old = array_find_or_insert(a, entry))) {
		force_assert((*old)->type == entry->type);
		entry->fn->insert_dup(*old, entry);
	}
}

int array_is_vlist(array *a) {
	for (size_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (!du->is_index_key || du->type != TYPE_STRING) return 0;
	}
	return 1;
}

int array_is_kvany(array *a) {
	for (size_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (du->is_index_key) return 0;
	}
	return 1;
}

int array_is_kvarray(array *a) {
	for (size_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (du->is_index_key || du->type != TYPE_ARRAY) return 0;
	}
	return 1;
}

int array_is_kvstring(array *a) {
	for (size_t i = 0; i < a->used; ++i) {
		data_unset *du = a->data[i];
		if (du->is_index_key || du->type != TYPE_STRING) return 0;
	}
	return 1;
}

/* array_match_*() routines follow very similar pattern, but operate on slightly
 * different data: array key/value, prefix/suffix match, case-insensitive or not
 * While these could be combined into fewer routines with flags to modify the
 * behavior, the interface distinctions are useful to add clarity to the code,
 * and the specialized routines run slightly faster */

data_unset *
array_match_key_prefix_klen (const array * const a, const char * const s, const size_t slen)
{
    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const key = a->data[i]->key;
        const size_t klen = buffer_string_length(key);
        if (klen <= slen && 0 == memcmp(s, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

data_unset *
array_match_key_prefix_nc_klen (const array * const a, const char * const s, const size_t slen)
{
    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const key = a->data[i]->key;
        const size_t klen = buffer_string_length(key);
        if (klen <= slen && buffer_eq_icase_ssn(s, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

data_unset *
array_match_key_prefix (const array * const a, const buffer * const b)
{
    return array_match_key_prefix_klen(a, CONST_BUF_LEN(b));
}

data_unset *
array_match_key_prefix_nc (const array * const a, const buffer * const b)
{
    return array_match_key_prefix_nc_klen(a, CONST_BUF_LEN(b));
}

const buffer *
array_match_value_prefix (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);

    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const value = ((data_string *)a->data[i])->value;
        const size_t vlen = buffer_string_length(value);
        if (vlen <= blen && 0 == memcmp(b->ptr, value->ptr, vlen))
            return value;
    }
    return NULL;
}

const buffer *
array_match_value_prefix_nc (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);

    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const value = ((data_string *)a->data[i])->value;
        const size_t vlen = buffer_string_length(value);
        if (vlen <= blen && buffer_eq_icase_ssn(b->ptr, value->ptr, vlen))
            return value;
    }
    return NULL;
}

data_unset *
array_match_key_suffix (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);
    const char * const end = b->ptr + blen;

    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const key = a->data[i]->key;
        const size_t klen = buffer_string_length(key);
        if (klen <= blen && 0 == memcmp(end - klen, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

data_unset *
array_match_key_suffix_nc (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);
    const char * const end = b->ptr + blen;

    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const key = a->data[i]->key;
        const size_t klen = buffer_string_length(key);
        if (klen <= blen && buffer_eq_icase_ssn(end - klen, key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}

const buffer *
array_match_value_suffix (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);
    const char * const end = b->ptr + blen;

    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const value = ((data_string *)a->data[i])->value;
        const size_t vlen = buffer_string_length(value);
        if (vlen <= blen && 0 == memcmp(end - vlen, value->ptr, vlen))
            return value;
    }
    return NULL;
}

const buffer *
array_match_value_suffix_nc (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);
    const char * const end = b->ptr + blen;

    for (size_t i = 0; i < a->used; ++i) {
        const buffer * const value = ((data_string *)a->data[i])->value;
        const size_t vlen = buffer_string_length(value);
        if (vlen <= blen && buffer_eq_icase_ssn(end - vlen, value->ptr, vlen))
            return value;
    }
    return NULL;
}

data_unset *
array_match_path_or_ext (const array * const a, const buffer * const b)
{
    const size_t blen = buffer_string_length(b);

    for (size_t i = 0; i < a->used; ++i) {
        /* check extension in the form "^/path" or ".ext$" */
        const buffer * const key = a->data[i]->key;
        const size_t klen = buffer_string_length(key);
        if (klen <= blen
            && 0 == memcmp((*(key->ptr) == '/' ? b->ptr : b->ptr + blen - klen),
                           key->ptr, klen))
            return a->data[i];
    }
    return NULL;
}





#include <stdio.h>

void array_print_indent(int depth) {
	int i;
	for (i = 0; i < depth; i ++) {
		fprintf(stdout, "    ");
	}
}

size_t array_get_max_key_length(array *a) {
	size_t maxlen, i;

	maxlen = 0;
	for (i = 0; i < a->used; i ++) {
		data_unset *du = a->data[i];
		size_t len = buffer_string_length(du->key);

		if (len > maxlen) {
			maxlen = len;
		}
	}
	return maxlen;
}

int array_print(array *a, int depth) {
	size_t i;
	size_t maxlen;
	int oneline = 1;

	if (a->used > 5) {
		oneline = 0;
	}
	for (i = 0; i < a->used && oneline; i++) {
		data_unset *du = a->data[i];
		if (!du->is_index_key) {
			oneline = 0;
			break;
		}
		switch (du->type) {
			case TYPE_INTEGER:
			case TYPE_STRING:
				break;
			default:
				oneline = 0;
				break;
		}
	}
	if (oneline) {
		fprintf(stdout, "(");
		for (i = 0; i < a->used; i++) {
			data_unset *du = a->data[i];
			if (i != 0) {
				fprintf(stdout, ", ");
			}
			du->fn->print(du, depth + 1);
		}
		fprintf(stdout, ")");
		return 0;
	}

	maxlen = array_get_max_key_length(a);
	fprintf(stdout, "(\n");
	for (i = 0; i < a->used; i++) {
		data_unset *du = a->data[i];
		array_print_indent(depth + 1);
		if (!du->is_index_key) {
			int j;

			if (i && (i % 5) == 0) {
				fprintf(stdout, "# %zu\n", i);
				array_print_indent(depth + 1);
			}
			fprintf(stdout, "\"%s\"", du->key->ptr);
			for (j = maxlen - buffer_string_length(du->key); j > 0; j--) {
				fprintf(stdout, " ");
			}
			fprintf(stdout, " => ");
		}
		du->fn->print(du, depth + 1);
		fprintf(stdout, ",\n");
	}
	if (!(i && (i - 1 % 5) == 0)) {
		array_print_indent(depth + 1);
		fprintf(stdout, "# %zu\n", i);
	}
	array_print_indent(depth);
	fprintf(stdout, ")");

	return 0;
}
