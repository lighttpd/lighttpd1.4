#ifndef LI_VECTOR_H
#define LI_VECTOR_H
#include "first.h"

#include "ck.h"         /* ck_assert() */

static inline size_t vector_align_size(size_t s) {
	size_t a = (s + 15) & ~(size_t)15uL;
	return (a < s) ? s : a;
}

void vector_free(void *data);

__attribute_malloc__
void *vector_malloc(size_t sz);

__attribute_returns_nonnull__
void *vector_realloc(void *data, size_t elem_size, size_t size, size_t used);

#define DEFINE_TYPED_VECTOR(name, entry, release) \
	typedef struct vector_ ## name { \
		entry* data; \
		size_t used; \
		size_t size; \
	} vector_ ## name; \
	static inline void vector_ ## name ## _init(vector_ ## name *v) { \
		v->data = NULL; \
		v->used = v->size = 0; \
	} \
	__attribute_malloc__ \
	__attribute_returns_nonnull__ \
	static inline vector_ ## name *vector_ ## name ## _alloc() { \
		vector_ ## name *v = vector_malloc(sizeof(*v)); \
		ck_assert(NULL != v); \
		vector_ ## name ## _init(v); \
		return v; \
	} \
	static inline void vector_ ## name ## _clear(vector_ ## name *v) { \
		if (release) for (size_t i = 0; i < v->used; ++i) release(v->data[i]); \
		vector_free(v->data); \
		vector_ ## name ## _init(v); \
	} \
	static inline void vector_ ## name ## _free(vector_ ## name *v) { \
		if (NULL != v) { \
			vector_ ## name ## _clear(v); \
			vector_free(v); \
		} \
	} \
	static inline void vector_ ## name ## _reserve(vector_ ## name *v, size_t p) { \
		if (v->size - v->used < p) { \
			ck_assert(v->used < SIZE_MAX - p); \
			v->size = vector_align_size(v->used + p); \
			v->data = vector_realloc(v->data, sizeof(entry), v->size, v->used); \
		} \
	} \
	static inline void vector_ ## name ## _push(vector_ ## name *v, entry e) { \
		vector_ ## name ## _reserve(v, 1); \
		v->data[v->used++] = e; \
	} \
	static inline entry vector_ ## name ## _pop(vector_ ## name *v) { \
		ck_assert(v->used > 0); \
		return v->data[--v->used]; \
	} \
	struct vector_ ## name /* expect trailing semicolon */ \
	/* end of DEFINE_TYPED_VECTOR */

#define DEFINE_TYPED_VECTOR_NO_RELEASE(name, entry) \
	DEFINE_TYPED_VECTOR(name, entry, ((void(*)(entry)) NULL)) \
	/* end of DEFINE_TYPED_VECTOR_NO_RELEASE */


#endif
