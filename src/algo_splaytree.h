#ifndef _SPLAY_TREE_H_
#define _SPLAY_TREE_H_
#include "first.h"

typedef struct tree_node {
    struct tree_node * left, * right;
    int key;
    void *data;
} splay_tree;

__attribute_nonnull__()
__attribute_returns_nonnull__
splay_tree * splaytree_splay_nonnull (splay_tree *t, int key);

static inline splay_tree * splaytree_splay (splay_tree *t, int key);
static inline splay_tree * splaytree_splay (splay_tree *t, int key) {
    if (t == NULL || key == t->key) return t;
    return splaytree_splay_nonnull(t, key);
}

__attribute_returns_nonnull__
splay_tree * splaytree_insert_splayed(splay_tree * t, int key, void *data);

__attribute_returns_nonnull__
splay_tree * splaytree_insert(splay_tree *t, int key, void *data);

__attribute_nonnull__()
splay_tree * splaytree_delete_splayed_node(splay_tree *t);

splay_tree * splaytree_delete(splay_tree *t, int key);


#include "algo_md.h"

__attribute_pure__
static inline int32_t splaytree_djbhash(const char *str, const uint32_t len);
static inline int32_t splaytree_djbhash(const char *str, const uint32_t len)
{
    return (int32_t)djbhash(str, len, DJBHASH_INIT);
}


#endif
