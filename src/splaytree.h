#ifndef _SPLAY_TREE_H_
#define _SPLAY_TREE_H_
#include "first.h"

typedef struct tree_node {
    struct tree_node * left, * right;
    int key;
    int size;   /* maintained to be the number of nodes rooted here */

    void *data;
} splay_tree;


splay_tree * splaytree_splay (splay_tree *t, int key);
splay_tree * splaytree_insert(splay_tree *t, int key, void *data);
splay_tree * splaytree_delete(splay_tree *t, int key);
splay_tree * splaytree_size(splay_tree *t);

#define splaytree_size(x) (((x)==NULL) ? 0 : ((x)->size))
/* This macro returns the size of a node.  Unlike "x->size",     */
/* it works even if x=NULL.  The test could be avoided by using  */
/* a special version of NULL which was a real node with size 0.  */


__attribute_pure__
static inline uint32_t djbhash(const char *str, const uint32_t len, uint32_t hash);

__attribute_pure__
static inline int32_t splaytree_djbhash(const char *str, const uint32_t len);


/* the famous DJB hash function for strings */
#define DJBHASH_INIT 5381
static inline uint32_t djbhash(const char *str, const uint32_t len, uint32_t hash)
{
    const unsigned char * const s = (const unsigned char *)str;
    for (uint32_t i = 0; i < len; ++i) hash = ((hash << 5) + hash) ^ s[i];
    return hash;
}


static inline int32_t splaytree_djbhash(const char *str, const uint32_t len)
{
    /* strip highest bit of hash value for splaytree */
    return (int32_t)(djbhash(str,len,DJBHASH_INIT) & ~(((uint32_t)1) << 31));
}


#endif
