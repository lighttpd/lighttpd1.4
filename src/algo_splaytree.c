/*
           An implementation of top-down splaying with sizes
             D. Sleator <sleator@cs.cmu.edu>, January 1994.

  This extends top-down-splay.c to maintain a size field in each node.
  This is the number of nodes in the subtree rooted there.  This makes
  it possible to efficiently compute the rank of a key.  (The rank is
  the number of nodes to the left of the given key.)  It it also
  possible to quickly find the node of a given rank.  Both of these
  operations are illustrated in the code below.  The remainder of this
  introduction is taken from top-down-splay.c.

    [[ XXX: size maintenance has been removed; not used in lighttpd ]]

  "Splay trees", or "self-adjusting search trees" are a simple and
  efficient data structure for storing an ordered set.  The data
  structure consists of a binary tree, with no additional fields.  It
  allows searching, insertion, deletion, deletemin, deletemax,
  splitting, joining, and many other operations, all with amortized
  logarithmic performance.  Since the trees adapt to the sequence of
  requests, their performance on real access patterns is typically even
  better.  Splay trees are described in a number of texts and papers
  [1,2,3,4].

  The code here is adapted from simple top-down splay, at the bottom of
  page 669 of [2].  It can be obtained via anonymous ftp from
  spade.pc.cs.cmu.edu in directory /usr/sleator/public.

  The chief modification here is that the splay operation works even if the
  item being splayed is not in the tree, and even if the tree root of the
  tree is NULL.  So the line:

                              t = splay(i, t);

  causes it to search for item with key i in the tree rooted at t.  If it's
  there, it is splayed to the root.  If it isn't there, then the node put
  at the root is the last one before NULL that would have been reached in a
  normal binary search for i.  (It's a neighbor of i in the tree.)  This
  allows many other operations to be easily implemented, as shown below.

  [1] "Data Structures and Their Algorithms", Lewis and Denenberg,
       Harper Collins, 1991, pp 243-251.
  [2] "Self-adjusting Binary Search Trees" Sleator and Tarjan,
       JACM Volume 32, No 3, July 1985, pp 652-686.
  [3] "Data Structure and Algorithm Analysis", Mark Weiss,
       Benjamin Cummins, 1992, pp 119-130.
  [4] "Data Structures, Algorithms, and Performance", Derick Wood,
       Addison-Wesley, 1993, pp 367-375
*/

#include "algo_splaytree.h"
#include <stdlib.h>
#include <assert.h>

#define compare(i,j) ((int)(((unsigned int)i)-((unsigned int)j)))
/* This is the comparison.                                       */
/* Returns <0 if i<j, =0 if i=j, and >0 if i>j                   */
/* (cast to unsigned int for underflow/overflow defined behavior)*/

/* Splay using the key i (which may or may not be in the tree.)
 * The starting root is t, and the tree used is defined by rat
 */
__attribute_noinline__
__attribute_nonnull__()
__attribute_returns_nonnull__
splay_tree * splaytree_splay_nonnull (splay_tree *t, int i) {
    splay_tree N, *l, *r, *y;

    N.left = N.right = NULL;
    l = r = &N;

    for (;;) {
        if (i < t->key) {
            if (t->left == NULL) break;
            if (i < t->left->key) {
                y = t->left;                           /* rotate right */
                t->left = y->right;
                y->right = t;
                t = y;
                if (t->left == NULL) break;
            }
            r->left = t;                               /* link right */
            r = t;
            t = t->left;
        } else if (i > t->key) {
            if (t->right == NULL) break;
            if (i > t->right->key) {
                y = t->right;                          /* rotate left */
                t->right = y->left;
                y->left = t;
                t = y;
                if (t->right == NULL) break;
            }
            l->right = t;                              /* link left */
            l = t;
            t = t->right;
        } else {
            break;
        }
    }

    l->right = t->left;                                /* assemble */
    r->left = t->right;
    t->left = N.right;
    t->right = N.left;

    return t;
}

splay_tree * splaytree_insert_splayed(splay_tree * t, int i, void *data) {
/* Insert key i into (already) splayed tree t.               */
/* Return a pointer to the resulting tree.                   */
    splay_tree * const new = (splay_tree *) malloc (sizeof (splay_tree));
    assert(new);
    if (t == NULL) {
	new->left = new->right = NULL;
    } else if (i < t->key) {
	new->left = t->left;
	new->right = t;
	t->left = NULL;
    } else {
	new->right = t->right;
	new->left = t;
	t->right = NULL;
    }
    new->key = i;
    new->data = data;
    return new;
}

splay_tree * splaytree_insert(splay_tree * t, int i, void *data) {
/* Insert key i into the tree t, if it is not already there. */
/* Return a pointer to the resulting tree.                   */
    return (t != NULL && (t = splaytree_splay_nonnull(t, i))->key == i)
      ? t
      : splaytree_insert_splayed(t, i, data);
}

__attribute_noinline__
__attribute_nonnull__()
splay_tree * splaytree_delete_splayed_node(splay_tree *t) {
/* Deletes (already) splayed node at the root of tree.  */
/* Return a pointer to the resulting tree.              */
    splay_tree * x = t->right;
    if (t->left != NULL) {
        x = splaytree_splay_nonnull(t->left, t->key);
	x->right = t->right;
    }
    free(t);
    return x;
}

splay_tree * splaytree_delete(splay_tree *t, int i) {
/* Deletes i from the tree if it's there.               */
/* Return a pointer to the resulting tree.              */
    return (t != NULL && (t = splaytree_splay_nonnull(t, i))->key == i)
      ? splaytree_delete_splayed_node(t)
      : t;
}
