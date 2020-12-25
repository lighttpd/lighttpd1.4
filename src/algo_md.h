/* algo_md.h - message digest (MD) wrapper (non-cryptographic)
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_ALGO_MD_H
#define INCLUDED_ALGO_MD_H
#include "first.h"


/*
 * not cryptographically secure (and never intended to be)
 */


/* DJB hash function for strings (djb2a) */
#define DJBHASH_INIT 5381
__attribute_pure__
static inline uint32_t djbhash(const char *str, const uint32_t len, uint32_t hash);
static inline uint32_t djbhash(const char *str, const uint32_t len, uint32_t hash)
{
    const unsigned char * const s = (const unsigned char *)str;
    for (uint32_t i = 0; i < len; ++i) hash = ((hash << 5) + hash) ^ s[i];
    return hash;
}


/* Donald E. Knuth
 * The Art Of Computer Programming Volume 3
 * Chapter 6.4, Topic: Sorting and Search */
/*(len should be passed as initial hash value.
 * On subsequent calls, pass intermediate hash value for incremental hashing)*/
__attribute_pure__
static inline uint32_t dekhash (const char *str, const uint32_t len, uint32_t hash);
static inline uint32_t dekhash (const char *str, const uint32_t len, uint32_t hash)
{
    const unsigned char * const s = (const unsigned char *)str;
    for (uint32_t i = 0; i < len; ++i) hash = (hash << 5) ^ (hash >> 27) ^ s[i];
    return hash;
}


#endif /* INCLUDED_ALGO_MD_H */
