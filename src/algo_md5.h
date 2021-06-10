#ifndef LI_MD5_H
#define LI_MD5_H
#include "first.h"

#include "sys-crypto-md.h"
#ifndef USE_LIB_CRYPTO_MD5

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* MD5 context. */
typedef struct {
  uint32_t state[4];                                /* state (ABCD) */
  uint32_t count[2];     /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

void MD5_Init (MD5_CTX *);
void MD5_Update (MD5_CTX *, const void *, unsigned int);
void MD5_Final (unsigned char [MD5_DIGEST_LENGTH], MD5_CTX *);

#else  /* USE_LIB_CRYPTO_MD5 */

#define li_MD5_CTX    MD5_CTX
#define li_MD5_Init   MD5_Init
#define li_MD5_Update MD5_Update
#define li_MD5_Final  MD5_Final

#endif /* USE_LIB_CRYPTO_MD5 */

#endif
