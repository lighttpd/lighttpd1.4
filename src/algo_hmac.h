/* algo_hmac - hash-based message authentication code (HMAC) wrapper
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_ALGO_HMAC_H
#define INCLUDED_ALGO_HMAC_H
#include "first.h"

int
li_hmac_md5 (unsigned char digest[16], /* [MD5_DIGEST_LENGTH] */
             const void * const secret, const uint32_t slen,
             const unsigned char * const msg, const uint32_t mlen);

int
li_hmac_sha1 (unsigned char digest[20], /* [SHA_DIGEST_LENGTH] */
              const void * const secret, const uint32_t slen,
              const unsigned char * const msg, const uint32_t mlen);

int
li_hmac_sha256 (unsigned char digest[32], /* [SHA256_DIGEST_LENGTH] */
                const void * const secret, const uint32_t slen,
                const unsigned char * const msg, const uint32_t mlen);

int
li_hmac_sha512 (unsigned char digest[64], /* [SHA512_DIGEST_LENGTH] */
                const void * const secret, const uint32_t slen,
                const unsigned char * const msg, const uint32_t mlen);


#endif /* INCLUDED_ALGO_HMAC_H */
