#ifndef INCLUDED_ALGO_SHA1_H
#define INCLUDED_ALGO_SHA1_H
#include "first.h"

#include "sys-crypto.h"
#ifdef USE_OPENSSL_CRYPTO

#include <openssl/sha.h>

#else

/*
 * sha.h
 *
 * Originally taken from the public domain SHA1 implementation
 * written by by Steve Reid <steve@edmweb.com>
 *
 * Modified by Aaron D. Gifford <agifford@infowest.com>
 *
 * NO COPYRIGHT - THIS IS 100% IN THE PUBLIC DOMAIN
 *
 * The original unmodified version is available at:
 *    ftp://ftp.funet.fi/pub/crypt/hash/sha/sha1.c
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#include <sys/types.h>

/* Make sure you define these types for your architecture: */
typedef uint32_t sha1_quadbyte;         /* 4 byte type */
typedef unsigned char sha1_byte;        /* single byte type */

#define SHA1_BLOCK_LENGTH   64
#define SHA1_DIGEST_LENGTH  20
/*(added for lighttpd)*/
#define SHA_DIGEST_LENGTH SHA1_DIGEST_LENGTH

/* The SHA1 structure: */
typedef struct _SHA_CTX {
    sha1_quadbyte state[5];
    sha1_quadbyte count[2];
    sha1_byte     buffer[SHA1_BLOCK_LENGTH];
} SHA_CTX;

#ifndef NOPROTO
void SHA1_Init(SHA_CTX *context);
void SHA1_Update(SHA_CTX *context, const sha1_byte *data, unsigned int len);
void SHA1_Final(sha1_byte digest[SHA1_DIGEST_LENGTH], SHA_CTX *context);
#else
void SHA1_Init();
void SHA1_Update();
void SHA1_Final();
#endif

#ifdef __cplusplus
}
#endif

#endif

#endif
