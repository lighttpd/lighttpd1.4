#include "first.h"

#include "rand.h"
#include "base.h"
#include "fdevent.h"
#include "safe_memclear.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_OPENSSL
#include <openssl/rand.h>
#endif
#ifdef HAVE_LINUX_RANDOM_H
#include <sys/syscall.h>
#include <linux/random.h>
#endif
#ifdef RNDGETENTCNT
#include <sys/ioctl.h>
#endif

/* Take some reasonable steps to attempt to *seed* random number generators with
 * cryptographically random data.  Some of these initialization routines may
 * block, and are intended to be called only at startup in lighttpd, or
 * immediately after fork() to start lighttpd workers.
 *
 * Note: results from li_rand() are not necessarily cryptographically random.
 *
 * https://wiki.openssl.org/index.php/Random_Numbers
 * https://wiki.openssl.org/index.php/Random_fork-safety
 *
 * openssl random number generators are not thread-safe by default
 * https://wiki.openssl.org/index.php/Manual:Threads(3)
 *
 * RFE: add more paranoid checks from the following to improve confidence:
 * http://insanecoding.blogspot.co.uk/2014/05/a-good-idea-with-bad-usage-devurandom.html
 * RFE: retry on EINTR
 * RFE: check RAND_status()
 */

static int li_getentropy (void *buf, size_t buflen)
{
  #ifdef HAVE_GETENTROPY
    return getentropy(buf, buflen);
  #else
    /*(see NOTES section in 'man getrandom' on Linux)*/
   #if defined(HAVE_GETRANDOM) || defined(SYS_getrandom)
    if (buflen <= 256) {
      #ifdef HAVE_GETRANDOM /*(not implemented in glibc yet)*/
        int num = getrandom(buf, buflen, 0);
      #elif defined(SYS_getrandom)
        /* https://lwn.net/Articles/605828/ */
        /* https://bbs.archlinux.org/viewtopic.php?id=200039 */
        int num = (int)syscall(SYS_getrandom, buf, buflen, 0);
      #endif
        if (num == (int)buflen) return 0;
        if (num < 0)            return num; /* -1 */
    }
   #else
    UNUSED(buf);
    UNUSED(buflen);
   #endif
    errno = EIO;
    return -1;
  #endif
}

static int li_rand_device_bytes (unsigned char *buf, int num)
{
    /* randomness from these devices is cryptographically strong,
     * unless /dev/urandom is low on entropy */

    static const char * const devices[] = {
      #ifdef __OpenBSD__
        "/dev/arandom",
      #endif
        "/dev/urandom",
        "/dev/random"
    };

    /* device files might not be available in chroot environment,
     * so prefer syscall, if available */
    if (0 == li_getentropy(buf, (size_t)num)) return 1;

    for (unsigned int u = 0; u < sizeof(devices)/sizeof(devices[0]); ++u) {
        /*(some systems might have symlink to another device; omit O_NOFOLLOW)*/
        int fd = fdevent_open_cloexec(devices[u], O_RDONLY, 0);
        if (fd >= 0) {
            ssize_t rd = 0;
          #ifdef RNDGETENTCNT
            int entropy;
            if (0 == ioctl(fd, RNDGETENTCNT, &entropy) && entropy >= num*8)
          #endif
                rd = read(fd, buf, (size_t)num);
            close(fd);
            if (rd == num) {
                return 1;
            }
        }
    }

    return 0;
}

static unsigned short xsubi[3];

void li_rand_reseed (void)
{
    /* (intended to be called at init and after fork() in order to re-seed PRNG
     *  so that forked children, grandchildren, etc do not share PRNG seed)
     * https://github.com/ramsey/uuid/issues/80
     * https://www.agwa.name/blog/post/libressls_prng_is_unsafe_on_linux
     *   (issue in early version of libressl has since been fixed)
     * https://github.com/libressl-portable/portable/commit/32d9eeeecf4e951e1566d5f4a42b36ea37b60f35
     */
    unsigned int u;
    if (1 == li_rand_device_bytes((unsigned char *)xsubi, (int)sizeof(xsubi))) {
        u = ((unsigned int)xsubi[0] << 16) | xsubi[1];
        srand(u); /*(initialize just in case rand() used elsewhere)*/
    }
    else {
      #ifdef HAVE_ARC4RANDOM
        srand(arc4random()); /*(initialize just in case rand() used elsewhere)*/
        arc4random_buf(xsubi, sizeof(xsubi));
      #else
        /* NOTE: not cryptographically random !!! */
        srand((unsigned int)(time(NULL) ^ getpid()));
        for (u = 0; u < sizeof(unsigned short); ++u)
            xsubi[u] = (unsigned short)(rand() & 0xFFFF);
      #endif
    }
  #ifdef USE_OPENSSL
    RAND_poll();
    RAND_seed(xsubi, (int)sizeof(xsubi));
  #endif
}

int li_rand (void)
{
    /* randomness *is not* cryptographically strong */
    /* (attempt to use better mechanisms to replace the more portable rand()) */
  #ifdef USE_OPENSSL
    int i;
    if (-1 != RAND_pseudo_bytes((unsigned char *)&i, sizeof(i))) return i;
  #endif
  #ifdef HAVE_ARC4RANDOM
    return (int)arc4random();
  #endif
  #ifdef HAVE_JRAND48
    /*(FYI: jrand48() reentrant, but use of file-scoped static xsubi[] is not)*/
    return (int)jrand48(xsubi);
  #else
    return rand();
  #endif
}

int li_rand_bytes (unsigned char *buf, int num)
{
  #ifdef USE_OPENSSL
    int rc = RAND_bytes(buf, num);
    if (-1 != rc) {
        return rc;
    }
  #endif
    if (1 == li_rand_device_bytes(buf, num)) {
        return 1;
    }
    else {
        /* NOTE: not cryptographically random !!! */
        for (int i = 0; i < num; ++i)
            buf[i] = li_rand() & 0xFF;
        /*(openssl RAND_pseudo_bytes rc for non-cryptographically random data)*/
        return 0;
    }
}

void li_rand_cleanup (void)
{
  #ifdef USE_OPENSSL
    RAND_cleanup();
  #endif
    safe_memclear(xsubi, sizeof(xsubi));
}
