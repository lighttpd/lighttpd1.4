#ifndef _LIGHTTPD_SETTINGS_H_
#define _LIGHTTPD_SETTINGS_H_
#include "first.h"

#define FILE_CACHE_MAX      16

/**
 * max size of a buffer which will just be reset
 * to ->used = 0 instead of really freeing the buffer
 *
 * 64kB (no real reason, just a guess)
 */
#define BUFFER_MAX_REUSE_SIZE  (4 * 1024)

/* both should be way smaller than SSIZE_MAX :) */
#define MAX_READ_LIMIT (256*1024)
#define MAX_WRITE_LIMIT (256*1024)

/**
 * max size of the HTTP request header
 *
 * 32k should be enough for everything (just a guess)
 *
 */
#define MAX_HTTP_REQUEST_HEADER  (32 * 1024)

#define HTTP_LINGER_TIMEOUT 5

#endif
