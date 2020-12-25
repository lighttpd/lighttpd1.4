/*
 * http_etag - HTTP ETag manipulation
 *
 * Copyright(c) 2015,2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_HTTP_ETAG_H
#define INCLUDED_HTTP_ETAG_H
#include "first.h"

#include "buffer.h"

#ifdef _AIX
#include <sys/stat.h>
#else
struct stat;            /* declaration */
#endif

typedef enum { ETAG_USE_INODE = 1, ETAG_USE_MTIME = 2, ETAG_USE_SIZE = 4 } etag_flags_t;

__attribute_pure__
int http_etag_matches (const buffer *etag, const char *matches, int weak_ok);

void http_etag_create (buffer *etag, const struct stat *st, int flags);


#endif
