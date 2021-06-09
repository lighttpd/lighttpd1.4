/*
 * http_etag - HTTP ETag manipulation
 *
 * Copyright(c) 2015,2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_etag.h"

#include <sys/stat.h>
#include <string.h>

#include "algo_md.h"
#include "buffer.h"

int
http_etag_matches (const buffer * const etag, const char *s, const int weak_ok)
{
    if ('*' == s[0] && '\0' == s[1]) return 1;
    if (buffer_is_blank(etag)) return 0;

    uint32_t etag_sz = buffer_clen(etag);
    const char *etag_ptr = etag->ptr;

    if (etag_ptr[0] == 'W' && etag_ptr[1] == '/') {
        if (!weak_ok) return 0;
        etag_ptr += 2;
        etag_sz  -= 2;
    }

    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == ',') ++s;
        if (s[0] == 'W' && s[1] == '/' ? (s+=2, weak_ok) : 1) {
            if (0 == strncmp(s, etag_ptr, etag_sz) || *s == '*') {
                s += (*s != '*' ? etag_sz : 1);
                if (*s == '\0' || *s == ' ' || *s == '\t' || *s == ',')
                    return 1;
            }
        }
        while (*s != '\0' && *s != ',') ++s;
    }
    return 0;
}

static void
http_etag_remix (buffer * const etag, const char * const str, const uint32_t len)
{
    uint32_t h = dekhash(str, len, len); /*(pass len as initial hash value)*/
  #if 0 /*(currently never elen > 2; always cleared in http_etag_create())*/
    uint32_t elen = buffer_clen(etag);
    if (elen > 2) {/*(expect "..." if set)*/
        h = dekhash(etag->ptr+1, elen-2, h);
        buffer_truncate(etag, 1);
    }
    else
        buffer_copy_string_len(etag, CONST_STR_LEN("\""));
  #else
    buffer_copy_string_len(etag, CONST_STR_LEN("\""));
  #endif
    buffer_append_int(etag, h);
    buffer_append_string_len(etag, CONST_STR_LEN("\""));
}

void
http_etag_create (buffer * const etag, const struct stat * const st, const int flags)
{
    if (0 == flags) return;

    uint64_t x[4];
    uint32_t len = 0;

    if (flags & ETAG_USE_INODE)
        x[len++] = (uint64_t)st->st_ino;

    if (flags & ETAG_USE_SIZE)
        x[len++] = (uint64_t)st->st_size;

    if (flags & ETAG_USE_MTIME) {
        x[len++] = (uint64_t)st->st_mtime;
      #ifdef st_mtime /* use high-precision timestamp if available */
      #if defined(__APPLE__) && defined(__MACH__)
        x[len++] = (uint64_t)st->st_mtimespec.tv_nsec;
      #else
        x[len++] = (uint64_t)st->st_mtim.tv_nsec;
      #endif
      #endif
    }

    buffer_clear(etag);
    http_etag_remix(etag, (char *)x, len << 3);
}
