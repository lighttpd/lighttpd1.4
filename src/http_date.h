/*
 * http_date - HTTP date manipulation
 *
 * Copyright(c) 2015 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#ifndef INCLUDED_HTTP_DATE_H
#define INCLUDED_HTTP_DATE_H
#include "first.h"

#include "sys-time.h"


#ifdef __cplusplus
extern "C" {
#endif


#define HTTP_DATE_SZ 30  /* (IMF-fixdate is 29 chars + '\0') */

uint32_t http_date_time_to_str (char *s, size_t sz, unix_time64_t t);

int http_date_if_modified_since (const char *ifmod, uint32_t ifmodlen, unix_time64_t lmtime);

/*(convenience macro to append IMF-fixdate to (buffer *))*/
#define http_date_time_append(b, t)                                           \
  do {                                                                        \
    if (!http_date_time_to_str(buffer_extend((b), HTTP_DATE_SZ-1),            \
                               HTTP_DATE_SZ, (t)))                            \
        buffer_truncate((b), (b)->used - HTTP_DATE_SZ); /*(truncate if err)*/ \
  } while (0)

#ifdef __cplusplus
}
#endif


#endif
