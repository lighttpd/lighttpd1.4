/*
 * http_kv - HTTP version, method, status key-value string mapping
 *
 * Fully-rewritten from original
 * Copyright(c) 2018 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_kv.h"
#include "buffer.h"

#include <string.h>

typedef struct {
	int key;
	unsigned int vlen;
	const char *value;
} keyvalue;

/* HTTP version string as SERVER_PROTOCOL string */
static const buffer http_versions[] = { /*(must by ordered by enum)*/
    { CONST_STR_LEN("HTTP/1.0")+1, 0 } /* HTTP_VERSION_1_0 */
   ,{ CONST_STR_LEN("HTTP/1.1")+1, 0 } /* HTTP_VERSION_1_1 */
   ,{ CONST_STR_LEN("HTTP/2.0")+1, 0 } /* HTTP_VERSION_2 */
   ,{ CONST_STR_LEN("HTTP/3.0")+1, 0 } /* HTTP_VERSION_3 */
   ,{ "", 0, 0 }
};

static const buffer http_methods[] = {
	{ CONST_STR_LEN("GET")+1, 0 },
	{ CONST_STR_LEN("HEAD")+1, 0 },
	{ CONST_STR_LEN("QUERY")+1, 0 },
	{ CONST_STR_LEN("POST")+1, 0 },
	{ CONST_STR_LEN("PUT")+1, 0 },
	{ CONST_STR_LEN("DELETE")+1, 0 },
	{ CONST_STR_LEN("CONNECT")+1, 0 },
	{ CONST_STR_LEN("OPTIONS")+1, 0 },
	{ CONST_STR_LEN("TRACE")+1, 0 },
	{ CONST_STR_LEN("ACL")+1, 0 },
	{ CONST_STR_LEN("BASELINE-CONTROL")+1, 0 },
	{ CONST_STR_LEN("BIND")+1, 0 },
	{ CONST_STR_LEN("CHECKIN")+1, 0 },
	{ CONST_STR_LEN("CHECKOUT")+1, 0 },
	{ CONST_STR_LEN("COPY")+1, 0 },
	{ CONST_STR_LEN("LABEL")+1, 0 },
	{ CONST_STR_LEN("LINK")+1, 0 },
	{ CONST_STR_LEN("LOCK")+1, 0 },
	{ CONST_STR_LEN("MERGE")+1, 0 },
	{ CONST_STR_LEN("MKACTIVITY")+1, 0 },
	{ CONST_STR_LEN("MKCALENDAR")+1, 0 },
	{ CONST_STR_LEN("MKCOL")+1, 0 },
	{ CONST_STR_LEN("MKREDIRECTREF")+1, 0 },
	{ CONST_STR_LEN("MKWORKSPACE")+1, 0 },
	{ CONST_STR_LEN("MOVE")+1, 0 },
	{ CONST_STR_LEN("ORDERPATCH")+1, 0 },
	{ CONST_STR_LEN("PATCH")+1, 0 },
	{ CONST_STR_LEN("PROPFIND")+1, 0 },
	{ CONST_STR_LEN("PROPPATCH")+1, 0 },
	{ CONST_STR_LEN("REBIND")+1, 0 },
	{ CONST_STR_LEN("REPORT")+1, 0 },
	{ CONST_STR_LEN("SEARCH")+1, 0 },
	{ CONST_STR_LEN("UNBIND")+1, 0 },
	{ CONST_STR_LEN("UNCHECKOUT")+1, 0 },
	{ CONST_STR_LEN("UNLINK")+1, 0 },
	{ CONST_STR_LEN("UNLOCK")+1, 0 },
	{ CONST_STR_LEN("UPDATE")+1, 0 },
	{ CONST_STR_LEN("UPDATEREDIRECTREF")+1, 0 },
	{ CONST_STR_LEN("VERSION-CONTROL")+1, 0 },

	{ CONST_STR_LEN("PRI")+1, 0 },
	{ "", 0, 0 }
};


const buffer *
http_version_buf (http_version_t i)
{
    return ((unsigned int)i < sizeof(http_versions)/sizeof(*http_versions))
      ? http_versions+i
      : http_versions+sizeof(http_versions)/sizeof(*http_versions)-1;
}


const buffer *
http_method_buf (http_method_t i)
{
    return ((unsigned int)i < sizeof(http_methods)/sizeof(*http_methods)-2)
      ? http_methods+i
      : http_methods+i+sizeof(http_methods)/sizeof(*http_methods);
        /* HTTP_METHOD_PRI is -2, HTTP_METHOD_UNSET is -1 */
}


http_method_t
http_method_key_get (const char *s, const size_t slen)
{
    if (slen == 3 && s[0] == 'G' && s[1] == 'E' && s[2] == 'T')
        return HTTP_METHOD_GET;
    const buffer *kv = http_methods+1; /*(step over http_methods[0] ("GET"))*/
    while (kv->used && (kv->used-1 != slen || 0 != memcmp(kv->ptr, s, slen)))
        ++kv;
    const uint_fast32_t i = kv - http_methods;
    /*(not done: could overload kv->size and store enum in kv->size)*/
    return (i < sizeof(http_methods)/sizeof(*http_methods)-2)
      ? (http_method_t)i
      : i == sizeof(http_methods)/sizeof(*http_methods)-2
        ? HTTP_METHOD_PRI
        : HTTP_METHOD_UNSET;
}
