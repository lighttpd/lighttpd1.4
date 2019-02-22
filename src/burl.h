#ifndef INCLUDED_BURL_H
#define INCLUDED_BURL_H
#include "first.h"

#include "buffer.h"

struct burl_parts_t {
  buffer *scheme;
  buffer *authority;
  unsigned short port;
  buffer *path;
  buffer *query;
};

enum burl_opts_e {
  HTTP_PARSEOPT_HEADER_STRICT  = 0x1
 ,HTTP_PARSEOPT_HOST_STRICT    = 0x2
 ,HTTP_PARSEOPT_HOST_NORMALIZE = 0x4
 ,HTTP_PARSEOPT_URL_NORMALIZE  = 0x8/*normalize chars %-encoded, uppercase hex*/
 ,HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED          =0x10 /* decode unreserved */
 ,HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED            =0x20 /* decode (un)reserved*/
 ,HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT        =0x40
 ,HTTP_PARSEOPT_URL_NORMALIZE_PATH_BACKSLASH_TRANS=0x80 /* "\\" -> "/" Cygwin */
 ,HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE      =0x100/* "%2F"-> "/" */
 ,HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT      =0x200
 ,HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE  =0x400/* "." ".." "//" */
 ,HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT  =0x800
 ,HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS       =0x1000
 ,HTTP_PARSEOPT_METHOD_GET_BODY                   =0x8000
};

int burl_normalize (buffer *b, buffer *t, int flags);

enum burl_recoding_e {
  BURL_TOLOWER         = 0x0001
 ,BURL_TOUPPER         = 0x0002
 ,BURL_ENCODE_NONE     = 0x0004
 ,BURL_ENCODE_ALL      = 0x0008
 ,BURL_ENCODE_NDE      = 0x0010 /* encode delims, but no-double-encode (NDE) */
 ,BURL_ENCODE_PSNDE    = 0x0020 /* similar to NDE, but preserve literal slash */
 ,BURL_ENCODE_B64U     = 0x0040
 ,BURL_DECODE_B64U     = 0x0080
};

void burl_append (buffer * const b, const char * const str, const size_t len, const int flags);

#endif
