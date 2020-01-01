#include "first.h"
#include "burl.h"

#include <string.h>

#include "buffer.h"
#include "base64.h"

static const char hex_chars_uc[] = "0123456789ABCDEF";

/* everything except: ! $ & ' ( ) * + , - . / 0-9 : ; = ? @ A-Z _ a-z ~ */
static const char encoded_chars_http_uri_reqd[] = {
  /*
  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
  */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
  1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F space " # % */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,  /*  70 -  7F { | } DEL */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};


/* c (char) and n (nibble) MUST be unsigned integer types */
#define li_cton(c,n) \
  (((n) = (c) - '0') <= 9 || (((n) = ((c)&0xdf) - 'A') <= 5 ? ((n) += 10) : 0))

/* b (byte) MUST be unsigned integer type
 * https://en.wikipedia.org/wiki/UTF-8
 * reject overlong encodings of 7-byte ASCII and invalid UTF-8
 * (but does not detect other overlong multi-byte encodings) */
#define li_utf8_invalid_byte(b) ((b) >= 0xF5 || ((b)|0x1) == 0xC1)


static int burl_is_unreserved (const int c)
{
    return (light_isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~');
}


static int burl_normalize_basic_unreserved_fix (buffer *b, buffer *t, int i, int qs)
{
    int j = i;
    const int used = (int)buffer_string_length(b);
    const unsigned char * const s = (unsigned char *)b->ptr;
    unsigned char * const p =
      (unsigned char *)buffer_string_prepare_copy(t,i+(used-i)*3+1);
    unsigned int n1, n2;
    memcpy(p, s, (size_t)i);
    for (; i < used; ++i, ++j) {
        if (!encoded_chars_http_uri_reqd[s[i]]) {
            if (s[i] == '?' && -1 == qs) qs = j;
            p[j] = s[i];
        }
        else if (s[i]=='%' && li_cton(s[i+1], n1) && li_cton(s[i+2], n2)) {
            const unsigned int x = (n1 << 4) | n2;
            if (burl_is_unreserved(x)) {
                p[j] = x;
            }
            else {
                p[j]   = '%';
                p[++j] = hex_chars_uc[n1]; /*(s[i+1] & 0xdf)*/
                p[++j] = hex_chars_uc[n2]; /*(s[i+2] & 0xdf)*/
                if (li_utf8_invalid_byte(x)) qs = -2;
            }
            i+=2;
        }
        else if (s[i] == '#') break; /* ignore fragment */
        else {
            p[j]   = '%';
            p[++j] = hex_chars_uc[(s[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[s[i] & 0xF];
            if (li_utf8_invalid_byte(s[i])) qs = -2;
        }
    }
    buffer_commit(t, (size_t)j);
    buffer_copy_buffer(b, t);
    return qs;
}


static int burl_normalize_basic_unreserved (buffer *b, buffer *t)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    const int used = (int)buffer_string_length(b);
    unsigned int n1, n2, x;
    int qs = -1;

    for (int i = 0; i < used; ++i) {
        if (!encoded_chars_http_uri_reqd[s[i]]) {
            if (s[i] == '?' && -1 == qs) qs = i;
        }
        else if (s[i]=='%' && li_cton(s[i+1], n1) && li_cton(s[i+2], n2)
                 && !burl_is_unreserved((x = (n1 << 4) | n2))) {
            if (li_utf8_invalid_byte(x)) qs = -2;
            if (s[i+1] >= 'a') b->ptr[i+1] &= 0xdf; /* uppercase hex */
            if (s[i+2] >= 'a') b->ptr[i+2] &= 0xdf; /* uppercase hex */
            i+=2;
        }
        else if (s[i] == '#') { /* ignore fragment */
            buffer_string_set_length(b, (size_t)i);
            break;
        }
        else {
            qs = burl_normalize_basic_unreserved_fix(b, t, i, qs);
            break;
        }
    }

    return qs;
}


static int burl_normalize_basic_required_fix (buffer *b, buffer *t, int i, int qs)
{
    int j = i;
    const int used = (int)buffer_string_length(b);
    const unsigned char * const s = (unsigned char *)b->ptr;
    unsigned char * const p =
      (unsigned char *)buffer_string_prepare_copy(t,i+(used-i)*3+1);
    unsigned int n1, n2;
    memcpy(p, s, (size_t)i);
    for (; i < used; ++i, ++j) {
        if (!encoded_chars_http_uri_reqd[s[i]]) {
            if (s[i] == '?' && -1 == qs) qs = j;
            p[j] = s[i];
        }
        else if (s[i]=='%' && li_cton(s[i+1], n1) && li_cton(s[i+2], n2)) {
            const unsigned int x = (n1 << 4) | n2;
            if (!encoded_chars_http_uri_reqd[x]
                && (qs < 0
                    ? (x != '/' && x != '?')
                    : (x != '&' && x != '=' && x != ';' && x != '+'))) {
                p[j] = x;
            }
            else {
                p[j]   = '%';
                p[++j] = hex_chars_uc[n1]; /*(s[i+1] & 0xdf)*/
                p[++j] = hex_chars_uc[n2]; /*(s[i+2] & 0xdf)*/
                if (li_utf8_invalid_byte(x)) qs = -2;
            }
            i+=2;
        }
        else if (s[i] == '#') break; /* ignore fragment */
        else {
            p[j]   = '%';
            p[++j] = hex_chars_uc[(s[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[s[i] & 0xF];
            if (li_utf8_invalid_byte(s[i])) qs = -2;
        }
    }
    buffer_commit(t, (size_t)j);
    buffer_copy_buffer(b, t);
    return qs;
}


static int burl_normalize_basic_required (buffer *b, buffer *t)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    const int used = (int)buffer_string_length(b);
    unsigned int n1, n2, x;
    int qs = -1;

    for (int i = 0; i < used; ++i) {
        if (!encoded_chars_http_uri_reqd[s[i]]) {
            if (s[i] == '?' && -1 == qs) qs = i;
        }
        else if (s[i]=='%' && li_cton(s[i+1], n1) && li_cton(s[i+2], n2)
                 && (encoded_chars_http_uri_reqd[(x = (n1 << 4) | n2)]
                     || (qs < 0
                         ? (x == '/' || x == '?')
                         : (x == '&' || x == '=' || x == ';' || x == '+')))) {
            if (li_utf8_invalid_byte(x)) qs = -2;
            if (s[i+1] >= 'a') b->ptr[i+1] &= 0xdf; /* uppercase hex */
            if (s[i+2] >= 'a') b->ptr[i+2] &= 0xdf; /* uppercase hex */
            i+=2;
        }
        else if (s[i] == '#') { /* ignore fragment */
            buffer_string_set_length(b, (size_t)i);
            break;
        }
        else {
            qs = burl_normalize_basic_required_fix(b, t, i, qs);
            break;
        }
    }

    return qs;
}


static int burl_contains_ctrls (const buffer *b)
{
    const char * const s = b->ptr;
    const int used = (int)buffer_string_length(b);
    for (int i = 0; i < used; ++i) {
        if (s[i] == '%' && (s[i+1] < '2' || (s[i+1] == '7' && s[i+2] == 'F')))
            return 1;
    }
    return 0;
}


static void burl_normalize_qs20_to_plus_fix (buffer *b, int i)
{
    char * const s = b->ptr;
    const int used = (int)buffer_string_length(b);
    int j = i;
    for (; i < used; ++i, ++j) {
        s[j] = s[i];
        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == '0') {
            s[j] = '+';
            i+=2;
        }
    }
    buffer_string_set_length(b, j);
}


static void burl_normalize_qs20_to_plus (buffer *b, int qs)
{
    const char * const s = b->ptr;
    const int used = qs < 0 ? 0 : (int)buffer_string_length(b);
    int i;
    if (qs < 0) return;
    for (i = qs+1; i < used; ++i) {
        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == '0') break;
    }
    if (i != used) burl_normalize_qs20_to_plus_fix(b, i);
}


static int burl_normalize_2F_to_slash_fix (buffer *b, int qs, int i)
{
    char * const s = b->ptr;
    const int blen = (int)buffer_string_length(b);
    const int used = qs < 0 ? blen : qs;
    int j = i;
    for (; i < used; ++i, ++j) {
        s[j] = s[i];
        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == 'F') {
            s[j] = '/';
            i+=2;
        }
    }
    if (qs >= 0) {
        const int qslen = blen - qs;
        memmove(s+j, s+qs, (size_t)qslen);
        qs = j;
        j += qslen;
    }
    buffer_string_set_length(b, j);
    return qs;
}


static int burl_normalize_2F_to_slash (buffer *b, int qs, int flags)
{
    /*("%2F" must already have been uppercased during normalization)*/
    const char * const s = b->ptr;
    const int used = qs < 0 ? (int)buffer_string_length(b) : qs;
    for (int i = 0; i < used; ++i) {
        if (s[i] == '%' && s[i+1] == '2' && s[i+2] == 'F') {
            return (flags & HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE)
              ? burl_normalize_2F_to_slash_fix(b, qs, i)
              : -2; /*(flags & HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT)*/
        }
    }
    return qs;
}


static int burl_normalize_path (buffer *b, buffer *t, int qs, int flags)
{
    const unsigned char * const s = (unsigned char *)b->ptr;
    const int used = (int)buffer_string_length(b);
    int path_simplify = 0;
    for (int i = 0, len = qs < 0 ? used : qs; i < len; ++i) {
        if (s[i] == '.' && (s[i+1] != '.' || ++i)
            && (s[i+1] == '/' || s[i+1] == '?' || s[i+1] == '\0')) {
            path_simplify = 1;
            break;
        }
        while (i < len && s[i] != '/') ++i;
        if (s[i] == '/' && s[i+1] == '/') { /*(s[len] != '/')*/
            path_simplify = 1;
            break;
        }
    }

    if (path_simplify) {
        if (flags & HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT) return -2;
        if (qs >= 0) {
            buffer_copy_string_len(t, b->ptr+qs, used - qs);
            buffer_string_set_length(b, qs);
        }

        buffer_path_simplify(b, b);

        if (qs >= 0) {
            qs = (int)buffer_string_length(b);
            buffer_append_string_len(b, CONST_BUF_LEN(t));
        }
    }

    return qs;
}


int burl_normalize (buffer *b, buffer *t, int flags)
{
    int qs;

  #if defined(__WIN32) || defined(__CYGWIN__)
    /* Windows and Cygwin treat '\\' as '/' if '\\' is present in path;
     * convert to '/' for consistency before percent-encoding
     * normalization which will convert '\\' to "%5C" in the URL.
     * (Clients still should not be sending '\\' unencoded in requests.) */
    if (flags & HTTP_PARSEOPT_URL_NORMALIZE_PATH_BACKSLASH_TRANS) {
        for (char *p = b->ptr; *p != '?' && *p != '\0'; ++p) {
            if (*p == '\\') *p = '/';
        }
    }
  #endif

    qs = (flags & HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED)
      ? burl_normalize_basic_required(b, t)
      : burl_normalize_basic_unreserved(b, t);
    if (-2 == qs) return -2;

    if (flags & HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT) {
        if (burl_contains_ctrls(b)) return -2;
    }

    if (flags & (HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE
                |HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT)) {
        qs = burl_normalize_2F_to_slash(b, qs, flags);
        if (-2 == qs) return -2;
    }

    if (flags & (HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE
                |HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT)) {
        qs = burl_normalize_path(b, t, qs, flags);
        if (-2 == qs) return -2;
    }

    if (flags & HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS) {
        if (qs >= 0) burl_normalize_qs20_to_plus(b, qs);
    }

    return qs;
}


static void burl_append_encode_nde (buffer * const b, const char * const str, const size_t len)
{
    /* percent-encodes everything except unreserved  - . 0-9 A-Z _ a-z ~
     * unless already percent-encoded (does not double-encode) */
    /* Note: not checking for invalid UTF-8 */
    char * const p = buffer_string_prepare_append(b, len*3);
    unsigned int n1, n2;
    int j = 0;
    for (unsigned int i = 0; i < len; ++i, ++j) {
        if (str[i]=='%' && li_cton(str[i+1], n1) && li_cton(str[i+2], n2)) {
            const unsigned int x = (n1 << 4) | n2;
            if (burl_is_unreserved((int)x)) {
                p[j] = (char)x;
            }
            else { /* leave UTF-8, control chars, and required chars encoded */
                p[j]   = '%';
                p[++j] = str[i+1];
                p[++j] = str[i+2];
            }
            i+=2;
        }
        else if (burl_is_unreserved(str[i])) {
            p[j] = str[i];
        }
        else {
            p[j]   = '%';
            p[++j] = hex_chars_uc[(str[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[str[i] & 0xF];
        }
    }
    buffer_commit(b, j);
}


static void burl_append_encode_psnde (buffer * const b, const char * const str, const size_t len)
{
    /* percent-encodes everything except unreserved  - . 0-9 A-Z _ a-z ~ plus /
     * unless already percent-encoded (does not double-encode) */
    /* Note: not checking for invalid UTF-8 */
    char * const p = buffer_string_prepare_append(b, len*3);
    unsigned int n1, n2;
    int j = 0;
    for (unsigned int i = 0; i < len; ++i, ++j) {
        if (str[i]=='%' && li_cton(str[i+1], n1) && li_cton(str[i+2], n2)) {
            const unsigned int x = (n1 << 4) | n2;
            if (burl_is_unreserved((int)x)) {
                p[j] = (char)x;
            }
            else { /* leave UTF-8, control chars, and required chars encoded */
                p[j]   = '%';
                p[++j] = str[i+1];
                p[++j] = str[i+2];
            }
            i+=2;
        }
        else if (burl_is_unreserved(str[i]) || str[i] == '/') {
            p[j] = str[i];
        }
        else {
            p[j]   = '%';
            p[++j] = hex_chars_uc[(str[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[str[i] & 0xF];
        }
    }
    buffer_commit(b, j);
}


static void burl_append_encode_all (buffer * const b, const char * const str, const size_t len)
{
    /* percent-encodes everything except unreserved  - . 0-9 A-Z _ a-z ~
     * Note: double-encodes any existing '%') */
    /* Note: not checking for invalid UTF-8 */
    char * const p = buffer_string_prepare_append(b, len*3);
    int j = 0;
    for (unsigned int i = 0; i < len; ++i, ++j) {
        if (burl_is_unreserved(str[i])) {
            p[j] = str[i];
        }
        else {
            p[j]   = '%';
            p[++j] = hex_chars_uc[(str[i] >> 4) & 0xF];
            p[++j] = hex_chars_uc[str[i] & 0xF];
        }
    }
    buffer_commit(b, j);
}


static void burl_offset_tolower (buffer * const b, const size_t off)
{
    /*(skips over all percent-encodings, including encoding of alpha chars)*/
    for (char *p = b->ptr+off; p[0]; ++p) {
        if (p[0] >= 'A' && p[0] <= 'Z') p[0] |= 0x20;
        else if (p[0]=='%' && light_isxdigit(p[1]) && light_isxdigit(p[2]))
            p+=2;
    }
}


static void burl_offset_toupper (buffer * const b, const size_t off)
{
    /*(skips over all percent-encodings, including encoding of alpha chars)*/
    for (char *p = b->ptr+off; p[0]; ++p) {
        if (p[0] >= 'a' && p[0] <= 'z') p[0] &= 0xdf;
        else if (p[0]=='%' && light_isxdigit(p[1]) && light_isxdigit(p[2]))
            p+=2;
    }
}


void burl_append (buffer * const b, const char * const str, const size_t len, const int flags)
{
    size_t off = 0;

    if (0 == len) return;

    if (0 == flags) {
        buffer_append_string_len(b, str, len);
        return;
    }

    if (flags & (BURL_TOUPPER|BURL_TOLOWER)) off = buffer_string_length(b);

    if (flags & BURL_ENCODE_NONE) {
        buffer_append_string_len(b, str, len);
    }
    else if (flags & BURL_ENCODE_ALL) {
        burl_append_encode_all(b, str, len);
    }
    else if (flags & BURL_ENCODE_NDE) {
        burl_append_encode_nde(b, str, len);
    }
    else if (flags & BURL_ENCODE_PSNDE) {
        burl_append_encode_psnde(b, str, len);
    }
    else if (flags & BURL_ENCODE_B64U) {
        const unsigned char *s = (const unsigned char *)str;
        buffer_append_base64_encode_no_padding(b, s, len, BASE64_URL);
    }
    else if (flags & BURL_DECODE_B64U) {
        buffer_append_base64_decode(b, str, len, BASE64_URL);
    }

    /* note: not normalizing str, which could come from arbitrary header,
     * so it is possible that alpha chars are percent-encoded upper/lowercase */
    if (flags & (BURL_TOLOWER|BURL_TOUPPER)) {
        (flags & BURL_TOLOWER)
          ? burl_offset_tolower(b, off)  /*(flags & BURL_TOLOWER)*/
          : burl_offset_toupper(b, off); /*(flags & BURL_TOUPPER)*/
    }
}
