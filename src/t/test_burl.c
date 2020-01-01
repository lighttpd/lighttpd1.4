#include "first.h"

#include <stdio.h>
#include <stdlib.h>

#include "burl.h"

static void run_burl_normalize (buffer *psrc, buffer *ptmp, int flags, int line, const char *in, size_t in_len, const char *out, size_t out_len) {
    int qs;
    buffer_copy_string_len(psrc, in, in_len);
    qs = burl_normalize(psrc, ptmp, flags);
    if (out_len == (size_t)-2) {
        if (-2 == qs) return;
        fprintf(stderr,
                "%s.%d: %s('%s') failed: expected error, got '%s'\n",
                __FILE__, line, __func__+4, in, psrc->ptr);
    }
    else {
        if (buffer_is_equal_string(psrc, out, out_len)) return;
        fprintf(stderr,
                "%s.%d: %s('%s') failed: expected '%s', got '%s'\n",
                __FILE__, line, __func__+4, in, out, psrc->ptr);
    }
    fflush(stderr);
    abort();
}

static void test_burl_normalize (void) {
    buffer *psrc = buffer_init();
    buffer *ptmp = buffer_init();
    int flags;

    flags = HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("no-slash"), CONST_STR_LEN("no-slash"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/"), CONST_STR_LEN("/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc"), CONST_STR_LEN("/abc"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc/"), CONST_STR_LEN("/abc/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc/def"), CONST_STR_LEN("/abc/def"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?"), CONST_STR_LEN("/abc?"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d"), CONST_STR_LEN("/abc?d"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d="), CONST_STR_LEN("/abc?d="));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e"), CONST_STR_LEN("/abc?d=e"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&"), CONST_STR_LEN("/abc?d=e&"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f"), CONST_STR_LEN("/abc?d=e&f"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f=g"), CONST_STR_LEN("/abc?d=e&f=g"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f=g#"), CONST_STR_LEN("/abc?d=e&f=g"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f=g#any"), CONST_STR_LEN("/abc?d=e&f=g"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2F"), CONST_STR_LEN("/%2F"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2f"), CONST_STR_LEN("/%2F"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%20"), CONST_STR_LEN("/%20"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2b"), CONST_STR_LEN("/%2B"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2B"), CONST_STR_LEN("/%2B"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%3a"), CONST_STR_LEN("/%3A"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%3A"), CONST_STR_LEN("/%3A"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/~test%20ä_"), CONST_STR_LEN("/~test%20%C3%A4_"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\375"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\376"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\377"), "", (size_t)-2);

    flags = HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/"), CONST_STR_LEN("/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc"), CONST_STR_LEN("/abc"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc/"), CONST_STR_LEN("/abc/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc/def"), CONST_STR_LEN("/abc/def"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?"), CONST_STR_LEN("/abc?"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d"), CONST_STR_LEN("/abc?d"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d="), CONST_STR_LEN("/abc?d="));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e"), CONST_STR_LEN("/abc?d=e"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&"), CONST_STR_LEN("/abc?d=e&"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f"), CONST_STR_LEN("/abc?d=e&f"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f=g"), CONST_STR_LEN("/abc?d=e&f=g"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f=g#"), CONST_STR_LEN("/abc?d=e&f=g"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/abc?d=e&f=g#any"), CONST_STR_LEN("/abc?d=e&f=g"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2F"), CONST_STR_LEN("/%2F"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2f"), CONST_STR_LEN("/%2F"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%20"), CONST_STR_LEN("/%20"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2b"), CONST_STR_LEN("/+"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2B"), CONST_STR_LEN("/+"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%3a"), CONST_STR_LEN("/:"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%3A"), CONST_STR_LEN("/:"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2b?x=%2b"), CONST_STR_LEN("/+?x=%2B"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2B?x=%2B"), CONST_STR_LEN("/+?x=%2B"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/~test%20ä_"), CONST_STR_LEN("/~test%20%C3%A4_"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\375"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\376"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\377"), "", (size_t)-2);

    flags |= HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\a"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\t"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\r"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/\177"), "", (size_t)-2);

  #if defined(__WIN32) || defined(__CYGWIN__)
    flags |= HTTP_PARSEOPT_URL_NORMALIZE_PATH_BACKSLASH_TRANS;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a\\b"), CONST_STR_LEN("/a/b"));
  #endif

    flags |= HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b?c=/"), CONST_STR_LEN("/a/b?c=/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b?c=%2f"), CONST_STR_LEN("/a/b?c=/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("%2f?"), CONST_STR_LEN("/?"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("%2f%2f"), CONST_STR_LEN("//"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("%2f%2f?"), CONST_STR_LEN("//?"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/%2f?"), CONST_STR_LEN("//?"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a%2fb"), CONST_STR_LEN("/a/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a%2Fb"), CONST_STR_LEN("/a/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a%2fb?c=/"), CONST_STR_LEN("/a/b?c=/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a%2fb?c=%2f"), CONST_STR_LEN("/a/b?c=/"));
    flags &= ~HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE;

    flags |= HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a%2fb"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a%2Fb"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b?c=%2f"), CONST_STR_LEN("/a/b?c=/"));
    flags &= ~HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT;

    flags |= HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("//"), CONST_STR_LEN("/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a//b"), CONST_STR_LEN("/a/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("./a/b"), CONST_STR_LEN("/a/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("../a/b"), CONST_STR_LEN("/a/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/./b"), CONST_STR_LEN("/a/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/../b"), CONST_STR_LEN("/b"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b/."), CONST_STR_LEN("/a/b/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b/.."), CONST_STR_LEN("/a/"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/../b/.."), CONST_STR_LEN("/"));
    flags &= ~HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE;

    flags |= HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("./a/b"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("../a/b"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/./b"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/../b"), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b/."), "", (size_t)-2);
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b/.."), "", (size_t)-2);
    flags &= ~HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT;

    flags |= HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS;
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b?c=d+e"), CONST_STR_LEN("/a/b?c=d+e"));
    run_burl_normalize(psrc, ptmp, flags, __LINE__, CONST_STR_LEN("/a/b?c=d%20e"), CONST_STR_LEN("/a/b?c=d+e"));
    flags &= ~HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS;

    buffer_free(psrc);
    buffer_free(ptmp);
}

int main (void) {
    test_burl_normalize();
    return 0;
}
