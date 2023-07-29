#include "first.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* stub functions to avoid pulling in chunk.c and fdevent.c */
#include "chunk.h"
#define chunkqueue_append_mem(cq, mem_len)                 do { } while (0)
#define chunkqueue_append_cq_range(dst, src, offset, len)  do { } while (0)
#define chunkqueue_steal(dest, src, len)                   do { } while (0)
#define chunkqueue_mark_written(cq, len)                   do { } while (0)
#define chunkqueue_reset(cq)                               do { } while (0)
void chunkqueue_append_mem_min (chunkqueue * restrict cq, const char * restrict mem, size_t len) {
    UNUSED(cq);
    UNUSED(mem);
    UNUSED(len);
}

#include "http_range.c"

static void test_http_range_parse (void) {
    const char *http_range;
    int n;
    off_t content_length;
    off_t ranges[RMAX*2];

    http_range = "bytes=0-0";
    content_length = 1;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n);

    http_range = "bytes=0-1";
    content_length = 2;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n);

    /* consolidate ranges: sorted */
    http_range = "bytes=0-1,1-2,2-3,3-4,4-5,5-6,6-7,7-8,8-9,9-10,10-11,11-12";
    content_length = 1000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n && ranges[0] == 0 && ranges[1] == 12);

    /* consolidate ranges: unsorted */
    http_range = "bytes=1-2,2-3,3-4,4-5,5-6,6-7,7-8,8-9,0-1";
    content_length = 1000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n && ranges[0] == 0 && ranges[1] == 9);

    /*(test constructions below based on 10 unsorted limit)*/
    assert(RMAX_UNSORTED == 10);

    /* unsorted ranges up to RMAX_UNSORTED num ranges, consolidated */
    http_range = "bytes=9-10,8-9,7-8,6-7,5-6,4-5,3-4,2-3,1-2,0-1";
    content_length = 1000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n && ranges[0] == 0 && ranges[1] == 10);

    /* unsorted range ignored after RMAX_UNSORTED num ranges, consolidated */
    http_range = "bytes=10-11,9-10,8-9,7-8,6-7,5-6,4-5,3-4,2-3,1-2,0-1";
    content_length = 1000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n && ranges[0] == 1 && ranges[1] == 11);

    /* sorted ranges processed above RMAX_UNSORTED (up to RMAX) */
    http_range = "bytes=0-1,100-100,200-200,300-300,400-400,500-500,600-600,700-700,800-800,900-900,1000-1000,1100-1100";
    content_length = 10000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(24 == n && ranges[0] == 0 && ranges[22] == 1100);

    /* unsorted range ignored after RMAX_UNSORTED num ranges */
    http_range = "bytes=100-100,200-200,300-300,400-400,500-500,600-600,700-700,800-800,900-900,1000-1000,1100-1100,0-100";
    content_length = 10000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(22 == n && ranges[0] == 100 && ranges[20] == 1100);

    /* unsorted range after RMAX_UNSORTED, but prior sorted, consolidated */
    http_range = "bytes=1-2,2-3,3-4,4-5,5-6,6-7,7-8,8-9,9-10,10-11,11-12,0-1";
    content_length = 1000;
    n = http_range_parse(http_range+sizeof("bytes=")-1, content_length, ranges);
    assert(2 == n && ranges[0] == 0 && ranges[1] == 12);

    /* TODO (more) */
}

void test_http_range (void);
void test_http_range (void)
{
    test_http_range_parse();
    /* TODO (more) */
}
