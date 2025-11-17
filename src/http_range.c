/*
 * http_range - HTTP Range (RFC 7233)
 *
 * Copyright(c) 2015,2021,2023 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "http_range.h"

#include <limits.h>
#include <stdlib.h>   /* strtol(), strtoll() */
#include <string.h>   /* memmove() */

#include "buffer.h"
#include "chunk.h"
#include "http_header.h"
#include "http_status.h"
#include "request.h"

/* arbitrary limit for max num ranges (additional ranges are ignored) */
#undef  RMAX
#define RMAX 128
#undef  RMAX_UNSORTED
#define RMAX_UNSORTED 10

/* RFC 7233 Hypertext Transfer Protocol (HTTP/1.1): Range Requests
 * https://tools.ietf.org/html/rfc7233
 * Range requests are an OPTIONAL feature of HTTP, designed so that recipients
 * not implementing this feature (or not supporting it for the target resource)
 * can respond as if it is a normal GET request without impacting
 * interoperability. */


/* default: ignore Range with HTTP/1.0 requests */
static int http_range_allow_http10;
void http_range_config_allow_http10 (int flag)
{
    http_range_allow_http10 = flag;
}


__attribute_cold__
__attribute_noinline__
static int
http_range_coalesce_unsorted (off_t * const restrict ranges, int n)
{
    /* coalesce/combine overlapping ranges and ranges separated by a
     * gap which is smaller than the overhead of sending multiple parts
     * (typically around 80 bytes) ([RFC7233] 4.1 206 Partial Content)
     * (ranges are known to be positive, so subtract 80 instead of add 80
     *  to avoid any chance of integer overflow)
     * (n is limited to RMAX_UNSORTED ranges (pairs of off_t) since a malicious
     *  set of ranges has n^2 cost for this simplistic algorithm)
     * (sorting the ranges and then combining would lower the cost, but the
     *  cost should not be an issue since client should not send many ranges
     *  and we restrict the max number of ranges to limit abuse)
     * [RFC7233] 4.1 206 Partial Content recommends:
     *   When a multipart response payload is generated, the server SHOULD send
     *   the parts in the same order that the corresponding byte-range-spec
     *   appeared in the received Range header field, excluding those ranges
     *   that were deemed unsatisfiable or that were coalesced into other ranges
     */
    for (int i = 0; i+2 < n; i += 2) {
        const off_t b = ranges[i];
        const off_t e = ranges[i+1];
        for (int j = i+2; j < n; j += 2) {
            /* common case: ranges do not overlap */
            if (b <= ranges[j] ? e < ranges[j]-80 : ranges[j+1] < b-80)
                continue;
            /* else ranges do overlap, so combine into first range */
            ranges[i]   = b <= ranges[j]   ? b : ranges[j];
            ranges[i+1] = e >= ranges[j+1] ? e : ranges[j+1];
            memmove(ranges+j, ranges+j+2, (n-j-2)*sizeof(off_t));
            /* restart outer loop from beginning */
            n -= 2;
            i = -2;
            break;
        }
    }

    return n;
}


static const char *
http_range_parse_next (const char * restrict s, const off_t len,
                       off_t * const restrict ranges)
{
    /*(caller must check returned ranges[1] != -1, or else range was invalid)*/

    /*assert(len > 0);*//*(caller must ensure len > 0)*/
    char *e;
    off_t n = strtoll(s, &e, 10);
    ranges[1] = -1; /* invalid */
    if (n >= 0) {
        if (n != LLONG_MAX && n < len && s != e) {
            ranges[0] = n;
            while (*e == ' ' || *e == '\t') ++e;
            if (*e == '-') {
                n = strtoll((s = e+1), &e, 10);
                if (s == e || (n == 0 && e[-1] != '0'))
                    ranges[1] = len-1;
                else if (ranges[0] <= n && n != LLONG_MAX)
                    ranges[1] = n < len ? n : len-1;
            }
        }
    }
    else if (n != LLONG_MIN) {
        ranges[0] = len > -n ? len + n : 0;/*('n' is negative here)*/
        ranges[1] = len-1;
    }
    while (*e == ' ' || *e == '\t') ++e;
    return e;  /* ',' or '\0' or else invalid char in range request */
}


static int
http_range_parse (const char * restrict s, const off_t content_length,
                  off_t ranges[RMAX*2])
{
    /* [RFC7233] 2.1 Byte Ranges
     * If a valid byte-range-set includes at least one byte-range-spec
     * with a first-byte-pos that is less than the current length of
     * the representation, or at least one suffix-byte-range-spec with
     * a non-zero suffix-length, then the byte-range-set is satisfiable.
     * Otherwise, the byte-range-set is unsatisfiable.
     *
     * [RFC7233] 3.1 Range
     * A server that supports range requests MAY ignore or reject a Range
     * header field that consists of more than two overlapping ranges, or a
     * set of many small ranges that are not listed in ascending order,
     * since both are indications of either a broken client or a deliberate
     * denial-of-service attack (Section 6.1).  A client SHOULD NOT request
     * multiple ranges that are inherently less efficient to process and
     * transfer than a single range that encompasses the same data.
     */
    int n = 0;
    int lim = RMAX*2;
    do {
        s = http_range_parse_next(s, content_length, ranges+n);
        if ((*s == '\0' || *s == ',') && ranges[n+1] != -1) {
            n += 2;
            if (n < 4)
                continue;
            /* track if ranges are sorted and check coalesce with prior range */
            /* (specialized case of http_range_coalesce_unsorted())*/
            if (ranges[n-4] <= ranges[n-2]) { /* range1_begin <= range2_begin */
                if (ranges[n-3] < ranges[n-2]-80)/* range1_end < range2_begin */
                    continue;
                /* ranges close or overlap, so combine into first range */
                if (ranges[n-3] < ranges[n-1])   /* range1_end < range2_end */
                    ranges[n-3] = ranges[n-1];
                n -= 2;
            }
            else {
                /* reduce limit on num of ranges if unsorted */
                if (n > RMAX_UNSORTED*2) {
                    n -= 2;
                    break;
                }
                lim = RMAX_UNSORTED*2;
            }
        }
        else if (__builtin_expect(1, 0)) /*(cold branch)*/
            while (*s != '\0' && *s != ',') ++s; /*ignore invalid ranges*/
    } while (*s++ != '\0' && n < lim);
          /*(*s++ for multipart, increment to char after ',')*/

    if (n <= 2)
        return n;

    /* error if n == 0 (no valid ranges)
     * (if n >= RMAX_UNSORTED*2 (additional unsorted ranges may be ignored))
     * (if n == RMAX*2 (additional ranges > RMAX limit, if any, were ignored))*/
    return lim == RMAX*2 ? n : http_range_coalesce_unsorted(ranges, n);
}


static void
http_range_single (request_st * const r, const off_t ranges[2])
{
    /* caller already checked: n == 2, content_length > 0, ranges valid */
    chunkqueue * const restrict cq = &r->write_queue;
    const off_t complete_length = chunkqueue_length(cq);
    /* add Content-Range header */
    /*(large enough for "bytes X-X/X" with 3 huge numbers)*/
    uint32_t len = sizeof("bytes ")-1;
    char cr[72] = "bytes ";
    len += (uint32_t)li_itostrn(cr+len, sizeof(cr)-len, ranges[0]);
    cr[len++] = '-';
    len += (uint32_t)li_itostrn(cr+len, sizeof(cr)-len, ranges[1]);
    cr[len++] = '/';
    len += (uint32_t)li_itostrn(cr+len, sizeof(cr)-len, complete_length);
    http_header_response_set(r, HTTP_HEADER_CONTENT_RANGE,
                             CONST_STR_LEN("Content-Range"), cr, len);
    if (cq->first == cq->last) { /* single chunk in cq */
        /* consume from cq to start of range, truncate after end of range */
        if (ranges[0]) {
            chunkqueue_mark_written(cq, ranges[0]);
            cq->bytes_out -= ranges[0];
            cq->bytes_in -= ranges[0];
        }
        cq->bytes_in -= complete_length - (ranges[1] + 1);
        chunk * const c = cq->first;
        if (c->type == FILE_CHUNK)
            c->file.length = c->offset + ranges[1] - ranges[0] + 1;
        else /*(c->type == MEM_CHUNK)*/
            c->mem->used = c->offset + ranges[1] - ranges[0] + 1 + 1;
    }
    else {
        /* transfer contents to temporary cq, then transfer range back */
        chunkqueue tq;
        memset(&tq, 0, sizeof(tq));
        chunkqueue_steal(&tq, cq, complete_length);
        cq->bytes_out -= complete_length;
        cq->bytes_in -= complete_length;
        chunkqueue_mark_written(&tq, ranges[0]);
        chunkqueue_steal(cq, &tq, ranges[1] - ranges[0] + 1);
        chunkqueue_reset(&tq);
    }
}


__attribute_cold__
static void
http_range_multi (request_st * const r,
                  const off_t ranges[RMAX*2], const int n)
{
    /* multiple ranges that are not ordered are not expected to be common,
     * so those scenarios is not optimized here */
    #define HTTP_MULTIPART_BOUNDARY "fkj49sn38dcn3"
    static const char boundary_prefix[] =
      "\r\n--" HTTP_MULTIPART_BOUNDARY;
    static const char boundary_end[] =
      "\r\n--" HTTP_MULTIPART_BOUNDARY "--\r\n";
    static const char multipart_type[] =
      "multipart/byteranges; boundary=" HTTP_MULTIPART_BOUNDARY;

    buffer * const tb = r->tmp_buf;
    buffer_copy_string_len(tb, CONST_STR_LEN(boundary_prefix));
    const buffer * const content_type =
      http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE,
                               CONST_STR_LEN("Content-Type"));
    if (content_type) {
        buffer_append_str2(tb, CONST_STR_LEN("\r\nContent-Type: "),
                               BUF_PTR_LEN(content_type));
    }
    buffer_append_string_len(tb,CONST_STR_LEN("\r\nContent-Range: bytes "));
    const uint32_t prefix_len = buffer_clen(tb);

    http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
                             CONST_STR_LEN("Content-Type"),
                             CONST_STR_LEN(multipart_type));

    /* caller already checked: n > 2, content_length > 0, ranges valid */
    chunkqueue * const restrict cq = &r->write_queue;
    const off_t complete_length = chunkqueue_length(cq);

    /* copy chunks for ranges to end of cq, then consume original chunks
     *
     * future: if ranges ordered, could use technique in http_range_single(),
     * but [RFC7233] 4.1 206 Partial Content recommends:
     *   When a multipart response payload is generated, the server SHOULD send
     *   the parts in the same order that the corresponding byte-range-spec
     *   appeared in the received Range header field, excluding those ranges
     *   that were deemed unsatisfiable or that were coalesced into other ranges
     * and this code path is not expected to be hot, and so not optimized.
     */

    chunk * const c = (cq->first == cq->last && cq->first->type == MEM_CHUNK)
      ? cq->first
      : NULL;
    for (int i = 0; i < n; i += 2) {
        /* generate boundary-header including Content-Type and Content-Range */
        buffer_truncate(tb, prefix_len);
        buffer_append_int(tb, ranges[i]);
        buffer_append_char(tb, '-');
        buffer_append_int(tb, ranges[i+1]);
        buffer_append_char(tb, '/');
        buffer_append_int(tb, complete_length);
        buffer_append_string_len(tb, CONST_STR_LEN("\r\n\r\n"));
        if (c) /* single MEM_CHUNK in original cq; not using mem_min */
            chunkqueue_append_mem(cq, BUF_PTR_LEN(tb));
        else
            chunkqueue_append_mem_min(cq, BUF_PTR_LEN(tb));

        chunkqueue_append_cq_range(cq, cq, ranges[i],
                                   ranges[i+1] - ranges[i] + 1);
    }

    /* add boundary end */
    chunkqueue_append_mem_min(cq, CONST_STR_LEN(boundary_end));

    /* remove initial chunk(s), since duplicated into multipart ranges */
    /* remove initial "\r\n" in front of first boundary string */
    chunkqueue_mark_written(cq, complete_length+2);
    cq->bytes_out -= complete_length+2;
    cq->bytes_in -= complete_length+2;
}


__attribute_cold__
static int
http_range_not_satisfiable (request_st * const r, const off_t content_length)
{
    /*(large enough for "bytes '*'/X" with 1 huge number)*/
    uint32_t len = sizeof("bytes */")-1;
    char cr[32] = "bytes */";
    len += (uint32_t)li_itostrn(cr+len, sizeof(cr)-len, content_length);
    http_header_response_set(r, HTTP_HEADER_CONTENT_RANGE,
                             CONST_STR_LEN("Content-Range"), cr, len);
    http_status_set_err(r, 416); /* Range Not Satisfiable */
    return 416;
}


__attribute_cold__
__attribute_noinline__
static int
http_range_process (request_st * const r, const buffer * const http_range)
{
    const off_t content_length = chunkqueue_length(&r->write_queue);
    if (0 == content_length) /*(implementation detail; see comment at top)*/
        return r->http_status;  /* skip Range handling if empty payload */
    /* future: might skip Range if content_length is below threshold, e.g. 1k */

    /* An origin server MUST ignore a Range header field that contains a
     * range unit it does not understand. */
    if (buffer_clen(http_range) < sizeof("bytes=")-1
        || !buffer_eq_icase_ssn(http_range->ptr, "bytes=", sizeof("bytes=")-1))
        return r->http_status;         /* 200 OK */

    /* arbitrary limit: support up to RMAX ranges in request Range field
     * (validating and coalescing overlapping ranges is not a linear algorithm)
     * (use RMAX pairs of off_t to indicate too many ranges ( >= RMAX*2)) */
    off_t ranges[RMAX*2];
    const int n = http_range_parse(http_range->ptr+sizeof("bytes=")-1,
                                   content_length, ranges);

    /* checked above: content_length > 0, ranges valid */
    if (2 == n) /* single range */
        http_range_single(r, ranges);
    else if (0 == n)                   /* 416 Range Not Satisfiable */
        return http_range_not_satisfiable(r, content_length);
    else        /* multipart ranges */
        http_range_multi(r, ranges, n);

    /*(must either set Content-Length or unset prior value, if any)*/
    buffer_append_int(
      http_header_response_set_ptr(r, HTTP_HEADER_CONTENT_LENGTH,
                                   CONST_STR_LEN("Content-Length")),
      chunkqueue_length(&r->write_queue));

    return (r->http_status = 206);     /* 206 Partial Content */
}


int
http_range_rfc7233 (request_st * const r)
{
    const int http_status = r->http_status;

    /* implementation limitation:
     * limit range handling to when we have complete response
     * (future: might extend this to streamed files if Content-Length known)
     * (otherwise, might be unable to validate Range before send response header
     *  e.g. unable to handle suffix-byte-range-spec without entity length)*/
    if (!r->resp_body_finished)
        return http_status;

    /* limit range handling to 200 responses
     * [RFC7233] 3.1 Range
     *   The Range header field is evaluated after evaluating the precondition
     *   header fields defined in [RFC7232], and only if the result in absence
     *   of the Range header field would be a 200 (OK) response. */
    if (200 != http_status)
        return http_status;
    /* limit range handling to GET and HEAD (further limited below to GET)
     * [RFC7233] 3.1 Range
     *   A server MUST ignore a Range header field received with a request
     *   method other than GET.
     */
    if (!http_method_get_head_query(r->http_method))
        return http_status;
    /* no "Range" in HTTP/1.0 */
    if (r->http_version < HTTP_VERSION_1_1)
      if (!http_range_allow_http10)
        return http_status;
    /* do not attempt to handle range if Transfer-Encoding already applied.
     * skip Range processing if Content-Encoding has already been applied,
     * since Range is on the unencoded content length and Content-Encoding
     * might change content.  This includes if mod_deflate has applied
     * Content-Encoding.  If Transfer-Encoding: gzip, chunked were used
     * instead (not done), then Range processing could safely take place, too,
     * (but mod_deflate would need to run from new hook to handle TE: gzip).
     * Alternatively, lighttpd.conf could be configured to disable mod_deflate
     * for Range requests:
     *   $REQUEST_HEADER["Range"] != "" { deflate.mimetypes = () }
     */
    if ((r->resp_htags
         & (light_bshift(HTTP_HEADER_TRANSFER_ENCODING)
           |light_bshift(HTTP_HEADER_CONTENT_ENCODING))))
        return http_status;
  #if 0 /*(if Range already handled, HTTP status expected to be 206, not 200)*/
    /* check if Range request already handled (single range or multipart)*/
    if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_RANGE))
        return http_status;
    const buffer * const content_type =
      http_header_response_get(r, HTTP_HEADER_CONTENT_TYPE,
                               CONST_STR_LEN("Content-Type"));
    if (content_type
        && buffer_clen(content_type) >= sizeof("multipart/byteranges")-1
        && buffer_eq_icase_ssn(content_type->ptr, "multipart/byteranges",
                               sizeof("multipart/byteranges")-1))
        return http_status;
  #endif

    /* optional: advertise Accept-Ranges: bytes
     * Even if "Accept-Ranges: bytes" is not given,
     * [RFC7233] 2.3 Accept-Ranges
     *   A client MAY generate range requests without having received this
     *   header for the resource involved.
     */
    if (!light_btst(r->resp_htags, HTTP_HEADER_ACCEPT_RANGES))
        http_header_response_set(r, HTTP_HEADER_ACCEPT_RANGES,
                                 CONST_STR_LEN("Accept-Ranges"),
                                 CONST_STR_LEN("bytes"));
    else {
        const buffer * const accept_ranges =
          http_header_response_get(r, HTTP_HEADER_ACCEPT_RANGES,
                                   CONST_STR_LEN("Accept-Ranges"));
      #ifdef __COVERITY__
        force_assert(accept_ranges); /*(r->resp_htags checked above)*/
      #endif
        if (buffer_eq_slen(accept_ranges, CONST_STR_LEN("none")))
            return http_status;
    }

    /* limit range handling to GET
     * [RFC7233] 3.1 Range
     *   A server MUST ignore a Range header field received with a request
     *   method other than GET.
     * (extended to QUERY here, after limited to GET HEAD QUERY further above)
     */
    if (r->http_method == HTTP_METHOD_HEAD)
        return http_status;

    /* check for Range request */
    const buffer * const http_range =
      http_header_request_get(r, HTTP_HEADER_RANGE, CONST_STR_LEN("Range"));
    if (!http_range)
        return http_status;

    /* [RFC7233] 3.2 If-Range
     *   If-Range = entity-tag / HTTP-date
     *   A client MUST NOT generate an If-Range header field containing an
     *   entity-tag that is marked as weak.
     *   [...]
     *   Note that this comparison by exact match, including when the validator
     *   is an HTTP-date, differs from the "earlier than or equal to" comparison
     *   used when evaluating an If-Unmodified-Since conditional. */
    if (light_btst(r->rqst_htags, HTTP_HEADER_IF_RANGE)) {
        const buffer * const if_range =
          http_header_request_get(r, HTTP_HEADER_IF_RANGE,
                                  CONST_STR_LEN("If-Range"));
      #ifdef __COVERITY__
        force_assert(if_range); /*(r->rqst_htags checked above)*/
      #endif
        /* (weak ETag W/"<etag>" will not match Last-Modified) */
        const buffer * const cmp = (if_range->ptr[0] == '"')
          ? http_header_response_get(r, HTTP_HEADER_ETAG,
                                     CONST_STR_LEN("ETag"))
          : http_header_response_get(r, HTTP_HEADER_LAST_MODIFIED,
                                     CONST_STR_LEN("Last-Modified"));
        if (!cmp || !buffer_is_equal(if_range, cmp))
            return http_status;

      #if 0 /*(questionable utility; not deemed worthwhile)*/
        /* (In a modular server, the following RFC recommendation might be
         *  expensive and invasive to implement perfectly, so only making an
         *  effort here to comply with known headers added within this routine
         *  and within the purview of Range requests)
         * [RFC7233] 4.1 206 Partial Content
         *   If a 206 is generated in response to a request with an If-Range
         *   header field, the sender SHOULD NOT generate other representation
         *   header fields beyond those required above, because the client is
         *   understood to already have a prior response containing those header
         *   fields.
         */
        http_header_response_unset(r, HTTP_HEADER_ACCEPT_RANGES,
                                   CONST_STR_LEN("Accept-Ranges"));
      #endif
    }

    return http_range_process(r, http_range);
}
