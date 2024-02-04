/*
 * http_chunk - append response to chunkqueue, possibly in "chunked" encoding
 *
 * Fully-rewritten from original
 * Copyright(c) 2019 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_chunk.h"
#include "chunk.h"
#include "stat_cache.h"
#include "log.h"
#include "request.h"

#include "sys-unistd.h" /* <unistd.h> */

#include <string.h>

__attribute_noinline__
static void http_chunk_len_append(chunkqueue * const cq, uintmax_t len) {
    char buf[24]; /* 64-bit (8 bytes) is 16 hex chars (+2 \r\n, +1 \0 = 19) */
  #if 0
    buffer b = { buf, 0, sizeof(buf) };
    buffer_append_uint_hex(&b, len);
    buffer_append_string_len(&b, CONST_STR_LEN("\r\n"));
    chunkqueue_append_mem(cq, b.ptr, b.used-1);
  #else
    int i = (int)(sizeof(buf));
    buf[--i] = '\n';
    buf[--i] = '\r';
    do { buf[--i] = "0123456789abcdef"[len & 0x0F]; } while (len >>= 4);
    chunkqueue_append_mem(cq, buf+i, sizeof(buf)-i);
  #endif
}

__attribute_noinline__
static int http_chunk_len_append_tempfile(chunkqueue * const cq, uintmax_t len, log_error_st * const errh) {
    char buf[24]; /* 64-bit (8 bytes) is 16 hex chars (+2 \r\n, +1 \0 = 19) */
  #if 0
    buffer b = { buf, 0, sizeof(buf) };
    buffer_append_uint_hex(&b, len);
    buffer_append_string_len(&b, CONST_STR_LEN("\r\n"));
    return chunkqueue_append_mem_to_tempfile(cq, b.ptr, b.used-1, errh);
  #else
    int i = (int)(sizeof(buf));
    buf[--i] = '\n';
    buf[--i] = '\r';
    do { buf[--i] = "0123456789abcdef"[len & 0x0F]; } while (len >>= 4);
    return chunkqueue_append_mem_to_tempfile(cq, buf+i, sizeof(buf)-i, errh);
  #endif
}

__attribute_noinline__
static int http_chunk_append_read_fd_range(request_st * const r, const buffer * const fn, const int fd, off_t offset, off_t len) {
    /* note: this routine should not be used for range requests
     * unless the total size of ranges requested is small */
    /* note: future: could read into existing MEM_CHUNK in cq->last if
     * there is sufficient space, but would need to adjust for existing
     * offset in for cq->bytes_in in chunkqueue_append_buffer_commit() */
    UNUSED(fn);

    chunkqueue * const cq = &r->write_queue;

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    buffer * const b = chunkqueue_append_buffer_open_sz(cq, len+2+1);
    ssize_t rd;
    const off_t foff = offset;
    offset = 0;
    do {
        rd = chunk_file_pread(fd, b->ptr+offset, (size_t)len, foff+offset);
    } while (rd > 0 && (offset += rd, len -= rd));
    buffer_commit(b, offset);

    if (r->resp_send_chunked)
        buffer_append_string_len(b, CONST_STR_LEN("\r\n"));

    chunkqueue_append_buffer_commit(cq);
    return (len == 0) ? 0 : -1;
}

__attribute_noinline__
void http_chunk_append_file_ref_range(request_st * const r, stat_cache_entry * const sce, const off_t offset, off_t len) {
    chunkqueue * const cq = &r->write_queue;

    if (sce->st.st_size - offset < len)
        len = sce->st.st_size - offset;
    if (len <= 0)
        return;

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    const buffer * const fn = &sce->name;
    const int fd = sce->fd;
    chunkqueue_append_file_fd(cq, fn, fd, offset, len);
    if (fd >= 0) {
        chunk * const d = cq->last;
        d->file.ref = sce;
        d->file.refchg = stat_cache_entry_refchg;
        stat_cache_entry_refchg(sce, 1);
    }

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
}

__attribute_noinline__
void http_chunk_append_file_fd_range(request_st * const r, const buffer * const fn, const int fd, const off_t offset, const off_t len) {
    chunkqueue * const cq = &r->write_queue;

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    chunkqueue_append_file_fd(cq, fn, fd, offset, len);

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
}

int http_chunk_append_file_fd(request_st * const r, const buffer * const fn, const int fd, const off_t sz) {
    if (sz > 32768 || !r->resp_send_chunked) {
        http_chunk_append_file_fd_range(r, fn, fd, 0, sz);
        return 0;
    }

    /*(read small files into memory)*/
    int rc = (0 != sz) ? http_chunk_append_read_fd_range(r,fn,fd,0,sz) : 0;
    close(fd);
    return rc;
}

int http_chunk_append_file_ref(request_st * const r, stat_cache_entry * const sce) {
    const off_t sz = sce->st.st_size;
    if (sz > 32768 || !r->resp_send_chunked) {
        http_chunk_append_file_ref_range(r, sce, 0, sz);
        return 0;
    }

    /*(read small files into memory)*/
    const buffer * const fn = &sce->name;
    const int fd = sce->fd;
    int rc = (0 != sz) ? http_chunk_append_read_fd_range(r,fn,fd,0,sz) : 0;
    return rc;
}

__attribute_noinline__
static int http_chunk_append_to_tempfile(request_st * const r, const char * const mem, const size_t len) {
    chunkqueue * const cq = &r->write_queue;
    log_error_st * const errh = r->conf.errh;

    if (r->resp_send_chunked
        && 0 != http_chunk_len_append_tempfile(cq, len, errh))
        return -1;

    if (0 != chunkqueue_append_mem_to_tempfile(cq, mem, len, errh))
        return -1;

    if (r->resp_send_chunked
        && 0 !=
           chunkqueue_append_mem_to_tempfile(cq, CONST_STR_LEN("\r\n"), errh))
        return -1;

    return 0;
}

__attribute_noinline__
static int http_chunk_append_cq_to_tempfile(request_st * const r, chunkqueue * const src, const size_t len) {
    chunkqueue * const cq = &r->write_queue;
    log_error_st * const errh = r->conf.errh;

    if (r->resp_send_chunked
        && 0 != http_chunk_len_append_tempfile(cq, len, errh))
        return -1;

    if (0 != chunkqueue_steal_with_tempfiles(cq, src, len, errh))
        return -1;

    if (r->resp_send_chunked
        && 0 !=
           chunkqueue_append_mem_to_tempfile(cq, CONST_STR_LEN("\r\n"), errh))
        return -1;

    return 0;
}

/*(inlined by compiler optimizer)*/
__attribute_pure__
static int http_chunk_uses_tempfile(const chunkqueue * const cq, const size_t len) {

    /* current usage does not append_mem or append_buffer after appending
     * file, so not checking if users of this interface have appended large
     * (references to) files to chunkqueue, which would not be in memory
     * (but included in calculation for whether or not to use temp file) */
    const chunk * const c = cq->last;
    return
      ((c && c->type == FILE_CHUNK && c->file.is_temp)
       || chunkqueue_length(cq) + len > 65536);
}

__attribute_noinline__
int http_chunk_append_buffer(request_st * const r, buffer * const mem) {
    size_t len = mem ? buffer_clen(mem) : 0;
    if (0 == len) return 0;

    chunkqueue * const cq = &r->write_queue;

    if (http_chunk_uses_tempfile(cq, len)) {
        int rc = http_chunk_append_to_tempfile(r, mem->ptr, len);
        buffer_clear(mem);
        return rc;
    }

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, len);

    /*(chunkqueue_append_buffer() might steal buffer contents)*/
    chunkqueue_append_buffer(cq, mem);

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

__attribute_noinline__
int http_chunk_append_mem(request_st * const r, const char * const mem, const size_t len) {
    if (0 == len) return 0;

    chunkqueue * const cq = &r->write_queue;

    if (http_chunk_uses_tempfile(cq, len))
        return http_chunk_append_to_tempfile(r, mem, len);

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, len);

    chunkqueue_append_mem(cq, mem, len);

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

int http_chunk_transfer_cqlen(request_st * const r, chunkqueue * const src, const size_t len) {
    if (0 == len) return 0;

    chunkqueue * const cq = &r->write_queue;

    if (http_chunk_uses_tempfile(cq, len))
        return http_chunk_append_cq_to_tempfile(r, src, len);

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, len);

    chunkqueue_steal(cq, src, len);

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

void http_chunk_close(request_st * const r) {
    if (!r->resp_send_chunked) return;

    if (r->gw_dechunk) {
        if (!r->gw_dechunk->done)
            r->keep_alive = 0;
    }
    else
        chunkqueue_append_mem(&r->write_queue, CONST_STR_LEN("0\r\n\r\n"));
}

static int
http_chunk_decode_append_data (request_st * const r, const char *mem, off_t len)
{
    if (r->gw_dechunk->done) return -1; /*(excess data)*/

    buffer * const h = &r->gw_dechunk->b;
    off_t te_chunked = r->gw_dechunk->gw_chunked;
    while (len) {
        if (0 == te_chunked) {
            const char *p;
            unsigned char *s = (unsigned char *)mem;
            off_t hsz;
            if (buffer_is_blank(h)) {
                /*(short-circuit common case: complete chunked header line)*/
                p = memchr(mem, '\n', (size_t)len);
                if (p)
                    hsz = (off_t)(++p - mem);
                else {
                    if (len >= 1024) {
                        log_error(r->conf.errh, __FILE__, __LINE__,
                          "chunked header line too long");
                        return -1;
                    }
                    buffer_append_string_len(h, mem, (uint32_t)len);
                    break; /* incomplete HTTP chunked header line */
                }
            }
            else {
                uint32_t hlen = buffer_clen(h);
                p = strchr(h->ptr, '\n');
                if (p)
                    hsz = (off_t)(++p - h->ptr);
                else {
                    p = memchr(mem, '\n', (size_t)len);
                    hsz = (p ? (off_t)(++p - mem) : len);
                    if ((off_t)(1024 - hlen) < hsz) {
                        log_error(r->conf.errh, __FILE__, __LINE__,
                          "chunked header line too long");
                        return -1;
                    }
                    buffer_append_string_len(h, mem, hsz);
                    if (NULL == p) break;/*incomplete HTTP chunked header line*/
                    mem += hsz;
                    len -= hsz;
                    hsz = 0;
                }
                s = (unsigned char *)h->ptr;/*(note: read h->ptr after append)*/
            }

            for (unsigned char u; (u=(unsigned char)hex2int(*s))!=0xFF; ++s) {
                if (te_chunked > (off_t)(1uLL<<(8*sizeof(off_t)-5))-1-2) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked data size too large");
                    return -1;
                }
                te_chunked <<= 4;
                te_chunked |= u;
            }
            if ((char *)s == mem || (char *)s == h->ptr) return -1; /*(no hex)*/
            while (*s == ' ' || *s == '\t') ++s;
            if (*s != '\r' && *s != ';') { /*(not strictly checking \r\n)*/
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "chunked header invalid chars");
                return -1;
            }

            if (0 == te_chunked) {
                /* do not consume final chunked header until
                 * (optional) trailers received along with
                 * request-ending blank line "\r\n" */
                if (len - hsz >= 2 && p[0] == '\r' && p[1] == '\n') {
                    if (len - hsz > 2) return -1; /*(excess data)*/
                    /* common case with no trailers; final \r\n received */
                  #if 0 /*(avoid allocation for common case; users must check)*/
                    if (buffer_is_unset(h))
                        buffer_copy_string_len(h, CONST_STR_LEN("0\r\n\r\n"));
                  #else
                    buffer_clear(h);
                  #endif
                    r->gw_dechunk->done = r->http_status;
                    break;
                }

                /* accumulate trailers and check for end of trailers */
                /* XXX: reuse r->conf.max_request_field_size
                 *      or have separate limit? */
                uint32_t mlen = buffer_clen(h);
                mlen = (r->conf.max_request_field_size > mlen)
                     ?  r->conf.max_request_field_size - mlen
                     :  0;
                if ((off_t)mlen < len) {
                    /* truncate excessively long trailers */
                    /* (not truncated; passed as-is if r->resp_send_chunked) */
                    if (r->resp_send_chunked) r->keep_alive = 0;
                    r->gw_dechunk->done = r->http_status;
                    buffer_append_string_len(h, mem, mlen);
                    p = strrchr(h->ptr, '\n');
                    if (NULL != p) {
                        buffer_truncate(h, p + 1 - h->ptr);
                        if (p[-1] != '\r')
                            buffer_append_string_len(h, CONST_STR_LEN("\r\n"));
                    }
                    else { /*(should not happen)*/
                        buffer_clear(h);
                        buffer_append_string_len(h, CONST_STR_LEN("0\r\n"));
                    }
                    buffer_append_string_len(h, CONST_STR_LEN("\r\n"));
                    break;
                }
                buffer_append_string_len(h, mem, (uint32_t)len);
                if ((p = strstr(h->ptr, "\r\n\r\n"))) {
                    r->gw_dechunk->done = r->http_status;
                    if (p[4] != '\0') return -1; /*(excess data)*/
                        /*buffer_truncate(h, (uint32_t)(p+4-h->ptr));*/
                }
                break;
            }

            mem += hsz;
            len -= hsz;

            te_chunked += 2; /*(for trailing "\r\n" after chunked data)*/
            buffer_clear(h);
            if (0 == len) break;
        }

        if (te_chunked >= 2) {
            off_t clen = te_chunked - 2;
            if (clen > len) clen = len;
            if (!r->resp_send_chunked
                && 0 != http_chunk_append_mem(r, mem, clen))
                return -1;
            mem += clen;
            len -= clen;
            te_chunked -= clen;
            if (te_chunked == 2) {
                if (len >= 2) {
                    if (mem[0] != '\r' || mem[1] != '\n') return -1;
                    mem += 2;
                    len -= 2;
                    te_chunked = 0;
                }
                else if (len == 1) {
                    if (mem[0] != '\r') return -1;
                    /*++mem;*/
                    /*--len;*/
                    te_chunked = 1;
                    break;
                }
            }
        }
        else if (1 == te_chunked) {
            /* finish reading chunk block "\r\n" */
            if (mem[0] != '\n') return -1;
            ++mem;
            --len;
            te_chunked = 0;
        }
    }
    if (r->gw_dechunk->done)
        r->resp_body_finished = 1;
    r->gw_dechunk->gw_chunked = te_chunked;
    return 0;
}

int http_chunk_decode_append_buffer(request_st * const r, buffer * const mem)
{
    /* Note: this routine is separate from http_chunk_decode_append_mem() to
     * potentially avoid copying in http_chunk_append_buffer().  Otherwise this
     * would be: return http_chunk_decode_append_mem(r, BUF_PTR_LEN(mem)); */

    /*(called by funcs receiving chunked data from backends)*/
    /*(separate from http_chunk_append_buffer() called by numerous others)*/

    /* might avoid copy by transferring buffer if buffer is all data that is
     * part of large chunked block, but choosing to *not* expand that out here*/
    if (0 != http_chunk_decode_append_data(r, BUF_PTR_LEN(mem)))
        return -1;

    /* no need to decode chunked to immediately re-encode chunked;
     * pass through chunked encoding as provided by backend,
     * though it is still parsed (above) to maintain state.
     * XXX: consider having callers use chunk buffers for hctx->b
     *      for more efficient data copy avoidance and buffer reuse
     * note: r->resp_send_chunked = 0 until response headers sent,
     * which is when Transfer-Encoding: chunked might be chosen */
    if (r->resp_send_chunked) {
        r->resp_send_chunked = 0;
        int rc = http_chunk_append_buffer(r, mem); /* might append to tmpfile */
        r->resp_send_chunked = 1;
        return rc;
    }
    else
        buffer_clear(mem);

    return 0;
}

int http_chunk_decode_append_mem(request_st * const r, const char * const mem, size_t len)
{
    /*(called by funcs receiving chunked data from backends)*/
    /*(separate from http_chunk_append_mem() called by numerous others)*/

    if (0 != http_chunk_decode_append_data(r, mem, (off_t)len))
        return -1;

    /* no need to decode chunked to immediately re-encode chunked;
     * pass through chunked encoding as provided by backend,
     * though it is still parsed (above) to maintain state.
     * note: r->resp_send_chunked = 0 until response headers sent,
     * which is when Transfer-Encoding: chunked might be chosen */
    if (r->resp_send_chunked) {
        r->resp_send_chunked = 0;
        int rc = http_chunk_append_mem(r, mem, len); /*might append to tmpfile*/
        r->resp_send_chunked = 1;
        return rc;
    }

    return 0;
}
