/*
 * http_chunk - append response to chunkqueue, possibly in "chunked" encoding
 *
 * Fully-rewritten from original
 * Copyright(c) 2019 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include "http_chunk.h"
#include "base.h"
#include "chunk.h"
#include "stat_cache.h"
#include "fdevent.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>

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

static int http_chunk_append_file_open_fstat(const request_st * const r, const buffer * const fn, struct stat * const st) {
    return
      (r->conf.follow_symlink
       || !stat_cache_path_contains_symlink(fn, r->conf.errh))
        ? stat_cache_open_rdonly_fstat(fn, st, r->conf.follow_symlink)
        : -1;
}

static int http_chunk_append_read_fd_range(request_st * const r, const buffer * const fn, const int fd, off_t offset, off_t len) {
    /* note: this routine should not be used for range requests
     * unless the total size of ranges requested is small */
    /* note: future: could read into existing MEM_CHUNK in cq->last if
     * there is sufficient space, but would need to adjust for existing
     * offset in for cq->bytes_in in chunkqueue_append_buffer_commit() */
    UNUSED(fn);

    chunkqueue * const cq = r->write_queue;

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    if (0 != offset && -1 == lseek(fd, offset, SEEK_SET)) return -1;
    buffer * const b = chunkqueue_append_buffer_open_sz(cq, len+2);
    ssize_t rd;
    offset = 0;
    do {
        rd = read(fd, b->ptr+offset, len-offset);
    } while (rd > 0 ? (offset += rd, len -= rd) : errno == EINTR);
    buffer_commit(b, offset);

    if (r->resp_send_chunked)
        buffer_append_string_len(b, CONST_STR_LEN("\r\n"));

    chunkqueue_append_buffer_commit(cq);
    return (rd >= 0) ? 0 : -1;
}

static void http_chunk_append_file_fd_range(request_st * const r, const buffer * const fn, const int fd, const off_t offset, const off_t len) {
    chunkqueue * const cq = r->write_queue;

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, (uintmax_t)len);

    chunkqueue_append_file_fd(cq, fn, fd, offset, len);

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));
}

int http_chunk_append_file_range(request_st * const r, const buffer * const fn, const off_t offset, off_t len) {
    struct stat st;
    const int fd = http_chunk_append_file_open_fstat(r, fn, &st);
    if (fd < 0) return -1;

    if (-1 == len) {
        if (offset >= st.st_size) {
            close(fd);
            return (offset == st.st_size) ? 0 : -1;
        }
        len = st.st_size - offset;
    }
    else if (st.st_size - offset < len) {
        close(fd);
        return -1;
    }

    http_chunk_append_file_fd_range(r, fn, fd, offset, len);
    return 0;
}

int http_chunk_append_file(request_st * const r, const buffer * const fn) {
    struct stat st;
    const int fd = http_chunk_append_file_open_fstat(r, fn, &st);
    if (fd < 0) return -1;
    http_chunk_append_file_fd(r, fn, fd, st.st_size);
    return 0;
}

int http_chunk_append_file_fd(request_st * const r, const buffer * const fn, const int fd, const off_t sz) {
    if (sz > 32768) {
        http_chunk_append_file_fd_range(r, fn, fd, 0, sz);
        return 0;
    }

    /*(read small files into memory)*/
    int rc = (0 != sz) ? http_chunk_append_read_fd_range(r,fn,fd,0,sz) : 0;
    close(fd);
    return rc;
}

static int http_chunk_append_to_tempfile(request_st * const r, const char * const mem, const size_t len) {
    chunkqueue * const cq = r->write_queue;
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

static int http_chunk_append_cq_to_tempfile(request_st * const r, chunkqueue * const src, const size_t len) {
    chunkqueue * const cq = r->write_queue;
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

__attribute_pure__
static int http_chunk_uses_tempfile(const request_st * const r, const chunkqueue * const cq, const size_t len) {

    /* current usage does not append_mem or append_buffer after appending
     * file, so not checking if users of this interface have appended large
     * (references to) files to chunkqueue, which would not be in memory
     * (but included in calculation for whether or not to use temp file) */

    /*(allow slightly larger mem use if FDEVENT_STREAM_RESPONSE_BUFMIN
     * to reduce creation of temp files when backend producer will be
     * blocked until more data is sent to network to client)*/

    const chunk * const c = cq->last;
    return
      ((c && c->type == FILE_CHUNK && c->file.is_temp)
       || cq->bytes_in - cq->bytes_out + len
          > ((r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
             ? 128*1024
             :  64*1024));
}

int http_chunk_append_buffer(request_st * const r, buffer * const mem) {
    size_t len = buffer_string_length(mem);
    if (0 == len) return 0;

    chunkqueue * const cq = r->write_queue;

    if (http_chunk_uses_tempfile(r, cq, len))
        return http_chunk_append_to_tempfile(r, mem->ptr, len);

    if (r->resp_send_chunked)
        http_chunk_len_append(cq, len);

    /*(chunkqueue_append_buffer() might steal buffer contents)*/
    chunkqueue_append_buffer(cq, mem);

    if (r->resp_send_chunked)
        chunkqueue_append_mem(cq, CONST_STR_LEN("\r\n"));

    return 0;
}

int http_chunk_append_mem(request_st * const r, const char * const mem, const size_t len) {
    if (0 == len) return 0;
    force_assert(NULL != mem);

    chunkqueue * const cq = r->write_queue;

    if (http_chunk_uses_tempfile(r, cq, len))
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

    chunkqueue * const cq = r->write_queue;

    if (http_chunk_uses_tempfile(r, cq, len))
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

    if (r->gw_dechunk && !buffer_string_is_empty(&r->gw_dechunk->b)) {
        /* XXX: trailers passed through; no sanity check currently done */
        chunkqueue_append_buffer(r->write_queue, &r->gw_dechunk->b);
        if (!r->gw_dechunk->done)
            r->keep_alive = 0;
    }
    else
        chunkqueue_append_mem(r->write_queue, CONST_STR_LEN("0\r\n\r\n"));
}

static int
http_chunk_decode_append_data (request_st * const r, const char *mem, off_t len)
{
    /*(silently discard data, if any, after final \r\n)*/
    if (r->gw_dechunk->done) return 0;

    buffer * const h = &r->gw_dechunk->b;
    off_t te_chunked = r->gw_dechunk->gw_chunked;
    while (len) {
        if (0 == te_chunked) {
            const char *p = strchr(mem, '\n');
            /*(likely better ways to handle chunked header crossing chunkqueue
             * chunks, but this situation is not expected to occur frequently)*/
            if (NULL == p) { /* incomplete HTTP chunked header line */
                uint32_t hlen = buffer_string_length(h);
                if ((off_t)(1024 - hlen) < len) {
                    log_error(r->conf.errh, __FILE__, __LINE__,
                      "chunked header line too long");
                    return -1;
                }
                buffer_append_string_len(h, mem, len);
                break;
            }

            off_t hsz = ++p - mem;
            unsigned char *s = (unsigned char *)mem;
            if (!buffer_string_is_empty(h)) {
                uint32_t hlen = buffer_string_length(h);
                if (NULL == memchr(h->ptr, '\n', hlen)) {
                    if ((off_t)(1024 - hlen) < hsz) {
                        log_error(r->conf.errh, __FILE__, __LINE__,
                          "chunked header line too long");
                        return -1;
                    }
                    buffer_append_string_len(h, mem, hsz);
                }
                s = (unsigned char *)h->ptr;
            }
            for (unsigned char u; (u=(unsigned char)hex2int(*s))!=0xFF; ++s) {
                if (te_chunked > (off_t)(1uLL<<(8*sizeof(off_t)-5))-1) {
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
                if (len - hsz == 2 && p[0] == '\r' && p[1] == '\n') {
                    /* common case with no trailers; final \r\n received */
                    /*(silently discard data, if any, after final \r\n)*/
                  #if 0 /*(avoid allocation for common case; users must check)*/
                    if (buffer_is_empty(h))
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
                uint32_t hlen = buffer_string_length(h);
                if ((off_t)(r->conf.max_request_field_size - hlen) < hsz) {
                    /* truncate excessively long trailers */
                    r->gw_dechunk->done = r->http_status;
                    hsz = (off_t)(r->conf.max_request_field_size - hlen);
                    buffer_append_string_len(h, mem, hsz);
                    p = strrchr(h->ptr, '\n');
                    if (NULL != p)
                        buffer_string_set_length(h, p + 1 - h->ptr);
                    else { /*(should not happen)*/
                        buffer_clear(h);
                        buffer_append_string_len(h, CONST_STR_LEN("0\r\n"));
                    }
                    buffer_append_string_len(h, CONST_STR_LEN("\r\n"));
                    break;
                }
                buffer_append_string_len(h, mem, hsz);
                hlen += (uint32_t)hsz; /* uint32_t fits in (buffer *) */
                if (hlen < 4) break;
                p = h->ptr + hlen - 4;
                if (p[0]=='\r'&&p[1]=='\n'&&p[2]=='\r'&&p[3]=='\n')
                    r->gw_dechunk->done = r->http_status;
                else if ((p = strstr(h->ptr, "\r\n\r\n"))) {
                    r->gw_dechunk->done = r->http_status;
                    /*(silently discard data, if any, after final \r\n)*/
                    buffer_string_set_length(h, (uint32_t)(p+4-h->ptr));
                }
                break;
            }

            mem += hsz;
            len -= hsz;

            if (te_chunked > (off_t)(1uLL<<(8*sizeof(off_t)-5))-1-2) {
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "chunked data size too large");
                return -1;
            }
            te_chunked += 2; /*(for trailing "\r\n" after chunked data)*/
        }

        if (te_chunked >= 2) {
            off_t clen = te_chunked - 2;
            if (clen > len) clen = len;
            if (0 != http_chunk_append_mem(r, mem, clen))
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
                else if (len == 1 && mem[0] != '\r') return -1;
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
    r->gw_dechunk->gw_chunked = te_chunked;
    return 0;
}

int http_chunk_decode_append_buffer(request_st * const r, buffer * const mem)
{
    /*(called by funcs receiving data from backends, which might be chunked)*/
    /*(separate from http_chunk_append_buffer() called by numerous others)*/
    if (!r->resp_decode_chunked)
        return http_chunk_append_buffer(r, mem);

    /* no need to decode chunked to immediately re-encode chunked,
     * though would be more robust to still validate chunk lengths sent
     * (or else we might wait for keep-alive while client waits for final chunk)
     * Before finishing response/stream, we *are not* checking if we got final
     * chunk of chunked encoding from backend.  If we were, we could consider
     * closing HTTP/1.0 and HTTP/1.1 connections (no keep-alive), and in HTTP/2
     * we could consider sending RST_STREAM error.  http_chunk_close() would
     * only handle case of streaming chunked to client */
    if (r->resp_send_chunked) {
        r->resp_send_chunked = 0;
        int rc = http_chunk_append_buffer(r, mem); /* might append to tmpfile */
        r->resp_send_chunked = 1;
        return rc;
    }

    /* might avoid copy by transferring buffer if buffer is all data that is
     * part of large chunked block, but choosing to *not* expand that out here*/
    return http_chunk_decode_append_data(r, CONST_BUF_LEN(mem));
}

int http_chunk_decode_append_mem(request_st * const r, const char * const mem, const size_t len)
{
    /*(called by funcs receiving data from backends, which might be chunked)*/
    /*(separate from http_chunk_append_mem() called by numerous others)*/
    if (!r->resp_decode_chunked)
        return http_chunk_append_mem(r, mem, len);

    /* no need to decode chunked to immediately re-encode chunked,
     * though would be more robust to still validate chunk lengths sent
     * (or else we might wait for keep-alive while client waits for final chunk)
     * Before finishing response/stream, we *are not* checking if we got final
     * chunk of chunked encoding from backend.  If we were, we could consider
     * closing HTTP/1.0 and HTTP/1.1 connections (no keep-alive), and in HTTP/2
     * we could consider sending RST_STREAM error.  http_chunk_close() would
     * only handle case of streaming chunked to client */
    if (r->resp_send_chunked) {
        r->resp_send_chunked = 0;
        int rc = http_chunk_append_mem(r, mem, len); /*might append to tmpfile*/
        r->resp_send_chunked = 1;
        return rc;
    }

    return http_chunk_decode_append_data(r, mem, (off_t)len);
}
