#include "network_backends.h"

#ifdef USE_WRITEV

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "stat_cache.h"

#ifndef UIO_MAXIOV
# if defined(__FreeBSD__) || defined(__APPLE__) || defined(__NetBSD__)
/* FreeBSD 4.7 defines it in sys/uio.h only if _KERNEL is specified */ 
#  define UIO_MAXIOV 1024
# elif defined(__sgi)
/* IRIX 6.5 has sysconf(_SC_IOV_MAX) which might return 512 or bigger */ 
#  define UIO_MAXIOV 512
# elif defined(__sun)
/* Solaris (and SunOS?) defines IOV_MAX instead */
#  ifndef IOV_MAX
#   define UIO_MAXIOV 16
#  else
#   define UIO_MAXIOV IOV_MAX
#  endif
# elif defined(IOV_MAX)
#  define UIO_MAXIOV IOV_MAX
# else
#  error UIO_MAXIOV nor IOV_MAX are defined
# endif
#endif

int network_write_chunkqueue_writev(server *srv, connection *con, int fd, chunkqueue *cq) {
	chunk *c;
	size_t chunks_written = 0;
	
	for(c = cq->first; c; c = c->next) {
		int chunk_finished = 0;
		
		switch(c->type) {
		case MEM_CHUNK: {
			char * offset;
			size_t toSend;
			ssize_t r;
			
			size_t num_chunks, i;
			struct iovec chunks[UIO_MAXIOV];
			chunk *tc;
			size_t num_bytes = 0;
			
			/* we can't send more then SSIZE_MAX bytes in one chunk */
			
			/* build writev list 
			 * 
			 * 1. limit: num_chunks < UIO_MAXIOV
			 * 2. limit: num_bytes < SSIZE_MAX
			 */
			for(num_chunks = 0, tc = c; tc && tc->type == MEM_CHUNK && num_chunks < UIO_MAXIOV; num_chunks++, tc = tc->next);
			
			for(tc = c, i = 0; i < num_chunks; tc = tc->next, i++) {
				if (tc->mem->used == 0) {
					chunks[i].iov_base = tc->mem->ptr;
					chunks[i].iov_len  = 0;
				} else {
					offset = tc->mem->ptr + tc->offset;
					toSend = tc->mem->used - 1 - tc->offset;
				
					chunks[i].iov_base = offset;
					
					/* protect the return value of writev() */
					if (toSend > SSIZE_MAX ||
					    num_bytes + toSend > SSIZE_MAX) {
						chunks[i].iov_len = SSIZE_MAX - num_bytes;
						
						num_chunks = i + 1;
						break;
					} else {
						chunks[i].iov_len = toSend;
					}
					
					num_bytes += toSend;
				}
			}
			
			if ((r = writev(fd, chunks, num_chunks)) < 0) {
				switch (errno) {
				case EAGAIN:
				case EINTR:
					r = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					return -2;
				default:
					log_error_write(srv, __FILE__, __LINE__, "ssd", 
							"writev failed:", strerror(errno), fd);
				
					return -1;
				}
			}
			
			cq->bytes_out += r;

			/* check which chunks have been written */
			
			for(i = 0, tc = c; i < num_chunks; i++, tc = tc->next) {
				if (r >= (ssize_t)chunks[i].iov_len) {
					/* written */
					r -= chunks[i].iov_len;
					tc->offset += chunks[i].iov_len;
					
					if (chunk_finished) {
						/* skip the chunks from further touches */
						chunks_written++;
						c = c->next;
					} else {
						/* chunks_written + c = c->next is done in the for()*/
						chunk_finished++;
					}
				} else {
					/* partially written */
					
					tc->offset += r;
					chunk_finished = 0;

					break;
				}
			}
			
			break;
		}
		case FILE_CHUNK: {
			ssize_t r;
			off_t offset;
			size_t toSend;
			stat_cache_entry *sce = NULL;
			
			if (HANDLER_ERROR == stat_cache_get_entry(srv, con, c->file.name, &sce)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						strerror(errno), c->file.name);
				return -1;
			}

			offset = c->file.offset + c->offset;
			toSend = c->file.length - c->offset;
			
			if (offset > sce->st.st_size) {
				log_error_write(srv, __FILE__, __LINE__, "sb", 
						"file was shrinked:", c->file.name);
				
				return -1;
			}

			if (c->file.mmap.start == MAP_FAILED) {
				if (-1 == c->file.fd &&  /* open the file if not already open */
				    -1 == (c->file.fd = open(c->file.name->ptr, O_RDONLY))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));
				
					return -1;
				}

				/* Optimizations for the future:
				 *
				 * adaptive mem-mapping
				 *   the problem:
				 *     we mmap() the whole file. If someone has alot large files and 32bit
				 *     machine the virtual address area will be unrun and we will have a failing 
				 *     mmap() call.
				 *   solution:
				 *     only mmap 16M in one chunk and move the window as soon as we have finished
				 *     the first 8M
				 *
				 * read-ahead buffering
				 *   the problem:
				 *     sending out several large files in parallel trashes the read-ahead of the
				 *     kernel leading to long wait-for-seek times.
				 *   solutions: (increasing complexity)
				 *     1. use madvise
				 *     2. use a internal read-ahead buffer in the chunk-structure
				 *     3. use non-blocking IO for file-transfers
				 *   */
			

				if (MAP_FAILED == (c->file.mmap.start = mmap(0, sce->st.st_size, PROT_READ, MAP_SHARED, c->file.fd, 0))) {
					/* close it here, otherwise we'd have to set FD_CLOEXEC */
					close(c->file.fd);
					c->file.fd = -1;
					log_error_write(srv, __FILE__, __LINE__, "ssbd", "mmap failed: ", 
							strerror(errno), c->file.name,  c->file.fd);

					return -1;
				}
#ifdef USE_MADVISE
				/* we should use a sliding window here and only advise on the mmaped range and not
				 * on the full file (waiting for adaptive mem-mapping) */
				if (0 != madvise(c->file.mmap.start, sce->st.st_size, MADV_SEQUENTIAL)) {
					log_error_write(srv, __FILE__, __LINE__, "ssbd", "madvise failed: ", 
							strerror(errno), c->file.name,  c->file.fd);

					return -1;
				}
#endif

				close(c->file.fd);
				c->file.fd = -1;

				c->file.mmap.length = sce->st.st_size;

				/* chunk_reset() or chunk_free() will cleanup for us */
			}

			if ((r = write(fd, c->file.mmap.start + offset, toSend)) < 0) {
				switch (errno) {
				case EAGAIN:
				case EINTR:
					r = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					return -2;
				default:
					log_error_write(srv, __FILE__, __LINE__, "ssd", 
							"write failed:", strerror(errno), fd);
					
					return -1;
				}
			}
			
			c->offset += r;
			cq->bytes_out += r;
			
			if (c->offset == c->file.length) {
				chunk_finished = 1;

				/* we don't need the mmaping anymore */
				if (c->file.mmap.start != MAP_FAILED) {
					munmap(c->file.mmap.start, c->file.mmap.length);
					c->file.mmap.start = MAP_FAILED;
				}
			}
			
			break;
		}
		default:
			
			log_error_write(srv, __FILE__, __LINE__, "ds", c, "type not known");
			
			return -1;
		}
		
		if (!chunk_finished) {
			/* not finished yet */
			
			break;
		}
		
		chunks_written++;
	}

	return chunks_written;
}

#endif
