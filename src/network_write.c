#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "file_cache.h"

#include "sys-socket.h"

#include "network_backends.h"

int network_write_chunkqueue_write(server *srv, connection *con, chunkqueue *cq) {
	const int fd = con->fd;
	chunk *c;
	size_t chunks_written = 0;
	
	for(c = cq->first; c; c = c->next) {
		int chunk_finished = 0;
		
		switch(c->type) {
		case MEM_CHUNK: {
			char * offset;
			size_t toSend;
			ssize_t r;
			
			if (c->data.mem->used == 0) {
				chunk_finished = 1;
				break;
			}
			
			offset = c->data.mem->ptr + c->offset;
			toSend = c->data.mem->used - 1 - c->offset;
#ifdef __WIN32	
			if ((r = send(fd, offset, toSend, 0)) < 0) {
				log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed: ", strerror(errno), fd);
				
				return -1;
			}
#else
			if ((r = write(fd, offset, toSend)) < 0) {
				log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed: ", strerror(errno), fd);
				
				return -1;
			}
#endif
			
			c->offset += r;
			con->bytes_written += r;
			
			if (c->offset == (off_t)c->data.mem->used - 1) {
				chunk_finished = 1;
			}
			
			break;
		}
		case FILE_CHUNK: {
#ifdef USE_MMAP
			char *p = NULL;
#endif
			ssize_t r;
			off_t offset;
			size_t toSend;
			
			if (HANDLER_GO_ON != file_cache_get_entry(srv, con, c->data.file.name, &(con->fce))) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						strerror(errno), c->data.file.name);
				return -1;
			}
			
			offset = c->data.file.offset + c->offset;
			toSend = c->data.file.length - c->offset;
			
			if (offset > con->fce->st.st_size) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "file was shrinked:", c->data.file.name);
				
				return -1;
			}
			
			if (-1 == con->fce->fd) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "fd is invalid", c->data.file.name);
				
				return -1;
			}
			
#if defined USE_MMAP
			/* check if the mapping fits */
			if (con->fce->mmap_p &&
			    con->fce->mmap_length != con->fce->st.st_size &&
			    con->fce->mmap_offset != 0) {
				munmap(con->fce->mmap_p, con->fce->mmap_length);
				
				con->fce->mmap_p = NULL;
			}
			
			/* build mapping if neccesary */
			if (con->fce->mmap_p == NULL) {
				if (MAP_FAILED == (p = mmap(0, con->fce->st.st_size, PROT_READ, MAP_SHARED, con->fce->fd, 0))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "mmap failed: ", strerror(errno));
					
					return -1;
				}
				con->fce->mmap_p = p;
				con->fce->mmap_offset = 0;
				con->fce->mmap_length = con->fce->st.st_size;
			} else {
				p = con->fce->mmap_p;
			}
			
			if ((r = write(fd, p + offset, toSend)) <= 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "write failed: ", strerror(errno));
				
				return -1;
			}
			
			/* don't cache mmap()ings for files large then 64k */
			if (con->fce->mmap_length > 64 * 1024) {
				munmap(con->fce->mmap_p, con->fce->mmap_length);
				
				con->fce->mmap_p = NULL;
			}
			
#else
			buffer_prepare_copy(srv->tmp_buf, toSend);
			
			lseek(con->fce->fd, offset, SEEK_SET);
			if (-1 == (toSend = read(con->fce->fd, srv->tmp_buf->ptr, toSend))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "read: ", strerror(errno));
				
				return -1;
			}
#ifdef __WIN32
			if (-1 == (r = send(fd, srv->tmp_buf->ptr, toSend, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "write: ", strerror(errno));
				
				return -1;
			}
#else			
			if (-1 == (r = write(fd, srv->tmp_buf->ptr, toSend))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "write: ", strerror(errno));
				
				return -1;
			}
#endif
#endif
			c->offset += r;
			con->bytes_written += r;
			
			if (c->offset == c->data.file.length) {
				chunk_finished = 1;
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

#if 0
network_write_init(void) {
	p->write = network_write_write_chunkset;
}
#endif
