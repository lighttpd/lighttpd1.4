#include "network_backends.h"

#ifdef USE_OPENSSL
#include <sys/types.h>
#include <sys/socket.h>
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

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "file_cache.h"

# include <openssl/ssl.h> 
# include <openssl/err.h> 

int network_write_chunkqueue_openssl(server *srv, connection *con, chunkqueue *cq) {
	int ssl_r;
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
			
			/**
			 * SSL_write man-page
			 * 
			 * WARNING
			 *        When an SSL_write() operation has to be repeated because of
			 *        SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be
			 *        repeated with the same arguments.
			 * 
			 */
			
			if ((r = SSL_write(con->ssl, offset, toSend)) <= 0) {
				switch ((ssl_r = SSL_get_error(con->ssl, r))) {
				case SSL_ERROR_WANT_WRITE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* clean shutdown on the remote side */
					
					if (r == 0) return -2;
					
					/* fall thourgh */
				default:
					log_error_write(srv, __FILE__, __LINE__, "sdds", "SSL:", 
							ssl_r, r,
							ERR_error_string(ERR_get_error(), NULL));
					
					return  -1;
				}
			} else {
				c->offset += r;
				con->bytes_written += r;
			}
			
			if (c->offset == (off_t)c->data.mem->used - 1) {
				chunk_finished = 1;
			}
			
			break;
		}
		case FILE_CHUNK: {
			char *s;
			ssize_t r;
			off_t offset;
			size_t toSend;
# if defined USE_MMAP
			char *p;
# endif
			
			if (HANDLER_GO_ON != file_cache_get_entry(srv, con, c->data.file.name, &(con->fce))) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						strerror(errno), c->data.file.name);
				return -1;
			}
			
			offset = c->data.file.offset + c->offset;
			toSend = c->data.file.length - c->offset;
			
			
#if defined USE_MMAP
			if (MAP_FAILED == (p = mmap(0, con->fce->st.st_size, PROT_READ, MAP_SHARED, con->fce->fd, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "mmap failed: ", strerror(errno));
				
				return -1;
			}
			
			s = p + offset;
#else
			buffer_prepare_copy(srv->tmp_buf, toSend);
			
			lseek(con->fce->fd, offset, SEEK_SET);
			if (-1 == (toSend = read(con->fce->fd, srv->tmp_buf->ptr, toSend))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "read failed: ", strerror(errno));
				
				return -1;
			}
			
			s = srv->tmp_buf->ptr;
#endif
			
			if ((r = SSL_write(con->ssl, s, toSend)) <= 0) {
				switch ((ssl_r = SSL_get_error(con->ssl, r))) {
				case SSL_ERROR_WANT_WRITE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					/* clean shutdown on the remote side */
					
					if (r == 0) {
#if defined USE_MMAP
						munmap(p, c->data.file.length);
#endif
						return -2;
					}
					
					/* fall thourgh */
				default:
					log_error_write(srv, __FILE__, __LINE__, "sdds", "SSL:", 
							ssl_r, r, 
							ERR_error_string(ERR_get_error(), NULL));
					
#if defined USE_MMAP
					munmap(p, c->data.file.length);
#endif
					return -1;
				}
			} else {
				c->offset += r;
				con->bytes_written += r;
			}
			
#if defined USE_MMAP
			munmap(p, c->data.file.length);
#endif
			
			if (c->offset == c->data.file.length) {
				chunk_finished = 1;
			}
			
			break;
		}
		default:
			log_error_write(srv, __FILE__, __LINE__, "s", "type not known");
			
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

#if 0
network_openssl_init(void) {
	p->write_ssl = network_openssl_write_chunkset;
}
#endif
