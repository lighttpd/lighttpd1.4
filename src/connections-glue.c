#include "first.h"

#include "base.h"
#include "connections.h"
#include "joblist.h"
#include "log.h"

#include <errno.h>

#ifdef USE_OPENSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

const char *connection_get_state(connection_state_t state) {
	switch (state) {
	case CON_STATE_CONNECT: return "connect";
	case CON_STATE_READ: return "read";
	case CON_STATE_READ_POST: return "readpost";
	case CON_STATE_WRITE: return "write";
	case CON_STATE_CLOSE: return "close";
	case CON_STATE_ERROR: return "error";
	case CON_STATE_HANDLE_REQUEST: return "handle-req";
	case CON_STATE_REQUEST_START: return "req-start";
	case CON_STATE_REQUEST_END: return "req-end";
	case CON_STATE_RESPONSE_START: return "resp-start";
	case CON_STATE_RESPONSE_END: return "resp-end";
	default: return "(unknown)";
	}
}

const char *connection_get_short_state(connection_state_t state) {
	switch (state) {
	case CON_STATE_CONNECT: return ".";
	case CON_STATE_READ: return "r";
	case CON_STATE_READ_POST: return "R";
	case CON_STATE_WRITE: return "W";
	case CON_STATE_CLOSE: return "C";
	case CON_STATE_ERROR: return "E";
	case CON_STATE_HANDLE_REQUEST: return "h";
	case CON_STATE_REQUEST_START: return "q";
	case CON_STATE_REQUEST_END: return "Q";
	case CON_STATE_RESPONSE_START: return "s";
	case CON_STATE_RESPONSE_END: return "S";
	default: return "x";
	}
}

int connection_set_state(server *srv, connection *con, connection_state_t state) {
	UNUSED(srv);

	con->state = state;

	return 0;
}

#if 0
static void dump_packet(const unsigned char *data, size_t len) {
	size_t i, j;

	if (len == 0) return;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) fprintf(stderr, "  ");

		fprintf(stderr, "%02x ", data[i]);

		if ((i + 1) % 16 == 0) {
			fprintf(stderr, "  ");
			for (j = 0; j <= i % 16; j++) {
				unsigned char c;

				if (i-15+j >= len) break;

				c = data[i-15+j];

				fprintf(stderr, "%c", c > 32 && c < 128 ? c : '.');
			}

			fprintf(stderr, "\n");
		}
	}

	if (len % 16 != 0) {
		for (j = i % 16; j < 16; j++) {
			fprintf(stderr, "   ");
		}

		fprintf(stderr, "  ");
		for (j = i & ~0xf; j < len; j++) {
			unsigned char c;

			c = data[j];
			fprintf(stderr, "%c", c > 32 && c < 128 ? c : '.');
		}
		fprintf(stderr, "\n");
	}
}
#endif

static int connection_handle_read_ssl(server *srv, connection *con) {
#ifdef USE_OPENSSL
	int r, ssl_err, len;
	char *mem = NULL;
	size_t mem_len = 0;

	if (!con->srv_socket->is_ssl) return -1;

	ERR_clear_error();
	do {
		chunkqueue_get_memory(con->read_queue, &mem, &mem_len, 0, SSL_pending(con->ssl));
#if 0
		/* overwrite everything with 0 */
		memset(mem, 0, mem_len);
#endif

		len = SSL_read(con->ssl, mem, mem_len);
		if (len > 0) {
			chunkqueue_use_memory(con->read_queue, len);
			con->bytes_read += len;
		} else {
			chunkqueue_use_memory(con->read_queue, 0);
		}

		if (con->renegotiations > 1 && con->conf.ssl_disable_client_renegotiation) {
			log_error_write(srv, __FILE__, __LINE__, "s", "SSL: renegotiation initiated by client, killing connection");
			connection_set_state(srv, con, CON_STATE_ERROR);
			return -1;
		}
	} while (len > 0);

	if (len < 0) {
		int oerrno = errno;
		switch ((r = SSL_get_error(con->ssl, len))) {
		case SSL_ERROR_WANT_WRITE:
			con->is_writable = -1;
		case SSL_ERROR_WANT_READ:
			con->is_readable = 0;

			/* the manual says we have to call SSL_read with the same arguments next time.
			 * we ignore this restriction; no one has complained about it in 1.5 yet, so it probably works anyway.
			 */

			return 0;
		case SSL_ERROR_SYSCALL:
			/**
			 * man SSL_get_error()
			 *
			 * SSL_ERROR_SYSCALL
			 *   Some I/O error occurred.  The OpenSSL error queue may contain more
			 *   information on the error.  If the error queue is empty (i.e.
			 *   ERR_get_error() returns 0), ret can be used to find out more about
			 *   the error: If ret == 0, an EOF was observed that violates the
			 *   protocol.  If ret == -1, the underlying BIO reported an I/O error
			 *   (for socket I/O on Unix systems, consult errno for details).
			 *
			 */
			while((ssl_err = ERR_get_error())) {
				/* get all errors from the error-queue */
				log_error_write(srv, __FILE__, __LINE__, "sds", "SSL:",
						r, ERR_error_string(ssl_err, NULL));
			}

			switch(oerrno) {
			default:
				log_error_write(srv, __FILE__, __LINE__, "sddds", "SSL:",
						len, r, oerrno,
						strerror(oerrno));
				break;
			}

			break;
		case SSL_ERROR_ZERO_RETURN:
			/* clean shutdown on the remote side */

			if (r == 0) {
				/* FIXME: later */
			}

			/* fall thourgh */
		default:
			while((ssl_err = ERR_get_error())) {
				switch (ERR_GET_REASON(ssl_err)) {
				case SSL_R_SSL_HANDSHAKE_FAILURE:
			      #ifdef SSL_R_TLSV1_ALERT_UNKNOWN_CA
				case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
			      #endif
			      #ifdef SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN
				case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
			      #endif
			      #ifdef SSL_R_SSLV3_ALERT_BAD_CERTIFICATE
				case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
			      #endif
					if (!con->conf.log_ssl_noise) continue;
					break;
				default:
					break;
				}
				/* get all errors from the error-queue */
				log_error_write(srv, __FILE__, __LINE__, "sds", "SSL:",
				                r, ERR_error_string(ssl_err, NULL));
			}
			break;
		}

		connection_set_state(srv, con, CON_STATE_ERROR);

		return -1;
	} else if (len == 0) {
		con->is_readable = 0;
		/* the other end close the connection -> KEEP-ALIVE */

		return -2;
	} else {
		return 0;
	}
#else
	UNUSED(srv);
	UNUSED(con);
	return -1;
#endif
}

/* 0: everything ok, -1: error, -2: con closed */
int connection_handle_read(server *srv, connection *con) {
	int len;
	char *mem = NULL;
	size_t mem_len = 0;
	int toread;

	if (con->srv_socket->is_ssl) {
		return connection_handle_read_ssl(srv, con);
	}

	/* default size for chunks is 4kb; only use bigger chunks if FIONREAD tells
	 *  us more than 4kb is available
	 * if FIONREAD doesn't signal a big chunk we fill the previous buffer
	 *  if it has >= 1kb free
	 */
#if defined(__WIN32)
	chunkqueue_get_memory(con->read_queue, &mem, &mem_len, 0, 4096);

	len = recv(con->fd, mem, mem_len, 0);
#else /* __WIN32 */
	if (ioctl(con->fd, FIONREAD, &toread) || toread <= 4*1024) {
		toread = 4096;
	}
	else if (toread > MAX_READ_LIMIT) {
		toread = MAX_READ_LIMIT;
	}
	chunkqueue_get_memory(con->read_queue, &mem, &mem_len, 0, toread);

	len = read(con->fd, mem, mem_len);
#endif /* __WIN32 */

	chunkqueue_use_memory(con->read_queue, len > 0 ? len : 0);

	if (len < 0) {
		con->is_readable = 0;

#if defined(__WIN32)
		{
			int lastError = WSAGetLastError();
			switch (lastError) {
			case EAGAIN:
				return 0;
			case EINTR:
				/* we have been interrupted before we could read */
				con->is_readable = 1;
				return 0;
			case ECONNRESET:
				/* suppress logging for this error, expected for keep-alive */
				break;
			default:
				log_error_write(srv, __FILE__, __LINE__, "sd", "connection closed - recv failed: ", lastError);
				break;
			}
		}
#else /* __WIN32 */
		switch (errno) {
		case EAGAIN:
			return 0;
		case EINTR:
			/* we have been interrupted before we could read */
			con->is_readable = 1;
			return 0;
		case ECONNRESET:
			/* suppress logging for this error, expected for keep-alive */
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ssd", "connection closed - read failed: ", strerror(errno), errno);
			break;
		}
#endif /* __WIN32 */

		connection_set_state(srv, con, CON_STATE_ERROR);

		return -1;
	} else if (len == 0) {
		con->is_readable = 0;
		/* the other end close the connection -> KEEP-ALIVE */

		/* pipelining */

		return -2;
	} else if (len != (ssize_t) mem_len) {
		/* we got less then expected, wait for the next fd-event */

		con->is_readable = 0;
	}

	con->bytes_read += len;
#if 0
	dump_packet(b->ptr, len);
#endif

	return 0;
}

handler_t connection_handle_read_post_state(server *srv, connection *con) {
	chunkqueue *cq = con->read_queue;
	chunkqueue *dst_cq = con->request_content_queue;

	int is_closed = 0;

	if (con->is_readable) {
		con->read_idle_ts = srv->cur_ts;

		switch(connection_handle_read(srv, con)) {
		case -1:
			return HANDLER_ERROR;
		case -2:
			is_closed = 1;
			break;
		default:
			break;
		}
	}

	chunkqueue_remove_finished_chunks(cq);

	if (con->request.content_length <= 64*1024) {
		/* don't buffer request bodies <= 64k on disk */
		chunkqueue_steal(dst_cq, cq, (off_t)con->request.content_length - dst_cq->bytes_in);
	}
	else if (0 != chunkqueue_steal_with_tempfiles(srv, dst_cq, cq, (off_t)con->request.content_length - dst_cq->bytes_in)) {
		/* writing to temp file failed */
		con->http_status = 500; /* Internal Server Error */
		con->keep_alive = 0;
		con->mode = DIRECT;
		chunkqueue_reset(con->write_queue);

		return HANDLER_FINISHED;
	}

	chunkqueue_remove_finished_chunks(cq);

	if (dst_cq->bytes_in == (off_t)con->request.content_length) {
		/* Content is ready */
		con->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
		if (con->state == CON_STATE_READ_POST) {
			connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
		}
		return HANDLER_GO_ON;
	} else if (is_closed) {
	      #if 0
		con->http_status = 400; /* Bad Request */
		con->keep_alive = 0;
		con->mode = DIRECT;
		chunkqueue_reset(con->write_queue);

		return HANDLER_FINISHED;
	      #endif
		return HANDLER_ERROR;
	} else {
		con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
		return (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
		  ? HANDLER_GO_ON
		  : HANDLER_WAIT_FOR_EVENT;
	}
}

void connection_response_reset(server *srv, connection *con) {
	UNUSED(srv);

	con->http_status = 0;
	con->is_writable = 1;
	con->file_finished = 0;
	con->file_started = 0;
	con->got_response = 0;
	con->parsed_response = 0;
	con->response.keep_alive = 0;
	con->response.content_length = -1;
	con->response.transfer_encoding = 0;
	buffer_reset(con->physical.path);
	array_reset(con->response.headers);
	chunkqueue_reset(con->write_queue);
}
