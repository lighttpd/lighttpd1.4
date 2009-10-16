#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "connections.h"
#include "plugin.h"
#include "joblist.h"
#include "configfile.h"

#include "network_backends.h"
#include "sys-mmap.h"
#include "sys-socket.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef USE_OPENSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
#endif

static handler_t network_server_handle_fdevent(void *s, void *context, int revents) {
	server     *srv = (server *)s;
	server_socket *srv_socket = (server_socket *)context;
	connection *con;
	int loops = 0;

	UNUSED(context);

	if (revents != FDEVENT_IN) {
		log_error_write(srv, __FILE__, __LINE__, "sdd",
				"strange event for server socket",
				srv_socket->fd,
				revents);
		return HANDLER_ERROR;
	}

	/* accept()s at most 100 connections directly
	 *
	 * we jump out after 100 to give the waiting connections a chance */
	for (loops = 0; loops < 100 && NULL != (con = connection_accept(srv, srv_socket)); loops++) {
		handler_t r;

		connection_state_machine(srv, con);

		switch(r = plugins_call_handle_joblist(srv, con)) {
		case HANDLER_FINISHED:
		case HANDLER_GO_ON:
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "d", r);
			break;
		}
	}
	return HANDLER_GO_ON;
}

#if defined USE_OPENSSL && ! defined OPENSSL_NO_TLSEXT
static int network_ssl_servername_callback(SSL *ssl, int *al, server *srv) {
	const char *servername;
	connection *con = (connection *) SSL_get_app_data(ssl);
	UNUSED(al);

	buffer_copy_string(con->uri.scheme, "https");

	if (NULL == (servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))) {
#if 0
		/* this "error" just means the client didn't support it */
		log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
				"failed to get TLS server name");
#endif
		return SSL_TLSEXT_ERR_NOACK;
	}
	buffer_copy_string(con->tlsext_server_name, servername);
	buffer_to_lower(con->tlsext_server_name);

	config_cond_cache_reset(srv, con);
	config_setup_connection(srv, con);

	config_patch_connection(srv, con, COMP_SERVER_SOCKET);
	config_patch_connection(srv, con, COMP_HTTP_SCHEME);
	config_patch_connection(srv, con, COMP_HTTP_HOST);

	if (NULL == con->conf.ssl_ctx) {
		/* ssl_ctx <=> pemfile was set <=> ssl_ctx got patched: so this should never happen */
		log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
			"null SSL_CTX for TLS server name", con->tlsext_server_name);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	/* switch to new SSL_CTX in reaction to a client's server_name extension */
	if (con->conf.ssl_ctx != SSL_set_SSL_CTX(ssl, con->conf.ssl_ctx)) {
		log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
			"failed to set SSL_CTX for TLS server name", con->tlsext_server_name);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif

static int network_server_init(server *srv, buffer *host_token, specific_config *s) {
	int val;
	socklen_t addr_len;
	server_socket *srv_socket;
	char *sp;
	unsigned int port = 0;
	const char *host;
	buffer *b;
	int is_unix_domain_socket = 0;
	int fd;

#ifdef __WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		    /* Tell the user that we could not find a usable */
		    /* WinSock DLL.                                  */
		    return -1;
	}
#endif

	srv_socket = calloc(1, sizeof(*srv_socket));
	srv_socket->fd = -1;
	srv_socket->fde_ndx = -1;

	srv_socket->srv_token = buffer_init();
	buffer_copy_string_buffer(srv_socket->srv_token, host_token);

	b = buffer_init();
	buffer_copy_string_buffer(b, host_token);

	/* ipv4:port
	 * [ipv6]:port
	 */
	if (NULL == (sp = strrchr(b->ptr, ':'))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", "value of $SERVER[\"socket\"] has to be \"ip:port\".", b);

		goto error_free_socket;
	}

	host = b->ptr;

	/* check for [ and ] */
	if (b->ptr[0] == '[' && *(sp-1) == ']') {
		*(sp-1) = '\0';
		host++;

		s->use_ipv6 = 1;
	}

	*(sp++) = '\0';

	port = strtol(sp, NULL, 10);

	if (host[0] == '/') {
		/* host is a unix-domain-socket */
		is_unix_domain_socket = 1;
	} else if (port == 0 || port > 65535) {
		log_error_write(srv, __FILE__, __LINE__, "sd", "port out of range:", port);

		goto error_free_socket;
	}

	if (*host == '\0') host = NULL;

	if (is_unix_domain_socket) {
#ifdef HAVE_SYS_UN_H

		srv_socket->addr.plain.sa_family = AF_UNIX;

		if (-1 == (srv_socket->fd = socket(srv_socket->addr.plain.sa_family, SOCK_STREAM, 0))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			goto error_free_socket;
		}
#else
		log_error_write(srv, __FILE__, __LINE__, "s",
				"ERROR: Unix Domain sockets are not supported.");
		goto error_free_socket;
#endif
	}

#ifdef HAVE_IPV6
	if (s->use_ipv6) {
		srv_socket->addr.plain.sa_family = AF_INET6;

		if (-1 == (srv_socket->fd = socket(srv_socket->addr.plain.sa_family, SOCK_STREAM, IPPROTO_TCP))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			goto error_free_socket;
		}
		srv_socket->use_ipv6 = 1;
	}
#endif

	if (srv_socket->fd == -1) {
		srv_socket->addr.plain.sa_family = AF_INET;
		if (-1 == (srv_socket->fd = socket(srv_socket->addr.plain.sa_family, SOCK_STREAM, IPPROTO_TCP))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			goto error_free_socket;
		}
	}

#ifdef FD_CLOEXEC
	/* set FD_CLOEXEC now, fdevent_fcntl_set is called later; needed for pipe-logger forks */
	fcntl(srv_socket->fd, F_SETFD, FD_CLOEXEC);
#endif

	/* */
	srv->cur_fds = srv_socket->fd;

	val = 1;
	if (setsockopt(srv_socket->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "socketsockopt failed:", strerror(errno));
		goto error_free_socket;
	}

	switch(srv_socket->addr.plain.sa_family) {
#ifdef HAVE_IPV6
	case AF_INET6:
		memset(&srv_socket->addr, 0, sizeof(struct sockaddr_in6));
		srv_socket->addr.ipv6.sin6_family = AF_INET6;
		if (host == NULL) {
			srv_socket->addr.ipv6.sin6_addr = in6addr_any;
		} else {
			struct addrinfo hints, *res;
			int r;

			memset(&hints, 0, sizeof(hints));

			hints.ai_family   = AF_INET6;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) {
				log_error_write(srv, __FILE__, __LINE__,
						"sssss", "getaddrinfo failed: ",
						gai_strerror(r), "'", host, "'");

				goto error_free_socket;
			}

			memcpy(&(srv_socket->addr), res->ai_addr, res->ai_addrlen);

			freeaddrinfo(res);
		}
		srv_socket->addr.ipv6.sin6_port = htons(port);
		addr_len = sizeof(struct sockaddr_in6);
		break;
#endif
	case AF_INET:
		memset(&srv_socket->addr, 0, sizeof(struct sockaddr_in));
		srv_socket->addr.ipv4.sin_family = AF_INET;
		if (host == NULL) {
			srv_socket->addr.ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
		} else {
			struct hostent *he;
			if (NULL == (he = gethostbyname(host))) {
				log_error_write(srv, __FILE__, __LINE__,
						"sds", "gethostbyname failed: ",
						h_errno, host);
				goto error_free_socket;
			}

			if (he->h_addrtype != AF_INET) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "addr-type != AF_INET: ", he->h_addrtype);
				goto error_free_socket;
			}

			if (he->h_length != sizeof(struct in_addr)) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "addr-length != sizeof(in_addr): ", he->h_length);
				goto error_free_socket;
			}

			memcpy(&(srv_socket->addr.ipv4.sin_addr.s_addr), he->h_addr_list[0], he->h_length);
		}
		srv_socket->addr.ipv4.sin_port = htons(port);

		addr_len = sizeof(struct sockaddr_in);

		break;
	case AF_UNIX:
		srv_socket->addr.un.sun_family = AF_UNIX;
		strcpy(srv_socket->addr.un.sun_path, host);

#ifdef SUN_LEN
		addr_len = SUN_LEN(&srv_socket->addr.un);
#else
		/* stevens says: */
		addr_len = strlen(host) + 1 + sizeof(srv_socket->addr.un.sun_family);
#endif

		/* check if the socket exists and try to connect to it. */
		if (-1 != (fd = connect(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len))) {
			close(fd);

			log_error_write(srv, __FILE__, __LINE__, "ss",
				"server socket is still in use:",
				host);


			goto error_free_socket;
		}

		/* connect failed */
		switch(errno) {
		case ECONNREFUSED:
			unlink(host);
			break;
		case ENOENT:
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sds",
				"testing socket failed:",
				host, strerror(errno));

			goto error_free_socket;
		}

		break;
	default:
		goto error_free_socket;
	}

	if (0 != bind(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len)) {
		switch(srv_socket->addr.plain.sa_family) {
		case AF_UNIX:
			log_error_write(srv, __FILE__, __LINE__, "sds",
					"can't bind to socket:",
					host, strerror(errno));
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ssds",
					"can't bind to port:",
					host, port, strerror(errno));
			break;
		}
		goto error_free_socket;
	}

	if (-1 == listen(srv_socket->fd, 128 * 8)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "listen failed: ", strerror(errno));
		goto error_free_socket;
	}

	if (s->is_ssl) {
#ifdef USE_OPENSSL
		if (NULL == (srv_socket->ssl_ctx = s->ssl_ctx)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "ssl.pemfile has to be set");
			goto error_free_socket;
		}
#else

		buffer_free(srv_socket->srv_token);
		free(srv_socket);

		buffer_free(b);

		log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
				"ssl requested but openssl support is not compiled in");

		goto error_free_socket;
#endif
#ifdef TCP_DEFER_ACCEPT
	} else if (s->defer_accept) {
		int v = s->defer_accept;
		if (-1 == setsockopt(srv_socket->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &v, sizeof(v))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "can't set TCP_DEFER_ACCEPT: ", strerror(errno));
		}
#endif
	} else {
#ifdef SO_ACCEPTFILTER
		/* FreeBSD accf_http filter */
		struct accept_filter_arg afa;
		memset(&afa, 0, sizeof(afa));
		strcpy(afa.af_name, "httpready");
		if (setsockopt(srv_socket->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0) {
			if (errno != ENOENT) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "can't set accept-filter 'httpready': ", strerror(errno));
			}
		}
#endif
	}

	srv_socket->is_ssl = s->is_ssl;

	if (srv->srv_sockets.size == 0) {
		srv->srv_sockets.size = 4;
		srv->srv_sockets.used = 0;
		srv->srv_sockets.ptr = malloc(srv->srv_sockets.size * sizeof(server_socket));
	} else if (srv->srv_sockets.used == srv->srv_sockets.size) {
		srv->srv_sockets.size += 4;
		srv->srv_sockets.ptr = realloc(srv->srv_sockets.ptr, srv->srv_sockets.size * sizeof(server_socket));
	}

	srv->srv_sockets.ptr[srv->srv_sockets.used++] = srv_socket;

	buffer_free(b);

	return 0;

error_free_socket:
	if (srv_socket->fd != -1) {
		/* check if server fd are already registered */
		if (srv_socket->fde_ndx != -1) {
			fdevent_event_del(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd);
			fdevent_unregister(srv->ev, srv_socket->fd);
		}

		close(srv_socket->fd);
	}
	buffer_free(srv_socket->srv_token);
	free(srv_socket);

	return -1;
}

int network_close(server *srv) {
	size_t i;
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];

		if (srv_socket->fd != -1) {
			/* check if server fd are already registered */
			if (srv_socket->fde_ndx != -1) {
				fdevent_event_del(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd);
				fdevent_unregister(srv->ev, srv_socket->fd);
			}

			close(srv_socket->fd);
		}

		buffer_free(srv_socket->srv_token);

		free(srv_socket);
	}

	free(srv->srv_sockets.ptr);

	return 0;
}

typedef enum {
	NETWORK_BACKEND_UNSET,
	NETWORK_BACKEND_WRITE,
	NETWORK_BACKEND_WRITEV,
	NETWORK_BACKEND_LINUX_SENDFILE,
	NETWORK_BACKEND_FREEBSD_SENDFILE,
	NETWORK_BACKEND_SOLARIS_SENDFILEV
} network_backend_t;

int network_init(server *srv) {
	buffer *b;
	size_t i;
	network_backend_t backend;

	struct nb_map {
		network_backend_t nb;
		const char *name;
	} network_backends[] = {
		/* lowest id wins */
#if defined USE_LINUX_SENDFILE
		{ NETWORK_BACKEND_LINUX_SENDFILE,       "linux-sendfile" },
#endif
#if defined USE_FREEBSD_SENDFILE
		{ NETWORK_BACKEND_FREEBSD_SENDFILE,     "freebsd-sendfile" },
#endif
#if defined USE_SOLARIS_SENDFILEV
		{ NETWORK_BACKEND_SOLARIS_SENDFILEV,	"solaris-sendfilev" },
#endif
#if defined USE_WRITEV
		{ NETWORK_BACKEND_WRITEV,		"writev" },
#endif
		{ NETWORK_BACKEND_WRITE,		"write" },
		{ NETWORK_BACKEND_UNSET,        	NULL }
	};

#ifdef USE_OPENSSL
	/* load SSL certificates */
	for (i = 0; i < srv->config_context->used; i++) {
		specific_config *s = srv->config_storage[i];

		if (buffer_is_empty(s->ssl_pemfile)) continue;

#ifdef OPENSSL_NO_TLSEXT
		{
			data_config *dc = (data_config *)srv->config_context->data[i];
			if (COMP_HTTP_HOST == dc->comp) {
			    log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					    "can't use ssl.pemfile with $HTTP[\"host\"], openssl version does not support TLS extensions");
			    return -1;
			}
		}
#endif

		if (srv->ssl_is_init == 0) {
			SSL_load_error_strings();
			SSL_library_init();
			srv->ssl_is_init = 1;

			if (0 == RAND_status()) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						"not enough entropy in the pool");
				return -1;
			}
		}

		if (NULL == (s->ssl_ctx = SSL_CTX_new(SSLv23_server_method()))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		if (!s->ssl_use_sslv2) {
			/* disable SSLv2 */
			if (SSL_OP_NO_SSLv2 != SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv2)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
		}

		if (!buffer_is_empty(s->ssl_cipher_list)) {
			/* Disable support for low encryption ciphers */
			if (SSL_CTX_set_cipher_list(s->ssl_ctx, s->ssl_cipher_list->ptr) != 1) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
		}

		if (!buffer_is_empty(s->ssl_ca_file)) {
			if (1 != SSL_CTX_load_verify_locations(s->ssl_ctx, s->ssl_ca_file->ptr, NULL)) {
				log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
						ERR_error_string(ERR_get_error(), NULL), s->ssl_ca_file);
				return -1;
			}
			if (s->ssl_verifyclient) {
				STACK_OF(X509_NAME) *certs = SSL_load_client_CA_file(s->ssl_ca_file->ptr);
				if (!certs) {
					log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
							ERR_error_string(ERR_get_error(), NULL), s->ssl_ca_file);
				}
				if (SSL_CTX_set_session_id_context(s->ssl_ctx, (void*) &srv, sizeof(srv)) != 1) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
					return -1;
				}
				SSL_CTX_set_client_CA_list(s->ssl_ctx, certs);
				SSL_CTX_set_verify(
					s->ssl_ctx,
					SSL_VERIFY_PEER | (s->ssl_verifyclient_enforce ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
					NULL
				);
				SSL_CTX_set_verify_depth(s->ssl_ctx, s->ssl_verifyclient_depth);
			}
		} else if (s->ssl_verifyclient) {
			log_error_write(
				srv, __FILE__, __LINE__, "s",
				"SSL: You specified ssl.verifyclient.activate but no ca_file"
			);
		}

		if (SSL_CTX_use_certificate_file(s->ssl_ctx, s->ssl_pemfile->ptr, SSL_FILETYPE_PEM) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
					ERR_error_string(ERR_get_error(), NULL), s->ssl_pemfile);
			return -1;
		}

		if (SSL_CTX_use_PrivateKey_file (s->ssl_ctx, s->ssl_pemfile->ptr, SSL_FILETYPE_PEM) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
					ERR_error_string(ERR_get_error(), NULL), s->ssl_pemfile);
			return -1;
		}

		if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
			log_error_write(srv, __FILE__, __LINE__, "sssb", "SSL:",
					"Private key does not match the certificate public key, reason:",
					ERR_error_string(ERR_get_error(), NULL),
					s->ssl_pemfile);
			return -1;
		}
		SSL_CTX_set_default_read_ahead(s->ssl_ctx, 1);
		SSL_CTX_set_mode(s->ssl_ctx, SSL_CTX_get_mode(s->ssl_ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

# ifndef OPENSSL_NO_TLSEXT
		if (!SSL_CTX_set_tlsext_servername_callback(s->ssl_ctx, network_ssl_servername_callback) ||
		    !SSL_CTX_set_tlsext_servername_arg(s->ssl_ctx, srv)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					"failed to initialize TLS servername callback, openssl library does not support TLS servername extension");
			return -1;
		}
# endif
	}
#endif

	b = buffer_init();

	buffer_copy_string_buffer(b, srv->srvconf.bindhost);
	buffer_append_string_len(b, CONST_STR_LEN(":"));
	buffer_append_long(b, srv->srvconf.port);

	if (0 != network_server_init(srv, b, srv->config_storage[0])) {
		return -1;
	}
	buffer_free(b);

#ifdef USE_OPENSSL
	srv->network_ssl_backend_write = network_write_chunkqueue_openssl;
#endif

	/* get a usefull default */
	backend = network_backends[0].nb;

	/* match name against known types */
	if (!buffer_is_empty(srv->srvconf.network_backend)) {
		for (i = 0; network_backends[i].name; i++) {
			/**/
			if (buffer_is_equal_string(srv->srvconf.network_backend, network_backends[i].name, strlen(network_backends[i].name))) {
				backend = network_backends[i].nb;
				break;
			}
		}
		if (NULL == network_backends[i].name) {
			/* we don't know it */

			log_error_write(srv, __FILE__, __LINE__, "sb",
					"server.network-backend has a unknown value:",
					srv->srvconf.network_backend);

			return -1;
		}
	}

	switch(backend) {
	case NETWORK_BACKEND_WRITE:
		srv->network_backend_write = network_write_chunkqueue_write;
		break;
#ifdef USE_WRITEV
	case NETWORK_BACKEND_WRITEV:
		srv->network_backend_write = network_write_chunkqueue_writev;
		break;
#endif
#ifdef USE_LINUX_SENDFILE
	case NETWORK_BACKEND_LINUX_SENDFILE:
		srv->network_backend_write = network_write_chunkqueue_linuxsendfile;
		break;
#endif
#ifdef USE_FREEBSD_SENDFILE
	case NETWORK_BACKEND_FREEBSD_SENDFILE:
		srv->network_backend_write = network_write_chunkqueue_freebsdsendfile;
		break;
#endif
#ifdef USE_SOLARIS_SENDFILEV
	case NETWORK_BACKEND_SOLARIS_SENDFILEV:
		srv->network_backend_write = network_write_chunkqueue_solarissendfilev;
		break;
#endif
	default:
		return -1;
	}

	/* check for $SERVER["socket"] */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		specific_config *s = srv->config_storage[i];
		size_t j;

		/* not our stage */
		if (COMP_SERVER_SOCKET != dc->comp) continue;

		if (dc->cond != CONFIG_COND_EQ) continue;

		/* check if we already know this socket,
		 * if yes, don't init it */
		for (j = 0; j < srv->srv_sockets.used; j++) {
			if (buffer_is_equal(srv->srv_sockets.ptr[j]->srv_token, dc->string)) {
				break;
			}
		}

		if (j == srv->srv_sockets.used) {
			if (0 != network_server_init(srv, dc->string, s)) return -1;
		}
	}

	return 0;
}

int network_register_fdevents(server *srv) {
	size_t i;

	if (-1 == fdevent_reset(srv->ev)) {
		return -1;
	}

	/* register fdevents after reset */
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];

		fdevent_register(srv->ev, srv_socket->fd, network_server_handle_fdevent, srv_socket);
		fdevent_event_add(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd, FDEVENT_IN);
	}
	return 0;
}

int network_write_chunkqueue(server *srv, connection *con, chunkqueue *cq) {
	int ret = -1;
	off_t written = 0;
#ifdef TCP_CORK
	int corked = 0;
#endif
	server_socket *srv_socket = con->srv_socket;

	if (con->conf.global_kbytes_per_second &&
	    *(con->conf.global_bytes_per_second_cnt_ptr) > con->conf.global_kbytes_per_second * 1024) {
		/* we reached the global traffic limit */

		con->traffic_limit_reached = 1;
		joblist_append(srv, con);

		return 1;
	}

	written = cq->bytes_out;

#ifdef TCP_CORK
	/* Linux: put a cork into the socket as we want to combine the write() calls
	 * but only if we really have multiple chunks
	 */
	if (cq->first && cq->first->next) {
		corked = 1;
		setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
	}
#endif

	if (srv_socket->is_ssl) {
#ifdef USE_OPENSSL
		ret = srv->network_ssl_backend_write(srv, con, con->ssl, cq);
#endif
	} else {
		ret = srv->network_backend_write(srv, con, con->fd, cq);
	}

	if (ret >= 0) {
		chunkqueue_remove_finished_chunks(cq);
		ret = chunkqueue_is_empty(cq) ? 0 : 1;
	}

#ifdef TCP_CORK
	if (corked) {
		corked = 0;
		setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
	}
#endif

	written = cq->bytes_out - written;
	con->bytes_written += written;
	con->bytes_written_cur_second += written;

	*(con->conf.global_bytes_per_second_cnt_ptr) += written;

	if (con->conf.kbytes_per_second &&
	    (con->bytes_written_cur_second > con->conf.kbytes_per_second * 1024)) {
		/* we reached the traffic limit */

		con->traffic_limit_reached = 1;
		joblist_append(srv, con);
	}
	return ret;
}
