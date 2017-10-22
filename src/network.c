#include "first.h"

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "connections.h"
#include "plugin.h"
#include "joblist.h"
#include "configfile.h"
#include "inet_ntop_cache.h"

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

void
network_accept_tcp_nagle_disable (const int fd)
{
    static int noinherit_tcpnodelay = -1;
    int opt;

    if (!noinherit_tcpnodelay) /* TCP_NODELAY inherited from listen socket */
        return;

    if (noinherit_tcpnodelay < 0) {
        socklen_t optlen = sizeof(opt);
        if (0 == getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, &optlen)) {
            noinherit_tcpnodelay = !opt;
            if (opt)           /* TCP_NODELAY inherited from listen socket */
                return;
        }
    }

    opt = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

static handler_t network_server_handle_fdevent(server *srv, void *context, int revents) {
	server_socket *srv_socket = (server_socket *)context;
	connection *con;
	int loops = 0;

	UNUSED(context);

	if (0 == (revents & FDEVENT_IN)) {
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
		connection_state_machine(srv, con);
	}
	return HANDLER_GO_ON;
}

static void network_host_normalize_addr_str(buffer *host, sock_addr *addr) {
    buffer_reset(host);
    if (addr->plain.sa_family == AF_INET6)
        buffer_append_string_len(host, CONST_STR_LEN("["));
    sock_addr_inet_ntop_append_buffer(host, addr);
    if (addr->plain.sa_family == AF_INET6)
        buffer_append_string_len(host, CONST_STR_LEN("]"));
    if (addr->plain.sa_family != AF_UNIX) {
        unsigned short port = (addr->plain.sa_family == AF_INET)
          ? ntohs(addr->ipv4.sin_port)
          : ntohs(addr->ipv6.sin6_port);
        buffer_append_string_len(host, CONST_STR_LEN(":"));
        buffer_append_int(host, (int)port);
    }
}

static int network_host_parse_addr(server *srv, sock_addr *addr, socklen_t *addr_len, buffer *host, int use_ipv6) {
    char *h;
    char *colon = NULL;
    const char *chost;
    sa_family_t family = use_ipv6 ? AF_INET6 : AF_INET;
    unsigned int port = srv->srvconf.port;
    if (buffer_string_is_empty(host)) {
        log_error_write(srv, __FILE__, __LINE__, "s", "value of $SERVER[\"socket\"] must not be empty");
        return -1;
    }
    h = host->ptr;
    if (h[0] == '/') {
      #ifdef HAVE_SYS_UN_H
        return (1 == sock_addr_from_str_hints(srv,addr,addr_len,h,AF_UNIX,0))
          ? 0
          : -1;
      #else
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "ERROR: Unix Domain sockets are not supported.");
        return -1;
      #endif
    }
    buffer_copy_buffer(srv->tmp_buf, host);
    h = srv->tmp_buf->ptr;
    if (h[0] == '[') {
        family = AF_INET6;
        if ((h = strchr(h, ']'))) {
            *h++ = '\0';
            if (*h == ':') colon = h;
        } /*(else should not happen; validated in configparser.y)*/
        h = srv->tmp_buf->ptr+1;
    }
    else {
        colon = strrchr(h, ':');
    }
    if (colon) {
        *colon++ = '\0';
        port = strtol(colon, NULL, 10);
        if (port == 0 || port > 65535) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "port not set or out of range:", port);
            return -1;
        }
    }
    chost = *h ? h : family == AF_INET ? "0.0.0.0" : "::";
    if (1 != sock_addr_from_str_hints(srv,addr,addr_len,chost,family,port)) {
        return -1;
    }
    return 0;
}

static int network_server_init(server *srv, buffer *host_token, size_t sidx, int stdin_fd) {
	server_socket *srv_socket;
	const char *host;
	specific_config *s = srv->config_storage[sidx];
	socklen_t addr_len = sizeof(sock_addr);
	sock_addr addr;

#ifdef __WIN32
	int err;
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		    /* Tell the user that we could not find a usable */
		    /* WinSock DLL.                                  */
		    return -1;
	}
#endif

	if (buffer_string_is_empty(host_token)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "value of $SERVER[\"socket\"] must not be empty");
		return -1;
	}

	/* check if we already know this socket, and if yes, don't init it
	 * (optimization: check strings here to filter out exact matches;
	 *  binary addresses are matched further below) */
	for (size_t i = 0; i < srv->srv_sockets.used; ++i) {
		if (buffer_is_equal(srv->srv_sockets.ptr[i]->srv_token, host_token)) {
			buffer_copy_buffer(host_token, srv->srv_sockets.ptr[i]->srv_token);
			return 0;
		}
	}

	host = host_token->ptr;
	if ((s->use_ipv6 && (*host == '\0' || *host == ':')) || (host[0] == '[' && host[1] == ']')) {
			log_error_write(srv, __FILE__, __LINE__, "s", "warning: please use server.use-ipv6 only for hostnames, not without server.bind / empty address; your config will break if the kernel default for IPV6_V6ONLY changes");
	}
	if (*host == '[') s->use_ipv6 = 1;

	memset(&addr, 0, sizeof(addr));
	if (-1 != stdin_fd) {
		if (0 == sidx && srv->srv_sockets.used > 0) {
			close(stdin_fd);/*(graceful restart listening to "/dev/stdin")*/
			return 0;
		}
		if (-1 == getsockname(stdin_fd, (struct sockaddr *)&addr, &addr_len)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"getsockname()", strerror(errno));
			return -1;
		}
	} else if (0 != network_host_parse_addr(srv, &addr, &addr_len, host_token, s->use_ipv6)) {
		return -1;
	}
	network_host_normalize_addr_str(host_token, &addr);
	host = host_token->ptr;

	if (srv->srvconf.preflight_check) {
		return 0;
	}

	/* check if we already know this socket (after potential DNS resolution), and if yes, don't init it */
	for (size_t i = 0; i < srv->srv_sockets.used; ++i) {
		if (0 == memcmp(&srv->srv_sockets.ptr[i]->addr, &addr, sizeof(addr))) {
			return 0;
		}
	}

	srv_socket = calloc(1, sizeof(*srv_socket));
	force_assert(NULL != srv_socket);
	memcpy(&srv_socket->addr, &addr, addr_len);
	srv_socket->fd = -1;
	srv_socket->fde_ndx = -1;
	srv_socket->sidx = sidx;
	srv_socket->is_ssl = s->ssl_enabled;
	srv_socket->srv_token = buffer_init_buffer(host_token);

	if (srv->srv_sockets.size == 0) {
		srv->srv_sockets.size = 4;
		srv->srv_sockets.used = 0;
		srv->srv_sockets.ptr = malloc(srv->srv_sockets.size * sizeof(server_socket*));
		force_assert(NULL != srv->srv_sockets.ptr);
	} else if (srv->srv_sockets.used == srv->srv_sockets.size) {
		srv->srv_sockets.size += 4;
		srv->srv_sockets.ptr = realloc(srv->srv_sockets.ptr, srv->srv_sockets.size * sizeof(server_socket*));
		force_assert(NULL != srv->srv_sockets.ptr);
	}
	srv->srv_sockets.ptr[srv->srv_sockets.used++] = srv_socket;

	if (srv->sockets_disabled) { /* lighttpd -1 (one-shot mode) */
		return 0;
	}

	if (-1 != stdin_fd) {
		srv_socket->fd = stdin_fd;
		if (-1 == fdevent_fcntl_set_nb_cloexec(srv->ev, stdin_fd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl:", strerror(errno));
			return -1;
		}
	} else
#ifdef HAVE_SYS_UN_H
	if (AF_UNIX == srv_socket->addr.plain.sa_family) {
		/* check if the socket exists and try to connect to it. */
		force_assert(host); /*(static analysis hint)*/
		if (-1 == (srv_socket->fd = fdevent_socket_cloexec(srv_socket->addr.plain.sa_family, SOCK_STREAM, 0))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			return -1;
		}
		if (0 == connect(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
				"server socket is still in use:",
				host);


			return -1;
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

			return -1;
		}

		fdevent_fcntl_set_nb(srv->ev, srv_socket->fd);
	} else
#endif
	{
		if (-1 == (srv_socket->fd = fdevent_socket_nb_cloexec(srv_socket->addr.plain.sa_family, SOCK_STREAM, IPPROTO_TCP))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			return -1;
		}
	}

#ifdef HAVE_IPV6
		if (AF_INET6 == srv_socket->addr.plain.sa_family
		    && host != NULL) {
			if (s->set_v6only) {
				int val = 1;
				if (-1 == setsockopt(srv_socket->fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "setsockopt(IPV6_V6ONLY) failed:", strerror(errno));
					return -1;
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "s", "warning: server.set-v6only will be removed soon, update your config to have different sockets for ipv4 and ipv6");
			}
		}
#endif

	/* */
	srv->cur_fds = srv_socket->fd;

	if (fdevent_set_so_reuseaddr(srv_socket->fd, 1) < 0) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "setsockopt(SO_REUSEADDR) failed:", strerror(errno));
		return -1;
	}

	if (srv_socket->addr.plain.sa_family != AF_UNIX) {
		if (fdevent_set_tcp_nodelay(srv_socket->fd, 1) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "setsockopt(TCP_NODELAY) failed:", strerror(errno));
			return -1;
		}
	}

	if (-1 != stdin_fd) { } else
	if (0 != bind(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len)) {
		log_error_write(srv, __FILE__, __LINE__, "sss",
				"can't bind to socket:", host, strerror(errno));
		return -1;
	}

	if (-1 != stdin_fd) { } else
	if (srv_socket->addr.plain.sa_family == AF_UNIX && !buffer_string_is_empty(s->socket_perms)) {
		mode_t m = 0;
		for (char *str = s->socket_perms->ptr; *str; ++str) {
			m <<= 3;
			m |= (*str - '0');
		}
		if (0 != m && -1 == chmod(host, m)) {
			log_error_write(srv, __FILE__, __LINE__, "sssbss", "chmod(\"", host, "\", ", s->socket_perms, "):", strerror(errno));
		}
	}

	if (-1 != stdin_fd) { } else
	if (-1 == listen(srv_socket->fd, s->listen_backlog)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "listen failed: ", strerror(errno));
		return -1;
	}

	if (s->ssl_enabled) {
#ifdef TCP_DEFER_ACCEPT
	} else if (s->defer_accept) {
		int v = s->defer_accept;
		if (-1 == setsockopt(srv_socket->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &v, sizeof(v))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "can't set TCP_DEFER_ACCEPT: ", strerror(errno));
		}
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) \
 || defined(__OpenBSD__) || defined(__DragonFly__)
	} else if (!buffer_is_empty(s->bsd_accept_filter)
		   && (buffer_is_equal_string(s->bsd_accept_filter, CONST_STR_LEN("httpready"))
			|| buffer_is_equal_string(s->bsd_accept_filter, CONST_STR_LEN("dataready")))) {
#ifdef SO_ACCEPTFILTER
		/* FreeBSD accf_http filter */
		struct accept_filter_arg afa;
		memset(&afa, 0, sizeof(afa));
		strncpy(afa.af_name, s->bsd_accept_filter->ptr, sizeof(afa.af_name));
		if (setsockopt(srv_socket->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0) {
			if (errno != ENOENT) {
				log_error_write(srv, __FILE__, __LINE__, "SBss", "can't set accept-filter '", s->bsd_accept_filter, "':", strerror(errno));
			}
		}
#endif
#endif
	}

	return 0;
}

int network_close(server *srv) {
	size_t i;
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];
		if (srv_socket->fd != -1) {
			network_unregister_sock(srv, srv_socket);
			close(srv_socket->fd);
		}

		buffer_free(srv_socket->srv_token);

		free(srv_socket);
	}

	free(srv->srv_sockets.ptr);
	srv->srv_sockets.ptr = NULL;
	srv->srv_sockets.used = 0;
	srv->srv_sockets.size = 0;

	return 0;
}

typedef enum {
	NETWORK_BACKEND_UNSET,
	NETWORK_BACKEND_WRITE,
	NETWORK_BACKEND_WRITEV,
	NETWORK_BACKEND_SENDFILE,
} network_backend_t;

int network_init(server *srv, int stdin_fd) {
	size_t i;
	network_backend_t backend;

	struct nb_map {
		network_backend_t nb;
		const char *name;
	} network_backends[] = {
		/* lowest id wins */
#if defined USE_SENDFILE
		{ NETWORK_BACKEND_SENDFILE,   "sendfile" },
#endif
#if defined USE_LINUX_SENDFILE
		{ NETWORK_BACKEND_SENDFILE,   "linux-sendfile" },
#endif
#if defined USE_FREEBSD_SENDFILE
		{ NETWORK_BACKEND_SENDFILE,   "freebsd-sendfile" },
#endif
#if defined USE_SOLARIS_SENDFILEV
		{ NETWORK_BACKEND_SENDFILE,   "solaris-sendfilev" },
#endif
#if defined USE_WRITEV
		{ NETWORK_BACKEND_WRITEV,     "writev" },
#endif
		{ NETWORK_BACKEND_WRITE,      "write" },
		{ NETWORK_BACKEND_UNSET,       NULL }
	};

	/* get a useful default */
	backend = network_backends[0].nb;

	/* match name against known types */
	if (!buffer_string_is_empty(srv->srvconf.network_backend)) {
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
#if defined(USE_WRITEV)
	case NETWORK_BACKEND_WRITEV:
		srv->network_backend_write = network_write_chunkqueue_writev;
		break;
#endif
#if defined(USE_SENDFILE)
	case NETWORK_BACKEND_SENDFILE:
		srv->network_backend_write = network_write_chunkqueue_sendfile;
		break;
#endif
	default:
		return -1;
	}

	{
		int rc;
		buffer *b = buffer_init();
		buffer_copy_buffer(b, srv->srvconf.bindhost);
		if (b->ptr[0] != '/') { /*(skip adding port if unix socket path)*/
			buffer_append_string_len(b, CONST_STR_LEN(":"));
			buffer_append_int(b, srv->srvconf.port);
		}

		rc = network_server_init(srv, b, 0, stdin_fd);
		buffer_free(b);
		if (0 != rc) return -1;
	}

	/* check for $SERVER["socket"] */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];

		/* not our stage */
		if (COMP_SERVER_SOCKET != dc->comp) continue;

		if (dc->cond == CONFIG_COND_NE) {
			socklen_t addr_len = sizeof(sock_addr);
			sock_addr addr;
			if (0 != network_host_parse_addr(srv, &addr, &addr_len, dc->string, srv->config_storage[i]->use_ipv6)) {
				return -1;
			}
			network_host_normalize_addr_str(dc->string, &addr);
			continue;
		}

		if (dc->cond != CONFIG_COND_EQ) continue;

			if (0 != network_server_init(srv, dc->string, i, -1)) return -1;
	}

	return 0;
}

void network_unregister_sock(server *srv, server_socket *srv_socket) {
	if (-1 == srv_socket->fd || -1 == srv_socket->fde_ndx) return;
	fdevent_event_del(srv->ev, &srv_socket->fde_ndx, srv_socket->fd);
	fdevent_unregister(srv->ev, srv_socket->fd);
}

int network_register_fdevents(server *srv) {
	size_t i;

	if (-1 == fdevent_reset(srv->ev)) {
		return -1;
	}

	if (srv->sockets_disabled) return 0; /* lighttpd -1 (one-shot mode) */

	/* register fdevents after reset */
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];

		fdevent_register(srv->ev, srv_socket->fd, network_server_handle_fdevent, srv_socket);
		fdevent_event_set(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd, FDEVENT_IN);
	}
	return 0;
}
