#include "first.h"

#include "network.h"
#include "base.h"
#include "fdevent.h"
#include "log.h"
#include "connections.h"
#include "plugin.h"
#include "sock_addr.h"

#include "network_write.h"
#include "sys-socket.h"

#include <sys/types.h>
#include <sys/stat.h>
#include "sys-time.h"
#include "sys-unistd.h" /* <unistd.h> */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
/* (Note: assume overwrite == 1 in this setenv() replacement) */
/*#define setenv(name,value,overwrite)  SetEnvironmentVariable((name),(value))*/
/*#define unsetenv(name)                SetEnvironmentVariable((name),NULL)*/
#define setenv(name,value,overwrite)  _putenv_s((name), strdup(value))
#define unsetenv(name)                _putenv_s((name), "")
#endif

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

static handler_t network_server_handle_fdevent(void *context, int revents) {
    const server_socket * const srv_socket = (server_socket *)context;
    server * const srv = srv_socket->srv;

    if (0 == (revents & FDEVENT_IN)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "strange event for server socket %d %d", srv_socket->fd, revents);
        return HANDLER_ERROR;
    }

    /* accept()s at most 100 new connections before
     * jumping out to process events on other connections */
    int loops = (int)srv->lim_conns;
    if (loops > 100)
        loops = 100;
    else if (loops <= 0)
        return HANDLER_GO_ON;

    const int nagle_disable =
      (sock_addr_get_family(&srv_socket->addr) != AF_UNIX);

    sock_addr addr;
    size_t addrlen; /*(size_t intentional; not socklen_t)*/
    do {
        addrlen = sizeof(addr);
        int fd = fdevent_accept_listenfd(srv_socket->fd,
                                         (struct sockaddr *)&addr, &addrlen);
        if (-1 == fd) break;

        if (nagle_disable)
            network_accept_tcp_nagle_disable(fd);
      #ifdef HAVE_SYS_UN_H /*(see sock_addr.h)*/
        else if (addrlen <= 2) /*(AF_UNIX if !nagle_disable)*/
            memcpy(addr.un.sun_path, srv_socket->addr.un.sun_path,
                   srv_socket->srv_token_colon < sizeof(addr.un.sun_path)
                   ? (size_t)srv_socket->srv_token_colon+1 /*(+1 for '\0')*/
                   : sizeof(addr.un.sun_path));/*(escaped len might be longer)*/
      #endif

        connection *con = connection_accepted(srv, srv_socket, &addr, fd);
        if (__builtin_expect( (!con), 0)) return HANDLER_GO_ON;
        connection_state_machine(con);
    } while (--loops);

    if (loops) {
      #ifdef _WIN32
        switch (WSAGetLastError()) {
          case WSAEWOULDBLOCK:
          case WSAECONNRESET:
          case WSAENOBUFS:
          case WSAEINTR:
          case WSAECONNABORTED:
          case WSAEMFILE:
            break;
          default:
            log_serror(srv->errh, __FILE__, __LINE__, "accept()");
        }
      #else
        switch (errno) {
          case EAGAIN:
         #if EWOULDBLOCK != EAGAIN
          case EWOULDBLOCK:
         #endif
          case EINTR:
          case ECONNABORTED:
          case EMFILE:
            break;
          default:
            log_perror(srv->errh, __FILE__, __LINE__, "accept()");
        }
      #endif
    }

    return HANDLER_GO_ON;
}

#ifdef HAVE_SYS_UN_H

/* abstract socket (Linux, QNX?, Windows 10?) */

__attribute_cold__
static void
network_abstract_socket_enc (buffer * const restrict abstract,
                             unsigned char * const restrict sun_path,
                             const uint32_t len)
{
    /*(strings needing encoding are expected to be short;
     * code not written for performance)*/
    buffer_clear(abstract);
    uint32_t n = 0;
    for (uint32_t i = 0; i < len; ++i)
        n += (sun_path[i]-20 < 107) ? 1 : 4;
    char *s = buffer_extend(abstract, n);
    for (uint32_t i = 0; i < len; ++i) {
        /* (sun_path[i] >= 20 && sun_path[i] < 127 && sun_path[i] != '\\') */
        if (sun_path[i]-20 < 107 && sun_path[i] != '\\')
            *s++ = ((char *)sun_path)[i];
        else {
            s[0] = '\\';
            s[1] = 'x';
            s[2] = "0123456789abcdef"[sun_path[i] >>  4];
            s[3] = "0123456789abcdef"[sun_path[i] & 0xF];
            s += 4;
        }
    }
}

__attribute_cold__
static uint32_t
network_abstract_socket_dec (const buffer * const restrict abstract,
                             char * const restrict sun_path,
                             const uint32_t plen)
{
    /*(strings expected to begin with "\\x00")*/
    /*(strings needing decoding are expected to be short;
     * code not written for performance)*/
    const char *s = abstract->ptr;
    uint32_t n = 0;
    for (int hi, lo; *s && n < plen; ++n) {
        if (s[0] != '\\')
            sun_path[n] = *s++;
        else if (s[1] == 'x'
                 && (hi = hex2int(s[2])) != 0xFF
                 && (lo = hex2int(s[3])) != 0xFF) {
            sun_path[n] = (char)((hi << 4) | lo);
            s += 4;
        }
        else
            break;
    }
    return *s == '\0' ? n : 0;
}

__attribute_cold__
static int
network_abstract_socket_parse (const buffer *abstract,
                               sock_addr *addr, socklen_t *addr_len,
                               log_error_st *errh)
{
    /* abstract socket (Linux, QNX?, Windows 10?) */
    /*assert(*addr_len >= sizeof(struct sockaddr_un));*/
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->un.sun_family = AF_UNIX;
    uint32_t len =
      (uint32_t)(*addr_len - offsetof(struct sockaddr_un, sun_path));
    if (len > sizeof(addr->un.sun_path))
        len = sizeof(addr->un.sun_path);
    len = network_abstract_socket_dec(abstract, addr->un.sun_path, len);
    if (len) {
        *addr_len = offsetof(struct sockaddr_un, sun_path) + len;
        return 0;
    }
    else {
        log_error(errh, __FILE__, __LINE__,
          "abstract unix socket filename invalid encoding or too long: %s",
          abstract->ptr);
        return -1;
    }
}

#endif /* HAVE_SYS_UN_H */

static void network_host_normalize_addr_str(buffer *host, sock_addr *addr, socklen_t addr_len) {
    buffer_clear(host);
    sock_addr_stringify_append_buffer(host, addr);
  #ifdef HAVE_SYS_UN_H
    if (AF_UNIX == sock_addr_get_family(addr) && 0 == buffer_clen(host))
        network_abstract_socket_enc(host, (unsigned char *)addr->un.sun_path,
                                    (uint32_t)(addr_len
                                    - offsetof(struct sockaddr_un, sun_path)));
  #else
    UNUSED(addr_len);
  #endif
}

static int network_host_parse_addr(server *srv, sock_addr *addr, socklen_t *addr_len, buffer *host, int use_ipv6) {
    char *h;
    char *colon = NULL;
    const char *chost;
    sa_family_t family = use_ipv6 ? AF_INET6 : AF_INET;
    unsigned int port = srv->srvconf.port;
    if (buffer_is_blank(host)) {
        log_error(srv->errh, __FILE__, __LINE__,
          "value of $SERVER[\"socket\"] must not be empty");
        return -1;
    }
    h = host->ptr;
    if (h[0] == '/' || h[0] == '\\') {
      #ifdef HAVE_SYS_UN_H
        if (h[0] == '\\' && h[1] == 'x' && h[2] == '0' && h[3] == '0')
            return network_abstract_socket_parse(host,addr,addr_len,srv->errh);
        return (1 ==
                sock_addr_from_str_hints(addr,addr_len,h,AF_UNIX,0,srv->errh))
          ? 0
          : -1;
      #else
        log_error(srv->errh, __FILE__, __LINE__,
          "ERROR: Unix Domain sockets are not supported.");
        return -1;
      #endif
    }
    buffer * const tb = srv->tmp_buf;
    buffer_copy_buffer(tb, host);
    h = tb->ptr;
    if (h[0] == '[') {
        family = AF_INET6;
        if ((h = strchr(h, ']'))) {
            *h++ = '\0';
            if (*h == ':') colon = h;
        } /*(else should not happen; validated in configparser.y)*/
        h = tb->ptr+1;
    }
    else {
        colon = strrchr(h, ':');
    }
    if (colon) {
        *colon++ = '\0';
        port = (unsigned int)strtol(colon, NULL, 10);
        if (port == 0 || port > 65535) {
            log_error(srv->errh, __FILE__, __LINE__,
              "port not set or out of range: %u", port);
            return -1;
        }
    }
    if (h[0] == '*' && h[1] == '\0') {
        family = AF_INET;
        ++h;
    }
    chost = *h ? h : family == AF_INET ? "0.0.0.0" : "::";
    if (1 !=
        sock_addr_from_str_hints(addr,addr_len,chost,family,port,srv->errh)) {
        return -1;
    }
    return 0;
}

static void network_srv_sockets_append(server *srv, server_socket *srv_socket) {
    server_socket_array * const srv_sockets = &srv->srv_sockets;
    if (!(srv_sockets->used & (4-1)))
        ck_realloc_u32((void **)&srv_sockets->ptr, srv_sockets->used,
                       4, sizeof(*srv_sockets->ptr));
    srv_sockets->ptr[srv_sockets->used++] = srv_socket;
}

typedef struct {
    /* global or per-socket config; not patched per connection */
    int listen_backlog;
    unsigned char ssl_enabled;
    unsigned char use_ipv6;
    unsigned char set_v6only; /* set_v6only is only a temporary option */
    unsigned char defer_accept;
    int8_t v4mapped;
    const buffer *socket_perms;
    const buffer *bsd_accept_filter;
} network_socket_config;

typedef struct {
    PLUGIN_DATA;
    network_socket_config defaults;
    network_socket_config conf;
} network_plugin_data;

static void network_merge_config_cpv(network_socket_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* ssl.engine */
        pconf->ssl_enabled = (0 != cpv->v.u);
        break;
      case 1: /* server.listen-backlog */
        pconf->listen_backlog = (int)cpv->v.u;
        break;
      case 2: /* server.socket-perms */
        pconf->socket_perms = cpv->v.b;
        break;
      case 3: /* server.bsd-accept-filter */
        pconf->bsd_accept_filter = cpv->v.b;
        break;
      case 4: /* server.defer-accept */
        pconf->defer_accept = (0 != cpv->v.u);
        break;
      case 5: /* server.use-ipv6 */
        pconf->use_ipv6 = (0 != cpv->v.u);
        break;
      case 6: /* server.set-v6only */
        pconf->set_v6only = (0 != cpv->v.u);
        break;
      case 7: /* server.v4mapped */
        pconf->v4mapped = (0 != cpv->v.u);
        break;
      default:/* should not happen */
        return;
    }
}

static void network_merge_config(network_socket_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        network_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

__attribute_pure__
static uint8_t network_srv_token_colon (const buffer * const b) {
    const char *colon = NULL;
    const char * const p = b->ptr;
    if (*p == '[') {
        colon = strstr(p, "]:");
        if (colon) ++colon;
    }
    else if (*p != '/') {
        colon = strchr(p, ':');
    }
    return colon ? (uint8_t)(colon - p) : (uint8_t)buffer_clen(b);
}

static void network_srv_socket_init_token (server_socket * const srv_socket, const buffer * const token) {
    buffer * const srv_token = srv_socket->srv_token = buffer_init();
    buffer_copy_buffer(srv_token, token);
  #ifdef HAVE_SYS_UN_H
    /*(srv_socket->addr must have been initialized by caller)*/
    if (AF_UNIX == sock_addr_get_family(&srv_socket->addr))
        srv_socket->srv_token_colon = buffer_clen(srv_token);
    else
  #endif
        srv_socket->srv_token_colon = network_srv_token_colon(srv_token);
}

static int network_server_init(server *srv, const network_socket_config *s, buffer *host_token, size_t sidx, int stdin_fd) {
	server_socket *srv_socket;
	const char *host;
	socklen_t addr_len = sizeof(sock_addr);
	sock_addr addr;
	int family = 0;
	int use_ipv6 = s->use_ipv6;
      #ifdef HAVE_IPV6
	int set_v6only = 0;
      #endif

	if (buffer_is_blank(host_token)) {
		log_error(srv->errh, __FILE__, __LINE__,
		  "value of $SERVER[\"socket\"] must not be empty");
		return -1;
	}

	/* check if we already know this socket, and if yes, don't init it
	 * (optimization: check strings here to filter out exact matches;
	 *  binary addresses are matched further below) */
	for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
		if (buffer_is_equal(srv->srv_sockets.ptr[i]->srv_token, host_token)) {
			if ((unsigned short)~0u == srv->srv_sockets.ptr[i]->sidx) {
				srv->srv_sockets.ptr[i]->sidx = sidx;
				srv->srv_sockets.ptr[i]->is_ssl = s->ssl_enabled;
			}
			return 0;
		}
	}

	host = host_token->ptr;
	if ((use_ipv6 && (*host == '\0' || *host == ':')) || (host[0] == '[' && host[1] == ']')) {
		log_warn(srv->errh, __FILE__, __LINE__,
		  "warning: please use server.use-ipv6 only for hostnames, "
		  "not without server.bind / empty address; your config will "
		  "break if the kernel default for IPV6_V6ONLY changes");
	}
	if (*host == '[') use_ipv6 = 1;

	memset(&addr, 0, sizeof(addr));
	if (-1 != stdin_fd) {
		if (-1 == getsockname(stdin_fd, (struct sockaddr *)&addr, &addr_len)) {
			log_serror(srv->errh, __FILE__, __LINE__, "getsockname()");
			return -1;
		}
	} else if (0 != network_host_parse_addr(srv, &addr, &addr_len, host_token, use_ipv6)) {
		return -1;
	}

	family = sock_addr_get_family(&addr);

      #ifdef HAVE_IPV6
	if (*host != '\0' && AF_INET6 == family) {
		if (s->set_v6only) {
			set_v6only = 1;
		} else {
			log_warn(srv->errh, __FILE__, __LINE__,
			  "warning: server.set-v6only will be removed soon, "
			  "update your config to have different sockets for ipv4 and ipv6");
		}
	}
	if (AF_INET6 == family && -1 != s->v4mapped) { /*(configured; -1 is unset)*/
		set_v6only = (s->v4mapped ? -1 : 1);
	}
      #endif

	network_host_normalize_addr_str(host_token, &addr, addr_len);
	host = host_token->ptr;

	if (srv->srvconf.preflight_check) {
		return 0;
	}

	/* check if we already know this socket (after potential DNS resolution), and if yes, don't init it */
	for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
		if (0 == memcmp(&srv->srv_sockets.ptr[i]->addr, &addr, sizeof(addr))) {
			if ((unsigned short)~0u == srv->srv_sockets.ptr[i]->sidx) {
				srv->srv_sockets.ptr[i]->sidx = sidx;
				srv->srv_sockets.ptr[i]->is_ssl = s->ssl_enabled;
			}
			return 0;
		}
	}

	srv_socket = ck_calloc(1, sizeof(*srv_socket));
	memcpy(&srv_socket->addr, &addr, addr_len);
	srv_socket->fd = -1;
	srv_socket->sidx = sidx;
	srv_socket->is_ssl = s->ssl_enabled;
	srv_socket->srv = srv;
	network_srv_socket_init_token(srv_socket, host_token);
	network_srv_sockets_append(srv, srv_socket);

	if (srv->sockets_disabled) { /* lighttpd -1 (one-shot mode) */
		return 0;
	}

	if (srv->srvconf.systemd_socket_activation) {
		for (uint32_t i = 0; i < srv->srv_sockets_inherited.used; ++i) {
			if (0 != memcmp(&srv->srv_sockets_inherited.ptr[i]->addr, &srv_socket->addr, addr_len)) continue;
			if ((unsigned short)~0u == srv->srv_sockets_inherited.ptr[i]->sidx) {
				srv->srv_sockets_inherited.ptr[i]->sidx = sidx;
			}
			stdin_fd = srv->srv_sockets_inherited.ptr[i]->fd;
			break;
		}
	}

	if (-1 != stdin_fd) {
		srv_socket->fd = stdin_fd;
		if (-1 == fdevent_socket_set_nb_cloexec(stdin_fd)) {
			log_serror(srv->errh, __FILE__, __LINE__, "fcntl()");
			return -1;
		}
	} else
#ifdef HAVE_SYS_UN_H
	if (AF_UNIX == family) {
		/* check if the socket exists and try to connect to it. */
		force_assert(host); /*(static analysis hint)*/
		if (-1 == (srv_socket->fd = fdevent_socket_cloexec(AF_UNIX, SOCK_STREAM, 0))) {
			log_serror(srv->errh, __FILE__, __LINE__, "socket()");
			return -1;
		}
		if (0 == connect(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len)) {
			log_error(srv->errh, __FILE__, __LINE__,
			  "server socket is still in use: %s", host);
			return -1;
		}

		/* connect failed */
	  #ifdef _WIN32
		switch(WSAGetLastError()) {
		case WSAECONNRESET:
		case WSAECONNREFUSED:
			/* socket might or might not exist; unlink anyway */
			if (*host == '/') unlink(host);
			break;
		default:
			log_serror(srv->errh, __FILE__, __LINE__,
			  "testing socket failed: connect() %s", host);
			return -1;
		}
	  #else
		switch(errno) {
		case ECONNREFUSED:
			if (*host == '/') unlink(host);
			break;
		case ENOENT:
			break;
		default:
			log_serror(srv->errh, __FILE__, __LINE__,
			  "testing socket failed: connect() %s", host);
			return -1;
		}
	  #endif

		if (-1 == fdevent_socket_set_nb(srv_socket->fd)) {
			log_serror(srv->errh, __FILE__, __LINE__, "fcntl()");
			return -1;
		}
	} else
#endif
	{
		if (-1 == (srv_socket->fd = fdevent_socket_nb_cloexec(family, SOCK_STREAM, IPPROTO_TCP))) {
		  #ifndef _WIN32
			/* some configs might always include IPv6 addresses,
			 * but some containers might not support IPv6 */
			if (family == AF_INET6 && errno == EAFNOSUPPORT) {
				log_serror(srv->errh, __FILE__, __LINE__,
				  "ignoring $SERVER[\"socket\"] == \"%s\"; socket(AF_INET6)",
				  host);
				return 0;
			}
		  #endif
			log_serror(srv->errh, __FILE__, __LINE__, "socket()");
			return -1;
		}

#ifdef HAVE_IPV6
		if (set_v6only) {
				int val = (set_v6only > 0);
				if (-1 == setsockopt(srv_socket->fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
					log_serror(srv->errh, __FILE__, __LINE__, "setsockopt(IPV6_V6ONLY)");
					return -1;
				}
		}
#endif
	}

  #ifdef _WIN32
	++srv->cur_fds;
  #else
	srv->cur_fds = srv_socket->fd;
  #endif

	if (fdevent_set_so_reuseaddr(srv_socket->fd, 1) < 0) {
		log_serror(srv->errh, __FILE__, __LINE__, "setsockopt(SO_REUSEADDR)");
		return -1;
	}

	if (family != AF_UNIX) {
		if (fdevent_set_tcp_nodelay(srv_socket->fd, 1) < 0) {
			log_serror(srv->errh, __FILE__, __LINE__, "setsockopt(TCP_NODELAY)");
			return -1;
		}
	}

	if (-1 != stdin_fd) { } else
	if (0 != bind(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len)) {
		log_serror(srv->errh, __FILE__, __LINE__, "bind() %s", host);
		return -1;
	}

  #ifdef HAVE_SYS_UN_H
	if (-1 != stdin_fd) { } else
	if (AF_UNIX == family && s->socket_perms) {
		mode_t m = 0;
		for (char *str = s->socket_perms->ptr; *str; ++str) {
			m <<= 3;
			m |= (*str - '0');
		}
		if (0 != m && *host == '/' && -1 == chmod(host, m)) {
			log_perror(srv->errh, __FILE__, __LINE__,
			  "chmod(\"%s\", %s)", host, s->socket_perms->ptr);
			return -1;
		}
	}
  #endif

	if (-1 != stdin_fd) { } else
	if (-1 == listen(srv_socket->fd, s->listen_backlog)) {
		log_serror(srv->errh, __FILE__, __LINE__, "listen()");
		return -1;
	}

	if (s->ssl_enabled) {
	}
#ifdef TCP_DEFER_ACCEPT
	else if (s->defer_accept) {
		int v = s->defer_accept;
		if (-1 == setsockopt(srv_socket->fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &v, sizeof(v))) {
			log_serror(srv->errh, __FILE__, __LINE__, "setsockopt(TCP_DEFER_ACCEPT)");
		}
	}
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) \
 || defined(__OpenBSD__) || defined(__DragonFly__)
#ifdef SO_ACCEPTFILTER
	else if (s->bsd_accept_filter
		   && (buffer_is_equal_string(s->bsd_accept_filter, CONST_STR_LEN("httpready"))
			|| buffer_is_equal_string(s->bsd_accept_filter, CONST_STR_LEN("dataready")))) {
		/* FreeBSD accf_http filter */
		struct accept_filter_arg afa;
		memset(&afa, 0, sizeof(afa));
		strncpy(afa.af_name, s->bsd_accept_filter->ptr, sizeof(afa.af_name)-1);
		if (setsockopt(srv_socket->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0) {
			if (errno != ENOENT) {
				log_perror(srv->errh, __FILE__, __LINE__,
				  "can't set accept-filter '%s'", s->bsd_accept_filter->ptr);
			}
		}
	}
#endif
#endif

	return 0;
}

int network_close(server *srv) {
	for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];
		if (srv_socket->fd != -1) {
			network_unregister_sock(srv, srv_socket);
			fdio_close_socket(srv_socket->fd);
		}

		buffer_free(srv_socket->srv_token);

		free(srv_socket);
	}

	free(srv->srv_sockets.ptr);
	srv->srv_sockets.ptr = NULL;
	srv->srv_sockets.used = 0;

	for (uint32_t i = 0; i < srv->srv_sockets_inherited.used; ++i) {
		server_socket *srv_socket = srv->srv_sockets_inherited.ptr[i];
		if (srv_socket->fd != -1 && srv_socket->sidx != (unsigned short)~0u) {
			fdio_close_socket(srv_socket->fd);
		}

		buffer_free(srv_socket->srv_token);

		free(srv_socket);
	}

	free(srv->srv_sockets_inherited.ptr);
	srv->srv_sockets_inherited.ptr = NULL;
	srv->srv_sockets_inherited.used = 0;

	return 0;
}

void network_socket_activation_to_env (server * const srv) {
    /* set up listening sockets for systemd socket activation
     * and ensure FD_CLOEXEC flag is not set on listen fds */
    int fd = 3; /* #define SD_LISTEN_FDS_START 3 */
    for (uint32_t n = 0, i; n < srv->srv_sockets.used; ++n) {
        server_socket *srv_socket = srv->srv_sockets.ptr[n];
        if (srv_socket->fd < fd) continue;
        if (srv_socket->fd == fd) {
            (void)fdevent_socket_clr_cloexec(fd);
            ++fd;
            continue;
        }
        /* (expecting ordered list, but check if fd is later in list)*/
        for (i = n+1; i < srv->srv_sockets.used; ++i) {
            if (fd == srv->srv_sockets.ptr[i]->fd)
                break;
        }
        if (i < srv->srv_sockets.used) {
            (void)fdevent_socket_clr_cloexec(fd);
            ++fd;
            --n; /* loop to reprocess this entry */
            continue;
        }

        /* dup2() removes FD_CLOEXEC on newfd */
        if (fd != dup2(srv_socket->fd, fd)) continue;
        ++fd;
        /* old fd will be closed upon execv() due to its FD_CLOEXEC flag
         * (if not already closed by another dup2() over it) */
    }
    fd -= 3; /* now num fds; #define SD_LISTEN_FDS_START 3 */
    if (0 == fd) return; /*(no active sockets?)*/
    buffer * const tb = srv->tmp_buf;
    buffer_clear(tb);
    buffer_append_int(tb, fd);
    setenv("LISTEN_FDS", tb->ptr, 1);
    buffer_clear(tb);
    buffer_append_int(tb, srv->pid); /* getpid() */
    setenv("LISTEN_PID", tb->ptr, 1);
}

static int network_socket_activation_nfds(server *srv, const network_socket_config *s, int nfds) {
    buffer *host = buffer_init();
    socklen_t addr_len;
    sock_addr addr;
    int rc = 0;
    nfds += 3; /* #define SD_LISTEN_FDS_START 3 */
    for (int fd = 3; fd < nfds; ++fd) {
        addr_len = sizeof(sock_addr);
        if (-1 == (rc = getsockname(fd, (struct sockaddr *)&addr, &addr_len))) {
            log_serror(srv->errh, __FILE__, __LINE__,
              "socket activation getsockname()");
            break;
        }
        network_host_normalize_addr_str(host, &addr, addr_len);
        rc = network_server_init(srv, s, host, 0, fd);
        if (0 != rc) break;
        srv->srv_sockets.ptr[srv->srv_sockets.used-1]->sidx = (unsigned short)~0u;
    }
    buffer_free(host);
    memcpy(&srv->srv_sockets_inherited, &srv->srv_sockets, sizeof(server_socket_array));
    memset(&srv->srv_sockets, 0, sizeof(server_socket_array));
    return rc;
}

static int network_socket_activation_from_env(server *srv, const network_socket_config *s) {
    char *listen_pid = getenv("LISTEN_PID");
    char *listen_fds = getenv("LISTEN_FDS");
    pid_t lpid = listen_pid ? (pid_t)strtoul(listen_pid,NULL,10) : 0;
    int nfds = listen_fds ? atoi(listen_fds) : 0;
    int rc = (nfds > 0 && nfds < 5000
              && (lpid == getpid()
                 #ifndef _WIN32
                  || (0 == strncmp(listen_pid, "parent:", 7)
                      && getppid() == (pid_t)strtoul(listen_pid+7,NULL,10))
                 #endif
                 ))
      ? network_socket_activation_nfds(srv, s, nfds)
      : 0;
    unsetenv("LISTEN_PID");
    unsetenv("LISTEN_FDS");
    unsetenv("LISTEN_FDNAMES");
    /*(upon graceful restart, unsetenv will result in no-op above)*/
    return rc;
}

int network_init(server *srv, int stdin_fd) {
    /*(network params used during setup (from $SERVER["socket"] condition))*/
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.engine"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.listen-backlog"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.socket-perms"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.bsd-accept-filter"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.defer-accept"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.use-ipv6"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.set-v6only"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SOCKET }
     ,{ CONST_STR_LEN("server.v4mapped"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SOCKET }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    if (0 != network_write_init(srv)) return -1;

    network_plugin_data np;
    memset(&np, 0, sizeof(network_plugin_data));
    network_plugin_data *p = &np;

    if (!config_plugin_values_init(srv, p, cpk, "network"))
        return HANDLER_ERROR;

    p->defaults.listen_backlog = 1024;
    p->defaults.defer_accept = 0;
    p->defaults.use_ipv6 = 0;
    p->defaults.set_v6only = 1;
    p->defaults.v4mapped = -1; /*(-1 for unset; not 0 or 1)*/

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            network_merge_config(&p->defaults, cpv);
    }

    if (config_feature_bool(srv, "server.graceful-restart-bg", 0))
        srv->srvconf.systemd_socket_activation = 1;

    int rc = 0;
    do {

        if (srv->srvconf.systemd_socket_activation) {
            for (uint32_t i = 0; i < srv->srv_sockets_inherited.used; ++i) {
                srv->srv_sockets_inherited.ptr[i]->sidx = (unsigned short)~0u;
            }
            rc = network_socket_activation_from_env(srv, &p->defaults);
            if (0 != rc) break;
            if (0 == srv->srv_sockets_inherited.used) {
                srv->srvconf.systemd_socket_activation = 0;
            }
        }

        /* special-case srv->srvconf.bindhost = "/dev/stdin" (see server.c) */
        if (-1 != stdin_fd) {
            buffer *b = buffer_init();
            buffer_copy_buffer(b, srv->srvconf.bindhost);
            /*assert(buffer_eq_slen(b, CONST_STR_LEN("/dev/stdin")));*/
            rc = (0 == srv->srv_sockets.used)
              ? network_server_init(srv, &p->defaults, b, 0, stdin_fd)
              : fdio_close_socket(stdin_fd);/*(graceful restart; "/dev/stdin")*/
            buffer_free(b);
            if (0 != rc) break;
        }

        /* check for $SERVER["socket"] */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            config_cond_info cfginfo;
            config_get_config_cond_info(&cfginfo, i);
            if (COMP_SERVER_SOCKET != cfginfo.comp) continue;/* not our stage */

            buffer *host_token;
            *(const buffer **)&host_token = cfginfo.string;
            /*(cfginfo.string is modified during config)*/

            memcpy(&p->conf, &p->defaults, sizeof(network_socket_config));
            for (int j = !p->cvlist[0].v.u2[1]; j < p->nconfig; ++j) {
                if ((int)i != p->cvlist[j].k_id) continue;
                const config_plugin_value_t *cpv =
                  p->cvlist + p->cvlist[j].v.u2[0];
                network_merge_config(&p->conf, cpv);
                break;
            }

            if (cfginfo.cond == CONFIG_COND_EQ) {
                rc = network_server_init(srv, &p->conf, host_token, i, -1);
                if (0 != rc) break;
            }
            else if (cfginfo.cond == CONFIG_COND_NE) {
                socklen_t addr_len = sizeof(sock_addr);
                sock_addr addr;
                rc = network_host_parse_addr(srv, &addr, &addr_len,
                                             host_token, p->conf.use_ipv6);
                if (0 != rc) break;
                network_host_normalize_addr_str(host_token, &addr, addr_len);
            }
        }
        if (0 != rc) break;

        /* process srv->srvconf.bindhost
         * init global config for server.bindhost and server.port after
         * initializing $SERVER["socket"] so that if bindhost and port match
         * another $SERVER["socket"], the $SERVER["socket"] config is used,
         * as the $SERVER["socket"] config inherits from the global scope and
         * can then be overridden.  (bindhost = "/dev/stdin" is handled above)
         * (skip if systemd socket activation is enabled and bindhost is empty;
         *  do not additionally listen on "*") */
        if ((!srv->srvconf.systemd_socket_activation || srv->srvconf.bindhost)
            && -1 == stdin_fd) {
            buffer *b = buffer_init();
            if (srv->srvconf.bindhost)
                buffer_copy_buffer(b, srv->srvconf.bindhost);
            /*(skip adding port if unix socket path)*/
            if (!b->ptr || (b->ptr[0] != '/' && b->ptr[0] != '\\')) {
                buffer_append_char(b, ':');
                buffer_append_int(b, srv->srvconf.port);
            }
          #ifdef __COVERITY__
            force_assert(b->ptr);
          #endif

            rc = network_server_init(srv, &p->defaults, b, 0, -1);
            buffer_free(b);
            if (0 != rc) break;
        }

        if (srv->srvconf.systemd_socket_activation) {
            /* activate any inherited sockets not explicitly listed in config */
            server_socket *srv_socket;
            for (uint32_t i = 0; i < srv->srv_sockets_inherited.used; ++i) {
                    if ((unsigned short)~0u
                        != srv->srv_sockets_inherited.ptr[i]->sidx)
                        continue;
                    srv->srv_sockets_inherited.ptr[i]->sidx = 0;
                srv_socket = ck_calloc(1, sizeof(server_socket));
                memcpy(srv_socket, srv->srv_sockets_inherited.ptr[i],
                       sizeof(server_socket));
                srv_socket->is_ssl = p->defaults.ssl_enabled;
                /*(note: re-inits srv_socket->srv_token to new buffer ptr)*/
                network_srv_socket_init_token(srv_socket,srv_socket->srv_token);
                network_srv_sockets_append(srv, srv_socket);
            }
        }

        /* reset sidx of any graceful sockets not explicitly listed in config */
        for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
            if ((unsigned short)~0u == srv->srv_sockets.ptr[i]->sidx) {
                srv->srv_sockets.ptr[i]->sidx = 0;
                srv->srv_sockets.ptr[i]->is_ssl = p->defaults.ssl_enabled;
            }
        }

    } while (0);

    free(p->cvlist);
    return rc;
}

void network_unregister_sock(server *srv, server_socket *srv_socket) {
	fdnode *fdn = srv_socket->fdn;
	if (NULL == fdn) return;
	srv_socket->fdn = NULL;
	fdevent_fdnode_event_del(srv->ev, fdn);
	fdevent_unregister(srv->ev, fdn);
}

int network_register_fdevents(server *srv) {
	if (-1 == fdevent_reset(srv->ev)) {
		return -1;
	}

	if (srv->sockets_disabled) return 0; /* lighttpd -1 (one-shot mode) */

	/* register fdevents after reset */
	for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];
		if (srv_socket->fd == -1) continue;

		srv_socket->fdn = fdevent_register(srv->ev, srv_socket->fd, network_server_handle_fdevent, srv_socket);
		fdevent_fdnode_event_set(srv->ev, srv_socket->fdn, FDEVENT_IN);
	}
	return 0;
}
