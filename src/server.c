#include "first.h"

#include "server.h"
#include "buffer.h"
#include "network.h"
#include "log.h"
#include "keyvalue.h"
#include "rand.h"
#include "response.h"
#include "request.h"
#include "chunk.h"
#include "http_auth.h"
#include "http_chunk.h"
#include "http_vhostdb.h"
#include "fdevent.h"
#include "connections.h"
#include "stat_cache.h"
#include "plugin.h"
#include "joblist.h"
#include "network_backends.h"

#ifdef HAVE_VERSIONSTAMP_H
# include "versionstamp.h"
#else
# define REPO_VERSION ""
#endif

#define PACKAGE_DESC PACKAGE_NAME "/" PACKAGE_VERSION REPO_VERSION

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <locale.h>

#include <stdio.h>

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef HAVE_PWD_H
# include <grp.h>
# include <pwd.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#if defined HAVE_LIBSSL && defined HAVE_OPENSSL_SSL_H
#define USE_SSL
#define TEXT_SSL " (ssl)"
#else
#define TEXT_SSL
#endif

#ifndef __sgi
/* IRIX doesn't like the alarm based time() optimization */
/* #define USE_ALARM */
#endif

static int oneshot_fd = 0;
static volatile int pid_fd = -2;
static server_socket_array graceful_sockets;
static volatile sig_atomic_t graceful_restart = 0;
static volatile sig_atomic_t graceful_shutdown = 0;
static volatile sig_atomic_t srv_shutdown = 0;
static volatile sig_atomic_t handle_sig_child = 0;
static volatile sig_atomic_t handle_sig_alarm = 1;
static volatile sig_atomic_t handle_sig_hup = 0;

#if defined(HAVE_SIGACTION) && defined(SA_SIGINFO)
static volatile siginfo_t last_sigterm_info;
static volatile siginfo_t last_sighup_info;

static void sigaction_handler(int sig, siginfo_t *si, void *context) {
	static const siginfo_t empty_siginfo;
	UNUSED(context);

	if (!si) *(const siginfo_t **)&si = &empty_siginfo;

	switch (sig) {
	case SIGTERM:
		srv_shutdown = 1;
		last_sigterm_info = *si;
		break;
	case SIGUSR1:
		if (!graceful_shutdown) {
			graceful_restart = 1;
			graceful_shutdown = 1;
			last_sigterm_info = *si;
		}
		break;
	case SIGINT:
		if (graceful_shutdown) {
			if (2 == graceful_restart)
				graceful_restart = 1;
			else
				srv_shutdown = 1;
		} else {
			graceful_shutdown = 1;
		}
		last_sigterm_info = *si;

		break;
	case SIGALRM: 
		handle_sig_alarm = 1; 
		break;
	case SIGHUP:
		handle_sig_hup = 1;
		last_sighup_info = *si;
		break;
	case SIGCHLD:
		handle_sig_child = 1;
		break;
	}
}
#elif defined(HAVE_SIGNAL) || defined(HAVE_SIGACTION)
static void signal_handler(int sig) {
	switch (sig) {
	case SIGTERM: srv_shutdown = 1; break;
	case SIGUSR1:
		if (!graceful_shutdown) {
			graceful_restart = 1;
			graceful_shutdown = 1;
		}
		break;
	case SIGINT:
		if (graceful_shutdown) {
			if (2 == graceful_restart)
				graceful_restart = 1;
			else
				srv_shutdown = 1;
		} else {
			graceful_shutdown = 1;
		}
		break;
	case SIGALRM: handle_sig_alarm = 1; break;
	case SIGHUP:  handle_sig_hup = 1; break;
	case SIGCHLD: handle_sig_child = 1; break;
	}
}
#endif

#ifdef HAVE_FORK
static int daemonize(void) {
	int pipefd[2];
	pid_t pid;
#ifdef SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif

	if (pipe(pipefd) < 0) exit(-1);

	if (0 > (pid = fork())) exit(-1);

	if (0 < pid) {
		char buf;
		ssize_t bytes;

		close(pipefd[1]);
		/* parent waits for grandchild to be ready */
		do {
			bytes = read(pipefd[0], &buf, sizeof(buf));
		} while (bytes < 0 && EINTR == errno);
		close(pipefd[0]);

		if (bytes <= 0) {
			/* closed fd (without writing) == failure in grandchild */
			fputs("daemonized server failed to start; check error log for details\n", stderr);
			exit(-1);
		}

		exit(0);
	}

	close(pipefd[0]);

	if (-1 == setsid()) exit(0);

	signal(SIGHUP, SIG_IGN);

	if (0 != fork()) exit(0);

	if (0 != chdir("/")) exit(0);

	fdevent_setfd_cloexec(pipefd[1]);
	return pipefd[1];
}
#endif

static server *server_init(void) {
	int i;
	server *srv = calloc(1, sizeof(*srv));
	force_assert(srv);
#define CLEAN(x) \
	srv->x = buffer_init();

	CLEAN(response_header);
	CLEAN(parse_full_path);
	CLEAN(ts_debug_str);
	CLEAN(ts_date_str);
	CLEAN(errorlog_buf);
	CLEAN(response_range);
	CLEAN(tmp_buf);
	srv->empty_string = buffer_init_string("");
	CLEAN(cond_check_buf);

	CLEAN(srvconf.errorlog_file);
	CLEAN(srvconf.breakagelog_file);
	CLEAN(srvconf.groupname);
	CLEAN(srvconf.username);
	CLEAN(srvconf.changeroot);
	CLEAN(srvconf.bindhost);
	CLEAN(srvconf.event_handler);
	CLEAN(srvconf.pid_file);
	CLEAN(srvconf.syslog_facility);

	CLEAN(tmp_chunk_len);
#undef CLEAN

#define CLEAN(x) \
	srv->x = array_init();

	CLEAN(config_context);
	CLEAN(config_touched);
	CLEAN(status);
#undef CLEAN

	for (i = 0; i < FILE_CACHE_MAX; i++) {
		srv->mtime_cache[i].mtime = (time_t)-1;
		srv->mtime_cache[i].str = buffer_init();
	}

	li_rand_reseed();

	srv->cur_ts = time(NULL);
	srv->startup_ts = srv->cur_ts;

	srv->conns = calloc(1, sizeof(*srv->conns));
	force_assert(srv->conns);

	srv->joblist = calloc(1, sizeof(*srv->joblist));
	force_assert(srv->joblist);

	srv->fdwaitqueue = calloc(1, sizeof(*srv->fdwaitqueue));
	force_assert(srv->fdwaitqueue);

	srv->srvconf.modules = array_init();
	srv->srvconf.modules_dir = buffer_init_string(LIBRARY_DIR);
	srv->srvconf.network_backend = buffer_init();
	srv->srvconf.upload_tempdirs = array_init();
	srv->srvconf.reject_expect_100_with_417 = 1;
	srv->srvconf.xattr_name = buffer_init_string("Content-Type");
	srv->srvconf.http_header_strict  = 1;
	srv->srvconf.http_host_strict    = 1; /*(implies http_host_normalize)*/
	srv->srvconf.http_host_normalize = 0;
	srv->srvconf.high_precision_timestamps = 0;
	srv->srvconf.max_request_field_size = 8192;
	srv->srvconf.loadavg[0] = 0.0;
	srv->srvconf.loadavg[1] = 0.0;
	srv->srvconf.loadavg[2] = 0.0;

	/* use syslog */
	srv->errorlog_fd = STDERR_FILENO;
	srv->errorlog_mode = ERRORLOG_FD;

	srv->split_vals = array_init();
	srv->request_env = plugins_call_handle_request_env;

	return srv;
}

static void server_free(server *srv) {
	size_t i;

	for (i = 0; i < FILE_CACHE_MAX; i++) {
		buffer_free(srv->mtime_cache[i].str);
	}

	if (oneshot_fd > 0) {
		close(oneshot_fd);
	}

#define CLEAN(x) \
	buffer_free(srv->x);

	CLEAN(response_header);
	CLEAN(parse_full_path);
	CLEAN(ts_debug_str);
	CLEAN(ts_date_str);
	CLEAN(errorlog_buf);
	CLEAN(response_range);
	CLEAN(tmp_buf);
	CLEAN(empty_string);
	CLEAN(cond_check_buf);

	CLEAN(srvconf.errorlog_file);
	CLEAN(srvconf.breakagelog_file);
	CLEAN(srvconf.groupname);
	CLEAN(srvconf.username);
	CLEAN(srvconf.changeroot);
	CLEAN(srvconf.bindhost);
	CLEAN(srvconf.event_handler);
	CLEAN(srvconf.pid_file);
	CLEAN(srvconf.modules_dir);
	CLEAN(srvconf.network_backend);
	CLEAN(srvconf.xattr_name);
	CLEAN(srvconf.syslog_facility);

	CLEAN(tmp_chunk_len);
#undef CLEAN

#if 0
	fdevent_unregister(srv->ev, srv->fd);
#endif
	fdevent_free(srv->ev);

	free(srv->conns);

	if (srv->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			specific_config *s = srv->config_storage[i];

			if (!s) continue;

			buffer_free(s->document_root);
			buffer_free(s->server_name);
			buffer_free(s->server_tag);
			buffer_free(s->error_handler);
			buffer_free(s->error_handler_404);
			buffer_free(s->errorfile_prefix);
			buffer_free(s->socket_perms);
			array_free(s->mimetypes);
			free(s);
		}
		free(srv->config_storage);
		srv->config_storage = NULL;
	}

#define CLEAN(x) \
	array_free(srv->x);

	CLEAN(config_context);
	CLEAN(config_touched);
	CLEAN(status);
	CLEAN(srvconf.upload_tempdirs);
#undef CLEAN

	joblist_free(srv, srv->joblist);
	fdwaitqueue_free(srv, srv->fdwaitqueue);

	if (srv->stat_cache) {
		stat_cache_free(srv->stat_cache);
	}

	array_free(srv->srvconf.modules);
	array_free(srv->split_vals);

	li_rand_cleanup();

	free(srv);
}

static void remove_pid_file(server *srv) {
	if (pid_fd <= -2) return;
	if (!buffer_string_is_empty(srv->srvconf.pid_file) && 0 <= pid_fd) {
		if (0 != ftruncate(pid_fd, 0)) {
			log_error_write(srv, __FILE__, __LINE__, "sbds",
					"ftruncate failed for:",
					srv->srvconf.pid_file,
					errno,
					strerror(errno));
		}
	}
	if (0 <= pid_fd) {
		close(pid_fd);
		pid_fd = -1;
	}
	if (!buffer_string_is_empty(srv->srvconf.pid_file) &&
	    buffer_string_is_empty(srv->srvconf.changeroot)) {
		if (0 != unlink(srv->srvconf.pid_file->ptr)) {
			if (errno != EACCES && errno != EPERM) {
				log_error_write(srv, __FILE__, __LINE__, "sbds",
						"unlink failed for:",
						srv->srvconf.pid_file,
						errno,
						strerror(errno));
			}
		}
	}
}


static server_socket * server_oneshot_getsock(server *srv, sock_addr *cnt_addr) {
	server_socket *srv_socket, *srv_socket_wild = NULL;
	size_t i;
	for (i = 0; i < srv->srv_sockets.used; ++i) {
		srv_socket = srv->srv_sockets.ptr[i];
		if (cnt_addr->plain.sa_family != srv_socket->addr.plain.sa_family) continue;
		switch (cnt_addr->plain.sa_family) {
		case AF_INET:
			if (srv_socket->addr.ipv4.sin_port != cnt_addr->ipv4.sin_port) continue;
			if (srv_socket->addr.ipv4.sin_addr.s_addr == cnt_addr->ipv4.sin_addr.s_addr) {
				return srv_socket;
			}
			if (srv_socket->addr.ipv4.sin_addr.s_addr == htonl(INADDR_ANY)) {
				srv_socket_wild = srv_socket;
			}
			continue;
		#ifdef HAVE_IPV6
		case AF_INET6:
			if (srv_socket->addr.ipv6.sin6_port != cnt_addr->ipv6.sin6_port) continue;
			if (0 == memcmp(&srv_socket->addr.ipv6.sin6_addr, &cnt_addr->ipv6.sin6_addr, sizeof(struct in6_addr))) {
				return srv_socket;
			}
			if (0 == memcmp(&srv_socket->addr.ipv6.sin6_addr, &in6addr_any, sizeof(struct in6_addr))) {
				srv_socket_wild = srv_socket;
			}
			continue;
		#endif
		#ifdef HAVE_SYS_UN_H
		case AF_UNIX:
			if (0 == strcmp(srv_socket->addr.un.sun_path, cnt_addr->un.sun_path)) {
				return srv_socket;
			}
			continue;
		#endif
		default: continue;
		}
	}

	if (NULL != srv_socket_wild) {
		return srv_socket_wild;
	} else if (srv->srv_sockets.used) {
		return srv->srv_sockets.ptr[0];
	} else {
		log_error_write(srv, __FILE__, __LINE__, "s", "no sockets configured");
		return NULL;
	}
}


static int server_oneshot_init(server *srv, int fd) {
	/* Note: does not work with netcat due to requirement that fd be socket.
	 * STDOUT_FILENO was not saved earlier in startup, and that is to where
	 * netcat expects output to be sent.  Since lighttpd expects connections
	 * to be sockets, con->fd is where output is sent; separate fds are not
	 * stored for input and output, but netcat has different fds for stdin
	 * and * stdout.  To support netcat, would additionally need to avoid
	 * S_ISSOCK(), getsockname(), and getpeername() below, reconstructing
	 * addresses from environment variables:
	 *   NCAT_LOCAL_ADDR   NCAT_LOCAL_PORT
	 *   NCAT_REMOTE_ADDR  NCAT_REMOTE_PORT
	 *   NCAT_PROTO
	 */
	connection *con;
	server_socket *srv_socket;
	sock_addr cnt_addr;
	socklen_t cnt_len;
	struct stat st;

	if (0 != fstat(fd, &st)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "fstat:", strerror(errno));
		return 0;
	}

	if (!S_ISSOCK(st.st_mode)) {
		/* require that fd is a socket
		 * (modules might expect STDIN_FILENO and STDOUT_FILENO opened to /dev/null) */
		log_error_write(srv, __FILE__, __LINE__, "s", "lighttpd -1 stdin is not a socket");
		return 0;
	}

	cnt_len = sizeof(cnt_addr);
	if (0 != getsockname(fd, (struct sockaddr *)&cnt_addr, &cnt_len)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "getsockname:", strerror(errno));
		return 0;
	}

	srv_socket = server_oneshot_getsock(srv, &cnt_addr);
	if (NULL == srv_socket) return 0;

	cnt_len = sizeof(cnt_addr);
	if (0 != getpeername(fd, (struct sockaddr *)&cnt_addr, &cnt_len)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "getpeername:", strerror(errno));
		return 0;
	}

	/*(must set flags; fd did not pass through fdevent accept() logic)*/
	if (-1 == fdevent_fcntl_set_nb_cloexec(srv->ev, fd)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl:", strerror(errno));
		return 0;
	}

	if (cnt_addr.plain.sa_family != AF_UNIX) {
		network_accept_tcp_nagle_disable(fd);
	}

	con = connection_accepted(srv, srv_socket, &cnt_addr, fd);
	if (NULL == con) return 0;

	connection_state_machine(srv, con);
	return 1;
}


static void show_version (void) {
	char *b = PACKAGE_DESC TEXT_SSL \
" - a light and fast webserver\n"
#ifdef NONREPRODUCIBLE_BUILD
"Build-Date: " __DATE__ " " __TIME__ "\n";
#endif
;
	write_all(STDOUT_FILENO, b, strlen(b));
}

static void show_features (void) {
  const char features[] = ""
#ifdef USE_SELECT
      "\t+ select (generic)\n"
#else
      "\t- select (generic)\n"
#endif
#ifdef USE_POLL
      "\t+ poll (Unix)\n"
#else
      "\t- poll (Unix)\n"
#endif
#ifdef USE_LINUX_EPOLL
      "\t+ epoll (Linux 2.6)\n"
#else
      "\t- epoll (Linux 2.6)\n"
#endif
#ifdef USE_SOLARIS_DEVPOLL
      "\t+ /dev/poll (Solaris)\n"
#else
      "\t- /dev/poll (Solaris)\n"
#endif
#ifdef USE_SOLARIS_PORT
      "\t+ eventports (Solaris)\n"
#else
      "\t- eventports (Solaris)\n"
#endif
#ifdef USE_FREEBSD_KQUEUE
      "\t+ kqueue (FreeBSD)\n"
#else
      "\t- kqueue (FreeBSD)\n"
#endif
#ifdef USE_LIBEV
      "\t+ libev (generic)\n"
#else
      "\t- libev (generic)\n"
#endif
      "\nNetwork handler:\n\n"
#if defined USE_LINUX_SENDFILE
      "\t+ linux-sendfile\n"
#else
      "\t- linux-sendfile\n"
#endif
#if defined USE_FREEBSD_SENDFILE
      "\t+ freebsd-sendfile\n"
#else
      "\t- freebsd-sendfile\n"
#endif
#if defined USE_DARWIN_SENDFILE
      "\t+ darwin-sendfile\n"
#else
      "\t- darwin-sendfile\n"
#endif
#if defined USE_SOLARIS_SENDFILEV
      "\t+ solaris-sendfilev\n"
#else
      "\t- solaris-sendfilev\n"
#endif
#if defined USE_WRITEV
      "\t+ writev\n"
#else
      "\t- writev\n"
#endif
      "\t+ write\n"
#ifdef USE_MMAP
      "\t+ mmap support\n"
#else
      "\t- mmap support\n"
#endif
      "\nFeatures:\n\n"
#ifdef HAVE_IPV6
      "\t+ IPv6 support\n"
#else
      "\t- IPv6 support\n"
#endif
#if defined HAVE_ZLIB_H && defined HAVE_LIBZ
      "\t+ zlib support\n"
#else
      "\t- zlib support\n"
#endif
#if defined HAVE_BZLIB_H && defined HAVE_LIBBZ2
      "\t+ bzip2 support\n"
#else
      "\t- bzip2 support\n"
#endif
#if defined(HAVE_CRYPT) || defined(HAVE_CRYPT_R) || defined(HAVE_LIBCRYPT)
      "\t+ crypt support\n"
#else
      "\t- crypt support\n"
#endif
#ifdef USE_SSL
      "\t+ SSL support\n"
#else
      "\t- SSL support\n"
#endif
#ifdef HAVE_LIBPCRE
      "\t+ PCRE support\n"
#else
      "\t- PCRE support\n"
#endif
#ifdef HAVE_MYSQL
      "\t+ MySQL support\n"
#else
      "\t- MySQL support\n"
#endif
#ifdef HAVE_PGSQL
      "\t+ PgSQL support\n"
#else
      "\t- PgSQL support\n"
#endif
#ifdef HAVE_DBI
      "\t+ DBI support\n"
#else
      "\t- DBI support\n"
#endif
#ifdef HAVE_KRB5
      "\t+ Kerberos support\n"
#else
      "\t- Kerberos support\n"
#endif
#if defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER)
      "\t+ LDAP support\n"
#else
      "\t- LDAP support\n"
#endif
#ifdef USE_MEMCACHED
      "\t+ memcached support\n"
#else
      "\t- memcached support\n"
#endif
#ifdef HAVE_FAM_H
      "\t+ FAM support\n"
#else
      "\t- FAM support\n"
#endif
#ifdef HAVE_LUA_H
      "\t+ LUA support\n"
#else
      "\t- LUA support\n"
#endif
#ifdef HAVE_LIBXML_H
      "\t+ xml support\n"
#else
      "\t- xml support\n"
#endif
#ifdef HAVE_SQLITE3_H
      "\t+ SQLite support\n"
#else
      "\t- SQLite support\n"
#endif
#ifdef HAVE_GDBM_H
      "\t+ GDBM support\n"
#else
      "\t- GDBM support\n"
#endif
      "\n";
  show_version();
  printf("\nEvent Handlers:\n\n%s", features);
}

static void show_help (void) {
	char *b = PACKAGE_DESC TEXT_SSL
#ifdef NONREPRODUCIBLE_BUILD
" ("__DATE__ " " __TIME__ ")"
#endif
" - a light and fast webserver\n" \
"usage:\n" \
" -f <name>  filename of the config-file\n" \
" -m <name>  module directory (default: "LIBRARY_DIR")\n" \
" -i <secs>  graceful shutdown after <secs> of inactivity\n" \
" -1         process single (one) request on stdin socket, then exit\n" \
" -p         print the parsed config-file in internal form, and exit\n" \
" -t         test config-file syntax, then exit\n" \
" -tt        test config-file syntax, load and init modules, then exit\n" \
" -D         don't go to background (default: go to background)\n" \
" -v         show version\n" \
" -V         show compile-time features\n" \
" -h         show this help\n" \
"\n"
;
	write_all(STDOUT_FILENO, b, strlen(b));
}

/**
 * open the errorlog
 *
 * we have 4 possibilities:
 * - stderr (default)
 * - syslog
 * - logfile
 * - pipe
 *
 */

static int log_error_open(server *srv) {
    int errfd;
  #ifdef HAVE_SYSLOG_H
    /* perhaps someone wants to use syslog() */
    int facility = -1;
    if (!buffer_string_is_empty(srv->srvconf.syslog_facility)) {
        static const struct facility_name_st {
          const char *name;
          int val;
        } facility_names[] = {
            { "auth",     LOG_AUTH }
          #ifdef LOG_AUTHPRIV
           ,{ "authpriv", LOG_AUTHPRIV }
          #endif
          #ifdef LOG_CRON
           ,{ "cron",     LOG_CRON }
          #endif
           ,{ "daemon",   LOG_DAEMON }
          #ifdef LOG_FTP
           ,{ "ftp",      LOG_FTP }
          #endif
          #ifdef LOG_KERN
           ,{ "kern",     LOG_KERN }
          #endif
          #ifdef LOG_LPR
           ,{ "lpr",      LOG_LPR }
          #endif
          #ifdef LOG_MAIL
           ,{ "mail",     LOG_MAIL }
          #endif
          #ifdef LOG_NEWS
           ,{ "news",     LOG_NEWS }
          #endif
           ,{ "security", LOG_AUTH }           /* DEPRECATED */
          #ifdef LOG_SYSLOG
           ,{ "syslog",   LOG_SYSLOG }
          #endif
          #ifdef LOG_USER
           ,{ "user",     LOG_USER }
          #endif
          #ifdef LOG_UUCP
           ,{ "uucp",     LOG_UUCP }
          #endif
           ,{ "local0",   LOG_LOCAL0 }
           ,{ "local1",   LOG_LOCAL1 }
           ,{ "local2",   LOG_LOCAL2 }
           ,{ "local3",   LOG_LOCAL3 }
           ,{ "local4",   LOG_LOCAL4 }
           ,{ "local5",   LOG_LOCAL5 }
           ,{ "local6",   LOG_LOCAL6 }
           ,{ "local7",   LOG_LOCAL7 }
        };
        unsigned int i;
        for (i = 0; i < sizeof(facility_names)/sizeof(facility_names[0]); ++i) {
            const struct facility_name_st *f = facility_names+i;
            if (0 == strcmp(srv->srvconf.syslog_facility->ptr, f->name)) {
                facility = f->val;
                break;
            }
        }
        if (-1 == facility) {
            log_error_write(srv, __FILE__, __LINE__, "SBS",
                            "unrecognized server.syslog-facility: \"",
                            srv->srvconf.syslog_facility,
                            "\"; defaulting to \"daemon\" facility");
        }
    }
    openlog("lighttpd", LOG_CONS|LOG_PID, -1==facility ? LOG_DAEMON : facility);
  #endif

    srv->errorlog_mode = ERRORLOG_FD;
    srv->errorlog_fd = STDERR_FILENO;

    if (srv->srvconf.errorlog_use_syslog) {
        srv->errorlog_mode = ERRORLOG_SYSLOG;
    }
    else if (!buffer_string_is_empty(srv->srvconf.errorlog_file)) {
        const char *logfile = srv->srvconf.errorlog_file->ptr;

        if (-1 == (srv->errorlog_fd = fdevent_open_logger(logfile))) {
            log_error_write(srv, __FILE__, __LINE__, "SSSS",
                            "opening errorlog '", logfile,
                            "' failed: ", strerror(errno));
            return -1;
        }
        srv->errorlog_mode = logfile[0] == '|' ? ERRORLOG_PIPE : ERRORLOG_FILE;
    }

    if (srv->errorlog_mode == ERRORLOG_FD && !srv->srvconf.dont_daemonize) {
        /* We can only log to stderr in dont-daemonize mode;
         * if we do daemonize and no errorlog file is specified,
         * we log into /dev/null
         */
        srv->errorlog_fd = -1;
    }

    if (!buffer_string_is_empty(srv->srvconf.breakagelog_file)) {
        const char *logfile = srv->srvconf.breakagelog_file->ptr;

        if (srv->errorlog_mode == ERRORLOG_FD) {
            srv->errorlog_fd = dup(STDERR_FILENO);
            fdevent_setfd_cloexec(srv->errorlog_fd);
        }

        if (-1 == (errfd = fdevent_open_logger(logfile))) {
            log_error_write(srv, __FILE__, __LINE__, "SSSS",
                            "opening errorlog '", logfile,
                            "' failed: ", strerror(errno));
            return -1;
        }

        if (*logfile == '|') fdevent_breakagelog_logger_pipe(errfd);
    }
    else if (!srv->srvconf.dont_daemonize) {
        /* move STDERR_FILENO to /dev/null */
        if (-1 == (errfd = fdevent_open_devnull())) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "opening /dev/null failed:", strerror(errno));
            return -1;
        }
    }
    else {
        /*(leave STDERR_FILENO as-is)*/
        errfd = -1;
    }

    if (0 != fdevent_set_stdin_stdout_stderr(-1, -1, errfd)) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "setting stderr failed:", strerror(errno));
      #ifdef FD_CLOEXEC
        if (-1 != errfd) close(errfd);
      #endif
        return -1;
    }
  #ifdef FD_CLOEXEC
    if (-1 != errfd) close(errfd);
  #endif

    return 0;
}

/**
 * cycle the errorlog
 *
 */

static int log_error_cycle(server *srv) {
    /* cycle only if the error log is a file */

    if (srv->errorlog_mode == ERRORLOG_FILE) {
        const char *logfile = srv->srvconf.errorlog_file->ptr;
        if (-1 == fdevent_cycle_logger(logfile, &srv->errorlog_fd)) {
            /* write to old log */
            log_error_write(srv, __FILE__, __LINE__, "SSSS",
                            "cycling errorlog '", logfile,
                            "' failed: ", strerror(errno));
        }
    }

    return 0;
}

static int log_error_close(server *srv) {
    switch(srv->errorlog_mode) {
    case ERRORLOG_PIPE:
    case ERRORLOG_FILE:
    case ERRORLOG_FD:
        if (-1 != srv->errorlog_fd) {
            /* don't close STDERR */
            /* fdevent_close_logger_pipes() closes ERRORLOG_PIPE */
            if (STDERR_FILENO != srv->errorlog_fd
                && srv->errorlog_mode != ERRORLOG_PIPE) {
                close(srv->errorlog_fd);
            }
            srv->errorlog_fd = -1;
        }
        break;
    case ERRORLOG_SYSLOG:
      #ifdef HAVE_SYSLOG_H
        closelog();
      #endif
        break;
    }

    return 0;
}

static void server_sockets_save (server *srv) {    /* graceful_restart */
    memcpy(&graceful_sockets, &srv->srv_sockets, sizeof(server_socket_array));
    memset(&srv->srv_sockets, 0, sizeof(server_socket_array));
}

static void server_sockets_restore (server *srv) { /* graceful_restart */
    memcpy(&srv->srv_sockets, &graceful_sockets, sizeof(server_socket_array));
    memset(&graceful_sockets, 0, sizeof(server_socket_array));
}

static int server_sockets_set_nb_cloexec (server *srv) {
    if (srv->sockets_disabled) return 0; /* lighttpd -1 (one-shot mode) */
    for (size_t i = 0; i < srv->srv_sockets.used; ++i) {
        server_socket *srv_socket = srv->srv_sockets.ptr[i];
        if (-1 == fdevent_fcntl_set_nb_cloexec_sock(srv->ev, srv_socket->fd)) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "fcntl failed:", strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void server_sockets_set_event (server *srv, int event) {
    for (size_t i = 0; i < srv->srv_sockets.used; ++i) {
        server_socket *srv_socket = srv->srv_sockets.ptr[i];
        fdevent_event_set(srv->ev,&(srv_socket->fde_ndx),srv_socket->fd,event);
    }
}

static void server_sockets_unregister (server *srv) {
    for (size_t i = 0; i < srv->srv_sockets.used; ++i)
        network_unregister_sock(srv, srv->srv_sockets.ptr[i]);
}

static void server_sockets_close (server *srv) {
    /* closing socket right away will make it possible for the next lighttpd
     * to take over (old-style graceful restart), but only if backends
     * (e.g. fastcgi, scgi, etc) are independent from lighttpd, rather
     * than started by lighttpd via "bin-path")
     */
    for (size_t i = 0; i < srv->srv_sockets.used; ++i) {
        server_socket *srv_socket = srv->srv_sockets.ptr[i];
        if (-1 == srv_socket->fd) continue;
        network_unregister_sock(srv, srv_socket);
        close(srv_socket->fd);
        srv_socket->fd = -1;
        /* network_close() will cleanup after us */
    }
}

static void server_graceful_shutdown_maint (server *srv) {
    connections *conns = srv->conns;
    for (size_t ndx = 0; ndx < conns->used; ++ndx) {
        connection * const con = conns->ptr[ndx];
        int changed = 0;

        if (con->state == CON_STATE_CLOSE) {
            /* reduce remaining linger timeout to be
             * (from zero) *up to* one more second, but no more */
            if (HTTP_LINGER_TIMEOUT > 1)
                con->close_timeout_ts -= (HTTP_LINGER_TIMEOUT - 1);
            if (srv->cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT)
                changed = 1;
        }
        else if (con->state == CON_STATE_READ && con->request_count > 1
                 && chunkqueue_is_empty(con->read_queue)) {
            /* close connections in keep-alive waiting for next request */
            connection_set_state(srv, con, CON_STATE_ERROR);
            changed = 1;
        }

        con->keep_alive = 0;                    /* disable keep-alive */

        con->conf.kbytes_per_second = 0;        /* disable rate limit */
        con->conf.global_kbytes_per_second = 0; /* disable rate limit */
        if (con->traffic_limit_reached) {
            con->traffic_limit_reached = 0;
            changed = 1;
        }

        if (changed) {
            connection_state_machine(srv, con);
        }
    }
}

static void server_graceful_state (server *srv) {

    if (!srv_shutdown) server_graceful_shutdown_maint(srv);

    if (!oneshot_fd) {
        if (0==srv->srv_sockets.used || -1 == srv->srv_sockets.ptr[0]->fde_ndx)
            return;
    }

    log_error_write(srv, __FILE__, __LINE__, "s",
                    "[note] graceful shutdown started");

    /* no graceful restart if chroot()ed, if oneshot mode, or if idle timeout */
    if (!buffer_string_is_empty(srv->srvconf.changeroot)
        || oneshot_fd || 2 == graceful_shutdown)
        graceful_restart = 0;

    if (graceful_restart) {
        server_sockets_unregister(srv);
        if (pid_fd > 0) pid_fd = -pid_fd; /*(flag to skip removing pid file)*/
    }
    else {
        server_sockets_close(srv);
        remove_pid_file(srv);
        buffer_reset(srv->srvconf.pid_file); /*(prevent more removal attempts)*/
    }
}

static int server_main (server * const srv, int argc, char **argv) {
	int print_config = 0;
	int test_config = 0;
	int i_am_root = 0;
	int o;
#ifdef HAVE_FORK
	int num_childs = 0;
#endif
	size_t i;
	time_t idle_limit = 0, last_active_ts = time(NULL);
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

#ifdef HAVE_FORK
	int parent_pipe_fd = -1;
#endif
	int stdin_fd = -1;

#ifdef HAVE_GETUID
	i_am_root = (0 == getuid());
#endif

	/* initialize globals (including file-scoped static globals) */
	oneshot_fd = 0;
	srv_shutdown = 0;
	graceful_shutdown = 0;
	handle_sig_alarm = 1;
	handle_sig_hup = 0;
	chunkqueue_set_tempdirs_default_reset();
	http_auth_dumbdata_reset();
	http_vhostdb_dumbdata_reset();
	/*graceful_restart = 0;*//*(reset below to avoid further daemonizing)*/
	/*(intentionally preserved)*/
	/*memset(graceful_sockets, 0, sizeof(graceful_sockets));*/
	/*pid_fd = -1;*/

	srv->srvconf.port = 0;
	srv->srvconf.dont_daemonize = 0;
	srv->srvconf.preflight_check = 0;

	while(-1 != (o = getopt(argc, argv, "f:m:i:hvVD1pt"))) {
		switch(o) {
		case 'f':
			if (srv->config_storage) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"Can only read one config file. Use the include command to use multiple config files.");
				return -1;
			}
			if (config_read(srv, optarg)) {
				return -1;
			}
			break;
		case 'm':
			buffer_copy_string(srv->srvconf.modules_dir, optarg);
			break;
		case 'i': {
			char *endptr;
			long timeout = strtol(optarg, &endptr, 0);
			if (!*optarg || *endptr || timeout < 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"Invalid idle timeout value:", optarg);
				return -1;
			}
			idle_limit = (time_t)timeout;
			break;
		}
		case 'p': print_config = 1; break;
		case 't': ++test_config; break;
		case '1': if (0 == oneshot_fd) oneshot_fd = dup(STDIN_FILENO);
			  break;
		case 'D': srv->srvconf.dont_daemonize = 1; break;
		case 'v': show_version(); return 0;
		case 'V': show_features(); return 0;
		case 'h': show_help(); return 0;
		default:
			show_help();
			return -1;
		}
	}

	if (!srv->config_storage) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"No configuration available. Try using -f option.");
		return -1;
	}

	if (print_config) {
		data_unset *dc = srv->config_context->data[0];
		if (dc) {
			dc->print(dc, 0);
			fprintf(stdout, "\n");
		} else {
			/* shouldn't happend */
			fprintf(stderr, "global config not found\n");
		}
	}

	if (test_config) {
		buffer_reset(srv->srvconf.pid_file);
		if (1 == test_config) {
			printf("Syntax OK\n");
		} else { /*(test_config > 1)*/
			test_config = 0;
			srv->srvconf.preflight_check = 1;
			srv->srvconf.dont_daemonize = 1;
		}
	}

	if (test_config || print_config) {
		return 0;
	}

	if (oneshot_fd) {
		if (oneshot_fd <= STDERR_FILENO) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"Invalid fds at startup with lighttpd -1");
			return -1;
		}
		graceful_shutdown = 1;
		srv->sockets_disabled = 1;
		srv->srvconf.dont_daemonize = 1;
		buffer_reset(srv->srvconf.pid_file);
		if (srv->srvconf.max_worker) {
			srv->srvconf.max_worker = 0;
			log_error_write(srv, __FILE__, __LINE__, "s",
					"server one-shot command line option disables server.max-worker config file option.");
		}
	}

	if (buffer_is_equal_string(srv->srvconf.bindhost, CONST_STR_LEN("/dev/stdin"))) {
		stdin_fd = dup(STDIN_FILENO);
		if (stdin_fd <= STDERR_FILENO) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"Invalid fds at startup");
			return -1;
		}
	}

	/* close stdin and stdout, as they are not needed */
	{
		struct stat st;
		int devnull;
		int errfd;
		do {
			/* coverity[overwrite_var : FALSE] */
			devnull = fdevent_open_devnull();
		      #ifdef __COVERITY__
			__coverity_escape__(devnull);
		      #endif
		} while (-1 != devnull && devnull <= STDERR_FILENO);
		if (-1 == devnull) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"opening /dev/null failed:", strerror(errno));
			return -1;
		}
		errfd = (0 == fstat(STDERR_FILENO, &st)) ? -1 : devnull;
		if (0 != fdevent_set_stdin_stdout_stderr(devnull, devnull, errfd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"setting default fds failed:", strerror(errno));
		      #ifdef FD_CLOEXEC
			if (-1 != errfd) close(errfd);
			if (devnull != errfd) close(devnull);
		      #endif
			return -1;
		}
	      #ifdef FD_CLOEXEC
		if (-1 != errfd) close(errfd);
		if (devnull != errfd) close(devnull);
	      #endif
	}

	if (0 != config_set_defaults(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"setting default values failed");
		return -1;
	}

	/* check document-root */
	if (buffer_string_is_empty(srv->config_storage[0]->document_root)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"document-root is not set\n");
		return -1;
	}

	if (plugins_load(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"loading plugins finally failed");
		return -1;
	}

	if (HANDLER_GO_ON != plugins_call_init(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Initialization of plugins failed. Going down.");
		return -1;
	}

	/* open pid file BEFORE chroot */
	if (-2 == pid_fd) pid_fd = -1; /*(initial startup state)*/
	if (-1 == pid_fd && !buffer_string_is_empty(srv->srvconf.pid_file)) {
		if (-1 == (pid_fd = fdevent_open_cloexec(srv->srvconf.pid_file->ptr, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
			struct stat st;
			if (errno != EEXIST) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
					"opening pid-file failed:", srv->srvconf.pid_file, strerror(errno));
				return -1;
			}

			if (0 != stat(srv->srvconf.pid_file->ptr, &st)) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"stating existing pid-file failed:", srv->srvconf.pid_file, strerror(errno));
			}

			if (!S_ISREG(st.st_mode)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"pid-file exists and isn't regular file:", srv->srvconf.pid_file);
				return -1;
			}

			if (-1 == (pid_fd = fdevent_open_cloexec(srv->srvconf.pid_file->ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"opening pid-file failed:", srv->srvconf.pid_file, strerror(errno));
				return -1;
			}
		}
	}

	if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
		/* select limits itself
		 *
		 * as it is a hard limit and will lead to a segfault we add some safety
		 * */
		srv->max_fds = FD_SETSIZE - 200;
	} else {
		srv->max_fds = 4096;
	}

	{
#ifdef HAVE_GETRLIMIT
		struct rlimit rlim;
		int use_rlimit = 1;
#ifdef HAVE_VALGRIND_VALGRIND_H
		if (RUNNING_ON_VALGRIND) use_rlimit = 0;
#endif

		if (0 != getrlimit(RLIMIT_NOFILE, &rlim)) {
			log_error_write(srv, __FILE__, __LINE__,
					"ss", "couldn't get 'max filedescriptors'",
					strerror(errno));
			return -1;
		}

		/**
		 * if we are not root can can't increase the fd-limit above rlim_max, but we can reduce it
		 */
		if (use_rlimit && srv->srvconf.max_fds
		    && (i_am_root || srv->srvconf.max_fds <= rlim.rlim_max)) {
			/* set rlimits */

			rlim.rlim_cur = srv->srvconf.max_fds;
			if (i_am_root) rlim.rlim_max = srv->srvconf.max_fds;

			if (0 != setrlimit(RLIMIT_NOFILE, &rlim)) {
				log_error_write(srv, __FILE__, __LINE__,
						"ss", "couldn't set 'max filedescriptors'",
						strerror(errno));
				return -1;
			}
		}

		if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
			srv->max_fds = rlim.rlim_cur < (rlim_t)FD_SETSIZE - 200 ? (int)rlim.rlim_cur : (int)FD_SETSIZE - 200;
		} else {
			srv->max_fds = rlim.rlim_cur;
			/*(default upper limit of 4k if server.max-fds not specified)*/
			if (i_am_root && 0 == srv->srvconf.max_fds && rlim.rlim_cur > 4096)
				srv->max_fds = 4096;
		}

		/* set core file rlimit, if enable_cores is set */
		if (use_rlimit && srv->srvconf.enable_cores && getrlimit(RLIMIT_CORE, &rlim) == 0) {
			rlim.rlim_cur = rlim.rlim_max;
			setrlimit(RLIMIT_CORE, &rlim);
		}
#endif
		if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
			/* don't raise the limit above FD_SET_SIZE */
			if (srv->max_fds > ((int)FD_SETSIZE) - 200) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"can't raise max filedescriptors above",  FD_SETSIZE - 200,
						"if event-handler is 'select'. Use 'poll' or something else or reduce server.max-fds.");
				return -1;
			}
		}
	}

	/* we need root-perms for port < 1024 */
	if (0 != network_init(srv, stdin_fd)) {
		return -1;
	}

	if (i_am_root) {
#ifdef HAVE_PWD_H
		/* set user and group */
		struct group *grp = NULL;
		struct passwd *pwd = NULL;

		if (!buffer_string_is_empty(srv->srvconf.groupname)) {
			if (NULL == (grp = getgrnam(srv->srvconf.groupname->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					"can't find groupname", srv->srvconf.groupname);
				return -1;
			}
		}

		if (!buffer_string_is_empty(srv->srvconf.username)) {
			if (NULL == (pwd = getpwnam(srv->srvconf.username->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"can't find username", srv->srvconf.username);
				return -1;
			}

			if (pwd->pw_uid == 0) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"I will not set uid to 0\n");
				return -1;
			}

			if (NULL == grp && NULL == (grp = getgrgid(pwd->pw_gid))) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
					"can't find group id", pwd->pw_gid);
				return -1;
			}
		}

		if (NULL != grp) {
			if (grp->gr_gid == 0) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"I will not set gid to 0\n");
				return -1;
			}
		}

		/* 
		 * Change group before chroot, when we have access
		 * to /etc/group
		 * */
		if (NULL != grp) {
			if (-1 == setgid(grp->gr_gid)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "setgid failed: ", strerror(errno));
				return -1;
			}
			if (-1 == setgroups(0, NULL)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "setgroups failed: ", strerror(errno));
				return -1;
			}
			if (!buffer_string_is_empty(srv->srvconf.username)) {
				initgroups(srv->srvconf.username->ptr, grp->gr_gid);
			}
		}
#endif
#ifdef HAVE_CHROOT
		if (!buffer_string_is_empty(srv->srvconf.changeroot)) {
			tzset();

			if (-1 == chroot(srv->srvconf.changeroot->ptr)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "chroot failed: ", strerror(errno));
				return -1;
			}
			if (-1 == chdir("/")) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "chdir failed: ", strerror(errno));
				return -1;
			}
		}
#endif
#ifdef HAVE_PWD_H
		/* drop root privs */
		if (NULL != pwd) {
			if (-1 == setuid(pwd->pw_uid)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "setuid failed: ", strerror(errno));
				return -1;
			}
		}
#endif
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_DUMPABLE)
		/**
		 * on IRIX 6.5.30 they have prctl() but no DUMPABLE
		 */
		if (srv->srvconf.enable_cores) {
			prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
		}
#endif
	}

	/* set max-conns */
	if (srv->srvconf.max_conns > srv->max_fds/2) {
		/* we can't have more connections than max-fds/2 */
		log_error_write(srv, __FILE__, __LINE__, "sdd", "can't have more connections than fds/2: ", srv->srvconf.max_conns, srv->max_fds);
		srv->max_conns = srv->max_fds/2;
	} else if (srv->srvconf.max_conns) {
		/* otherwise respect the wishes of the user */
		srv->max_conns = srv->srvconf.max_conns;
	} else {
		/* or use the default: we really don't want to hit max-fds */
		srv->max_conns = srv->max_fds/3;
	}

#ifdef HAVE_FORK
	/* network is up, let's daemonize ourself */
	if (0 == srv->srvconf.dont_daemonize && 0 == graceful_restart) {
		parent_pipe_fd = daemonize();
	}
#endif
	graceful_restart = 0;/*(reset here after avoiding further daemonizing)*/
	graceful_shutdown= 0;


#ifdef HAVE_SIGACTION
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
# if defined(SA_SIGINFO)
	last_sighup_info.si_uid = 0,
	last_sighup_info.si_pid = 0;
	last_sigterm_info.si_uid = 0,
	last_sigterm_info.si_pid = 0;
	act.sa_sigaction = sigaction_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
# else
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
# endif
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);

	/* it should be safe to restart syscalls after SIGCHLD */
	act.sa_flags |= SA_RESTART | SA_NOCLDSTOP;
	sigaction(SIGCHLD, &act, NULL);

#elif defined(HAVE_SIGNAL)
	/* ignore the SIGPIPE from sendfile() */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGCHLD,  signal_handler);
	signal(SIGINT,  signal_handler);
	signal(SIGUSR1, signal_handler);
#endif


	srv->gid = getgid();
	srv->uid = getuid();
	srv->pid = getpid();

	/* write pid file */
	if (pid_fd > 2) {
		buffer_copy_int(srv->tmp_buf, srv->pid);
		buffer_append_string_len(srv->tmp_buf, CONST_STR_LEN("\n"));
		if (-1 == write_all(pid_fd, CONST_BUF_LEN(srv->tmp_buf))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "Couldn't write pid file:", strerror(errno));
			close(pid_fd);
			pid_fd = -1;
			return -1;
		}
	} else if (pid_fd < -2) {
		pid_fd = -pid_fd;
	}

	/* Close stderr ASAP in the child process to make sure that nothing
	 * is being written to that fd which may not be valid anymore. */
	if (!srv->srvconf.preflight_check) {
		if (-1 == log_error_open(srv)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "Opening errorlog failed. Going down.");
			return -1;
		}
		log_error_write(srv, __FILE__, __LINE__, "s", "server started (" PACKAGE_DESC ")");
	}

	if (buffer_is_empty(srv->config_storage[0]->server_tag)) {
		buffer_copy_string_len(srv->config_storage[0]->server_tag, CONST_STR_LEN(PACKAGE_DESC));
	}

	if (HANDLER_GO_ON != plugins_call_set_defaults(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Configuration of plugins failed. Going down.");
		return -1;
	}

	/* settings might be enabled during module config set defaults */
	srv->config_storage[0]->high_precision_timestamps = srv->srvconf.high_precision_timestamps;

	/* dump unused config-keys */
	for (i = 0; i < srv->config_context->used; i++) {
		array *config = ((data_config *)srv->config_context->data[i])->value;
		size_t j;

		for (j = 0; config && j < config->used; j++) {
			data_unset *du = config->data[j];

			/* all var.* is known as user defined variable */
			if (strncmp(du->key->ptr, "var.", sizeof("var.") - 1) == 0) {
				continue;
			}

			if (NULL == array_get_element_klen(srv->config_touched, CONST_BUF_LEN(du->key))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"WARNING: unknown config-key:",
						du->key,
						"(ignored)");
			}
		}
	}

	if (srv->config_unsupported) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"Configuration contains unsupported keys. Going down.");
	}

	if (srv->config_deprecated) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"Configuration contains deprecated keys. Going down.");
	}

	if (srv->config_unsupported || srv->config_deprecated) {
		return -1;
	}

	if (srv->srvconf.preflight_check) {
		/*printf("Preflight OK");*//*(stdout reopened to /dev/null)*/
		return 0;
	}


#ifdef HAVE_FORK
	/**
	 * notify daemonize-grandparent of successful startup
	 * do this before any further forking is done (workers)
	 */
	if (0 == srv->srvconf.dont_daemonize && -1 != parent_pipe_fd) {
		if (0 > write(parent_pipe_fd, "", 1)) return -1;
		close(parent_pipe_fd);
	}

	if (idle_limit && srv->srvconf.max_worker) {
		srv->srvconf.max_worker = 0;
		log_error_write(srv, __FILE__, __LINE__, "s",
				"server idle time limit command line option disables server.max-worker config file option.");
	}

	/* start watcher and workers */
	num_childs = srv->srvconf.max_worker;
	if (num_childs > 0) {
		pid_t pids[num_childs];
		pid_t pid;
		const int npids = num_childs;
		int child = 0;
		unsigned int timer = 0;
		for (int n = 0; n < npids; ++n) pids[n] = -1;
		while (!child && !srv_shutdown && !graceful_shutdown) {
			if (num_childs > 0) {
				switch ((pid = fork())) {
				case -1:
					return -1;
				case 0:
					child = 1;
					alarm(0);
					break;
				default:
					num_childs--;
					for (int n = 0; n < npids; ++n) {
						if (-1 == pids[n]) {
							pids[n] = pid;
							break;
						}
					}
					break;
				}
			} else {
				int status;

				if (-1 != (pid = wait(&status))) {
					srv->cur_ts = time(NULL);
					if (plugins_call_handle_waitpid(srv, pid, status) != HANDLER_GO_ON) {
						if (!timer) alarm((timer = 5));
						continue;
					}
					switch (fdevent_reaped_logger_pipe(pid)) {
					  default: break;
					  case -1: if (!timer) alarm((timer = 5));
						   /* fall through */
					  case  1: continue;
					}
					/** 
					 * check if one of our workers went away
					 */
					for (int n = 0; n < npids; ++n) {
						if (pid == pids[n]) {
							pids[n] = -1;
							num_childs++;
							break;
						}
					}
				} else {
					switch (errno) {
					case EINTR:
						srv->cur_ts = time(NULL);
						/**
						 * if we receive a SIGHUP we have to close our logs ourself as we don't 
						 * have the mainloop who can help us here
						 */
						if (handle_sig_hup) {
							handle_sig_hup = 0;

							log_error_cycle(srv);

							/* forward SIGHUP to workers */
							for (int n = 0; n < npids; ++n) {
								if (pids[n] > 0) kill(pids[n], SIGHUP);
							}
						}
						if (handle_sig_alarm) {
							handle_sig_alarm = 0;
							timer = 0;
							plugins_call_handle_trigger(srv);
							fdevent_restart_logger_pipes(srv->cur_ts);
						}
						break;
					default:
						break;
					}
				}
			}
		}

		/**
		 * for the parent this is the exit-point 
		 */
		if (!child) {
			/** 
			 * kill all children too 
			 */
			if (graceful_shutdown || graceful_restart) {
				/* flag to ignore one SIGINT if graceful_restart */
				if (graceful_restart) graceful_restart = 2;
				kill(0, SIGINT);
				server_graceful_state(srv);
			} else if (srv_shutdown) {
				kill(0, SIGTERM);
			}

			return 0;
		}

		/* ignore SIGUSR1 in workers; only parent directs graceful restart */
	      #ifdef HAVE_SIGACTION
		{
			struct sigaction actignore;
			memset(&actignore, 0, sizeof(actignore));
			actignore.sa_handler = SIG_IGN;
			sigaction(SIGUSR1, &actignore, NULL);
		}
	      #elif defined(HAVE_SIGNAL)
			signal(SIGUSR1, SIG_IGN);
	      #endif

		/**
		 * make sure workers do not muck with pid-file
		 */
		if (0 <= pid_fd) {
			close(pid_fd);
			pid_fd = -1;
		}
		buffer_reset(srv->srvconf.pid_file);

		fdevent_clr_logger_pipe_pids();
		srv->pid = getpid();
		li_rand_reseed();
	}
#endif

	if (NULL == (srv->ev = fdevent_init(srv, srv->max_fds + 1, srv->event_handler))) {
		log_error_write(srv, __FILE__, __LINE__,
				"s", "fdevent_init failed");
		return -1;
	}

	/* libev backend overwrites our SIGCHLD handler and calls waitpid on SIGCHLD; we want our own SIGCHLD handling. */
#ifdef HAVE_SIGACTION
	sigaction(SIGCHLD, &act, NULL);
#elif defined(HAVE_SIGNAL)
	signal(SIGCHLD,  signal_handler);
#endif

	/*
	 * kqueue() is called here, select resets its internals,
	 * all server sockets get their handlers
	 *
	 * */
	if (0 != network_register_fdevents(srv)) {
		return -1;
	}

	/* might fail if user is using fam (not gamin) and famd isn't running */
	if (NULL == (srv->stat_cache = stat_cache_init(srv))) {
		log_error_write(srv, __FILE__, __LINE__, "s",
			"stat-cache could not be setup, dieing.");
		return -1;
	}

#ifdef USE_ALARM
	{
		/* setup periodic timer (1 second) */
		struct itimerval interval;
		interval.it_interval.tv_sec = 1;
		interval.it_interval.tv_usec = 0;
		interval.it_value.tv_sec = 1;
		interval.it_value.tv_usec = 0;
		if (setitimer(ITIMER_REAL, &interval, NULL)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "setting timer failed");
			return -1;
		}
	}
#endif


	/* get the current number of FDs */
	{
		int fd = fdevent_open_devnull();
		if (fd >= 0) {
			srv->cur_fds = fd;
			close(fd);
		}
	}

	if (0 != server_sockets_set_nb_cloexec(srv)) {
		return -1;
	}

	if (oneshot_fd && server_oneshot_init(srv, oneshot_fd)) {
		oneshot_fd = -1;
	}

	/* main-loop */
	while (!srv_shutdown) {
		int n;
		size_t ndx;
		time_t min_ts;

		if (handle_sig_hup) {
			handler_t r;

			/* reset notification */
			handle_sig_hup = 0;


			/* cycle logfiles */

			switch(r = plugins_call_handle_sighup(srv)) {
			case HANDLER_GO_ON:
				break;
			default:
				log_error_write(srv, __FILE__, __LINE__, "sd", "sighup-handler return with an error", r);
				break;
			}

			if (-1 == log_error_cycle(srv)) {
				log_error_write(srv, __FILE__, __LINE__, "s", "cycling errorlog failed, dying");

				return -1;
			} else {
#ifdef HAVE_SIGACTION
				log_error_write(srv, __FILE__, __LINE__, "sdsd", 
					"logfiles cycled UID =",
					last_sighup_info.si_uid,
					"PID =",
					last_sighup_info.si_pid);
#else
				log_error_write(srv, __FILE__, __LINE__, "s", 
					"logfiles cycled");
#endif
			}
		}

		if (handle_sig_alarm) {
			/* a new second */

#ifdef USE_ALARM
			/* reset notification */
			handle_sig_alarm = 0;
#endif

			/* get current time */
			min_ts = time(NULL);

			if (min_ts != srv->cur_ts) {
#ifdef DEBUG_CONNECTION_STATES
				int cs = 0;
#endif
				connections *conns = srv->conns;
				handler_t r;

				switch(r = plugins_call_handle_trigger(srv)) {
				case HANDLER_GO_ON:
					break;
				case HANDLER_ERROR:
					log_error_write(srv, __FILE__, __LINE__, "s", "one of the triggers failed");
					break;
				default:
					log_error_write(srv, __FILE__, __LINE__, "d", r);
					break;
				}

				srv->cur_ts = min_ts;

				/* check idle time limit, if enabled */
				if (idle_limit && idle_limit < min_ts - last_active_ts && !graceful_shutdown) {
					log_error_write(srv, __FILE__, __LINE__, "sDs", "[note] idle timeout", (int)idle_limit,
							"s exceeded, initiating graceful shutdown");
					graceful_shutdown = 2; /* value 2 indicates idle timeout */
					if (graceful_restart) {
						graceful_restart = 0;
						if (pid_fd < -2) pid_fd = -pid_fd;
						server_sockets_close(srv);
					}
				}

			      #ifdef HAVE_GETLOADAVG
				/* refresh loadavg data every 30 seconds */
				if (srv->srvconf.loadts + 30 < min_ts) {
					if (-1 != getloadavg(srv->srvconf.loadavg, 3)) {
						srv->srvconf.loadts = min_ts;
					}
				}
			      #endif

				/* cleanup stat-cache */
				stat_cache_trigger_cleanup(srv);
				/* reset global/aggregate rate limit counters */
				for (i = 0; i < srv->config_context->used; ++i) {
					srv->config_storage[i]->global_bytes_per_second_cnt = 0;
				}
				/* if graceful_shutdown, accelerate cleanup of recently completed request/responses */
				if (graceful_shutdown && !srv_shutdown) server_graceful_shutdown_maint(srv);
				/**
				 * check all connections for timeouts
				 *
				 */
				for (ndx = 0; ndx < conns->used; ndx++) {
					connection * const con = conns->ptr[ndx];
					const int waitevents = fdevent_event_get_interest(srv->ev, con->fd);
					int changed = 0;
					int t_diff;

					if (con->state == CON_STATE_CLOSE) {
						if (srv->cur_ts - con->close_timeout_ts > HTTP_LINGER_TIMEOUT) {
							changed = 1;
						}
					} else if (waitevents & FDEVENT_IN) {
						if (con->request_count == 1 || con->state != CON_STATE_READ) { /* e.g. CON_STATE_READ_POST || CON_STATE_WRITE */
							if (srv->cur_ts - con->read_idle_ts > con->conf.max_read_idle) {
								/* time - out */
								if (con->conf.log_request_handling) {
									log_error_write(srv, __FILE__, __LINE__, "sd",
										"connection closed - read timeout:", con->fd);
								}

								connection_set_state(srv, con, CON_STATE_ERROR);
								changed = 1;
							}
						} else {
							if (srv->cur_ts - con->read_idle_ts > con->keep_alive_idle) {
								/* time - out */
								if (con->conf.log_request_handling) {
									log_error_write(srv, __FILE__, __LINE__, "sd",
										"connection closed - keep-alive timeout:", con->fd);
								}

								connection_set_state(srv, con, CON_STATE_ERROR);
								changed = 1;
							}
						}
					}

					/* max_write_idle timeout currently functions as backend timeout,
					 * too, after response has been started.
					 * future: have separate backend timeout, and then change this
					 * to check for write interest before checking for timeout */
					/*if (waitevents & FDEVENT_OUT)*/
					if ((con->state == CON_STATE_WRITE) &&
					    (con->write_request_ts != 0)) {
#if 0
						if (srv->cur_ts - con->write_request_ts > 60) {
							log_error_write(srv, __FILE__, __LINE__, "sdd",
									"connection closed - pre-write-request-timeout:", con->fd, srv->cur_ts - con->write_request_ts);
						}
#endif

						if (srv->cur_ts - con->write_request_ts > con->conf.max_write_idle) {
							/* time - out */
							if (con->conf.log_timeouts) {
								log_error_write(srv, __FILE__, __LINE__, "sbsbsosds",
									"NOTE: a request from",
									con->dst_addr_buf,
									"for",
									con->request.uri,
									"timed out after writing",
									con->bytes_written,
									"bytes. We waited",
									(int)con->conf.max_write_idle,
									"seconds. If this a problem increase server.max-write-idle");
							}
							connection_set_state(srv, con, CON_STATE_ERROR);
							changed = 1;
						}
					}

					/* we don't like div by zero */
					if (0 == (t_diff = srv->cur_ts - con->connection_start)) t_diff = 1;

					if (con->traffic_limit_reached &&
					    (con->conf.kbytes_per_second == 0 ||
					     ((con->bytes_written / t_diff) < con->conf.kbytes_per_second * 1024))) {
						/* enable connection again */
						con->traffic_limit_reached = 0;

						changed = 1;
					}

					con->bytes_written_cur_second = 0;

					if (changed) {
						connection_state_machine(srv, con);
					}

#if DEBUG_CONNECTION_STATES
					if (cs == 0) {
						fprintf(stderr, "connection-state: ");
						cs = 1;
					}

					fprintf(stderr, "c[%d,%d]: %s ",
						con->fd,
						con->fcgi.fd,
						connection_get_state(con->state));
#endif
				}

#ifdef DEBUG_CONNECTION_STATES
				if (cs == 1) fprintf(stderr, "\n");
#endif
			}
		}

		if (handle_sig_child) {
			pid_t pid;
			handle_sig_child = 0;
			do {
				int status;
				pid = waitpid(-1, &status, WNOHANG);
				if (pid > 0) {
					if (plugins_call_handle_waitpid(srv, pid, status) != HANDLER_GO_ON) {
						continue;
					}
					if (0 == srv->srvconf.max_worker) {
						/* check piped-loggers and restart, even if shutting down */
						if (fdevent_waitpid_logger_pipe_pid(pid, srv->cur_ts)) {
							continue;
						}
					}
				}
			} while (pid > 0 || (-1 == pid && errno == EINTR));
		}

		if (graceful_shutdown) {
			server_graceful_state(srv);
			srv->sockets_disabled = 1;
		} else if (srv->sockets_disabled) {
			/* our server sockets are disabled, why ? */

			if ((srv->cur_fds + srv->want_fds < srv->max_fds * 8 / 10) && /* we have enough unused fds */
			    (srv->conns->used <= srv->max_conns * 9 / 10)) {
				server_sockets_set_event(srv, FDEVENT_IN);
				log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets enabled again");

				srv->sockets_disabled = 0;
			}
		} else {
			if ((srv->cur_fds + srv->want_fds > srv->max_fds * 9 / 10) || /* out of fds */
			    (srv->conns->used >= srv->max_conns)) { /* out of connections */
				/* disable server-fds */
				server_sockets_set_event(srv, 0);

				if (srv->conns->used >= srv->max_conns) {
					log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets disabled, connection limit reached");
				} else {
					log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets disabled, out-of-fds");
				}

				srv->sockets_disabled = 1;
			}
		}

		if (graceful_shutdown && srv->conns->used == 0) {
			/* we are in graceful shutdown phase and all connections are closed
			 * we are ready to terminate without harming anyone */
			srv_shutdown = 1;
			break;
		}

		/* we still have some fds to share */
		if (srv->want_fds) {
			/* check the fdwaitqueue for waiting fds */
			int free_fds = srv->max_fds - srv->cur_fds - 16;
			connection *con;

			for (; free_fds > 0 && NULL != (con = fdwaitqueue_unshift(srv, srv->fdwaitqueue)); free_fds--) {
				connection_state_machine(srv, con);

				srv->want_fds--;
			}
		}

		if ((n = fdevent_poll(srv->ev, 1000)) > 0) {
			/* n is the number of events */
			int fd;
			int revents;
			int fd_ndx;
			last_active_ts = srv->cur_ts;
			fd_ndx = -1;
			do {
				fdevent_handler handler;
				void *context;

				fd_ndx  = fdevent_event_next_fdndx (srv->ev, fd_ndx);
				if (-1 == fd_ndx) break; /* not all fdevent handlers know how many fds got an event */

				revents = fdevent_event_get_revent (srv->ev, fd_ndx);
				fd      = fdevent_event_get_fd     (srv->ev, fd_ndx);
				handler = fdevent_get_handler(srv->ev, fd);
				context = fdevent_get_context(srv->ev, fd);
				if (NULL != handler) {
					(*handler)(srv, context, revents);
				}
			} while (--n > 0);
		} else if (n < 0 && errno != EINTR) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"fdevent_poll failed:",
					strerror(errno));
		}

		if (n >= 0) fdevent_sched_run(srv, srv->ev);

		for (ndx = 0; ndx < srv->joblist->used; ndx++) {
			connection *con = srv->joblist->ptr[ndx];
			connection_state_machine(srv, con);
		}

		srv->joblist->used = 0;
	}

	if (graceful_shutdown || graceful_restart) {
		server_graceful_state(srv);
	}

	if (2 == graceful_shutdown) { /* value 2 indicates idle timeout */
		log_error_write(srv, __FILE__, __LINE__, "s",
				"server stopped after idle timeout");
	} else {
#ifdef HAVE_SIGACTION
		log_error_write(srv, __FILE__, __LINE__, "sdsd",
				"server stopped by UID =",
				last_sigterm_info.si_uid,
				"PID =",
				last_sigterm_info.si_pid);
#else
		log_error_write(srv, __FILE__, __LINE__, "s",
				"server stopped");
#endif
	}

	return 0;
}

int main (int argc, char **argv) {
    int rc;

  #ifdef HAVE_GETUID
  #ifndef HAVE_ISSETUGID
  #define issetugid() (geteuid() != getuid() || getegid() != getgid())
  #endif
    if (0 != getuid() && issetugid()) { /*check as early as possible in main()*/
        fprintf(stderr,
                "Are you nuts ? Don't apply a SUID bit to this binary\n");
        return -1;
    }
  #endif

    /* for nice %b handling in strftime() */
    setlocale(LC_TIME, "C");

    do {
        server * const srv = server_init();

        if (graceful_restart) {
            server_sockets_restore(srv);
            optind = 1;
        }

        rc = server_main(srv, argc, argv);

        /* clean-up */
        remove_pid_file(srv);
        log_error_close(srv);
        fdevent_close_logger_pipes();
        if (graceful_restart)
            server_sockets_save(srv);
        else
            network_close(srv);
        connections_free(srv);
        plugins_free(srv);
        server_free(srv);

        if (0 != rc || !graceful_restart) break;

        /* wait for all children to exit before graceful restart */
        while (waitpid(-1, NULL, 0) > 0) ;
    } while (graceful_restart);

    return rc;
}
