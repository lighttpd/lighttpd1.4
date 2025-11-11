#include "first.h"

#include "base.h"
#include "buffer.h"
#include "network.h"
#include "log.h"
#include "rand.h"
#include "chunk.h"
#include "http_range.h"     /* http_range_config_allow_http10() */
#include "fdevent.h"
#include "fdlog.h"
#include "connections.h"
#include "sock_addr.h"
#include "stat_cache.h"
#include "plugin.h"
#include "plugins.h"
#include "plugin_config.h"
#include "network_write.h"  /* network_write_show_handlers() */
#include "reqpool.h"        /* request_pool_init() request_pool_free() */
#include "response.h"       /* http_dispatch[] strftime_cache_reset() */
                            /* http_response_fn_init() */

#ifdef HAVE_VERSIONSTAMP_H
# include "versionstamp.h"
#else
# define REPO_VERSION ""
#endif

#define PACKAGE_DESC PACKAGE_NAME "/" PACKAGE_VERSION REPO_VERSION
static const buffer default_server_tag =
  { PACKAGE_DESC "\0server", sizeof(PACKAGE_DESC), 0 };

#include <sys/types.h>
#include "sys-setjmp.h"
#include "sys-stat.h"
#include "sys-time.h"
#include "sys-unistd.h" /* <unistd.h> */

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <locale.h>
#ifdef _WIN32
#include <mbctype.h>    /* _setmbcp() */
#endif

#include <stdio.h>

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#else
/* basic (very limited) getopt() implementation */
extern char *optarg;
extern int optind, opterr, optopt;
char *optarg = NULL;
int optind = 1, opterr = 1, optopt = 0;
int getopt (int argc, char * const argv[], const char *optstring);
int getopt (int argc, char * const argv[], const char *optstring)
{
    static char *nextchar;
    optarg = NULL;
    if (optind >= argc || argc < 1)
        return -1;
    if (optind <= 1)
        nextchar = argv[(optind = 1)];
    else if (nextchar == NULL)
        nextchar = argv[optind];

    if (nextchar == argv[optind]) {
        if (*nextchar++ != '-'
            || nextchar[0] == '\0' /* "-" */
            || (nextchar[0] == '-' && nextchar[1] == '\0')) { /* "--" */
            return -1;
        }
        ++optind;
    }

    const char *o = optstring;
    if (*o == '+' || *o == '-') ++o; /*(ignore; behave as if '+' is set)*/
    if (*o == ':') ++o;              /*(ignore; behave as if ':' is set)*/
    for (; *o; ++o) {
        if (*o == *nextchar)
            break;
        if (o[1] == ':') ++o;
        if (o[1] == ':') ++o;
    }
    if (!*o) {
        /* if (opterr) fprintf(stderr, "..."); */
        optopt = *nextchar;
        return '?';
    }

    if (!*++nextchar)
        nextchar = NULL;

    if (o[1] == ':') {
        if (nextchar) {
            optarg = nextchar;
            nextchar = NULL;
        }
        else if (optind < argc)
            optarg = argv[optind++];
        else if (o[2] != ':') {
            /* if (opterr) fprintf(stderr, "..."); */
              /*(fprintf if ':' not at beginning of optstring)*/
            optopt = *o;
            return ':';
        }
    }

    return *o;
}
#endif

#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif

#ifdef HAVE_PWD_H
# include <grp.h>
# include <pwd.h>
#endif

#ifdef HAVE_SYS_LOADAVG_H
# include <sys/loadavg.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif
#ifdef HAVE_SYS_PROCCTL_H
# include <sys/procctl.h>
#endif
#ifdef HAVE_PRIV_H
# include <priv.h>
#endif

#ifdef HAVE_MALLOC_H
#ifndef LIGHTTPD_STATIC
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#endif
#include <malloc.h>
#if defined(HAVE_MALLOC_TRIM)
static int(*malloc_trim_fn)(size_t);
static size_t malloc_top_pad;
#endif
#endif

#include "sys-crypto.h"
#if defined(USE_OPENSSL_CRYPTO) \
 || defined(USE_MBEDTLS_CRYPTO) \
 || defined(USE_NSS_CRYPTO) \
 || defined(USE_GNUTLS_CRYPTO) \
 || defined(USE_WOLFTLS_CRYPTO)
#define TEXT_SSL " (ssl)"
#else
#define TEXT_SSL
#endif

#ifdef _WIN32
/* (Note: assume overwrite == 1 in this setenv() replacement) */
/*#define setenv(name,value,overwrite)  SetEnvironmentVariable((name),(value))*/
/*#define unsetenv(name)                SetEnvironmentVariable((name),NULL)*/
#define setenv(name,value,overwrite)  _putenv_s((name), strdup(value))
#define unsetenv(name)                _putenv_s((name), "")
#endif

#include "h1.h"
static const struct http_dispatch h1_1_dispatch_table = {
  .send_1xx          = h1_send_1xx
};

static int oneshot_fd = 0;
static int oneshot_fdout = -1;
static fdnode *oneshot_fdn = NULL;
static int (*oneshot_read_cq)(connection *con, chunkqueue *cq, off_t max_bytes);
static volatile int pid_fd = -2;
static server_socket_array graceful_sockets;
static server_socket_array inherited_sockets;
static volatile sig_atomic_t graceful_restart = 0;
static volatile sig_atomic_t graceful_shutdown = 0;
static volatile sig_atomic_t srv_shutdown = 0;
static volatile sig_atomic_t handle_sig_child = 0;
static volatile sig_atomic_t handle_sig_alarm = 1;
static volatile sig_atomic_t handle_sig_hup = 0;
static int idle_limit = 0;

__attribute_cold__
int server_main (int argc, char ** argv);

#ifdef _WIN32
#ifndef SIGBREAK
#define SIGBREAK 21
#endif
/* Ctrl-BREAK (repurposed and treated as SIGUSR1)*/
#ifndef SIGUSR1
#define SIGUSR1 SIGBREAK
#endif
#include "server_win32.c"
#endif

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
  #ifndef _WIN32
	case SIGALRM: handle_sig_alarm = 1; break;
	case SIGHUP:  handle_sig_hup = 1; break;
	case SIGCHLD: handle_sig_child = 1; break;
  #endif
	}
}
#endif

#if defined(HAVE_SIGNAL)
#ifdef _WIN32
static BOOL WINAPI ConsoleCtrlHandler(DWORD dwType)
{
    /* Note: Windows handles "signals" inconsistently, varying depending on
     * whether or not the program is attached to a non-hidden window.
     * CTRL_CLOSE_EVENT sent by taskkill can be received if attached to a
     * non-hidden window, but taskkill /f must be used (and CTRL_CLOSE_EVENT
     * is not received here) if process is not attached to a window, or if
     * the window is hidden. (WTH MS?!)  This *does not* catch CTRL_CLOSE_EVENT:
     *   start -FilePath .\lighttpd.exe -ArgumentList "-D -f lighttpd.conf"
     *     -WindowStyle Hidden   # (or None)
     * but any other -WindowStyle can catch CTRL_CLOSE_EVENT.
     * CTRL_C_EVENT can only be sent to 0 (self process group) or self pid
     * and is ignored by default (sending signal does not indicate failure)
     * in numerous other cases.  Some people have resorted to standalone helper
     * programs to attempt AttachConsole() to a target pid before sending
     * CTRL_C_EVENT via GenerateConsoleCtrlEvent().  Another alternative is
     * running lighttpd as a Windows service, which uses a different mechanism,
     * also more limited than unix signals.  Other alternatives include
     * NSSM (Non-Sucking Service Manager) or cygwin's cygrunsrv program */
    switch(dwType) {
      case CTRL_C_EVENT:
        signal_handler(SIGINT);
        break;
      case CTRL_BREAK_EVENT:
        /* Ctrl-BREAK (repurposed and treated as SIGUSR1)*/
        signal_handler(SIGUSR1);
        break;
      case CTRL_CLOSE_EVENT:/* sent by taskkill */
      case CTRL_LOGOFF_EVENT:
      case CTRL_SHUTDOWN_EVENT:
        /* non-cancellable event; program terminates soon after return */
        signal_handler(SIGTERM);/* trigger server shutdown in main thread */
        Sleep(2000);            /* sleep 2 secs to give threads chance to exit*/
        return FALSE;
    }
    return TRUE;
}
#endif
#endif

static void server_main_setup_signals (void) {
  #ifdef HAVE_SIGACTION
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);

    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

   #ifndef _MSC_VER
    act.sa_flags = SA_NODEFER;
    act.sa_handler = sys_setjmp_sigbus;
    sigaction(SIGBUS, &act, NULL);
    act.sa_flags = 0;
   #endif

   #if defined(SA_SIGINFO)
    last_sighup_info.si_uid = 0,
    last_sighup_info.si_pid = 0;
    last_sigterm_info.si_uid = 0,
    last_sigterm_info.si_pid = 0;
    act.sa_sigaction = sigaction_handler;
    act.sa_flags = SA_SIGINFO;
   #else
    act.sa_handler = signal_handler;
    act.sa_flags = 0;
   #endif
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);

   #ifdef __QNX__
      /*
       * In QNX SDP 7.1 SA_RESTART is not supported
       */
      #ifndef SA_RESTART
         #define SA_RESTART 0
      #endif
   #endif /* __QNX__ */

    /* it should be safe to restart syscalls after SIGCHLD */
    act.sa_flags |= SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &act, NULL);
  #elif defined(HAVE_SIGNAL)
   #ifndef _WIN32
    /* ignore the SIGPIPE from sendfile() */
    signal(SIGPIPE, SIG_IGN);
   #endif
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
   #ifndef _WIN32
    signal(SIGHUP,  signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGCHLD, signal_handler);
   #else
    /* Ctrl-BREAK (repurposed and treated as SIGUSR1)*/
    signal(SIGUSR1, signal_handler);
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleCtrlHandler,TRUE);
   #endif
   #ifndef _MSC_VER
    signal(SIGBUS,  sys_setjmp_sigbus);
   #endif
  #endif
}

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

	if (fdevent_pipe_cloexec(pipefd, 64) < 0) exit(-1);

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

	return pipefd[1];
}
#endif

static int clockid_mono_coarse = 0;

static unix_time64_t
server_monotonic_secs (void)
{
  #ifdef _MSC_VER
    return (unix_time64_t)(GetTickCount64() / 1000);
  #else
    unix_timespec64_t ts;
    return (0 == log_clock_gettime(clockid_mono_coarse, &ts))
      ? ts.tv_sec
      : log_monotonic_secs;
  #endif
}

static unix_time64_t
server_epoch_secs (server * const srv, unix_time64_t mono_ts_delta)
{
    const unix_time64_t cur_ts = log_epoch_secs;
    const unix_time64_t new_ts = TIME64_CAST(time(NULL));
    const unix_time64_t new_ts_adj = new_ts - mono_ts_delta;
    /* attempt to detect large clock jump */
    if (new_ts_adj < cur_ts || new_ts_adj - cur_ts > 300) { /*(5 mins)*/
        log_warn(srv->errh, __FILE__, __LINE__,
          "warning: clock jumped %lld secs",
          (long long)((int64_t)new_ts_adj - (int64_t)cur_ts));

        /* graceful restart not available if chroot'ed */
        if (srv->srvconf.changeroot)
            return new_ts;

        int delta =                             /*(30 mins default)*/
          config_feature_int(srv, "server.clock-jump-restart", 1800);
        if (delta && (new_ts_adj > cur_ts
                      ? new_ts_adj-cur_ts
                      : cur_ts-new_ts_adj) > (unix_time64_t)delta) {
            log_error(srv->errh, __FILE__, __LINE__,
              "clock jumped; "
              "attempting graceful restart in < ~5 seconds, else hard restart");
            srv->graceful_expire_ts = log_monotonic_secs + 5;
            raise(SIGUSR1);
        }
    }
    return new_ts;
}

__attribute_cold__
__attribute_noinline__
__attribute_returns_nonnull__
static server *server_init(void) {
	server *srv = ck_calloc(1, sizeof(*srv));

	srv->tmp_buf = buffer_init();

	strftime_cache_reset();

	li_rand_reseed();

	srv->startup_ts = log_epoch_secs = TIME64_CAST(time(NULL));
  #ifdef HAVE_CLOCK_GETTIME
	unix_timespec64_t ts;
	UNUSED(&ts);
   #ifdef CLOCK_MONOTONIC_COARSE
	if (0 == log_clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
		clockid_mono_coarse = CLOCK_MONOTONIC_COARSE;
	else
   #endif
   #ifdef CLOCK_MONOTONIC_RAW_APPROX
	if (0 == log_clock_gettime(CLOCK_MONOTONIC_RAW_APPROX, &ts))
		clockid_mono_coarse = CLOCK_MONOTONIC_RAW_APPROX;
	else
   #endif
   #ifdef CLOCK_MONOTONIC_RAW
	if (0 == log_clock_gettime(CLOCK_MONOTONIC_RAW, &ts))
		clockid_mono_coarse = CLOCK_MONOTONIC_RAW;
	else
   #endif
		clockid_mono_coarse = CLOCK_MONOTONIC;
  #endif
	log_monotonic_secs = server_monotonic_secs();

	srv->errh = log_set_global_errh(NULL, 0);

	config_init(srv);

	srv->request_env = plugins_call_handle_request_env;
	srv->plugins_request_reset = plugins_call_handle_request_reset;

	srv->loadavg[0] = 0.0;
	srv->loadavg[1] = 0.0;
	srv->loadavg[2] = 0.0;
	srv->stdin_fd = -1;
	srv->default_server_tag = &default_server_tag;

	log_con_jqueue = (connection *)(uintptr_t)&log_con_jqueue;/*(sentinel)*/
	memset(http_dispatch, 0, sizeof(http_dispatch));

	return srv;
}

__attribute_cold__
__attribute_noinline__
static void server_free(server *srv) {
	if (oneshot_fd > 0) {
		if (oneshot_fdn) {
			fdevent_fdnode_event_del(srv->ev, oneshot_fdn);
			fdevent_unregister(srv->ev, oneshot_fdn);
			oneshot_fdn = NULL;
		}
		if (oneshot_fdout >= 0)
			fdio_close_pipe(oneshot_fd);
		else
			fdio_close_socket(oneshot_fd);
	}
	if (oneshot_fdout >= 0) {
		fdio_close_pipe(oneshot_fdout);
	}
	if (srv->stdin_fd >= 0) {
		fdio_close_socket(srv->stdin_fd);
	}

	buffer_free(srv->tmp_buf);

	fdevent_free(srv->ev);

	config_free(srv);

	stat_cache_free();

	li_rand_cleanup();
	chunkqueue_chunk_pool_free();

	if (srv->errh != log_set_global_errh(NULL, 0))
		fdlog_free(srv->errh);
	free(srv);
}

__attribute_cold__
__attribute_noinline__
static void server_pid_file_remove(server *srv) {
	if (pid_fd <= -2) return;
	if (srv->srvconf.pid_file && 0 <= pid_fd) {
		if (0 != ftruncate(pid_fd, 0)) {
			log_perror(srv->errh, __FILE__, __LINE__,
			  "ftruncate failed for: %s", srv->srvconf.pid_file->ptr);
		}
	}
	if (0 <= pid_fd) {
		close(pid_fd);
		pid_fd = -1;
	}
	if (srv->srvconf.pid_file && !srv->srvconf.changeroot) {
		if (0 != unlink(srv->srvconf.pid_file->ptr)) {
			if (errno != EACCES && errno != EPERM) {
				log_perror(srv->errh, __FILE__, __LINE__,
				  "unlink failed for: %s", srv->srvconf.pid_file->ptr);
			}
		}
	}
}

__attribute_cold__
static int server_pid_file_open(server * const srv, int i_am_root) {
    if (NULL == srv->srvconf.pid_file)
        return 0;
    const char * const pidfile = srv->srvconf.pid_file->ptr;

    pid_fd = fdevent_open_cloexec(pidfile, 0, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
                                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (-1 != pid_fd)
        return 0;

  #ifdef __linux__
    if (errno == EACCES
        && i_am_root && srv->srvconf.username && !srv->srvconf.changeroot)
        /* root without CAP_DAC_OVERRIDE capability
         * and pidfile owned by target user */
        return 0;
  #else
    UNUSED(i_am_root);
  #endif

    struct stat st;
    if (errno != EEXIST
        || 0 != stat(pidfile, &st)
        || !S_ISREG(st.st_mode)
        || (pid_fd =
              fdevent_open_cloexec(pidfile, 0,
                                   O_WRONLY | O_CREAT | O_TRUNC,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))==-1){
        log_perror(srv->errh, __FILE__, __LINE__,
          "opening pid-file failed: %s", pidfile);
        return -1;
    }

    return 0;
}


__attribute_cold__
static server_socket * server_oneshot_getsock(server *srv, sock_addr *cnt_addr) {
	server_socket *srv_socket, *srv_socket_wild = NULL;
	for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
		srv_socket = srv->srv_sockets.ptr[i];
		if (!sock_addr_is_port_eq(&srv_socket->addr,cnt_addr)) continue;
		if (sock_addr_is_addr_eq(&srv_socket->addr,cnt_addr)) return srv_socket;

		if (NULL != srv_socket_wild) continue;
		if (sock_addr_is_addr_wildcard(&srv_socket->addr)) {
			srv_socket_wild = srv_socket;
		}
	}

	if (NULL != srv_socket_wild) {
		return srv_socket_wild;
	} else if (srv->srv_sockets.used) {
		return srv->srv_sockets.ptr[0];
	} else {
		log_error(srv->errh, __FILE__, __LINE__, "no sockets configured");
		return NULL;
	}
}


static int server_oneshot_read_cq(connection *con, chunkqueue *cq, off_t max_bytes) {
    /* temporary set con->fd to oneshot_fd (fd input) rather than outshot_fdout
     * (lighttpd generally assumes operation on sockets, so this is a kludge) */
    int fd = con->fd;
    con->fd = oneshot_fdn->fd;
    int rc = oneshot_read_cq(con, cq, max_bytes);
    con->fd = fd;

    /* note: optimistic reads (elsewhere) may or may not be enough to re-enable
     * read interest after FDEVENT_IN interest was paused for other reasons */

    const int events = fdevent_fdnode_interest(oneshot_fdn);
    int n = con->is_readable > 0 ? 0 : FDEVENT_IN;
    if (events & FDEVENT_RDHUP)
        n |= FDEVENT_RDHUP;
    fdevent_fdnode_event_set(con->srv->ev, oneshot_fdn, n);
    return rc;
}


static handler_t server_oneshot_handle_fdevent(void *context, int revents) {
    connection *con = context;

    /* note: not sync'd with con->fdn or connection_set_fdevent_interest() */
    int rdhup = 0;
    int n = fdevent_fdnode_interest(oneshot_fdn);
    if (revents & FDEVENT_IN)
        n &= ~FDEVENT_IN;
    request_st * const r = &con->request;
    if (r->state != CON_STATE_ERROR && (revents & (FDEVENT_HUP|FDEVENT_RDHUP))){
        revents &= ~(FDEVENT_HUP|FDEVENT_RDHUP);
        /* copied and modified from connection_handle_fdevent()
         * fdevent_is_tcp_half_closed() will fail on pipe
         * and, besides, read end of pipes should treat POLLHUP as POLLRDHUP */
        n &= ~(FDEVENT_IN|FDEVENT_RDHUP);
        rdhup = 1;
    }
    fdevent_fdnode_event_set(con->srv->ev, oneshot_fdn, n);

    fdnode * const fdn = con->fdn; /* fdn->ctx == con */
    handler_t rc = (fdn && (fdevent_handler)NULL != fdn->handler)
      ? (*fdn->handler)(con, revents)
      : HANDLER_FINISHED;

    if (rdhup) {
        r->conf.stream_request_body &=
          ~(FDEVENT_STREAM_REQUEST_BUFMIN|FDEVENT_STREAM_REQUEST_POLLIN);
        r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLRDHUP;
        r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_TCP_FIN;
        con->is_readable = 1; /*(can read 0 for end-of-stream)*/
        if (chunkqueue_is_empty(con->read_queue)) r->keep_alive = 0;
        if (r->reqbody_length < -1) /*(transparent proxy mode; no more data)*/
            r->reqbody_length = r->reqbody_queue.bytes_in;
    }

    return rc;
}


__attribute_cold__
static int server_oneshot_init_pipe(server *srv, int fdin, int fdout) {
    /* Note: attempt to work with netcat pipes though other code expects socket.
     * netcat has different fds (pipes) for stdin and stdout.  To support
     * netcat, need to avoid S_ISSOCK(), getsockname(), and getpeername(),
     * reconstructing addresses from environment variables:
     *   NCAT_LOCAL_ADDR   NCAT_LOCAL_PORT
     *   NCAT_REMOTE_ADDR  NCAT_REMOTE_PORT
     *   NCAT_PROTO (TCP, UDP, SCTP)
     */
    connection *con;
    const server_socket *srv_socket;
    sock_addr cnt_addr;

    /* detect if called from netcat or else fabricate localhost addrs */
    const char * const ncat =
             getenv("NCAT_LOCAL_ADDR");
    const char * const ncat_local_addr  =
      ncat ? ncat                       : "127.0.0.1"; /*(fabricated)*/
    const char * const ncat_local_port  =
      ncat ? getenv("NCAT_LOCAL_PORT")  : "80";        /*(fabricated)*/
    const char * const ncat_remote_addr =
      ncat ? getenv("NCAT_REMOTE_ADDR") : "127.0.0.1"; /*(fabricated)*/
    const char * const ncat_remote_port =
      ncat ? getenv("NCAT_REMOTE_PORT") : "48080";     /*(fabricated)*/
    if (NULL == ncat_local_addr  || NULL == ncat_local_port)  return 0;
    if (NULL == ncat_remote_addr || NULL == ncat_remote_port) return 0;

    const int family = ncat && strchr(ncat_local_addr,':') ? AF_INET6 : AF_INET;
    unsigned short port;

    port = (unsigned short)strtol(ncat_local_port, NULL, 10);
    if (1 != sock_addr_inet_pton(&cnt_addr, ncat_local_addr, family, port)) {
        log_error(srv->errh, __FILE__, __LINE__, "invalid local addr");
        return 0;
    }

    srv_socket = server_oneshot_getsock(srv, &cnt_addr);
    if (NULL == srv_socket) return 0;

    port = (unsigned short)strtol(ncat_remote_port, NULL, 10);
    if (1 != sock_addr_inet_pton(&cnt_addr, ncat_remote_addr, family, port)) {
        log_error(srv->errh, __FILE__, __LINE__, "invalid remote addr");
        return 0;
    }

    /*(must set flags; fd did not pass through fdevent accept() logic)*/
    if (-1 == fdevent_fcntl_set_nb_cloexec(fdin)) {
        log_perror(srv->errh, __FILE__, __LINE__, "fcntl()");
        return 0;
    }
    if (-1 == fdevent_fcntl_set_nb_cloexec(fdout)) {
        log_perror(srv->errh, __FILE__, __LINE__, "fcntl()");
        return 0;
    }

    con = connection_accepted(srv, srv_socket, &cnt_addr, fdout);
    if (NULL == con) return 0;

    /* note: existing routines assume socket, not pipe
     * connections.c:connection_read_cq()
     *   uses recv() ifdef _WIN32
     *   passes S_IFSOCK to fdevent_ioctl_fionread()
     *   (The routine could be copied and modified, if required)
     * This is unlikely to work if TLS is used over pipe since the SSL_CTX
     * is associated with the other end of the pipe.  However, if using
     * pipes, using TLS is unexpected behavior.
     */

    /*assert(oneshot_fd == fdin);*/
    oneshot_read_cq = con->network_read;
    con->network_read = server_oneshot_read_cq;
    oneshot_fdn =
      fdevent_register(srv->ev, fdin, server_oneshot_handle_fdevent, con);
    fdevent_fdnode_event_set(srv->ev, oneshot_fdn, FDEVENT_RDHUP);

    connection_state_machine(con);
    return 1;
}


__attribute_cold__
static int server_oneshot_init(server *srv, int fd) {
	connection *con;
	const server_socket *srv_socket;
	sock_addr cnt_addr;
	socklen_t cnt_len;

	cnt_len = sizeof(cnt_addr);
	if (0 != getsockname(fd, (struct sockaddr *)&cnt_addr, &cnt_len)) {
		log_perror(srv->errh, __FILE__, __LINE__, "getsockname()");
		return 0;
	}

	srv_socket = server_oneshot_getsock(srv, &cnt_addr);
	if (NULL == srv_socket) return 0;

      #ifdef __clang_analyzer__
        memset(&cnt_addr, 0, sizeof(cnt_addr));
      #endif
	cnt_len = sizeof(cnt_addr);
	if (0 != getpeername(fd, (struct sockaddr *)&cnt_addr, &cnt_len)) {
		log_perror(srv->errh, __FILE__, __LINE__, "getpeername()");
		return 0;
	}

	/*(must set flags; fd did not pass through fdevent accept() logic)*/
	if (-1 == fdevent_socket_set_nb_cloexec(fd)) {
		log_perror(srv->errh, __FILE__, __LINE__, "fcntl()");
		return 0;
	}

	if (sock_addr_get_family(&cnt_addr) != AF_UNIX) {
		network_accept_tcp_nagle_disable(fd);
	}

	con = connection_accepted(srv, srv_socket, &cnt_addr, fd);
	if (NULL == con) return 0;

	connection_state_machine(con);
	return 1;
}


__attribute_cold__
static void show_version (void) {
	char *b = PACKAGE_DESC TEXT_SSL \
" - a light and fast webserver\n"
#ifdef NONREPRODUCIBLE_BUILD
"Build-Date: " __DATE__ " " __TIME__ "\n";
#endif
;
	write_all(STDOUT_FILENO, b, strlen(b));
}

__attribute_cold__
static void show_features (void) {
  static const char features[] =
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
#if defined HAVE_ZSTD_H && defined HAVE_ZSTD
      "\t+ zstd support\n"
#else
      "\t- zstd support\n"
#endif
#if defined HAVE_BZLIB_H && defined HAVE_LIBBZ2
      "\t+ bzip2 support\n"
#else
      "\t- bzip2 support\n"
#endif
#if defined HAVE_BROTLI_ENCODE_H && defined HAVE_BROTLI
      "\t+ brotli support\n"
#else
      "\t- brotli support\n"
#endif
#if defined(HAVE_CRYPT) || defined(HAVE_CRYPT_R)
      "\t+ crypt support\n"
#else
      "\t- crypt support\n"
#endif
#ifdef USE_OPENSSL_CRYPTO
      "\t+ OpenSSL support\n"
#else
      "\t- OpenSSL support\n"
#endif
#ifdef USE_MBEDTLS_CRYPTO
      "\t+ mbedTLS support\n"
#else
      "\t- mbedTLS support\n"
#endif
#ifdef USE_NSS_CRYPTO
      "\t+ NSS crypto support\n"
#else
      "\t- NSS crypto support\n"
#endif
#ifdef USE_GNUTLS_CRYPTO
      "\t+ GnuTLS support\n"
#else
      "\t- GnuTLS support\n"
#endif
#ifdef USE_WOLFSSL_CRYPTO
      "\t+ WolfSSL support\n"
#else
      "\t- WolfSSL support\n"
#endif
#ifdef USE_NETTLE_CRYPTO
      "\t+ Nettle support\n"
#else
      "\t- Nettle support\n"
#endif
#ifdef HAVE_PCRE
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
#ifdef HAVE_PAM
      "\t+ PAM support\n"
#else
      "\t- PAM support\n"
#endif
#if !defined(HAVE_SYS_INOTIFY_H) && !defined(HAVE_KQUEUE)
#ifdef HAVE_FAM_H
      "\t+ FAM support\n"
#else
      "\t- FAM support\n"
#endif
#endif
#ifdef HAVE_SYS_INOTIFY_H
      "\t+ inotify support\n"
#endif
#ifdef HAVE_KQUEUE
      "\t+ kqueue support\n"
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
      ;
  show_version();
  printf("%s%s%s%s\n",
         fdevent_show_event_handlers(),
         network_write_show_handlers(),
         features,
         sizeof(time_t) > 4 || (sizeof(time_t) == 4 && (time_t)-1 > (time_t)1)
           ? "\t+ Y2038 support\n"
           : "\t- Y2038 support (unsafe 32-bit signed time_t)\n");
}

__attribute_cold__
static void show_help (void) {
	char *b = PACKAGE_DESC TEXT_SSL
#ifdef NONREPRODUCIBLE_BUILD
" ("__DATE__ " " __TIME__ ")"
#endif
" - a light and fast webserver\n" \
"usage:\n" \
" -f <name>  filename of the config-file ('-' for stdin)\n" \
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

__attribute_cold__
__attribute_noinline__
static void server_sockets_save (server *srv) {    /* graceful_restart */
    for (uint32_t i = 0; i < srv->srv_sockets.used; ++i)
        srv->srv_sockets.ptr[i]->srv = NULL; /* srv will shortly be invalid */
    for (uint32_t i = 0; i < srv->srv_sockets_inherited.used; ++i)
        srv->srv_sockets_inherited.ptr[i]->srv = NULL; /* srv to be invalid */
    memcpy(&graceful_sockets, &srv->srv_sockets, sizeof(server_socket_array));
    memset(&srv->srv_sockets, 0, sizeof(server_socket_array));
    memcpy(&inherited_sockets, &srv->srv_sockets_inherited, sizeof(server_socket_array));
    memset(&srv->srv_sockets_inherited, 0, sizeof(server_socket_array));
}

__attribute_cold__
__attribute_noinline__
static void server_sockets_restore (server *srv) { /* graceful_restart */
    memcpy(&srv->srv_sockets, &graceful_sockets, sizeof(server_socket_array));
    memset(&graceful_sockets, 0, sizeof(server_socket_array));
    memcpy(&srv->srv_sockets_inherited, &inherited_sockets, sizeof(server_socket_array));
    memset(&inherited_sockets, 0, sizeof(server_socket_array));
    for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
        srv->srv_sockets.ptr[i]->srv = srv;           /* update ptr */
        srv->srv_sockets.ptr[i]->sidx= (unsigned short)~0u;
    }
    for (uint32_t i = 0; i < srv->srv_sockets_inherited.used; ++i)
        srv->srv_sockets_inherited.ptr[i]->srv = srv; /* update ptr */
}

__attribute_cold__
static int server_sockets_set_nb_cloexec (server *srv) {
    if (srv->sockets_disabled) return 0; /* lighttpd -1 (one-shot mode) */
    for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
        server_socket *srv_socket = srv->srv_sockets.ptr[i];
        if (-1 == fdevent_fcntl_set_nb_cloexec_sock(srv_socket->fd)) {
            log_perror(srv->errh, __FILE__, __LINE__, "fcntl()");
            return -1;
        }
    }
    return 0;
}

__attribute_cold__
static void server_sockets_set_event (server *srv, int event) {
    for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
        server_socket *srv_socket = srv->srv_sockets.ptr[i];
        fdevent_fdnode_event_set(srv->ev, srv_socket->fdn, event);
    }
}

__attribute_cold__
static void server_sockets_unregister (server *srv) {
    if (2 == srv->sockets_disabled) return;
    srv->sockets_disabled = 2;
    for (uint32_t i = 0; i < srv->srv_sockets.used; ++i)
        network_unregister_sock(srv, srv->srv_sockets.ptr[i]);
}

__attribute_cold__
static void server_sockets_close (server *srv) {
    /* closing socket right away will make it possible for the next lighttpd
     * to take over (old-style graceful restart), but only if backends
     * (e.g. fastcgi, scgi, etc) are independent from lighttpd, rather
     * than started by lighttpd via "bin-path")
     */
    if (3 == srv->sockets_disabled) return;
    for (uint32_t i = 0; i < srv->srv_sockets.used; ++i) {
        server_socket *srv_socket = srv->srv_sockets.ptr[i];
        if (-1 == srv_socket->fd) continue;
        if (2 != srv->sockets_disabled) network_unregister_sock(srv,srv_socket);
        fdio_close_socket(srv_socket->fd);
        srv_socket->fd = -1;
        /* network_close() will cleanup after us */
    }
    srv->sockets_disabled = 3;
}

__attribute_cold__
static void server_graceful_signal_prev_generation (void)
{
  #ifdef HAVE_FORK
    const char * const prev_gen = getenv("LIGHTTPD_PREV_GEN");
    if (NULL == prev_gen) return;
    pid_t pid = (pid_t)strtol(prev_gen, NULL, 10);
    unsetenv("LIGHTTPD_PREV_GEN");
    if (pid <= 0) return; /*(should not happen)*/
    if (pid == fdevent_waitpid(pid,NULL,1)) return; /*(pid exited; unexpected)*/
    kill(pid, SIGINT); /* signal previous generation for graceful shutdown */
  #endif
}

__attribute_cold__
static int server_graceful_state_bg (server *srv) {
    /*assert(graceful_restart);*/
    /*(SIGUSR1 set to SIG_IGN in workers, so should not reach here if worker)*/
    if (srv_shutdown) return 0;

    /* check if server should fork and background (bg) itself
     * to continue processing requests already in progress */
    if (!config_feature_bool(srv, "server.graceful-restart-bg", 0)) return 0;

    /*(set flag to false to avoid repeating)*/
    data_unset * const du =
      array_get_data_unset(srv->srvconf.feature_flags,
                           CONST_STR_LEN("server.graceful-restart-bg"));
    if (du->type == TYPE_STRING)
        buffer_copy_string_len(&((data_string *)du)->value,
                               CONST_STR_LEN("false"));
    else /* (du->type == TYPE_INTEGER) */
        ((data_integer *)du)->value = 0;

    /* require exec'd via absolute path or daemon in foreground
     * and exec'd with path containing '/' (e.g. "./xxxxx") */
    char ** const argv = srv->argv;
    if (0 == srv->srvconf.dont_daemonize
        ? argv[0][0] != '/'
        : NULL == strchr(argv[0], '/')) return 0;

    /* flush log buffers to avoid potential duplication of entries
     * server_handle_sighup(srv) does the following, but skip logging */
    plugins_call_handle_sighup(srv);
    fdlog_files_cycle(srv->errh); /* reopen log files, not pipes */

    /* backgrounding to continue processing requests in progress */
    /* re-exec lighttpd in original process
     *   Note: using path in re-exec is portable and allows lighttpd upgrade.
     *   OTOH, getauxval() AT_EXECFD and fexecve() could be used on Linux to
     *   re-exec without access to original executable on disk, which might be
     *   desirable in some situations, but is not implemented here.
     *   Alternatively, if argv[] was not available, could use readlink() on
     *   /proc/self/exe (Linux-specific), though there are ways on many other
     *   platforms to achieve the same:
     *   https://stackoverflow.com/questions/1023306/finding-current-executables-path-without-proc-self-exe
     */
  #if defined(HAVE_KQUEUE)
   #if defined(__FreeBSD__) || defined(__DragonFly__)
    /*(must *exclude* rfork RFFDG flag for kqueue to work across rfork)*/
    pid_t pid = rfork(RFPROC);
   #else
    pid_t pid = -1;
    if (pid < 0) {
        /* kqueue is not inherited across fork
         * future: fdevent kqueue and stat_cache kqueue would need to be closed,
         *         re-opened, and active fds re-registered.  Not current done.
         *         Need to create some routines like fdevent_reinit_after_fork*/
        log_warn(srv->errh, __FILE__, __LINE__,
          "server.graceful-restart-bg ignored on OpenBSD and NetBSD "
          "due to limitation in kqueue inheritance and lacking rfork");
        return 0;
    }
   #endif
  #elif defined(HAVE_FORK)
    pid_t pid = fork();
  #else
    pid_t pid = -1;
  #endif
    if (pid) { /* original process */
        if (pid < 0) return 0;
        network_socket_activation_to_env(srv);
        /* save pid of original server in environment so that it can be
         * signalled by restarted server once restarted server is ready
         * to accept new connections */
        server_graceful_signal_prev_generation();/*(expect no prev gen active)*/
        if (0 == srv->srvconf.max_worker) {
            buffer * const tb = srv->tmp_buf;
            buffer_clear(tb);
            buffer_append_int(tb, pid);
            setenv("LIGHTTPD_PREV_GEN", tb->ptr, 1);
        }
        /*fdevent_waitpid(pid, NULL, 0);*//* detach? */
        execv(argv[0], argv);
        _exit(1);
    }
    /* else child/grandchild */

    /*if (-1 == setsid()) _exit(1);*//* should we detach? */
    /* Note: restarted server will fail with socket-in-use error if
     *       server.systemd-socket-activation not enabled in restarted server */
    if (0 != srv->srvconf.max_worker)
        server_sockets_close(srv);/*(close before parent reaps pid in waitpid)*/
    /*if (0 != fork())    _exit(0);*//* should we detach? */
    /*(grandchild is now backgrounded and detached from original process)*/

    /* XXX: might extend code to have new server.feature-flags param specify
     *      max lifetime before aborting remaining connections */

    /* (reached if lighttpd workers or if sole process w/o workers)
     * use same code as comment elsewhere in server.c:
     *   make sure workers do not muck with pid-file */
    if (0 <= pid_fd) {
            close(pid_fd);
            pid_fd = -1;
    }
    srv->srvconf.pid_file = NULL;

    /* (original process is backgrounded -- even if no active connections --
     *  to allow graceful shutdown tasks to be run by server and by modules) */
    log_notice(srv->errh, __FILE__, __LINE__,
      "[note] pid %lld continuing to handle %u connection(s) in progress",
      (long long)getpid(), srv->srvconf.max_conns - srv->lim_conns);

    if (0 == srv->srvconf.max_worker) {
        /* reset graceful_shutdown; wait for signal from restarted server */
        srv->graceful_expire_ts = 0;
        graceful_shutdown = 0;
    }
    graceful_restart = 0;
    return 1;
}

__attribute_cold__
__attribute_noinline__
static void server_graceful_shutdown_maint (server *srv) {
    if (oneshot_fd) {
        /* permit keep-alive on one-shot connections until graceful_expire_ts */
        if (!srv->graceful_expire_ts) return;
        if (srv->graceful_expire_ts >= log_monotonic_secs) return;
    }
    connection_graceful_shutdown_maint(srv);
}

#ifndef server_status_stopping
#define server_status_stopping(srv) do { } while (0)
#endif

__attribute_cold__
__attribute_noinline__
static void server_graceful_state (server *srv) {

    if (!srv_shutdown) {
        if (0 == srv->graceful_expire_ts) {
            srv->graceful_expire_ts =
              config_feature_int(srv, "server.graceful-shutdown-timeout", 8);
            if (srv->graceful_expire_ts)
                srv->graceful_expire_ts += log_monotonic_secs;
        }
        server_graceful_shutdown_maint(srv);
    }

    server_status_stopping(srv);/*might be called multiple times; intentional*/

    if (2 == srv->sockets_disabled || 3 == srv->sockets_disabled) {
        if (oneshot_fd) graceful_restart = 0;
        return;
    }

    log_notice(srv->errh,__FILE__,__LINE__,"[note] graceful shutdown started");

    /* no graceful restart if chroot()ed, if oneshot mode, or if idle timeout */
    if (srv->srvconf.changeroot || oneshot_fd || 2 == graceful_shutdown)
        graceful_restart = 0;

    if (graceful_restart) {
        if (!server_graceful_state_bg(srv))
            server_sockets_unregister(srv);
        if (pid_fd > 0) pid_fd = -pid_fd; /*(flag to skip removing pid file)*/
    }
    else {
        server_sockets_close(srv);
        server_pid_file_remove(srv);
        /*(prevent more removal attempts)*/
        srv->srvconf.pid_file = NULL;
    }
}

__attribute_cold__
__attribute_noinline__
static void server_sockets_enable (server *srv) {
    server_sockets_set_event(srv, FDEVENT_IN);
    srv->sockets_disabled = 0;
    log_notice(srv->errh, __FILE__, __LINE__, "[note] sockets enabled again");
}

__attribute_cold__
__attribute_noinline__
static void server_sockets_disable (server *srv) {
    server_sockets_set_event(srv, 0);
    srv->sockets_disabled = 1;
    log_notice(srv->errh, __FILE__, __LINE__,
      (0 == srv->lim_conns)
        ? "[note] sockets disabled, connection limit reached"
        : "[note] sockets disabled, out-of-fds");
}

__attribute_cold__
static void server_overload_check (server *srv) {
    if (srv->cur_fds < srv->max_fds_lowat && 0 != srv->lim_conns)
        server_sockets_enable(srv);
}

static void server_load_check (server *srv) {
    /* check if hit limits for num fds used or num connections */
    if (srv->cur_fds > srv->max_fds_hiwat || 0 == srv->lim_conns)
        server_sockets_disable(srv);
}

#ifdef HAVE_FORK
__attribute_noinline__
static int server_main_setup_workers (server * const srv, const int npids) {
    pid_t pid;
    int num_childs = npids;
    int child = 0;
    unsigned int timer = 0;
    pid_t pids[npids];
    for (int n = 0; n < npids; ++n) pids[n] = -1;
    server_graceful_signal_prev_generation();
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
        }
        else {
            int status;
            unix_time64_t mono_ts;
            if (-1 != (pid = fdevent_waitpid_intr(-1, &status))) {
                mono_ts = log_monotonic_secs;
                log_monotonic_secs = server_monotonic_secs();
                log_epoch_secs =
                  server_epoch_secs(srv, log_monotonic_secs - mono_ts);
                if (plugins_call_handle_waitpid(srv, pid, status)
                    != HANDLER_GO_ON) {
                    if (!timer) alarm((timer = 5));
                    continue;
                }
                switch (fdlog_pipes_waitpid_cb(pid)) {
                  default: break;
                  case -1: if (!timer) alarm((timer = 5));
                           __attribute_fallthrough__
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
            }
            else if (errno == EINTR) {
                mono_ts = log_monotonic_secs;
                log_monotonic_secs = server_monotonic_secs();
                log_epoch_secs =
                  server_epoch_secs(srv, log_monotonic_secs - mono_ts);
                /* On SIGHUP, cycle logs (periodic maint runs in children) */
                if (handle_sig_hup) {
                    handle_sig_hup = 0;
                    fdlog_files_cycle(srv->errh);/*reopen log files, not pipes*/
                    /* forward SIGHUP to workers */
                    for (int n = 0; n < npids; ++n) {
                        if (pids[n] > 0) kill(pids[n], SIGHUP);
                    }
                }
                if (handle_sig_alarm) {
                    handle_sig_alarm = 0;
                    timer = 0;
                    plugins_call_handle_trigger(srv);
                    fdlog_pipes_restart(log_monotonic_secs);
                }
            }
        }
    }

    if (!child) {
        /* exit point for parent monitoring workers;
         * signal children, too */
        if (graceful_shutdown || graceful_restart) {
            /* flag to ignore one SIGINT if graceful_restart */
            if (graceful_restart) graceful_restart = 2;
            kill(0, SIGINT);
            server_graceful_state(srv);
        }
        else if (srv_shutdown)
            kill(0, SIGTERM);

        return 0;
    }

    /* ignore SIGUSR1 in workers; only parent directs graceful restart */
  #ifdef HAVE_SIGACTION
    struct sigaction actignore;
    memset(&actignore, 0, sizeof(actignore));
    actignore.sa_handler = SIG_IGN;
    sigaction(SIGUSR1, &actignore, NULL);
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
    srv->srvconf.pid_file = NULL;

    fdlog_pipes_abandon_pids();
    srv->pid = getpid();
    li_rand_reseed();

    return 1; /* child worker */
}
#endif

__attribute_cold__
__attribute_noinline__
static int server_main_setup (server * const srv, int argc, char **argv) {
	int print_config = 0;
	int test_config = 0;
	int i_am_root = 0;
#ifdef HAVE_FORK
	int parent_pipe_fd = -1;
	const char *conffile = NULL;
#endif

#ifdef HAVE_GETUID
	i_am_root = (0 == getuid());
#endif

	/* initialize globals (including file-scoped static globals) */
	oneshot_fd = 0;
	oneshot_fdout = -1;
	srv_shutdown = 0;
	graceful_shutdown = 0;
	handle_sig_alarm = 1;
	handle_sig_hup = 0;
	idle_limit = 0;
	chunkqueue_set_tempdirs_default_reset();
	/*graceful_restart = 0;*//*(reset below to avoid further daemonizing)*/
	/*(intentionally preserved)*/
	/*memset(graceful_sockets, 0, sizeof(graceful_sockets));*/
	/*memset(inherited_sockets, 0, sizeof(inherited_sockets));*/
	/*pid_fd = -1;*/
	srv->argv = argv;

	for (int o; -1 != (o = getopt(argc, argv, "f:m:i:hvVD1pt")); ) {
		switch(o) {
		case 'f':
			if (srv->config_data_base) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "Can only read one config file. Use the include command to use multiple config files.");
				return -1;
			}
			if (config_read(srv, optarg)) {
				return -1;
			}
#ifdef HAVE_FORK
			conffile = optarg;
#endif
			break;
		case 'm':
			srv->srvconf.modules_dir = optarg;
			break;
		case 'i': {
			char *endptr;
			long timeout = strtol(optarg, &endptr, 0);
			if (!*optarg || *endptr || timeout < 0) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "Invalid idle timeout value: %s", optarg);
				return -1;
			}
			idle_limit = (int)timeout;
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

      #if defined(__CYGWIN__) || defined(_WIN32)
	if (!srv->config_data_base && NULL != getenv("NSSM_SERVICE_NAME")) {
		char *dir = getenv("NSSM_SERVICE_DIR");
		if (NULL != dir && 0 != chdir(dir)) {
			log_perror(srv->errh, __FILE__, __LINE__, "chdir %s failed", dir);
			return -1;
		}
		srv->srvconf.dont_daemonize = 1;
		srv->srvconf.modules_dir = "modules";
		if (config_read(srv, "conf/lighttpd.conf")) return -1;
	}
      #ifndef HAVE_FORK
	srv->srvconf.dont_daemonize = 1;
      #endif
      #endif

	if (!srv->config_data_base) {
		log_error(srv->errh, __FILE__, __LINE__,
		  "No configuration available. Try using -f option.");
		return -1;
	}

	if (1 == srv->srvconf.max_worker)
		srv->srvconf.max_worker = 0;

	if (print_config) {
		config_print(srv);
		puts(srv->tmp_buf->ptr);
	}

	if (test_config) {
		srv->srvconf.pid_file = NULL;
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
			log_error(srv->errh, __FILE__, __LINE__,
			  "Invalid fds at startup with lighttpd -1");
			return -1;
		}
		graceful_shutdown = 1;
		srv->sockets_disabled = 2;
		srv->srvconf.dont_daemonize = 1;
		srv->srvconf.pid_file = NULL;
		if (srv->srvconf.max_worker) {
			srv->srvconf.max_worker = 0;
			log_warn(srv->errh, __FILE__, __LINE__,
			  "server one-shot command line option disables server.max-worker config file option.");
		}

		struct stat st;
		if (0 != fstat(oneshot_fd, &st)) {
			log_perror(srv->errh, __FILE__, __LINE__, "fstat()");
			return -1;
		}

	  #ifndef _WIN32 /*(skip S_ISFIFO() and hope for the best if _WIN32)*/
		if (S_ISFIFO(st.st_mode)) {
			oneshot_fdout = dup(STDOUT_FILENO);
			if (oneshot_fdout <= STDERR_FILENO) {
				log_perror(srv->errh, __FILE__, __LINE__, "dup()");
				return -1;
			}
		}
	  #endif
	  #ifndef _WIN32 /*(skip S_ISSOCK() and hope for the best if _WIN32)*/
		else if (!S_ISSOCK(st.st_mode)) {
			/* require that fd is a socket
			 * (modules might expect STDIN_FILENO and STDOUT_FILENO opened to /dev/null) */
			log_error(srv->errh, __FILE__, __LINE__,
			  "lighttpd -1 stdin is not a socket");
			return -1;
		}
	  #endif
	}

	if (srv->srvconf.bindhost && buffer_is_equal_string(srv->srvconf.bindhost, CONST_STR_LEN("/dev/stdin"))) {
		/* XXX: to potentially support on _WIN32,
		 *      (SOCKET)GetStdHandle(STD_INPUT_HANDLE) and
		 *      WSADuplicateSocket() instead of dup() */
		if (-1 == srv->stdin_fd)
			srv->stdin_fd = dup(STDIN_FILENO);
		if (srv->stdin_fd <= STDERR_FILENO) {
			log_error(srv->errh, __FILE__, __LINE__,
			  "Invalid fds at startup");
			return -1;
		}
	}

	/* close stdin and stdout, as they are not needed */
  #ifdef _WIN32
	/* _WIN32 file descriptors are not allocated lowest first.
	 * Open NUL in binary mode and as (default) inheritable handle
	 * https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/dup-dup2?view=msvc-170
	 *
	 * A stream is associated with a file descriptor (_fileno(stream)).
	 * An open file descriptor has an underlying operating system HANDLE.
	 * However, standard handles are cached at program startup,
	 * so we try to match them all back up after redirection. */
	if (   NULL == freopen("nul:", "rb", stdin)
	    || NULL == freopen("nul:", "wb", stdout)
	    || (_fileno(stderr) == -2
		&& NULL == freopen("nul:", "wb", stderr))) {
		log_perror(srv->errh, __FILE__, __LINE__, "freopen() NUL");
		return -1;
	}
	SetStdHandle(STD_INPUT_HANDLE, (HANDLE)_get_osfhandle(_fileno(stdin)));
	SetStdHandle(STD_OUTPUT_HANDLE,(HANDLE)_get_osfhandle(_fileno(stdout)));
	SetStdHandle(STD_ERROR_HANDLE, (HANDLE)_get_osfhandle(_fileno(stderr)));
	fdevent_setfd_cloexec(STDERR_FILENO);
  #else
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
			log_perror(srv->errh, __FILE__, __LINE__,
			  "opening /dev/null failed");
			return -1;
		}
		errfd = (0 == fstat(STDERR_FILENO, &st)) ? -1 : devnull;
		if (0 != fdevent_set_stdin_stdout_stderr(devnull, devnull, errfd)) {
			log_perror(srv->errh, __FILE__, __LINE__,
			  "setting default fds failed");
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
  #endif

	http_range_config_allow_http10(config_feature_bool(srv, "http10.range", 0));

	if (0 != config_set_defaults(srv)) {
		log_error(srv->errh, __FILE__, __LINE__,
		  "setting default values failed");
		return -1;
	}

	if (plugins_load(srv)) {
		log_error(srv->errh, __FILE__, __LINE__,
		  "loading plugins finally failed");
		return -1;
	}

	if (HANDLER_GO_ON != plugins_call_init(srv)) {
		log_error(srv->errh, __FILE__, __LINE__,
		  "Initialization of plugins failed. Going down.");
		return -1;
	}
	http_response_fn_init(srv);

	http_dispatch[HTTP_VERSION_1_1] = h1_1_dispatch_table; /* copy struct */

	if (config_feature_bool(srv, "server.h2-discard-backend-1xx", 0))
		http_dispatch[HTTP_VERSION_2].send_1xx = 0;

	if (config_feature_bool(srv, "server.h1-discard-backend-1xx", 0))
		http_dispatch[HTTP_VERSION_1_1].send_1xx = 0;

	if (config_feature_bool(srv, "server.discard-backend-1xx", 0)) {
		http_dispatch[HTTP_VERSION_3].send_1xx = 0;
		http_dispatch[HTTP_VERSION_2].send_1xx = 0;
		http_dispatch[HTTP_VERSION_1_1].send_1xx = 0;
	}

	/* mod_indexfile should be listed in server.modules prior to dynamic handlers */
	uint32_t i = 0;
	for (const char *pname = NULL; i < srv->plugins.used; ++i) {
		plugin *p = ((plugin **)srv->plugins.ptr)[i];
		if (0 == strcmp(p->name, "indexfile")) {
			if (pname)
				log_warn(srv->errh, __FILE__, __LINE__,
				  "Warning: mod_indexfile should be listed in server.modules prior to mod_%s", pname);
			break;
		}
		if (p->handle_subrequest_start && p->handle_subrequest) {
			if (!pname) pname = p->name;
		}
	}

	/* open pid file BEFORE chroot */
	if (-2 == pid_fd) pid_fd = -1; /*(initial startup state)*/
	if (-1 == pid_fd && 0 != server_pid_file_open(srv, i_am_root))
		return -1;

	{
#ifdef HAVE_GETRLIMIT
		struct rlimit rlim = { 4096, 4096 };
		int use_rlimit = 1;
#ifdef HAVE_VALGRIND_VALGRIND_H
		if (RUNNING_ON_VALGRIND) use_rlimit = 0;
#endif

		if (0 != getrlimit(RLIMIT_NOFILE, &rlim)) {
			log_perror(srv->errh, __FILE__, __LINE__, "getrlimit()");
			use_rlimit = 0;
		}
		else if (0 == srv->srvconf.max_fds) {
			/*(default upper limit of 4k if server.max-fds not specified)*/
			/*(and if existing rlim_max >= 4096, whether or not root)*/
			if (rlim.rlim_cur < 4096 && rlim.rlim_max >= 4096)
				srv->srvconf.max_fds = 4096;
		}
		else if (i_am_root)
				rlim.rlim_max = srv->srvconf.max_fds;

		if (use_rlimit && srv->srvconf.max_fds
		    && (i_am_root || srv->srvconf.max_fds <= rlim.rlim_max)) {
			/* set rlimits */
			/* root can increase fd-limit above rlim_max, others can only reduce it */

			rlim_t rlim_cur = rlim.rlim_cur;
			rlim.rlim_cur = srv->srvconf.max_fds;

			if (0 != setrlimit(RLIMIT_NOFILE, &rlim)) {
				log_perror(srv->errh, __FILE__, __LINE__, "setrlimit()");
				log_error(srv->errh, __FILE__, __LINE__, "setrlimit() may need root to run once: setsebool -P httpd_setrlimit on");
				use_rlimit = 0;
				if (srv->srvconf.max_fds > rlim_cur)
					srv->srvconf.max_fds = rlim_cur;
			}
		}

		/*(default upper limit of 4k if server.max-fds not specified)*/
		if (0 == srv->srvconf.max_fds)
			srv->srvconf.max_fds = (rlim.rlim_cur <= 4096)
			  ? (unsigned short)rlim.rlim_cur
			  : 4096;

		/* set core file rlimit, if enable_cores is set */
		if (use_rlimit && srv->srvconf.enable_cores && getrlimit(RLIMIT_CORE, &rlim) == 0) {
			rlim.rlim_cur = rlim.rlim_max;
			setrlimit(RLIMIT_CORE, &rlim);
		}
#else
	  #ifdef _WIN32
		/*(default upper limit of 4k if server.max-fds not specified)*/
		if (0 == srv->srvconf.max_fds)
			srv->srvconf.max_fds = 4096;
	  #endif
#endif
	}

	/* we need root-perms for port < 1024 */
	if (0 != network_init(srv, srv->stdin_fd)) {
		return -1;
	}
	srv->stdin_fd = -1;

	if (i_am_root) {
#ifdef HAVE_PWD_H
		/* set user and group */
		struct group *grp = NULL;
		struct passwd *pwd = NULL;

		if (srv->srvconf.groupname) {
			if (NULL == (grp = getgrnam(srv->srvconf.groupname->ptr))) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "can't find groupname %s", srv->srvconf.groupname->ptr);
				return -1;
			}
		}

		if (srv->srvconf.username) {
			if (NULL == (pwd = getpwnam(srv->srvconf.username->ptr))) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "can't find username %s", srv->srvconf.username->ptr);
				return -1;
			}

			if (pwd->pw_uid == 0) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "I will not set uid to 0.  Perhaps you should comment out server.username in lighttpd.conf\n");
				return -1;
			}

			if (NULL == grp && NULL == (grp = getgrgid(pwd->pw_gid))) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "can't find group id %d", (int)pwd->pw_gid);
				return -1;
			}
		}

		if (NULL != grp) {
			if (grp->gr_gid == 0) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "I will not set gid to 0.  Perhaps you should comment out server.groupname in lighttpd.conf\n");
				return -1;
			}
		}

		/* 
		 * Change group before chroot, when we have access
		 * to /etc/group
		 * */
		if (NULL != grp) {
			if (-1 == setgid(grp->gr_gid)) {
				log_perror(srv->errh, __FILE__, __LINE__, "setgid()");
				return -1;
			}
			if (-1 == setgroups(0, NULL)) {
				log_perror(srv->errh, __FILE__, __LINE__, "setgroups()");
				return -1;
			}
			if (srv->srvconf.username) {
				initgroups(srv->srvconf.username->ptr, grp->gr_gid);
			}
		}
#endif
#ifdef HAVE_CHROOT
		if (srv->srvconf.changeroot) {
			tzset();

			if (-1 == chroot(srv->srvconf.changeroot->ptr)) {
				log_perror(srv->errh, __FILE__, __LINE__, "chroot()");
				return -1;
			}
			if (-1 == chdir("/")) {
				log_perror(srv->errh, __FILE__, __LINE__, "chdir()");
				return -1;
			}
		}
#endif
#ifdef HAVE_PWD_H
		/* drop root privs */
		if (NULL != pwd) {
			if (-1 == setuid(pwd->pw_uid)) {
				log_perror(srv->errh, __FILE__, __LINE__, "setuid()");
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
#elif defined(HAVE_SYS_PROCCTL_H) && defined(PROC_TRACE_CTL_ENABLE)
		/* (DragonFlyBSD has procctl(), but not PROC_TRACE_CTL_ENABLE) */
		if (srv->srvconf.enable_cores) {
			int dumpable = PROC_TRACE_CTL_ENABLE;
			procctl(P_PID, 0, PROC_TRACE_CTL, &dumpable);
		}
#elif defined(HAVE_SETPFLAGS) && defined(__PROC_PROTECT)
		/**
		 * setpflags seems uniquely a solaris/illumos feature
		 * but just taking extra precautions clearing __PROC_PROTECT option
		 */
		if (srv->srvconf.enable_cores) {
			setpflags(__PROC_PROTECT, 0);
		}
#endif
	}

#if defined(HAVE_SYS_PRCTL_H) && defined(PR_CAP_AMBIENT)
	/* clear Linux ambient capabilities, if any had been granted
	 * (avoid leaking privileges to CGI or other subprocesses) */
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) < 0
           /* not supported before linux 4.3 / on some emulators (e.g. Cloud Run 1st gen) */
           && errno != EINVAL) {
		log_perror(srv->errh, __FILE__, __LINE__,
		  "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)");
		return -1;
	}
#endif

#ifdef __linux__ /*(might occur w/ root on Linux and w/ limited Capabilities)*/
	if (-1 == pid_fd && 0 != server_pid_file_open(srv, 0))
		return -1;
#endif

#ifdef HAVE_FORK
	/* network is up, let's daemonize ourself */
	if (0 == srv->srvconf.dont_daemonize && 0 == graceful_restart) {
		if (conffile && *conffile != '/'
		    && (conffile[0] != '-' || conffile[1] != '\0')/*(special-case "-")*/
		   #if defined(_WIN32)
                    && *conffile != '\\'
                    && conffile[0] && conffile[1] != ':'
		   #endif
		    /*(might perform similar checks on srv->srvconf.modules_dir)*/
		    ) {
			log_warn(srv->errh, __FILE__, __LINE__,
			  "(warning) daemonizing without absolute path command line args"
			  " (graceful restart may fail)");
		}
		parent_pipe_fd = daemonize();
	}
#endif
	graceful_restart = 0;/*(reset here after avoiding further daemonizing)*/
	if (0 == oneshot_fd) graceful_shutdown = 0;

	server_main_setup_signals();

  #ifdef HAVE_GETUID
	srv->gid = getgid();
	srv->uid = getuid();
  #endif
	srv->pid = getpid();

	/* write pid file */
	if (pid_fd > 2) {
		buffer * const tb = srv->tmp_buf;
		buffer_clear(tb);
		buffer_append_int(tb, srv->pid);
		buffer_append_char(tb, '\n');
		if (-1 == write_all(pid_fd, BUF_PTR_LEN(tb))) {
			log_perror(srv->errh, __FILE__, __LINE__, "Couldn't write pid file");
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
		if (-1 == config_log_error_open(srv)) {
			log_error(srv->errh, __FILE__, __LINE__, "Opening errorlog failed. Going down.");
			return -1;
		}
		if (!oneshot_fd)
			log_notice(srv->errh, __FILE__, __LINE__, "server started (" PACKAGE_DESC ")");
	}

	if (HANDLER_GO_ON != plugins_call_set_defaults(srv)) {
		log_error(srv->errh, __FILE__, __LINE__, "Configuration of plugins failed. Going down.");
		return -1;
	}

	if (!config_finalize(srv, &default_server_tag)) {
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
		log_warn(srv->errh, __FILE__, __LINE__,
		  "server idle time limit command line option disables server.max-worker config file option.");
	}

	/* start watcher and workers */
	if (srv->srvconf.max_worker > 0) {
		int rc = server_main_setup_workers(srv, srv->srvconf.max_worker);
		if (rc != 1) /* 1 for worker; 0 for worker parent done; -1 for error */
			return rc;
	}
#endif

	srv->max_fds = (int)srv->srvconf.max_fds;
        if (srv->max_fds < 32) /*(sanity check; not expected)*/
            srv->max_fds = 32; /*(server load checks will fail if too low)*/
	srv->ev = fdevent_init(srv->srvconf.event_handler, &srv->max_fds, &srv->cur_fds, srv->errh);
	if (NULL == srv->ev) {
		log_error(srv->errh, __FILE__, __LINE__, "fdevent_init failed");
		return -1;
	}

	srv->max_fds_lowat = srv->max_fds * 8 / 10;
	srv->max_fds_hiwat = srv->max_fds * 9 / 10;

	/* set max-conns */
	if (srv->srvconf.max_conns > srv->max_fds/2) {
		/* we can't have more connections than max-fds/2 */
		log_warn(srv->errh, __FILE__, __LINE__,
		  "can't have more connections than fds/2: %hu %d",
		  srv->srvconf.max_conns, srv->max_fds);
		srv->lim_conns = srv->srvconf.max_conns = srv->max_fds/2;
	} else if (srv->srvconf.max_conns) {
		/* otherwise respect the wishes of the user */
		srv->lim_conns = srv->srvconf.max_conns;
	} else {
		/* or use the default: we really don't want to hit max-fds */
		srv->lim_conns = srv->srvconf.max_conns = srv->max_fds/3;
	}

  #if defined(HAVE_MALLOC_TRIM)
	if (srv->srvconf.max_conns <= 16 && malloc_top_pad == 524288)
		malloc_top_pad = 131072; /*(reduce memory use on small systems)*/
  #endif

	/*
	 * kqueue() is called here, select resets its internals,
	 * all server sockets get their handlers
	 *
	 * */
	if (0 != network_register_fdevents(srv)) {
		return -1;
	}

	chunkqueue_internal_pipes(config_feature_bool(srv, "chunkqueue.splice", 1));

	/* might fail if user is using fam (not gamin) and famd isn't running */
	if (!stat_cache_init(srv->ev, srv->errh)) {
		log_error(srv->errh, __FILE__, __LINE__,
		  "stat-cache could not be setup, dying.");
		return -1;
	}

	/* get the current number of FDs */
  #ifdef _WIN32
	srv->cur_fds = 3; /*(estimate on _WIN32)*/
  #else
	{
		int fd = fdevent_open_devnull();
		if (fd >= 0) {
			srv->cur_fds = fd;
			close(fd);
		}
	}
  #endif

	if (0 != server_sockets_set_nb_cloexec(srv)) {
		return -1;
	}

	/* plugin hook for worker_init */
	if (HANDLER_GO_ON != plugins_call_worker_init(srv))
		return -1;

	if (oneshot_fdout > 0) {
		if (server_oneshot_init_pipe(srv, oneshot_fd, oneshot_fdout)) {
			oneshot_fd = -1;
			oneshot_fdout = -1;
		}
	}
	else if (oneshot_fd && server_oneshot_init(srv, oneshot_fd)) {
		oneshot_fd = -1;
	}

	if (0 == srv->srvconf.max_worker)
		server_graceful_signal_prev_generation();

	return 1;
}

__attribute_cold__
__attribute_noinline__
static void server_handle_sighup (server * const srv) {

			/* cycle logfiles */

			plugins_call_handle_sighup(srv);
			fdlog_files_cycle(srv->errh); /* reopen log files, not pipes */
#ifdef HAVE_SIGACTION
				log_info(srv->errh, __FILE__, __LINE__,
				  "logfiles cycled UID = %d PID = %d",
				  (int)last_sighup_info.si_uid,
				  (int)last_sighup_info.si_pid);
#else
				log_info(srv->errh, __FILE__, __LINE__,
				  "logfiles cycled");
#endif
}

__attribute_noinline__
static void server_handle_sigalrm (server * const srv, unix_time64_t mono_ts, unix_time64_t last_active_ts) {

				plugins_call_handle_trigger(srv);

				log_monotonic_secs = mono_ts;
				log_epoch_secs = server_epoch_secs(srv, 0);

				/* check idle time limit, if enabled */
				if (idle_limit && (unix_time64_t)idle_limit < mono_ts - last_active_ts && !graceful_shutdown) {
					log_notice(srv->errh, __FILE__, __LINE__,
					  "[note] idle timeout %ds exceeded, "
					  "initiating graceful shutdown", (int)idle_limit);
					graceful_shutdown = 2; /* value 2 indicates idle timeout */
					if (graceful_restart) {
						graceful_restart = 0;
						if (pid_fd < -2) pid_fd = -pid_fd;
						server_sockets_close(srv);
					}
				}

			      #ifdef HAVE_GETLOADAVG
				/* refresh loadavg data every 30 seconds */
				if (srv->loadts + 30 < mono_ts) {
					if (-1 != getloadavg(srv->loadavg, 3)) {
						srv->loadts = mono_ts;
					}
				}
			      #endif

				if (0 == (mono_ts & 0x3f)) { /*(once every 64 secs)*/
					/* free logger buffers every 64 secs */
					fdlog_flushall(srv->errh);
					/* free excess chunkqueue buffers every 64 secs */
					chunkqueue_chunk_pool_clear();
					/* clear request and connection pools every 64 secs */
					request_pool_free();
					connections_pool_clear(srv);
				  #if defined(HAVE_MALLOC_TRIM)
					if (malloc_trim_fn) malloc_trim_fn(malloc_top_pad);
				  #endif
					/* attempt to restart dead piped loggers every 64 secs */
					if (0 == srv->srvconf.max_worker)
						fdlog_pipes_restart(mono_ts);
				}
				/* cleanup stat-cache */
				stat_cache_trigger_cleanup();
				/* reset global/aggregate rate limit counters */
				config_reset_config_bytes_sec(srv->config_data_base);
				/* if graceful_shutdown, accelerate cleanup of recently completed request/responses */
				if (graceful_shutdown && !srv_shutdown)
					server_graceful_shutdown_maint(srv);
				connection_periodic_maint(srv, mono_ts);
}

__attribute_noinline__
static void server_handle_sigchld (server * const srv) {
			pid_t pid;
			do {
				int status;
				pid = fdevent_waitpid(-1, &status, 1);
				if (pid > 0) {
					if (plugins_call_handle_waitpid(srv, pid, status) != HANDLER_GO_ON) {
						continue;
					}
					if (0 == srv->srvconf.max_worker) {
						/* check piped-loggers and restart, even if shutting down */
						if (fdlog_pipes_waitpid_cb(pid)) {
							continue;
						}
					}
				}
			} while (pid > 0 || (-1 == pid && errno == EINTR));
}

__attribute_hot__
__attribute_nonnull__()
static void server_run_con_queue (connection * const restrict joblist, const connection * const sentinel) {
    for (connection *con = joblist, *jqnext; con != sentinel; con = jqnext) {
        jqnext = con->jqnext;
        con->jqnext = NULL;
        connection_state_machine(con);
    }
}

__attribute_hot__
__attribute_noinline__
static void server_main_loop (server * const srv) {
	unix_time64_t last_active_ts = server_monotonic_secs();
	log_epoch_secs = server_epoch_secs(srv, 0);

	while (!srv_shutdown) {

		if (handle_sig_hup) {
			handle_sig_hup = 0;
			server_handle_sighup(srv);
		}

		/*(SIGALRM not used here; fdevent_poll() is effective periodic timer)*/
	      #if 0
		if (handle_sig_alarm) {
			handle_sig_alarm = 0;
	      #endif
			unix_time64_t mono_ts = server_monotonic_secs();
			if (mono_ts != log_monotonic_secs) {
				server_handle_sigalrm(srv, mono_ts, last_active_ts);
			}
	      #if 0
		}
	      #endif

		if (handle_sig_child) {
			handle_sig_child = 0;
			server_handle_sigchld(srv);
		}

		if (graceful_shutdown) {
			server_graceful_state(srv);
			if (NULL == srv->conns && graceful_shutdown) {
				/* we are in graceful shutdown phase and all connections are closed
				 * we are ready to terminate without harming anyone */
				srv_shutdown = 1;
				break;
			}
		} else if (srv->sockets_disabled) {
			server_overload_check(srv);
		} else {
			server_load_check(srv);
		}

	  #ifndef _MSC_VER
		static
	  #endif
		connection * const sentinel =
		  (connection *)(uintptr_t)&log_con_jqueue;
		connection * const joblist = log_con_jqueue;
		log_con_jqueue = sentinel;
		server_run_con_queue(joblist, sentinel);

		if (fdevent_poll(srv->ev, log_con_jqueue != sentinel ? 0 : 1000) > 0)
			last_active_ts = log_monotonic_secs;
	}
}

__attribute_cold__
__attribute_noinline__
static int main_init_once (void) {
  #ifdef HAVE_GETUID
  #ifndef HAVE_ISSETUGID
  #define issetugid() (geteuid() != getuid() || getegid() != getgid())
  #endif
    if (0 != getuid() && issetugid()) { /*check as early as possible in main()*/
        fprintf(stderr,
                "Are you nuts ? Don't apply a SUID bit to this binary\n");
        return 0;
    }
  #endif

  #if defined(HAVE_MALLOPT) && defined(M_ARENA_MAX)
  #ifdef LIGHTTPD_STATIC
    mallopt(M_ARENA_MAX, 2); /*(ignore error, if any)*/
  #else
    {
        int (*mallopt_fn)(int, int);
        mallopt_fn = (int (*)(int, int))(intptr_t)dlsym(RTLD_DEFAULT,"mallopt");
        if (mallopt_fn) mallopt_fn(M_ARENA_MAX, 2); /*(ignore error, if any)*/
    }
  #endif
  #endif

  #if defined(HAVE_MALLOC_TRIM)
    malloc_top_pad = 524288;
    {
        const char * const top_pad_str = getenv("MALLOC_TOP_PAD_");
        if (top_pad_str) {
            unsigned long top_pad = strtoul(top_pad_str, NULL, 10);
            if (top_pad != ULONG_MAX) malloc_top_pad = (size_t)top_pad;
        }
    }
  #ifdef LIGHTTPD_STATIC
    malloc_trim_fn = malloc_trim;
  #else
    malloc_trim_fn =
      (int (*)(size_t))(intptr_t)dlsym(RTLD_DEFAULT,"malloc_trim");
  #endif
  #endif

    /* for nice %b handling in strftime() */
  #ifdef _WIN32
    setlocale(LC_ALL, "C.UTF-8");
   #ifdef __MINGW32__
    _setmbcp(_MB_CP_LOCALE);
   #else
    _setmbcp(_MB_CP_UTF8);
   #endif
  #else
    setlocale(LC_TIME, "C");
  #endif
    tzset();

  #ifdef __MINGW32__
    /* MSYS2 translates SHELL path even if MSYS_NO_PATHCONV=1
     * lighttpd uses "/bin/sh" for consistency and substitutes "cmd.exe" later
     * (__MINGW32__ is also set when mingw cross-compiler used under Cygwin) */
    if (getenv("MSYSTEM")) { /* MSYS2 */
        const char *shell = getenv("SHELL");
        size_t len = shell ? strlen(shell) : 0;
        if (len >= 11 && 0 == strcmp(shell+len-11, "\\bin\\sh.exe"))
            setenv("SHELL", "/bin/sh", 1);
    }
  #endif

    ck_static_assert(sizeof(off_t) == 8); /* sanity check: 64-bit off_t */

    return 1;
}

#ifndef server_status_running
#define server_status_running(srv) do { } while (0)
#endif

#ifndef main
#define server_main main
#endif

__attribute_cold__
int server_main (int argc, char ** argv) {
    if (!main_init_once()) return -1;

    int rc;

    do {
        server * const srv = server_init();

        if (graceful_restart) {
            server_sockets_restore(srv);
            optind = 1;
        }

        rc = server_main_setup(srv, argc, argv);
        if (rc > 0) {
            server_status_running(srv);

            server_main_loop(srv);

            if (graceful_shutdown || graceful_restart) {
                server_graceful_state(srv);
            }

            if (NULL == srv->conns) rc = 0;
            if (2 == graceful_shutdown) { /* value 2 indicates idle timeout */
                log_notice(srv->errh, __FILE__, __LINE__,
                  "server stopped after idle timeout");
            } else if (!oneshot_fd) {
              #ifdef HAVE_SIGACTION
                log_notice(srv->errh, __FILE__, __LINE__,
                  "server stopped by UID = %d PID = %d",
                  (int)last_sigterm_info.si_uid,
                  (int)last_sigterm_info.si_pid);
              #else
                log_notice(srv->errh, __FILE__, __LINE__,
                  "server stopped");
              #endif
            }
        }

        /* clean-up */
        chunkqueue_internal_pipes(0);
        server_pid_file_remove(srv);
        config_log_error_close(srv);
      #ifdef _WIN32
        fdevent_win32_cleanup();
      #endif
        if (graceful_restart)
            server_sockets_save(srv);
        else
            network_close(srv);
        request_pool_free();
        connections_free(srv);
        plugins_free(srv);
        server_free(srv);

        if (rc < 0 || !graceful_restart) break;

        /* wait for all children to exit before graceful restart */
        while (fdevent_waitpid(-1, NULL, 0) > 0) ;
    } while (graceful_restart);

    return rc;
}
