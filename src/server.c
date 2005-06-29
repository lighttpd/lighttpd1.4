#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <locale.h>

#include <stdio.h>

#include "server.h"
#include "buffer.h"
#include "network.h"
#include "log.h"
#include "keyvalue.h"
#include "response.h"
#include "request.h"
#include "chunk.h"
#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "file_cache.h"
#include "plugin.h"
#include "joblist.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_PWD_H
#include <grp.h>
#include <pwd.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

const char *patches[] = { "SERVERsocket", "HTTPurl", "HTTPhost", "HTTPreferer", "HTTPuseragent", "HTTPcookie", NULL };


#ifndef __sgi
/* IRIX doesn't like the alarm based time() optimization */
/* #define USE_ALARM */
#endif

static sig_atomic_t srv_shutdown = 0;
static sig_atomic_t handle_sig_alarm = 1;
static sig_atomic_t handle_sig_hup = 0;

#if defined(HAVE_SIGACTION) && defined(SA_SIGINFO)
static void sigaction_handler(int sig, siginfo_t *si, void *context) {
	UNUSED(si);
	UNUSED(context);

	switch (sig) {
	case SIGTERM: srv_shutdown = 1; break;
	case SIGALRM: handle_sig_alarm = 1; break;
	case SIGHUP:  handle_sig_hup = 1; break;
	case SIGCHLD: break;
	}
}
#elif defined(HAVE_SIGNAL) || defined(HAVE_SIGACTION)
static void signal_handler(int sig) {
	switch (sig) {
	case SIGTERM: srv_shutdown = 1; break;
	case SIGALRM: handle_sig_alarm = 1; break;
	case SIGHUP:  handle_sig_hup = 1; break;
	case SIGCHLD:  break;
	}
}
#endif

#ifdef HAVE_FORK
static void daemonize(void) {
#ifdef SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
	if (fork() != 0) exit(0);
	
	if (setsid() == -1) exit(0);

	signal(SIGHUP, SIG_IGN);

	if (fork() != 0) exit(0);
	
	chdir("/");
	
	umask(0);
}
#endif

static server *server_init(void) {
	int i;
	
	server *srv = calloc(1, sizeof(*srv));
	assert(srv);
#define CLEAN(x) \
	srv->x = buffer_init();
	
	CLEAN(response_header);
	CLEAN(parse_full_path);
	CLEAN(ts_debug_str);
	CLEAN(ts_date_str);
	CLEAN(error_log);
	CLEAN(response_range);
	CLEAN(tmp_buf);
	CLEAN(file_cache_etag);
	CLEAN(range_buf);
	CLEAN(empty_string);
	
	buffer_copy_string(srv->empty_string, "");
	
	CLEAN(srvconf.error_logfile);
	CLEAN(srvconf.groupname);
	CLEAN(srvconf.username);
	CLEAN(srvconf.changeroot);
	CLEAN(srvconf.bindhost);
	CLEAN(srvconf.errorfile_prefix);
	CLEAN(srvconf.license);
	CLEAN(srvconf.event_handler);
	CLEAN(srvconf.pid_file);
	
	CLEAN(tmp_chunk_len);
#undef CLEAN
	
#define CLEAN(x) \
	srv->x = array_init();
	
	CLEAN(config_context);
	CLEAN(config_touched);
#undef CLEAN
	
	for (i = 0; i < FILE_CACHE_MAX; i++) {
		srv->mtime_cache[i].str = buffer_init();
	}
	
	srv->cur_ts = time(NULL);
	srv->startup_ts = srv->cur_ts;
	
	srv->conns = calloc(1, sizeof(*srv->conns));
	assert(srv->conns);
	
	srv->joblist = calloc(1, sizeof(*srv->joblist));
	assert(srv->joblist);
	
	srv->fdwaitqueue = calloc(1, sizeof(*srv->fdwaitqueue));
	assert(srv->fdwaitqueue);
	
	srv->file_cache = file_cache_init();
	assert(srv->file_cache);
	
	srv->srvconf.modules = array_init();
	
	/* use syslog */
	srv->log_error_fd = -1;

	srv->split_vals = array_init();
	
	srv->config_patches = buffer_array_init();
	for (i = 0; patches[i]; i++) {
		buffer *b;
		
		b = buffer_array_append_get_buffer(srv->config_patches);
		buffer_copy_string(b, patches[i]);
	}
	
	return srv;
}

static void server_free(server *srv) {
	size_t i;
	
	for (i = 0; i < FILE_CACHE_MAX; i++) {
		buffer_free(srv->mtime_cache[i].str);
	}
	
	buffer_array_free(srv->config_patches);
	
#define CLEAN(x) \
	buffer_free(srv->x);
	
	CLEAN(response_header);
	CLEAN(parse_full_path);
	CLEAN(ts_debug_str);
	CLEAN(ts_date_str);
	CLEAN(error_log);
	CLEAN(response_range);
	CLEAN(tmp_buf);
	CLEAN(file_cache_etag);
	CLEAN(range_buf);
	CLEAN(empty_string);
	
	CLEAN(srvconf.error_logfile);
	CLEAN(srvconf.groupname);
	CLEAN(srvconf.username);
	CLEAN(srvconf.changeroot);
	CLEAN(srvconf.bindhost);
	CLEAN(srvconf.errorfile_prefix);
	CLEAN(srvconf.license);
	CLEAN(srvconf.event_handler);
	CLEAN(srvconf.pid_file);
	
	CLEAN(tmp_chunk_len);
#undef CLEAN

#if 0
	fdevent_unregister(srv->ev, srv->fd);
#endif
	fdevent_free(srv->ev);
	
	connections_free(srv);
	free(srv->conns);
	
	if (srv->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			specific_config *s = srv->config_storage[i];

			if (!s) continue;
			
			buffer_free(s->document_root);
			buffer_free(s->server_name);
			buffer_free(s->server_tag);
			buffer_free(s->ssl_pemfile);
			buffer_free(s->ssl_ca_file);
			buffer_free(s->error_handler);
			buffer_free(s->dirlist_css);
			buffer_free(s->dirlist_encoding);
			array_free(s->indexfiles);
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
#undef CLEAN
	
	joblist_free(srv, srv->joblist);
	fdwaitqueue_free(srv, srv->fdwaitqueue);
	
	file_cache_free(srv, srv->file_cache);
	
	array_free(srv->srvconf.modules);
	array_free(srv->split_vals);
	
	free(srv);
}

static void show_version (void) {
#ifdef USE_OPENSSL
# define TEXT_SSL " (ssl)"
#else
# define TEXT_SSL
#endif
	char *b = PACKAGE_NAME "-" PACKAGE_VERSION TEXT_SSL \
" - a light and fast webserver\n" \
"Build-Date: " __DATE__ " " __TIME__ "\n";
;
#undef TEXT_SSL	
	write(STDOUT_FILENO, b, strlen(b));
}

static void show_help (void) {
#ifdef USE_OPENSSL
# define TEXT_SSL " (ssl)"
#else
# define TEXT_SSL
#endif
#ifdef HAVE_IPV6
# define TEXT_IPV6 " -6         use IPv6\n"
#else
# define TEXT_IPV6
#endif
	char *b = PACKAGE_NAME "-" PACKAGE_VERSION TEXT_SSL " ("__DATE__ " " __TIME__ ")" \
" - a light and fast webserver\n" \
"usage:\n" \
" -f <name>  filename of the config-file\n" \
" -D         don't go to background (default: go to background)\n" \
TEXT_IPV6 \
" -v         show version\n" \
" -h         show this help\n" \
"\n"
;
#undef TEXT_SSL	
#undef TEXT_IPV6
	write(STDOUT_FILENO, b, strlen(b));
}

int main (int argc, char **argv) {
	server *srv = NULL;
	int i_am_root;
	int o;
	int num_childs = 0;
	int pid_fd = -1, fd;
	size_t i;
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif
#ifdef HAVE_GETRLIMIT
	struct rlimit rlim;
#endif
	
#ifdef USE_ALARM
	struct itimerval interval;
	
	interval.it_interval.tv_sec = 1;
	interval.it_interval.tv_usec = 0;
	interval.it_value.tv_sec = 1;
	interval.it_value.tv_usec = 0;
#endif
	
	
	/* for nice %b handling in strfime() */
	setlocale(LC_TIME, "C");
	
	if (NULL == (srv = server_init())) {
		fprintf(stderr, "did this really happend ?\n");
		return -1;
	}
	
	/* init structs done */
	
	srv->srvconf.port = 0;
#ifdef HAVE_GETUID
	i_am_root = (getuid() == 0);
#else
	i_am_root = 0;
#endif
	srv->srvconf.dont_daemonize = 0;
	
	while(-1 != (o = getopt(argc, argv, "f:hvD"))) {
		switch(o) {
		case 'f': 
			if (config_read(srv, optarg)) { 
				server_free(srv);
				return -1;
			}
			break;
		case 'D': srv->srvconf.dont_daemonize = 1; break;
		case 'v': show_version(); return 0;
		case 'h': show_help(); return 0;
		default: 
			show_help();
			server_free(srv);
			return -1;
		}
	}
	
	if (!srv->config_storage) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"No configuration available. Try using -f option.");
		
		server_free(srv);
		return -1;
	}
	
	/* close stdin and stdout, as they are not needed */
	/* move stdin to /dev/null */
	if (-1 != (fd = open("/dev/null", O_RDONLY))) {
		close(STDIN_FILENO);
		dup2(fd, STDIN_FILENO);
		close(fd);
	}
	
	/* move stdout to /dev/null */
	if (-1 != (fd = open("/dev/null", O_WRONLY))) {
		close(STDOUT_FILENO);
		dup2(fd, STDOUT_FILENO);
		close(fd);
	}
	
	if (0 != config_set_defaults(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"setting default values failed");
		server_free(srv);
		return -1;
	}
	
	/* UID handling */
#ifdef HAVE_GETUID
	if (!i_am_root && (geteuid() == 0 || getegid() == 0)) {
		/* we are setuid-root */
		
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"Are you nuts ? Don't apply a SUID bit to this binary");
		
		server_free(srv);
		return -1;
	}
#endif
	
	/* check document-root */
	if (srv->config_storage[0]->document_root->used <= 1) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"document-root is not set\n");
		
		server_free(srv);
		
		return -1;
	}
	
	if (plugins_load(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"loading plugins finally failed");
		
		plugins_free(srv);
		server_free(srv);
		
		return -1;
	}
	
	/* open pid file BEFORE chroot */
	if (srv->srvconf.pid_file->used) {
		if (-1 == (pid_fd = open(srv->srvconf.pid_file->ptr, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
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
			
			if (-1 == (pid_fd = open(srv->srvconf.pid_file->ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"opening pid-file failed:", srv->srvconf.pid_file, strerror(errno));
				return -1;
			}
		}
	}
	
	if (i_am_root) {
		struct group *grp = NULL;
		struct passwd *pwd = NULL;
		int use_rlimit = 1;

#ifdef HAVE_VALGRIND_VALGRIND_H
		if (RUNNING_ON_VALGRIND) use_rlimit = 0;
#endif
		
#ifdef HAVE_GETRLIMIT
		if (0 != getrlimit(RLIMIT_NOFILE, &rlim)) {
			log_error_write(srv, __FILE__, __LINE__,
					"ss", "couldn't get 'max filedescriptors'",
					strerror(errno));
			return -1;
		}
		
		if (use_rlimit && srv->srvconf.max_fds) {
			/* set rlimits */
			
			rlim.rlim_cur = srv->srvconf.max_fds;
			rlim.rlim_max = srv->srvconf.max_fds;
			
			if (0 != setrlimit(RLIMIT_NOFILE, &rlim)) {
				log_error_write(srv, __FILE__, __LINE__,
						"ss", "couldn't set 'max filedescriptors'",
						strerror(errno));
				return -1;
			}
		}
		
		srv->max_fds = rlim.rlim_cur;
#else
		srv->max_fds = 4096;
#endif
		
		if (NULL == (srv->ev = fdevent_init(srv->max_fds + 1, srv->event_handler))) {
			log_error_write(srv, __FILE__, __LINE__,
					"s", "fdevent_init failed");
			return -1;
		}
		
#ifdef HAVE_PWD_H
		/* set user and group */
		if (srv->srvconf.username->used) {
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
		}
		
		if (srv->srvconf.groupname->used) {
			if (NULL == (grp = getgrnam(srv->srvconf.groupname->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb", 
					"can't find groupname", srv->srvconf.groupname);
				return -1;
			}
			if (grp->gr_gid == 0) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"I will not set gid to 0\n");
				return -1;
			}
		}
#endif		
		/* we need root-perms for port < 1024 */
		if (0 != network_init(srv)) {
			plugins_free(srv);
			server_free(srv);
			
			return -1;
		}
#ifdef HAVE_CHROOT	
		if (srv->srvconf.changeroot->used) {
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
		if (srv->srvconf.groupname->used) {
			setgid(grp->gr_gid);
			setgroups(0, NULL);
		}
		if (srv->srvconf.username->used && srv->srvconf.groupname->used)
			initgroups(srv->srvconf.username->ptr, grp->gr_gid);
		if (srv->srvconf.username->used) setuid(pwd->pw_uid);
#endif
	} else {
#ifdef HAVE_GETRLIMIT
		if (0 != getrlimit(RLIMIT_NOFILE, &rlim)) {
			log_error_write(srv, __FILE__, __LINE__,
					"ss", "couldn't get 'max filedescriptors'",
					strerror(errno));
			return -1;
		}
		
		srv->max_fds = rlim.rlim_cur;
#else
		srv->max_fds = 4096;
#endif
		
		if (NULL == (srv->ev = fdevent_init(srv->max_fds + 1, srv->event_handler))) {
			log_error_write(srv, __FILE__, __LINE__,
					"s", "fdevent_init failed");
			return -1;
		}
		
		if (0 != network_init(srv)) {
			plugins_free(srv);
			server_free(srv);
			
			return -1;
		}
	}
	
	if (HANDLER_GO_ON != plugins_call_init(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Initialization of plugins failed. Going down.");
		
		plugins_free(srv);
		network_close(srv);
		server_free(srv);
		
		return -1;
	}

#ifdef HAVE_FORK	
	/* network is up, let's deamonize ourself */
	if (srv->srvconf.dont_daemonize == 0) daemonize();
#endif
	
	/* write pid file */
	if (pid_fd != -1) {
		buffer_copy_long(srv->tmp_buf, getpid());
		buffer_append_string(srv->tmp_buf, "\n");
		write(pid_fd, srv->tmp_buf->ptr, srv->tmp_buf->used - 1);
		close(pid_fd);
		pid_fd = -1;
	}
	
	if (HANDLER_GO_ON != plugins_call_set_defaults(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Configuration of plugins failed. Going down.");
		
		plugins_free(srv);
		network_close(srv);
		server_free(srv);
		
		return -1;
	}
	
	/* dump unused config-keys */
	for (i = 0; srv->config && i < srv->config->used; i++) {
		data_unset *du = srv->config->data[i];
		
		if (NULL == array_get_element(srv->config_touched, du->key->ptr)) {
			log_error_write(srv, __FILE__, __LINE__, "sbs", 
					"WARNING: unknown config-key:",
					du->key,
					"(ignored)");
		}
	}
	
	if (srv->config_deprecated) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"Configuration contains deprecated keys. Going down.");
		
		plugins_free(srv);
		network_close(srv);
		server_free(srv);
		
		return -1;
	}
	
	if (-1 == log_error_open(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"opening errorlog failed, dying");
		
		plugins_free(srv);
		network_close(srv);
		server_free(srv);
		return -1;
	}
	
	/* kqueue needs a reset AFTER daemonize() */
	if (0 != network_register_fdevents(srv)) {
		plugins_free(srv);
		network_close(srv);
		server_free(srv);
		
		return -1;
	}
	
	/* get the current number of FDs */
	srv->cur_fds = open("/dev/null", O_RDONLY);
	close(srv->cur_fds);
	
	
#ifdef HAVE_SIGACTION
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
# if defined(SA_SIGINFO)
	act.sa_sigaction = sigaction_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
# else
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
# endif
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	
#elif defined(HAVE_SIGNAL)
	/* ignore the SIGPIPE from sendfile() */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGALRM, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGCHLD,  signal_handler);
#endif
	
#ifdef USE_ALARM
	signal(SIGALRM, signal_handler);
	
	/* setup periodic timer (1 second) */
	if (setitimer(ITIMER_REAL, &interval, NULL)) {
		log_error_write(srv, __FILE__, __LINE__, "setting timer failed");
		return -1;
	}
	
	getitimer(ITIMER_REAL, &interval);
#endif

#ifdef HAVE_FORK	
	/* start watcher and workers */
	num_childs = srv->srvconf.max_worker;
	if (num_childs > 0) {
		int child = 0;
		while (!child && !srv_shutdown) {
			if (num_childs > 0) {
				switch (fork()) {
				case -1:
					return -1;
				case 0:
					child = 1;
					break;
				default:
					num_childs--;
					break;
				}
			} else {
				int status;
				wait(&status);
				num_childs++;
			}
		}
		if (!child) return 0;
	}
#endif

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
				int cs = 0;
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
				
				/* trigger waitpid */
				srv->cur_ts = min_ts;
				
				/**
				 * check all connections for timeouts 
				 * 
				 */
				for (ndx = 0; ndx < conns->used; ndx++) {
					int changed = 0;
					connection *con;
					int t_diff;
					
					con = conns->ptr[ndx];

					if (con->state == CON_STATE_READ ||
					    con->state == CON_STATE_READ_POST) {
						if (con->request_count == 1) {
							if (srv->cur_ts - con->read_idle_ts > con->conf.max_read_idle) {
								/* time - out */
#if 0
								log_error_write(srv, __FILE__, __LINE__, "sd", 
										"connection closed - read-timeout:", con->fd);
#endif
								connection_set_state(srv, con, CON_STATE_ERROR);
								changed = 1;
							}
						} else {
							if (srv->cur_ts - con->read_idle_ts > con->conf.max_keep_alive_idle) {
								/* time - out */
#if 0
								log_error_write(srv, __FILE__, __LINE__, "sd", 
										"connection closed - read-timeout:", con->fd);
#endif
								connection_set_state(srv, con, CON_STATE_ERROR);
								changed = 1;
							}
						}
					}
					
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
#if 1
							log_error_write(srv, __FILE__, __LINE__, "sd", 
									"connection closed - write-request-timeout:", con->fd);
#endif
							connection_set_state(srv, con, CON_STATE_ERROR);
							changed = 1;
						}
					}
					/* we don't like div by zero */
					if (0 == (t_diff = srv->cur_ts - con->connection_start)) t_diff = 1;
	
					if (con->traffic_limit_reached && 
					    ((con->bytes_written / t_diff) < con->conf.kbytes_per_second * 1024)) {
						/* enable connection again */
						con->traffic_limit_reached = 0;
						
						changed = 1;
					}
					
					if (changed) {
						connection_state_machine(srv, con);
					}
					con->bytes_written_cur_second = 0;
					*(con->conf.global_bytes_per_second_cnt_ptr) = 0;
					
#if 0
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
				
				if (cs == 1) fprintf(stderr, "\n");
			}
		}

		/* handle out of fd condition */
		if (!srv->sockets_disabled &&
		    srv->cur_fds + srv->want_fds > srv->max_fds * 0.9) {
			
			/* disable server-fds */
			
			for (i = 0; i < srv->srv_sockets.used; i++) {
				server_socket *srv_socket = srv->srv_sockets.ptr[i];
				fdevent_event_del(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd);
			}
			
			log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets disabled, out-of-fds");
			
			srv->sockets_disabled = 1;
		} else if (srv->sockets_disabled &&
			   srv->cur_fds + srv->want_fds < srv->max_fds * 0.8) {
			
			for (i = 0; i < srv->srv_sockets.used; i++) {
				server_socket *srv_socket = srv->srv_sockets.ptr[i];
				fdevent_event_add(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd, FDEVENT_IN);
			}
			
			log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets enabled, out-of-fds");
			
			srv->sockets_disabled = 0;
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
			int revents;
			int fd_ndx;
#if 0
			if (n > 0) {
				log_error_write(srv, __FILE__, __LINE__, "sd", 
						"polls:", n);
			}
#endif			
			fd_ndx = -1;
			do {
				fdevent_handler handler;
				void *context;
				handler_t r;
				
				fd_ndx  = fdevent_event_next_fdndx (srv->ev, fd_ndx);
				revents = fdevent_event_get_revent (srv->ev, fd_ndx);
				fd      = fdevent_event_get_fd     (srv->ev, fd_ndx);
				handler = fdevent_get_handler(srv->ev, fd);
				context = fdevent_get_context(srv->ev, fd);
				
				/* connection_handle_fdevent needs a joblist_append */
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sdd", 
						"event for", fd, revents);
#endif				
				switch (r = (*handler)(srv, context, revents)) {
				case HANDLER_FINISHED:
				case HANDLER_GO_ON:
				case HANDLER_WAIT_FOR_EVENT:
				case HANDLER_WAIT_FOR_FD:
					break;
				case HANDLER_ERROR:
					/* should never happen */
					SEGFAULT();
					break;
				default:
					log_error_write(srv, __FILE__, __LINE__, "d", r);
					break;
				}
			} while (--n > 0);
		} else if (n < 0 && errno != EINTR) {
			log_error_write(srv, __FILE__, __LINE__, "ss", 
					"fdevent_poll failed:", 
					strerror(errno));
		}
		
		for (ndx = 0; ndx < srv->joblist->used; ndx++) {
			connection *con = srv->joblist->ptr[ndx];
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
			
			con->in_joblist = 0;
		}
		
		srv->joblist->used = 0;
	}
	
	if (srv->srvconf.pid_file->used &&
	    srv->srvconf.changeroot->used == 0) {
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
	
	/* clean-up */
	log_error_close(srv);
	network_close(srv);
	plugins_free(srv);
	server_free(srv);
	
	return 0;
}
