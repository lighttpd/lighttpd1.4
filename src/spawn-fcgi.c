#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_PWD_H
#include <grp.h>
#include <pwd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define FCGI_LISTENSOCK_FILENO 0

#include "sys-socket.h"

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

/* for solaris 2.5 and netbsd 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifdef HAVE_SYS_UN_H
int fcgi_spawn_connection(char *appPath, char **appArgv, char *addr, unsigned short port, const char *unixsocket, int fork_count, int child_count, int pid_fd, int nofork) {
	int fcgi_fd;
	int socket_type, status, rc = 0;
	struct timeval tv = { 0, 100 * 1000 };

	struct sockaddr_un fcgi_addr_un;
	struct sockaddr_in fcgi_addr_in;
	struct sockaddr *fcgi_addr;

	socklen_t servlen;

	if (child_count < 2) {
		child_count = 5;
	}

	if (child_count > 256) {
		child_count = 256;
	}


	if (unixsocket) {
		memset(&fcgi_addr_un, 0, sizeof(fcgi_addr_un));

		fcgi_addr_un.sun_family = AF_UNIX;
		strcpy(fcgi_addr_un.sun_path, unixsocket);

#ifdef SUN_LEN
		servlen = SUN_LEN(&fcgi_addr_un);
#else
		/* stevens says: */
		servlen = strlen(fcgi_addr_un.sun_path) + sizeof(fcgi_addr_un.sun_family);
#endif
		socket_type = AF_UNIX;
		fcgi_addr = (struct sockaddr *) &fcgi_addr_un;
	} else {
		memset(&fcgi_addr_in, 0, sizeof(fcgi_addr_in));
		fcgi_addr_in.sin_family = AF_INET;
		if (addr != NULL) {
			fcgi_addr_in.sin_addr.s_addr = inet_addr(addr);
		} else {
			fcgi_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
		}
		fcgi_addr_in.sin_port = htons(port);
		servlen = sizeof(fcgi_addr_in);

		socket_type = AF_INET;
		fcgi_addr = (struct sockaddr *) &fcgi_addr_in;
	}

	if (-1 == (fcgi_fd = socket(socket_type, SOCK_STREAM, 0))) {
		fprintf(stderr, "%s.%d\n",
			__FILE__, __LINE__);
		return -1;
	}

	if (-1 == connect(fcgi_fd, fcgi_addr, servlen)) {
		/* server is not up, spawn in  */
		pid_t child;
		int val;

		if (unixsocket) unlink(unixsocket);

		close(fcgi_fd);

		/* reopen socket */
		if (-1 == (fcgi_fd = socket(socket_type, SOCK_STREAM, 0))) {
			fprintf(stderr, "%s.%d\n",
				__FILE__, __LINE__);
			return -1;
		}

		val = 1;
		if (setsockopt(fcgi_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
			fprintf(stderr, "%s.%d\n",
				__FILE__, __LINE__);
			return -1;
		}

		/* create socket */
		if (-1 == bind(fcgi_fd, fcgi_addr, servlen)) {
			fprintf(stderr, "%s.%d: bind failed: %s\n",
				__FILE__, __LINE__,
				strerror(errno));
			return -1;
		}

		if (-1 == listen(fcgi_fd, 1024)) {
			fprintf(stderr, "%s.%d: fd = -1\n",
				__FILE__, __LINE__);
			return -1;
		}

		while (fork_count-- > 0) {

			if (!nofork) {
				child = fork();
			} else {
				child = 0;
			}

			switch (child) {
			case 0: {
				char cgi_childs[64];
				int max_fd = 0;

				int i = 0;

				/* loose control terminal */
				setsid();

				/* is safe as we limit to 256 childs */
				sprintf(cgi_childs, "PHP_FCGI_CHILDREN=%d", child_count);

				if(fcgi_fd != FCGI_LISTENSOCK_FILENO) {
					close(FCGI_LISTENSOCK_FILENO);
					dup2(fcgi_fd, FCGI_LISTENSOCK_FILENO);
					close(fcgi_fd);
				}

				max_fd = open("/dev/null", O_RDWR);
				close(STDERR_FILENO);
				dup2(max_fd, STDERR_FILENO);
				close(max_fd);

				max_fd = open("/dev/null", O_RDWR);
				close(STDOUT_FILENO);
				dup2(max_fd, STDOUT_FILENO);
				close(max_fd);

				/* we don't need the client socket */
				for (i = 3; i < max_fd; i++) {
					if (i != FCGI_LISTENSOCK_FILENO) close(i);
				}

				/* create environment */

				putenv(cgi_childs);

				/* fork and replace shell */
				if (appArgv) {
					execv(appArgv[0], appArgv);

				} else {
					char *b = malloc(strlen("exec ") + strlen(appPath) + 1);
					strcpy(b, "exec ");
					strcat(b, appPath);

					/* exec the cgi */
					execl("/bin/sh", "sh", "-c", b, (char *)NULL);
				}

				exit(errno);

				break;
			}
			case -1:
				/* error */
				break;
			default:
				/* father */

				/* wait */
				select(0, NULL, NULL, NULL, &tv);

				switch (waitpid(child, &status, WNOHANG)) {
				case 0:
					fprintf(stdout, "%s.%d: child spawned successfully: PID: %d\n",
						__FILE__, __LINE__,
						child);

					/* write pid file */
					if (pid_fd != -1) {
						/* assume a 32bit pid_t */
						char pidbuf[12];

						snprintf(pidbuf, sizeof(pidbuf) - 1, "%d", child);

						write(pid_fd, pidbuf, strlen(pidbuf));
						/* avoid eol for the last one */
						if (fork_count != 0) {
							write(pid_fd, "\n", 1);
						}
					}

					break;
				case -1:
					break;
				default:
					if (WIFEXITED(status)) {
						fprintf(stderr, "%s.%d: child exited with: %d\n",
							__FILE__, __LINE__, WEXITSTATUS(status));
						rc = WEXITSTATUS(status);
					} else if (WIFSIGNALED(status)) {
						fprintf(stderr, "%s.%d: child signaled: %d\n",
							__FILE__, __LINE__,
							WTERMSIG(status));
						rc = 1;
					} else {
						fprintf(stderr, "%s.%d: child died somehow: %d\n",
							__FILE__, __LINE__,
							status);
						rc = status;
					}
				}

				break;
			}
		}
		close(pid_fd);
		pid_fd = -1;
	} else {
		fprintf(stderr, "%s.%d: socket is already used, can't spawn\n",
			__FILE__, __LINE__);
		return -1;
	}

	close(fcgi_fd);

	return rc;
}


void show_version () {
	char *b = "spawn-fcgi" "-" PACKAGE_VERSION \
" - spawns fastcgi processes\n"
;
	write(1, b, strlen(b));
}

void show_help () {
	char *b = \
"Usage: spawn-fcgi [options] -- <fcgiapp> [fcgi app arguments]\n" \
"\n" \
"spawn-fcgi v" PACKAGE_VERSION " - spawns fastcgi processes\n" \
"\n" \
"Options:\n" \
" -f <fcgiapp> filename of the fcgi-application\n" \
" -a <addr>    bind to ip address\n" \
" -p <port>    bind to tcp-port\n" \
" -s <path>    bind to unix-domain socket\n" \
" -C <childs>  (PHP only) numbers of childs to spawn (default 5)\n" \
" -F <childs>  numbers of childs to fork (default 1)\n" \
" -P <path>    name of PID-file for spawed process\n" \
" -n           no fork (for daemontools)\n" \
" -v           show version\n" \
" -h           show this help\n" \
"(root only)\n" \
" -c <dir>     chroot to directory\n" \
" -u <user>    change to user-id\n" \
" -g <group>   change to group-id\n" \
;
	write(1, b, strlen(b));
}


int main(int argc, char **argv) {
	char *fcgi_app = NULL, *changeroot = NULL, *username = NULL,
               *groupname = NULL, *unixsocket = NULL, *pid_file = NULL,
                *addr = NULL;
	char **fcgi_app_argv = { NULL };
	unsigned short port = 0;
	int child_count = 5;
	int fork_count = 1;
	int i_am_root, o;
	int pid_fd = -1;
	int nofork = 0;
	struct sockaddr_un un;

	i_am_root = (getuid() == 0);

	while (-1 != (o = getopt(argc, argv, "c:f:g:hna:p:u:vC:F:s:P:"))) {
		switch(o) {
		case 'f': fcgi_app = optarg; break;
		case 'a': addr = optarg;/* ip addr */ break;
		case 'p': port = strtol(optarg, NULL, 10);/* port */ break;
		case 'C': child_count = strtol(optarg, NULL, 10);/*  */ break;
		case 'F': fork_count = strtol(optarg, NULL, 10);/*  */ break;
		case 's': unixsocket = optarg; /* unix-domain socket */ break;
		case 'c': if (i_am_root) { changeroot = optarg; }/* chroot() */ break;
		case 'u': if (i_am_root) { username = optarg; } /* set user */ break;
		case 'g': if (i_am_root) { groupname = optarg; } /* set group */ break;
		case 'n': nofork = 1; break;
		case 'P': pid_file = optarg; /* PID file */ break;
		case 'v': show_version(); return 0;
		case 'h': show_help(); return 0;
		default:
			show_help();
			return -1;
		}
	}

	if (optind < argc) {
		fcgi_app_argv = &argv[optind];
	}

	if ((fcgi_app == NULL && fcgi_app_argv == NULL) || (port == 0 && unixsocket == NULL)) {
		show_help();
		return -1;
	}

	if (unixsocket && port) {
		fprintf(stderr, "%s.%d: %s\n",
			__FILE__, __LINE__,
			"either a unix domain socket or a tcp-port, but not both\n");

		return -1;
	}

	if (unixsocket && strlen(unixsocket) > sizeof(un.sun_path) - 1) {
		fprintf(stderr, "%s.%d: %s\n",
			__FILE__, __LINE__,
			"path of the unix socket is too long\n");

		return -1;
	}

	/* UID handling */
	if (!i_am_root && (geteuid() == 0 || getegid() == 0)) {
		/* we are setuid-root */

		fprintf(stderr, "%s.%d: %s\n",
			__FILE__, __LINE__,
			"Are you nuts ? Don't apply a SUID bit to this binary\n");

		return -1;
	}

	if (pid_file &&
	    (-1 == (pid_fd = open(pid_file, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)))) {
		struct stat st;
		if (errno != EEXIST) {
			fprintf(stderr, "%s.%d: opening pid-file '%s' failed: %s\n",
				__FILE__, __LINE__,
				pid_file, strerror(errno));

			return -1;
		}

		/* ok, file exists */

		if (0 != stat(pid_file, &st)) {
			fprintf(stderr, "%s.%d: stating pid-file '%s' failed: %s\n",
				__FILE__, __LINE__,
				pid_file, strerror(errno));

			return -1;
		}

		/* is it a regular file ? */

		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "%s.%d: pid-file exists and isn't regular file: '%s'\n",
				__FILE__, __LINE__,
				pid_file);

			return -1;
		}

		if (-1 == (pid_fd = open(pid_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
			fprintf(stderr, "%s.%d: opening pid-file '%s' failed: %s\n",
				__FILE__, __LINE__,
				pid_file, strerror(errno));

			return -1;
		}
	}

	if (i_am_root) {
		struct group *grp = NULL;
		struct passwd *pwd = NULL;

		/* set user and group */

		if (username) {
			if (NULL == (pwd = getpwnam(username))) {
				fprintf(stderr, "%s.%d: %s, %s\n",
					__FILE__, __LINE__,
					"can't find username", username);
				return -1;
			}

			if (pwd->pw_uid == 0) {
				fprintf(stderr, "%s.%d: %s\n",
					__FILE__, __LINE__,
					"I will not set uid to 0\n");
				return -1;
			}
		}

		if (groupname) {
			if (NULL == (grp = getgrnam(groupname))) {
				fprintf(stderr, "%s.%d: %s %s\n",
					__FILE__, __LINE__,
					"can't find groupname",
					groupname);
				return -1;
			}
			if (grp->gr_gid == 0) {
				fprintf(stderr, "%s.%d: %s\n",
					__FILE__, __LINE__,
					"I will not set gid to 0\n");
				return -1;
			}

			/* do the change before we do the chroot() */
			setgid(grp->gr_gid);
			setgroups(0, NULL); 

			if (username) {
				initgroups(username, grp->gr_gid);
			}

		}

		if (changeroot) {
			if (-1 == chroot(changeroot)) {
				fprintf(stderr, "%s.%d: %s %s\n",
					__FILE__, __LINE__,
					"chroot failed: ", strerror(errno));
				return -1;
			}
			if (-1 == chdir("/")) {
				fprintf(stderr, "%s.%d: %s %s\n",
					__FILE__, __LINE__,
					"chdir failed: ", strerror(errno));
				return -1;
			}
		}

		/* drop root privs */
		if (username) {
			setuid(pwd->pw_uid);
		}
	}

       return fcgi_spawn_connection(fcgi_app, fcgi_app_argv, addr, port, unixsocket, fork_count, child_count, pid_fd, nofork);
}
#else
int main() {
	return -1;
}
#endif
