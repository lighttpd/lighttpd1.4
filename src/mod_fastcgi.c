#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>

#include "buffer.h"
#include "server.h"
#include "keyvalue.h"
#include "log.h"

#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "response.h"
#include "joblist.h"

#include "plugin.h"

#include "inet_ntop_cache.h"

#include <fastcgi.h>
#include <stdio.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"


#ifndef UNIX_PATH_MAX
# define UNIX_PATH_MAX 108
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif


/*
 * 
 * TODO:
 * 
 * - add timeout for a connect to a non-fastcgi process
 *   (use state_timestamp + state)
 * 
 */

typedef struct fcgi_proc {
	size_t id; /* id will be between 1 and max_procs */
	buffer *socket; /* config.socket + "-" + id */
	unsigned port;  /* config.port + pno */
	
	pid_t pid;   /* PID of the spawned process (0 if not spawned locally) */


	size_t load; /* number of requests waiting on this process */

	time_t last_used; /* see idle_timeout */
	size_t requests;  /* see max_requests */
	struct fcgi_proc *prev, *next; /* see first */
	
	time_t disable_ts; /* replace by host->something */
	
	int is_local;

	enum { PROC_STATE_UNSET,            /* init-phase */
			PROC_STATE_RUNNING, /* alive */
			PROC_STATE_DIED_WAIT_FOR_PID,
			PROC_STATE_KILLED,  /* was killed as we don't have the load anymore */
			PROC_STATE_DIED,    /* marked as dead, should be restarted */
			PROC_STATE_DISABLED /* proc disabled as it resulted in an error */
	} state; 
} fcgi_proc;

typedef struct {
	/* list of processes handling this extension
	 * sorted by lowest load
	 *
	 * whenever a job is done move it up in the list
	 * until it is sorted, move it down as soon as the 
	 * job is started
	 */
	fcgi_proc *first; 
	fcgi_proc *unused_procs; 

	/* 
	 * spawn at least min_procs, at max_procs.
	 *
	 * as soon as the load of the first entry 
	 * is max_load_per_proc we spawn a new one
	 * and add it to the first entry and give it 
	 * the load
	 * 
	 */

	unsigned short min_procs;
	unsigned short max_procs;
	size_t num_procs;    /* how many procs are started */
	size_t active_procs; /* how many of them are really running */

	unsigned short max_load_per_proc;

	/*
	 * kick the process from the list if it was not
	 * used for idle_timeout until min_procs is 
	 * reached. this helps to get the processlist
	 * small again we had a small peak load.
	 *
	 */
	
	unsigned short idle_timeout;
	
	/*
	 * time after a disabled remote connection is tried to be re-enabled
	 * 
	 * 
	 */
	
	unsigned short disable_time;

	/*
	 * same fastcgi processes get a little bit larger
	 * than wanted. max_requests_per_proc kills a 
	 * process after a number of handled requests.
	 *
	 */
	size_t max_requests_per_proc;
	

	/* config */

	/* 
	 * host:port 
	 *
	 * if host is one of the local IP adresses the 
	 * whole connection is local
	 *
	 * if tcp/ip should be used host AND port have
	 * to be specified 
	 * 
	 */ 
	buffer *host; 
	unsigned short port;

	/*
	 * Unix Domain Socket
	 *
	 * instead of TCP/IP we can use Unix Domain Sockets
	 * - more secure (you have fileperms to play with)
	 * - more control (on locally)
	 * - more speed (no extra overhead)
	 */
	buffer *unixsocket;

	/* if socket is local we can start the fastcgi 
	 * process ourself
	 *
	 * bin-path is the path to the binary
	 *
	 * check min_procs and max_procs for the number
	 * of process to start-up
	 */
	buffer *bin_path; 
	
	/* bin-path is set bin-environment is taken to 
	 * create the environement before starting the
	 * FastCGI process
	 * 
	 */
	array *bin_env;
	
	array *bin_env_copy;
	
	/*
	 * docroot-translation between URL->phys and the 
	 * remote host
	 *
	 * reasons:
	 * - different dir-layout if remote
	 * - chroot if local
	 *
	 */
	buffer *docroot;

	/*
	 * fastcgi-mode:
	 * - responser
	 * - authorizer
	 *
	 */
	unsigned short mode;

	/*
	 * check_local tell you if the phys file is stat()ed 
	 * or not. FastCGI doesn't care if the service is
	 * remote. If the web-server side doesn't contain
	 * the fastcgi-files we should not stat() for them
	 * and say '404 not found'.
	 */
	unsigned short check_local;

		
	ssize_t load; /* replace by host->load */

	size_t max_id; /* corresponds most of the time to
	num_procs.
	
	only if a process is killed max_id waits for the process itself
	to die and decrements its afterwards */
} fcgi_extension_host;

/*
 * one extension can have multiple hosts assigned
 * one host can spawn additional processes on the same 
 *   socket (if we control it)
 *
 * ext -> host -> procs
 *    1:n     1:n
 *
 * if the fastcgi process is remote that whole goes down 
 * to
 *
 * ext -> host -> procs
 *    1:n     1:1 
 *
 * in case of PHP and FCGI_CHILDREN we have again a procs
 * but we don't control it directly.
 *
 */

typedef struct {
	buffer *key; /* like .php */

	fcgi_extension_host **hosts;
	
	size_t used;
	size_t size;
} fcgi_extension;

typedef struct {
	fcgi_extension **exts;

	size_t used;
	size_t size;
} fcgi_exts;


typedef struct {
	fcgi_exts *exts; 
	
	int debug;
} plugin_config;

typedef struct {
	size_t *ptr;
	size_t used;
	size_t size;
} buffer_uint;

typedef struct {
	char **ptr;
	
	size_t size;
	size_t used;
} char_array;

/* generic plugin data, shared between all connections */
typedef struct {
	PLUGIN_DATA;
	buffer_uint fcgi_request_id;
	
	buffer *fcgi_env;
	
	buffer *path;
	buffer *parse_response;
	
	plugin_config **config_storage;
	
	plugin_config conf; /* this is only used as long as no handler_ctx is setup */
} plugin_data;

/* connection specific data */
typedef enum { FCGI_STATE_INIT, FCGI_STATE_CONNECT, FCGI_STATE_PREPARE_WRITE, 
		FCGI_STATE_WRITE, FCGI_STATE_READ 
} fcgi_connection_state_t;

typedef struct {
	buffer  *response; 
	size_t   response_len;
	int      response_type;
	int      response_padding;
	size_t   response_request_id;
	
	fcgi_proc *proc;
	fcgi_extension_host *host;
	
	fcgi_connection_state_t state;
	time_t   state_timestamp;
	
	int      reconnects; /* number of reconnect attempts */
	
	buffer   *write_buffer;
	size_t    write_offset;
	
	read_buffer *rb;
	
	buffer   *response_header;
	
	int       delayed;   /* flag to mark that the connect() is delayed */
	
	size_t    request_id;
	int       fd;        /* fd to the fastcgi process */
	int       fde_ndx;   /* index into the fd-event buffer */

	size_t    path_info_offset; /* start of path_info in uri.path */
	
	plugin_config conf;
	
	connection *remote_conn;  /* dumb pointer */
	plugin_data *plugin_data; /* dumb pointer */
} handler_ctx;


/* ok, we need a prototype */
static handler_t fcgi_handle_fdevent(void *s, void *ctx, int revents);

int fcgi_proclist_sort_down(server *srv, fcgi_extension_host *host, fcgi_proc *proc);



static handler_ctx * handler_ctx_init() {
	handler_ctx * hctx;
	
	hctx = calloc(1, sizeof(*hctx));
	assert(hctx);
	
	hctx->fde_ndx = -1;
	
	hctx->response = buffer_init();
	hctx->response_header = buffer_init();
	hctx->write_buffer = buffer_init();
	
	hctx->request_id = 0;
	hctx->state = FCGI_STATE_INIT;
	hctx->proc = NULL;
	
	hctx->response_len = 0;
	hctx->response_type = 0;
	hctx->response_padding = 0;
	hctx->response_request_id = 0;
	hctx->fd = -1;
	
	hctx->reconnects = 0;
	
	return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
	buffer_free(hctx->response);
	buffer_free(hctx->response_header);
	buffer_free(hctx->write_buffer);
	
	if (hctx->rb) {
		if (hctx->rb->ptr) free(hctx->rb->ptr);
		free(hctx->rb);
	}
	
	free(hctx);
}

fcgi_proc *fastcgi_process_init() {
	fcgi_proc *f;

	f = calloc(1, sizeof(*f));
	f->socket = buffer_init();
	
	f->prev = NULL;
	f->next = NULL;
	
	return f;
}

void fastcgi_process_free(fcgi_proc *f) {
	if (!f) return;
	
	fastcgi_process_free(f->next);
	
	buffer_free(f->socket);
	
	free(f);
}

fcgi_extension_host *fastcgi_host_init() {
	fcgi_extension_host *f;

	f = calloc(1, sizeof(*f));

	f->host = buffer_init();
	f->unixsocket = buffer_init();
	f->docroot = buffer_init();
	f->bin_path = buffer_init();
	f->bin_env = array_init();
	f->bin_env_copy = array_init();
	
	return f;
}

void fastcgi_host_free(fcgi_extension_host *h) {
	if (!h) return;
	
	buffer_free(h->host);
	buffer_free(h->unixsocket);
	buffer_free(h->docroot);
	buffer_free(h->bin_path);
	array_free(h->bin_env);
	array_free(h->bin_env_copy);
	
	fastcgi_process_free(h->first);
	fastcgi_process_free(h->unused_procs);
	
	free(h);
	
}

fcgi_exts *fastcgi_extensions_init() {
	fcgi_exts *f;

	f = calloc(1, sizeof(*f));
	
	return f;
}

void fastcgi_extensions_free(fcgi_exts *f) {
	size_t i;
	
	if (!f) return;
	
	for (i = 0; i < f->used; i++) {
		fcgi_extension *fe;
		size_t j;
		
		fe = f->exts[i];
		
		for (j = 0; j < fe->used; j++) {
			fcgi_extension_host *h;
			
			h = fe->hosts[j];
			
			fastcgi_host_free(h);
		}
		
		buffer_free(fe->key);
		free(fe->hosts);
		
		free(fe);
	}
	
	free(f->exts);
	
	free(f);
}

int fastcgi_extension_insert(fcgi_exts *ext, buffer *key, fcgi_extension_host *fh) {
	fcgi_extension *fe;
	size_t i;

	/* there is something */

	for (i = 0; i < ext->used; i++) {
		if (buffer_is_equal(key, ext->exts[i]->key)) {
			break;
		}
	}

	if (i == ext->used) {
		/* filextension is new */
		fe = calloc(1, sizeof(*fe));
		assert(fe);
		fe->key = buffer_init();
		buffer_copy_string_buffer(fe->key, key);

		/* */

		if (ext->size == 0) {
			ext->size = 8;
			ext->exts = malloc(ext->size * sizeof(*(ext->exts)));
			assert(ext->exts);
		} else if (ext->used == ext->size) {
			ext->size += 8;
			ext->exts = realloc(ext->exts, ext->size * sizeof(*(ext->exts)));
			assert(ext->exts);
		}
		ext->exts[ext->used++] = fe;
	} else {
		fe = ext->exts[i];
	}

	if (fe->size == 0) {
		fe->size = 4;
		fe->hosts = malloc(fe->size * sizeof(*(fe->hosts)));
		assert(fe->hosts);
	} else if (fe->size == fe->used) {
		fe->size += 4;
		fe->hosts = realloc(fe->hosts, fe->size * sizeof(*(fe->hosts)));
		assert(fe->hosts);
	}

	fe->hosts[fe->used++] = fh; 

	return 0;
	
}

INIT_FUNC(mod_fastcgi_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->fcgi_env = buffer_init();
	
	p->path = buffer_init();
	p->parse_response = buffer_init();
	
	return p;
}


FREE_FUNC(mod_fastcgi_free) {
	plugin_data *p = p_d;
	buffer_uint *r = &(p->fcgi_request_id);
	
	UNUSED(srv);

	if (r->ptr) free(r->ptr);
	
	buffer_free(p->fcgi_env);
	buffer_free(p->path);
	buffer_free(p->parse_response);
	
	if (p->config_storage) {
		size_t i, j, n;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			fcgi_exts *exts;
			
			if (!s) continue;
			
			exts = s->exts;

			for (j = 0; j < exts->used; j++) {
				fcgi_extension *ex;
				
				ex = exts->exts[j];
				
				for (n = 0; n < ex->used; n++) {
					fcgi_proc *proc;
					fcgi_extension_host *host;
					
					host = ex->hosts[n];
					
					for (proc = host->first; proc; proc = proc->next) {
						if (proc->pid != 0) kill(proc->pid, SIGTERM);
						
						if (proc->is_local && 
						    !buffer_is_empty(proc->socket)) {
							unlink(proc->socket->ptr);
						}
					}
					
					for (proc = host->unused_procs; proc; proc = proc->next) {
						if (proc->pid != 0) kill(proc->pid, SIGTERM);
						
						if (proc->is_local && 
						    !buffer_is_empty(proc->socket)) {
							unlink(proc->socket->ptr);
						}
					}
				}
			}
			
			fastcgi_extensions_free(s->exts);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	free(p);
	
	return HANDLER_GO_ON;
}

static int env_add(char_array *env, const char *key, size_t key_len, const char *val, size_t val_len) {
	char *dst;
	
	if (!key || !val) return -1;
	
	dst = malloc(key_len + val_len + 3);
	memcpy(dst, key, key_len);
	dst[key_len] = '=';
	/* add the \0 from the value */
	memcpy(dst + key_len + 1, val, val_len + 1);
	
	if (env->size == 0) {
		env->size = 16;
		env->ptr = malloc(env->size * sizeof(*env->ptr));
	} else if (env->size == env->used) {
		env->size += 16;
		env->ptr = realloc(env->ptr, env->size * sizeof(*env->ptr));
	}
	
	env->ptr[env->used++] = dst;
	
	return 0;
}

static int fcgi_spawn_connection(server *srv, 
				 plugin_data *p,
				 fcgi_extension_host *host,
				 fcgi_proc *proc) {
	int fcgi_fd;
	int socket_type, status;
	struct timeval tv = { 0, 100 * 1000 };
#ifdef HAVE_SYS_UN_H
	struct sockaddr_un fcgi_addr_un;
#endif
	struct sockaddr_in fcgi_addr_in;
	struct sockaddr *fcgi_addr;
	
	socklen_t servlen;
	
#ifndef HAVE_FORK
	return -1;
#endif
	
	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sdb",
				"new proc, socket:", proc->port, proc->socket);
	}
		
	if (!buffer_is_empty(proc->socket)) {
		memset(&fcgi_addr, 0, sizeof(fcgi_addr));
		
#ifdef HAVE_SYS_UN_H
		fcgi_addr_un.sun_family = AF_UNIX;
		strcpy(fcgi_addr_un.sun_path, proc->socket->ptr);
		
#ifdef SUN_LEN
		servlen = SUN_LEN(&fcgi_addr_un);
#else
		/* stevens says: */
		servlen = proc->socket - 1 + sizeof(fcgi_addr_un.sun_family);
#endif
		socket_type = AF_UNIX;
		fcgi_addr = (struct sockaddr *) &fcgi_addr_un;
#else
		log_error_write(srv, __FILE__, __LINE__, "s",
				"ERROR: Unix Domain sockets are not supported.");
		return -1;
#endif
	} else {
		fcgi_addr_in.sin_family = AF_INET;
		
		if (buffer_is_empty(host->host)) {
			fcgi_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
		} else {
			struct hostent *he;
			
			/* set a usefull default */
			fcgi_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
			
			
			if (NULL == (he = gethostbyname(host->host->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, 
						"ssb", "gethostbyname failed: ", 
						hstrerror(h_errno), host->host);
				return -1;
			}
			
			if (he->h_addrtype != AF_INET) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "addr-type != AF_INET: ", he->h_addrtype);
				return -1;
			}
			
			if (he->h_length != sizeof(struct in_addr)) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "addr-length != sizeof(in_addr): ", he->h_length);
				return -1;
			}
			
			memcpy(&(fcgi_addr_in.sin_addr.s_addr), he->h_addr_list[0], he->h_length);
			
		}
		fcgi_addr_in.sin_port = htons(proc->port);
		servlen = sizeof(fcgi_addr_in);
		
		socket_type = AF_INET;
		fcgi_addr = (struct sockaddr *) &fcgi_addr_in;
	}
	
	if (-1 == (fcgi_fd = socket(socket_type, SOCK_STREAM, 0))) {
		log_error_write(srv, __FILE__, __LINE__, "ss", 
				"failed:", strerror(errno));
		return -1;
	}
	
	if (-1 == connect(fcgi_fd, fcgi_addr, servlen)) {
		/* server is not up, spawn in  */
		pid_t child;
		int val;
		
		if (!buffer_is_empty(proc->socket)) {
			unlink(proc->socket->ptr);
		}
		
		close(fcgi_fd);
		
		/* reopen socket */
		if (-1 == (fcgi_fd = socket(socket_type, SOCK_STREAM, 0))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", 
				"socket failed:", strerror(errno));
			return -1;
		}
		
		val = 1;
		if (setsockopt(fcgi_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ss", 
					"socketsockopt failed:", strerror(errno));
			return -1;
		}
		
		/* create socket */
		if (-1 == bind(fcgi_fd, fcgi_addr, servlen)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", 
				"bind failed:", strerror(errno));
			return -1;
		}
		
		if (-1 == listen(fcgi_fd, 1024)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", 
				"listen failed:", strerror(errno));
			return -1;
		}
		
#ifdef HAVE_FORK	
		switch ((child = fork())) {
		case 0: {
			buffer *b;
			size_t i = 0;
			char_array env;
			
			
			/* create environment */
			env.ptr = NULL;
			env.size = 0;
			env.used = 0;
			
			if(fcgi_fd != FCGI_LISTENSOCK_FILENO) {
				close(FCGI_LISTENSOCK_FILENO);
				dup2(fcgi_fd, FCGI_LISTENSOCK_FILENO);
				close(fcgi_fd);
			}
			
			/* we don't need the client socket */
			for (i = 3; i < 256; i++) {
				close(i);
			}
			
			/* build clean environment */
			if (host->bin_env_copy->used) {
				for (i = 0; i < host->bin_env_copy->used; i++) {
					data_string *ds = (data_string *)host->bin_env_copy->data[i];
					char *ge;
					
					if (NULL != (ge = getenv(ds->value->ptr))) {
						env_add(&env, CONST_BUF_LEN(ds->value), ge, strlen(ge));
					}
				}
			} else {
				for (i = 0; environ[i]; i++) {
					char *eq;
					
					if (NULL != (eq = strchr(environ[i], '='))) {
						env_add(&env, environ[i], eq - environ[i], eq+1, strlen(eq+1));
					}
				}
			}
			
			/* create environment */
			for (i = 0; i < host->bin_env->used; i++) {
				data_string *ds = (data_string *)host->bin_env->data[i];
				
				env_add(&env, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
			}
			
			for (i = 0; i < env.used; i++) {
				/* search for PHP_FCGI_CHILDREN */
				if (0 == strncmp(env.ptr[i], "PHP_FCGI_CHILDREN=", sizeof("PHP_FCGI_CHILDREN=") - 1)) break;
			}
			
			/* not found, add a default */
			if (i == env.used) {
				env_add(&env, CONST_STR_LEN("PHP_FCGI_CHILDREN"), CONST_STR_LEN("1"));
			}
			
			env.ptr[env.used] = NULL;
			
			b = buffer_init();
			buffer_copy_string(b, "exec ");
			buffer_append_string_buffer(b, host->bin_path);
			
			/* exec the cgi */
			execle("/bin/sh", "sh", "-c", b->ptr, NULL, env.ptr);
			
			log_error_write(srv, __FILE__, __LINE__, "sbs", 
					"execl failed for:", host->bin_path, strerror(errno));
			
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
				/* child still running after timeout, good */
				break;
			case -1:
				/* no PID found ? should never happen */
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"pid not found:", strerror(errno));
				return -1;
			default:
				/* the child should not terminate at all */
				if (WIFEXITED(status)) {
					log_error_write(srv, __FILE__, __LINE__, "sd", 
							"child exited (is this a FastCGI binary ?):", 
							WEXITSTATUS(status));
				} else if (WIFSIGNALED(status)) {
					log_error_write(srv, __FILE__, __LINE__, "sd", 
							"child signaled:", 
							WTERMSIG(status));
				} else {
					log_error_write(srv, __FILE__, __LINE__, "sd", 
							"child died somehow:", 
							status);
				}
				return -1;
			}

			/* register process */
			proc->pid = child;
			proc->last_used = srv->cur_ts;
			proc->is_local = 1;
						
			break;
		}
#endif
	} else {
		proc->is_local = 0;
		proc->pid = 0;
		
		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"(debug) socket is already used, won't spawn:",
					proc->socket);
		}
	}
	
	proc->state = PROC_STATE_RUNNING;
	host->active_procs++;
	
	close(fcgi_fd);
	
	return 0;
}


SETDEFAULTS_FUNC(mod_fastcgi_set_defaults) {
	plugin_data *p = p_d;
	data_unset *du;
	size_t i = 0;
	buffer *fcgi_mode = buffer_init();
	
	config_values_t cv[] = { 
		{ "fastcgi.server",              NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "fastcgi.debug",               NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ NULL,                          NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		array *ca;
		
		s = malloc(sizeof(plugin_config));
		s->exts          = fastcgi_extensions_init();
		s->debug         = 0;
		
		cv[0].destination = s->exts;
		cv[1].destination = &(s->debug);
		
		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;
	
		if (0 != config_insert_values_global(srv, ca, cv)) {
			return HANDLER_ERROR;
		}
		
		/* 
		 * <key> = ( ... )
		 */
		
		if (NULL != (du = array_get_element(ca, "fastcgi.server"))) {
			size_t j;
			data_array *da = (data_array *)du;
			
			if (du->type != TYPE_ARRAY) {
				log_error_write(srv, __FILE__, __LINE__, "sss", 
						"unexpected type for key: ", "fastcgi.server", "array of strings");
				
				return HANDLER_ERROR;
			}
			
			
			/* 
			 * fastcgi.server = ( "<ext>" => ( ... ), 
			 *                    "<ext>" => ( ... ) )
			 */
			
			for (j = 0; j < da->value->used; j++) {
				size_t n;
				data_array *da_ext = (data_array *)da->value->data[j];
				
				if (da->value->data[j]->type != TYPE_ARRAY) {
					log_error_write(srv, __FILE__, __LINE__, "sssbs", 
							"unexpected type for key: ", "fastcgi.server", 
							"[", da->value->data[j]->key, "](string)");
					
					return HANDLER_ERROR;
				}
				
				/* 
				 * da_ext->key == name of the extension 
				 */
				
				/* 
				 * fastcgi.server = ( "<ext>" => 
				 *                     ( "<host>" => ( ... ), 
				 *                       "<host>" => ( ... )
				 *                     ), 
				 *                    "<ext>" => ... )
				 */
					
				for (n = 0; n < da_ext->value->used; n++) {
					data_array *da_host = (data_array *)da_ext->value->data[n];
					
					fcgi_extension_host *df;
					
					config_values_t fcv[] = { 
						{ "host",              NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
						{ "docroot",           NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
						{ "mode",              NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
						{ "socket",            NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 3 */
						{ "bin-path",          NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 4 */
						
						{ "check-local",       NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },      /* 5 */
						{ "port",              NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },        /* 6 */
						{ "min-procs",         NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },        /* 7 */
						{ "max-procs",         NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },        /* 8 */
						{ "max-load-per-proc", NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },        /* 9 */
						{ "idle-timeout",      NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },        /* 10 */
						{ "disable-time",      NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },        /* 11 */
						
						{ "bin-environment",   NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },        /* 12 */
						{ "bin-copy-environment", NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },     /* 13 */
						
						{ NULL,                NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
					};
					
					if (da_host->type != TYPE_ARRAY) {
						log_error_write(srv, __FILE__, __LINE__, "ssSBS", 
								"unexpected type for key:", 
								"fastcgi.server", 
								"[", da_host->key, "](string)");
						
						return HANDLER_ERROR;
					}
					
					df = fastcgi_host_init();
					
					df->check_local  = 1;
					df->min_procs    = 4;
					df->max_procs    = 4;
					df->max_load_per_proc = 1;
					df->idle_timeout = 60;
					df->mode = FCGI_RESPONDER;
					df->disable_time = 60;
					
					fcv[0].destination = df->host;
					fcv[1].destination = df->docroot;
					fcv[2].destination = fcgi_mode;
					fcv[3].destination = df->unixsocket;
					fcv[4].destination = df->bin_path;
					
					fcv[5].destination = &(df->check_local);
					fcv[6].destination = &(df->port);
					fcv[7].destination = &(df->min_procs);
					fcv[8].destination = &(df->max_procs);
					fcv[9].destination = &(df->max_load_per_proc);
					fcv[10].destination = &(df->idle_timeout);
					fcv[11].destination = &(df->disable_time);
					
					fcv[12].destination = df->bin_env;
					fcv[13].destination = df->bin_env_copy;
					
					if (0 != config_insert_values_internal(srv, da_host->value, fcv)) {
						return HANDLER_ERROR;
					}
							
					if ((!buffer_is_empty(df->host) || df->port) && 
					    !buffer_is_empty(df->unixsocket)) {
						log_error_write(srv, __FILE__, __LINE__, "s", 
								"either host+port or socket");
						
						return HANDLER_ERROR;
					}
					
					if (!buffer_is_empty(df->unixsocket)) {
						/* unix domain socket */
						
						if (df->unixsocket->used > UNIX_PATH_MAX - 2) {
							log_error_write(srv, __FILE__, __LINE__, "s", 
									"path of the unixdomain socket is too large");
							return HANDLER_ERROR;
						}
					} else {
						/* tcp/ip */
						
						if (buffer_is_empty(df->host) && 
						    buffer_is_empty(df->bin_path)) {
							log_error_write(srv, __FILE__, __LINE__, "sbbbs", 
									"missing key (string):", 
									da->key,
									da_ext->key,
									da_host->key,
									"host");
							
							return HANDLER_ERROR;
						} else if (df->port == 0) {
							log_error_write(srv, __FILE__, __LINE__, "sbbbs", 
									"missing key (short):", 
									da->key,
									da_ext->key,
									da_host->key,
									"port");
							return HANDLER_ERROR;
						}
					}
						
					if (!buffer_is_empty(df->bin_path)) { 
						/* a local socket + self spawning */
						size_t pno;
						
						if (df->min_procs > df->max_procs) df->max_procs = df->min_procs;
						if (df->max_load_per_proc < 1) df->max_load_per_proc = 0;
						
						if (s->debug) {
							log_error_write(srv, __FILE__, __LINE__, "ssbsdsbsdsd",
									"--- fastcgi spawning local",
									"\n\tproc:", df->bin_path,
									"\n\tport:", df->port,
									"\n\tsocket", df->unixsocket,
									"\n\tmin-procs:", df->min_procs,
									"\n\tmax-procs:", df->max_procs);
						}
						
						for (pno = 0; pno < df->min_procs; pno++) {
							fcgi_proc *proc;

							proc = fastcgi_process_init();
							proc->id = df->num_procs++;
							df->max_id++;

							if (buffer_is_empty(df->unixsocket)) {
								proc->port = df->port + pno;
							} else {
								buffer_copy_string_buffer(proc->socket, df->unixsocket);
								buffer_append_string(proc->socket, "-");
								buffer_append_long(proc->socket, pno);
							}
							
							if (s->debug) {
								log_error_write(srv, __FILE__, __LINE__, "ssdsbsdsd",
										"--- fastcgi spawning",
										"\n\tport:", df->port,
										"\n\tsocket", df->unixsocket,
										"\n\tcurrent:", pno, "/", df->min_procs);
							}
							
							if (fcgi_spawn_connection(srv, p, df, proc)) {
								log_error_write(srv, __FILE__, __LINE__, "s",
										"[ERROR]: spawning fcgi failed.");
								return HANDLER_ERROR;
							}
							
							proc->next = df->first;
							if (df->first) 	df->first->prev = proc;
							
							df->first = proc;
						}
					} else {
						fcgi_proc *fp;
						
						fp = fastcgi_process_init();
						fp->id = df->num_procs++;
						df->max_id++;
						df->active_procs++;
						fp->state = PROC_STATE_RUNNING;
						
						if (buffer_is_empty(df->unixsocket)) {
							fp->port = df->port;
						} else {
							buffer_copy_string_buffer(fp->socket, df->unixsocket);
						}
						
						df->first = fp;
						
						df->min_procs = 1;
						df->max_procs = 1;
					}
					
					if (!buffer_is_empty(fcgi_mode)) {
						if (strcmp(fcgi_mode->ptr, "responder") == 0) {
							df->mode = FCGI_RESPONDER;
						} else if (strcmp(fcgi_mode->ptr, "authorizer") == 0) {
							df->mode = FCGI_AUTHORIZER;
							if (buffer_is_empty(df->docroot)) {
								log_error_write(srv, __FILE__, __LINE__, "s",
										"ERROR: docroot is required for authorizer mode.");
								return HANDLER_ERROR;
							}
						} else {
							log_error_write(srv, __FILE__, __LINE__, "sbs",
									"WARNING: unknown fastcgi mode:",
									fcgi_mode, "(ignored, mode set to responder)");
						}
					}
					
					/* if extension already exists, take it */
					fastcgi_extension_insert(s->exts, da_ext->key, df);
				}
			}
		}
	}
	
	buffer_free(fcgi_mode);
	
	return HANDLER_GO_ON;
}

static int fcgi_set_state(server *srv, handler_ctx *hctx, fcgi_connection_state_t state) {
	hctx->state = state;
	hctx->state_timestamp = srv->cur_ts;
	
	return 0;
}


static size_t fcgi_requestid_new(server *srv, plugin_data *p) {
	size_t m = 0;
	size_t i;
	buffer_uint *r = &(p->fcgi_request_id);
	
	UNUSED(srv);

	for (i = 0; i < r->used; i++) {
		if (r->ptr[i] > m) m = r->ptr[i];
	}
	
	if (r->size == 0) {
		r->size = 16;
		r->ptr = malloc(sizeof(*r->ptr) * r->size);
	} else if (r->used == r->size) {
		r->size += 16;
		r->ptr = realloc(r->ptr, sizeof(*r->ptr) * r->size);
	}
	
	r->ptr[r->used++] = ++m;
	
	return m;
}

static int fcgi_requestid_del(server *srv, plugin_data *p, size_t request_id) {
	size_t i;
	buffer_uint *r = &(p->fcgi_request_id);
	
	UNUSED(srv);

	for (i = 0; i < r->used; i++) {
		if (r->ptr[i] == request_id) break;
	}
	
	if (i != r->used) {
		/* found */
		
		if (i != r->used - 1) {
			r->ptr[i] = r->ptr[r->used - 1];
		}
		r->used--;
	}
	
	return 0;
}

void fcgi_connection_cleanup(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection  *con;
	
	if (NULL == hctx) return;
	
	p    = hctx->plugin_data;
	con  = hctx->remote_conn;
	
	if (con->mode != p->id) {
		WP();
		return;
	}
	
	if (hctx->fd != -1) {
		fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
		fdevent_unregister(srv->ev, hctx->fd);
		close(hctx->fd);
		srv->cur_fds--;
	}
	
	if (hctx->request_id != 0) {
		fcgi_requestid_del(srv, p, hctx->request_id);
	}

	if (hctx->host && hctx->proc) {
		hctx->host->load--;
		if (hctx->state != FCGI_STATE_INIT &&
		    hctx->state != FCGI_STATE_CONNECT) {
			/* after the connect the process gets a load */
			hctx->proc->load--;
			
			if (p->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__, "sddb",
						"release proc:", 
						hctx->fd,
						hctx->proc->pid, hctx->proc->socket);
			}
		}

		fcgi_proclist_sort_down(srv, hctx->host, hctx->proc);
	}

	
	handler_ctx_free(hctx);
	con->plugin_ctx[p->id] = NULL;	
}

static int fcgi_reconnect(server *srv, handler_ctx *hctx) {
	plugin_data *p    = hctx->plugin_data;
	
	/* child died 
	 * 
	 * 1. 
	 * 
	 * connect was ok, connection was accepted
	 * but the php accept loop checks after the accept if it should die or not.
	 * 
	 * if yes we can only detect it at a write() 
	 * 
	 * next step is resetting this attemp and setup a connection again
	 * 
	 * if we have more then 5 reconnects for the same request, die
	 * 
	 * 2. 
	 * 
	 * we have a connection but the child died by some other reason
	 * 
	 */
	
	fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
	fdevent_unregister(srv->ev, hctx->fd);
	close(hctx->fd);
	srv->cur_fds--;
	
	fcgi_requestid_del(srv, p, hctx->request_id);
	
	fcgi_set_state(srv, hctx, FCGI_STATE_INIT);
	
	hctx->request_id = 0;
	hctx->reconnects++;
	
	if (p->conf.debug) {
		log_error_write(srv, __FILE__, __LINE__, "sddb",
				"release proc:", 
				hctx->fd,
				hctx->proc->pid, hctx->proc->socket);
	}
	
	hctx->proc->load--;
	fcgi_proclist_sort_down(srv, hctx->host, hctx->proc);
	
	return 0;
}


static handler_t fcgi_connection_reset(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	
	fcgi_connection_cleanup(srv, con->plugin_ctx[p->id]);
	
	return HANDLER_GO_ON;
}


static int fcgi_env_add(buffer *env, const char *key, size_t key_len, const char *val, size_t val_len) {
	size_t len;
	
	if (!key || !val) return -1;
	
	len = key_len + val_len;
	
	len += key_len > 127 ? 4 : 1;
	len += val_len > 127 ? 4 : 1;
	
	buffer_prepare_append(env, len);
	
	if (key_len > 127) {
		env->ptr[env->used++] = ((key_len >> 24) & 0xff) | 0x80;
		env->ptr[env->used++] = (key_len >> 16) & 0xff;
		env->ptr[env->used++] = (key_len >> 8) & 0xff;
		env->ptr[env->used++] = (key_len >> 0) & 0xff;
	} else {
		env->ptr[env->used++] = (key_len >> 0) & 0xff;
	}
	
	if (val_len > 127) {
		env->ptr[env->used++] = ((val_len >> 24) & 0xff) | 0x80;
		env->ptr[env->used++] = (val_len >> 16) & 0xff;
		env->ptr[env->used++] = (val_len >> 8) & 0xff;
		env->ptr[env->used++] = (val_len >> 0) & 0xff;
	} else {
		env->ptr[env->used++] = (val_len >> 0) & 0xff;
	}
	
	memcpy(env->ptr + env->used, key, key_len);
	env->used += key_len;
	memcpy(env->ptr + env->used, val, val_len);
	env->used += val_len;
	
	return 0;
}

static int fcgi_header(FCGI_Header * header, unsigned char type, size_t request_id, int contentLength, unsigned char paddingLength) {
	header->version = FCGI_VERSION_1;
	header->type = type;
	header->requestIdB0 = request_id & 0xff;
	header->requestIdB1 = (request_id >> 8) & 0xff;
	header->contentLengthB0 = contentLength & 0xff;
	header->contentLengthB1 = (contentLength >> 8) & 0xff;
	header->paddingLength = paddingLength;
	header->reserved = 0;
	
	return 0;
}
/**
 * 
 * returns
 *   -1 error
 *    0 connected
 *    1 not connected yet
 */

static int fcgi_establish_connection(server *srv, handler_ctx *hctx) {
	struct sockaddr *fcgi_addr;
	struct sockaddr_in fcgi_addr_in;
#ifdef HAVE_SYS_UN_H
	struct sockaddr_un fcgi_addr_un;
#endif
	socklen_t servlen;
	
	fcgi_extension_host *host = hctx->host;
	fcgi_proc *proc   = hctx->proc;
	int fcgi_fd       = hctx->fd;
	
	memset(&fcgi_addr, 0, sizeof(fcgi_addr));
	
	if (!buffer_is_empty(proc->socket)) {
#ifdef HAVE_SYS_UN_H
		/* use the unix domain socket */
		fcgi_addr_un.sun_family = AF_UNIX;
		strcpy(fcgi_addr_un.sun_path, proc->socket->ptr);
#ifdef SUN_LEN
		servlen = SUN_LEN(&fcgi_addr_un);
#else
		/* stevens says: */
		servlen = proc->socket->used - 1 + sizeof(fcgi_addr_un.sun_family);
#endif
		fcgi_addr = (struct sockaddr *) &fcgi_addr_un;
#else
		return -1;
#endif
	} else {
		fcgi_addr_in.sin_family = AF_INET;
		if (0 == inet_aton(host->host->ptr, &(fcgi_addr_in.sin_addr))) {
			log_error_write(srv, __FILE__, __LINE__, "sbs", 
					"converting IP-adress failed for", host->host, 
					"\nBe sure to specify an IP address here");
			
			return -1;
		}
		fcgi_addr_in.sin_port = htons(proc->port);
		servlen = sizeof(fcgi_addr_in);
		
		fcgi_addr = (struct sockaddr *) &fcgi_addr_in;
	}
	
	if (-1 == connect(fcgi_fd, fcgi_addr, servlen)) {
		if (errno == EINPROGRESS || 
		    errno == EALREADY ||
		    errno == EINTR) {
			if (hctx->conf.debug) {
				log_error_write(srv, __FILE__, __LINE__, "sd", 
						"connect delayed:", fcgi_fd);
			}
			
			return 1;
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sdsddb", 
					"connect failed:", fcgi_fd, 
					strerror(errno), errno,
					proc->port, proc->socket);

			if (errno == EAGAIN) {
				/* this is Linux only */
				
				log_error_write(srv, __FILE__, __LINE__, "s", 
						"If this happend on Linux: You have been run out of local ports. "
						"Check the manual, section Performance how to handle this.");
			} 
			
			return -1;
		}
	}
	if (hctx->conf.debug > 1) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"connect succeeded: ", fcgi_fd);
	}


	
	return 0;
}

static int fcgi_env_add_request_headers(server *srv, connection *con, plugin_data *p) {
	size_t i;
	
	for (i = 0; i < con->request.headers->used; i++) {
		data_string *ds;
		
		ds = (data_string *)con->request.headers->data[i];
		
		if (ds->value->used && ds->key->used) {
			size_t j;
			buffer_reset(srv->tmp_buf);
			
			if (0 != strcasecmp(ds->key->ptr, "CONTENT-TYPE")) {
				BUFFER_COPY_STRING_CONST(srv->tmp_buf, "HTTP_");
				srv->tmp_buf->used--;
			}
			
			buffer_prepare_append(srv->tmp_buf, ds->key->used + 2);
			for (j = 0; j < ds->key->used - 1; j++) {
				srv->tmp_buf->ptr[srv->tmp_buf->used++] = 
					light_isalpha(ds->key->ptr[j]) ? 
					ds->key->ptr[j] & ~32 : '_';
			}
			srv->tmp_buf->ptr[srv->tmp_buf->used++] = '\0';
			
			fcgi_env_add(p->fcgi_env, CONST_BUF_LEN(srv->tmp_buf), CONST_BUF_LEN(ds->value));
		}
	}
	
	for (i = 0; i < con->environment->used; i++) {
		data_string *ds;
		
		ds = (data_string *)con->environment->data[i];
		
		if (ds->value->used && ds->key->used) {
			size_t j;
			buffer_reset(srv->tmp_buf);
			
			buffer_prepare_append(srv->tmp_buf, ds->key->used + 2);
			for (j = 0; j < ds->key->used - 1; j++) {
				srv->tmp_buf->ptr[srv->tmp_buf->used++] = 
					isalpha((unsigned char)ds->key->ptr[j]) ? 
					toupper((unsigned char)ds->key->ptr[j]) : '_';
			}
			srv->tmp_buf->ptr[srv->tmp_buf->used++] = '\0';
			
			fcgi_env_add(p->fcgi_env, CONST_BUF_LEN(srv->tmp_buf), CONST_BUF_LEN(ds->value));
		}
	}
	
	return 0;
}


static int fcgi_create_env(server *srv, handler_ctx *hctx, size_t request_id) {
	FCGI_BeginRequestRecord beginRecord;
	FCGI_Header header;
	
	char buf[32];
	size_t offset;
	const char *s;
#ifdef HAVE_IPV6
	char b2[INET6_ADDRSTRLEN + 1];
#endif
	
	plugin_data *p    = hctx->plugin_data;
	fcgi_extension_host *host= hctx->host;

	connection *con   = hctx->remote_conn;
	server_socket *srv_sock = con->srv_socket;
	
	sock_addr our_addr;
	socklen_t our_addr_len;
	
	/* send FCGI_BEGIN_REQUEST */
	
	fcgi_header(&(beginRecord.header), FCGI_BEGIN_REQUEST, request_id, sizeof(beginRecord.body), 0);
	beginRecord.body.roleB0 = host->mode;
	beginRecord.body.roleB1 = 0;
	beginRecord.body.flags = 0;
	memset(beginRecord.body.reserved, 0, sizeof(beginRecord.body.reserved));
	
	buffer_copy_memory(hctx->write_buffer, (const char *)&beginRecord, sizeof(beginRecord));
	
	/* send FCGI_PARAMS */
	buffer_prepare_copy(p->fcgi_env, 1024);


	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SERVER_SOFTWARE"), CONST_STR_LEN(PACKAGE_NAME"/"PACKAGE_VERSION));
	
	if (con->server_name->used) {
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SERVER_NAME"), CONST_BUF_LEN(con->server_name));
	} else {
#ifdef HAVE_IPV6
		s = inet_ntop(srv_sock->addr.plain.sa_family, 
			      srv_sock->addr.plain.sa_family == AF_INET6 ? 
			      (const void *) &(srv_sock->addr.ipv6.sin6_addr) :
			      (const void *) &(srv_sock->addr.ipv4.sin_addr),
			      b2, sizeof(b2)-1);
#else
		s = inet_ntoa(srv_sock->addr.ipv4.sin_addr);
#endif
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SERVER_NAME"), s, strlen(s));
	}
	
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("GATEWAY_INTERFACE"), CONST_STR_LEN("CGI/1.1"));
	
	ltostr(buf, 
#ifdef HAVE_IPV6
	       ntohs(srv_sock->addr.plain.sa_family ? srv_sock->addr.ipv6.sin6_port : srv_sock->addr.ipv4.sin_port)
#else
	       ntohs(srv_sock->addr.ipv4.sin_port)
#endif
	       );
	
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SERVER_PORT"), buf, strlen(buf));
	
	/* get the server-side of the connection to the client */
	our_addr_len = sizeof(our_addr);
	
	if (-1 == getsockname(con->fd, &(our_addr.plain), &our_addr_len)) {
		s = inet_ntop_cache_get_ip(srv, &(srv_sock->addr));
	} else {
		s = inet_ntop_cache_get_ip(srv, &(our_addr));
	}
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SERVER_ADDR"), s, strlen(s));
	
	ltostr(buf, 
#ifdef HAVE_IPV6
	       ntohs(con->dst_addr.plain.sa_family ? con->dst_addr.ipv6.sin6_port : con->dst_addr.ipv4.sin_port)
#else
	       ntohs(con->dst_addr.ipv4.sin_port)
#endif
	       );
	
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REMOTE_PORT"), buf, strlen(buf));
	
	s = inet_ntop_cache_get_ip(srv, &(con->dst_addr));
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REMOTE_ADDR"), s, strlen(s));
	
	if (!buffer_is_empty(con->authed_user)) {
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REMOTE_USER"),
			     CONST_BUF_LEN(con->authed_user));
	}
	
	if (con->request.content_length > 0 && host->mode != FCGI_AUTHORIZER) {
		/* CGI-SPEC 6.1.2 and FastCGI spec 6.3 */
		
		/* request.content_length < SSIZE_MAX, see request.c */
		ltostr(buf, con->request.content_length);
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("CONTENT_LENGTH"), buf, strlen(buf));
	}

	if (host->mode != FCGI_AUTHORIZER) {
		/*
		 * SCRIPT_NAME, PATH_INFO and PATH_TRANSLATED according to
		 * http://cgi-spec.golux.com/draft-coar-cgi-v11-03-clean.html
		 * (6.1.14, 6.1.6, 6.1.7)
		 * For AUTHORIZER mode these headers should be omitted.
		 */

		if (hctx->path_info_offset == 0) {  /* no pathinfo */
			fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SCRIPT_NAME"), CONST_BUF_LEN(con->uri.path));
			fcgi_env_add(p->fcgi_env, CONST_STR_LEN("PATH_INFO"), CONST_STR_LEN(""));
		} else {                                /* pathinfo */
			*(con->uri.path->ptr + hctx->path_info_offset) = '\0'; /* get sctipt_name part */
			fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SCRIPT_NAME"), CONST_BUF_LEN(con->uri.path));
			
			*(con->uri.path->ptr + hctx->path_info_offset) = '/';  /* restore uri.path */
			fcgi_env_add(p->fcgi_env, CONST_STR_LEN("PATH_INFO"), 
				     con->uri.path->ptr + hctx->path_info_offset, 
				     con->uri.path->used - 1 - hctx->path_info_offset);
			
			if (host->docroot->used) {
				buffer_copy_string_buffer(p->path, host->docroot);
				buffer_append_string(p->path, con->uri.path->ptr + hctx->path_info_offset);
				fcgi_env_add(p->fcgi_env, CONST_STR_LEN("PATH_TRANSLATED"), CONST_BUF_LEN(p->path));
			} else {
				fcgi_env_add(p->fcgi_env, CONST_STR_LEN("PATH_TRANSLATED"), 
					     con->uri.path->ptr + hctx->path_info_offset, 
					     con->uri.path->used - 1 - hctx->path_info_offset);
			}
		}
	}

	/*
	 * SCRIPT_FILENAME and DOCUMENT_ROOT for php. The PHP manual
	 * http://www.php.net/manual/en/reserved.variables.php
	 * treatment of PATH_TRANSLATED is different from the one of CGI specs.
	 * TODO: this code should be checked against cgi.fix_pathinfo php
	 * parameter.
	 */

	if (!buffer_is_empty(host->docroot)) {
		/* 
		 * rewrite SCRIPT_FILENAME 
		 * 
		 */
		
		buffer_copy_string_buffer(p->path, host->docroot);
		buffer_append_string_buffer(p->path, con->uri.path);
		
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SCRIPT_FILENAME"), CONST_BUF_LEN(p->path));
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("DOCUMENT_ROOT"), CONST_BUF_LEN(host->docroot));
	} else {
		if (con->request.pathinfo->used) {
			fcgi_env_add(p->fcgi_env, CONST_STR_LEN("PATH_INFO"), CONST_BUF_LEN(con->request.pathinfo));
		}
		
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SCRIPT_FILENAME"), CONST_BUF_LEN(con->physical.path));
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("DOCUMENT_ROOT"), CONST_BUF_LEN(con->physical.doc_root));
	}
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REQUEST_URI"), CONST_BUF_LEN(con->request.orig_uri));
	if (!buffer_is_equal(con->request.uri, con->request.orig_uri)) {
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REDIRECT_URI"), CONST_BUF_LEN(con->request.uri));
	}
	if (!buffer_is_empty(con->uri.query)) {
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("QUERY_STRING"), CONST_BUF_LEN(con->uri.query));
	} else {
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("QUERY_STRING"), CONST_STR_LEN(""));
	}
	
	s = get_http_method_name(con->request.http_method);
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REQUEST_METHOD"), s, strlen(s));
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("REDIRECT_STATUS"), CONST_STR_LEN("200")); /* if php is compiled with --force-redirect */
	s = get_http_version_name(con->request.http_version);
	fcgi_env_add(p->fcgi_env, CONST_STR_LEN("SERVER_PROTOCOL"), s, strlen(s));
	
#ifdef USE_OPENSSL
	if (srv_sock->is_ssl) {
		fcgi_env_add(p->fcgi_env, CONST_STR_LEN("HTTPS"), CONST_STR_LEN("on"));
	}
#endif
	
	
	fcgi_env_add_request_headers(srv, con, p);
	
	fcgi_header(&(header), FCGI_PARAMS, request_id, p->fcgi_env->used, 0);
	buffer_append_memory(hctx->write_buffer, (const char *)&header, sizeof(header));
	buffer_append_memory(hctx->write_buffer, (const char *)p->fcgi_env->ptr, p->fcgi_env->used);
	
	fcgi_header(&(header), FCGI_PARAMS, request_id, 0, 0);
	buffer_append_memory(hctx->write_buffer, (const char *)&header, sizeof(header));
	
	/* send FCGI_STDIN */
	
	/* something to send ? */
	for (offset = 0; offset != con->request.content_length; ) {
		/* send chunks of 1024 bytes */
		size_t toWrite = con->request.content_length - offset > 4096 ? 4096 : con->request.content_length - offset;
		
		fcgi_header(&(header), FCGI_STDIN, request_id, toWrite, 0);
		buffer_append_memory(hctx->write_buffer, (const char *)&header, sizeof(header));
		buffer_append_memory(hctx->write_buffer, (const char *)(con->request.content->ptr + offset), toWrite);
		
		offset += toWrite;
	}
	
	/* terminate STDIN */
	fcgi_header(&(header), FCGI_STDIN, request_id, 0, 0);
	buffer_append_memory(hctx->write_buffer, (const char *)&header, sizeof(header));

#if 0
	for (i = 0; i < hctx->write_buffer->used; i++) {
		fprintf(stderr, "%02x ", hctx->write_buffer->ptr[i]);
		if ((i+1) % 16 == 0) {
			size_t j;
			for (j = i-15; j <= i; j++) {
				fprintf(stderr, "%c", 
					isprint((unsigned char)hctx->write_buffer->ptr[j]) ? hctx->write_buffer->ptr[j] : '.');
			}
			fprintf(stderr, "\n");
		}
	}
#endif
	
	return 0;
}

static int fcgi_response_parse(server *srv, connection *con, plugin_data *p, buffer *in) {
	char *s, *ns;
	
	handler_ctx *hctx = con->plugin_ctx[p->id];
	fcgi_extension_host *host= hctx->host;
	
	UNUSED(srv);

	/* \r\n -> \0\0 */
	
	buffer_copy_string_buffer(p->parse_response, in);
	
	for (s = p->parse_response->ptr; NULL != (ns = strstr(s, "\r\n")); s = ns + 2) {
		char *key, *value;
		int key_len;
		data_string *ds;
		
		ns[0] = '\0';
		ns[1] = '\0';
		
		key = s;
		if (NULL == (value = strchr(s, ':'))) {
			/* we expect: "<key>: <value>\n" */
			continue;
		}
		
		key_len = value - key;
		
		value++;
		/* strip WS */
		while (*value == ' ' || *value == '\t') value++;
		
		if (host->mode != FCGI_AUTHORIZER ||
		    !(con->http_status == 0 ||
		      con->http_status == 200)) {
			/* authorizers shouldn't affect the response headers sent back to the client */
			if (NULL == (ds = (data_string *)array_get_unused_element(con->response.headers, TYPE_STRING))) {
				ds = data_response_init();
			}
			buffer_copy_string_len(ds->key, key, key_len);
			buffer_copy_string(ds->value, value);
			
			array_insert_unique(con->response.headers, (data_unset *)ds);
		}
		
		switch(key_len) {
		case 4:
			if (0 == strncasecmp(key, "Date", key_len)) {
				con->parsed_response |= HTTP_DATE;
			}
			break;
		case 6:
			if (0 == strncasecmp(key, "Status", key_len)) {
				con->http_status = strtol(value, NULL, 10);
				con->parsed_response |= HTTP_STATUS;
			}
			break;
		case 8:
			if (0 == strncasecmp(key, "Location", key_len)) {
				con->parsed_response |= HTTP_LOCATION;
			}
			break;
		case 10:
			if (0 == strncasecmp(key, "Connection", key_len)) {
				con->response.keep_alive = (0 == strcasecmp(value, "Keep-Alive")) ? 1 : 0;
				con->parsed_response |= HTTP_CONNECTION;
			}
			break;
		case 14:
			if (0 == strncasecmp(key, "Content-Length", key_len)) {
				con->response.content_length = strtol(value, NULL, 10);
				con->parsed_response |= HTTP_CONTENT_LENGTH;
				
				if (con->response.content_length < 0) con->response.content_length = 0;
			}
			break;
		default:
			break;
		}
	}
	
	/* CGI/1.1 rev 03 - 7.2.1.2 */
	if ((con->parsed_response & HTTP_LOCATION) &&
	    !(con->parsed_response & HTTP_STATUS)) {
		con->http_status = 302;
	}
	
	return 0;
}


static int fcgi_demux_response(server *srv, handler_ctx *hctx) {
	ssize_t len;
	int fin = 0;
	int b;
	ssize_t r;
	
	plugin_data *p    = hctx->plugin_data;
	connection *con   = hctx->remote_conn;
	int fcgi_fd       = hctx->fd;
	fcgi_extension_host *host= hctx->host;
	fcgi_proc *proc   = hctx->proc;
	
	/* 
	 * check how much we have to read 
	 */
	if (ioctl(hctx->fd, FIONREAD, &b)) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"unexpected end-of-file (perhaps the fastcgi process died):",
				fcgi_fd);
		return -1;
	}
	
	/* init read-buffer */
	if (hctx->rb == NULL) {
		hctx->rb = calloc(1, sizeof(*hctx->rb));
	}
	
	if (b > 0) {
		if (hctx->rb->size == 0) {
			hctx->rb->size = b;
			hctx->rb->ptr = malloc(hctx->rb->size * sizeof(*hctx->rb->ptr));
		} else if (hctx->rb->size < hctx->rb->used + b) {
			hctx->rb->size += b;
			hctx->rb->ptr = realloc(hctx->rb->ptr, hctx->rb->size * sizeof(*hctx->rb->ptr));
		}
		
		/* append to read-buffer */
		if (-1 == (r = read(hctx->fd, hctx->rb->ptr + hctx->rb->used, b))) {
			log_error_write(srv, __FILE__, __LINE__, "sds", 
					"unexpected end-of-file (perhaps the fastcgi process died):",
					fcgi_fd, strerror(errno));
			return -1;
		}
		
		/* this should be catched by the b > 0 above */
		assert(r);
		
		hctx->rb->used += r;
	} else {
		log_error_write(srv, __FILE__, __LINE__, "ssdsdsd", 
				"unexpected end-of-file (perhaps the fastcgi process died):",
				"pid:", proc->pid,
				"fcgi-fd:", fcgi_fd, 
				"remote-fd:", con->fd);
		
		return -1;
	}
	
	/* parse all fcgi packets 
	 * 
	 *   start: hctx->rb->ptr 
	 *   end  : hctx->rb->ptr + hctx->rb->used
	 * 
	 */
	while (fin == 0) {
		size_t request_id;
		
		if (hctx->response_len == 0) {
			FCGI_Header *header;
			
			if (hctx->rb->used - hctx->rb->offset < sizeof(*header)) {
				/* didn't get the full header packet (most often 0),
				 * but didn't recieved the final packet either
				 * 
				 * we will come back later and finish everything
				 * 
				 */
				
				hctx->delayed = 1;
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sddd", "didn't get the full header: ",
						hctx->rb->used - hctx->rb->offset, sizeof(*header),
						fcgi_fd
						);
#endif
				break;
			}
#if 0
			fprintf(stderr, "fcgi-version: %02x\n", hctx->rb->ptr[hctx->rb->offset]);
#endif
			
			header = (FCGI_Header *)(hctx->rb->ptr + hctx->rb->offset);
			hctx->rb->offset += sizeof(*header);
			
			len = (header->contentLengthB0 | (header->contentLengthB1 << 8)) + header->paddingLength;
			request_id = (header->requestIdB0 | (header->requestIdB1 << 8));

			hctx->response_len = len;
			hctx->response_request_id = request_id;
			hctx->response_type = header->type;
			hctx->response_padding = header->paddingLength;
			
#if 0
			log_error_write(srv, __FILE__, __LINE__, "sddd", "offset: ",
					fcgi_fd, hctx->rb->offset, header->type
					);
#endif
			
		} else {
			len = hctx->response_len;
		}
		
		if (hctx->rb->used - hctx->rb->offset < hctx->response_len) {
			/* we are not finished yet */
			break;
		}
		
		hctx->response->ptr = hctx->rb->ptr + hctx->rb->offset;
		hctx->rb->offset += hctx->response_len;
#if 0
		log_error_write(srv, __FILE__, __LINE__, "sdd", "offset: ",
				fcgi_fd, hctx->rb->offset
				);
#endif
		
		/* remove padding */
#if 0
		hctx->response->ptr[hctx->response_len - hctx->response_padding] = '\0';
#endif
		hctx->response->used = hctx->response_len - hctx->response_padding + 1;
		
		/* mark the fast-cgi packet as finished */
		hctx->response_len = 0;
		
		switch(hctx->response_type) {
		case FCGI_STDOUT:
			if (len) {
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sdb", "len", len, hctx->response);
#endif
				
				if (0 == con->got_response) {
					con->got_response = 1;
					buffer_prepare_copy(hctx->response_header, 128);
				}
				
				if (0 == con->file_started) {
					char *c;
					
					/* search for the \r\n\r\n in the string */
					if (NULL != (c = buffer_search_string_len(hctx->response, "\r\n\r\n", 4))) {
						size_t hlen = c - hctx->response->ptr + 4;
						size_t blen = hctx->response->used - hlen - 1;
						/* found */
						
						buffer_append_string_len(hctx->response_header, hctx->response->ptr, c - hctx->response->ptr + 4);
#if 0
						log_error_write(srv, __FILE__, __LINE__, "ss", "Header:", hctx->response_header->ptr);
#endif
						/* parse the response header */
						fcgi_response_parse(srv, con, p, hctx->response_header);
						
						
						if (host->mode != FCGI_AUTHORIZER ||
						    !(con->http_status == 0 ||
						      con->http_status == 200)) {
							/* enable chunked-transfer-encoding */
							if (con->request.http_version == HTTP_VERSION_1_1 &&
							    !(con->parsed_response & HTTP_CONTENT_LENGTH)) {
								con->response.transfer_encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
							}

							con->file_started = 1;
						
							if (blen) {
								http_chunk_append_mem(srv, con, c + 4, blen + 1);
								joblist_append(srv, con);
#if 0
								log_error_write(srv, __FILE__, __LINE__, "sd", "body-len", blen);
#endif
							}
						}
					} else {
						/* copy everything */
						buffer_append_string_buffer(hctx->response_header, hctx->response);
					}
				} else {
					if (host->mode != FCGI_AUTHORIZER ||
					    !(con->http_status == 0 ||
					      con->http_status == 200)) {
						http_chunk_append_mem(srv, con, hctx->response->ptr, hctx->response->used);
						joblist_append(srv, con);
					}
#if 0
					log_error_write(srv, __FILE__, __LINE__, "sd", "body-len", hctx->response->used);
#endif
				}
			} else {
				/* finished */
			}
			
			break;
		case FCGI_STDERR:
			log_error_write(srv, __FILE__, __LINE__, "sb", 
					"FastCGI-stderr:", hctx->response);
			
			break;
		case FCGI_END_REQUEST:
			con->file_finished = 1;
			
			if (host->mode != FCGI_AUTHORIZER ||
			    !(con->http_status == 0 ||
			      con->http_status == 200)) {
				/* send chunk-end if nesseary */
				http_chunk_append_mem(srv, con, NULL, 0);
				joblist_append(srv, con);
			}
			
			fin = 1;
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sd", 
					"FastCGI: header.type not handled: ", hctx->response_type);
			break;
		}
	}
	
	hctx->response->ptr = NULL;

	return fin;
}

int fcgi_proclist_sort_up(server *srv, fcgi_extension_host *host, fcgi_proc *proc) {
	fcgi_proc *p;
	
	UNUSED(srv);
	
	/* we have been the smallest of the current list 
	 * and we want to insert the node sorted as soon 
	 * possible
	 *
	 * 1 0 0 0 1 1 1 
	 * |      ^ 
	 * |      |
	 * +------+
	 * 
	 */

	/* nothing to sort, only one element */
	if (host->first == proc && proc->next == NULL) return 0;

	for (p = proc; p->next && p->next->load < proc->load; p = p->next);

	/* no need to move something 
	 *
	 * 1 2 2 2 3 3 3 
	 * ^
	 * |
	 * +
	 *
	 */
	if (p == proc) return 0;

	if (host->first == proc) {
		/* we have been the first elememt */

		host->first = proc->next;
		host->first->prev = NULL;
	}

	/* disconnect proc */

	if (proc->prev) proc->prev->next = proc->next;
	if (proc->next) proc->next->prev = proc->prev;
	
	/* proc should be right of p */
	
	proc->next = p->next;
	proc->prev = p;
	if (p->next) p->next->prev = proc;
	p->next = proc;
#if 0
	for(p = host->first; p; p = p->next) {
		log_error_write(srv, __FILE__, __LINE__, "dd", 
				p->pid, p->load);
	}
#else
	UNUSED(srv);
#endif

	return 0;
}

int fcgi_proclist_sort_down(server *srv, fcgi_extension_host *host, fcgi_proc *proc) {
	fcgi_proc *p;
	
	UNUSED(srv);
	
	/* we have been the smallest of the current list 
	 * and we want to insert the node sorted as soon 
	 * possible
	 *
	 *  0 0 0 0 1 0 1 
	 * ^          |
	 * |          |
	 * +----------+
	 *
	 *
	 * the basic is idea is:
	 * - the last active fastcgi process should be still 
	 *   in ram and is not swapped out yet
	 * - processes that are not reused will be killed
	 *   after some time by the trigger-handler
	 * - remember it as:
	 *   everything > 0 is hot
	 *   all unused procs are colder the more right they are
	 *   ice-cold processes are propably unused since more
	 *   than 'unused-timeout', are swaped out and won't be
	 *   reused in the next seconds anyway.
	 * 
	 */

	/* nothing to sort, only one element */
	if (host->first == proc && proc->next == NULL) return 0;

	for (p = host->first; p != proc && p->load < proc->load; p = p->next);


	/* no need to move something 
	 *
	 * 1 2 2 2 3 3 3 
	 * ^
	 * |
	 * +
	 *
	 */
	if (p == proc) return 0;
	
	/* we have to move left. If we are already the first element
	 * we are done */
	if (host->first == proc) return 0;

	/* release proc */
	if (proc->prev) proc->prev->next = proc->next;
	if (proc->next) proc->next->prev = proc->prev;

	/* proc should be left of p */
	proc->next = p;
	proc->prev = p->prev;
	if (p->prev) p->prev->next = proc;
	p->prev = proc;

	if (proc->prev == NULL) host->first = proc;
#if 0	
	for(p = host->first; p; p = p->next) {
		log_error_write(srv, __FILE__, __LINE__, "dd", 
				p->pid, p->load);
	}
#else
	UNUSED(srv);
#endif

	return 0;
}



static handler_t fcgi_write_request(server *srv, handler_ctx *hctx) {
	plugin_data *p    = hctx->plugin_data;
	fcgi_extension_host *host= hctx->host;
	connection *con   = hctx->remote_conn;
	
	int r;

	/* sanity check */	
	if (!host ||
	    ((!host->host->used || !host->port) && !host->unixsocket->used)) return HANDLER_ERROR;
	
	switch(hctx->state) {
	case FCGI_STATE_INIT:
		r = host->unixsocket->used ? AF_UNIX : AF_INET;
		
		if (-1 == (hctx->fd = socket(r, SOCK_STREAM, 0))) {
			if (errno == EMFILE ||
			    errno == EINTR) {
				log_error_write(srv, __FILE__, __LINE__, "sd", 
						"wait for fd at connection:", con->fd);
				
				return HANDLER_WAIT_FOR_FD;
			}
			
			log_error_write(srv, __FILE__, __LINE__, "ssdd", 
					"socket failed:", strerror(errno), srv->cur_fds, srv->max_fds);
			return HANDLER_ERROR;
		}
		hctx->fde_ndx = -1;
		
		srv->cur_fds++;
		
		fdevent_register(srv->ev, hctx->fd, fcgi_handle_fdevent, hctx);
		
		if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", 
					"fcntl failed: ", strerror(errno));
			
			return HANDLER_ERROR;
		}
		
		/* fall through */
	case FCGI_STATE_CONNECT:
		if (hctx->state == FCGI_STATE_INIT) {
			for (hctx->proc = hctx->host->first; 
			     hctx->proc && hctx->proc->state != PROC_STATE_RUNNING; 
			     hctx->proc = hctx->proc->next);
			
			/* all childs are dead */
			if (hctx->proc == NULL) {
				hctx->fde_ndx = -1;
				
				return HANDLER_ERROR;
			}
			
			
			switch (fcgi_establish_connection(srv, hctx)) {
			case 1:
				fcgi_set_state(srv, hctx, FCGI_STATE_CONNECT);
				
				/* connection is in progress, wait for an event and call getsockopt() below */
				
				return HANDLER_WAIT_FOR_EVENT;
			case -1:
				/* if ECONNREFUSED choose another connection -> FIXME */
				hctx->fde_ndx = -1;
				
				return HANDLER_ERROR;
			default:
				/* everything is ok, go on */
				break;
			}

			
		} else {
			int socket_error;
			socklen_t socket_error_len = sizeof(socket_error);
			
			/* try to finish the connect() */
			if (0 != getsockopt(hctx->fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", 
						"getsockopt failed:", strerror(errno));
				
				return HANDLER_ERROR;
			}
			if (socket_error != 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss",
						"establishing connection failed:", strerror(socket_error), 
						"port:", hctx->proc->port);
				
				return HANDLER_ERROR;
			}
		}
		
		/* ok, we have the connection */
		
		hctx->proc->load++;
		hctx->proc->last_used = srv->cur_ts;
		
		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__, "sddbdd",
					"got proc:", 
					hctx->fd,
					hctx->proc->pid, 
					hctx->proc->socket, 
					hctx->proc->port,
					hctx->proc->load);
		}

		/* move the proc-list entry down the list */
		fcgi_proclist_sort_up(srv, hctx->host, hctx->proc);
		
		if (hctx->request_id == 0) {
			hctx->request_id = fcgi_requestid_new(srv, p);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd", 
					"fcgi-request is already in use:", hctx->request_id);
		}
		
		fcgi_set_state(srv, hctx, FCGI_STATE_PREPARE_WRITE);
		/* fall through */
	case FCGI_STATE_PREPARE_WRITE:
		fcgi_create_env(srv, hctx, hctx->request_id);
		
		fcgi_set_state(srv, hctx, FCGI_STATE_WRITE);
		hctx->write_offset = 0;
		
		/* fall through */
	case FCGI_STATE_WRITE:
		/* continue with the code after the switch */
		if (-1 == (r = write(hctx->fd, 
				     hctx->write_buffer->ptr + hctx->write_offset, 
				     hctx->write_buffer->used - hctx->write_offset))) {
			
			if (errno == ENOTCONN) {
				/* the connection got dropped after accept() 
				 * 
				 * this is most of the time a PHP which dies 
				 * after PHP_FCGI_MAX_REQUESTS
				 * 
				 */ 
				if (hctx->write_offset == 0 &&
				    hctx->reconnects < 5) {
					usleep(10000); /* take away the load of the webserver 
							* to let the php a chance to restart 
							*/
					
					fcgi_reconnect(srv, hctx);
				
					return HANDLER_WAIT_FOR_FD;
				}
				
				/* not reconnected ... why
				 * 
				 * far@#lighttpd report this for FreeBSD
				 * 
				 */
				
				log_error_write(srv, __FILE__, __LINE__, "ssdsd", 
						"[REPORT ME] connection was dropped after accept(). reconnect() denied:",
						"write-offset:", hctx->write_offset,
						"reconnect attempts:", hctx->reconnects);
				
				
				
				return HANDLER_ERROR;
			}
			
			if ((errno != EAGAIN) &&
			    (errno != EINTR)) {
				
				log_error_write(srv, __FILE__, __LINE__, "ssd", 
						"write failed:", strerror(errno), errno);
				
				return HANDLER_ERROR;
			} else {
				return HANDLER_WAIT_FOR_EVENT;
			}
		}
		
		hctx->write_offset += r;
		
		if (hctx->write_offset == hctx->write_buffer->used) {
			fcgi_set_state(srv, hctx, FCGI_STATE_READ);
		}
		
		break;
	case FCGI_STATE_READ:
		/* waiting for a response */
		break;
	default:
		log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
		return HANDLER_ERROR;
	}
	
	return HANDLER_WAIT_FOR_EVENT;
}

static int fcgi_restart_dead_procs(server *srv, plugin_data *p, fcgi_extension_host *host) {
	fcgi_proc *proc;
	
	for (proc = host->first; proc; proc = proc->next) {
		if (p->conf.debug) {
			log_error_write(srv, __FILE__, __LINE__,  "sbdbdddd", 
					"proc:", 
					host->host, proc->port, 
					proc->socket,
					proc->state,
					proc->is_local,
					proc->load,
					proc->pid);
		}
		
		if (0 == proc->is_local) {
			/* 
			 * external servers might get disabled 
			 * 
			 * enable the server again, perhaps it is back again 
			 */
			
			if ((proc->state == PROC_STATE_DISABLED) &&
			    (srv->cur_ts - proc->disable_ts > FCGI_RETRY_TIMEOUT)) {
				proc->state = PROC_STATE_RUNNING;
				host->active_procs++;
				
				log_error_write(srv, __FILE__, __LINE__,  "sbdb", 
						"fcgi-server re-enabled:", 
						host->host, host->port, 
						host->unixsocket);
			}
		} else {
			/* the child should not terminate at all */
			int status;
			
			if (proc->state == PROC_STATE_DIED_WAIT_FOR_PID) {
				switch(waitpid(proc->pid, &status, WNOHANG)) {
				case 0:
					/* child is still alive */
					break;
				case -1:
					break;
				default:
					if (WIFEXITED(status)) {
						log_error_write(srv, __FILE__, __LINE__, "sdsd", 
								"child exited, pid:", proc->pid,
								"status:", WEXITSTATUS(status));
					} else if (WIFSIGNALED(status)) {
						log_error_write(srv, __FILE__, __LINE__, "sd", 
								"child signaled:", 
								WTERMSIG(status));
					} else {
						log_error_write(srv, __FILE__, __LINE__, "sd", 
								"child died somehow:", 
								status);
					}
					
					proc->state = PROC_STATE_DIED;
					break;
				}
			}
			
			/* 
			 * local servers might died, but we restart them
			 * 
			 */
			if (proc->state == PROC_STATE_DIED &&
			    proc->load == 0) {
				/* restart the child */
				
				if (fcgi_spawn_connection(srv, p, host, proc)) {
					log_error_write(srv, __FILE__, __LINE__, "s",
							"ERROR: spawning fcgi failed.");
					return HANDLER_ERROR;
				}
				
				fcgi_proclist_sort_down(srv, host, proc);
			}
		}
	}
	
	return 0;
}

SUBREQUEST_FUNC(mod_fastcgi_handle_subrequest) {
	plugin_data *p = p_d;
	
	handler_ctx *hctx = con->plugin_ctx[p->id];
	fcgi_proc *proc;
	fcgi_extension_host *host;
	
	if (NULL == hctx) return HANDLER_GO_ON;
	
	/* not my job */
	if (con->mode != p->id) return HANDLER_GO_ON;
	
	/* ok, create the request */
	switch(fcgi_write_request(srv, hctx)) {
	case HANDLER_ERROR:
		proc = hctx->proc;
		host = hctx->host;
		
		if (proc && 
		    0 == proc->is_local &&
		    proc->state != PROC_STATE_DISABLED) {
			/* only disable remote servers as we don't manage them*/
			
			log_error_write(srv, __FILE__, __LINE__,  "sbdb", "fcgi-server disabled:", 
					host->host,
					proc->port,
					proc->socket);
			
			/* disable this server */
			proc->disable_ts = srv->cur_ts;
			proc->state = PROC_STATE_DISABLED;
			host->active_procs--;
		}
		
		if (hctx->state == FCGI_STATE_INIT ||
		    hctx->state == FCGI_STATE_CONNECT) {
			/* connect() or getsockopt() failed, 
			 * restart the request-handling 
			 */
			if (proc && proc->is_local) {
				log_error_write(srv, __FILE__, __LINE__,  "sbdb", "connect() to fastcgi failed, restarting the request-handling:", 
						host->host,
						proc->port,
						proc->socket);
			
				proc->state = PROC_STATE_DIED_WAIT_FOR_PID;
			}
			
			fcgi_restart_dead_procs(srv, p, host);
			
			fcgi_connection_cleanup(srv, hctx);
			
			buffer_reset(con->physical.path);
			con->mode = DIRECT;
			
			joblist_append(srv, con);
			
			/* mis-using HANDLER_WAIT_FOR_FD to break out of the loop 
			 * and hope that the childs will be restarted 
			 * 
			 */
			return HANDLER_WAIT_FOR_FD;
		} else {
		
			fcgi_connection_cleanup(srv, hctx);
			
			buffer_reset(con->physical.path);
			con->mode = DIRECT;
			con->http_status = 503;
			
			return HANDLER_FINISHED;
		}
	case HANDLER_WAIT_FOR_EVENT:
		if (con->file_started == 1) {
			return HANDLER_FINISHED;
		} else {
			return HANDLER_WAIT_FOR_EVENT;
		}
	case HANDLER_WAIT_FOR_FD:
		return HANDLER_WAIT_FOR_FD;
	default:
		return HANDLER_ERROR;
	}
}

static handler_t fcgi_connection_close(server *srv, handler_ctx *hctx) {
	plugin_data *p;
	connection  *con;
	
	if (NULL == hctx) return HANDLER_GO_ON;
	
	p    = hctx->plugin_data;
	con  = hctx->remote_conn;
	
	if (con->mode != p->id) return HANDLER_GO_ON;
	
	log_error_write(srv, __FILE__, __LINE__, "ssdsd", 
			"emergency exit: fastcgi:", 
			"connection-fd:", con->fd,
			"fcgi-fd:", hctx->fd);
	
	
	
	fcgi_connection_cleanup(srv, hctx);
	
	return HANDLER_FINISHED;
}


static handler_t fcgi_handle_fdevent(void *s, void *ctx, int revents) {
	server      *srv  = (server *)s;
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;
	plugin_data *p    = hctx->plugin_data;
	
	fcgi_proc *proc   = hctx->proc;
	fcgi_extension_host *host= hctx->host;

	joblist_append(srv, con);
	
	if ((revents & FDEVENT_IN) &&
	    hctx->state == FCGI_STATE_READ) {
		switch (fcgi_demux_response(srv, hctx)) {
		case 0:
			break;
		case 1:
			
			if (host->mode == FCGI_AUTHORIZER && 
		   	    (con->http_status == 200 ||
			     con->http_status == 0)) {
				/*
				 * If we are here in AUTHORIZER mode then a request for autorizer
				 * was proceeded already, and status 200 has been returned. We need
				 * now to handle autorized request.
				 */

				buffer_copy_string_buffer(con->physical.doc_root, host->docroot);
				
				buffer_copy_string_buffer(con->physical.path, host->docroot);
				buffer_append_string_buffer(con->physical.path, con->uri.path);
				fcgi_connection_cleanup(srv, hctx);
				
				con->mode = DIRECT;
				con->file_started = 1; /* fcgi_extension won't touch the request afterwards */
			} else {
				/* we are done */
				fcgi_connection_cleanup(srv, hctx);
			}
			
			return HANDLER_FINISHED;
		case -1:
			if (proc->pid) {
				int status;
				switch(waitpid(proc->pid, &status, WNOHANG)) {
				case 0:
					/* child is still alive */
					break;
				case -1:
					break;
				default:
					/* the child should not terminate at all */
					if (WIFEXITED(status)) {
						log_error_write(srv, __FILE__, __LINE__, "sdsd", 
								"child exited, pid:", proc->pid,
								"status:", WEXITSTATUS(status));
					} else if (WIFSIGNALED(status)) {
						log_error_write(srv, __FILE__, __LINE__, "sd", 
								"child signaled:", 
								WTERMSIG(status));
					} else {
						log_error_write(srv, __FILE__, __LINE__, "sd", 
								"child died somehow:", 
								status);
					}
					
					if (fcgi_spawn_connection(srv, p, host, proc)) {
						/* child died */
						proc->state = PROC_STATE_DIED;
					} else {
						fcgi_proclist_sort_down(srv, host, proc);
					}
					
					break;
				}
			}

			if (con->file_started == 0) {
				/* nothing has been send out yet, try to use another child */
				
				if (hctx->write_offset == 0 &&
				    hctx->reconnects < 5) {
					fcgi_reconnect(srv, hctx);
					
					log_error_write(srv, __FILE__, __LINE__, "sdsdsd", 
						"response not sent, request not sent, reconnection.",
						"connection-fd:", con->fd,
						"fcgi-fd:", hctx->fd);
					
					return HANDLER_WAIT_FOR_FD;
				}
				
				log_error_write(srv, __FILE__, __LINE__, "sdsdsd", 
						"response not sent, request sent:", hctx->write_offset,
						"connection-fd:", con->fd,
						"fcgi-fd:", hctx->fd);
				
				fcgi_connection_cleanup(srv, hctx);
				
				connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
				buffer_reset(con->physical.path);
				con->http_status = 500;
				con->mode = DIRECT;
			} else {
				/* response might have been already started, kill the connection */
				fcgi_connection_cleanup(srv, hctx);
				
				log_error_write(srv, __FILE__, __LINE__, "ssdsd", 
						"response already sent out, termination connection",
						"connection-fd:", con->fd,
						"fcgi-fd:", hctx->fd);
				
				connection_set_state(srv, con, CON_STATE_ERROR);
			}

			/* */
			
			
			return HANDLER_FINISHED;
		}
	}
	
	if (revents & FDEVENT_OUT) {
		if (hctx->state == FCGI_STATE_CONNECT ||
		    hctx->state == FCGI_STATE_WRITE) {
			/* we are allowed to send something out
			 * 
			 * 1. in a unfinished connect() call
			 * 2. in a unfinished write() call (long POST request)
			 */
			return mod_fastcgi_handle_subrequest(srv, con, p);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd", 
					"got a FDEVENT_OUT and didn't know why:", 
					hctx->state);
		}
	}
	
	/* perhaps this issue is already handled */
	if (revents & FDEVENT_HUP) {
		if (hctx->state == FCGI_STATE_CONNECT) {
			/* getoptsock will catch this one (right ?)
			 * 
			 * if we are in connect we might get a EINPROGRESS 
			 * in the first call and a FDEVENT_HUP in the 
			 * second round
			 * 
			 * FIXME: as it is a bit ugly.
			 * 
			 */
			return mod_fastcgi_handle_subrequest(srv, con, p);
		} else if (hctx->state == FCGI_STATE_READ &&
			   hctx->proc->port == 0) {
			/* FIXME:
			 * 
			 * ioctl says 8192 bytes to read from PHP and we receive directly a HUP for the socket
			 * even if the FCGI_FIN packet is not received yet
			 */
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sbSBSDSd", 
					"error: unexpected close of fastcgi connection for", 
					con->uri.path,
					"(no fastcgi process on host: ", 
					host->host,
					", port: ", 
					host->port,
					" ?)",
					hctx->state);
			
			connection_set_state(srv, con, CON_STATE_ERROR);
			fcgi_connection_close(srv, hctx);
		}
	} else if (revents & FDEVENT_ERR) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"fcgi: got a FDEVENT_ERR. Don't know why.");
		/* kill all connections to the fastcgi process */


		connection_set_state(srv, con, CON_STATE_ERROR);
		fcgi_connection_close(srv, hctx);
	}
	
	return HANDLER_FINISHED;
}
#define PATCH(x) \
	p->conf.x = s->x;
static int fcgi_patch_connection(server *srv, connection *con, plugin_data *p, const char *stage, size_t stage_len) {
	size_t i, j;
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		plugin_config *s = p->config_storage[i];
		
		/* not our stage */
		if (!buffer_is_equal_string(dc->comp_key, stage, stage_len)) continue;
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("fastcgi.server"))) {
				PATCH(exts);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("fastcgi.debug"))) {
				PATCH(debug);
			}
		}
	}
	
	return 0;
}

static int fcgi_setup_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	UNUSED(srv);
	UNUSED(con);
	
	PATCH(exts);
	PATCH(debug);
	
	return 0;
}
#undef PATCH


static handler_t fcgi_check_extension(server *srv, connection *con, void *p_d, int uri_path_handler) {
	plugin_data *p = p_d;
	size_t s_len;
	int used = -1;
	int ndx;
	size_t k, i;
	buffer *fn;
	fcgi_extension *extension = NULL;
	size_t path_info_offset;
	
	/* Possibly, we processed already this request */
	if (con->file_started == 1) return HANDLER_GO_ON;
	
	fn = uri_path_handler ? con->uri.path : con->physical.path;

	if (fn->used == 0) {
		return HANDLER_ERROR;
	}
	
	s_len = fn->used - 1;
	
	/* select the right config */
	fcgi_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		fcgi_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	path_info_offset = 0;
	
	/* check if extension matches */
	for (k = 0; k < p->conf.exts->used; k++) {
		size_t ct_len;
		
		extension = p->conf.exts->exts[k];
		
		if (extension->key->used == 0) continue;
		
		ct_len = extension->key->used - 1;
		
		if (s_len < ct_len) continue;
		
		/* check extension in the form "/fcgi_pattern" */
		if (*(extension->key->ptr) == '/' && strncmp(fn->ptr, extension->key->ptr, ct_len) == 0) {
			if (s_len > ct_len + 1) {
				char *pi_offset;
				
				if (0 != (pi_offset = strchr(fn->ptr + ct_len + 1, '/'))) {
					path_info_offset = pi_offset - fn->ptr;
				}
			}
			break;
		} else if (0 == strncmp(fn->ptr + s_len - ct_len, extension->key->ptr, ct_len)) {
			/* check extension in the form ".fcg" */
			break;
		}
	}
	
	/* extension doesn't match */
	if (k == p->conf.exts->used) {
		return HANDLER_GO_ON;
	}
	
	/* get best server */
	for (k = 0, ndx = -1; k < extension->used; k++) {
		fcgi_extension_host *host = extension->hosts[k];
		
		/* we should have at least one proc that can do somthing */
		if (host->active_procs == 0) continue;

		if (used == -1 || host->load < used) {
			used = host->load;
			
			ndx = k;
		}
	}
	
	/* found a server */
	if (ndx != -1) {
		fcgi_extension_host *host = extension->hosts[ndx];
		
		/* 
		 * if check-local is disabled, use the uri.path handler 
		 * 
		 */
		
		/* init handler-context */
		if (uri_path_handler) {
			if (host->check_local == 0) {
				handler_ctx *hctx;
				hctx = handler_ctx_init();
				
				hctx->path_info_offset = path_info_offset;
				hctx->remote_conn      = con;
				hctx->plugin_data      = p;
				hctx->host             = host;
				hctx->proc	       = NULL;

				hctx->conf.exts        = p->conf.exts;
				hctx->conf.debug       = p->conf.debug;
				
				con->plugin_ctx[p->id] = hctx;
				
				host->load++;
				
				con->mode = p->id;
			}
			return HANDLER_GO_ON;
		} else {
			handler_ctx *hctx;
			hctx = handler_ctx_init();
			
			hctx->path_info_offset = path_info_offset;
			hctx->remote_conn      = con;
			hctx->plugin_data      = p;
			hctx->host             = host;
			hctx->proc             = NULL;
			
			hctx->conf.exts        = p->conf.exts;
			hctx->conf.debug       = p->conf.debug;
			
			con->plugin_ctx[p->id] = hctx;
			
			host->load++;
			
			con->mode = p->id;
			
			return HANDLER_FINISHED;
		}
	} else {
		/* no handler found */
		buffer_reset(con->physical.path);
		con->http_status = 500;
		
		log_error_write(srv, __FILE__, __LINE__,  "sb", 
				"no fcgi-handler found for:", 
				fn);
		
		return HANDLER_FINISHED;
	}
	return HANDLER_GO_ON;
}

/* uri-path handler */
static handler_t fcgi_check_extension_1(server *srv, connection *con, void *p_d) {
	return fcgi_check_extension(srv, con, p_d, 1);
}

/* start request handler */
static handler_t fcgi_check_extension_2(server *srv, connection *con, void *p_d) {
	return fcgi_check_extension(srv, con, p_d, 0);
}

JOBLIST_FUNC(mod_fastcgi_handle_joblist) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	
	if (hctx == NULL) return HANDLER_GO_ON;

	if (hctx->fd != -1) {
		switch (hctx->state) {
		case FCGI_STATE_READ:
			fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
			
			break;
		case FCGI_STATE_CONNECT:
		case FCGI_STATE_WRITE:
			fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
			
			break;
		case FCGI_STATE_INIT:
			/* at reconnect */
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sd", "unhandled fcgi.state", hctx->state);
			break;
		}
	}

	return HANDLER_GO_ON;
}


static handler_t fcgi_connection_close_callback(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	
	return fcgi_connection_close(srv, con->plugin_ctx[p->id]);
}

TRIGGER_FUNC(mod_fastcgi_handle_trigger) {
	plugin_data *p = p_d;
	size_t i, j, n;
	
	
	/* perhaps we should kill a connect attempt after 10-15 seconds
	 * 
	 * currently we wait for the TCP timeout which is on Linux 180 seconds
	 * 
	 * 
	 * 
	 */

	/* check all childs if they are still up */

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *conf;
		fcgi_exts *exts;

		conf = p->config_storage[i];

		exts = conf->exts;

		for (j = 0; j < exts->used; j++) {
			fcgi_extension *ex;

			ex = exts->exts[j];
			
			for (n = 0; n < ex->used; n++) {
				
				fcgi_proc *proc;
				unsigned long sum_load = 0;
				fcgi_extension_host *host;
				
				host = ex->hosts[n];
				
				fcgi_restart_dead_procs(srv, p, host);
				
				for (proc = host->first; proc; proc = proc->next) {
					sum_load += proc->load;
				}
				
				if (host->num_procs &&
				    host->num_procs < host->max_procs &&
				    (sum_load / host->num_procs) > host->max_load_per_proc) {
					/* overload, spawn new child */
					fcgi_proc *fp = NULL;
					
					if (p->conf.debug) {
						log_error_write(srv, __FILE__, __LINE__, "s", 
								"overload detected, spawning a new child");
					}
					
					for (fp = host->unused_procs; fp && fp->pid != 0; fp = fp->next);
					
					if (fp) {
						if (fp == host->unused_procs) host->unused_procs = fp->next;
						
						if (fp->next) fp->next->prev = NULL;
						
						host->max_id++;
					} else {
						fp = fastcgi_process_init();
						fp->id = host->max_id++;
					}
					
					host->num_procs++;
					
					if (buffer_is_empty(host->unixsocket)) {
						fp->port = host->port + fp->id;
					} else {
						buffer_copy_string_buffer(fp->socket, host->unixsocket);
						buffer_append_string(fp->socket, "-");
						buffer_append_long(fp->socket, fp->id);
					}
					
					if (fcgi_spawn_connection(srv, p, host, fp)) {
						log_error_write(srv, __FILE__, __LINE__, "s",
								"ERROR: spawning fcgi failed.");
						return HANDLER_ERROR;
					}
					
					fp->prev = NULL;
					fp->next = host->first;
					if (host->first) {
						host->first->prev = fp;
					}
					host->first = fp;
				}
				
				for (proc = host->first; proc; proc = proc->next) {
					if (proc->load != 0) break;
					if (host->num_procs <= host->min_procs) break;
					if (proc->pid == 0) continue;
					
					if (srv->cur_ts - proc->last_used > host->idle_timeout) {
						/* a proc is idling for a long time now,
						 * terminated it */
						
						if (p->conf.debug) {
							log_error_write(srv, __FILE__, __LINE__, "ssbsd", 
									"idle-timeout reached, terminating child:", 
									"socket:", proc->socket, 
									"pid", proc->pid);
						}
						
						
						if (proc->next) proc->next->prev = proc->prev;
						if (proc->prev) proc->prev->next = proc->next;
						
						if (proc->prev == NULL) host->first = proc->next;
						
						proc->prev = NULL;
						proc->next = host->unused_procs;
						
						if (host->unused_procs) host->unused_procs->prev = proc;
						host->unused_procs = proc;
						
						kill(proc->pid, SIGTERM);
						
						proc->state = PROC_STATE_KILLED;
						
						log_error_write(srv, __FILE__, __LINE__, "ssbsd", 
									"killed:", 
									"socket:", proc->socket, 
									"pid", proc->pid);
						
						host->num_procs--;
						
						/* proc is now in unused, let the next second handle the next process */
						break;
					}	
				}
				
				for (proc = host->unused_procs; proc; proc = proc->next) {
					int status;
					
					if (proc->pid == 0) continue;
					
					switch (waitpid(proc->pid, &status, WNOHANG)) {
					case 0:
						/* child still running after timeout, good */
						break;
					case -1:
						if (errno != EINTR) {
							/* no PID found ? should never happen */
							log_error_write(srv, __FILE__, __LINE__, "sddss", 
									"pid ", proc->pid, proc->state,
									"not found:", strerror(errno));
							
#if 0
							if (errno == ECHILD) {
								/* someone else has cleaned up for us */
								proc->pid = 0;
								proc->state = PROC_STATE_UNSET;
							}
#endif
						}
						break;
					default:
						/* the child should not terminate at all */
						if (WIFEXITED(status)) {
							if (proc->state != PROC_STATE_KILLED) {
								log_error_write(srv, __FILE__, __LINE__, "sdb", 
										"child exited:", 
										WEXITSTATUS(status), proc->socket);
							}
						} else if (WIFSIGNALED(status)) {
							if (WTERMSIG(status) != SIGTERM) {
								log_error_write(srv, __FILE__, __LINE__, "sd", 
										"child signaled:", 
										WTERMSIG(status));
							}
						} else {
							log_error_write(srv, __FILE__, __LINE__, "sd", 
									"child died somehow:", 
									status);
						}
						proc->pid = 0;
						proc->state = PROC_STATE_UNSET;
						host->max_id--;
					}
				}
			}
		}
	}

	return HANDLER_GO_ON;
}


int mod_fastcgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name         = buffer_init_string("fastcgi");

	p->init         = mod_fastcgi_init;
	p->cleanup      = mod_fastcgi_free;
	p->set_defaults = mod_fastcgi_set_defaults;
	p->connection_reset        = fcgi_connection_reset;
	p->handle_connection_close = fcgi_connection_close_callback;
	p->handle_uri_clean        = fcgi_check_extension_1;
	p->handle_subrequest_start = fcgi_check_extension_2;
	p->handle_subrequest       = mod_fastcgi_handle_subrequest;
	p->handle_joblist          = mod_fastcgi_handle_joblist;
	p->handle_trigger          = mod_fastcgi_handle_trigger;
	
	p->data         = NULL;
	
	return 0;
}
