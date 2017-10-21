#include "first.h"

#include "server.h"
#include "stat_cache.h"
#include "keyvalue.h"
#include "log.h"
#include "connections.h"
#include "joblist.h"
#include "response.h"
#include "http_chunk.h"

#include "plugin.h"

#include <sys/types.h>
#include "sys-mmap.h"
#include "sys-socket.h"
# include <sys/wait.h>

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fdevent.h>

#include <fcntl.h>
#include <signal.h>

static int pipe_cloexec(int pipefd[2]) {
  #ifdef HAVE_PIPE2
    if (0 == pipe2(pipefd, O_CLOEXEC)) return 0;
  #endif
    return 0 == pipe(pipefd)
       #ifdef FD_CLOEXEC
        && 0 == fcntl(pipefd[0], F_SETFD, FD_CLOEXEC)
        && 0 == fcntl(pipefd[1], F_SETFD, FD_CLOEXEC)
       #endif
      ?  0
      : -1;
}

typedef struct {
	char **ptr;

	size_t size;
	size_t used;
} char_array;

typedef struct {
	struct { pid_t pid; void *ctx; } *ptr;
	size_t used;
	size_t size;
} buffer_pid_t;

typedef struct {
	array *cgi;
	unsigned short execute_x_only;
	unsigned short local_redir;
	unsigned short xsendfile_allow;
	unsigned short upgrade;
	array *xsendfile_docroot;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	buffer_pid_t cgi_pid;

	plugin_config **config_storage;

	plugin_config conf;
} plugin_data;

typedef struct {
	pid_t pid;
	int fd;
	int fdtocgi;
	int fde_ndx; /* index into the fd-event buffer */
	int fde_ndx_tocgi; /* index into the fd-event buffer */

	connection *remote_conn;  /* dumb pointer */
	plugin_data *plugin_data; /* dumb pointer */

	buffer *response;
	buffer *cgi_handler;      /* dumb pointer */
	http_response_opts opts;
	plugin_config conf;
} handler_ctx;

static handler_ctx * cgi_handler_ctx_init(void) {
	handler_ctx *hctx = calloc(1, sizeof(*hctx));

	force_assert(hctx);

	hctx->response = buffer_init();
	hctx->fd = -1;
	hctx->fdtocgi = -1;

	return hctx;
}

static void cgi_handler_ctx_free(handler_ctx *hctx) {
	buffer_free(hctx->response);
	free(hctx);
}

INIT_FUNC(mod_cgi_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	force_assert(p);

	return p;
}


FREE_FUNC(mod_cgi_free) {
	plugin_data *p = p_d;
	buffer_pid_t *r = &(p->cgi_pid);

	UNUSED(srv);

	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			array_free(s->cgi);
			array_free(s->xsendfile_docroot);

			free(s);
		}
		free(p->config_storage);
	}


	if (r->ptr) free(r->ptr);

	free(p);

	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_fastcgi_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "cgi.assign",                  NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "cgi.execute-x-only",          NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 1 */
		{ "cgi.x-sendfile",              NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 2 */
		{ "cgi.x-sendfile-docroot",      NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_CONNECTION },     /* 3 */
		{ "cgi.local-redir",             NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 4 */
		{ "cgi.upgrade",                 NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 5 */
		{ NULL,                          NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET}
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));
	force_assert(p->config_storage);

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		force_assert(s);

		s->cgi    = array_init();
		s->execute_x_only = 0;
		s->local_redir    = 0;
		s->xsendfile_allow= 0;
		s->xsendfile_docroot = array_init();
		s->upgrade        = 0;

		cv[0].destination = s->cgi;
		cv[1].destination = &(s->execute_x_only);
		cv[2].destination = &(s->xsendfile_allow);
		cv[3].destination = s->xsendfile_docroot;
		cv[4].destination = &(s->local_redir);
		cv[5].destination = &(s->upgrade);

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (!array_is_kvstring(s->cgi)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for cgi.assign; expected list of \"ext\" => \"exepath\"");
			return HANDLER_ERROR;
		}

		if (s->xsendfile_docroot->used) {
			size_t j;
			for (j = 0; j < s->xsendfile_docroot->used; ++j) {
				data_string *ds = (data_string *)s->xsendfile_docroot->data[j];
				if (ds->type != TYPE_STRING) {
					log_error_write(srv, __FILE__, __LINE__, "s",
						"unexpected type for key cgi.x-sendfile-docroot; expected: cgi.x-sendfile-docroot = ( \"/allowed/path\", ... )");
					return HANDLER_ERROR;
				}
				if (ds->value->ptr[0] != '/') {
					log_error_write(srv, __FILE__, __LINE__, "SBs",
						"cgi.x-sendfile-docroot paths must begin with '/'; invalid: \"", ds->value, "\"");
					return HANDLER_ERROR;
				}
				buffer_path_simplify(ds->value, ds->value);
				buffer_append_slash(ds->value);
			}
		}
	}

	return HANDLER_GO_ON;
}


static void cgi_pid_add(plugin_data *p, pid_t pid, void *ctx) {
	buffer_pid_t *r = &(p->cgi_pid);

	if (r->size == 0) {
		r->size = 16;
		r->ptr = malloc(sizeof(*r->ptr) * r->size);
		force_assert(r->ptr);
	} else if (r->used == r->size) {
		r->size += 16;
		r->ptr = realloc(r->ptr, sizeof(*r->ptr) * r->size);
		force_assert(r->ptr);
	}

	r->ptr[r->used].pid = pid;
	r->ptr[r->used].ctx = ctx;
	++r->used;
}

static void cgi_pid_kill(plugin_data *p, pid_t pid) {
    buffer_pid_t *r = &(p->cgi_pid);
    for (size_t i = 0; i < r->used; ++i) {
        if (r->ptr[i].pid == pid) {
            r->ptr[i].ctx = NULL;
            kill(pid, SIGTERM);
            return;
        }
    }
}

static void cgi_pid_del(plugin_data *p, size_t i) {
	buffer_pid_t *r = &(p->cgi_pid);

		if (i != r->used - 1) {
			r->ptr[i] = r->ptr[r->used - 1];
		}
		r->used--;
}


static void cgi_connection_close_fdtocgi(server *srv, handler_ctx *hctx) {
	/*(closes only hctx->fdtocgi)*/
	fdevent_event_del(srv->ev, &(hctx->fde_ndx_tocgi), hctx->fdtocgi);
	/*fdevent_unregister(srv->ev, hctx->fdtocgi);*//*(handled below)*/
	fdevent_sched_close(srv->ev, hctx->fdtocgi, 0);
	hctx->fdtocgi = -1;
}

static void cgi_connection_close(server *srv, handler_ctx *hctx) {
	plugin_data *p = hctx->plugin_data;
	connection *con = hctx->remote_conn;

	/* the connection to the browser went away, but we still have a connection
	 * to the CGI script
	 *
	 * close cgi-connection
	 */

	if (hctx->fd != -1) {
		/* close connection to the cgi-script */
		fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
		/*fdevent_unregister(srv->ev, hctx->fd);*//*(handled below)*/
		fdevent_sched_close(srv->ev, hctx->fd, 0);
	}

	if (hctx->fdtocgi != -1) {
		cgi_connection_close_fdtocgi(srv, hctx); /*(closes only hctx->fdtocgi)*/
	}

	if (hctx->pid > 0) {
		cgi_pid_kill(p, hctx->pid);
	}

	con->plugin_ctx[p->id] = NULL;

	cgi_handler_ctx_free(hctx);

	/* finish response (if not already con->file_started, con->file_finished) */
	if (con->mode == p->id) {
		http_response_backend_done(srv, con);
	}
}

static handler_t cgi_connection_close_callback(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	if (hctx) cgi_connection_close(srv, hctx);

	return HANDLER_GO_ON;
}


static int cgi_write_request(server *srv, handler_ctx *hctx, int fd);


static handler_t cgi_handle_fdevent_send (server *srv, void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;

	/*(joblist only actually necessary here in mod_cgi fdevent send if returning HANDLER_ERROR)*/
	joblist_append(srv, con);

	if (revents & FDEVENT_OUT) {
		if (0 != cgi_write_request(srv, hctx, hctx->fdtocgi)) {
			cgi_connection_close(srv, hctx);
			return HANDLER_ERROR;
		}
		/* more request body to be sent to CGI */
	}

	if (revents & FDEVENT_HUP) {
		/* skip sending remaining data to CGI */
		if (con->request.content_length) {
			chunkqueue *cq = con->request_content_queue;
			chunkqueue_mark_written(cq, chunkqueue_length(cq));
			if (cq->bytes_in != (off_t)con->request.content_length) {
				con->keep_alive = 0;
			}
		}

		cgi_connection_close_fdtocgi(srv, hctx); /*(closes only hctx->fdtocgi)*/
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the cgi process */
#if 1
		log_error_write(srv, __FILE__, __LINE__, "s", "cgi-FDEVENT_ERR");
#endif
		cgi_connection_close(srv, hctx);
		return HANDLER_ERROR;
	}

	return HANDLER_FINISHED;
}


static handler_t cgi_response_headers(server *srv, connection *con, struct http_response_opts_t *opts) {
    /* response headers just completed */
    handler_ctx *hctx = (handler_ctx *)opts->pdata;

    if (con->parsed_response & HTTP_UPGRADE) {
        if (hctx->conf.upgrade && con->http_status == 101) {
            /* 101 Switching Protocols; transition to transparent proxy */
            http_response_upgrade_read_body_unknown(srv, con);
        }
        else {
            con->parsed_response &= ~HTTP_UPGRADE;
          #if 0
            /* preserve prior questionable behavior; likely broken behavior
             * anyway if backend thinks connection is being upgraded but client
             * does not receive Connection: upgrade */
            response_header_overwrite(srv, con, CONST_STR_LEN("Upgrade"),
                                                CONST_STR_LEN(""));
          #endif
        }
    }

    if (hctx->conf.upgrade && !(con->parsed_response & HTTP_UPGRADE)) {
        chunkqueue *cq = con->request_content_queue;
        hctx->conf.upgrade = 0;
        if (cq->bytes_out == (off_t)con->request.content_length) {
            cgi_connection_close_fdtocgi(srv, hctx); /*(closes hctx->fdtocgi)*/
        }
    }

    return HANDLER_GO_ON;
}


static int cgi_recv_response(server *srv, handler_ctx *hctx) {
		switch (http_response_read(srv, hctx->remote_conn, &hctx->opts,
					   hctx->response, hctx->fd, &hctx->fde_ndx)) {
		default:
			return HANDLER_GO_ON;
		case HANDLER_ERROR:
			http_response_backend_error(srv, hctx->remote_conn);
			/* fall through */
		case HANDLER_FINISHED:
			cgi_connection_close(srv, hctx);
			return HANDLER_FINISHED;
		case HANDLER_COMEBACK:
			/* hctx->conf.local_redir */
			connection_response_reset(srv, hctx->remote_conn); /*(includes con->http_status = 0)*/
			plugins_call_connection_reset(srv, hctx->remote_conn);
			/*cgi_connection_close(srv, hctx);*//*(already cleaned up and hctx is now invalid)*/
			return HANDLER_COMEBACK;
		}
}


static handler_t cgi_handle_fdevent(server *srv, void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;

	joblist_append(srv, con);

	if (revents & FDEVENT_IN) {
		handler_t rc = cgi_recv_response(srv, hctx);/*(might invalidate hctx)*/
		if (rc != HANDLER_GO_ON) return rc;         /*(unless HANDLER_GO_ON)*/
	}

	/* perhaps this issue is already handled */
	if (revents & FDEVENT_HUP) {
		if (con->file_started) {
			/* drain any remaining data from kernel pipe buffers
			 * even if (con->conf.stream_response_body
			 *          & FDEVENT_STREAM_RESPONSE_BUFMIN)
			 * since event loop will spin on fd FDEVENT_HUP event
			 * until unregistered. */
			handler_t rc;
			do {
				rc = cgi_recv_response(srv,hctx);/*(might invalidate hctx)*/
			} while (rc == HANDLER_GO_ON);           /*(unless HANDLER_GO_ON)*/
			return rc; /* HANDLER_FINISHED or HANDLER_COMEBACK or HANDLER_ERROR */
		} else if (!buffer_string_is_empty(hctx->response)) {
			/* unfinished header package which is a body in reality */
			con->file_started = 1;
			if (0 != http_chunk_append_buffer(srv, con, hctx->response)) {
				cgi_connection_close(srv, hctx);
				return HANDLER_ERROR;
			}
			if (0 == con->http_status) con->http_status = 200; /* OK */
		}
		cgi_connection_close(srv, hctx);
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the cgi process */
		cgi_connection_close(srv, hctx);
		return HANDLER_ERROR;
	}

	return HANDLER_FINISHED;
}


static int cgi_env_add(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	char_array *env = venv;
	char *dst;

	if (!key || !val) return -1;

	dst = malloc(key_len + val_len + 2);
	force_assert(dst);
	memcpy(dst, key, key_len);
	dst[key_len] = '=';
	memcpy(dst + key_len + 1, val, val_len);
	dst[key_len + 1 + val_len] = '\0';

	if (env->size == 0) {
		env->size = 16;
		env->ptr = malloc(env->size * sizeof(*env->ptr));
		force_assert(env->ptr);
	} else if (env->size == env->used) {
		env->size += 16;
		env->ptr = realloc(env->ptr, env->size * sizeof(*env->ptr));
		force_assert(env->ptr);
	}

	env->ptr[env->used++] = dst;

	return 0;
}

/*(improved from network_write_mmap.c)*/
static off_t mmap_align_offset(off_t start) {
    static off_t pagemask = 0;
    if (0 == pagemask) {
        long pagesize = sysconf(_SC_PAGESIZE);
        if (-1 == pagesize) pagesize = 4096;
        pagemask = ~((off_t)pagesize - 1); /* pagesize always power-of-2 */
    }
    return (start & pagemask);
}

/* returns: 0: continue, -1: fatal error, -2: connection reset */
/* similar to network_write_file_chunk_mmap, but doesn't use send on windows (because we're on pipes),
 * also mmaps and sends complete chunk instead of only small parts - the files
 * are supposed to be temp files with reasonable chunk sizes.
 *
 * Also always use mmap; the files are "trusted", as we created them.
 */
static ssize_t cgi_write_file_chunk_mmap(server *srv, connection *con, int fd, chunkqueue *cq) {
	chunk* const c = cq->first;
	off_t offset, toSend, file_end;
	ssize_t r;
	size_t mmap_offset, mmap_avail;
	char *data = NULL;

	force_assert(NULL != c);
	force_assert(FILE_CHUNK == c->type);
	force_assert(c->offset >= 0 && c->offset <= c->file.length);

	offset = c->file.start + c->offset;
	toSend = c->file.length - c->offset;
	file_end = c->file.start + c->file.length; /* offset to file end in this chunk */

	if (0 == toSend) {
		chunkqueue_remove_finished_chunks(cq);
		return 0;
	}

	/*(simplified from chunk.c:chunkqueue_open_file_chunk())*/
	UNUSED(con);
	if (-1 == c->file.fd) {
		if (-1 == (c->file.fd = fdevent_open_cloexec(c->file.name->ptr, O_RDONLY, 0))) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "open failed:", strerror(errno), c->file.name);
			return -1;
		}
	}

	/* (re)mmap the buffer if range is not covered completely */
	if (MAP_FAILED == c->file.mmap.start
		|| offset < c->file.mmap.offset
		|| file_end > (off_t)(c->file.mmap.offset + c->file.mmap.length)) {

		if (MAP_FAILED != c->file.mmap.start) {
			munmap(c->file.mmap.start, c->file.mmap.length);
			c->file.mmap.start = MAP_FAILED;
		}

		c->file.mmap.offset = mmap_align_offset(offset);
		c->file.mmap.length = file_end - c->file.mmap.offset;

		if (MAP_FAILED == (c->file.mmap.start = mmap(NULL, c->file.mmap.length, PROT_READ, MAP_PRIVATE, c->file.fd, c->file.mmap.offset))) {
			if (toSend > 65536) toSend = 65536;
			data = malloc(toSend);
			force_assert(data);
			if (-1 == lseek(c->file.fd, offset, SEEK_SET)
			    || 0 >= (toSend = read(c->file.fd, data, toSend))) {
				if (-1 == toSend) {
					log_error_write(srv, __FILE__, __LINE__, "ssbdo", "lseek/read failed:",
						strerror(errno), c->file.name, c->file.fd, offset);
				} else { /*(0 == toSend)*/
					log_error_write(srv, __FILE__, __LINE__, "sbdo", "unexpected EOF (input truncated?):",
						c->file.name, c->file.fd, offset);
				}
				free(data);
				return -1;
			}
		}
	}

	if (MAP_FAILED != c->file.mmap.start) {
		force_assert(offset >= c->file.mmap.offset);
		mmap_offset = offset - c->file.mmap.offset;
		force_assert(c->file.mmap.length > mmap_offset);
		mmap_avail = c->file.mmap.length - mmap_offset;
		force_assert(toSend <= (off_t) mmap_avail);

		data = c->file.mmap.start + mmap_offset;
	}

	r = write(fd, data, toSend);

	if (MAP_FAILED == c->file.mmap.start) free(data);

	if (r < 0) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return 0;
		case EPIPE:
		case ECONNRESET:
			return -2;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ssd",
				"write failed:", strerror(errno), fd);
			return -1;
		}
	}

	if (r >= 0) {
		chunkqueue_mark_written(cq, r);
	}

	return r;
}

static int cgi_write_request(server *srv, handler_ctx *hctx, int fd) {
	connection *con = hctx->remote_conn;
	chunkqueue *cq = con->request_content_queue;
	chunk *c;

	/* old comment: windows doesn't support select() on pipes - wouldn't be easy to fix for all platforms.
	 * solution: if this is still a problem on windows, then substitute
	 * socketpair() for pipe() and closesocket() for close() on windows.
	 */

	for (c = cq->first; c; c = cq->first) {
		ssize_t r = -1;

		switch(c->type) {
		case FILE_CHUNK:
			r = cgi_write_file_chunk_mmap(srv, con, fd, cq);
			break;

		case MEM_CHUNK:
			if ((r = write(fd, c->mem->ptr + c->offset, buffer_string_length(c->mem) - c->offset)) < 0) {
				switch(errno) {
				case EAGAIN:
				case EINTR:
					/* ignore and try again */
					r = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					/* connection closed */
					r = -2;
					break;
				default:
					/* fatal error */
					log_error_write(srv, __FILE__, __LINE__, "ss", "write failed due to: ", strerror(errno));
					r = -1;
					break;
				}
			} else if (r > 0) {
				chunkqueue_mark_written(cq, r);
			}
			break;
		}

		if (0 == r) break; /*(might block)*/

		switch (r) {
		case -1:
			/* fatal error */
			return -1;
		case -2:
			/* connection reset */
			log_error_write(srv, __FILE__, __LINE__, "s", "failed to send post data to cgi, connection closed by CGI");
			/* skip all remaining data */
			chunkqueue_mark_written(cq, chunkqueue_length(cq));
			break;
		default:
			break;
		}
	}

	if (cq->bytes_out == (off_t)con->request.content_length && !hctx->conf.upgrade) {
		/* sent all request body input */
		/* close connection to the cgi-script */
		if (-1 == hctx->fdtocgi) { /*(received request body sent in initial send to pipe buffer)*/
			--srv->cur_fds;
			if (close(fd)) {
				log_error_write(srv, __FILE__, __LINE__, "sds", "cgi stdin close failed ", fd, strerror(errno));
			}
		} else {
			cgi_connection_close_fdtocgi(srv, hctx); /*(closes only hctx->fdtocgi)*/
		}
	} else {
		off_t cqlen = cq->bytes_in - cq->bytes_out;
		if (cq->bytes_in != con->request.content_length && cqlen < 65536 - 16384) {
			/*(con->conf.stream_request_body & FDEVENT_STREAM_REQUEST)*/
			if (!(con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN)) {
				con->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
				con->is_readable = 1; /* trigger optimistic read from client */
			}
		}
		if (-1 == hctx->fdtocgi) { /*(not registered yet)*/
			hctx->fdtocgi = fd;
			hctx->fde_ndx_tocgi = -1;
			fdevent_register(srv->ev, hctx->fdtocgi, cgi_handle_fdevent_send, hctx);
		}
		if (0 == cqlen) { /*(chunkqueue_is_empty(cq))*/
			if ((fdevent_event_get_interest(srv->ev, hctx->fdtocgi) & FDEVENT_OUT)) {
				fdevent_event_set(srv->ev, &(hctx->fde_ndx_tocgi), hctx->fdtocgi, 0);
			}
		} else {
			/* more request body remains to be sent to CGI so register for fdevents */
			fdevent_event_set(srv->ev, &(hctx->fde_ndx_tocgi), hctx->fdtocgi, FDEVENT_OUT);
		}
	}

	return 0;
}

static int cgi_create_env(server *srv, connection *con, plugin_data *p, handler_ctx *hctx, buffer *cgi_handler) {
	char_array env;
	char *args[3];
	int to_cgi_fds[2];
	int from_cgi_fds[2];
	int dfd = -1;
	UNUSED(p);

	if (!buffer_string_is_empty(cgi_handler)) {
		/* stat the exec file */
		struct stat st;
		if (-1 == (stat(cgi_handler->ptr, &st))) {
			log_error_write(srv, __FILE__, __LINE__, "sbss",
					"stat for cgi-handler", cgi_handler,
					"failed:", strerror(errno));
			return -1;
		}
	}

	if (pipe_cloexec(to_cgi_fds)) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "pipe failed:", strerror(errno));
		return -1;
	}
	if (pipe_cloexec(from_cgi_fds)) {
		close(to_cgi_fds[0]);
		close(to_cgi_fds[1]);
		log_error_write(srv, __FILE__, __LINE__, "ss", "pipe failed:", strerror(errno));
		return -1;
	}
	fdevent_setfd_cloexec(to_cgi_fds[1]);
	fdevent_setfd_cloexec(from_cgi_fds[0]);

	{
		int i = 0;
		const char *s;
		http_cgi_opts opts = { 0, 0, NULL, NULL };

		/* create environment */
		env.ptr = NULL;
		env.size = 0;
		env.used = 0;

		http_cgi_headers(srv, con, &opts, cgi_env_add, &env);

		/* for valgrind */
		if (NULL != (s = getenv("LD_PRELOAD"))) {
			cgi_env_add(&env, CONST_STR_LEN("LD_PRELOAD"), s, strlen(s));
		}

		if (NULL != (s = getenv("LD_LIBRARY_PATH"))) {
			cgi_env_add(&env, CONST_STR_LEN("LD_LIBRARY_PATH"), s, strlen(s));
		}
#ifdef __CYGWIN__
		/* CYGWIN needs SYSTEMROOT */
		if (NULL != (s = getenv("SYSTEMROOT"))) {
			cgi_env_add(&env, CONST_STR_LEN("SYSTEMROOT"), s, strlen(s));
		}
#endif

		if (env.size == env.used) {
			env.size += 16;
			env.ptr = realloc(env.ptr, env.size * sizeof(*env.ptr));
		}

		env.ptr[env.used] = NULL;

		/* set up args */
		i = 0;

		if (!buffer_string_is_empty(cgi_handler)) {
			args[i++] = cgi_handler->ptr;
		}
		args[i++] = con->physical.path->ptr;
		args[i  ] = NULL;
	}

	dfd = fdevent_open_dirname(con->physical.path->ptr);
	if (-1 == dfd) {
		log_error_write(srv, __FILE__, __LINE__, "ssb", "open dirname failed:", strerror(errno), con->physical.path);
	}

	hctx->pid = (dfd >= 0) ? fdevent_fork_execve(args[0], args, env.ptr, to_cgi_fds[0], from_cgi_fds[1], -1, dfd) : -1;

	for (size_t i = 0; i < env.used; ++i) free(env.ptr[i]);
	free(env.ptr);

	if (-1 == hctx->pid) {
		/* log error with errno prior to calling close() (might change errno) */
		log_error_write(srv, __FILE__, __LINE__, "ss", "fork failed:", strerror(errno));
		if (-1 != dfd) close(dfd);
		close(from_cgi_fds[0]);
		close(from_cgi_fds[1]);
		close(to_cgi_fds[0]);
		close(to_cgi_fds[1]);
		return -1;
	} else {
		if (-1 != dfd) close(dfd);
		close(from_cgi_fds[1]);
		close(to_cgi_fds[0]);

		hctx->fd = from_cgi_fds[0];
		hctx->fde_ndx = -1;

		++srv->cur_fds;

		cgi_pid_add(p, hctx->pid, hctx);

		if (0 == con->request.content_length) {
			close(to_cgi_fds[1]);
		} else {
			/* there is content to send */
			if (-1 == fdevent_fcntl_set_nb(srv->ev, to_cgi_fds[1])) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed: ", strerror(errno));
				close(to_cgi_fds[1]);
				cgi_connection_close(srv, hctx);
				return -1;
			}

			if (0 != cgi_write_request(srv, hctx, to_cgi_fds[1])) {
				close(to_cgi_fds[1]);
				cgi_connection_close(srv, hctx);
				return -1;
			}

			++srv->cur_fds;
		}

		fdevent_register(srv->ev, hctx->fd, cgi_handle_fdevent, hctx);
		if (-1 == fdevent_fcntl_set_nb(srv->ev, hctx->fd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed: ", strerror(errno));
			cgi_connection_close(srv, hctx);
			return -1;
		}
		fdevent_event_set(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);

		return 0;
	}
}

static buffer * cgi_get_handler(array *a, buffer *fn) {
	size_t k, s_len = buffer_string_length(fn);
	for (k = 0; k < a->used; ++k) {
		data_string *ds = (data_string *)a->data[k];
		size_t ct_len = buffer_string_length(ds->key);

		if (buffer_is_empty(ds->key)) continue;
		if (s_len < ct_len) continue;

		if (0 == strncmp(fn->ptr + s_len - ct_len, ds->key->ptr, ct_len)) {
			return ds->value;
		}
	}

	return NULL;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_cgi_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(cgi);
	PATCH(execute_x_only);
	PATCH(local_redir);
	PATCH(upgrade);
	PATCH(xsendfile_allow);
	PATCH(xsendfile_docroot);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("cgi.assign"))) {
				PATCH(cgi);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cgi.execute-x-only"))) {
				PATCH(execute_x_only);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cgi.local-redir"))) {
				PATCH(local_redir);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cgi.upgrade"))) {
				PATCH(upgrade);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cgi.x-sendfile"))) {
				PATCH(xsendfile_allow);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cgi.x-sendfile-docroot"))) {
				PATCH(xsendfile_docroot);
			}
		}
	}

	return 0;
}
#undef PATCH

URIHANDLER_FUNC(cgi_is_handled) {
	plugin_data *p = p_d;
	buffer *fn = con->physical.path;
	stat_cache_entry *sce = NULL;
	struct stat stbuf;
	struct stat *st;
	buffer *cgi_handler;

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	if (buffer_is_empty(fn)) return HANDLER_GO_ON;

	mod_cgi_patch_connection(srv, con, p);

	if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
		st = &sce->st;
	} else {
		/* CGI might be executable even if it is not readable
		 * (stat_cache_get_entry() currently checks file is readable)*/
		if (0 != stat(con->physical.path->ptr, &stbuf)) return HANDLER_GO_ON;
		st = &stbuf;
	}

	if (!S_ISREG(st->st_mode)) return HANDLER_GO_ON;
	if (p->conf.execute_x_only == 1 && (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) return HANDLER_GO_ON;

	if (NULL != (cgi_handler = cgi_get_handler(p->conf.cgi, fn))) {
		handler_ctx *hctx = cgi_handler_ctx_init();
		hctx->remote_conn = con;
		hctx->plugin_data = p;
		hctx->cgi_handler = cgi_handler;
		memcpy(&hctx->conf, &p->conf, sizeof(plugin_config));
		hctx->conf.upgrade =
		  hctx->conf.upgrade
		  && con->request.http_version == HTTP_VERSION_1_1
		  && NULL != array_get_element_klen(con->request.headers, CONST_STR_LEN("Upgrade"));
		hctx->opts.fdfmt = S_IFIFO;
		hctx->opts.backend = BACKEND_CGI;
		hctx->opts.authorizer = 0;
		hctx->opts.local_redir = hctx->conf.local_redir;
		hctx->opts.xsendfile_allow = hctx->conf.xsendfile_allow;
		hctx->opts.xsendfile_docroot = hctx->conf.xsendfile_docroot;
		hctx->opts.pdata = hctx;
		hctx->opts.headers = cgi_response_headers;
		con->plugin_ctx[p->id] = hctx;
		con->mode = p->id;
	}

	return HANDLER_GO_ON;
}

/*
 * - HANDLER_GO_ON : not our job
 * - HANDLER_FINISHED: got response
 * - HANDLER_WAIT_FOR_EVENT: waiting for response
 */
SUBREQUEST_FUNC(mod_cgi_handle_subrequest) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	chunkqueue *cq = con->request_content_queue;

	if (con->mode != p->id) return HANDLER_GO_ON;
	if (NULL == hctx) return HANDLER_GO_ON;

	if ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
	    && con->file_started) {
		if (chunkqueue_length(con->write_queue) > 65536 - 4096) {
			fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
		} else if (!(fdevent_event_get_interest(srv->ev, hctx->fd) & FDEVENT_IN)) {
			/* optimistic read from backend */
			handler_t rc = cgi_recv_response(srv, hctx); /*(might invalidate hctx)*/
			if (rc != HANDLER_GO_ON) return rc;          /*(unless HANDLER_GO_ON)*/
			fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
		}
	}

	if (cq->bytes_in != (off_t)con->request.content_length) {
		/*(64k - 4k to attempt to avoid temporary files
		 * in conjunction with FDEVENT_STREAM_REQUEST_BUFMIN)*/
		if (cq->bytes_in - cq->bytes_out > 65536 - 4096
		    && (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN)){
			con->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
			if (-1 != hctx->fd) return HANDLER_WAIT_FOR_EVENT;
		} else {
			handler_t r = connection_handle_read_post_state(srv, con);
			if (!chunkqueue_is_empty(cq)) {
				if (fdevent_event_get_interest(srv->ev, hctx->fdtocgi) & FDEVENT_OUT) {
					return (r == HANDLER_GO_ON) ? HANDLER_WAIT_FOR_EVENT : r;
				}
			}
			if (r != HANDLER_GO_ON) return r;

			/* CGI environment requires that Content-Length be set.
			 * Send 411 Length Required if Content-Length missing.
			 * (occurs here if client sends Transfer-Encoding: chunked
			 *  and module is flagged to stream request body to backend) */
			if (-1 == con->request.content_length) {
				return connection_handle_read_post_error(srv, con, 411);
			}
		}
	}

	if (-1 == hctx->fd) {
		if (cgi_create_env(srv, con, p, hctx, hctx->cgi_handler)) {
			con->http_status = 500;
			con->mode = DIRECT;

			return HANDLER_FINISHED;
		}
	} else if (!chunkqueue_is_empty(con->request_content_queue)) {
		if (0 != cgi_write_request(srv, hctx, hctx->fdtocgi)) {
			cgi_connection_close(srv, hctx);
			return HANDLER_ERROR;
		}
	}

	/* if not done, wait for CGI to close stdout, so we read EOF on pipe */
	return HANDLER_WAIT_FOR_EVENT;
}


static handler_t cgi_waitpid_cb(server *srv, void *p_d, pid_t pid, int status) {
    plugin_data *p = (plugin_data *)p_d;
    for (size_t i = 0; i < p->cgi_pid.used; ++i) {
        handler_ctx *hctx;
        if (pid != p->cgi_pid.ptr[i].pid) continue;

        hctx = (handler_ctx *)p->cgi_pid.ptr[i].ctx;
        if (hctx) hctx->pid = -1;
        cgi_pid_del(p, i);

        if (WIFEXITED(status)) {
            /* (skip logging (non-zero) CGI exit; might be very noisy) */
        }
        else if (WIFSIGNALED(status)) {
            /* ignore SIGTERM if sent by cgi_connection_close() (NULL == hctx)*/
            if (WTERMSIG(status) != SIGTERM || NULL == hctx) {
                log_error_write(srv, __FILE__, __LINE__, "sdsd", "CGI pid", pid,
                                "died with signal", WTERMSIG(status));
            }
        }
        else {
            log_error_write(srv, __FILE__, __LINE__, "sds",
                            "CGI pid", pid, "ended unexpectedly");
        }

        return HANDLER_FINISHED;
    }

    return HANDLER_GO_ON;
}


int mod_cgi_plugin_init(plugin *p);
int mod_cgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("cgi");

	p->connection_reset = cgi_connection_close_callback;
	p->handle_subrequest_start = cgi_is_handled;
	p->handle_subrequest = mod_cgi_handle_subrequest;
	p->handle_waitpid = cgi_waitpid_cb;
	p->init           = mod_cgi_init;
	p->cleanup        = mod_cgi_free;
	p->set_defaults   = mod_fastcgi_set_defaults;

	p->data        = NULL;

	return 0;
}
