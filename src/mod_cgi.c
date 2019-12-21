#include "first.h"

#include "base.h"
#include "stat_cache.h"
#include "http_kv.h"
#include "log.h"
#include "connections.h"
#include "response.h"
#include "http_chunk.h"
#include "http_header.h"

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
	char *ptr;
	size_t used;
	size_t size;
	size_t *offsets;
	size_t osize;
	size_t oused;
	char **eptr;
	size_t esize;
	buffer *ld_preload;
	buffer *ld_library_path;
      #ifdef __CYGWIN__
	buffer *systemroot;
      #endif
} env_accum;

typedef struct {
	struct { pid_t pid; void *ctx; } *ptr;
	size_t used;
	size_t size;
} buffer_pid_t;

typedef struct {
	const array *cgi;
	unsigned short execute_x_only;
	unsigned short local_redir;
	unsigned short xsendfile_allow;
	unsigned short upgrade;
	const array *xsendfile_docroot;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	plugin_config conf;
	buffer_pid_t cgi_pid;
	env_accum env;
} plugin_data;

typedef struct {
	pid_t pid;
	int fd;
	int fdtocgi;
	fdnode *fdn;
	fdnode *fdntocgi;

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

	hctx->response = chunk_buffer_acquire();
	hctx->fd = -1;
	hctx->fdtocgi = -1;

	return hctx;
}

static void cgi_handler_ctx_free(handler_ctx *hctx) {
	chunk_buffer_release(hctx->response);
	free(hctx);
}

INIT_FUNC(mod_cgi_init) {
	plugin_data *p;
	const char *s;

	p = calloc(1, sizeof(*p));

	force_assert(p);

	/* for valgrind */
	s = getenv("LD_PRELOAD");
	if (s) p->env.ld_preload = buffer_init_string(s);
	s = getenv("LD_LIBRARY_PATH");
	if (s) p->env.ld_library_path = buffer_init_string(s);
      #ifdef __CYGWIN__
	/* CYGWIN needs SYSTEMROOT */
	s = getenv("SYSTEMROOT");
	if (s) p->env.systemroot = buffer_init_string(s);
      #endif

	return p;
}


FREE_FUNC(mod_cgi_free) {
	plugin_data *p = p_d;
	buffer_pid_t *bp = &(p->cgi_pid);
	if (bp->ptr) free(bp->ptr);
	free(p->env.ptr);
	free(p->env.offsets);
	free(p->env.eptr);
	buffer_free(p->env.ld_preload);
	buffer_free(p->env.ld_library_path);
      #ifdef __CYGWIN__
	buffer_free(p->env.systemroot);
      #endif
}

static void mod_cgi_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* cgi.assign */
        pconf->cgi = cpv->v.a;
        break;
      case 1: /* cgi.execute-x-only */
        pconf->execute_x_only = (unsigned short)cpv->v.u;
        break;
      case 2: /* cgi.x-sendfile */
        pconf->xsendfile_allow = (unsigned short)cpv->v.u;
        break;
      case 3: /* cgi.x-sendfile-docroot */
        pconf->xsendfile_docroot = cpv->v.a;
        break;
      case 4: /* cgi.local-redir */
        pconf->local_redir = (unsigned short)cpv->v.u;
        break;
      case 5: /* cgi.upgrade */
        pconf->upgrade = (unsigned short)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_cgi_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_cgi_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_cgi_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_cgi_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_cgi_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("cgi.assign"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cgi.execute-x-only"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cgi.x-sendfile"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cgi.x-sendfile-docroot"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cgi.local-redir"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("cgi.upgrade"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_cgi"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* cgi.assign */
              case 1: /* cgi.execute-x-only */
              case 2: /* cgi.x-sendfile */
                break;
              case 3: /* cgi.x-sendfile-docroot */
                for (uint32_t j = 0; j < cpv->v.a->used; ++j) {
                    data_string *ds = (data_string *)cpv->v.a->data[j];
                    if (ds->value.ptr[0] != '/') {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "%s paths must begin with '/'; invalid: \"%s\"",
                          cpk[cpv->k_id].k, ds->value.ptr);
                        return HANDLER_ERROR;
                    }
                    buffer_path_simplify(&ds->value, &ds->value);
                    buffer_append_slash(&ds->value);
                }
                break;
              case 4: /* cgi.local-redir */
              case 5: /* cgi.upgrade */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_cgi_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


static void cgi_pid_add(plugin_data *p, pid_t pid, void *ctx) {
    buffer_pid_t *bp = &(p->cgi_pid);

    if (bp->used == bp->size) {
        bp->size += 16;
        bp->ptr = realloc(bp->ptr, sizeof(*bp->ptr) * bp->size);
        force_assert(bp->ptr);
    }

    bp->ptr[bp->used].pid = pid;
    bp->ptr[bp->used].ctx = ctx;
    ++bp->used;
}

static void cgi_pid_kill(plugin_data *p, pid_t pid) {
    buffer_pid_t *bp = &(p->cgi_pid);
    for (size_t i = 0; i < bp->used; ++i) {
        if (bp->ptr[i].pid == pid) {
            bp->ptr[i].ctx = NULL;
            kill(pid, SIGTERM);
            return;
        }
    }
}

static void cgi_pid_del(plugin_data *p, size_t i) {
    buffer_pid_t *bp = &(p->cgi_pid);

    if (i != bp->used - 1)
        bp->ptr[i] = bp->ptr[bp->used - 1];

    --bp->used;
}


static void cgi_connection_close_fdtocgi(connection *con, handler_ctx *hctx) {
	/*(closes only hctx->fdtocgi)*/
	struct fdevents * const ev = con->srv->ev;
	fdevent_fdnode_event_del(ev, hctx->fdntocgi);
	/*fdevent_unregister(ev, hctx->fdtocgi);*//*(handled below)*/
	fdevent_sched_close(ev, hctx->fdtocgi, 0);
	hctx->fdntocgi = NULL;
	hctx->fdtocgi = -1;
}

static void cgi_connection_close(connection *con, handler_ctx *hctx) {
	plugin_data *p = hctx->plugin_data;

	/* the connection to the browser went away, but we still have a connection
	 * to the CGI script
	 *
	 * close cgi-connection
	 */

	if (hctx->fd != -1) {
		struct fdevents * const ev = con->srv->ev;
		/* close connection to the cgi-script */
		fdevent_fdnode_event_del(ev, hctx->fdn);
		/*fdevent_unregister(ev, hctx->fd);*//*(handled below)*/
		fdevent_sched_close(ev, hctx->fd, 0);
		hctx->fdn = NULL;
	}

	if (hctx->fdtocgi != -1) {
		cgi_connection_close_fdtocgi(con, hctx); /*(closes only hctx->fdtocgi)*/
	}

	if (hctx->pid > 0) {
		cgi_pid_kill(p, hctx->pid);
	}

	con->plugin_ctx[p->id] = NULL;

	cgi_handler_ctx_free(hctx);

	/* finish response (if not already con->file_started, con->file_finished) */
	if (con->mode == p->id) {
		http_response_backend_done(con);
	}
}

static handler_t cgi_connection_close_callback(connection *con, void *p_d) {
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	if (hctx) cgi_connection_close(con, hctx);

	return HANDLER_GO_ON;
}


static int cgi_write_request(handler_ctx *hctx, int fd);


static handler_t cgi_handle_fdevent_send (void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;

	/*(joblist only actually necessary here in mod_cgi fdevent send if returning HANDLER_ERROR)*/
	joblist_append(con);

	if (revents & FDEVENT_OUT) {
		if (0 != cgi_write_request(hctx, hctx->fdtocgi)) {
			cgi_connection_close(con, hctx);
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

		cgi_connection_close_fdtocgi(con, hctx); /*(closes only hctx->fdtocgi)*/
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the cgi process */
#if 1
		log_error(con->conf.errh, __FILE__, __LINE__, "cgi-FDEVENT_ERR");
#endif
		cgi_connection_close(con, hctx);
		return HANDLER_ERROR;
	}

	return HANDLER_FINISHED;
}


static handler_t cgi_response_headers(connection *con, struct http_response_opts_t *opts) {
    /* response headers just completed */
    handler_ctx *hctx = (handler_ctx *)opts->pdata;

    if (con->response.htags & HTTP_HEADER_UPGRADE) {
        if (hctx->conf.upgrade && con->http_status == 101) {
            /* 101 Switching Protocols; transition to transparent proxy */
            http_response_upgrade_read_body_unknown(con);
        }
        else {
            con->response.htags &= ~HTTP_HEADER_UPGRADE;
          #if 0
            /* preserve prior questionable behavior; likely broken behavior
             * anyway if backend thinks connection is being upgraded but client
             * does not receive Connection: upgrade */
            http_header_response_unset(con, HTTP_HEADER_UPGRADE,
                                       CONST_STR_LEN("Upgrade"));
          #endif
        }
    }

    if (hctx->conf.upgrade && !(con->response.htags & HTTP_HEADER_UPGRADE)) {
        chunkqueue *cq = con->request_content_queue;
        hctx->conf.upgrade = 0;
        if (cq->bytes_out == (off_t)con->request.content_length) {
            cgi_connection_close_fdtocgi(con, hctx); /*(closes hctx->fdtocgi)*/
        }
    }

    return HANDLER_GO_ON;
}


static int cgi_recv_response(connection *con, handler_ctx *hctx) {
		switch (http_response_read(con, &hctx->opts,
					   hctx->response, hctx->fdn)) {
		default:
			return HANDLER_GO_ON;
		case HANDLER_ERROR:
			http_response_backend_error(con);
			/* fall through */
		case HANDLER_FINISHED:
			cgi_connection_close(con, hctx);
			return HANDLER_FINISHED;
		case HANDLER_COMEBACK:
			/* hctx->conf.local_redir */
			buffer_clear(hctx->response);
			connection_response_reset(con); /*(includes con->http_status = 0)*/
			plugins_call_connection_reset(con);
			/*cgi_connection_close(con, hctx);*//*(already cleaned up and hctx is now invalid)*/
			return HANDLER_COMEBACK;
		}
}


static handler_t cgi_handle_fdevent(void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	connection  *con  = hctx->remote_conn;

	joblist_append(con);

	if (revents & FDEVENT_IN) {
		handler_t rc = cgi_recv_response(con, hctx);/*(might invalidate hctx)*/
		if (rc != HANDLER_GO_ON) return rc;         /*(unless HANDLER_GO_ON)*/
	}

	/* perhaps this issue is already handled */
	if (revents & (FDEVENT_HUP|FDEVENT_RDHUP)) {
		if (con->file_started) {
			/* drain any remaining data from kernel pipe buffers
			 * even if (con->conf.stream_response_body
			 *          & FDEVENT_STREAM_RESPONSE_BUFMIN)
			 * since event loop will spin on fd FDEVENT_HUP event
			 * until unregistered. */
			handler_t rc;
			const unsigned short flags = con->conf.stream_response_body;
			con->conf.stream_response_body &= ~FDEVENT_STREAM_RESPONSE_BUFMIN;
			con->conf.stream_response_body |= FDEVENT_STREAM_RESPONSE_POLLRDHUP;
			do {
				rc = cgi_recv_response(con,hctx);/*(might invalidate hctx)*/
			} while (rc == HANDLER_GO_ON);           /*(unless HANDLER_GO_ON)*/
			con->conf.stream_response_body = flags;
			return rc; /* HANDLER_FINISHED or HANDLER_COMEBACK or HANDLER_ERROR */
		} else if (!buffer_string_is_empty(hctx->response)) {
			/* unfinished header package which is a body in reality */
			con->file_started = 1;
			if (0 != http_chunk_append_buffer(con, hctx->response)) {
				cgi_connection_close(con, hctx);
				return HANDLER_ERROR;
			}
			if (0 == con->http_status) con->http_status = 200; /* OK */
		}
		cgi_connection_close(con, hctx);
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the cgi process */
		cgi_connection_close(con, hctx);
		return HANDLER_ERROR;
	}

	return HANDLER_FINISHED;
}


static int cgi_env_add(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	env_accum *env = venv;
	char *dst;

	if (!key || !val) return -1;

	if (env->size - env->used < key_len + val_len + 2) {
		if (0 == env->size) env->size = 4096;
		do { env->size *= 2; } while (env->size - env->used < key_len + val_len + 2);
		env->ptr = realloc(env->ptr, env->size);
		force_assert(env->ptr);
	}

	dst = env->ptr + env->used;
	memcpy(dst, key, key_len);
	dst[key_len] = '=';
	memcpy(dst + key_len + 1, val, val_len);
	dst[key_len + 1 + val_len] = '\0';

	if (env->osize == env->oused) {
		env->osize += 16;
		env->offsets = realloc(env->offsets, env->osize * sizeof(*env->offsets));
		force_assert(env->offsets);
	}
	env->offsets[env->oused++] = env->used;
	env->used += key_len + val_len + 2;

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
static ssize_t cgi_write_file_chunk_mmap(connection *con, int fd, chunkqueue *cq) {
	chunk* const c = cq->first;
	off_t offset, toSend, file_end;
	ssize_t wr;
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
		if (-1 == (c->file.fd = fdevent_open_cloexec(c->mem->ptr, con->conf.follow_symlink, O_RDONLY, 0))) {
			log_perror(con->conf.errh, __FILE__, __LINE__, "open failed: %s", c->mem->ptr);
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
					log_perror(con->conf.errh, __FILE__, __LINE__,
					  "lseek/read %s %d %lld failed:",
					  c->mem->ptr, c->file.fd, (long long)offset);
				} else { /*(0 == toSend)*/
					log_error(con->conf.errh, __FILE__, __LINE__,
					  "unexpected EOF (input truncated?): %s %d %lld",
					  c->mem->ptr, c->file.fd, (long long)offset);
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

	wr = write(fd, data, toSend);

	if (MAP_FAILED == c->file.mmap.start) free(data);

	if (wr < 0) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return 0;
		case EPIPE:
		case ECONNRESET:
			return -2;
		default:
			log_perror(con->conf.errh, __FILE__, __LINE__,
			  "write %d failed", fd);
			return -1;
		}
	}

	chunkqueue_mark_written(cq, wr);
	return wr;
}

static int cgi_write_request(handler_ctx *hctx, int fd) {
	connection *con = hctx->remote_conn;
	chunkqueue *cq = con->request_content_queue;
	chunk *c;

	/* old comment: windows doesn't support select() on pipes - wouldn't be easy to fix for all platforms.
	 * solution: if this is still a problem on windows, then substitute
	 * socketpair() for pipe() and closesocket() for close() on windows.
	 */

	for (c = cq->first; c; c = cq->first) {
		ssize_t wr = -1;

		switch(c->type) {
		case FILE_CHUNK:
			wr = cgi_write_file_chunk_mmap(con, fd, cq);
			break;

		case MEM_CHUNK:
			if ((wr = write(fd, c->mem->ptr + c->offset, buffer_string_length(c->mem) - c->offset)) < 0) {
				switch(errno) {
				case EAGAIN:
				case EINTR:
					/* ignore and try again */
					wr = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					/* connection closed */
					wr = -2;
					break;
				default:
					/* fatal error */
					log_perror(con->conf.errh, __FILE__, __LINE__, "write() failed");
					wr = -1;
					break;
				}
			} else if (wr > 0) {
				chunkqueue_mark_written(cq, wr);
			}
			break;
		}

		if (0 == wr) break; /*(might block)*/

		switch (wr) {
		case -1:
			/* fatal error */
			return -1;
		case -2:
			/* connection reset */
			log_error(con->conf.errh, __FILE__, __LINE__,
			  "failed to send post data to cgi, connection closed by CGI");
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
			--con->srv->cur_fds;
			if (close(fd)) {
				log_perror(con->conf.errh, __FILE__, __LINE__, "cgi stdin close %d failed", fd);
			}
		} else {
			cgi_connection_close_fdtocgi(con, hctx); /*(closes only hctx->fdtocgi)*/
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
		struct fdevents * const ev = con->srv->ev;
		if (-1 == hctx->fdtocgi) { /*(not registered yet)*/
			hctx->fdtocgi = fd;
			hctx->fdntocgi = fdevent_register(ev, hctx->fdtocgi, cgi_handle_fdevent_send, hctx);
		}
		if (0 == cqlen) { /*(chunkqueue_is_empty(cq))*/
			if ((fdevent_fdnode_interest(hctx->fdntocgi) & FDEVENT_OUT)) {
				fdevent_fdnode_event_set(ev, hctx->fdntocgi, 0);
			}
		} else {
			/* more request body remains to be sent to CGI so register for fdevents */
			fdevent_fdnode_event_set(ev, hctx->fdntocgi, FDEVENT_OUT);
		}
	}

	return 0;
}

static const struct stat * cgi_stat(buffer *path) {
    /* CGI might be executable even if it is not readable */
    const stat_cache_entry * const sce = stat_cache_get_entry(path);
    return sce ? &sce->st : NULL;
}

static int cgi_create_env(connection *con, plugin_data *p, handler_ctx *hctx, buffer *cgi_handler) {
	char *args[3];
	int to_cgi_fds[2];
	int from_cgi_fds[2];
	int dfd = -1;
	UNUSED(p);

	if (!buffer_string_is_empty(cgi_handler)) {
		if (NULL == cgi_stat(cgi_handler)) {
			log_perror(con->conf.errh, __FILE__, __LINE__,
			  "stat for cgi-handler %s", cgi_handler->ptr);
			return -1;
		}
	}

	if (pipe_cloexec(to_cgi_fds)) {
		log_perror(con->conf.errh, __FILE__, __LINE__, "pipe failed");
		return -1;
	}
	if (pipe_cloexec(from_cgi_fds)) {
		close(to_cgi_fds[0]);
		close(to_cgi_fds[1]);
		log_perror(con->conf.errh, __FILE__, __LINE__, "pipe failed");
		return -1;
	}
	fdevent_setfd_cloexec(to_cgi_fds[1]);
	fdevent_setfd_cloexec(from_cgi_fds[0]);

	{
		size_t i = 0;
		http_cgi_opts opts = { 0, 0, NULL, NULL };
		env_accum *env = &p->env;
		env->used = 0;
		env->oused = 0;

		/* create environment */

		http_cgi_headers(con, &opts, cgi_env_add, env);

		/* for valgrind */
		if (p->env.ld_preload) {
			cgi_env_add(env, CONST_STR_LEN("LD_PRELOAD"), CONST_BUF_LEN(p->env.ld_preload));
		}
		if (p->env.ld_library_path) {
			cgi_env_add(env, CONST_STR_LEN("LD_LIBRARY_PATH"), CONST_BUF_LEN(p->env.ld_library_path));
		}
	      #ifdef __CYGWIN__
		/* CYGWIN needs SYSTEMROOT */
		if (p->env.systemroot) {
			cgi_env_add(env, CONST_STR_LEN("SYSTEMROOT"), CONST_BUF_LEN(p->env.systemroot));
		}
	      #endif

		if (env->esize <= env->oused) {
			env->esize = (env->oused + 1 + 0xf) & ~(0xfuL);
			env->eptr = realloc(env->eptr, env->esize * sizeof(*env->eptr));
			force_assert(env->eptr);
		}
		for (i = 0; i < env->oused; ++i) {
			env->eptr[i] = env->ptr + env->offsets[i];
		}
		env->eptr[env->oused] = NULL;

		/* set up args */
		i = 0;

		if (!buffer_string_is_empty(cgi_handler)) {
			args[i++] = cgi_handler->ptr;
		}
		args[i++] = con->physical.path->ptr;
		args[i  ] = NULL;
	}

	dfd = fdevent_open_dirname(con->physical.path->ptr, con->conf.follow_symlink);
	if (-1 == dfd) {
		log_perror(con->conf.errh, __FILE__, __LINE__, "open dirname %s failed", con->physical.path->ptr);
	}

	int serrh_fd = con->conf.serrh ? con->conf.serrh->errorlog_fd : -1;
	hctx->pid = (dfd >= 0) ? fdevent_fork_execve(args[0], args, p->env.eptr, to_cgi_fds[0], from_cgi_fds[1], serrh_fd, dfd) : -1;

	if (-1 == hctx->pid) {
		/* log error with errno prior to calling close() (might change errno) */
		log_perror(con->conf.errh, __FILE__, __LINE__, "fork failed");
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

		cgi_pid_add(p, hctx->pid, hctx);

		++con->srv->cur_fds;

		if (0 == con->request.content_length) {
			close(to_cgi_fds[1]);
		} else {
			/* there is content to send */
			if (-1 == fdevent_fcntl_set_nb(to_cgi_fds[1])) {
				log_perror(con->conf.errh, __FILE__, __LINE__, "fcntl failed");
				close(to_cgi_fds[1]);
				cgi_connection_close(con, hctx);
				return -1;
			}

			if (0 != cgi_write_request(hctx, to_cgi_fds[1])) {
				close(to_cgi_fds[1]);
				cgi_connection_close(con, hctx);
				return -1;
			}

			++con->srv->cur_fds;
		}

		struct fdevents * const ev = con->srv->ev;
		hctx->fdn = fdevent_register(ev, hctx->fd, cgi_handle_fdevent, hctx);
		if (-1 == fdevent_fcntl_set_nb(hctx->fd)) {
			log_perror(con->conf.errh, __FILE__, __LINE__, "fcntl failed");
			cgi_connection_close(con, hctx);
			return -1;
		}
		fdevent_fdnode_event_set(ev, hctx->fdn, FDEVENT_IN | FDEVENT_RDHUP);

		return 0;
	}
}

URIHANDLER_FUNC(cgi_is_handled) {
	plugin_data *p = p_d;
	const struct stat *st;
	data_string *ds;

	if (con->mode != DIRECT) return HANDLER_GO_ON;
	if (buffer_is_empty(con->physical.path)) return HANDLER_GO_ON;

	mod_cgi_patch_config(con, p);
	if (NULL == p->conf.cgi) return HANDLER_GO_ON;

	ds = (data_string *)array_match_key_suffix(p->conf.cgi, con->physical.path);
	if (NULL == ds) return HANDLER_GO_ON;

	st = cgi_stat(con->physical.path);
	if (NULL == st) return HANDLER_GO_ON;

	if (!S_ISREG(st->st_mode)) return HANDLER_GO_ON;
	if (p->conf.execute_x_only == 1 && (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) return HANDLER_GO_ON;

	{
		handler_ctx *hctx = cgi_handler_ctx_init();
		hctx->remote_conn = con;
		hctx->plugin_data = p;
		hctx->cgi_handler = &ds->value;
		memcpy(&hctx->conf, &p->conf, sizeof(plugin_config));
		hctx->conf.upgrade =
		  hctx->conf.upgrade
		  && con->request.http_version == HTTP_VERSION_1_1
		  && NULL != http_header_request_get(con, HTTP_HEADER_UPGRADE, CONST_STR_LEN("Upgrade"));
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
	plugin_data * const p = p_d;
	handler_ctx * const hctx = con->plugin_ctx[p->id];

	if (con->mode != p->id) return HANDLER_GO_ON;
	if (NULL == hctx) return HANDLER_GO_ON;

	if ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
	    && con->file_started) {
		if (chunkqueue_length(con->write_queue) > 65536 - 4096) {
			fdevent_fdnode_event_clr(con->srv->ev,hctx->fdn,FDEVENT_IN);
		} else if (!(fdevent_fdnode_interest(hctx->fdn) & FDEVENT_IN)) {
			/* optimistic read from backend */
			handler_t rc = cgi_recv_response(con, hctx); /*(might invalidate hctx)*/
			if (rc != HANDLER_GO_ON) return rc;          /*(unless HANDLER_GO_ON)*/
			fdevent_fdnode_event_add(con->srv->ev, hctx->fdn, FDEVENT_IN);
		}
	}

	chunkqueue * const cq = con->request_content_queue;

	if (cq->bytes_in != (off_t)con->request.content_length) {
		/*(64k - 4k to attempt to avoid temporary files
		 * in conjunction with FDEVENT_STREAM_REQUEST_BUFMIN)*/
		if (cq->bytes_in - cq->bytes_out > 65536 - 4096
		    && (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN)){
			con->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
			if (-1 != hctx->fd) return HANDLER_WAIT_FOR_EVENT;
		} else {
			handler_t rc = connection_handle_read_post_state(con);
			if (!chunkqueue_is_empty(cq)) {
				if (fdevent_fdnode_interest(hctx->fdntocgi) & FDEVENT_OUT) {
					return (rc == HANDLER_GO_ON) ? HANDLER_WAIT_FOR_EVENT : rc;
				}
			}
			if (rc != HANDLER_GO_ON) return rc;

			/* CGI environment requires that Content-Length be set.
			 * Send 411 Length Required if Content-Length missing.
			 * (occurs here if client sends Transfer-Encoding: chunked
			 *  and module is flagged to stream request body to backend) */
			if (-1 == con->request.content_length) {
				return connection_handle_read_post_error(con, 411);
			}
		}
	}

	if (-1 == hctx->fd) {
		if (cgi_create_env(con, p, hctx, hctx->cgi_handler)) {
			con->http_status = 500;
			con->mode = DIRECT;

			return HANDLER_FINISHED;
		}
	} else if (!chunkqueue_is_empty(con->request_content_queue)) {
		if (0 != cgi_write_request(hctx, hctx->fdtocgi)) {
			cgi_connection_close(con, hctx);
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
            if (WTERMSIG(status) != SIGTERM || NULL != hctx) {
                log_error_st *errh = hctx
                  ? hctx->remote_conn->conf.errh
                  : srv->errh;
                log_error(errh, __FILE__, __LINE__,
                  "CGI pid %d died with signal %d", pid, WTERMSIG(status));
            }
        }
        else {
            log_error_st *errh = hctx
              ? hctx->remote_conn->conf.errh
              : srv->errh;
            log_error(errh, __FILE__, __LINE__,
              "CGI pid %d ended unexpectedly", pid);
        }

        return HANDLER_FINISHED;
    }

    return HANDLER_GO_ON;
}


int mod_cgi_plugin_init(plugin *p);
int mod_cgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "cgi";

	p->connection_reset = cgi_connection_close_callback;
	p->handle_subrequest_start = cgi_is_handled;
	p->handle_subrequest = mod_cgi_handle_subrequest;
	p->handle_waitpid = cgi_waitpid_cb;
	p->init           = mod_cgi_init;
	p->cleanup        = mod_cgi_free;
	p->set_defaults   = mod_cgi_set_defaults;

	return 0;
}
