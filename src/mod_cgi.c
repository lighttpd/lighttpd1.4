#include "first.h"

#include "base.h"
#include "stat_cache.h"
#include "http_kv.h"
#include "fdlog.h"
#include "log.h"
#include "response.h"
#include "http_cgi.h"
#include "http_chunk.h"
#include "http_header.h"
#include "http_status.h"
#include "gw_backend.h" /* gw_upgrade_policy() */

#include "plugin.h"

#include <sys/types.h>
#include "sys-socket.h"
#include "sys-unistd.h" /* <unistd.h> */
#include "sys-wait.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fdevent.h>

#include <fcntl.h>
#include <signal.h>

/* _WIN32 custom socketpair() is used here instead of pipe() */
#ifdef _WIN32
#undef fdio_close_pipe
#define fdio_close_pipe(fd) fdio_close_socket(fd)
#define fdevent_fcntl_set_nb(fd) fdevent_socket_set_nb(fd)
#endif

typedef struct {
	uintptr_t *offsets;
	size_t osize;
	size_t oused;
	buffer *b;
	buffer *boffsets;
} env_accum;

typedef struct {
	unix_time64_t read_timeout;
	unix_time64_t write_timeout;
	int signal_fin;
} cgi_limits;

typedef struct {
	const array *cgi;
	const cgi_limits *limits;
	unsigned short execute_x_only;
	unsigned short local_redir;
	unsigned short xsendfile_allow;
	unsigned short upgrade;
	const array *xsendfile_docroot;
} plugin_config;

struct cgi_pid_t;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	int tempfile_accum;
	struct {
		buffer *ld_preload;
		buffer *ld_library_path;
	  #if defined(__CYGWIN__) || defined(_WIN32)
		buffer *systemroot;
	  #endif
	  #if defined(_WIN32)
		buffer *cygvol;
		buffer *msystem;
	  #endif
	} env;
} plugin_data;

static struct cgi_pid_t *cgi_pids; /* thread-safety todo: lock around modify */

typedef struct {
	struct cgi_pid_t *cgi_pid;
	int fd;
	int fdtocgi;
	int rd_revents;
	int wr_revents;
	fdnode *fdn;
	fdnode *fdntocgi;

	request_st *r;
	connection *con;          /* dumb pointer */
	struct fdevents *ev;      /* dumb pointer */
	plugin_data *plugin_data; /* dumb pointer */

	buffer *response;
	unix_time64_t read_ts;
	unix_time64_t write_ts;
	buffer *cgi_handler;      /* dumb pointer */
	http_response_opts opts;
	plugin_config conf;
	off_t orig_reqbody_length;
} handler_ctx;

typedef struct cgi_pid_t {
	pid_t pid;
	int signal_sent;
	handler_ctx *hctx;
	struct cgi_pid_t *next;
	struct cgi_pid_t *prev;
} cgi_pid_t;

__attribute_returns_nonnull__
static handler_ctx * cgi_handler_ctx_init(void) {
	handler_ctx *hctx = ck_calloc(1, sizeof(*hctx));
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
	plugin_data * const p = ck_calloc(1, sizeof(*p));
	const char *s;

	/* for valgrind */
	s = getenv("LD_PRELOAD");
	if (s) buffer_copy_string((p->env.ld_preload = buffer_init()), s);
	s = getenv("LD_LIBRARY_PATH");
	if (s) buffer_copy_string((p->env.ld_library_path = buffer_init()), s);
      #if defined(__CYGWIN__) || defined(_WIN32)
	/* CYGWIN needs SYSTEMROOT */
	s = getenv("SYSTEMROOT");
	if (s) buffer_copy_string((p->env.systemroot = buffer_init()), s);
      #endif
      #if defined(_WIN32)
	s = getenv("MSYSTEM");
	if (s) buffer_copy_string((p->env.msystem = buffer_init()), s);
	s = getenv("CYGVOL");
	if (s) buffer_copy_string((p->env.cygvol = buffer_init()), s);
      #endif

	return p;
}


FREE_FUNC(mod_cgi_free) {
	plugin_data *p = p_d;
	buffer_free(p->env.ld_preload);
	buffer_free(p->env.ld_library_path);
      #if defined(__CYGWIN__) || defined(_WIN32)
	buffer_free(p->env.systemroot);
      #endif
      #if defined(_WIN32)
	buffer_free(p->env.cygvol);
	buffer_free(p->env.msystem);
      #endif

    for (cgi_pid_t *cgi_pid = cgi_pids, *next; cgi_pid; cgi_pid = next) {
        next = cgi_pid->next;
        free(cgi_pid);
    }
    cgi_pids = NULL;

    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 6: /* cgi.limits */
                free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
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
      case 6: /* cgi.limits */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->limits = cpv->v.v;
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

static void mod_cgi_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_cgi_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

__attribute_cold__
__attribute_pure__
static int mod_cgi_str_to_signal (const char *s, int default_sig) {
    static const struct { const char *name; int sig; } sigs[] = {
     #ifdef SIGHUP
      { "HUP",  SIGHUP  },
     #endif
      { "INT",  SIGINT  }
     #ifdef SIGQUIT
     ,{ "QUIT", SIGQUIT }
     #endif
     #ifdef SIGILL
     ,{ "ILL",  SIGILL  }
     #endif
     #ifdef SIGTRAP
     ,{ "TRAP", SIGTRAP }
     #endif
     #ifdef SIGABRT
     ,{ "ABRT", SIGABRT }
     #endif
     #ifdef SIGBUS
     ,{ "BUS",  SIGBUS  }
     #endif
     #ifdef SIGFPE
     ,{ "FPE",  SIGFPE  }
     #endif
     #ifndef SIGKILL
     #define SIGKILL 9
     #endif
     ,{ "KILL", SIGKILL }
     #ifdef SIGUSR1
     ,{ "USR1", SIGUSR1 }
     #endif
     #ifdef SIGSEGV
     ,{ "SEGV", SIGSEGV }
     #endif
     #ifdef SIGUSR2
     ,{ "USR2", SIGUSR2 }
     #endif
     #ifdef SIGPIPE
     ,{ "PIPE", SIGPIPE }
     #endif
     #ifdef SIGALRM
     ,{ "ALRM", SIGALRM }
     #endif
     ,{ "TERM", SIGTERM }
     #ifdef SIGCHLD
     ,{ "CHLD", SIGCHLD }
     #endif
     #ifdef SIGCONT
     ,{ "CONT", SIGCONT }
     #endif
     #ifdef SIGURG
     ,{ "URG",  SIGURG  }
     #endif
     #ifdef SIGXCPU
     ,{ "XCPU", SIGXCPU }
     #endif
     #ifdef SIGXFSZ
     ,{ "XFSZ", SIGXFSZ }
     #endif
     #ifdef SIGWINCH
     ,{ "WINCH",SIGWINCH}
     #endif
     #ifdef SIGPOLL
     ,{ "POLL", SIGPOLL }
     #endif
     #ifdef SIGIO
     ,{ "IO",   SIGIO   }
     #endif
    };

    if (s[0] == 'S' && s[1] == 'I' && s[2] == 'G') s += 3; /*("SIG" prefix)*/
    for (uint32_t i = 0; i < sizeof(sigs)/sizeof(*sigs); ++i) {
        if (0 == strcmp(s, sigs[i].name)) return sigs[i].sig;
    }
    return default_sig;
}

static cgi_limits * mod_cgi_parse_limits(const array * const a, log_error_st * const errh) {
    cgi_limits * const limits = ck_calloc(1, sizeof(cgi_limits));
    for (uint32_t i = 0; i < a->used; ++i) {
        const data_unset * const du = a->data[i];
        int32_t v = config_plugin_value_to_int32(du, -1);
        if (buffer_eq_icase_slen(&du->key, CONST_STR_LEN("read-timeout"))) {
            limits->read_timeout = (unix_time64_t)v;
            continue;
        }
        if (buffer_eq_icase_slen(&du->key, CONST_STR_LEN("write-timeout"))) {
            limits->write_timeout = (unix_time64_t)v;
            continue;
        }
        if (buffer_eq_icase_slen(&du->key, CONST_STR_LEN("tcp-fin-propagate"))) {
            if (-1 == v) {
                v = SIGTERM;
                if (du->type == TYPE_STRING) {
                    buffer * const vstr = &((data_string *)du)->value;
                    buffer_to_upper(vstr);
                    v = mod_cgi_str_to_signal(vstr->ptr, SIGTERM);
                }
            }
            limits->signal_fin = v;
            continue;
        }
        log_error(errh, __FILE__, __LINE__,
                  "unrecognized cgi.limits param: %s", du->key.ptr);
    }
    return limits;
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
     ,{ CONST_STR_LEN("cgi.limits"),
        T_CONFIG_ARRAY_KVANY,
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
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
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
                    buffer_path_simplify(&ds->value);
                    buffer_append_slash(&ds->value);
                }
                break;
              case 4: /* cgi.local-redir */
              case 5: /* cgi.upgrade */
                break;
              case 6: /* cgi.limits */
                cpv->v.v = mod_cgi_parse_limits(cpv->v.a, srv->errh);
                if (NULL == cpv->v.v) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
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

    p->tempfile_accum = config_feature_bool(srv, "cgi.tempfile-accum", 1);

    return HANDLER_GO_ON;
}


static cgi_pid_t * cgi_pid_add(pid_t pid, handler_ctx *hctx) {
    cgi_pid_t *cgi_pid = ck_malloc(sizeof(cgi_pid_t));
    cgi_pid->pid = pid;
    cgi_pid->signal_sent = 0;
    cgi_pid->hctx = hctx;
    cgi_pid->prev = NULL;

    /* thread-safety todo: lock around modifications */
    cgi_pid->next = cgi_pids;
    if (cgi_pid->next)
        cgi_pid->next->prev = cgi_pid;
    cgi_pids = cgi_pid;

    return cgi_pid;
}

static void cgi_pid_kill(cgi_pid_t *cgi_pid, int sig) {
    cgi_pid->signal_sent = sig; /*(save last signal sent)*/
    fdevent_kill(cgi_pid->pid, sig);
}

static void cgi_pid_del(cgi_pid_t *cgi_pid) {
    /* thread-safety todo: lock around modifications */
    if (cgi_pid->prev)
        cgi_pid->prev->next = cgi_pid->next;
    else
        cgi_pids = cgi_pid->next;

    if (cgi_pid->next)
        cgi_pid->next->prev = cgi_pid->prev;

    free(cgi_pid);
}


__attribute_noinline__
static void cgi_connection_close_fdtocgi(handler_ctx *hctx) {
	/*(closes only hctx->fdtocgi)*/
	if (-1 == hctx->fdtocgi) return;
	fdevent_fdnode_event_del(hctx->ev, hctx->fdntocgi);
	/*fdevent_unregister(ev, hctx->fdntocgi);*//*(handled below)*/
	fdevent_sched_close(hctx->ev, hctx->fdntocgi);
	hctx->fdntocgi = NULL;
	hctx->fdtocgi = -1;
}

static void cgi_connection_close(handler_ctx *hctx) {
	/* the connection to the browser went away, but we still have a connection
	 * to the CGI script
	 *
	 * close cgi-connection
	 */

	if (hctx->fd != -1) {
		/* close connection to the cgi-script */
		fdevent_fdnode_event_del(hctx->ev, hctx->fdn);
		/*fdevent_unregister(ev, hctx->fdn);*//*(handled below)*/
		fdevent_sched_close(hctx->ev, hctx->fdn);
		hctx->fdn = NULL;
	}

	if (hctx->fdtocgi != -1) {
		cgi_connection_close_fdtocgi(hctx); /*(closes only hctx->fdtocgi)*/
	}

	const plugin_data * const p = hctx->plugin_data;
	request_st * const r = hctx->r;
	r->plugin_ctx[p->id] = NULL;

	if (hctx->cgi_pid) {
		cgi_pid_kill(hctx->cgi_pid, SIGTERM);
		hctx->cgi_pid->hctx = NULL;
	}
	cgi_handler_ctx_free(hctx);

	/* (r->reqbody_queue.upload_temp_file_size might have been changed even
	 *  with 0 == r->reqbody_length, if hctx->conf.upgrade is set) */
	if (p->tempfile_accum) /*(and if not streaming)*/
		chunkqueue_set_tempdirs(&r->reqbody_queue, 0); /* reset sz */

	/* finish response (if not already r->resp_body_started, r->resp_body_finished) */
	if (r->handler_module == p->self) {
		http_response_backend_done(r);
	}
}

static handler_t cgi_connection_close_callback(request_st * const r, void *p_d) {
    handler_ctx *hctx = r->plugin_ctx[((plugin_data *)p_d)->id];
    if (hctx) {
        cgi_connection_close(hctx);
    }
    return HANDLER_GO_ON;
}


static int cgi_write_request(handler_ctx *hctx, int fd);


static handler_t cgi_handle_fdevent_send (void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	hctx->wr_revents |= revents;
	joblist_append(hctx->con);
	return HANDLER_FINISHED;
}


static handler_t cgi_process_wr_revents (handler_ctx * const hctx, request_st * const r, int revents) {
	if (revents & FDEVENT_OUT) {
		if (0 != cgi_write_request(hctx, hctx->fdtocgi)) {
			cgi_connection_close(hctx);
			return HANDLER_ERROR;
		}
		/* more request body to be sent to CGI */
	}

	if (revents & FDEVENT_HUP) {
		/* skip sending remaining data to CGI */
		if (r->reqbody_length) {
			chunkqueue *cq = &r->reqbody_queue;
			chunkqueue_mark_written(cq, chunkqueue_length(cq));
			if (cq->bytes_in != (off_t)r->reqbody_length) {
				r->keep_alive = 0;
			}
		}

		cgi_connection_close_fdtocgi(hctx); /*(closes only hctx->fdtocgi)*/
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the cgi process */
#if 1
		log_error(r->conf.errh, __FILE__, __LINE__, "cgi-FDEVENT_ERR");
#endif
		cgi_connection_close(hctx);
		return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}


static handler_t cgi_response_headers(request_st * const r, struct http_response_opts_t *opts) {
    /* response headers just completed */
    handler_ctx *hctx = (handler_ctx *)opts->pdata;

    if (opts->upgrade && opts->upgrade != 2) {
        opts->upgrade = 0;
        chunkqueue *cq = &r->reqbody_queue;
        r->reqbody_length = hctx->orig_reqbody_length;
        if (cq->bytes_out == (off_t)r->reqbody_length) {
            cgi_connection_close_fdtocgi(hctx); /*(closes hctx->fdtocgi)*/
        }
    }
    hctx->conf.upgrade = opts->upgrade;

    return HANDLER_GO_ON;
}


__attribute_cold__
static handler_t cgi_local_redir(request_st * const r, handler_ctx * const hctx) {
    buffer_clear(hctx->response);
    chunk_buffer_yield(hctx->response);
    http_response_reset(r); /*(includes r->http_status = 0)*/
    r->con->srv->plugins_request_reset(r);
    /*cgi_connection_close(hctx);*//*(already cleaned up and hctx is now invalid)*/
    return HANDLER_COMEBACK;
}


static int cgi_recv_response(request_st * const r, handler_ctx * const hctx) {
		const off_t bytes_in = r->write_queue.bytes_in;
		switch (http_response_read(r, &hctx->opts,
					   hctx->response, hctx->fdn)) {
		default:
			if (r->write_queue.bytes_in > bytes_in)
				hctx->read_ts = log_monotonic_secs;
			return HANDLER_GO_ON;
		case HANDLER_ERROR:
			http_response_backend_error(r);
			__attribute_fallthrough__
		case HANDLER_FINISHED:
			cgi_connection_close(hctx);
			return HANDLER_FINISHED;
		case HANDLER_COMEBACK:
			return cgi_local_redir(r, hctx); /* HANDLER_COMEBACK */
		}
}


static handler_t cgi_handle_fdevent(void *ctx, int revents) {
	handler_ctx *hctx = ctx;
	hctx->rd_revents |= revents;
	joblist_append(hctx->con);
	return HANDLER_FINISHED;
}


static handler_t cgi_process_rd_revents(handler_ctx * const hctx, request_st * const r, int revents) {
	if (revents & FDEVENT_IN) {
		handler_t rc = cgi_recv_response(r, hctx); /*(might invalidate hctx)*/
		if (rc != HANDLER_GO_ON) return rc;         /*(unless HANDLER_GO_ON)*/
	}

	/* perhaps this issue is already handled */
	if (revents & (FDEVENT_HUP|FDEVENT_RDHUP)) {
		if (r->resp_body_started) {
			/* drain any remaining data from kernel pipe buffers
			 * even if (r->conf.stream_response_body
			 *          & FDEVENT_STREAM_RESPONSE_BUFMIN)
			 * since event loop will spin on fd FDEVENT_HUP event
			 * until unregistered. */
			handler_t rc;
			const unsigned short flags = r->conf.stream_response_body;
			r->conf.stream_response_body &= ~FDEVENT_STREAM_RESPONSE_BUFMIN;
			r->conf.stream_response_body |= FDEVENT_STREAM_RESPONSE_POLLRDHUP;
			do {
				rc = cgi_recv_response(r,hctx); /*(might invalidate hctx)*/
			} while (rc == HANDLER_GO_ON);           /*(unless HANDLER_GO_ON)*/
			r->conf.stream_response_body = flags;
			return rc; /* HANDLER_FINISHED or HANDLER_COMEBACK or HANDLER_ERROR */
		} else if (!buffer_is_blank(hctx->response)) {
			/* unfinished header package which is a body in reality */
			r->resp_body_started = 1;
			if (0 != http_chunk_append_buffer(r, hctx->response)) {
				cgi_connection_close(hctx);
				return HANDLER_ERROR;
			}
			if (0 == r->http_status) r->http_status = 200; /* OK */
		}
		cgi_connection_close(hctx);
		return HANDLER_FINISHED;
	} else if (revents & FDEVENT_ERR) {
		/* kill all connections to the cgi process */
		cgi_connection_close(hctx);
		return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}


__attribute_cold__
__attribute_noinline__
static void cgi_env_offset_resize(env_accum *env) {
    chunk_buffer_prepare_append(env->boffsets, env->boffsets->size*2);
    env->offsets = (uintptr_t *)(void *)env->boffsets->ptr;
    env->osize = env->boffsets->size/sizeof(*env->offsets);
}

static int cgi_env_add(void *venv, const char *key, size_t key_len, const char *val, size_t val_len) {
	env_accum *env = venv;

	if (!key || (!val && val_len)) return -1;

	if (__builtin_expect( (env->osize == env->oused), 0))
		cgi_env_offset_resize(env);
	env->offsets[env->oused++] = env->b->used-1;

	char * const dst = buffer_extend(env->b, key_len + val_len + 2);
	memcpy(dst, key, key_len);
	dst[key_len] = '=';
	if (val_len) memcpy(dst + key_len + 1, val, val_len);
	dst[key_len + 1 + val_len] = '\0';

	return 0;
}

static int cgi_write_request(handler_ctx *hctx, int fd) {
	request_st * const r = hctx->r;
	chunkqueue *cq = &r->reqbody_queue;

	chunkqueue_remove_finished_chunks(cq); /* unnecessary? */

  #ifdef _WIN32
	if (0 !=
	    r->con->srv->network_backend_write(fd,cq,MAX_WRITE_LIMIT,r->conf.errh)){
		/* connection closed */
		log_error(r->conf.errh, __FILE__, __LINE__,
		  "failed to send post data to cgi, connection closed by CGI");
		/* skip all remaining data */
		chunkqueue_mark_written(cq, chunkqueue_length(cq));
	}
  #else
	for (chunk *c = cq->first; c; c = cq->first) {
		ssize_t wr = chunkqueue_write_chunk_to_pipe(fd, cq, r->conf.errh);
		if (wr > 0) {
			hctx->write_ts = log_monotonic_secs;
			chunkqueue_mark_written(cq, wr);
			/* continue if wrote whole chunk or wrote 16k block
			 * (see chunkqueue_write_chunk_file_intermed()) */
			if (c != cq->first || wr == 16384)
				continue;
			/*(else partial write)*/
		}
		else if (wr < 0) {
				switch(errno) {
				case EAGAIN:
			  #ifdef EWOULDBLOCK
			  #if EAGAIN != EWOULDBLOCK
				case EWOULDBLOCK:
			  #endif
			  #endif
				case EINTR:
					/* ignore and try again later */
					break;
				case EPIPE:
				case ECONNRESET:
					/* connection closed */
				   #if 0 /*(not necessarily an error for CGI to close input)*/
					log_error(r->conf.errh, __FILE__, __LINE__,
					  "failed to send post data to cgi, connection closed by CGI");
				   #endif
					/* skip all remaining data */
					/*(this may repeat if streaming and more data is received)*/
					chunkqueue_mark_written(cq, chunkqueue_length(cq));
					break;
				default:
					/* fatal error */
					log_perror(r->conf.errh, __FILE__, __LINE__, "write() failed");
					return -1;
				}
		}
		/*if (0 == wr) break;*/ /*(might block)*/
		break;
	}
  #endif

	if (cq->bytes_out == (off_t)r->reqbody_length && !hctx->conf.upgrade) {
		/* sent all request body input */
		/* close connection to the cgi-script */
		cgi_connection_close_fdtocgi(hctx); /*(closes only hctx->fdtocgi)*/
	} else {
		off_t cqlen = chunkqueue_length(cq);
		if (cq->bytes_in != r->reqbody_length && cqlen < 65536 - 16384) {
			/*(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)*/
			if (!(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN)) {
				r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
				if (r->http_version <= HTTP_VERSION_1_1)
					r->con->is_readable = 1;/* trigger optimistic client read */
			}
		}
		struct fdevents * const ev = hctx->ev;
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
			hctx->write_ts = log_monotonic_secs;
			fdevent_fdnode_event_set(ev, hctx->fdntocgi, FDEVENT_OUT);
		}
	}

	return 0;
}

/* lighttpd STDIN_FILENO is reopened to /dev/null, inheritable by children */
#define MOD_CGI_INHERIT_STDIN_DEV_NULL

__attribute_cold__
static int cgi_create_err (request_st * const r, int cgi_fds[4], const char *msg)
{
    /* log error with errno prior to calling close() (might change errno) */
  #ifdef _WIN32
    if (msg && (0 == strcmp(msg,"socketpair()") || 0 == strcmp(msg,"fcntl()")))
        log_serror(r->conf.errh, __FILE__, __LINE__, "%s", msg);
    else
  #endif
    if (msg)
        log_perror(r->conf.errh, __FILE__, __LINE__, "%s", msg);

    int * const to_cgi_fds = cgi_fds; /* some fd might be -1; not checking */
    if (0 == r->reqbody_length) {
      #ifndef MOD_CGI_INHERIT_STDIN_DEV_NULL
        fdio_close_file(to_cgi_fds[0]); /* /dev/null */
      #endif
    }
    else if (-1 != to_cgi_fds[1]) { /* not (shared) open file in chunkqueue */
        fdio_close_pipe(to_cgi_fds[0]);
        fdio_close_pipe(to_cgi_fds[1]);
    }

    int * const from_cgi_fds = cgi_fds+2;/* some fd might be -1; not checking */
    fdio_close_pipe(from_cgi_fds[0]);
    fdio_close_pipe(from_cgi_fds[1]);

    return -1;
}

static int cgi_create_env(request_st * const r, handler_ctx * const hctx, buffer * const cgi_handler) {
	int cgi_fds[4] = { -1, -1, -1, -1 };
	int * const to_cgi_fds = cgi_fds;
	int * const from_cgi_fds = to_cgi_fds+2;

  #if 0
	/*(posix_spawn() should return error if exec target does not exist)*/
	if (!buffer_is_blank(cgi_handler)) {
		if (NULL == stat_cache_path_stat(cgi_handler)) {
			return cgi_create_err(r, cgi_fds, cgi_handler->ptr);
		}
	}
  #endif

	if (0 == r->reqbody_length) {
	  #ifndef MOD_CGI_INHERIT_STDIN_DEV_NULL
		to_cgi_fds[0] = fdevent_open_devnull();
		if (-1 == to_cgi_fds[0]) {
			return cgi_create_err(r, cgi_fds, "open() /dev/null");
		}
	  #endif
	}
	else if (!(r->conf.stream_request_body /*(if not streaming request body)*/
	           & (FDEVENT_STREAM_REQUEST|FDEVENT_STREAM_REQUEST_BUFMIN))
	         && !hctx->conf.upgrade) {
		chunkqueue * const cq = &r->reqbody_queue;
		chunk * const c = cq->first;
		if (c && c == cq->last && c->type == FILE_CHUNK && c->file.is_temp) {
			/* request body in single tempfile if not streaming req body */
			if (-1 == c->file.fd && 0 != chunk_open_file_chunk(c, r->conf.errh))
				return cgi_create_err(r, cgi_fds, NULL);
		  #ifdef __COVERITY__
			force_assert(-1 != c->file.fd);
		  #endif
			if (-1 == lseek(c->file.fd, 0, SEEK_SET)) {
				return cgi_create_err(r, cgi_fds, c->mem->ptr);
			}
			to_cgi_fds[0] = c->file.fd;
		}
	}

  #ifdef _WIN32
	if (-1 == to_cgi_fds[0] && 0 != r->reqbody_length) {
		if (0 != fdevent_socketpair_cloexec(AF_INET,SOCK_STREAM,0,to_cgi_fds))
			return cgi_create_err(r, cgi_fds, "socketpair()");
		if (0 != fdevent_fcntl_set_nb(to_cgi_fds[1]))
			return cgi_create_err(r, cgi_fds, "fcntl()");
	}
	if (0 != fdevent_socketpair_cloexec(AF_INET,SOCK_STREAM,0,from_cgi_fds))
		return cgi_create_err(r, cgi_fds, "socketpair()");
	/* fdevent_socketpair_cloexec() creates a pair of connected sockets with
	 * one socket (sv[0]) non-overlapped, and one socket (sv[1]) overlapped.
	 * The socket used for redirected I/O in child must be non-overlapped,
	 * so swap sockets in from_cgi_fds[] so write socket is non-overlapped*/
	int tmpfd = from_cgi_fds[0];
	from_cgi_fds[0] = from_cgi_fds[1];
	from_cgi_fds[1] = tmpfd;
  #else
	unsigned int bufsz_hint = 16384;
	if (-1 == to_cgi_fds[0] && 0 != r->reqbody_length) {
		if (0 != fdevent_pipe_cloexec(to_cgi_fds, bufsz_hint))
			return cgi_create_err(r, cgi_fds, "pipe()");
		if (0 != fdevent_fcntl_set_nb(to_cgi_fds[1]))
			return cgi_create_err(r, cgi_fds, "fcntl()");
	}
	if (fdevent_pipe_cloexec(from_cgi_fds, bufsz_hint))
		return cgi_create_err(r, cgi_fds, "pipe()");
  #endif
	if (-1 == fdevent_fcntl_set_nb(from_cgi_fds[0]))
		return cgi_create_err(r, cgi_fds, "fcntl()");

	env_accum envacc;
	env_accum * const env = &envacc;
	env->b = chunk_buffer_acquire();
	env->boffsets = chunk_buffer_acquire();
	buffer_truncate(env->b, 0);
	char *args[3];
	char **envp;
	{
		size_t i = 0;
		http_cgi_opts opts = { 0, 0, NULL, NULL };
		env->offsets = (uintptr_t *)(void *)env->boffsets->ptr;
		env->osize = env->boffsets->size/sizeof(*env->offsets);
		env->oused = 0;

		/* create environment */

		if (hctx->conf.upgrade) {
			r->reqbody_length = hctx->orig_reqbody_length;
			if (r->reqbody_length < 0)
				r->reqbody_length = 0;
		}

		http_cgi_headers(r, &opts, cgi_env_add, env);

		if (hctx->conf.upgrade)
			r->reqbody_length = -1;

		const plugin_data * const p = hctx->plugin_data;;
		/* for valgrind */
		if (p->env.ld_preload) {
			cgi_env_add(env, CONST_STR_LEN("LD_PRELOAD"), BUF_PTR_LEN(p->env.ld_preload));
		}
		if (p->env.ld_library_path) {
			cgi_env_add(env, CONST_STR_LEN("LD_LIBRARY_PATH"), BUF_PTR_LEN(p->env.ld_library_path));
		}
	      #if defined(__CYGWIN__) || defined(_WIN32)
		/* CYGWIN and _WIN32 need SYSTEMROOT */
		if (p->env.systemroot) {
			cgi_env_add(env, CONST_STR_LEN("SYSTEMROOT"), BUF_PTR_LEN(p->env.systemroot));
		}
	      #endif
	      #if defined(_WIN32)
		if (p->env.msystem) {
			cgi_env_add(env, CONST_STR_LEN("MSYSTEM"), BUF_PTR_LEN(p->env.msystem));
		}
	      #endif

		/* adjust (uintptr_t) offsets to (char *) ptr
		 * (stored as offsets while accumulating in buffer,
		 *  in case buffer is reallocated during env creation) */
		if (__builtin_expect( (env->osize == env->oused), 0))
			cgi_env_offset_resize(env);
		envp = (char **)env->offsets;
		envp[env->oused] = NULL;
		const uintptr_t baseptr = (uintptr_t)env->b->ptr;
		for (i = 0; i < env->oused; ++i)
			envp[i] += baseptr;

		/* set up args */
		i = 0;

		if (!buffer_is_blank(cgi_handler)) {
			args[i++] = cgi_handler->ptr;
		}
	  #ifdef _WIN32
		/* adjust path to scripts run via cygwin program if CYGVOL env is set */
		if (p->env.cygvol) {
			buffer *tb = r->tmp_buf;
			buffer_copy_buffer(tb, p->env.cygvol); /* e.g. "/cygdrive/c" */
			buffer_append_path_len(tb, BUF_PTR_LEN(&r->physical.path));
			args[i++] = tb->ptr;
		}
		else
	  #endif
			args[i++] = r->physical.path.ptr;
		args[i] = NULL;
	}

  #ifdef _WIN32
	/*(flag to chdir to script dir on _WIN32)*/
	int dfd = !buffer_is_blank(cgi_handler) ? -3 : -2;
	int serrh_fd = r->conf.serrh ? r->conf.serrh->fd : -1;
	pid_t pid =
	  fdevent_createprocess(args, envp, (intptr_t)to_cgi_fds[0],
	                        (intptr_t)from_cgi_fds[1], serrh_fd, dfd);
  #else
   #if 0 /*(if cache used, then must skip fdio_close_dirfd(dfd) further below)*/
	/*(similar to fdevent_open_dirname(), but leveraging stat_cache)*/
	/*(would need specialized routine to also pass O_DIRECTORY)*/
	/*(if not for r->conf.follow_symlink policy (of dubious benefit itself),
	 * the target dir could be handled in fdevent_fork_execve() similarly
	 * to how target dir is handled in fdevent_createprocess())*/
	/*(handle special cases of no dirname or dirname is root directory)*/
	const char * const path = r->physical.path.ptr;
	char * const c = strrchr(path, '/');
	const char * const dname = (NULL != c ? c != path ? path : "/" : ".");
	buffer * const tb = r->tmp_buf;
	buffer_copy_string_len(tb, dname, dname == path ? (uint32_t)(c - path) : 1);
	const stat_cache_entry * const sce =
	  stat_cache_get_entry_open(tb, r->conf.follow_symlink);
	int dfd = sce ? sce->fd : -1;
   #else
	int dfd = fdevent_open_dirname(r->physical.path.ptr,r->conf.follow_symlink);
   #endif
	if (-1 == dfd) {
		log_perror(r->conf.errh, __FILE__, __LINE__, "open dirname %s failed", r->physical.path.ptr);
	}

	int serrh_fd = r->conf.serrh ? r->conf.serrh->fd : -1;
	pid_t pid = (dfd >= 0)
	  ? fdevent_fork_execve(args[0], args, envp,
	                        to_cgi_fds[0], from_cgi_fds[1], serrh_fd, dfd)
	  : -1;
  #endif

	chunk_buffer_release(env->boffsets);
	chunk_buffer_release(env->b);
	env->boffsets = NULL;
	env->b = NULL;

	if (-1 == pid) {
		/* log error with errno prior to calling close() (might change errno) */
		log_perror(r->conf.errh, __FILE__, __LINE__, "fork/spawn %s", args[0]);
		if (dfd >= 0) fdio_close_dirfd(dfd);
		return cgi_create_err(r, cgi_fds, NULL);
	}

	{
		if (dfd >= 0) fdio_close_dirfd(dfd);
		hctx->cgi_pid = cgi_pid_add(pid, hctx);

		if (0 == r->reqbody_length) {
		  #ifndef MOD_CGI_INHERIT_STDIN_DEV_NULL
			fdio_close_file(to_cgi_fds[0]);
		  #endif
		}
		else if (-1 == to_cgi_fds[1]) {
			chunkqueue * const cq = &r->reqbody_queue;
			chunkqueue_mark_written(cq, chunkqueue_length(cq));
		}
		else if (0 != cgi_write_request(hctx, to_cgi_fds[1])) {
			return cgi_create_err(r, cgi_fds, NULL);
		}
		else {
			if (-1 == hctx->fdtocgi) /*(body fully sent in initial write)*/
				fdio_close_pipe(to_cgi_fds[1]);
			else /*(fdevent_register() was called on fd opened further above)*/
				++r->con->srv->cur_fds;
			fdio_close_pipe(to_cgi_fds[0]);
		}

		fdio_close_pipe(from_cgi_fds[1]);
		++r->con->srv->cur_fds;
		hctx->fd = from_cgi_fds[0];
		struct fdevents * const ev = hctx->ev;
		hctx->fdn = fdevent_register(ev, hctx->fd, cgi_handle_fdevent, hctx);
		hctx->read_ts = log_monotonic_secs;
		fdevent_fdnode_event_set(ev, hctx->fdn, FDEVENT_IN | FDEVENT_RDHUP);
		return 0;
	}
}

URIHANDLER_FUNC(cgi_is_handled) {
	const stat_cache_st *st;
	data_string *ds;

	if (NULL != r->handler_module) return HANDLER_GO_ON;
	/* r->physical.path is non-empty for handle_subrequest_start */
	/*if (buffer_is_blank(&r->physical.path)) return HANDLER_GO_ON;*/

	plugin_config pconf;
	mod_cgi_patch_config(r, p_d, &pconf);
	if (NULL == pconf.cgi) return HANDLER_GO_ON;

	ds = (data_string *)array_match_key_suffix(pconf.cgi, &r->physical.path);
	if (NULL == ds) return HANDLER_GO_ON;

	/* r->tmp_sce is set in http_response_physical_path_check() and is valid
	 * in handle_subrequest_start callback -- handle_subrequest_start callbacks
	 * should not change r->physical.path (or should invalidate r->tmp_sce) */
	st = r->tmp_sce && buffer_is_equal(&r->tmp_sce->name, &r->physical.path)
	   ? &r->tmp_sce->st
	   : stat_cache_path_stat(&r->physical.path);
	if (NULL == st) return HANDLER_GO_ON;

	/* (aside: CGI might be executable even if it is not readable) */
	if (!S_ISREG(st->st_mode)) return HANDLER_GO_ON;
	if (pconf.execute_x_only == 1 && (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) return HANDLER_GO_ON;

	pconf.upgrade = (unsigned short)
	  gw_upgrade_policy(r, 0, (int)pconf.upgrade);
	if (0 != r->http_status)
		return HANDLER_FINISHED;

	if (!gw_incremental_policy(r, (int)pconf.upgrade))
		return HANDLER_FINISHED;

	const plugin_data * const p = p_d;
	if (r->reqbody_length
	    && p->tempfile_accum
	    && !(r->conf.stream_request_body /*(if not streaming request body)*/
	         & (FDEVENT_STREAM_REQUEST|FDEVENT_STREAM_REQUEST_BUFMIN))) {
		/* store request body in single tempfile if not streaming request body*/
		r->reqbody_queue.upload_temp_file_size =
		  (off_t)((1uLL << (sizeof(off_t)*8-1))-1);
	}

	{
		handler_ctx *hctx = cgi_handler_ctx_init();
		hctx->ev = r->con->srv->ev;
		hctx->r = r;
		hctx->con = r->con;
		hctx->plugin_data = p_d;
		hctx->cgi_handler = &ds->value;
		memcpy(&hctx->conf, &pconf, sizeof(plugin_config));
		if (hctx->conf.upgrade) {
			hctx->opts.upgrade = hctx->conf.upgrade;
			hctx->orig_reqbody_length = r->reqbody_length;
			r->reqbody_length = -1;
		}
		hctx->opts.max_per_read =
		  !(r->conf.stream_response_body /*(if not streaming response body)*/
		    & (FDEVENT_STREAM_RESPONSE|FDEVENT_STREAM_RESPONSE_BUFMIN))
		    ? 262144
		    : (r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
		      ? 16384  /* FDEVENT_STREAM_RESPONSE_BUFMIN */
		      : 65536; /* FDEVENT_STREAM_RESPONSE */
	  #ifdef _WIN32
		hctx->opts.fdfmt = S_IFSOCK;
	  #else
		hctx->opts.fdfmt = S_IFIFO;
	  #endif
		hctx->opts.backend = BACKEND_CGI;
		hctx->opts.authorizer = 0;
		hctx->opts.local_redir = hctx->conf.local_redir;
		hctx->opts.xsendfile_allow = hctx->conf.xsendfile_allow;
		hctx->opts.xsendfile_docroot = hctx->conf.xsendfile_docroot;
		hctx->opts.pdata = hctx;
		hctx->opts.headers = cgi_response_headers;
		r->plugin_ctx[p->id] = hctx;
		r->handler_module = p->self;
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
	handler_ctx * const hctx = r->plugin_ctx[p->id];
	if (NULL == hctx) return HANDLER_GO_ON;

	if (__builtin_expect(
	     (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_TCP_FIN), 0)
	    && hctx->conf.limits && hctx->conf.limits->signal_fin) {
		/* XXX: consider setting r->http_status = 499 if (0 == r->http_status)
		 * (499 is nginx custom status to indicate client closed connection) */
		if (-1 == hctx->fd) return HANDLER_ERROR; /*(CGI not yet spawned)*/
		if (hctx->cgi_pid) /* send signal to notify CGI about TCP FIN */
			cgi_pid_kill(hctx->cgi_pid, hctx->conf.limits->signal_fin);
	}

	const int rd_revents = hctx->rd_revents;
	const int wr_revents = hctx->wr_revents;
	if (rd_revents) {
		hctx->rd_revents = 0;
		handler_t rc = cgi_process_rd_revents(hctx, r, rd_revents);
		if (rc != HANDLER_GO_ON) return rc; /*(might invalidate hctx)*/
	}
	if (wr_revents) {
		hctx->wr_revents = 0;
		handler_t rc = cgi_process_wr_revents(hctx, r, wr_revents);
		if (rc != HANDLER_GO_ON) return rc; /*(might invalidate hctx)*/
	}

	if ((r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
	    && r->resp_body_started) {
		if (chunkqueue_length(&r->write_queue) > 65536 - 4096) {
			fdevent_fdnode_event_clr(hctx->ev, hctx->fdn, FDEVENT_IN);
		} else if (!(fdevent_fdnode_interest(hctx->fdn) & FDEVENT_IN)) {
			/* optimistic read from backend */
			handler_t rc = cgi_recv_response(r, hctx);  /*(might invalidate hctx)*/
			if (rc != HANDLER_GO_ON) return rc;          /*(unless HANDLER_GO_ON)*/
			hctx->read_ts = log_monotonic_secs;
			fdevent_fdnode_event_add(hctx->ev, hctx->fdn, FDEVENT_IN);
		}
	}

	chunkqueue * const cq = &r->reqbody_queue;

	if (cq->bytes_in != (off_t)r->reqbody_length) {
		/*(64k - 4k to attempt to avoid temporary files
		 * in conjunction with FDEVENT_STREAM_REQUEST_BUFMIN)*/
		if (chunkqueue_length(cq) > 65536 - 4096
		    && (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN)){
			r->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
		} else {
			handler_t rc = r->con->reqbody_read(r);
			if (rc != HANDLER_GO_ON
			    && !(hctx->conf.upgrade && -1 == hctx->fd
			         && rc == HANDLER_WAIT_FOR_EVENT))
				return rc;
		}
	}

	if (-1 == hctx->fd) {
			/* CGI environment requires that Content-Length be set.
			 * Send 411 Length Required if Content-Length missing.
			 * (occurs here if client sends Transfer-Encoding: chunked
			 *  and module is flagged to stream request body to backend) */
			if (-1 == r->reqbody_length && !hctx->conf.upgrade) {
				return (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
				  ? http_response_reqbody_read_error(r, 411)
				  : HANDLER_WAIT_FOR_EVENT;
			}
		if (cgi_create_env(r, hctx, hctx->cgi_handler))
			return http_status_set_err(r, 500); /* HANDLER_FINISHED */
	} else if (!chunkqueue_is_empty(cq)) {
		if (fdevent_fdnode_interest(hctx->fdntocgi) & FDEVENT_OUT)
			return HANDLER_WAIT_FOR_EVENT;
		if (0 != cgi_write_request(hctx, hctx->fdtocgi)) {
			cgi_connection_close(hctx);
			return HANDLER_ERROR;
		}
	}

	/* if not done, wait for CGI to close stdout, so we read EOF on pipe */
	return HANDLER_WAIT_FOR_EVENT;
}


__attribute_cold__
__attribute_noinline__
static void cgi_trigger_hctx_timeout(handler_ctx * const hctx, const char * const msg) {
    request_st * const r = hctx->r;
    joblist_append(r->con);

    log_error(r->conf.errh, __FILE__, __LINE__,
      "%s timeout on CGI: %s (pid: %lld)",
      msg, r->physical.path.ptr, (long long)hctx->cgi_pid->pid);

    if (*msg == 'w') { /* "write" */
        /* theoretically, response might be waiting on hctx->fdn pipe
         * if it arrived since we last checked for event, and if CGI
         * timeout out while reading (or did not read) request body */
        handler_t rc = cgi_recv_response(r, hctx); /*(might invalidate hctx)*/
        if (rc != HANDLER_GO_ON) return;            /*(unless HANDLER_GO_ON)*/
    }

    if (0 == r->http_status) r->http_status = 504; /* Gateway Timeout */
    cgi_connection_close(hctx);
}


static handler_t cgi_trigger_cb(server *srv, void *p_d) {
    UNUSED(srv);
    UNUSED(p_d);
    const unix_time64_t mono = log_monotonic_secs;
    for (cgi_pid_t *cgi_pid = cgi_pids; cgi_pid; cgi_pid = cgi_pid->next) {
        /*(hctx stays in cgi_pid list until process pid is reaped,
         * so cgi_pids[] is not modified during this loop)*/
        handler_ctx * const hctx = cgi_pid->hctx;
        if (!hctx) continue; /*(already called cgi_pid_kill())*/
        const cgi_limits * const limits = hctx->conf.limits;
        if (NULL == limits) continue;
        if (limits->read_timeout && hctx->fdn
            && (fdevent_fdnode_interest(hctx->fdn) & FDEVENT_IN)
            && mono - hctx->read_ts > limits->read_timeout) {
            cgi_trigger_hctx_timeout(hctx, "read");
            continue;
        }
        if (limits->write_timeout && hctx->fdntocgi
            && (fdevent_fdnode_interest(hctx->fdntocgi) & FDEVENT_OUT)
            && mono - hctx->write_ts > limits->write_timeout) {
            cgi_trigger_hctx_timeout(hctx, "write");
            continue;
        }
    }
    return HANDLER_GO_ON;
}


static handler_t cgi_waitpid_cb(server *srv, void *p_d, pid_t pid, int status) {
    /*(XXX: if supporting a large number of CGI, might use a different algorithm
     * instead of linked list, e.g. splaytree indexed with pid)*/
    UNUSED(p_d);
    for (cgi_pid_t *cgi_pid = cgi_pids; cgi_pid; cgi_pid = cgi_pid->next) {
        if (pid != cgi_pid->pid) continue;

        handler_ctx * const hctx = cgi_pid->hctx;
        if (hctx) hctx->cgi_pid = NULL;

        if (WIFEXITED(status)) {
            /* (skip logging (non-zero) CGI exit; might be very noisy) */
        }
        else if (WIFSIGNALED(status)) {
            /* ignore SIGTERM if sent by cgi_connection_close() (NULL == hctx)*/
            if (WTERMSIG(status) != cgi_pid->signal_sent) {
                log_error_st *errh = hctx ? hctx->r->conf.errh : srv->errh;
                log_error(errh, __FILE__, __LINE__,
                  "CGI pid %d died with signal %d", pid, WTERMSIG(status));
            }
        }
      #if 0 /*(should not happen; lighttpd not catching STOP or CONT)*/
        else {
            log_error_st *errh = hctx ? hctx->r->conf.errh : srv->errh;
            log_error(errh, __FILE__, __LINE__,
              "CGI pid %d ended unexpectedly", pid);
        }
      #endif

        cgi_pid_del(cgi_pid);
        return HANDLER_FINISHED;
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_cgi_plugin_init(plugin *p);
int mod_cgi_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "cgi";

	p->handle_request_reset = cgi_connection_close_callback;
	p->handle_subrequest_start = cgi_is_handled;
	p->handle_subrequest = mod_cgi_handle_subrequest;
	p->handle_trigger = cgi_trigger_cb;
	p->handle_waitpid = cgi_waitpid_cb;
	p->init           = mod_cgi_init;
	p->cleanup        = mod_cgi_free;
	p->set_defaults   = mod_cgi_set_defaults;

	return 0;
}
