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

#include "plugin.h"

#include <sys/types.h>
#include "sys-socket.h"
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fdevent.h>

#include <fcntl.h>
#include <signal.h>

typedef struct {
	uintptr_t *offsets;
	size_t osize;
	size_t oused;
	buffer *b;
	buffer *boffsets;
	buffer *ld_preload;
	buffer *ld_library_path;
      #ifdef __CYGWIN__
	buffer *systemroot;
      #endif
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
	plugin_config conf;
	int tempfile_accum;
	struct cgi_pid_t *cgi_pid;
	env_accum env;
} plugin_data;

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
} handler_ctx;

typedef struct cgi_pid_t {
	pid_t pid;
	int signal_sent;
	handler_ctx *hctx;
	struct cgi_pid_t *next;
	struct cgi_pid_t *prev;
} cgi_pid_t;

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
	buffer_free(p->env.ld_preload);
	buffer_free(p->env.ld_library_path);
      #ifdef __CYGWIN__
	buffer_free(p->env.systemroot);
      #endif

    for (cgi_pid_t *cgi_pid = p->cgi_pid, *next; cgi_pid; cgi_pid = next) {
        next = cgi_pid->next;
        free(cgi_pid);
    }

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

static void mod_cgi_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_cgi_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

__attribute_cold__
__attribute_pure__
static int mod_cgi_str_to_signal (const char *s, int default_sig) {
    static const struct { const char *name; int sig; } sigs[] = {
      { "HUP",  SIGHUP  }
     ,{ "INT",  SIGINT  }
     ,{ "QUIT", SIGQUIT }
     ,{ "ILL",  SIGILL  }
     ,{ "TRAP", SIGTRAP }
     ,{ "ABRT", SIGABRT }
     #ifdef SIGBUS
     ,{ "BUS",  SIGBUS  }
     #endif
     ,{ "FPE",  SIGFPE  }
     ,{ "KILL", SIGKILL }
     #ifdef SIGUSR1
     ,{ "USR1", SIGUSR1 }
     #endif
     ,{ "SEGV", SIGSEGV }
     #ifdef SIGUSR2
     ,{ "USR2", SIGUSR2 }
     #endif
     ,{ "PIPE", SIGPIPE }
     ,{ "ALRM", SIGALRM }
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
    cgi_limits * const limits = calloc(1, sizeof(cgi_limits));
    force_assert(limits);
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


static cgi_pid_t * cgi_pid_add(plugin_data *p, pid_t pid, handler_ctx *hctx) {
    cgi_pid_t *cgi_pid = malloc(sizeof(cgi_pid_t));
    force_assert(cgi_pid);
    cgi_pid->pid = pid;
    cgi_pid->signal_sent = 0;
    cgi_pid->hctx = hctx;
    cgi_pid->prev = NULL;
    cgi_pid->next = p->cgi_pid;
    p->cgi_pid = cgi_pid;
    return cgi_pid;
}

static void cgi_pid_kill(cgi_pid_t *cgi_pid, int sig) {
    cgi_pid->signal_sent = sig; /*(save last signal sent)*/
    kill(cgi_pid->pid, sig);
}

static void cgi_pid_del(plugin_data *p, cgi_pid_t *cgi_pid) {
    if (cgi_pid->prev)
        cgi_pid->prev->next = cgi_pid->next;
    else
        p->cgi_pid = cgi_pid->next;

    if (cgi_pid->next)
        cgi_pid->next->prev = cgi_pid->prev;

    free(cgi_pid);
}


static void cgi_connection_close_fdtocgi(handler_ctx *hctx) {
	/*(closes only hctx->fdtocgi)*/
	if (-1 == hctx->fdtocgi) return;
	struct fdevents * const ev = hctx->ev;
	fdevent_fdnode_event_del(ev, hctx->fdntocgi);
	/*fdevent_unregister(ev, hctx->fdtocgi);*//*(handled below)*/
	fdevent_sched_close(ev, hctx->fdtocgi, 0);
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
		struct fdevents * const ev = hctx->ev;
		/* close connection to the cgi-script */
		fdevent_fdnode_event_del(ev, hctx->fdn);
		/*fdevent_unregister(ev, hctx->fd);*//*(handled below)*/
		fdevent_sched_close(ev, hctx->fd, 0);
		hctx->fdn = NULL;
	}

	if (hctx->fdtocgi != -1) {
		cgi_connection_close_fdtocgi(hctx); /*(closes only hctx->fdtocgi)*/
	}

	plugin_data * const p = hctx->plugin_data;
	request_st * const r = hctx->r;
	r->plugin_ctx[p->id] = NULL;

	if (hctx->cgi_pid) {
		cgi_pid_kill(hctx->cgi_pid, SIGTERM);
		hctx->cgi_pid->hctx = NULL;
	}
	cgi_handler_ctx_free(hctx);

	/* finish response (if not already r->resp_body_started, r->resp_body_finished) */
	if (r->handler_module == p->self) {
		http_response_backend_done(r);
	}
}

static handler_t cgi_connection_close_callback(request_st * const r, void *p_d) {
    handler_ctx *hctx = r->plugin_ctx[((plugin_data *)p_d)->id];
    if (hctx) {
        chunkqueue_set_tempdirs(&r->reqbody_queue, /* reset sz */
                                r->reqbody_queue.tempdirs, 0);
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

    if (light_btst(r->resp_htags, HTTP_HEADER_UPGRADE)) {
        if (hctx->conf.upgrade && r->http_status == 101) {
            /* 101 Switching Protocols; transition to transparent proxy */
            http_response_upgrade_read_body_unknown(r);
        }
        else {
            light_bclr(r->resp_htags, HTTP_HEADER_UPGRADE);
          #if 0
            /* preserve prior questionable behavior; likely broken behavior
             * anyway if backend thinks connection is being upgraded but client
             * does not receive Connection: upgrade */
            http_header_response_unset(r, HTTP_HEADER_UPGRADE,
                                       CONST_STR_LEN("Upgrade"));
          #endif
        }
    }

    if (hctx->conf.upgrade
        && !light_btst(r->resp_htags, HTTP_HEADER_UPGRADE)) {
        chunkqueue *cq = &r->reqbody_queue;
        hctx->conf.upgrade = 0;
        if (cq->bytes_out == (off_t)r->reqbody_length) {
            cgi_connection_close_fdtocgi(hctx); /*(closes hctx->fdtocgi)*/
        }
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
__attribute_noinline__
static handler_t cgi_local_redir(request_st * const r, handler_ctx * const hctx) {
    buffer_clear(hctx->response);
    chunk_buffer_yield(hctx->response);
    http_response_reset(r); /*(includes r->http_status = 0)*/
    plugins_call_handle_request_reset(r);
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
	chunk *c;

	chunkqueue_remove_finished_chunks(cq); /* unnecessary? */

	/* old comment: windows doesn't support select() on pipes - wouldn't be easy to fix for all platforms.
	 */

	for (c = cq->first; c; c = cq->first) {
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
				case EINTR:
					/* ignore and try again later */
					break;
				case EPIPE:
				case ECONNRESET:
					/* connection closed */
					log_error(r->conf.errh, __FILE__, __LINE__,
					  "failed to send post data to cgi, connection closed by CGI");
					/* skip all remaining data */
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

	if (cq->bytes_out == (off_t)r->reqbody_length && !hctx->conf.upgrade) {
		/* sent all request body input */
		/* close connection to the cgi-script */
		if (-1 == hctx->fdtocgi) { /*(received request body sent in initial send to pipe buffer)*/
			--r->con->srv->cur_fds;
			if (close(fd)) {
				log_perror(r->conf.errh, __FILE__, __LINE__, "cgi stdin close %d failed", fd);
			}
		} else {
			cgi_connection_close_fdtocgi(hctx); /*(closes only hctx->fdtocgi)*/
		}
	} else {
		off_t cqlen = chunkqueue_length(cq);
		if (cq->bytes_in != r->reqbody_length && cqlen < 65536 - 16384) {
			/*(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)*/
			if (!(r->conf.stream_request_body & FDEVENT_STREAM_REQUEST_POLLIN)) {
				r->conf.stream_request_body |= FDEVENT_STREAM_REQUEST_POLLIN;
				r->con->is_readable = 1; /* trigger optimistic read from client */
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

static int cgi_create_env(request_st * const r, plugin_data * const p, handler_ctx * const hctx, buffer * const cgi_handler) {
	char *args[3];
	int to_cgi_fds[2];
	int from_cgi_fds[2];
	UNUSED(p);

	if (!buffer_is_blank(cgi_handler)) {
		if (NULL == stat_cache_path_stat(cgi_handler)) {
			log_perror(r->conf.errh, __FILE__, __LINE__,
			  "stat for cgi-handler %s", cgi_handler->ptr);
			return -1;
		}
	}

	to_cgi_fds[0] = -1;
  #ifndef __CYGWIN__
	if (0 == r->reqbody_length) {
		/* future: might keep fd open in p->devnull for reuse
		 * and dup() here, or do not close() (later in this func) */
		to_cgi_fds[0] = fdevent_open_devnull();
		if (-1 == to_cgi_fds[0]) {
			log_perror(r->conf.errh, __FILE__, __LINE__, "open /dev/null");
			return -1;
		}
	}
	else if (!(r->conf.stream_request_body /*(if not streaming request body)*/
	           & (FDEVENT_STREAM_REQUEST|FDEVENT_STREAM_REQUEST_BUFMIN))) {
		chunkqueue * const cq = &r->reqbody_queue;
		chunk * const c = cq->first;
		if (c && c == cq->last && c->type == FILE_CHUNK && c->file.is_temp) {
			/* request body in single tempfile if not streaming req body */
			if (-1 == c->file.fd
			    && 0 != chunkqueue_open_file_chunk(cq, r->conf.errh))
				return -1;
		  #ifdef __COVERITY__
			force_assert(-1 != c->file.fd);
		  #endif
			if (-1 == lseek(c->file.fd, 0, SEEK_SET)) {
				log_perror(r->conf.errh, __FILE__, __LINE__,
				  "lseek %s", c->mem->ptr);
				return -1;
			}
			to_cgi_fds[0] = c->file.fd;
			to_cgi_fds[1] = -1;
		}
	}
  #endif

	unsigned int bufsz_hint = 16384;
  #ifdef _WIN32
	if (r->reqbody_length <= 1048576)
		bufsz_hint = (unsigned int)r->reqbody_length;
  #endif
	if (-1 == to_cgi_fds[0] && fdevent_pipe_cloexec(to_cgi_fds, bufsz_hint)) {
		log_perror(r->conf.errh, __FILE__, __LINE__, "pipe failed");
		return -1;
	}
	if (fdevent_pipe_cloexec(from_cgi_fds, bufsz_hint)) {
		if (0 == r->reqbody_length) {
			close(to_cgi_fds[0]);
		}
		else if (-1 != to_cgi_fds[1]) {
			close(to_cgi_fds[0]);
			close(to_cgi_fds[1]);
		}
		log_perror(r->conf.errh, __FILE__, __LINE__, "pipe failed");
		return -1;
	}

	env_accum * const env = &p->env;
	env->b = chunk_buffer_acquire();
	env->boffsets = chunk_buffer_acquire();
	buffer_truncate(env->b, 0);
	char **envp;
	{
		size_t i = 0;
		http_cgi_opts opts = { 0, 0, NULL, NULL };
		env->offsets = (uintptr_t *)(void *)env->boffsets->ptr;
		env->osize = env->boffsets->size/sizeof(*env->offsets);
		env->oused = 0;

		/* create environment */

		http_cgi_headers(r, &opts, cgi_env_add, env);

		/* for valgrind */
		if (p->env.ld_preload) {
			cgi_env_add(env, CONST_STR_LEN("LD_PRELOAD"), BUF_PTR_LEN(p->env.ld_preload));
		}
		if (p->env.ld_library_path) {
			cgi_env_add(env, CONST_STR_LEN("LD_LIBRARY_PATH"), BUF_PTR_LEN(p->env.ld_library_path));
		}
	      #ifdef __CYGWIN__
		/* CYGWIN needs SYSTEMROOT */
		if (p->env.systemroot) {
			cgi_env_add(env, CONST_STR_LEN("SYSTEMROOT"), BUF_PTR_LEN(p->env.systemroot));
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
		args[i++] = r->physical.path.ptr;
		args[i  ] = NULL;
	}

	int dfd = fdevent_open_dirname(r->physical.path.ptr,r->conf.follow_symlink);
	if (-1 == dfd) {
		log_perror(r->conf.errh, __FILE__, __LINE__, "open dirname %s failed", r->physical.path.ptr);
	}

	int serrh_fd = r->conf.serrh ? r->conf.serrh->fd : -1;
	pid_t pid = (dfd >= 0)
	  ? fdevent_fork_execve(args[0], args, envp,
	                        to_cgi_fds[0], from_cgi_fds[1], serrh_fd, dfd)
	  : -1;

	chunk_buffer_release(env->boffsets);
	chunk_buffer_release(env->b);
	env->boffsets = NULL;
	env->b = NULL;

	if (-1 == pid) {
		/* log error with errno prior to calling close() (might change errno) */
		log_perror(r->conf.errh, __FILE__, __LINE__, "fork failed");
		if (-1 != dfd) close(dfd);
		close(from_cgi_fds[0]);
		close(from_cgi_fds[1]);
		if (0 == r->reqbody_length) {
			close(to_cgi_fds[0]);
		}
		else if (-1 != to_cgi_fds[1]) {
			close(to_cgi_fds[0]);
			close(to_cgi_fds[1]);
		}
		return -1;
	} else {
		if (-1 != dfd) close(dfd);
		close(from_cgi_fds[1]);

		hctx->fd = from_cgi_fds[0];
		hctx->cgi_pid = cgi_pid_add(p, pid, hctx);

		if (0 == r->reqbody_length) {
			close(to_cgi_fds[0]);
		}
		else if (-1 == to_cgi_fds[1]) {
			chunkqueue * const cq = &r->reqbody_queue;
			chunkqueue_mark_written(cq, chunkqueue_length(cq));
		}
		else if (0 == fdevent_fcntl_set_nb(to_cgi_fds[1])
		         && 0 == cgi_write_request(hctx, to_cgi_fds[1])) {
			close(to_cgi_fds[0]);
			++r->con->srv->cur_fds;
		}
		else {
			close(to_cgi_fds[0]);
			close(to_cgi_fds[1]);
			/*(hctx->fd not yet registered with fdevent, so manually
			 * cleanup here; see fdevent_register() further below)*/
			close(hctx->fd);
			hctx->fd = -1;
			cgi_connection_close(hctx);
			return -1;
		}

		++r->con->srv->cur_fds;

		struct fdevents * const ev = hctx->ev;
		hctx->fdn = fdevent_register(ev, hctx->fd, cgi_handle_fdevent, hctx);
		if (-1 == fdevent_fcntl_set_nb(hctx->fd)) {
			log_perror(r->conf.errh, __FILE__, __LINE__, "fcntl failed");
			cgi_connection_close(hctx);
			return -1;
		}
		hctx->read_ts = log_monotonic_secs;
		fdevent_fdnode_event_set(ev, hctx->fdn, FDEVENT_IN | FDEVENT_RDHUP);

		return 0;
	}
}

URIHANDLER_FUNC(cgi_is_handled) {
	plugin_data *p = p_d;
	const stat_cache_st *st;
	data_string *ds;

	if (NULL != r->handler_module) return HANDLER_GO_ON;
	/* r->physical.path is non-empty for handle_subrequest_start */
	/*if (buffer_is_blank(&r->physical.path)) return HANDLER_GO_ON;*/

	mod_cgi_patch_config(r, p);
	if (NULL == p->conf.cgi) return HANDLER_GO_ON;

	ds = (data_string *)array_match_key_suffix(p->conf.cgi, &r->physical.path);
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
	if (p->conf.execute_x_only == 1 && (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) return HANDLER_GO_ON;

	if (r->reqbody_length
	    && p->tempfile_accum
	    && !(r->conf.stream_request_body /*(if not streaming request body)*/
	         & (FDEVENT_STREAM_REQUEST|FDEVENT_STREAM_REQUEST_BUFMIN))) {
		/* store request body in single tempfile if not streaming request body*/
		r->reqbody_queue.upload_temp_file_size = INTMAX_MAX;
	}

	{
		handler_ctx *hctx = cgi_handler_ctx_init();
		hctx->ev = r->con->srv->ev;
		hctx->r = r;
		hctx->con = r->con;
		hctx->plugin_data = p;
		hctx->cgi_handler = &ds->value;
		memcpy(&hctx->conf, &p->conf, sizeof(plugin_config));
		if (!light_btst(r->rqst_htags, HTTP_HEADER_UPGRADE))
			hctx->conf.upgrade = 0;
		else if (!hctx->conf.upgrade || r->http_version != HTTP_VERSION_1_1) {
			hctx->conf.upgrade = 0;
			http_header_request_unset(r, HTTP_HEADER_UPGRADE,
			                          CONST_STR_LEN("Upgrade"));
		}
		hctx->opts.max_per_read =
		  !(r->conf.stream_response_body /*(if not streaming response body)*/
		    & (FDEVENT_STREAM_RESPONSE|FDEVENT_STREAM_RESPONSE_BUFMIN))
		    ? 262144
		    : (r->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
		      ? 16384  /* FDEVENT_STREAM_RESPONSE_BUFMIN */
		      : 65536; /* FDEVENT_STREAM_RESPONSE */
		hctx->opts.fdfmt = S_IFIFO;
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
			if (-1 != hctx->fd) return HANDLER_WAIT_FOR_EVENT;
		} else {
			handler_t rc = r->con->reqbody_read(r);
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
			if (-1 == r->reqbody_length) {
				return (r->conf.stream_request_body & FDEVENT_STREAM_REQUEST)
				  ? http_response_reqbody_read_error(r, 411)
				  : HANDLER_WAIT_FOR_EVENT;
			}
		}
	}

	if (-1 == hctx->fd) {
		if (cgi_create_env(r, p, hctx, hctx->cgi_handler)) {
			r->http_status = 500;
			r->handler_module = NULL;

			return HANDLER_FINISHED;
		}
	} else if (!chunkqueue_is_empty(cq)) {
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
    const unix_time64_t mono = log_monotonic_secs;
    plugin_data * const p = p_d;
    for (cgi_pid_t *cgi_pid = p->cgi_pid; cgi_pid; cgi_pid = cgi_pid->next) {
        /*(hctx stays in cgi_pid list until process pid is reaped,
         * so p->cgi_pid[] is not modified during this loop)*/
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
    plugin_data *p = (plugin_data *)p_d;
    for (cgi_pid_t *cgi_pid = p->cgi_pid; cgi_pid; cgi_pid = cgi_pid->next) {
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
        else {
            log_error_st *errh = hctx ? hctx->r->conf.errh : srv->errh;
            log_error(errh, __FILE__, __LINE__,
              "CGI pid %d ended unexpectedly", pid);
        }

        cgi_pid_del(p, cgi_pid);
        return HANDLER_FINISHED;
    }

    return HANDLER_GO_ON;
}


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
