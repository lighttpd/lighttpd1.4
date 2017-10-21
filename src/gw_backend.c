#include "first.h"

#include "gw_backend.h"

#include <sys/types.h>
#include "sys-socket.h"
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "array.h"
#include "buffer.h"
#include "crc32.h"
#include "fdevent.h"
#include "inet_ntop_cache.h"
#include "log.h"




#include "status_counter.h"

static data_integer * gw_status_get_di(server *srv, gw_host *host, gw_proc *proc, const char *tag, size_t len) {
    buffer *b = srv->tmp_buf;
    buffer_copy_string_len(b, CONST_STR_LEN("gw.backend."));
    buffer_append_string_buffer(b, host->id);
    if (proc) {
        buffer_append_string_len(b, CONST_STR_LEN("."));
        buffer_append_int(b, proc->id);
    }
    buffer_append_string_len(b, tag, len);
    return status_counter_get_counter(srv, CONST_BUF_LEN(b));
}

static void gw_proc_tag_inc(server *srv, gw_host *host, gw_proc *proc, const char *tag, size_t len) {
    data_integer *di = gw_status_get_di(srv, host, proc, tag, len);
    ++di->value;
}

static void gw_proc_load_inc(server *srv, gw_host *host, gw_proc *proc) {
    data_integer *di = gw_status_get_di(srv,host,proc,CONST_STR_LEN(".load"));
    di->value = ++proc->load;

    status_counter_inc(srv, CONST_STR_LEN("gw.active-requests"));
}

static void gw_proc_load_dec(server *srv, gw_host *host, gw_proc *proc) {
    data_integer *di = gw_status_get_di(srv,host,proc,CONST_STR_LEN(".load"));
    di->value = --proc->load;

    status_counter_dec(srv, CONST_STR_LEN("gw.active-requests"));
}

static void gw_host_assign(server *srv, gw_host *host) {
    data_integer *di = gw_status_get_di(srv,host,NULL,CONST_STR_LEN(".load"));
    di->value = ++host->load;
}

static void gw_host_reset(server *srv, gw_host *host) {
    data_integer *di = gw_status_get_di(srv,host,NULL,CONST_STR_LEN(".load"));
    di->value = --host->load;
}

static int gw_status_init(server *srv, gw_host *host, gw_proc *proc) {
    gw_status_get_di(srv, host, proc, CONST_STR_LEN(".disabled"))->value = 0;
    gw_status_get_di(srv, host, proc, CONST_STR_LEN(".died"))->value = 0;
    gw_status_get_di(srv, host, proc, CONST_STR_LEN(".overloaded"))->value = 0;
    gw_status_get_di(srv, host, proc, CONST_STR_LEN(".connected"))->value = 0;
    gw_status_get_di(srv, host, proc, CONST_STR_LEN(".load"))->value = 0;

    gw_status_get_di(srv, host, NULL, CONST_STR_LEN(".load"))->value = 0;

    return 0;
}




static void gw_proc_set_state(gw_host *host, gw_proc *proc, int state) {
    if ((int)proc->state == state) return;
    if (proc->state == PROC_STATE_RUNNING) {
        --host->active_procs;
    } else if (state == PROC_STATE_RUNNING) {
        ++host->active_procs;
    }
    proc->state = state;
}


static gw_proc *gw_proc_init(void) {
    gw_proc *f = calloc(1, sizeof(*f));
    force_assert(f);

    f->unixsocket = buffer_init();
    f->connection_name = buffer_init();

    f->prev = NULL;
    f->next = NULL;
    f->state = PROC_STATE_DIED;

    return f;
}

static void gw_proc_free(gw_proc *f) {
    if (!f) return;

    gw_proc_free(f->next);

    buffer_free(f->unixsocket);
    buffer_free(f->connection_name);
    free(f->saddr);

    free(f);
}

static gw_host *gw_host_init(void) {
    gw_host *f = calloc(1, sizeof(*f));
    force_assert(f);

    f->id = buffer_init();
    f->host = buffer_init();
    f->unixsocket = buffer_init();
    f->docroot = buffer_init();
    f->bin_path = buffer_init();
    f->bin_env = array_init();
    f->bin_env_copy = array_init();
    f->strip_request_uri = buffer_init();
    f->xsendfile_docroot = array_init();

    return f;
}

static void gw_host_free(gw_host *h) {
    if (!h) return;
    if (h->refcount) {
        --h->refcount;
        return;
    }

    buffer_free(h->id);
    buffer_free(h->host);
    buffer_free(h->unixsocket);
    buffer_free(h->docroot);
    buffer_free(h->bin_path);
    buffer_free(h->strip_request_uri);
    array_free(h->bin_env);
    array_free(h->bin_env_copy);
    array_free(h->xsendfile_docroot);

    gw_proc_free(h->first);
    gw_proc_free(h->unused_procs);

    for (size_t i = 0; i < h->args.used; ++i) free(h->args.ptr[i]);
    free(h->args.ptr);
    free(h);
}

static gw_exts *gw_extensions_init(void) {
    gw_exts *f = calloc(1, sizeof(*f));
    force_assert(f);
    return f;
}

static void gw_extensions_free(gw_exts *f) {
    if (!f) return;
    for (size_t i = 0; i < f->used; ++i) {
        gw_extension *fe = f->exts[i];
        for (size_t j = 0; j < fe->used; ++j) {
            gw_host_free(fe->hosts[j]);
        }
        buffer_free(fe->key);
        free(fe->hosts);
        free(fe);
    }
    free(f->exts);
    free(f);
}

static int gw_extension_insert(gw_exts *ext, buffer *key, gw_host *fh) {
    gw_extension *fe = NULL;
    for (size_t i = 0; i < ext->used; ++i) {
        if (buffer_is_equal(key, ext->exts[i]->key)) {
            fe = ext->exts[i];
            break;
        }
    }

    if (NULL == fe) {
        fe = calloc(1, sizeof(*fe));
        force_assert(fe);
        fe->key = buffer_init();
        fe->last_used_ndx = -1;
        buffer_copy_buffer(fe->key, key);

        if (ext->size == 0) {
            ext->size = 8;
            ext->exts = malloc(ext->size * sizeof(*(ext->exts)));
            force_assert(ext->exts);
        } else if (ext->used == ext->size) {
            ext->size += 8;
            ext->exts = realloc(ext->exts, ext->size * sizeof(*(ext->exts)));
            force_assert(ext->exts);
        }
        ext->exts[ext->used++] = fe;
        fe->size = 4;
        fe->hosts = malloc(fe->size * sizeof(*(fe->hosts)));
        force_assert(fe->hosts);
    } else if (fe->size == fe->used) {
        fe->size += 4;
        fe->hosts = realloc(fe->hosts, fe->size * sizeof(*(fe->hosts)));
        force_assert(fe->hosts);
    }

    fe->hosts[fe->used++] = fh;
    return 0;
}

static void gw_proc_connect_success(server *srv, gw_host *host, gw_proc *proc, int debug) {
    gw_proc_tag_inc(srv, host, proc, CONST_STR_LEN(".connected"));
    proc->last_used = srv->cur_ts;

    if (debug) {
        log_error_write(srv, __FILE__, __LINE__, "ssdsbsd",
                        "got proc:",
                        "pid:", proc->pid,
                        "socket:", proc->connection_name,
                        "load:", proc->load);
    }
}

static void gw_proc_connect_error(server *srv, gw_host *host, gw_proc *proc, pid_t pid, int errnum, int debug) {
    log_error_write(srv, __FILE__, __LINE__, "sssb",
                    "establishing connection failed:", strerror(errnum),
                    "socket:", proc->connection_name);

    if (!proc->is_local) {
        proc->disabled_until = srv->cur_ts + host->disable_time;
        gw_proc_set_state(host, proc, PROC_STATE_OVERLOADED);
    }
    else if (proc->pid == pid && proc->state == PROC_STATE_RUNNING) {
        /* several requests from lighttpd might reference the same proc
         *
         * Only one of them should mark the proc
         * and all other ones should just take a new one.
         *
         * If a new proc was started with the old struct, this might
         * otherwise lead to marking a perfectly good proc as dead
         */
        log_error_write(srv, __FILE__, __LINE__, "sdssd",
                        "backend error; we'll disable for", host->disable_time,
                        "secs and send the request to another backend instead:",
                        "load:", host->load);
        if (EAGAIN == errnum) {
            /* - EAGAIN: cool down the backend; it is overloaded */
          #ifdef __linux__
            log_error_write(srv, __FILE__, __LINE__, "s",
              "If this happened on Linux: You have run out of local ports. "
              "Check the manual, section Performance how to handle this.");
          #endif
            if (debug) {
                log_error_write(srv, __FILE__, __LINE__, "sbsd",
                  "This means that you have more incoming requests than your "
                  "FastCGI backend can handle in parallel.  It might help to "
                  "spawn more FastCGI backends or PHP children; if not, "
                  "decrease server.max-connections.  The load for this FastCGI "
                  "backend", proc->connection_name, "is", proc->load);
            }
            proc->disabled_until = srv->cur_ts + host->disable_time;
            gw_proc_set_state(host, proc, PROC_STATE_OVERLOADED);
        }
        else {
            /* we got a hard error from the backend like
             * - ECONNREFUSED for tcp-ip sockets
             * - ENOENT for unix-domain-sockets
             */
          #if 0
            gw_proc_set_state(host, proc, PROC_STATE_DIED_WAIT_FOR_PID);
          #else  /* treat as overloaded (future: unless we send kill() signal)*/
            proc->disabled_until = srv->cur_ts + host->disable_time;
            gw_proc_set_state(host, proc, PROC_STATE_OVERLOADED);
          #endif
        }
    }

    if (EAGAIN == errnum) {
        gw_proc_tag_inc(srv, host, proc, CONST_STR_LEN(".overloaded"));
    }
    else {
        gw_proc_tag_inc(srv, host, proc, CONST_STR_LEN(".died"));
    }
}

static void gw_proc_release(server *srv, gw_host *host, gw_proc *proc, int debug) {
    gw_proc_load_dec(srv, host, proc);

    if (debug) {
        log_error_write(srv, __FILE__, __LINE__, "ssdsbsd",
                        "released proc:",
                        "pid:", proc->pid,
                        "socket:", proc->connection_name,
                        "load:", proc->load);
    }
}

static void gw_proc_check_enable(server *srv, gw_host *host, gw_proc *proc) {
    if (srv->cur_ts <= proc->disabled_until) return;
    if (proc->state != PROC_STATE_OVERLOADED) return;

    gw_proc_set_state(host, proc, PROC_STATE_RUNNING);

    log_error_write(srv, __FILE__, __LINE__,  "sbbdb",
                    "gw-server re-enabled:", proc->connection_name,
                    host->host, host->port, host->unixsocket);
}

static void gw_proc_waitpid_log(server *srv, gw_host *host, gw_proc *proc, int status) {
    UNUSED(host);
    if (WIFEXITED(status)) {
        if (proc->state != PROC_STATE_KILLED) {
            log_error_write(srv, __FILE__, __LINE__, "sdb",
                            "child exited:",
                            WEXITSTATUS(status), proc->connection_name);
        }
    } else if (WIFSIGNALED(status)) {
        if (WTERMSIG(status) != SIGTERM && WTERMSIG(status) != SIGINT) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                            "child signalled:", WTERMSIG(status));
        }
    } else {
        log_error_write(srv, __FILE__, __LINE__, "sd",
                        "child died somehow:", status);
    }
}

static int gw_proc_waitpid(server *srv, gw_host *host, gw_proc *proc) {
    int rc, status;

    if (!proc->is_local) return 0;
    if (proc->pid <= 0) return 0;

    do {
        rc = waitpid(proc->pid, &status, WNOHANG);
    } while (-1 == rc && errno == EINTR);
    if (0 == rc) return 0; /* child still running */

    /* child terminated */
    if (-1 == rc) {
        /* EINVAL or ECHILD no child processes */
        /* should not happen; someone else has cleaned up for us */
        log_error_write(srv, __FILE__, __LINE__, "sddss",
                        "pid ", proc->pid, proc->state,
                        "not found:", strerror(errno));
    }
    else {
        gw_proc_waitpid_log(srv, host, proc, status);
    }

    proc->pid = 0;
    if (proc->state != PROC_STATE_KILLED)
        proc->disabled_until = srv->cur_ts;
    gw_proc_set_state(host, proc, PROC_STATE_DIED);
    return 1;
}

static int gw_proc_sockaddr_init(server *srv, gw_host *host, gw_proc *proc) {
    sock_addr addr;
    socklen_t addrlen;

    if (!buffer_string_is_empty(proc->unixsocket)) {
        if (1 != sock_addr_from_str_hints(srv, &addr, &addrlen,
                                          proc->unixsocket->ptr, AF_UNIX, 0)) {
            errno = EINVAL;
            return -1;
        }
        buffer_copy_string_len(proc->connection_name, CONST_STR_LEN("unix:"));
        buffer_append_string_buffer(proc->connection_name, proc->unixsocket);
    }
    else {
        /*(note: name resolution here is *blocking* if IP string not supplied)*/
        if (1 != sock_addr_from_str_hints(srv, &addr, &addrlen,
                                          host->host->ptr, 0, proc->port)) {
            errno = EINVAL;
            return -1;
        }
        else {
            /* overwrite host->host buffer with IP addr string so that
             * any further use of gw_host does not block on DNS lookup */
            sock_addr_inet_ntop_copy_buffer(host->host, &addr);
            host->family = addr.plain.sa_family;
        }
        buffer_copy_string_len(proc->connection_name, CONST_STR_LEN("tcp:"));
        buffer_append_string_buffer(proc->connection_name, host->host);
        buffer_append_string_len(proc->connection_name, CONST_STR_LEN(":"));
        buffer_append_int(proc->connection_name, proc->port);
    }

    if (NULL != proc->saddr && proc->saddrlen < addrlen) {
        free(proc->saddr);
        proc->saddr = NULL;
    }
    if (NULL == proc->saddr) {
        proc->saddr = (struct sockaddr *)malloc(addrlen);
        force_assert(proc->saddr);
    }
    proc->saddrlen = addrlen;
    memcpy(proc->saddr, &addr, addrlen);
    return 0;
}

static int env_add(char_array *env, const char *key, size_t key_len, const char *val, size_t val_len) {
    char *dst;

    if (!key || !val) return -1;

    dst = malloc(key_len + val_len + 3);
    force_assert(dst);
    memcpy(dst, key, key_len);
    dst[key_len] = '=';
    memcpy(dst + key_len + 1, val, val_len + 1); /* add the \0 from the value */

    for (size_t i = 0; i < env->used; ++i) {
        if (0 == strncmp(dst, env->ptr[i], key_len + 1)) {
            free(env->ptr[i]);
            env->ptr[i] = dst;
            return 0;
        }
    }

    if (env->size == 0) {
        env->size = 16;
        env->ptr = malloc(env->size * sizeof(*env->ptr));
        force_assert(env->ptr);
    } else if (env->size == env->used + 1) {
        env->size += 16;
        env->ptr = realloc(env->ptr, env->size * sizeof(*env->ptr));
        force_assert(env->ptr);
    }

    env->ptr[env->used++] = dst;

    return 0;
}

static int gw_spawn_connection(server *srv, gw_host *host, gw_proc *proc, int debug) {
    int gw_fd;
    int status;
    struct timeval tv = { 0, 10 * 1000 };

    if (debug) {
        log_error_write(srv, __FILE__, __LINE__, "sdb",
                        "new proc, socket:", proc->port, proc->unixsocket);
    }

    gw_fd = fdevent_socket_cloexec(proc->saddr->sa_family, SOCK_STREAM, 0);
    if (-1 == gw_fd) {
        log_error_write(srv, __FILE__, __LINE__, "ss",
                        "failed:", strerror(errno));
        return -1;
    }

    do {
        status = connect(gw_fd, proc->saddr, proc->saddrlen);
    } while (-1 == status && errno == EINTR);

    if (-1 == status && errno != ENOENT
        && !buffer_string_is_empty(proc->unixsocket)) {
        log_error_write(srv, __FILE__, __LINE__, "sbss",
                        "unlink", proc->unixsocket,
                        "after connect failed:", strerror(errno));
        unlink(proc->unixsocket->ptr);
    }

    close(gw_fd);

    if (-1 == status) {
        /* server is not up, spawn it  */
        char_array env;
        size_t i;
        int dfd = -1;

        /* reopen socket */
        gw_fd = fdevent_socket_cloexec(proc->saddr->sa_family, SOCK_STREAM, 0);
        if (-1 == gw_fd) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "socket failed:", strerror(errno));
            return -1;
        }

        if (fdevent_set_so_reuseaddr(gw_fd, 1) < 0) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "socketsockopt failed:", strerror(errno));
            close(gw_fd);
            return -1;
        }

        /* create socket */
        if (-1 == bind(gw_fd, proc->saddr, proc->saddrlen)) {
            log_error_write(srv, __FILE__, __LINE__, "sbs",
                            "bind failed for:",
                            proc->connection_name,
                            strerror(errno));
            close(gw_fd);
            return -1;
        }

        if (-1 == listen(gw_fd, host->listen_backlog)) {
            log_error_write(srv, __FILE__, __LINE__, "ss",
                            "listen failed:", strerror(errno));
            close(gw_fd);
            return -1;
        }

        {
            /* create environment */
            env.ptr = NULL;
            env.size = 0;
            env.used = 0;

            /* build clean environment */
            if (host->bin_env_copy->used) {
                for (i = 0; i < host->bin_env_copy->used; ++i) {
                    data_string *ds=(data_string *)host->bin_env_copy->data[i];
                    char *ge;

                    if (NULL != (ge = getenv(ds->value->ptr))) {
                        env_add(&env, CONST_BUF_LEN(ds->value), ge, strlen(ge));
                    }
                }
            } else {
                char ** const e = environ;
                for (i = 0; e[i]; ++i) {
                    char *eq;

                    if (NULL != (eq = strchr(e[i], '='))) {
                        env_add(&env, e[i], eq - e[i], eq+1, strlen(eq+1));
                    }
                }
            }

            /* create environment */
            for (i = 0; i < host->bin_env->used; ++i) {
                data_string *ds = (data_string *)host->bin_env->data[i];

                env_add(&env, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
            }

            for (i = 0; i < env.used; ++i) {
                /* search for PHP_FCGI_CHILDREN */
                if (0 == strncmp(env.ptr[i], "PHP_FCGI_CHILDREN=",
                                      sizeof("PHP_FCGI_CHILDREN=")-1)) {
                    break;
                }
            }

            /* not found, add a default */
            if (i == env.used) {
                env_add(&env, CONST_STR_LEN("PHP_FCGI_CHILDREN"),
                              CONST_STR_LEN("1"));
            }

            env.ptr[env.used] = NULL;
        }

        dfd = fdevent_open_dirname(host->args.ptr[0]);
        if (-1 == dfd) {
            log_error_write(srv, __FILE__, __LINE__, "sss",
                            "open dirname failed:", strerror(errno),
                            host->args.ptr[0]);
        }

        /*(FCGI_LISTENSOCK_FILENO == STDIN_FILENO == 0)*/
        proc->pid = (dfd >= 0)
          ? fdevent_fork_execve(host->args.ptr[0], host->args.ptr,
                                env.ptr, gw_fd, -1, -1, dfd)
          : -1;

        for (i = 0; i < env.used; ++i) free(env.ptr[i]);
        free(env.ptr);
        if (-1 != dfd) close(dfd);
        close(gw_fd);

        if (-1 == proc->pid) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "gw-backend failed to start:", host->bin_path);
            proc->pid = 0;
            proc->disabled_until = srv->cur_ts;
            return -1;
        }

        /* register process */
        proc->last_used = srv->cur_ts;
        proc->is_local = 1;

        /* wait */
        select(0, NULL, NULL, NULL, &tv);

        if (0 != gw_proc_waitpid(srv, host, proc)) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "gw-backend failed to start:", host->bin_path);
            log_error_write(srv, __FILE__, __LINE__, "s",
              "If you're trying to run your app as a FastCGI backend, make "
              "sure you're using the FastCGI-enabled version.  If this is PHP "
              "on Gentoo, add 'fastcgi' to the USE flags.  If this is PHP, try "
              "removing the bytecode caches for now and try again.");
            return -1;
        }
    } else {
        proc->is_local = 0;
        proc->pid = 0;

        if (debug) {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "(debug) socket is already used; won't spawn:",
                            proc->connection_name);
        }
    }

    gw_proc_set_state(host, proc, PROC_STATE_RUNNING);
    return 0;
}

static void gw_proc_spawn(server *srv, gw_host *host, int debug) {
    gw_proc *proc;
    for (proc = host->unused_procs; proc; proc = proc->next) {
        /* (proc->pid <= 0 indicates PROC_STATE_DIED, not PROC_STATE_KILLED) */
        if (proc->pid > 0) continue;
        /* (do not attempt to spawn another proc if a proc just exited) */
        if (proc->disabled_until >= srv->cur_ts) return;
        break;
    }
    if (proc) {
        if (proc == host->unused_procs)
            host->unused_procs = proc->next;
        else
            proc->prev->next = proc->next;

        if (proc->next) {
            proc->next->prev = proc->prev;
            proc->next = NULL;
        }

        proc->prev = NULL;
    } else {
        proc = gw_proc_init();
        proc->id = host->max_id++;
    }

    ++host->num_procs;

    if (buffer_string_is_empty(host->unixsocket)) {
        proc->port = host->port + proc->id;
    } else {
        buffer_copy_buffer(proc->unixsocket, host->unixsocket);
        buffer_append_string_len(proc->unixsocket, CONST_STR_LEN("-"));
        buffer_append_int(proc->unixsocket, proc->id);
    }

    if (0 != gw_proc_sockaddr_init(srv, host, proc)) {
        /*(should not happen if host->host validated at startup,
         * and translated from name to IP address at startup)*/
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "ERROR: spawning backend failed.");
        --host->num_procs;
        if (proc->id == host->max_id-1) --host->max_id;
        gw_proc_free(proc);
    } else if (gw_spawn_connection(srv, host, proc, debug)) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "ERROR: spawning backend failed.");
        proc->next = host->unused_procs;
        if (host->unused_procs)
            host->unused_procs->prev = proc;
        host->unused_procs = proc;
    } else {
        proc->next = host->first;
        if (host->first)
            host->first->prev = proc;
        host->first = proc;
    }
}

static void gw_proc_kill(server *srv, gw_host *host, gw_proc *proc) {
    UNUSED(srv);
    if (proc->next) proc->next->prev = proc->prev;
    if (proc->prev) proc->prev->next = proc->next;

    if (proc->prev == NULL) host->first = proc->next;

    proc->prev = NULL;
    proc->next = host->unused_procs;
    proc->disabled_until = 0;

    if (host->unused_procs)
        host->unused_procs->prev = proc;
    host->unused_procs = proc;

    kill(proc->pid, SIGTERM);

    gw_proc_set_state(host, proc, PROC_STATE_KILLED);

    --host->num_procs;
}

static gw_host * unixsocket_is_dup(gw_plugin_data *p, size_t used, buffer *unixsocket) {
    for (size_t i = 0; i < used; ++i) {
        gw_exts *exts = p->config_storage[i]->exts;
        if (NULL == exts) continue;
        for (size_t j = 0; j < exts->used; ++j) {
            gw_extension *ex = exts->exts[j];
            for (size_t n = 0; n < ex->used; ++n) {
                gw_host *host = ex->hosts[n];
                if (!buffer_string_is_empty(host->unixsocket)
                    && buffer_is_equal(host->unixsocket, unixsocket)
                    && !buffer_string_is_empty(host->bin_path))
                    return host;
            }
        }
    }

    return NULL;
}

static int parse_binpath(char_array *env, buffer *b) {
    char *start = b->ptr;
    char c;
    /* search for spaces */
    for (size_t i = 0; i < buffer_string_length(b); ++i) {
        switch(b->ptr[i]) {
        case ' ':
        case '\t':
            /* a WS, stop here and copy the argument */

            if (env->size == 0) {
                env->size = 16;
                env->ptr = malloc(env->size * sizeof(*env->ptr));
            } else if (env->size == env->used) {
                env->size += 16;
                env->ptr = realloc(env->ptr, env->size * sizeof(*env->ptr));
            }

            c = b->ptr[i];
            b->ptr[i] = '\0';
            env->ptr[env->used++] = strdup(start);
            b->ptr[i] = c;

            start = b->ptr + i + 1;
            break;
        default:
            break;
        }
    }

    if (env->size == 0) {
        env->size = 16;
        env->ptr = malloc(env->size * sizeof(*env->ptr));
    } else if (env->size == env->used) { /*need one extra for terminating NULL*/
        env->size += 16;
        env->ptr = realloc(env->ptr, env->size * sizeof(*env->ptr));
    }

    /* the rest */
    env->ptr[env->used++] = strdup(start);

    if (env->size == 0) {
        env->size = 16;
        env->ptr = malloc(env->size * sizeof(*env->ptr));
    } else if (env->size == env->used) { /*need one extra for terminating NULL*/
        env->size += 16;
        env->ptr = realloc(env->ptr, env->size * sizeof(*env->ptr));
    }

    /* terminate */
    env->ptr[env->used++] = NULL;

    return 0;
}

enum {
  GW_BALANCE_LEAST_CONNECTION,
  GW_BALANCE_RR,
  GW_BALANCE_HASH,
  GW_BALANCE_STICKY
};

static gw_host * gw_host_get(server *srv, connection *con, gw_extension *extension, int balance, int debug) {
    gw_host *host;
    unsigned long last_max = ULONG_MAX;
    int max_usage = INT_MAX;
    int ndx = -1;
    size_t k;

    if (extension->used <= 1) {
        if (1 == extension->used && extension->hosts[0]->active_procs > 0) {
            ndx = 0;
        }
    } else switch(balance) {
    case GW_BALANCE_HASH:
        /* hash balancing */

        if (debug) {
            log_error_write(srv, __FILE__, __LINE__,  "sd",
                            "proxy - used hash balancing, hosts:",
                            extension->used);
        }

        for (k = 0, ndx = -1, last_max = ULONG_MAX; k < extension->used; ++k) {
            unsigned long cur_max;
            host = extension->hosts[k];
            if (0 == host->active_procs) continue;

            cur_max = generate_crc32c(CONST_BUF_LEN(con->uri.path))
                    + generate_crc32c(CONST_BUF_LEN(host->host)) /* cachable */
                    + generate_crc32c(CONST_BUF_LEN(con->uri.authority));

            if (debug) {
                log_error_write(srv, __FILE__, __LINE__,  "sbbbd",
                                "proxy - election:", con->uri.path,
                                host->host, con->uri.authority, cur_max);
            }

            if (last_max < cur_max || last_max == ULONG_MAX) {
                last_max = cur_max;
                ndx = k;
            }
        }

        break;
    case GW_BALANCE_LEAST_CONNECTION:
        /* fair balancing */
        if (debug) {
            log_error_write(srv, __FILE__, __LINE__,  "s",
                            "proxy - used least connection");
        }

        for (k = 0, ndx = -1, max_usage = INT_MAX; k < extension->used; ++k) {
            host = extension->hosts[k];
            if (0 == host->active_procs) continue;

            if (host->load < max_usage) {
                max_usage = host->load;
                ndx = k;
            }
        }

        break;
    case GW_BALANCE_RR:
        /* round robin */
        if (debug) {
            log_error_write(srv, __FILE__, __LINE__,  "s",
                            "proxy - used round-robin balancing");
        }

        /* just to be sure */
        force_assert(extension->used < INT_MAX);

        host = extension->hosts[0];

        /* Use last_used_ndx from first host in list */
        k = extension->last_used_ndx;
        ndx = k + 1; /* use next host after the last one */
        if (ndx < 0) ndx = 0;

        /* Search first active host after last_used_ndx */
        while (ndx < (int) extension->used
               && 0 == (host = extension->hosts[ndx])->active_procs) ++ndx;

        if (ndx >= (int) extension->used) {
            /* didn't find a higher id, wrap to the start */
            for (ndx = 0; ndx <= (int) k; ++ndx) {
                host = extension->hosts[ndx];
                if (0 != host->active_procs) break;
            }

            /* No active host found */
            if (0 == host->active_procs) ndx = -1;
        }

        /* Save new index for next round */
        extension->last_used_ndx = ndx;

        break;
    case GW_BALANCE_STICKY:
        /* source sticky balancing */

        if (debug) {
            log_error_write(srv, __FILE__, __LINE__,  "sd",
                            "proxy - used sticky balancing, hosts:",
                            extension->used);
        }

        for (k = 0, ndx = -1, last_max = ULONG_MAX; k < extension->used; ++k) {
            unsigned long cur_max;
            host = extension->hosts[k];

            if (0 == host->active_procs) continue;

            cur_max = generate_crc32c(CONST_BUF_LEN(con->dst_addr_buf))
                    + generate_crc32c(CONST_BUF_LEN(host->host))
                    + host->port;

            if (debug) {
                log_error_write(srv, __FILE__, __LINE__,  "sbbdd",
                                "proxy - election:", con->dst_addr_buf,
                                host->host, host->port, cur_max);
            }

            if (last_max < cur_max || last_max == ULONG_MAX) {
                last_max = cur_max;
                ndx = k;
            }
        }

        break;
    default:
        break;
    }

    if (-1 != ndx) {
        /* found a server */
        host = extension->hosts[ndx];

        if (debug) {
            log_error_write(srv, __FILE__, __LINE__,  "sbd",
                            "gw - found a host", host->host, host->port);
        }

        return host;
    } else if (0 == srv->srvconf.max_worker) {
        /* special-case adaptive spawning and 0 == host->min_procs */
        for (k = 0; k < extension->used; ++k) {
            host = extension->hosts[k];
            if (0 == host->min_procs && 0 == host->num_procs
                && !buffer_string_is_empty(host->bin_path)) {
                gw_proc_spawn(srv, host, debug);
                if (host->num_procs) return host;
            }
        }
    }

    /* all hosts are down */
    /* sorry, we don't have a server alive for this ext */
    con->http_status = 503; /* Service Unavailable */
    con->mode = DIRECT;

    /* only send the 'no handler' once */
    if (!extension->note_is_sent) {
        extension->note_is_sent = 1;
        log_error_write(srv, __FILE__, __LINE__, "sBSbsbs",
                        "all handlers for", con->uri.path, "?",
                        con->uri.query, "on", extension->key, "are down.");
    }

    return NULL;
}

static int gw_establish_connection(server *srv, gw_host *host, gw_proc *proc, pid_t pid, int gw_fd, int debug) {
    if (-1 == connect(gw_fd, proc->saddr, proc->saddrlen)) {
        if (errno == EINPROGRESS ||
            errno == EALREADY ||
            errno == EINTR) {
            if (debug > 2) {
                log_error_write(srv, __FILE__, __LINE__, "sb",
                                "connect delayed; will continue later:",
                                proc->connection_name);
            }

            return 1;
        } else {
            gw_proc_connect_error(srv, host, proc, pid, errno, debug);
            return -1;
        }
    }

    if (debug > 1) {
        log_error_write(srv, __FILE__, __LINE__, "sd",
                        "connect succeeded: ", gw_fd);
    }

    return 0;
}

static void gw_restart_dead_procs(server *srv, gw_host *host, int debug) {
    for (gw_proc *proc = host->first; proc; proc = proc->next) {
        if (debug > 2) {
            log_error_write(srv, __FILE__, __LINE__,  "sbdddd",
                            "proc:", proc->connection_name, proc->state,
                            proc->is_local, proc->load, proc->pid);
        }

        switch (proc->state) {
        case PROC_STATE_RUNNING:
            break;
        case PROC_STATE_OVERLOADED:
            gw_proc_check_enable(srv, host, proc);
            break;
        case PROC_STATE_KILLED:
            break;
        case PROC_STATE_DIED_WAIT_FOR_PID:
            /*(state should not happen in workers if server.max-worker > 0)*/
            /*(if PROC_STATE_DIED_WAIT_FOR_PID is used in future, might want
             * to save proc->disabled_until before gw_proc_waitpid() since
             * gw_proc_waitpid will set proc->disabled_until to srv->cur_ts,
             * and so process will not be restarted below until one sec later)*/
            if (0 == gw_proc_waitpid(srv, host, proc)) {
                gw_proc_check_enable(srv, host, proc);
            }

            if (proc->state != PROC_STATE_DIED) break;
            /* fall through *//*(we have a dead proc now)*/

        case PROC_STATE_DIED:
            /* local procs get restarted by us,
             * remote ones hopefully by the admin */

            if (!buffer_string_is_empty(host->bin_path)) {
                /* we still have connections bound to this proc,
                 * let them terminate first */
                if (proc->load != 0) break;

                /* avoid spinning if child exits too quickly */
                if (proc->disabled_until >= srv->cur_ts) break;

                /* restart the child */

                if (debug) {
                    log_error_write(srv, __FILE__, __LINE__, "ssbsdsd",
                                    "--- gw spawning",
                                    "\n\tsocket", proc->connection_name,
                                    "\n\tcurrent:", 1, "/", host->max_procs);
                }

                if (gw_spawn_connection(srv, host, proc, debug)) {
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "ERROR: spawning gw failed.");
                }
            } else {
                gw_proc_check_enable(srv, host, proc);
            }
            break;
        }
    }
}




#include "base.h"
#include "connections.h"
#include "joblist.h"
#include "keyvalue.h"
#include "plugin.h"
#include "response.h"


/* ok, we need a prototype */
static handler_t gw_handle_fdevent(server *srv, void *ctx, int revents);


static gw_handler_ctx * handler_ctx_init(size_t sz) {
    gw_handler_ctx *hctx = calloc(1, 0 == sz ? sizeof(*hctx) : sz);
    force_assert(hctx);

    hctx->fde_ndx = -1;

    /*hctx->response = buffer_init();*//*(allocated when needed)*/

    hctx->request_id = 0;
    hctx->gw_mode = GW_RESPONDER;
    hctx->state = GW_STATE_INIT;
    hctx->proc = NULL;

    hctx->fd = -1;

    hctx->reconnects = 0;
    hctx->send_content_body = 1;

    /*hctx->rb = chunkqueue_init();*//*(allocated when needed)*/
    hctx->wb = chunkqueue_init();
    hctx->wb_reqlen = 0;

    return hctx;
}

static void handler_ctx_free(gw_handler_ctx *hctx) {
    /* caller MUST have called gw_backend_close(srv, hctx) if necessary */
    if (hctx->handler_ctx_free) hctx->handler_ctx_free(hctx);
    buffer_free(hctx->response);

    chunkqueue_free(hctx->rb);
    chunkqueue_free(hctx->wb);

    free(hctx);
}

static void handler_ctx_clear(gw_handler_ctx *hctx) {
    /* caller MUST have called gw_backend_close(srv, hctx) if necessary */

    hctx->proc = NULL;
    hctx->host = NULL;
    hctx->ext  = NULL;
    /*hctx->ext_auth is intentionally preserved to flag prior authorizer*/

    hctx->gw_mode = GW_RESPONDER;
    hctx->state = GW_STATE_INIT;
    /*hctx->state_timestamp = 0;*//*(unused; left as-is)*/

    if (hctx->rb) chunkqueue_reset(hctx->rb);
    if (hctx->wb) chunkqueue_reset(hctx->wb);
    hctx->wb_reqlen = 0;

    buffer_reset(hctx->response);

    hctx->fd = -1;
    hctx->fde_ndx = -1;
    hctx->reconnects = 0;
    hctx->request_id = 0;
    hctx->send_content_body = 1;

    /*plugin_config conf;*//*(no need to reset for same request)*/

    /*hctx->remote_conn = NULL;*//*(no need to reset for same request)*/
    /*hctx->plugin_data = NULL;*//*(no need to reset for same request)*/
}


void * gw_init(void) {
    return calloc(1, sizeof(gw_plugin_data));
}


void gw_plugin_config_free(gw_plugin_config *s) {
    gw_exts *exts = s->exts;
    if (exts) {
        for (size_t j = 0; j < exts->used; ++j) {
            gw_extension *ex = exts->exts[j];
            for (size_t n = 0; n < ex->used; ++n) {
                gw_proc *proc;
                gw_host *host = ex->hosts[n];

                for (proc = host->first; proc; proc = proc->next) {
                    if (proc->pid > 0) {
                        kill(proc->pid, host->kill_signal);
                    }

                    if (proc->is_local &&
                        !buffer_string_is_empty(proc->unixsocket)) {
                        unlink(proc->unixsocket->ptr);
                    }
                }

                for (proc = host->unused_procs; proc; proc = proc->next) {
                    if (proc->pid > 0) {
                        kill(proc->pid, host->kill_signal);
                    }
                    if (proc->is_local &&
                        !buffer_string_is_empty(proc->unixsocket)) {
                        unlink(proc->unixsocket->ptr);
                    }
                }
            }
        }

        gw_extensions_free(s->exts);
        gw_extensions_free(s->exts_auth);
        gw_extensions_free(s->exts_resp);
    }
    array_free(s->ext_mapping);
    free(s);
}

handler_t gw_free(server *srv, void *p_d) {
    gw_plugin_data *p = p_d;
    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; ++i) {
            gw_plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;
            gw_plugin_config_free(s);
        }
        free(p->config_storage);
    }
    free(p);
    return HANDLER_GO_ON;
}

int gw_set_defaults_backend(server *srv, gw_plugin_data *p, data_unset *du, size_t i, int sh_exec) {
    /* per-module plugin_config MUST have common "base class" gw_plugin_config*/
    /* per-module plugin_data MUST have pointer-compatible common "base class"
     * with gw_plugin_data (stemming from gw_plugin_config compatibility) */

    data_array *da = (data_array *)du;
    gw_plugin_config *s = p->config_storage[i];
    buffer *gw_mode;
    gw_host *host = NULL;

    if (NULL == da) return 1;

    if (da->type != TYPE_ARRAY || !array_is_kvarray(da->value)) {
        log_error_write(srv, __FILE__, __LINE__, "s",
          "unexpected value for xxxxx.server; expected "
          "( \"ext\" => ( \"backend-label\" => ( \"key\" => \"value\" )))");
        return 0;
    }

    p->srv_pid = srv->pid;

    gw_mode = buffer_init();

    s->exts      = gw_extensions_init();
    s->exts_auth = gw_extensions_init();
    s->exts_resp = gw_extensions_init();
    /*s->balance = GW_BALANCE_LEAST_CONNECTION;*//*(default)*/

    /*
     * gw.server = ( "<ext>" => ( ... ),
     *               "<ext>" => ( ... ) )
     */

    for (size_t j = 0; j < da->value->used; ++j) {
        data_array *da_ext = (data_array *)da->value->data[j];

        /*
         * da_ext->key == name of the extension
         */

        /*
         * gw.server = ( "<ext>" =>
         *                     ( "<host>" => ( ... ),
         *                       "<host>" => ( ... )
         *                     ),
         *               "<ext>" => ... )
         */

        for (size_t n = 0; n < da_ext->value->used; ++n) {
            data_array *da_host = (data_array *)da_ext->value->data[n];

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

                { "broken-scriptfilename", NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },  /* 14 */
                { "allow-x-send-file",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },     /* 15 */
                { "strip-request-uri",  NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },      /* 16 */
                { "kill-signal",        NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 17 */
                { "fix-root-scriptname",   NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },  /* 18 */
                { "listen-backlog",    NULL, T_CONFIG_INT,   T_CONFIG_SCOPE_CONNECTION },        /* 19 */
                { "x-sendfile",        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },      /* 20 */
                { "x-sendfile-docroot",NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },       /* 21 */

                { NULL,                NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
            };
            unsigned short host_mode = GW_RESPONDER;

            if (da_host->type != TYPE_ARRAY || !array_is_kvany(da_host->value)){
                log_error_write(srv, __FILE__, __LINE__, "SBS",
                  "unexpected value for gw.server near [",
                  da_host->key, "](string); expected ( \"ext\" => ( \"backend-label\" => ( \"key\" => \"value\" )))");

                goto error;
            }

            host = gw_host_init();
            buffer_reset(gw_mode);

            buffer_copy_buffer(host->id, da_host->key);

            host->check_local  = 1;
            host->min_procs    = 4;
            host->max_procs    = 4;
            host->max_load_per_proc = 1;
            host->idle_timeout = 60;
            host->disable_time = 1;
            host->break_scriptfilename_for_php = 0;
            host->kill_signal = SIGTERM;
            host->fix_root_path_name = 0;
            host->listen_backlog = 1024;
            host->xsendfile_allow = 0;
            host->refcount = 0;

            fcv[0].destination = host->host;
            fcv[1].destination = host->docroot;
            fcv[2].destination = gw_mode;
            fcv[3].destination = host->unixsocket;
            fcv[4].destination = host->bin_path;

            fcv[5].destination = &(host->check_local);
            fcv[6].destination = &(host->port);
            fcv[7].destination = &(host->min_procs);
            fcv[8].destination = &(host->max_procs);
            fcv[9].destination = &(host->max_load_per_proc);
            fcv[10].destination = &(host->idle_timeout);
            fcv[11].destination = &(host->disable_time);

            fcv[12].destination = host->bin_env;
            fcv[13].destination = host->bin_env_copy;
            fcv[14].destination = &(host->break_scriptfilename_for_php);
            fcv[15].destination = &(host->xsendfile_allow);
            fcv[16].destination = host->strip_request_uri;
            fcv[17].destination = &(host->kill_signal);
            fcv[18].destination = &(host->fix_root_path_name);
            fcv[19].destination = &(host->listen_backlog);
            fcv[20].destination = &(host->xsendfile_allow);
            fcv[21].destination = host->xsendfile_docroot;

            if (0 != config_insert_values_internal(srv, da_host->value, fcv, T_CONFIG_SCOPE_CONNECTION)) {
                goto error;
            }

            for (size_t m = 0; m < da_host->value->used; ++m) {
                if (NULL != strchr(da_host->value->data[m]->key->ptr, '_')) {
                    log_error_write(srv, __FILE__, __LINE__, "sb",
                      "incorrect directive contains underscore ('_') instead of dash ('-'):",
                      da_host->value->data[m]->key);
                }
            }

            if ((!buffer_string_is_empty(host->host) || host->port)
                && !buffer_string_is_empty(host->unixsocket)) {
                log_error_write(srv, __FILE__, __LINE__, "sbsbsbs",
                  "either host/port or socket have to be set in:",
                  da->key, "= (",
                  da_ext->key, " => (",
                  da_host->key, " ( ...");

                goto error;
            }

            if (!buffer_string_is_empty(host->host) && *host->host->ptr == '/'
                && buffer_string_is_empty(host->unixsocket)) {
                buffer_copy_buffer(host->unixsocket, host->host);
            }

            if (!buffer_string_is_empty(host->unixsocket)) {
                /* unix domain socket */
                struct sockaddr_un un;

                if (buffer_string_length(host->unixsocket) + 1 > sizeof(un.sun_path) - 2) {
                    log_error_write(srv, __FILE__, __LINE__, "sbsbsbs",
                            "unixsocket is too long in:",
                            da->key, "= (",
                            da_ext->key, " => (",
                            da_host->key, " ( ...");

                    goto error;
                }

                if (!buffer_string_is_empty(host->bin_path)) {
                    gw_host *duplicate = unixsocket_is_dup(p, i+1, host->unixsocket);
                    if (NULL != duplicate) {
                        if (!buffer_is_equal(host->bin_path, duplicate->bin_path)) {
                            log_error_write(srv, __FILE__, __LINE__, "sb",
                                "duplicate unixsocket path:",
                                host->unixsocket);
                            goto error;
                        }
                        gw_host_free(host);
                        host = duplicate;
                        ++host->refcount;
                    }
                }

                host->family = AF_UNIX;
            } else {
                /* tcp/ip */

                if (buffer_string_is_empty(host->host) &&
                    buffer_string_is_empty(host->bin_path)) {
                    log_error_write(srv, __FILE__, __LINE__, "sbsbsbs",
                            "host or binpath have to be set in:",
                            da->key, "= (",
                            da_ext->key, " => (",
                            da_host->key, " ( ...");

                    goto error;
                } else if (0 == host->port) {
                    host->port = 80;
                }

                host->family = (!buffer_string_is_empty(host->host)
                                && NULL != strchr(host->host->ptr, ':'))
                  ? AF_INET6
                  : AF_INET;
            }

            if (host->refcount) {
                /* already init'd; skip spawning */
            } else if (!buffer_string_is_empty(host->bin_path)) {
                /* a local socket + self spawning */
                struct stat st;
                parse_binpath(&host->args, host->bin_path);
                if (0 != stat(host->args.ptr[0], &st) || !S_ISREG(st.st_mode)
                    || !(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
                    log_error_write(srv, __FILE__, __LINE__, "SSs",
                      "invalid \"bin-path\" => \"", host->bin_path->ptr,
                      "\" (check that file exists, is regular file, "
                      "and is executable by lighttpd)");
                }

                if (sh_exec) {
                    /*(preserve prior behavior for SCGI exec of command)*/
                    /*(admin should really prefer to put
                     * any complex command into a script)*/
                    for (size_t m = 0; m < host->args.used; ++m)
                        free(host->args.ptr[m]);
                    free(host->args.ptr);

                    host->args.ptr = calloc(4, sizeof(char *));
                    force_assert(host->args.ptr);
                    host->args.used = 3;
                    host->args.size = 4;
                    host->args.ptr[0] = malloc(sizeof("/bin/sh"));
                    force_assert(host->args.ptr[0]);
                    memcpy(host->args.ptr[0], "/bin/sh", sizeof("/bin/sh"));
                    host->args.ptr[1] = malloc(sizeof("-c"));
                    force_assert(host->args.ptr[1]);
                    memcpy(host->args.ptr[1], "-c", sizeof("-c"));
                    host->args.ptr[2] =
                      malloc(sizeof("exec ")-1
                             + buffer_string_length(host->bin_path) + 1);
                    force_assert(host->args.ptr[2]);
                    memcpy(host->args.ptr[2], "exec ", sizeof("exec ")-1);
                    memcpy(host->args.ptr[2]+sizeof("exec ")-1,
                           host->bin_path->ptr,
                           buffer_string_length(host->bin_path)+1);
                    host->args.ptr[3] = NULL;
                }

                if (host->min_procs > host->max_procs)
                    host->min_procs = host->max_procs;
                if (host->min_procs!= host->max_procs
                    && 0 != srv->srvconf.max_worker) {
                    host->min_procs = host->max_procs;
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "adaptive backend spawning disabled "
                                    "(server.max_worker is non-zero)");
                }
                if (host->max_load_per_proc < 1)
                    host->max_load_per_proc = 0;

                if (s->debug) {
                    log_error_write(srv, __FILE__, __LINE__, "ssbsdsbsdsd",
                                    "--- gw spawning local",
                                    "\n\tproc:", host->bin_path,
                                    "\n\tport:", host->port,
                                    "\n\tsocket", host->unixsocket,
                                    "\n\tmin-procs:", host->min_procs,
                                    "\n\tmax-procs:", host->max_procs);
                }

                for (size_t pno = 0; pno < host->min_procs; ++pno) {
                    gw_proc *proc = gw_proc_init();
                    proc->id = host->num_procs++;
                    host->max_id++;

                    if (buffer_string_is_empty(host->unixsocket)) {
                        proc->port = host->port + pno;
                    } else {
                        buffer_copy_buffer(proc->unixsocket, host->unixsocket);
                        buffer_append_string_len(proc->unixsocket,
                                                 CONST_STR_LEN("-"));
                        buffer_append_int(proc->unixsocket, pno);
                    }

                    if (s->debug) {
                        log_error_write(srv, __FILE__, __LINE__, "ssdsbsdsd",
                          "--- gw spawning",
                          "\n\tport:", host->port,
                          "\n\tsocket", host->unixsocket,
                          "\n\tcurrent:", pno, "/", host->max_procs);
                    }

                    if (0 != gw_proc_sockaddr_init(srv, host, proc)) {
                        gw_proc_free(proc);
                        goto error;
                    }

                    if (!srv->srvconf.preflight_check
                        && gw_spawn_connection(srv, host, proc, s->debug)) {
                        log_error_write(srv, __FILE__, __LINE__, "s",
                                        "[ERROR]: spawning gw failed.");
                        gw_proc_free(proc);
                        goto error;
                    }

                    gw_status_init(srv, host, proc);

                    proc->next = host->first;
                    if (host->first) host->first->prev = proc;

                    host->first = proc;
                }
            } else {
                gw_proc *proc;

                proc = gw_proc_init();
                proc->id = host->num_procs++;
                host->max_id++;
                gw_proc_set_state(host, proc, PROC_STATE_RUNNING);

                if (buffer_string_is_empty(host->unixsocket)) {
                    proc->port = host->port;
                } else {
                    buffer_copy_buffer(proc->unixsocket, host->unixsocket);
                }

                gw_status_init(srv, host, proc);

                host->first = proc;

                host->min_procs = 1;
                host->max_procs = 1;

                if (0 != gw_proc_sockaddr_init(srv, host, proc)) goto error;
            }

            if (!buffer_string_is_empty(gw_mode)) {
                if (strcmp(gw_mode->ptr, "responder") == 0) {
                    host_mode = GW_RESPONDER;
                } else if (strcmp(gw_mode->ptr, "authorizer") == 0) {
                    host_mode = GW_AUTHORIZER;
                } else {
                    log_error_write(srv, __FILE__, __LINE__, "sbs",
                                    "WARNING: unknown gw mode:",
                                    gw_mode,"(ignored, mode set to responder)");
                }
            }

            if (host->xsendfile_docroot->used) {
                size_t k;
                for (k = 0; k < host->xsendfile_docroot->used; ++k) {
                    data_string *ds = (data_string *)host->xsendfile_docroot->data[k];
                    if (ds->type != TYPE_STRING) {
                        log_error_write(srv, __FILE__, __LINE__, "s",
                          "unexpected type for x-sendfile-docroot; expected: \"x-sendfile-docroot\" => ( \"/allowed/path\", ... )");
                        goto error;
                    }
                    if (ds->value->ptr[0] != '/') {
                        log_error_write(srv, __FILE__, __LINE__, "SBs",
                          "x-sendfile-docroot paths must begin with '/'; invalid: \"", ds->value, "\"");
                        goto error;
                    }
                    buffer_path_simplify(ds->value, ds->value);
                    buffer_append_slash(ds->value);
                }
            }

            /* s->exts is list of exts -> hosts
             * s->exts now used as combined list
             *   of authorizer and responder hosts (for backend maintenance)
             * s->exts_auth is list of exts -> authorizer hosts
             * s->exts_resp is list of exts -> responder hosts
             * For each path/extension:
             * there may be an independent GW_AUTHORIZER and GW_RESPONDER
             * (The GW_AUTHORIZER and GW_RESPONDER could be handled by the same
             *  host, and an admin might want to do that for large uploads,
             *  since GW_AUTHORIZER runs prior to receiving (potentially large)
             *  request body from client and can authorizer or deny request
             *  prior to receiving the full upload)
             */
            gw_extension_insert(s->exts, da_ext->key, host);

            if (host_mode == GW_AUTHORIZER) {
                ++host->refcount;
                gw_extension_insert(s->exts_auth, da_ext->key, host);
            } else if (host_mode == GW_RESPONDER) {
                ++host->refcount;
                gw_extension_insert(s->exts_resp, da_ext->key, host);
            } /*(else should have been rejected above)*/

            host = NULL;
        }
    }

    buffer_free(gw_mode);
    return 1;

error:
    if (NULL != host) gw_host_free(host);
    buffer_free(gw_mode);
    return 0;
}

int gw_set_defaults_balance(server *srv, gw_plugin_config *s, data_unset *du) {
    buffer *b;
    if (NULL == du) {
        b = NULL;
    } else if (du->type == TYPE_STRING) {
        b = ((data_string *)du)->value;
    } else {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "unexpected type for xxxxx.balance; expected string");
        return 0;
    }
    if (buffer_string_is_empty(b)) {
        s->balance = GW_BALANCE_LEAST_CONNECTION;
    } else if (buffer_is_equal_string(b, CONST_STR_LEN("fair"))) {
        s->balance = GW_BALANCE_LEAST_CONNECTION;
    } else if (buffer_is_equal_string(b, CONST_STR_LEN("least-connection"))) {
        s->balance = GW_BALANCE_LEAST_CONNECTION;
    } else if (buffer_is_equal_string(b, CONST_STR_LEN("round-robin"))) {
        s->balance = GW_BALANCE_RR;
    } else if (buffer_is_equal_string(b, CONST_STR_LEN("hash"))) {
        s->balance = GW_BALANCE_HASH;
    } else if (buffer_is_equal_string(b, CONST_STR_LEN("sticky"))) {
        s->balance = GW_BALANCE_STICKY;
    } else {
        log_error_write(srv, __FILE__, __LINE__, "sb",
                        "xxxxx.balance has to be one of: "
                        "least-connection, round-robin, hash, sticky, but not:",
                        b);
        return 0;
    }
    return 1;
}

static void gw_set_state(server *srv, gw_handler_ctx *hctx, gw_connection_state_t state) {
    hctx->state = state;
    hctx->state_timestamp = srv->cur_ts;
}


void gw_set_transparent(server *srv, gw_handler_ctx *hctx) {
    if (AF_UNIX != hctx->host->family) {
        if (-1 == fdevent_set_tcp_nodelay(hctx->fd, 1)) {
            /*(error, but not critical)*/
        }
    }
    hctx->wb_reqlen = -1;
    gw_set_state(srv, hctx, GW_STATE_WRITE);
}


static void gw_backend_close(server *srv, gw_handler_ctx *hctx) {
    if (hctx->fd >= 0) {
        fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
        /*fdevent_unregister(srv->ev, hctx->fd);*//*(handled below)*/
        fdevent_sched_close(srv->ev, hctx->fd, 1);
        hctx->fd = -1;
        hctx->fde_ndx = -1;
    }

    if (hctx->host) {
        if (hctx->proc) {
            gw_proc_release(srv, hctx->host, hctx->proc, hctx->conf.debug);
            hctx->proc = NULL;
        }

        gw_host_reset(srv, hctx->host);
        hctx->host = NULL;
    }
}

static void gw_connection_close(server *srv, gw_handler_ctx *hctx) {
    gw_plugin_data *p = hctx->plugin_data;
    connection *con = hctx->remote_conn;

    gw_backend_close(srv, hctx);
    handler_ctx_free(hctx);
    con->plugin_ctx[p->id] = NULL;

    if (con->mode == p->id) {
        http_response_backend_done(srv, con);
    }
}

static handler_t gw_reconnect(server *srv, gw_handler_ctx *hctx) {
    gw_backend_close(srv, hctx);

    hctx->host = gw_host_get(srv, hctx->remote_conn, hctx->ext,
                             hctx->conf.balance, hctx->conf.debug);
    if (NULL == hctx->host) return HANDLER_FINISHED;

    gw_host_assign(srv, hctx->host);
    hctx->request_id = 0;
    hctx->opts.xsendfile_allow = hctx->host->xsendfile_allow;
    hctx->opts.xsendfile_docroot = hctx->host->xsendfile_docroot;
    gw_set_state(srv, hctx, GW_STATE_INIT);
    return HANDLER_COMEBACK;
}


handler_t gw_connection_reset(server *srv, connection *con, void *p_d) {
    gw_plugin_data *p = p_d;
    gw_handler_ctx *hctx = con->plugin_ctx[p->id];
    if (hctx) gw_connection_close(srv, hctx);

    return HANDLER_GO_ON;
}


static handler_t gw_write_request(server *srv, gw_handler_ctx *hctx) {
    switch(hctx->state) {
    case GW_STATE_INIT:
        /* do we have a running process for this host (max-procs) ? */
        hctx->proc = NULL;

        for (gw_proc *proc = hctx->host->first; proc; proc = proc->next) {
             if (proc->state == PROC_STATE_RUNNING) {
                 hctx->proc = proc;
                 break;
             }
        }

        /* all children are dead */
        if (hctx->proc == NULL) {
            return HANDLER_ERROR;
        }

        /* check the other procs if they have a lower load */
        for (gw_proc *proc = hctx->proc->next; proc; proc = proc->next) {
            if (proc->state != PROC_STATE_RUNNING) continue;
            if (proc->load < hctx->proc->load) hctx->proc = proc;
        }

        gw_proc_load_inc(srv, hctx->host, hctx->proc);

        hctx->fd = fdevent_socket_nb_cloexec(hctx->host->family,SOCK_STREAM,0);
        if (-1 == hctx->fd) {
            if (errno == EMFILE || errno == EINTR) {
                log_error_write(srv, __FILE__, __LINE__, "sd",
                                "wait for fd at connection:",
                                hctx->remote_conn->fd);
                return HANDLER_WAIT_FOR_FD;
            }

            log_error_write(srv, __FILE__, __LINE__, "ssdd",
                            "socket failed:", strerror(errno),
                            srv->cur_fds, srv->max_fds);
            return HANDLER_ERROR;
        }

        srv->cur_fds++;

        fdevent_register(srv->ev, hctx->fd, gw_handle_fdevent, hctx);

        if (hctx->proc->is_local) {
            hctx->pid = hctx->proc->pid;
        }

        switch (gw_establish_connection(srv, hctx->host, hctx->proc, hctx->pid,
                                        hctx->fd, hctx->conf.debug)) {
        case 1: /* connection is in progress */
            fdevent_event_set(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
            gw_set_state(srv, hctx, GW_STATE_CONNECT_DELAYED);
            return HANDLER_WAIT_FOR_EVENT;
        case -1:/* connection error */
            return HANDLER_ERROR;
        case 0: /* everything is ok, go on */
            hctx->reconnects = 0;
            break;
        }
        /* fall through */
    case GW_STATE_CONNECT_DELAYED:
        if (hctx->state == GW_STATE_CONNECT_DELAYED) { /*(not GW_STATE_INIT)*/
            int socket_error = fdevent_connect_status(hctx->fd);
            if (socket_error != 0) {
                gw_proc_connect_error(srv, hctx->host, hctx->proc, hctx->pid,
                                      socket_error, hctx->conf.debug);
                return HANDLER_ERROR;
            }
            /* go on with preparing the request */
        }

        gw_proc_connect_success(srv, hctx->host, hctx->proc, hctx->conf.debug);

        gw_set_state(srv, hctx, GW_STATE_PREPARE_WRITE);
        /* fall through */
    case GW_STATE_PREPARE_WRITE:
        /* ok, we have the connection */

        {
            handler_t rc = hctx->create_env(srv, hctx);
            if (HANDLER_GO_ON != rc) {
                if (HANDLER_FINISHED != rc && HANDLER_ERROR != rc)
                    fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd,
                                      FDEVENT_OUT);
                return rc;
            }
        }

        /*(disable Nagle algorithm if streaming and content-length unknown)*/
        if (AF_UNIX != hctx->host->family) {
            connection *con = hctx->remote_conn;
            if (-1 == con->request.content_length) {
                if (-1 == fdevent_set_tcp_nodelay(hctx->fd, 1)) {
                    /*(error, but not critical)*/
                }
            }
        }

        fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
        gw_set_state(srv, hctx, GW_STATE_WRITE);
        /* fall through */
    case GW_STATE_WRITE:
        if (!chunkqueue_is_empty(hctx->wb)) {
            connection *con = hctx->remote_conn;
            int ret;
          #if 0
            if (hctx->conf.debug > 1) {
                log_error_write(srv, __FILE__, __LINE__, "sdsx",
                                "send data to backend ( fd =", hctx->fd,
                                "), size =", chunkqueue_length(hctx->wb));
            }
          #endif
            ret = srv->network_backend_write(srv, con, hctx->fd, hctx->wb,
                                             MAX_WRITE_LIMIT);

            chunkqueue_remove_finished_chunks(hctx->wb);

            if (ret < 0) {
                switch(errno) {
                case EPIPE:
                case ENOTCONN:
                case ECONNRESET:
                    /* the connection got dropped after accept()
                     * we don't care about that --
                     * if you accept() it, you have to handle it.
                     */
                    log_error_write(srv, __FILE__, __LINE__, "ssosb",
                                    "connection was dropped after accept() "
                                    "(perhaps the gw process died),",
                                    "write-offset:", hctx->wb->bytes_out,
                                    "socket:", hctx->proc->connection_name);
                    return HANDLER_ERROR;
                default:
                    log_error_write(srv, __FILE__, __LINE__, "ssd",
                                    "write failed:", strerror(errno), errno);
                    return HANDLER_ERROR;
                }
            }
        }

        if (hctx->wb->bytes_out == hctx->wb_reqlen) {
            fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
            gw_set_state(srv, hctx, GW_STATE_READ);
        } else {
            off_t wblen = hctx->wb->bytes_in - hctx->wb->bytes_out;
            if ((hctx->wb->bytes_in < hctx->wb_reqlen || hctx->wb_reqlen < 0)
                && wblen < 65536 - 16384) {
                connection *con = hctx->remote_conn;
                /*(con->conf.stream_request_body & FDEVENT_STREAM_REQUEST)*/
                if (!(con->conf.stream_request_body
                      & FDEVENT_STREAM_REQUEST_POLLIN)) {
                    con->conf.stream_request_body |=
                        FDEVENT_STREAM_REQUEST_POLLIN;
                    con->is_readable = 1;/*trigger optimistic read from client*/
                }
            }
            if (0 == wblen) {
                fdevent_event_clr(srv->ev,&hctx->fde_ndx,hctx->fd,FDEVENT_OUT);
            } else {
                fdevent_event_add(srv->ev,&hctx->fde_ndx,hctx->fd,FDEVENT_OUT);
            }
        }

        return HANDLER_WAIT_FOR_EVENT;
    case GW_STATE_READ:
        /* waiting for a response */
        return HANDLER_WAIT_FOR_EVENT;
    default:
        log_error_write(srv, __FILE__, __LINE__, "s", "(debug) unknown state");
        return HANDLER_ERROR;
    }
}

static handler_t gw_write_error(server *srv, gw_handler_ctx *hctx) {
    connection *con = hctx->remote_conn;
    int status = con->http_status;

    if (hctx->state == GW_STATE_INIT ||
        hctx->state == GW_STATE_CONNECT_DELAYED) {

        /* (optimization to detect backend process exit while processing a
         *  large number of ready events; (this block could be removed)) */
        if (0 == srv->srvconf.max_worker)
            gw_restart_dead_procs(srv, hctx->host, hctx->conf.debug);

        /* cleanup this request and let request handler start request again */
        if (hctx->reconnects++ < 5) return gw_reconnect(srv, hctx);
    }

    if (hctx->backend_error) hctx->backend_error(hctx);
    gw_connection_close(srv, hctx);
    con->http_status = (status == 400) ? 400 : 503;
    return HANDLER_FINISHED;
}

static handler_t gw_send_request(server *srv, gw_handler_ctx *hctx) {
    handler_t rc = gw_write_request(srv, hctx);
    return (HANDLER_ERROR != rc) ? rc : gw_write_error(srv, hctx);
}


static handler_t gw_recv_response(server *srv, gw_handler_ctx *hctx);


handler_t gw_handle_subrequest(server *srv, connection *con, void *p_d) {
    gw_plugin_data *p = p_d;
    gw_handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    if (con->mode != p->id) return HANDLER_GO_ON; /* not my job */

    if ((con->conf.stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN)
        && con->file_started) {
        if (chunkqueue_length(con->write_queue) > 65536 - 4096) {
            fdevent_event_clr(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
        }
        else if (!(fdevent_event_get_interest(srv->ev, hctx->fd) & FDEVENT_IN)){
            /* optimistic read from backend */
            handler_t rc;
            rc = gw_recv_response(srv, hctx);        /*(might invalidate hctx)*/
            if (rc != HANDLER_GO_ON) return rc;      /*(unless HANDLER_GO_ON)*/
            fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
        }
    }

    /* (do not receive request body before GW_AUTHORIZER has run or else
     *  the request body is discarded with handler_ctx_clear() after running
     *  the FastCGI Authorizer) */

    if (hctx->gw_mode != GW_AUTHORIZER
        && (0 == hctx->wb->bytes_in
            ? (con->state == CON_STATE_READ_POST || -1 == hctx->wb_reqlen)
            : (hctx->wb->bytes_in < hctx->wb_reqlen || hctx->wb_reqlen < 0))) {
        /* leave excess data in con->request_content_queue, which is
         * buffered to disk if too large and backend can not keep up */
        /*(64k - 4k to attempt to avoid temporary files
         * in conjunction with FDEVENT_STREAM_REQUEST_BUFMIN)*/
        if (hctx->wb->bytes_in - hctx->wb->bytes_out > 65536 - 4096) {
            if (con->conf.stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN) {
                con->conf.stream_request_body &= ~FDEVENT_STREAM_REQUEST_POLLIN;
            }
            if (0 != hctx->wb->bytes_in) return HANDLER_WAIT_FOR_EVENT;
        }
        else {
            handler_t r = connection_handle_read_post_state(srv, con);
            chunkqueue *req_cq = con->request_content_queue;
          #if 0 /*(not reached since we send 411 Length Required below)*/
            if (hctx->wb_reqlen < -1 && con->request.content_length >= 0) {
                /* (completed receiving Transfer-Encoding: chunked) */
                hctx->wb_reqlen= -hctx->wb_reqlen + con->request.content_length;
                if (hctx->stdin_append) {
                    handler_t rc = hctx->stdin_append(srv, hctx);
                    if (HANDLER_GO_ON != rc) return rc;
                }
            }
          #endif
            if ((0 != hctx->wb->bytes_in || -1 == hctx->wb_reqlen)
                && !chunkqueue_is_empty(req_cq)) {
                if (hctx->stdin_append) {
                    handler_t rc = hctx->stdin_append(srv, hctx);
                    if (HANDLER_GO_ON != rc) return rc;
                }
                else
                    chunkqueue_append_chunkqueue(hctx->wb, req_cq);
                if (fdevent_event_get_interest(srv->ev,hctx->fd) & FDEVENT_OUT){
                    return (r == HANDLER_GO_ON) ? HANDLER_WAIT_FOR_EVENT : r;
                }
            }
            if (r != HANDLER_GO_ON) return r;


            /* XXX: create configurable flag */
            /* CGI environment requires that Content-Length be set.
             * Send 411 Length Required if Content-Length missing.
             * (occurs here if client sends Transfer-Encoding: chunked
             *  and module is flagged to stream request body to backend) */
            /* proxy currently sends HTTP/1.0 request and ideally should send
             * Content-Length with request if request body is present, so
             * send 411 Length Required if Content-Length missing. */
            if (-1 == con->request.content_length) {
                return connection_handle_read_post_error(srv, con, 411);
            }
        }
    }

    return ((0 == hctx->wb->bytes_in || !chunkqueue_is_empty(hctx->wb))
        && hctx->state != GW_STATE_CONNECT_DELAYED)
      ? gw_send_request(srv, hctx)
      : HANDLER_WAIT_FOR_EVENT;
}


static handler_t gw_recv_response(server *srv, gw_handler_ctx *hctx) {
    connection *con = hctx->remote_conn;
    gw_proc *proc = hctx->proc;
    gw_host *host = hctx->host;
    /*(XXX: make this a configurable flag for other protocols)*/
    buffer *b = hctx->opts.backend == BACKEND_FASTCGI
      ? buffer_init()
      : hctx->response;

    switch (http_response_read(srv, hctx->remote_conn, &hctx->opts,
                               b, hctx->fd, &hctx->fde_ndx)) {
    default:
        break;
    case HANDLER_FINISHED:
        if (b != hctx->response) buffer_free(b);
        if (hctx->gw_mode == GW_AUTHORIZER
            && (200 == con->http_status || 0 == con->http_status)) {
            /*
             * If we are here in AUTHORIZER mode then a request for authorizer
             * was processed already, and status 200 has been returned. We need
             * now to handle authorized request.
             */
            buffer *physpath = NULL;

            if (!buffer_string_is_empty(host->docroot)) {
                buffer_copy_buffer(con->physical.doc_root, host->docroot);
                buffer_copy_buffer(con->physical.basedir, host->docroot);

                buffer_copy_buffer(con->physical.path, host->docroot);
                buffer_append_string_buffer(con->physical.path, con->uri.path);
                physpath = con->physical.path;
            }

            proc->last_used = srv->cur_ts;
            gw_backend_close(srv, hctx);
            handler_ctx_clear(hctx);

            /* don't do more than 6 loops here; normally shouldn't happen */
            if (++con->loops_per_request > 5) {
                log_error_write(srv, __FILE__, __LINE__, "sb",
                                "too many loops while processing request:",
                                con->request.orig_uri);
                con->http_status = 500; /* Internal Server Error */
                con->mode = DIRECT;
                return HANDLER_FINISHED;
            }

            /* restart the request so other handlers can process it */

            if (physpath) con->physical.path = NULL;
            connection_response_reset(srv,con);/*(includes con->http_status=0)*/
            /* preserve con->physical.path with modified docroot */
            if (physpath) con->physical.path = physpath;

            /*(FYI: if multiple FastCGI authorizers were to be supported,
             * next one could be started here instead of restarting request)*/

            con->mode = DIRECT;
            return HANDLER_COMEBACK;
        } else {
            /* we are done */
            gw_connection_close(srv, hctx);
        }

        return HANDLER_FINISHED;
    case HANDLER_COMEBACK: /*(not expected; treat as error)*/
    case HANDLER_ERROR:
        if (b != hctx->response) buffer_free(b);
        /* (optimization to detect backend process exit while processing a
         *  large number of ready events; (this block could be removed)) */
        if (proc->is_local && 1 == proc->load && proc->pid == hctx->pid
            && proc->state != PROC_STATE_DIED && 0 == srv->srvconf.max_worker) {
            /* intentionally check proc->disabed_until before gw_proc_waitpid */
            if (proc->disabled_until < srv->cur_ts
                && 0 != gw_proc_waitpid(srv, host, proc)) {
                if (hctx->conf.debug) {
                    log_error_write(srv, __FILE__, __LINE__, "ssbsdsd",
                                    "--- gw spawning",
                                    "\n\tsocket", proc->connection_name,
                                    "\n\tcurrent:", 1, "/", host->num_procs);
                }

                if (gw_spawn_connection(srv, host, proc, hctx->conf.debug)) {
                    log_error_write(srv, __FILE__, __LINE__, "s",
                                    "respawning failed, will retry later");
                }
            }
        }

        if (con->file_started == 0) {
            /* nothing has been sent out yet, try to use another child */

            if (hctx->wb->bytes_out == 0 &&
                hctx->reconnects++ < 5) {

                log_error_write(srv, __FILE__, __LINE__, "ssbsBSBs",
                  "response not received, request not sent",
                  "on socket:", proc->connection_name,
                  "for", con->uri.path, "?", con->uri.query, ", reconnecting");

                return gw_reconnect(srv, hctx);
            }

            log_error_write(srv, __FILE__, __LINE__, "sosbsBSBs",
              "response not received, request sent:", hctx->wb->bytes_out,
              "on socket:", proc->connection_name, "for", 
              con->uri.path, "?", con->uri.query, ", closing connection");
        } else {
            log_error_write(srv, __FILE__, __LINE__, "ssbsBSBs",
              "response already sent out, but backend returned error",
              "on socket:", proc->connection_name, "for",
              con->uri.path, "?", con->uri.query, ", terminating connection");
        }

        if (hctx->backend_error) hctx->backend_error(hctx);
        http_response_backend_error(srv, con);
        gw_connection_close(srv, hctx);
        return HANDLER_FINISHED;
    }

    if (b != hctx->response) buffer_free(b);
    return HANDLER_GO_ON;
}


static handler_t gw_handle_fdevent(server *srv, void *ctx, int revents) {
    gw_handler_ctx *hctx = ctx;
    connection *con = hctx->remote_conn;

    joblist_append(srv, con);

    if (revents & FDEVENT_IN) {
        handler_t rc = gw_recv_response(srv, hctx); /*(might invalidate hctx)*/
        if (rc != HANDLER_GO_ON) return rc;         /*(unless HANDLER_GO_ON)*/
    }

    if (revents & FDEVENT_OUT) {
        return gw_send_request(srv, hctx); /*(might invalidate hctx)*/
    }

    /* perhaps this issue is already handled */
    if (revents & FDEVENT_HUP) {
        if (hctx->state == GW_STATE_CONNECT_DELAYED) {
            /* getoptsock will catch this one (right ?)
             *
             * if we are in connect we might get an EINPROGRESS
             * in the first call and an FDEVENT_HUP in the
             * second round
             *
             * FIXME: as it is a bit ugly.
             *
             */
            gw_send_request(srv, hctx);
        } else if (con->file_started) {
            /* drain any remaining data from kernel pipe buffers
             * even if (con->conf.stream_response_body
             *          & FDEVENT_STREAM_RESPONSE_BUFMIN)
             * since event loop will spin on fd FDEVENT_HUP event
             * until unregistered. */
            handler_t rc;
            do {
                rc = gw_recv_response(srv,hctx); /*(might invalidate hctx)*/
            } while (rc == HANDLER_GO_ON);       /*(unless HANDLER_GO_ON)*/
            return rc; /* HANDLER_FINISHED or HANDLER_ERROR */
        } else {
            gw_proc *proc = hctx->proc;
            log_error_write(srv, __FILE__, __LINE__, "sBSbsbsd",
              "error: unexpected close of gw connection for",
              con->uri.path, "?", con->uri.query,
              "(no gw process on socket:", proc->connection_name, "?)",
              hctx->state);

            gw_connection_close(srv, hctx);
        }
    } else if (revents & FDEVENT_ERR) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "gw: got a FDEVENT_ERR. Don't know why.");

        if (hctx->backend_error) hctx->backend_error(hctx);
        http_response_backend_error(srv, con);
        gw_connection_close(srv, hctx);
    }

    return HANDLER_FINISHED;
}

handler_t gw_check_extension(server *srv, connection *con, gw_plugin_data *p, int uri_path_handler, size_t hctx_sz) {
  #if 0 /*(caller must handle)*/
    if (con->mode != DIRECT) return HANDLER_GO_ON;
    gw_patch_connection(srv, con, p);
    if (NULL == p->conf.exts) return HANDLER_GO_ON;
  #endif

    buffer *fn = uri_path_handler ? con->uri.path : con->physical.path;
    size_t s_len = buffer_string_length(fn);
    gw_extension *extension = NULL;
    gw_host *host = NULL;
    gw_handler_ctx *hctx;
    unsigned short gw_mode;

    if (0 == s_len) return HANDLER_GO_ON; /*(not expected)*/

    /* check p->conf.exts_auth list and then p->conf.ext_resp list
     * (skip p->conf.exts_auth if array is empty
     *  or if GW_AUTHORIZER already ran in this request) */
    hctx = con->plugin_ctx[p->id];
    /*(hctx not NULL if GW_AUTHORIZER ran; hctx->ext_auth check is redundant)*/
    gw_mode = (NULL == hctx || NULL == hctx->ext_auth)
      ? 0              /*GW_AUTHORIZER p->conf.exts_auth will be searched next*/
      : GW_AUTHORIZER; /*GW_RESPONDER p->conf.exts_resp will be searched next*/

    do {

        gw_exts *exts;
        if (0 == gw_mode) {
            gw_mode = GW_AUTHORIZER;
            exts = p->conf.exts_auth;
        } else {
            gw_mode = GW_RESPONDER;
            exts = p->conf.exts_resp;
        }

        if (0 == exts->used) continue;

        /* gw.map-extensions maps extensions to existing gw.server entries
         *
         * gw.map-extensions = ( ".php3" => ".php" )
         *
         * gw.server = ( ".php" => ... )
         *
         * */

        /* check if extension-mapping matches */
        if (p->conf.ext_mapping) {
            for (size_t k = 0; k < p->conf.ext_mapping->used; ++k) {
                data_string *ds = (data_string *)p->conf.ext_mapping->data[k];
                size_t ct_len = buffer_string_length(ds->key);
                if (s_len < ct_len) continue;

                /* found a mapping */
                if (0 == memcmp(fn->ptr+s_len-ct_len, ds->key->ptr, ct_len)) {
                    /* check if we know the extension */

                    /* we can reuse k here */
                    for (k = 0; k < exts->used; ++k) {
                        extension = exts->exts[k];

                        if (buffer_is_equal(ds->value, extension->key)) {
                            break;
                        }
                    }

                    if (k == exts->used) {
                        /* found nothing */
                        extension = NULL;
                    }
                    break;
                }
            }
        }

        if (extension == NULL) {
            size_t uri_path_len = buffer_string_length(con->uri.path);

            /* check if extension matches */
            for (size_t k = 0; k < exts->used; ++k) {
                gw_extension *ext = exts->exts[k];
                size_t ct_len = buffer_string_length(ext->key);

                /* check _url_ in the form "/gw_pattern" */
                if (ext->key->ptr[0] == '/') {
                    if (ct_len <= uri_path_len
                        && 0==memcmp(con->uri.path->ptr,ext->key->ptr,ct_len)){
                        extension = ext;
                        break;
                    }
                } else if (ct_len <= s_len
                           && 0 == memcmp(fn->ptr + s_len - ct_len,
                                          ext->key->ptr, ct_len)) {
                    /* check extension in the form ".fcg" */
                    extension = ext;
                    break;
                }
            }
        }

    } while (NULL == extension && gw_mode != GW_RESPONDER);

    /* extension doesn't match */
    if (NULL == extension) {
        return HANDLER_GO_ON;
    }

    /* check if we have at least one server for this extension up and running */
    host = gw_host_get(srv, con, extension, p->conf.balance, p->conf.debug);
    if (NULL == host) {
        return HANDLER_FINISHED;
    }

    /* a note about no handler is not sent yet */
    extension->note_is_sent = 0;

    /*
     * if check-local is disabled, use the uri.path handler
     *
     */

    /* init handler-context */
    if (uri_path_handler) {
        if (host->check_local != 0) {
            return HANDLER_GO_ON;
        } else {
            /* do not split path info for authorizer */
            if (gw_mode != GW_AUTHORIZER) {
                /* the prefix is the SCRIPT_NAME,
                * everything from start to the next slash
                * this is important for check-local = "disable"
                *
                * if prefix = /admin.gw
                *
                * /admin.gw/foo/bar
                *
                * SCRIPT_NAME = /admin.gw
                * PATH_INFO   = /foo/bar
                *
                * if prefix = /cgi-bin/
                *
                * /cgi-bin/foo/bar
                *
                * SCRIPT_NAME = /cgi-bin/foo
                * PATH_INFO   = /bar
                *
                * if prefix = /, and fix-root-path-name is enable
                *
                * /cgi-bin/foo/bar
                *
                * SCRIPT_NAME = /cgi-bin/foo
                * PATH_INFO   = /bar
                *
                */
                char *pathinfo;

                /* the rewrite is only done for /prefix/? matches */
                if (host->fix_root_path_name && extension->key->ptr[0] == '/'
                                             && extension->key->ptr[1] == '\0'){
                    buffer_copy_buffer(con->request.pathinfo, con->uri.path);
                    buffer_string_set_length(con->uri.path, 0);
                } else if (extension->key->ptr[0] == '/'
                           && buffer_string_length(con->uri.path)
                              > buffer_string_length(extension->key)
                           && (pathinfo =
                                 strchr(con->uri.path->ptr
                                        + buffer_string_length(extension->key),
                                        '/')) != NULL) {
                    /* rewrite uri.path and pathinfo */

                    buffer_copy_string(con->request.pathinfo, pathinfo);
                    buffer_string_set_length(
                      con->uri.path,
                      buffer_string_length(con->uri.path)
                      - buffer_string_length(con->request.pathinfo));
                }
            }
        }
    }

    if (!hctx) hctx = handler_ctx_init(hctx_sz);

    hctx->remote_conn      = con;
    hctx->plugin_data      = p;
    hctx->host             = host;
    hctx->proc             = NULL;
    hctx->ext              = extension;
    gw_host_assign(srv, host);

    hctx->gw_mode = gw_mode;
    if (gw_mode == GW_AUTHORIZER) {
        hctx->ext_auth = hctx->ext;
    }

    /*hctx->conf.exts        = p->conf.exts;*/
    /*hctx->conf.exts_auth   = p->conf.exts_auth;*/
    /*hctx->conf.exts_resp   = p->conf.exts_resp;*/
    /*hctx->conf.ext_mapping = p->conf.ext_mapping;*/
    hctx->conf.balance     = p->conf.balance;
    hctx->conf.proto       = p->conf.proto;
    hctx->conf.debug       = p->conf.debug;

    hctx->opts.fdfmt = S_IFSOCK;
    hctx->opts.authorizer = (gw_mode == GW_AUTHORIZER);
    hctx->opts.local_redir = 0;
    hctx->opts.xsendfile_allow = host->xsendfile_allow;
    hctx->opts.xsendfile_docroot = host->xsendfile_docroot;

    con->plugin_ctx[p->id] = hctx;

    con->mode = p->id;

    if (con->conf.log_request_handling) {
        log_error_write(srv, __FILE__, __LINE__, "s", "handling it in mod_gw");
    }

    return HANDLER_GO_ON;
}

static void gw_handle_trigger_host(server *srv, gw_host *host, int debug) {
    /*
     * TODO:
     *
     * - add timeout for a connect to a non-gw process
     *   (use state_timestamp + state)
     *
     * perhaps we should kill a connect attempt after 10-15 seconds
     *
     * currently we wait for the TCP timeout which is 180 seconds on Linux
     */

    /* check each child proc to detect if proc exited */

    gw_proc *proc;
    time_t idle_timestamp;
    int overload = 1;

    for (proc = host->first; proc; proc = proc->next) {
        gw_proc_waitpid(srv, host, proc);
    }

    gw_restart_dead_procs(srv, host, debug);

    /* check if adaptive spawning enabled */
    if (host->min_procs == host->max_procs) return;
    if (buffer_string_is_empty(host->bin_path)) return;

    for (proc = host->first; proc; proc = proc->next) {
        if (proc->load <= host->max_load_per_proc) {
            overload = 0;
            break;
        }
    }

    if (overload && host->num_procs && host->num_procs < host->max_procs) {
        /* overload, spawn new child */
        if (debug) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "overload detected, spawning a new child");
        }

        gw_proc_spawn(srv, host, debug);
    }

    idle_timestamp = srv->cur_ts - host->idle_timeout;
    for (proc = host->first; proc; proc = proc->next) {
        if (host->num_procs <= host->min_procs) break;
        if (0 != proc->load) continue;
        if (proc->pid <= 0) continue;
        if (proc->last_used >= idle_timestamp) continue;

        /* terminate proc that has been idling for a long time */
        if (debug) {
            log_error_write(srv, __FILE__, __LINE__, "ssbsd",
                            "idle-timeout reached, terminating child:",
                            "socket:", proc->unixsocket, "pid", proc->pid);
        }

        gw_proc_kill(srv, host, proc);

        /* proc is now in unused, let next second handle next process */
        break;
    }

    for (proc = host->unused_procs; proc; proc = proc->next) {
        gw_proc_waitpid(srv, host, proc);
    }
}

static void gw_handle_trigger_exts(server *srv, gw_exts *exts, int debug) {
    for (size_t j = 0; j < exts->used; ++j) {
        gw_extension *ex = exts->exts[j];
        for (size_t n = 0; n < ex->used; ++n) {
            gw_handle_trigger_host(srv, ex->hosts[n], debug);
        }
    }
}

handler_t gw_handle_trigger(server *srv, void *p_d) {
    gw_plugin_data *p = p_d;
    if (0 != srv->srvconf.max_worker && p->srv_pid != srv->pid)
        return HANDLER_GO_ON;

    for (size_t i = 0; i < srv->config_context->used; i++) {
        gw_plugin_config *conf = p->config_storage[i];
        gw_exts *exts = conf->exts;
        int debug = conf->debug ? conf->debug : p->config_storage[0]->debug;
        if (NULL == exts) continue;
        gw_handle_trigger_exts(srv, exts, debug);
    }

    return HANDLER_GO_ON;
}

handler_t gw_handle_waitpid_cb(server *srv, void *p_d, pid_t pid, int status) {
    gw_plugin_data *p = p_d;
    if (0 != srv->srvconf.max_worker && p->srv_pid != srv->pid)
        return HANDLER_GO_ON;

    for (size_t i = 0; i < srv->config_context->used; ++i) {
        gw_plugin_config *conf = p->config_storage[i];
        gw_exts *exts = conf->exts;
        int debug = conf->debug ? conf->debug : p->config_storage[0]->debug;
        if (NULL == exts) continue;
        for (size_t j = 0; j < exts->used; ++j) {
            gw_extension *ex = exts->exts[j];
            for (size_t n = 0; n < ex->used; ++n) {
                gw_host *host = ex->hosts[n];
                gw_proc *proc;
                for (proc = host->first; proc; proc = proc->next) {
                    if (!proc->is_local || proc->pid != pid) continue;

                    gw_proc_waitpid_log(srv, host, proc, status);
                    gw_proc_set_state(host, proc, PROC_STATE_DIED);
                    proc->pid = 0;

                    /* restart, but avoid spinning if child exits too quickly */
                    if (proc->disabled_until < srv->cur_ts) {
                        if (proc->state != PROC_STATE_KILLED)
                            proc->disabled_until = srv->cur_ts;
                        if (gw_spawn_connection(srv, host, proc, debug)) {
                            log_error_write(srv, __FILE__, __LINE__, "s",
                                            "ERROR: spawning gw failed.");
                        }
                    }

                    return HANDLER_FINISHED;
                }
                for (proc = host->unused_procs; proc; proc = proc->next) {
                    if (!proc->is_local || proc->pid != pid) continue;

                    gw_proc_waitpid_log(srv, host, proc, status);
                    if (proc->state != PROC_STATE_KILLED)
                        proc->disabled_until = srv->cur_ts;
                    gw_proc_set_state(host, proc, PROC_STATE_DIED);
                    proc->pid = 0;
                    return HANDLER_FINISHED;
                }
            }
        }
    }

    return HANDLER_GO_ON;
}
