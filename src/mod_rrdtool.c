#include "first.h"

#include "base.h"
#include "fdevent.h"
#include "log.h"
#include "response.h"

#include "plugin.h"
#include <sys/types.h>
#include "sys-stat.h"
#include "sys-time.h"
#include "sys-unistd.h" /* <unistd.h> */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef struct {
    const buffer *path_rrd;
    off_t requests;
    off_t bytes_written;
    off_t bytes_read;
} rrd_config;

typedef struct {
    rrd_config *rrd;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;

    int read_fd;
    int write_fd;
    pid_t rrdtool_pid;
    pid_t srv_pid;

    int rrdtool_running;
    const buffer *path_rrdtool_bin;
    server *srv;
} plugin_data;

INIT_FUNC(mod_rrd_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

static void mod_rrd_free_config(plugin_data * const p) {
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* rrdtool.db-name */
                if (cpv->vtype == T_CONFIG_LOCAL) free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

FREE_FUNC(mod_rrd_free) {
    plugin_data *p = p_d;
    if (NULL == p->srv) return;
    mod_rrd_free_config(p);

    if (p->read_fd >= 0) close(p->read_fd);
    if (p->write_fd >= 0) close(p->write_fd);
    if (p->rrdtool_pid > 0 && p->srv_pid == p->srv->pid) {
        /* collect status (blocking) */
        fdevent_waitpid(p->rrdtool_pid, NULL, 0);
    }
}

static int mod_rrd_create_pipe(server *srv, plugin_data *p) {
	char *args[3];
	int to_rrdtool_fds[2];
	int from_rrdtool_fds[2];
	/* mod_rrdtool does not work with server.max-workers > 0
	 * since the data between workers is not aggregated,
	 * and it is not valid to send data to rrdtool more than once a sec
	 * (which would happen with multiple workers writing to same pipe)
	 * If pipes were to be shared, then existing pipes would need to be
	 * reused here, if they already exist (not -1), and after flushing
	 * existing contents (read and discard from read-end of pipes). */
	if (fdevent_pipe_cloexec(to_rrdtool_fds, 4096)) {
		log_perror(srv->errh, __FILE__, __LINE__, "pipe()");
		return 0;
	}
	if (fdevent_pipe_cloexec(from_rrdtool_fds, 4096)) {
		log_perror(srv->errh, __FILE__, __LINE__, "pipe()");
		close(to_rrdtool_fds[0]);
		close(to_rrdtool_fds[1]);
		return 0;
	}
	const char * const path_rrdtool_bin = p->path_rrdtool_bin
	  ? p->path_rrdtool_bin->ptr
	  : "/usr/bin/rrdtool";
	*(const char **)&args[0] = path_rrdtool_bin;
	*(const char **)&args[1] = "-";
	args[2] = NULL;

	p->rrdtool_pid = fdevent_fork_execve(args[0], args, NULL, to_rrdtool_fds[0], from_rrdtool_fds[1], -1, -1);

	if (-1 != p->rrdtool_pid) {
		close(from_rrdtool_fds[1]);
		close(to_rrdtool_fds[0]);
		if (p->read_fd >= 0) close(p->read_fd);
		if (p->write_fd >= 0) close(p->write_fd);
		p->write_fd = to_rrdtool_fds[1];
		p->read_fd = from_rrdtool_fds[0];
		p->srv_pid = srv->pid;
		return 1;
	} else {
		log_perror(srv->errh, __FILE__, __LINE__,
		  "fork/exec(%s)", path_rrdtool_bin);
		close(to_rrdtool_fds[0]);
		close(to_rrdtool_fds[1]);
		close(from_rrdtool_fds[0]);
		close(from_rrdtool_fds[1]);
		return 0;
	}
}

__attribute_noinline__
static int mod_rrd_exec(server *srv, plugin_data *p) {
    return (p->rrdtool_running = mod_rrd_create_pipe(srv, p));
}

static void mod_rrd_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* rrdtool.db-name */
        if (cpv->vtype == T_CONFIG_LOCAL) pconf->rrd = cpv->v.v;
        break;
      case 1: /* rrdtool.binary */ /* T_CONFIG_SCOPE_SERVER */
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_rrd_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_rrd_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_rrd_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_rrd_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_rrd_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("rrdtool.db-name"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("rrdtool.binary"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    p->srv = srv;
    if (!config_plugin_values_init(srv, p, cpk, "mod_rrdtool"))
        return HANDLER_ERROR;

    int activate = 0;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* rrdtool.db-name */
                if (!buffer_is_blank(cpv->v.b)) {
                    rrd_config *rrd = ck_calloc(1, sizeof(rrd_config));
                    rrd->path_rrd = cpv->v.b;
                    cpv->v.v = rrd;
                    cpv->vtype = T_CONFIG_LOCAL;
                    activate = 1;
                }
                break;
              case 1: /* rrdtool.binary */ /* T_CONFIG_SCOPE_SERVER */
                if (!buffer_is_blank(cpv->v.b))
                    p->path_rrdtool_bin = cpv->v.b; /*(store directly in p)*/
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
            mod_rrd_merge_config(&p->defaults, cpv);
    }

    p->rrdtool_running = 0;
    p->read_fd  = -1;
    p->write_fd = -1;

    return (!activate || mod_rrd_exec(srv, p)) ? HANDLER_GO_ON : HANDLER_ERROR;
}

/* read/write wrappers to catch EINTR */

/* write to blocking socket; blocks until all data is sent, write returns 0 or an error (apart from EINTR) occurs. */
static ssize_t safe_write(int fd, const void *buf, size_t count) {
	ssize_t res, sum = 0;

	for (;;) {
		res = write(fd, buf, count);
		if (res >= 0) {
			sum += res;
			/* do not try again if res == 0 */
			if (res == 0 || (size_t) res == count) return sum;
			count -= res;
			buf = (const char*) buf + res;
			continue;
		}
		switch (errno) {
		case EINTR:
			continue;
		default:
			return -1;
		}
	}
}

/* this assumes we get enough data on a successful read */
static ssize_t safe_read(int fd, char *buf, size_t sz) {
	ssize_t res;

	do {
		res = read(fd, buf, sz-1);
	} while (-1 == res && errno == EINTR);

	if (res >= 0) buf[res] = '\0';
	return res;
}

static int mod_rrdtool_create_rrd(server *srv, plugin_data *p, rrd_config *s, char *resp, size_t respsz) {
	struct stat st;

	/* check if DB already exists */
	if (0 == stat(s->path_rrd->ptr, &st)) {
		/* check if it is plain file */
		if (!S_ISREG(st.st_mode)) {
			log_error(srv->errh, __FILE__, __LINE__,
			  "not a regular file: %s", s->path_rrd->ptr);
			return HANDLER_ERROR;
		}

		/* still create DB if it's empty file */
		if (st.st_size > 0) {
			return HANDLER_GO_ON;
		}
	}

	/* create a new one */
	buffer * const cmd = srv->tmp_buf;
	buffer_clear(cmd);
	buffer_append_str3(cmd,
	  CONST_STR_LEN("create "),
	  BUF_PTR_LEN(s->path_rrd),
	  CONST_STR_LEN(
		" --step 60 "
		"DS:InOctets:ABSOLUTE:600:U:U "
		"DS:OutOctets:ABSOLUTE:600:U:U "
		"DS:Requests:ABSOLUTE:600:U:U "
		"RRA:AVERAGE:0.5:1:600 "
		"RRA:AVERAGE:0.5:6:700 "
		"RRA:AVERAGE:0.5:24:775 "
		"RRA:AVERAGE:0.5:288:797 "
		"RRA:MAX:0.5:1:600 "
		"RRA:MAX:0.5:6:700 "
		"RRA:MAX:0.5:24:775 "
		"RRA:MAX:0.5:288:797 "
		"RRA:MIN:0.5:1:600 "
		"RRA:MIN:0.5:6:700 "
		"RRA:MIN:0.5:24:775 "
		"RRA:MIN:0.5:288:797\n"));

	if (-1 == (safe_write(p->write_fd, BUF_PTR_LEN(cmd)))) {
		log_perror(srv->errh, __FILE__, __LINE__, "rrdtool-write: failed");
		return HANDLER_ERROR;
	}

	if (-1 == safe_read(p->read_fd, resp, respsz)) {
		log_perror(srv->errh, __FILE__, __LINE__, "rrdtool-read: failed");
		return HANDLER_ERROR;
	}

	if (resp[0] != 'O' || resp[1] != 'K') {
		log_error(srv->errh, __FILE__, __LINE__,
		  "rrdtool-response: %s %s", cmd->ptr, resp);
		return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}

__attribute_cold__
static int mod_rrd_fatal_error(plugin_data *p) {
    /* future: might send kill() signal to p->rrdtool_pid to trigger restart */
    p->rrdtool_running = 0;
    return 0;
}

__attribute_noinline__
static int mod_rrd_write_data(server *srv, plugin_data *p, rrd_config *s) {
    char resp[4096];

    if (HANDLER_GO_ON != mod_rrdtool_create_rrd(srv, p, s, resp, sizeof(resp)))
        return 0;

    buffer * const cmd = srv->tmp_buf;
    buffer_clear(cmd);
    buffer_append_str3(cmd, CONST_STR_LEN("update "),
                            BUF_PTR_LEN(s->path_rrd),
                            CONST_STR_LEN(" N:"));
    buffer_append_int(cmd, s->bytes_read);
    buffer_append_char(cmd, ':');
    buffer_append_int(cmd, s->bytes_written);
    buffer_append_char(cmd, ':');
    buffer_append_int(cmd, s->requests);
    buffer_append_char(cmd, '\n');

    if (-1 == safe_write(p->write_fd, BUF_PTR_LEN(cmd))) {
        log_error(srv->errh, __FILE__, __LINE__, "rrdtool-write: failed");
        return mod_rrd_fatal_error(p);
    }

    if (-1 == safe_read(p->read_fd, resp, sizeof(resp))) {
        log_error(srv->errh, __FILE__, __LINE__, "rrdtool-read: failed");
        return mod_rrd_fatal_error(p);
    }

    if (resp[0] == 'O' && resp[1] == 'K') {
        s->requests = 0;
        s->bytes_written = 0;
        s->bytes_read = 0;
    }
    else if (!(strstr(resp, "(minimum one second step)")
               && log_epoch_secs - srv->startup_ts < 3)) {
        /* don't fail on this error if we just started (above condition)
         * (graceful restart, the old one might have just updated too) */
        log_error(srv->errh, __FILE__, __LINE__,
          "rrdtool-response: %s %s", cmd->ptr, resp);
        return mod_rrd_fatal_error(p);
    }

    return 1;
}

static void mod_rrd_write_data_loop(server *srv, plugin_data *p) {
    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* rrdtool.db-name */
                if (cpv->vtype != T_CONFIG_LOCAL) continue;
                mod_rrd_write_data(srv, p, cpv->v.v);
                if (!p->rrdtool_running) return;
                break;
            }
        }
    }
}

TRIGGER_FUNC(mod_rrd_trigger) {
    plugin_data *p = p_d;
    /*(0 == p->rrdtool_pid if never activated; not used)*/
    if (0 == p->rrdtool_pid) return HANDLER_GO_ON;

    /* write data once a minute */
    if ((log_epoch_secs % 60) != 0) return HANDLER_GO_ON;

    if (!p->rrdtool_running) {
        if (srv->pid != p->srv_pid) return HANDLER_GO_ON;
        /* restart limited to once every 60 sec (above) */
        if (!mod_rrd_exec(srv, p)) return HANDLER_GO_ON;
    }

    mod_rrd_write_data_loop(srv, p);
    return HANDLER_GO_ON;
}

static handler_t mod_rrd_waitpid_cb(server *srv, void *p_d, pid_t pid, int status) {
    plugin_data *p = p_d;
    if (pid != p->rrdtool_pid) return HANDLER_GO_ON;
    if (srv->pid != p->srv_pid) return HANDLER_GO_ON;

    p->rrdtool_running = 0;
    p->rrdtool_pid = -1;

    UNUSED(status);
    return HANDLER_FINISHED;
}

REQUESTDONE_FUNC(mod_rrd_account) {
    const plugin_data * const p = p_d;
    /*(0 == p->rrdtool_pid if never activated; not used)*/
    if (0 == p->rrdtool_pid) return HANDLER_GO_ON;

    plugin_config pconf;
    mod_rrd_patch_config(r, p, &pconf);
    rrd_config * const rrd = pconf.rrd;
    if (NULL != rrd) {
        /* thread-safety todo: atomics, or lock around modification */
        ++rrd->requests;
        rrd->bytes_written += http_request_stats_bytes_out(r);
        rrd->bytes_read    += http_request_stats_bytes_in(r);
    }
    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_rrdtool_plugin_init(plugin *p);
int mod_rrdtool_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "rrd";

	p->init        = mod_rrd_init;
	p->cleanup     = mod_rrd_free;
	p->set_defaults= mod_rrd_set_defaults;

	p->handle_trigger      = mod_rrd_trigger;
	p->handle_waitpid      = mod_rrd_waitpid_cb;
	p->handle_request_done = mod_rrd_account;

	return 0;
}
