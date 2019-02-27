#include "first.h"

#include "base.h"
#include "fdevent.h"
#include "log.h"

#include "plugin.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

typedef struct {
	buffer *path_rrdtool_bin;
	buffer *path_rrd;

	double requests, *requests_ptr;
	double bytes_written, *bytes_written_ptr;
	double bytes_read, *bytes_read_ptr;
} plugin_config;

typedef struct {
	PLUGIN_DATA;

	buffer *cmd;
	buffer *resp;

	int read_fd, write_fd;
	pid_t rrdtool_pid;
	pid_t srv_pid;

	int rrdtool_running;
	time_t rrdtool_startup_ts;

	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

INIT_FUNC(mod_rrd_init) {
	plugin_data *p;

	p = calloc(1, sizeof(*p));

	p->resp = buffer_init();
	p->cmd = buffer_init();

	return p;
}

FREE_FUNC(mod_rrd_free) {
	plugin_data *p = p_d;
	size_t i;

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			buffer_free(s->path_rrdtool_bin);
			buffer_free(s->path_rrd);

			free(s);
		}
	}
	buffer_free(p->cmd);
	buffer_free(p->resp);

	free(p->config_storage);

	if (p->read_fd >= 0) close(p->read_fd);
	if (p->write_fd >= 0) close(p->write_fd);

	if (p->rrdtool_pid > 0 && p->srv_pid == srv->pid) {
		/* collect status */
		while (-1 == waitpid(p->rrdtool_pid, NULL, 0) && errno == EINTR) ;
	}

	free(p);

	return HANDLER_GO_ON;
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
	if (pipe(to_rrdtool_fds)) {
		log_error_write(srv, __FILE__, __LINE__, "ss",
				"pipe failed: ", strerror(errno));
		return -1;
	}
	if (pipe(from_rrdtool_fds)) {
		log_error_write(srv, __FILE__, __LINE__, "ss",
				"pipe failed: ", strerror(errno));
		return -1;
	}
	fdevent_setfd_cloexec(to_rrdtool_fds[1]);
	fdevent_setfd_cloexec(from_rrdtool_fds[0]);
	*(const char **)&args[0] = p->conf.path_rrdtool_bin->ptr;
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
		return 0;
	} else {
		log_error_write(srv, __FILE__, __LINE__, "SBss", "fork/exec(", p->conf.path_rrdtool_bin, "):", strerror(errno));
		close(to_rrdtool_fds[0]);
		close(to_rrdtool_fds[1]);
		close(from_rrdtool_fds[0]);
		close(from_rrdtool_fds[1]);
		return -1;
	}
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
static ssize_t safe_read(int fd, buffer *b) {
	ssize_t res;

	buffer_string_prepare_copy(b, 4095);

	do {
		res = read(fd, b->ptr, b->size-1);
	} while (-1 == res && errno == EINTR);

	if (res >= 0) buffer_commit(b, res);
	return res;
}

static int mod_rrdtool_create_rrd(server *srv, plugin_data *p, plugin_config *s) {
	struct stat st;

	/* check if DB already exists */
	if (0 == stat(s->path_rrd->ptr, &st)) {
		/* check if it is plain file */
		if (!S_ISREG(st.st_mode)) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"not a regular file:", s->path_rrd);
			return HANDLER_ERROR;
		}

		/* still create DB if it's empty file */
		if (st.st_size > 0) {
			return HANDLER_GO_ON;
		}
	}

	/* create a new one */
	buffer_copy_string_len(p->cmd, CONST_STR_LEN("create "));
	buffer_append_string_buffer(p->cmd, s->path_rrd);
	buffer_append_string_len(p->cmd, CONST_STR_LEN(
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

	if (-1 == (safe_write(p->write_fd, CONST_BUF_LEN(p->cmd)))) {
		log_error_write(srv, __FILE__, __LINE__, "ss",
			"rrdtool-write: failed", strerror(errno));

		return HANDLER_ERROR;
	}

	if (-1 == safe_read(p->read_fd, p->resp)) {
		log_error_write(srv, __FILE__, __LINE__, "ss",
			"rrdtool-read: failed", strerror(errno));

		return HANDLER_ERROR;
	}

	if (p->resp->ptr[0] != 'O' ||
		p->resp->ptr[1] != 'K') {
		log_error_write(srv, __FILE__, __LINE__, "sbb",
			"rrdtool-response:", p->cmd, p->resp);

		return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_rrd_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(path_rrdtool_bin);
	PATCH(path_rrd);

	p->conf.bytes_written_ptr = &(s->bytes_written);
	p->conf.bytes_read_ptr = &(s->bytes_read);
	p->conf.requests_ptr = &(s->requests);

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("rrdtool.db-name"))) {
				PATCH(path_rrd);
				/* get pointers to double values */

				p->conf.bytes_written_ptr = &(s->bytes_written);
				p->conf.bytes_read_ptr = &(s->bytes_read);
				p->conf.requests_ptr = &(s->requests);
			}
		}
	}

	return 0;
}
#undef PATCH

static int mod_rrd_exec(server *srv, plugin_data *p) {
    if (mod_rrd_create_pipe(srv, p)) {
        return -1;
    }

    p->rrdtool_running = 1;
    p->rrdtool_startup_ts = srv->cur_ts;
    return 0;
}

SETDEFAULTS_FUNC(mod_rrd_set_defaults) {
	plugin_data *p = p_d;
	size_t i;
	int activate = 0;

	config_values_t cv[] = {
		{ "rrdtool.binary",  NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "rrdtool.db-name", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ NULL,              NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET      }
	};

	if (!p) return HANDLER_ERROR;

	force_assert(srv->config_context->used > 0);
	p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s;

		s = calloc(1, sizeof(plugin_config));
		s->path_rrdtool_bin = buffer_init();
		s->path_rrd = buffer_init();
		s->requests = 0;
		s->bytes_written = 0;
		s->bytes_read = 0;

		cv[0].destination = s->path_rrdtool_bin;
		cv[1].destination = s->path_rrd;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}

		if (i > 0 && !buffer_string_is_empty(s->path_rrdtool_bin)) {
			/* path_rrdtool_bin is a global option */

			log_error_write(srv, __FILE__, __LINE__, "s",
					"rrdtool.binary can only be set as a global option.");

			return HANDLER_ERROR;
		}

		if (!buffer_string_is_empty(s->path_rrd)) activate = 1;
	}

	p->conf.path_rrdtool_bin = p->config_storage[0]->path_rrdtool_bin;
	p->rrdtool_running = 0;
	p->read_fd  = -1;
	p->write_fd = -1;

	if (!activate) return HANDLER_GO_ON;

	/* check for dir */

	if (buffer_string_is_empty(p->conf.path_rrdtool_bin)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"rrdtool.binary has to be set");
		return HANDLER_ERROR;
	}

	return 0 == mod_rrd_exec(srv, p) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static void mod_rrd_fatal_error(server *srv, plugin_data *p) {
    /* future: might send kill() signal to p->rrdtool_pid to trigger restart */
    p->rrdtool_running = 0;
    UNUSED(srv);
}

TRIGGER_FUNC(mod_rrd_trigger) {
	plugin_data *p = p_d;
	size_t i;

	if (!p->rrdtool_running) {
		/* limit restart to once every 5 sec */
		/*(0 == p->rrdtool_pid if never activated; not used)*/
		if (-1 == p->rrdtool_pid
		    && p->srv_pid == srv->pid
		    && p->rrdtool_startup_ts + 5 < srv->cur_ts) {
			mod_rrd_exec(srv, p);
		}
		return HANDLER_GO_ON;
	}

	if ((srv->cur_ts % 60) != 0) return HANDLER_GO_ON;

	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s = p->config_storage[i];

		if (buffer_string_is_empty(s->path_rrd)) continue;

		/* write the data down every minute */

		if (HANDLER_GO_ON != mod_rrdtool_create_rrd(srv, p, s)) return HANDLER_GO_ON;

		buffer_copy_string_len(p->cmd, CONST_STR_LEN("update "));
		buffer_append_string_buffer(p->cmd, s->path_rrd);
		buffer_append_string_len(p->cmd, CONST_STR_LEN(" N:"));
		buffer_append_int(p->cmd, s->bytes_read);
		buffer_append_string_len(p->cmd, CONST_STR_LEN(":"));
		buffer_append_int(p->cmd, s->bytes_written);
		buffer_append_string_len(p->cmd, CONST_STR_LEN(":"));
		buffer_append_int(p->cmd, s->requests);
		buffer_append_string_len(p->cmd, CONST_STR_LEN("\n"));

		if (-1 == safe_write(p->write_fd, CONST_BUF_LEN(p->cmd))) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"rrdtool-write: failed", strerror(errno));

			mod_rrd_fatal_error(srv, p);
			return HANDLER_GO_ON;
		}

		if (-1 == safe_read(p->read_fd, p->resp)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"rrdtool-read: failed", strerror(errno));

			mod_rrd_fatal_error(srv, p);
			return HANDLER_GO_ON;
		}

		if (p->resp->ptr[0] != 'O' ||
		    p->resp->ptr[1] != 'K') {
			/* don't fail on this error if we just started (graceful restart, the old one might have just updated too) */
			if (!(strstr(p->resp->ptr, "(minimum one second step)") && (srv->cur_ts - srv->startup_ts < 3))) {
				log_error_write(srv, __FILE__, __LINE__, "sbb",
					"rrdtool-response:", p->cmd, p->resp);

				mod_rrd_fatal_error(srv, p);
				return HANDLER_GO_ON;
			}
		}
		s->requests = 0;
		s->bytes_written = 0;
		s->bytes_read = 0;
	}

	return HANDLER_GO_ON;
}

static handler_t mod_rrd_waitpid_cb(server *srv, void *p_d, pid_t pid, int status) {
	plugin_data *p = p_d;
	if (pid != p->rrdtool_pid) return HANDLER_GO_ON;
	if (srv->pid != p->srv_pid) return HANDLER_GO_ON;

	p->rrdtool_running = 0;
	p->rrdtool_pid = -1;

	/* limit restart to once every 5 sec */
	if (p->rrdtool_startup_ts + 5 < srv->cur_ts)
		mod_rrd_exec(srv, p);

	UNUSED(status);
	return HANDLER_FINISHED;
}

REQUESTDONE_FUNC(mod_rrd_account) {
	plugin_data *p = p_d;

	/*(0 == p->rrdtool_pid if never activated; not used)*/
	if (0 == p->rrdtool_pid) return HANDLER_GO_ON;
	mod_rrd_patch_connection(srv, con, p);

	*(p->conf.requests_ptr)      += 1;
	*(p->conf.bytes_written_ptr) += con->bytes_written;
	*(p->conf.bytes_read_ptr)    += con->bytes_read;

	return HANDLER_GO_ON;
}

int mod_rrdtool_plugin_init(plugin *p);
int mod_rrdtool_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("rrd");

	p->init        = mod_rrd_init;
	p->cleanup     = mod_rrd_free;
	p->set_defaults= mod_rrd_set_defaults;

	p->handle_trigger      = mod_rrd_trigger;
	p->handle_waitpid      = mod_rrd_waitpid_cb;
	p->handle_request_done = mod_rrd_account;

	p->data        = NULL;

	return 0;
}
