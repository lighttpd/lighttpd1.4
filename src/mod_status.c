#define _GNU_SOURCE
#include <sys/types.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "server.h"
#include "connections.h"
#include "response.h"
#include "connections.h"
#include "log.h"

#include "plugin.h"

#include "inet_ntop_cache.h"

typedef struct {
	buffer *config_url;
	buffer *status_url;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	double traffic_out;
	double requests;
	
	double mod_5s_traffic_out[5];
	double mod_5s_requests[5];
	size_t mod_5s_ndx;
	
	double rel_traffic_out;
	double rel_requests;
	
	double abs_traffic_out;
	double abs_requests;
	
	double bytes_written;
	
	buffer *module_list;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

INIT_FUNC(mod_status_init) {
	plugin_data *p;
	size_t i;
	
	p = calloc(1, sizeof(*p));
	
	p->traffic_out = p->requests = 0;
	p->rel_traffic_out = p->rel_requests = 0;
	p->abs_traffic_out = p->abs_requests = 0;
	p->bytes_written = 0;
	p->module_list = buffer_init();
	
	for (i = 0; i < 5; i++) {
		p->mod_5s_traffic_out[i] = p->mod_5s_requests[i] = 0;
	}
	
	return p;
}

FREE_FUNC(mod_status_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	buffer_free(p->module_list);
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			buffer_free(s->status_url);
			buffer_free(s->config_url);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	
	free(p);
	
	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_status_set_defaults) {
	plugin_data *p = p_d;
	size_t i;
	
	config_values_t cv[] = { 
		{ "status.status-url",           NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ "status.config-url",           NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },
		{ NULL,                          NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = malloc(srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = malloc(sizeof(plugin_config));
		s->config_url    = buffer_init();
		s->status_url    = buffer_init();
		
		cv[0].destination = s->status_url;
		cv[1].destination = s->config_url;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}
	
	return HANDLER_GO_ON;
}



static int mod_status_row_append(buffer *b, const char *key, const char *value) {
	BUFFER_APPEND_STRING_CONST(b, "   <tr>\n");
	BUFFER_APPEND_STRING_CONST(b, "    <td><b>");
	buffer_append_string(b, key);
	BUFFER_APPEND_STRING_CONST(b, "</b></td>\n");
	BUFFER_APPEND_STRING_CONST(b, "    <td>");
	buffer_append_string(b, value);
	BUFFER_APPEND_STRING_CONST(b, "</td>\n");
	BUFFER_APPEND_STRING_CONST(b, "   </tr>\n");
	
	return 0;
}

static int mod_status_header_append(buffer *b, const char *key) {
	BUFFER_APPEND_STRING_CONST(b, "   <tr>\n");
	BUFFER_APPEND_STRING_CONST(b, "    <th colspan=\"2\">");
	buffer_append_string(b, key);
	BUFFER_APPEND_STRING_CONST(b, "</th>\n");
	BUFFER_APPEND_STRING_CONST(b, "   </tr>\n");
	
	return 0;
}

static handler_t mod_status_handle_server_status(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	buffer *b;
	size_t j;
	double avg;
	char multiplier = '\0';
	char buf[32];
	time_t ts;
	
	int days, hours, mins, seconds;
	
	b = chunkqueue_get_append_buffer(con->write_queue);
	
	BUFFER_COPY_STRING_CONST(b, 
				 "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
				 "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
				 "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
				 "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
				 " <head>\n"
				 "  <title>Status</title>\n");
	
	BUFFER_APPEND_STRING_CONST(b,
				   "  <style type=\"text/css\">\n"
				   "th.status { background-color: black; color: white; }\n"
				   "table.status { border: black solid thin; }\n"
				   "td.int { background-color: #f0f0f0; text-align: right }\n"
				   "td.string { background-color: #f0f0f0; text-align: left }\n"
				   "  </style>\n");
	
	BUFFER_APPEND_STRING_CONST(b, 
				 " </head>\n"
				 " <body>\n");
	
	
	
	/* connection listing */
	BUFFER_APPEND_STRING_CONST(b, "<h1>Server-Status</h1>");
	
	BUFFER_APPEND_STRING_CONST(b, "<table class=\"status\">");
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Hostname</td><td class=\"string\">");
	buffer_append_string_buffer(b, con->uri.authority);
	BUFFER_APPEND_STRING_CONST(b, " (");
	buffer_append_string_buffer(b, con->server_name);
	BUFFER_APPEND_STRING_CONST(b, ")</td></tr>\n");
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Uptime</td><td class=\"string\">");
	
	ts = srv->cur_ts - srv->startup_ts;
	
	days = ts / (60 * 60 * 24);
	ts %= (60 * 60 * 24);
	
	hours = ts / (60 * 60);
	ts %= (60 * 60);
	
	mins = ts / (60);
	ts %= (60);
	
	seconds = ts;
	
	if (days) {
		buffer_append_long(b, days);
		BUFFER_APPEND_STRING_CONST(b, " days ");
	}
	
	if (hours) {
		buffer_append_long(b, hours);
		BUFFER_APPEND_STRING_CONST(b, " hours ");
	}
	
	if (mins) {
		buffer_append_long(b, mins);
		BUFFER_APPEND_STRING_CONST(b, " min ");
	}
	
	buffer_append_long(b, seconds);
	BUFFER_APPEND_STRING_CONST(b, " s");
	
	BUFFER_APPEND_STRING_CONST(b, "</td></tr>\n");
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Started at</td><td class=\"string\">");
	
	ts = srv->startup_ts;
	
	strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", localtime(&ts));
	buffer_append_string(b, buf);
	BUFFER_APPEND_STRING_CONST(b, "</td></tr>\n");
	
	
	BUFFER_APPEND_STRING_CONST(b, "<tr><th colspan=\"2\">absolute (since start)</th></tr>\n");
	
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Requests</td><td class=\"string\">");
	avg = p->abs_requests;
	multiplier = '\0';
	if (avg > 1000) { avg /= 1000; multiplier = 'k'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'M'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'G'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'T'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'P'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'E'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'Z'; }
	if (avg > 1000) { avg /= 1000; multiplier = 'Y'; }
	buffer_append_long(b, avg);
	BUFFER_APPEND_STRING_CONST(b, " ");
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	BUFFER_APPEND_STRING_CONST(b, "req</td></tr>\n");
	
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Traffic</td><td class=\"string\">");
	avg = p->abs_traffic_out;
	multiplier = '\0';
	
	if (avg > 1024) { avg /= 1024; multiplier = 'k'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'M'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'G'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'T'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'P'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'E'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'Z'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'Y'; }
	
	buffer_append_long(b, avg);
	BUFFER_APPEND_STRING_CONST(b, " ");
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	BUFFER_APPEND_STRING_CONST(b, "byte</td></tr>\n");
	
	
	BUFFER_APPEND_STRING_CONST(b, "<tr><th colspan=\"2\">average (5s sliding average)</th></tr>\n");
	for (j = 0, avg = 0; j < 5; j++) {
		avg += p->mod_5s_requests[j];
	}
	
	avg /= 5;
	
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Requests</td><td class=\"string\">");
	multiplier = '\0';
	
	if (avg > 1024) { avg /= 1024; multiplier = 'k'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'M'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'G'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'T'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'P'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'E'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'Z'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'Y'; }
	
	buffer_append_long(b, avg);
	BUFFER_APPEND_STRING_CONST(b, " ");
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	
	BUFFER_APPEND_STRING_CONST(b, "req/s</td></tr>\n");
	
	for (j = 0, avg = 0; j < 5; j++) {
		avg += p->mod_5s_traffic_out[j];
	}
	
	avg /= 5;
	
	BUFFER_APPEND_STRING_CONST(b, "<tr><td>Traffic</td><td class=\"string\">");
	multiplier = '\0';
	
	if (avg > 1024) { avg /= 1024; multiplier = 'k'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'M'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'G'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'T'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'P'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'E'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'Z'; }
	if (avg > 1024) { avg /= 1024; multiplier = 'Y'; }
	
	buffer_append_long(b, avg);
	BUFFER_APPEND_STRING_CONST(b, " ");
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	BUFFER_APPEND_STRING_CONST(b, "byte/s</td></tr>\n");
	
	BUFFER_APPEND_STRING_CONST(b, "</table>\n");
	
	
	BUFFER_APPEND_STRING_CONST(b, "<hr />\n<pre><b>legend</b>\n");
	BUFFER_APPEND_STRING_CONST(b, ". = connect, C = close, E = hard error\n");
	BUFFER_APPEND_STRING_CONST(b, "r = read, R = read-POST, W = write, h = handle-request\n");
	BUFFER_APPEND_STRING_CONST(b, "q = request-start,  Q = request-end\n");
	BUFFER_APPEND_STRING_CONST(b, "s = response-start, S = response-end\n");
	
	BUFFER_APPEND_STRING_CONST(b, "<b>");
	buffer_append_long(b, srv->conns->used);
	BUFFER_APPEND_STRING_CONST(b, " connections</b>\n");
	
	for (j = 0; j < srv->conns->used; j++) {
		connection *c = srv->conns->ptr[j];
		const char *state = connection_get_short_state(c->state);
		
		buffer_append_string_len(b, state, 1);
		
		if (((j + 1) % 50) == 0) {
			BUFFER_APPEND_STRING_CONST(b, "\n");
		}
	}
	
	BUFFER_APPEND_STRING_CONST(b, "\n</pre><hr />\n<h2>Connections</h2>\n");
	
	BUFFER_APPEND_STRING_CONST(b, "<table class=\"status\">\n");
	BUFFER_APPEND_STRING_CONST(b, "<tr>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">Client IP</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">Read</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">Written</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">State</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">Time</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">Host</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">URI</th>");
	BUFFER_APPEND_STRING_CONST(b, "<th class=\"status\">File</th>");
	BUFFER_APPEND_STRING_CONST(b, "</tr>\n");
	
	for (j = 0; j < srv->conns->used; j++) {
		connection *c = srv->conns->ptr[j];
		
		BUFFER_APPEND_STRING_CONST(b, "<tr><td class=\"string\">");
		
		buffer_append_string(b, inet_ntop_cache_get_ip(srv, &(c->dst_addr)));
		
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"int\">");
		
		if (con->request.content_length) {
			buffer_append_long(b, c->request.content->used);
			BUFFER_APPEND_STRING_CONST(b, "/");
			buffer_append_long(b, c->request.content_length);
		} else {
			BUFFER_APPEND_STRING_CONST(b, "0/0");
		}
	
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"int\">");
		
		buffer_append_off_t(b, chunkqueue_written(c->write_queue));
		BUFFER_APPEND_STRING_CONST(b, "/");
		buffer_append_off_t(b, chunkqueue_length(c->write_queue));
		
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"string\">");
		
		buffer_append_string(b, connection_get_state(c->state));
		
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"int\">");
		
		buffer_append_long(b, srv->cur_ts - c->request_start);
		
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"string\">");
		
		buffer_append_string_buffer(b, c->server_name);
		
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"string\">");
		
		buffer_append_string_html_encoded(b, c->uri.path->ptr);
		
		BUFFER_APPEND_STRING_CONST(b, "</td><td class=\"string\">");
		
		buffer_append_string_buffer(b, c->physical.path);
		
		BUFFER_APPEND_STRING_CONST(b, "</td></tr>\n");
	}
	
	
	BUFFER_APPEND_STRING_CONST(b, 
		      "</table>\n");
	
	
	BUFFER_APPEND_STRING_CONST(b, 
		      " </body>\n"
		      "</html>\n"
		      );
	
	response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	
	con->http_status = 200;
	con->file_finished = 1;
	
	return HANDLER_FINISHED;
}

static handler_t mod_status_handle_server_config(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	buffer *b, *m = p->module_list;
	size_t i;
	
	struct ev_map { fdevent_handler_t et; const char *name; } event_handlers[] = 
	{ 
		/* - poll is most reliable
		 * - select works everywhere
		 * - linux-* are experimental
		 */
#ifdef USE_POLL
		{ FDEVENT_HANDLER_POLL,           "poll" },
#endif
#ifdef USE_SELECT
		{ FDEVENT_HANDLER_SELECT,         "select" },
#endif
#ifdef USE_LINUX_EPOLL
		{ FDEVENT_HANDLER_LINUX_SYSEPOLL, "linux-sysepoll" },
#endif
#ifdef USE_LINUX_SIGIO
		{ FDEVENT_HANDLER_LINUX_RTSIG,    "linux-rtsig" },
#endif
#ifdef USE_SOLARIS_DEVPOLL
		{ FDEVENT_HANDLER_SOLARIS_DEVPOLL,"solaris-devpoll" },
#endif
#ifdef USE_FREEBSD_KQUEUE
		{ FDEVENT_HANDLER_FREEBSD_KQUEUE, "freebsd-kqueue" },
#endif
		{ FDEVENT_HANDLER_UNSET,          NULL }
	};
	
	b = chunkqueue_get_append_buffer(con->write_queue);
	
	BUFFER_COPY_STRING_CONST(b, 
			   "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
			   "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
			   "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
			   "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
			   " <head>\n"
			   "  <title>Status</title>\n"
			   " </head>\n"
			   " <body>\n"
			   "  <h1>" PACKAGE_NAME " " PACKAGE_VERSION "</h1>\n"
			   "  <table border=\"1\">\n");
	
	mod_status_header_append(b, "Server-Features");
#ifdef HAVE_PCRE_H
	mod_status_row_append(b, "Rewrite Engine", "enabled");
#else
	mod_status_row_append(b, "Rewrite Engine", "disabled - pcre missing");
#endif
#ifdef HAVE_ZLIB_H
	mod_status_row_append(b, "On-the-Fly Output Compression", "enabled");
#else
	mod_status_row_append(b, "On-the-Fly Output Compression", "disabled - zlib missing");
#endif
	mod_status_header_append(b, "Network Engine");
	
	for (i = 0; event_handlers[i].name; i++) {
		if (event_handlers[i].et == srv->event_handler) {
			mod_status_row_append(b, "fd-Event-Handler", event_handlers[i].name);
			break;
		}
	}
	
	mod_status_header_append(b, "Config-File-Settings");
	mod_status_row_append(b, "Directory Listings", con->conf.dir_listing ? "enabled" : "disabled");
	
	for (i = 0; i < srv->plugins.used; i++) {
		plugin **ps = srv->plugins.ptr;
		
		plugin *pl = ps[i];
	
		if (i == 0) {
			buffer_copy_string_buffer(m, pl->name);
		} else {
			BUFFER_APPEND_STRING_CONST(m, "<br />");
			buffer_append_string_buffer(m, pl->name);
		}
	}
	
	mod_status_row_append(b, "Loaded Modules", m->ptr);
	
	BUFFER_APPEND_STRING_CONST(b, "  </table>\n");
	
	BUFFER_APPEND_STRING_CONST(b, 
		      " </body>\n"
		      "</html>\n"
		      );
	
	response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	
	con->http_status = 200;
	con->file_finished = 1;
	
	return HANDLER_FINISHED;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_skeleton_patch_connection(server *srv, connection *con, plugin_data *p, const char *stage, size_t stage_len) {
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
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("status.status-url"))) {
				PATCH(status_url);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("status.config-url"))) {
				PATCH(config_url);
			} 
		}
	}
	
	return 0;
}

static int mod_skeleton_setup_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	UNUSED(srv);
	UNUSED(con);

	PATCH(status_url);
	PATCH(config_url);
	
	return 0;
}
#undef PATCH

static handler_t mod_status_handler(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	size_t i;
	
	mod_skeleton_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		mod_skeleton_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	if (!buffer_is_empty(p->conf.status_url) && 
	    buffer_is_equal(p->conf.status_url, con->uri.path)) {
		return mod_status_handle_server_status(srv, con, p_d);
	} else if (!buffer_is_empty(p->conf.config_url) && 
	    buffer_is_equal(p->conf.config_url, con->uri.path)) {
		return mod_status_handle_server_config(srv, con, p_d);
	}
	
	return HANDLER_GO_ON;
}

TRIGGER_FUNC(mod_status_trigger) {
	plugin_data *p = p_d;
	size_t i;
	
	/* check all connections */
	for (i = 0; i < srv->conns->used; i++) {
		connection *c = srv->conns->ptr[i];
		
		p->bytes_written += c->bytes_written_cur_second;
	}
	
	/* a sliding average */
	p->mod_5s_traffic_out[p->mod_5s_ndx] = p->bytes_written;
	p->mod_5s_requests   [p->mod_5s_ndx] = p->requests;
	
	p->mod_5s_ndx = (p->mod_5s_ndx+1) % 5;
	
	p->abs_traffic_out += p->bytes_written;
	p->rel_traffic_out += p->bytes_written;
	
	p->bytes_written = 0;
	
	/* reset storage - second */
	p->traffic_out = 0;
	p->requests    = 0;
	
	return HANDLER_GO_ON;
}

REQUESTDONE_FUNC(mod_status_account) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	p->requests++;
	p->rel_requests++;
	p->abs_requests++;
	
	p->bytes_written += con->bytes_written_cur_second;
	
	return HANDLER_GO_ON;
}

int mod_status_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("status");
	
	p->init        = mod_status_init;
	p->cleanup     = mod_status_free;
	p->set_defaults= mod_status_set_defaults;
	
	p->handle_uri_clean    = mod_status_handler;
	p->handle_trigger      = mod_status_trigger;
	p->handle_request_done = mod_status_account;
	
	p->data        = NULL;
	
	return 0;
}
