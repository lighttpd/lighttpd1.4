#include "first.h"

#include "base.h"
#include "connections.h"
#include "fdevent.h"
#include "http_header.h"
#include "log.h"

#include "plugin.h"

#include <sys/types.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

typedef struct {
    const buffer *config_url;
    const buffer *status_url;
    const buffer *statistics_url;

    int sort;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	plugin_config conf;

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
} plugin_data;

INIT_FUNC(mod_status_init) {
    return calloc(1, sizeof(plugin_data));
}

static void mod_status_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* status.status-url */
        pconf->status_url = cpv->v.b;
        break;
      case 1: /* status.config-url */
        pconf->config_url = cpv->v.b;
        break;
      case 2: /* status.statistics-url */
        pconf->statistics_url = cpv->v.b;
        break;
      case 3: /* status.enable-sort */
        pconf->sort = (int)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_status_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_status_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_status_patch_config(connection * const con, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_status_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_status_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("status.status-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("status.config-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("status.statistics-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("status.enable-sort"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_status"))
        return HANDLER_ERROR;

    p->defaults.sort = 1;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_status_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}



static int mod_status_row_append(buffer *b, const char *key, const char *value) {
	buffer_append_string_len(b, CONST_STR_LEN("   <tr>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("    <td><b>"));
	buffer_append_string(b, key);
	buffer_append_string_len(b, CONST_STR_LEN("</b></td>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("    <td>"));
	buffer_append_string(b, value);
	buffer_append_string_len(b, CONST_STR_LEN("</td>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("   </tr>\n"));

	return 0;
}

static int mod_status_header_append(buffer *b, const char *key) {
	buffer_append_string_len(b, CONST_STR_LEN("   <tr>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("    <th colspan=\"2\">"));
	buffer_append_string(b, key);
	buffer_append_string_len(b, CONST_STR_LEN("</th>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("   </tr>\n"));

	return 0;
}

static int mod_status_header_append_sort(buffer *b, plugin_data *p, const char* key) {

	if (p->conf.sort) {
		buffer_append_string_len(b, CONST_STR_LEN("<th class=\"status\"><a href=\"#\" class=\"sortheader\" onclick=\"resort(this);return false;\">"));
		buffer_append_string(b, key);
		buffer_append_string_len(b, CONST_STR_LEN("<span class=\"sortarrow\">:</span></a></th>\n"));
	} else {
		buffer_append_string_len(b, CONST_STR_LEN("<th class=\"status\">"));
		buffer_append_string(b, key);
		buffer_append_string_len(b, CONST_STR_LEN("</th>\n"));
	}

	return 0;
}

static int mod_status_get_multiplier(double *avg, char *multiplier, int size) {
	*multiplier = ' ';

	if (*avg > size) { *avg /= size; *multiplier = 'k'; }
	if (*avg > size) { *avg /= size; *multiplier = 'M'; }
	if (*avg > size) { *avg /= size; *multiplier = 'G'; }
	if (*avg > size) { *avg /= size; *multiplier = 'T'; }
	if (*avg > size) { *avg /= size; *multiplier = 'P'; }
	if (*avg > size) { *avg /= size; *multiplier = 'E'; }
	if (*avg > size) { *avg /= size; *multiplier = 'Z'; }
	if (*avg > size) { *avg /= size; *multiplier = 'Y'; }

	return 0;
}

static handler_t mod_status_handle_server_status_html(server *srv, connection *con, plugin_data *p) {
	buffer *b = chunkqueue_append_buffer_open(con->write_queue);
	double avg;
	uint32_t j;
	char multiplier = '\0';
	char buf[32];
	time_t ts;
	const time_t cur_ts = log_epoch_secs;

	int days, hours, mins, seconds;

	/*(CON_STATE_CLOSE must be last state in enum connection_state_t)*/
	int cstates[CON_STATE_CLOSE+3];
	memset(cstates, 0, sizeof(cstates));

	buffer_copy_string_len(b, CONST_STR_LEN(
				 "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
				 "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
				 "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
				 "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
				 " <head>\n"
				 "  <title>Status</title>\n"

				   "  <style type=\"text/css\">\n"
				   "    table.status { border: black solid thin; }\n"
				   "    td { white-space: nowrap; }\n"
				   "    td.int { background-color: #f0f0f0; text-align: right }\n"
				   "    td.string { background-color: #f0f0f0; text-align: left }\n"
				   "    th.status { background-color: black; color: white; font-weight: bold; }\n"
				   "    a.sortheader { background-color: black; color: white; font-weight: bold; text-decoration: none; display: block; }\n"
				   "    span.sortarrow { color: white; text-decoration: none; }\n"
				   "  </style>\n"));

	if (!buffer_string_is_empty(con->uri.query) && 0 == memcmp(con->uri.query->ptr, CONST_STR_LEN("refresh="))) {
		/* Note: Refresh is an historical, but non-standard HTTP header
		 * References (meta http-equiv="refresh" use is deprecated):
		 *   https://www.w3.org/TR/WCAG10-HTML-TECHS/#meta-element
		 *   https://www.w3.org/TR/WCAG10-CORE-TECHS/#auto-page-refresh
		 *   https://www.w3.org/QA/Tips/reback
		 */
		const long refresh = strtol(con->uri.query->ptr+sizeof("refresh=")-1, NULL, 10);
		if (refresh > 0) {
			buffer_append_string_len(b, CONST_STR_LEN("<meta http-equiv=\"refresh\" content=\""));
			buffer_append_int(b, refresh < 604800 ? refresh : 604800);
			buffer_append_string_len(b, CONST_STR_LEN("\">\n"));
		}
	}

	if (p->conf.sort) {
		buffer_append_string_len(b, CONST_STR_LEN(
					   "<script type=\"text/javascript\">\n"
					   "// <!--\n"
					   "var sort_column;\n"
					   "var prev_span = null;\n"

					   "function get_inner_text(el) {\n"
					   " if((typeof el == 'string')||(typeof el == 'undefined'))\n"
					   "  return el;\n"
					   " if(el.innerText)\n"
					   "  return el.innerText;\n"
					   " else {\n"
					   "  var str = \"\";\n"
					   "  var cs = el.childNodes;\n"
					   "  var l = cs.length;\n"
					   "  for (i=0;i<l;i++) {\n"
					   "   if (cs[i].nodeType==1) str += get_inner_text(cs[i]);\n"
					   "   else if (cs[i].nodeType==3) str += cs[i].nodeValue;\n"
					   "  }\n"
					   " }\n"
					   " return str;\n"
					   "}\n"

					   "function sortfn(a,b) {\n"
					   " var at = get_inner_text(a.cells[sort_column]);\n"
					   " var bt = get_inner_text(b.cells[sort_column]);\n"
					   " if (a.cells[sort_column].className == 'int') {\n"
					   "  return parseInt(at)-parseInt(bt);\n"
					   " } else {\n"
					   "  aa = at.toLowerCase();\n"
					   "  bb = bt.toLowerCase();\n"
					   "  if (aa==bb) return 0;\n"
					   "  else if (aa<bb) return -1;\n"
					   "  else return 1;\n"
					   " }\n"
					   "}\n"

					   "function resort(lnk) {\n"
					   " var span = lnk.childNodes[1];\n"
					   " var table = lnk.parentNode.parentNode.parentNode.parentNode;\n"
					   " var rows = new Array();\n"
					   " for (j=1;j<table.rows.length;j++)\n"
					   "  rows[j-1] = table.rows[j];\n"
					   " sort_column = lnk.parentNode.cellIndex;\n"
					   " rows.sort(sortfn);\n"

					   " if (prev_span != null) prev_span.innerHTML = '';\n"
					   " if (span.getAttribute('sortdir')=='down') {\n"
					   "  span.innerHTML = '&uarr;';\n"
					   "  span.setAttribute('sortdir','up');\n"
					   "  rows.reverse();\n"
					   " } else {\n"
					   "  span.innerHTML = '&darr;';\n"
					   "  span.setAttribute('sortdir','down');\n"
					   " }\n"
					   " for (i=0;i<rows.length;i++)\n"
					   "  table.tBodies[0].appendChild(rows[i]);\n"
					   " prev_span = span;\n"
					   "}\n"
					   "// -->\n"
					   "</script>\n"));
	}

	buffer_append_string_len(b, CONST_STR_LEN(
				 " </head>\n"
				 " <body>\n"));



	/* connection listing */
	buffer_append_string_len(b, CONST_STR_LEN("<h1>Server-Status ("));
	buffer_append_string_buffer(b, con->conf.server_tag);
	buffer_append_string_len(b, CONST_STR_LEN(")</h1>"));

	buffer_append_string_len(b, CONST_STR_LEN("<table summary=\"status\" class=\"status\">"));
	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Hostname</td><td class=\"string\">"));
	buffer_append_string_buffer(b, con->uri.authority);
	buffer_append_string_len(b, CONST_STR_LEN(" ("));
	buffer_append_string_buffer(b, con->request.server_name);
	buffer_append_string_len(b, CONST_STR_LEN(")</td></tr>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Uptime</td><td class=\"string\">"));

	ts = cur_ts - srv->startup_ts;

	days = ts / (60 * 60 * 24);
	ts %= (60 * 60 * 24);

	hours = ts / (60 * 60);
	ts %= (60 * 60);

	mins = ts / (60);
	ts %= (60);

	seconds = ts;

	if (days) {
		buffer_append_int(b, days);
		buffer_append_string_len(b, CONST_STR_LEN(" days "));
	}

	if (hours) {
		buffer_append_int(b, hours);
		buffer_append_string_len(b, CONST_STR_LEN(" hours "));
	}

	if (mins) {
		buffer_append_int(b, mins);
		buffer_append_string_len(b, CONST_STR_LEN(" min "));
	}

	buffer_append_int(b, seconds);
	buffer_append_string_len(b, CONST_STR_LEN(" s"));

	buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Started at</td><td class=\"string\">"));

	ts = srv->startup_ts;

	strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", localtime(&ts));
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"));


	buffer_append_string_len(b, CONST_STR_LEN("<tr><th colspan=\"2\">absolute (since start)</th></tr>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Requests</td><td class=\"string\">"));
	avg = p->abs_requests;

	mod_status_get_multiplier(&avg, &multiplier, 1000);

	buffer_append_int(b, avg);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	buffer_append_string_len(b, CONST_STR_LEN("req</td></tr>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Traffic</td><td class=\"string\">"));
	avg = p->abs_traffic_out;

	mod_status_get_multiplier(&avg, &multiplier, 1024);

	snprintf(buf, sizeof(buf), "%.2f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	buffer_append_string_len(b, CONST_STR_LEN("byte</td></tr>\n"));



	buffer_append_string_len(b, CONST_STR_LEN("<tr><th colspan=\"2\">average (since start)</th></tr>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Requests</td><td class=\"string\">"));
	avg = p->abs_requests / (cur_ts - srv->startup_ts);

	mod_status_get_multiplier(&avg, &multiplier, 1000);

	buffer_append_int(b, avg);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	buffer_append_string_len(b, CONST_STR_LEN("req/s</td></tr>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Traffic</td><td class=\"string\">"));
	avg = p->abs_traffic_out / (cur_ts - srv->startup_ts);

	mod_status_get_multiplier(&avg, &multiplier, 1024);

	snprintf(buf, sizeof(buf), "%.2f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	buffer_append_string_len(b, CONST_STR_LEN("byte/s</td></tr>\n"));



	buffer_append_string_len(b, CONST_STR_LEN("<tr><th colspan=\"2\">average (5s sliding average)</th></tr>\n"));
	for (j = 0, avg = 0; j < 5; j++) {
		avg += p->mod_5s_requests[j];
	}

	avg /= 5;

	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Requests</td><td class=\"string\">"));

	mod_status_get_multiplier(&avg, &multiplier, 1000);

	buffer_append_int(b, avg);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);

	buffer_append_string_len(b, CONST_STR_LEN("req/s</td></tr>\n"));

	for (j = 0, avg = 0; j < 5; j++) {
		avg += p->mod_5s_traffic_out[j];
	}

	avg /= 5;

	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Traffic</td><td class=\"string\">"));

	mod_status_get_multiplier(&avg, &multiplier, 1024);

	snprintf(buf, sizeof(buf), "%.2f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	if (multiplier)	buffer_append_string_len(b, &multiplier, 1);
	buffer_append_string_len(b, CONST_STR_LEN("byte/s</td></tr>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("</table>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<hr />\n<pre>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<b>"));
	buffer_append_int(b, srv->conns.used);
	buffer_append_string_len(b, CONST_STR_LEN(" connections</b>\n"));

	for (j = 0; j < srv->conns.used; ++j) {
		connection *c = srv->conns.ptr[j];
		const char *state;

		if (CON_STATE_READ == c->request.state && !buffer_string_is_empty(c->request.target_orig)) {
			state = "k";
			++cstates[CON_STATE_CLOSE+2];
		} else {
			state = connection_get_short_state(c->request.state);
			++cstates[(c->request.state <= CON_STATE_CLOSE ? c->request.state : CON_STATE_CLOSE+1)];
		}

		buffer_append_string_len(b, state, 1);

		if (((j + 1) % 50) == 0) {
			buffer_append_string_len(b, CONST_STR_LEN("\n"));
		}
	}
	buffer_append_string_len(b, CONST_STR_LEN("\n\n<table>\n"));
	buffer_append_string_len(b, CONST_STR_LEN("<tr><td style=\"text-align:right\">"));
	buffer_append_int(b, cstates[CON_STATE_CLOSE+2]);
	buffer_append_string_len(b, CONST_STR_LEN("<td>&nbsp;&nbsp;k = keep-alive</td></tr>\n"));
	for (j = 0; j < CON_STATE_CLOSE+2; ++j) {
		/*(skip "unknown" state if there are none; there should not be any unknown)*/
		if (0 == cstates[j] && j == CON_STATE_CLOSE+1) continue;
		buffer_append_string_len(b, CONST_STR_LEN("<tr><td style=\"text-align:right\">"));
		buffer_append_int(b, cstates[j]);
		buffer_append_string_len(b, CONST_STR_LEN("</td><td>&nbsp;&nbsp;"));
		buffer_append_string_len(b, connection_get_short_state(j), 1);
		buffer_append_string_len(b, CONST_STR_LEN(" = "));
		buffer_append_string(b, connection_get_state(j));
		buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"));
	}
	buffer_append_string_len(b, CONST_STR_LEN("</table>"));

	buffer_append_string_len(b, CONST_STR_LEN("\n</pre><hr />\n<h2>Connections</h2>\n"));

	buffer_append_string_len(b, CONST_STR_LEN("<table summary=\"status\" class=\"status\">\n"));
	buffer_append_string_len(b, CONST_STR_LEN("<tr>"));
	mod_status_header_append_sort(b, p, "Client IP");
	mod_status_header_append_sort(b, p, "Read");
	mod_status_header_append_sort(b, p, "Written");
	mod_status_header_append_sort(b, p, "State");
	mod_status_header_append_sort(b, p, "Time");
	mod_status_header_append_sort(b, p, "Host");
	mod_status_header_append_sort(b, p, "URI");
	mod_status_header_append_sort(b, p, "File");
	buffer_append_string_len(b, CONST_STR_LEN("</tr>\n"));

	for (j = 0; j < srv->conns.used; ++j) {
		connection *c = srv->conns.ptr[j];

		buffer_append_string_len(b, CONST_STR_LEN("<tr><td class=\"string\">"));

		buffer_append_string_buffer(b, c->dst_addr_buf);

		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"int\">"));

		if (c->request.reqbody_length) {
			buffer_append_int(b, c->request.reqbody_queue->bytes_in);
			buffer_append_string_len(b, CONST_STR_LEN("/"));
			buffer_append_int(b, c->request.reqbody_length);
		} else {
			buffer_append_string_len(b, CONST_STR_LEN("0/0"));
		}

		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"int\">"));

		buffer_append_int(b, c->write_queue->bytes_out);
		buffer_append_string_len(b, CONST_STR_LEN("/"));
		buffer_append_int(b, c->write_queue->bytes_out + chunkqueue_length(c->write_queue));

		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

		if (CON_STATE_READ == c->request.state && !buffer_string_is_empty(c->request.target_orig)) {
			buffer_append_string_len(b, CONST_STR_LEN("keep-alive"));
		} else {
			buffer_append_string(b, connection_get_state(c->request.state));
		}

		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"int\">"));

		buffer_append_int(b, cur_ts - c->request.start_ts);

		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

		if (buffer_string_is_empty(c->request.server_name)) {
			buffer_append_string_buffer(b, c->uri.authority);
		}
		else {
			buffer_append_string_buffer(b, c->request.server_name);
		}

		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

		if (!buffer_string_is_empty(c->uri.path)) {
			buffer_append_string_encoded(b, CONST_BUF_LEN(c->uri.path), ENCODING_HTML);
		}

		if (!buffer_string_is_empty(c->uri.query)) {
			buffer_append_string_len(b, CONST_STR_LEN("?"));
			buffer_append_string_encoded(b, CONST_BUF_LEN(c->uri.query), ENCODING_HTML);
		}

		if (!buffer_string_is_empty(c->request.target_orig)) {
			buffer_append_string_len(b, CONST_STR_LEN(" ("));
			buffer_append_string_encoded(b, CONST_BUF_LEN(c->request.target_orig), ENCODING_HTML);
			buffer_append_string_len(b, CONST_STR_LEN(")"));
		}
		buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

		buffer_append_string_buffer(b, c->physical.path);

		buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"));
	}


	buffer_append_string_len(b, CONST_STR_LEN(
		      "</table>\n"));


	buffer_append_string_len(b, CONST_STR_LEN(
		      " </body>\n"
		      "</html>\n"
		      ));

	chunkqueue_append_buffer_commit(con->write_queue);

	http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));

	return 0;
}


static handler_t mod_status_handle_server_status_text(server *srv, connection *con, plugin_data *p) {
	buffer *b = chunkqueue_append_buffer_open(con->write_queue);
	double avg;
	char buf[32];

	/* output total number of requests */
	buffer_append_string_len(b, CONST_STR_LEN("Total Accesses: "));
	avg = p->abs_requests;
	snprintf(buf, sizeof(buf) - 1, "%.0f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN("\n"));

	/* output total traffic out in kbytes */
	buffer_append_string_len(b, CONST_STR_LEN("Total kBytes: "));
	avg = p->abs_traffic_out / 1024;
	snprintf(buf, sizeof(buf) - 1, "%.0f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN("\n"));

	/* output uptime */
	buffer_append_string_len(b, CONST_STR_LEN("Uptime: "));
	buffer_append_int(b, log_epoch_secs - srv->startup_ts);
	buffer_append_string_len(b, CONST_STR_LEN("\n"));

	/* output busy servers */
	buffer_append_string_len(b, CONST_STR_LEN("BusyServers: "));
	buffer_append_int(b, srv->conns.used);
	buffer_append_string_len(b, CONST_STR_LEN("\n"));

	buffer_append_string_len(b, CONST_STR_LEN("IdleServers: "));
	buffer_append_int(b, srv->conns.size - srv->conns.used);
	buffer_append_string_len(b, CONST_STR_LEN("\n"));

	/* output scoreboard */
	buffer_append_string_len(b, CONST_STR_LEN("Scoreboard: "));
	for (uint32_t i = 0; i < srv->conns.used; ++i) {
		connection *c = srv->conns.ptr[i];
		const char *state =
		  (CON_STATE_READ == c->request.state && !buffer_string_is_empty(c->request.target_orig))
		    ? "k"
		    : connection_get_short_state(c->request.state);
		buffer_append_string_len(b, state, 1);
	}
	for (uint32_t i = 0; i < srv->conns.size - srv->conns.used; ++i) {
		buffer_append_string_len(b, CONST_STR_LEN("_"));
	}
	buffer_append_string_len(b, CONST_STR_LEN("\n"));

	chunkqueue_append_buffer_commit(con->write_queue);

	/* set text/plain output */
	http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/plain"));

	return 0;
}


static handler_t mod_status_handle_server_status_json(server *srv, connection *con, plugin_data *p) {
	buffer *b = chunkqueue_append_buffer_open(con->write_queue);
	double avg;
	char buf[32];
	uint32_t j;
	unsigned int jsonp = 0;

	if (buffer_string_length(con->uri.query) >= sizeof("jsonp=")-1
	   && 0 == memcmp(con->uri.query->ptr, CONST_STR_LEN("jsonp="))) {
		/* not a full parse of query string for multiple parameters,
		* not URL-decoding param and not XML-encoding (XSS protection),
		* so simply ensure that json function name isalnum() or '_' */
		const char *f = con->uri.query->ptr + sizeof("jsonp=")-1;
		int len = 0;
		while (light_isalnum(f[len]) || f[len] == '_') ++len;
		if (0 != len && light_isalpha(f[0]) && f[len] == '\0') {
			buffer_append_string_len(b, f, len);
			buffer_append_string_len(b, CONST_STR_LEN("("));
			jsonp = 1;
		}
	}

	/* output total number of requests */
	buffer_append_string_len(b, CONST_STR_LEN("{\n\t\"RequestsTotal\": "));
	avg = p->abs_requests;
	snprintf(buf, sizeof(buf) - 1, "%.0f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	/* output total traffic out in kbytes */
	buffer_append_string_len(b, CONST_STR_LEN("\t\"TrafficTotal\": "));
	avg = p->abs_traffic_out / 1024;
	snprintf(buf, sizeof(buf) - 1, "%.0f", avg);
	buffer_append_string(b, buf);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	/* output uptime */
	buffer_append_string_len(b, CONST_STR_LEN("\t\"Uptime\": "));
	buffer_append_int(b, log_epoch_secs - srv->startup_ts);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	/* output busy servers */
	buffer_append_string_len(b, CONST_STR_LEN("\t\"BusyServers\": "));
	buffer_append_int(b, srv->conns.used);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	buffer_append_string_len(b, CONST_STR_LEN("\t\"IdleServers\": "));
	buffer_append_int(b, srv->conns.size - srv->conns.used);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	for (j = 0, avg = 0; j < 5; j++) {
		avg += p->mod_5s_requests[j];
	}

	avg /= 5;

	buffer_append_string_len(b, CONST_STR_LEN("\t\"RequestAverage5s\":"));
	buffer_append_int(b, avg);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	for (j = 0, avg = 0; j < 5; j++) {
		avg += p->mod_5s_traffic_out[j];
	}

	avg /= 5;

	buffer_append_string_len(b, CONST_STR_LEN("\t\"TrafficAverage5s\":"));
	buffer_append_int(b, avg / 1024); /* kbps */
	buffer_append_string_len(b, CONST_STR_LEN("\n}"));

	if (jsonp) buffer_append_string_len(b, CONST_STR_LEN(");"));

	chunkqueue_append_buffer_commit(con->write_queue);

	/* set text/plain output */
	http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("application/javascript"));

	return 0;
}


static handler_t mod_status_handle_server_statistics(connection *con) {
	buffer *b;
	size_t i;
	array *st = &plugin_stats;

	if (0 == st->used) {
		/* we have nothing to send */
		con->http_status = 204;
		con->response.resp_body_finished = 1;

		return HANDLER_FINISHED;
	}

	b = chunkqueue_append_buffer_open(con->write_queue);
	for (i = 0; i < st->used; i++) {
		buffer_append_string_buffer(b, &st->sorted[i]->key);
		buffer_append_string_len(b, CONST_STR_LEN(": "));
		buffer_append_int(b, ((data_integer *)st->sorted[i])->value);
		buffer_append_string_len(b, CONST_STR_LEN("\n"));
	}
	chunkqueue_append_buffer_commit(con->write_queue);

	http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/plain"));

	con->http_status = 200;
	con->response.resp_body_finished = 1;

	return HANDLER_FINISHED;
}


static handler_t mod_status_handle_server_status(connection *con, plugin_data *p) {
	server * const srv = con->srv;
	if (buffer_is_equal_string(con->uri.query, CONST_STR_LEN("auto"))) {
		mod_status_handle_server_status_text(srv, con, p);
	} else if (buffer_string_length(con->uri.query) >= sizeof("json")-1
		   && 0 == memcmp(con->uri.query->ptr, CONST_STR_LEN("json"))) {
		mod_status_handle_server_status_json(srv, con, p);
	} else {
		mod_status_handle_server_status_html(srv, con, p);
	}

	con->http_status = 200;
	con->response.resp_body_finished = 1;

	return HANDLER_FINISHED;
}


static handler_t mod_status_handle_server_config(connection *con) {
	server * const srv = con->srv;
	buffer *b = chunkqueue_append_buffer_open(con->write_queue);

	buffer_copy_string_len(b, CONST_STR_LEN(
			   "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
			   "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
			   "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
			   "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
			   " <head>\n"
			   "  <title>Status</title>\n"
			   " </head>\n"
			   " <body>\n"
			   "  <h1>"));
	buffer_append_string_buffer(b, con->conf.server_tag);
	buffer_append_string_len(b, CONST_STR_LEN(
			   "</h1>\n"
			   "  <table summary=\"status\" border=\"1\">\n"));

	mod_status_header_append(b, "Server-Features");
#ifdef HAVE_PCRE_H
	mod_status_row_append(b, "RegEx Conditionals", "enabled");
#else
	mod_status_row_append(b, "RegEx Conditionals", "disabled - pcre missing");
#endif
	mod_status_header_append(b, "Network Engine");

	mod_status_row_append(b, "fd-Event-Handler", srv->srvconf.event_handler);

	mod_status_header_append(b, "Config-File-Settings");

	buffer *m = srv->tmp_buf;
	buffer_clear(m);
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		const char *name = ((plugin **)srv->plugins.ptr)[i]->name;
		if (i != 0) {
			buffer_append_string_len(m, CONST_STR_LEN("<br />"));
		}
		buffer_append_string_len(m, name, strlen(name));
	}
	mod_status_row_append(b, "Loaded Modules", m->ptr);

	buffer_append_string_len(b, CONST_STR_LEN("  </table>\n"));

	buffer_append_string_len(b, CONST_STR_LEN(
		      " </body>\n"
		      "</html>\n"
		      ));

	chunkqueue_append_buffer_commit(con->write_queue);

	http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));

	con->http_status = 200;
	con->response.resp_body_finished = 1;

	return HANDLER_FINISHED;
}

static handler_t mod_status_handler(connection *con, void *p_d) {
	plugin_data *p = p_d;

	if (NULL != con->response.handler_module) return HANDLER_GO_ON;

	mod_status_patch_config(con, p);

	if (!buffer_string_is_empty(p->conf.status_url) &&
	    buffer_is_equal(p->conf.status_url, con->uri.path)) {
		return mod_status_handle_server_status(con, p);
	} else if (!buffer_string_is_empty(p->conf.config_url) &&
	    buffer_is_equal(p->conf.config_url, con->uri.path)) {
		return mod_status_handle_server_config(con);
	} else if (!buffer_string_is_empty(p->conf.statistics_url) &&
	    buffer_is_equal(p->conf.statistics_url, con->uri.path)) {
		return mod_status_handle_server_statistics(con);
	}

	return HANDLER_GO_ON;
}

TRIGGER_FUNC(mod_status_trigger) {
	plugin_data *p = p_d;

	/* check all connections */
	for (uint32_t i = 0; i < srv->conns.used; ++i) {
		connection *c = srv->conns.ptr[i];

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

	p->requests++;
	p->rel_requests++;
	p->abs_requests++;

	p->bytes_written += con->bytes_written_cur_second;

	return HANDLER_GO_ON;
}


int mod_status_plugin_init(plugin *p);
int mod_status_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "status";

	p->init        = mod_status_init;
	p->set_defaults= mod_status_set_defaults;

	p->handle_uri_clean    = mod_status_handler;
	p->handle_trigger      = mod_status_trigger;
	p->handle_request_done = mod_status_account;

	return 0;
}
