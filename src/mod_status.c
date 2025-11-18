#include "first.h"

#include "base.h"
#include "fdevent.h"
#include "http_chunk.h"
#include "http_header.h"
#include "http_status.h"
#include "log.h"

#include "plugin.h"

#include <sys/types.h>
#include "sys-time.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
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

	off_t bytes_written_1s;
	off_t requests_1s;
	off_t abs_traffic_out;
	off_t abs_requests;

	off_t traffic_out_5s[5];
	off_t requests_5s[5];
	int ndx_5s;
} plugin_data;

INIT_FUNC(mod_status_init) {
    return ck_calloc(1, sizeof(plugin_data));
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

static void mod_status_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_status_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
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

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* status.status-url */
              case 1: /* status.config-url */
              case 2: /* status.statistics-url */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 3: /* status.enable-sort */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.sort = 1;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_status_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


static void mod_status_header_append_sort(buffer *b, const plugin_config * const pconf, const char* k, size_t klen)
{
    pconf->sort
      ? buffer_append_str3(b,
          CONST_STR_LEN("<th class=\"status\"><a href=\"#\" class=\"sortheader\" onclick=\"resort(this);return false;\">"),
          k, klen,
          CONST_STR_LEN("<span class=\"sortarrow\">:</span></a></th>\n"))
      : buffer_append_str3(b,
          CONST_STR_LEN("<th class=\"status\">"),
          k, klen,
          CONST_STR_LEN("</th>\n"));
}

static void mod_status_get_multiplier(buffer *b, double avg, int size) {
    char unit[] = "  ";

    if (avg > size) { avg /= size; unit[1] = 'k'; }
    if (avg > size) { avg /= size; unit[1] = 'M'; }
    if (avg > size) { avg /= size; unit[1] = 'G'; }
    if (avg > size) { avg /= size; unit[1] = 'T'; }
    if (avg > size) { avg /= size; unit[1] = 'P'; }
    if (avg > size) { avg /= size; unit[1] = 'E'; }
    if (avg > size) { avg /= size; unit[1] = 'Z'; }
    if (avg > size) { avg /= size; unit[1] = 'Y'; }

    if (size == 1000) {
        buffer_append_int(b, (intmax_t)avg);
    }
    else { /* (size == 1024) */
        char buf[32+1];
        buffer_append_string_len(b, buf, (size_t)
                                 snprintf(buf, sizeof(buf), "%.2f", avg));
    }
    buffer_append_string_len(b, unit, 2);
}

static void mod_status_html_rtable_r (buffer * const b, const request_st * const r, const unix_time64_t cur_ts) {
    buffer_append_str3(b, CONST_STR_LEN("<tr><td class=\"string\">"),
                          BUF_PTR_LEN(r->dst_addr_buf),
                          CONST_STR_LEN("</td><td class=\"int\">"));

    if (r->reqbody_length) {
        buffer_append_int(b, (r->http_version <= HTTP_VERSION_1_1
                              || (r->http_version == HTTP_VERSION_2
                                  && r->x.h2.id)
                             )
                             ? r->reqbody_queue.bytes_in
                             : http_request_stats_bytes_in(r));
        buffer_append_char(b, '/');
        buffer_append_int(b, r->reqbody_length);
    }
    else
        buffer_append_string_len(b, CONST_STR_LEN("0/0"));

    buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"int\">"));

    buffer_append_int(b, r->write_queue.bytes_out);
    buffer_append_char(b, '/');
    buffer_append_int(b, r->write_queue.bytes_in);

    buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

    if (http_request_state_is_keep_alive(r))
        buffer_append_string_len(b, CONST_STR_LEN("keep-alive"));
    else
        http_request_state_append(b, r->state);

    buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"int\">"));

    buffer_append_int(b, cur_ts - r->start_hp.tv_sec);

    buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

    if (buffer_is_blank(r->server_name))
        buffer_append_string_encoded(b, BUF_PTR_LEN(&r->uri.authority), ENCODING_HTML);
    else
        buffer_append_string_encoded(b, BUF_PTR_LEN(r->server_name), ENCODING_HTML);

    buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

    if (!buffer_is_blank(&r->uri.path))
        buffer_append_string_encoded(b, BUF_PTR_LEN(&r->uri.path), ENCODING_HTML);

    if (!buffer_is_blank(&r->uri.query)) {
        buffer_append_char(b, '?');
        buffer_append_string_encoded(b, BUF_PTR_LEN(&r->uri.query), ENCODING_HTML);
    }

    if (!buffer_is_blank(&r->target_orig)) {
        buffer_append_string_len(b, CONST_STR_LEN(" ("));
        buffer_append_string_encoded(b, BUF_PTR_LEN(&r->target_orig), ENCODING_HTML);
        buffer_append_char(b, ')');
    }
    buffer_append_string_len(b, CONST_STR_LEN("</td><td class=\"string\">"));

    buffer_append_string_encoded(b, BUF_PTR_LEN(&r->physical.path), ENCODING_HTML);

    buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"));
}

static void mod_status_html_rtable (request_st * const rq, const server * const srv, const unix_time64_t cur_ts) {
    /* connection table and URLs might be large, so double-buffer to aggregate
     * before sending to chunkqueue, which might be temporary file
     * (avoid write() per connection) */
    buffer * const b = rq->tmp_buf;
    buffer_clear(b);
    for (const connection *con = srv->conns; con; con = con->next) {
        const request_st * const r = &con->request;
        hxcon * const h2c = con->hx;
        { /*(r->http_version <= HTTP_VERSION_1_1 or HTTP/2 stream id 0)*/
            if (buffer_string_space(b) < 4096) {
                http_chunk_append_mem(rq, BUF_PTR_LEN(b));
                buffer_clear(b);
            }
            mod_status_html_rtable_r(b, r, cur_ts);
        }
        if (NULL != h2c) {
            for (uint32_t j = 0, rused = h2c->rused; j < rused; ++j) {
                if (buffer_string_space(b) < 4096) {
                    http_chunk_append_mem(rq, BUF_PTR_LEN(b));
                    buffer_clear(b);
                }
                mod_status_html_rtable_r(b, h2c->r[j], cur_ts);
            }
        }
    }
    http_chunk_append_mem(rq, BUF_PTR_LEN(b));
}

static handler_t mod_status_handle_server_status_html(server *srv, request_st * const r, const plugin_data * const p, const plugin_config * const pconf) {
	buffer * const b = chunkqueue_append_buffer_open(&r->write_queue);
	buffer_string_prepare_append(b, 8192-1);/*(status page base HTML is ~5.2k)*/
	double avg;
	unix_time64_t ts;
	const unix_time64_t cur_ts = log_epoch_secs;

	int days, hours, mins, seconds;

	/*(CON_STATE_CLOSE must be last state in enum connection_state_t)*/
	int cstates[CON_STATE_CLOSE+3];
	memset(cstates, 0, sizeof(cstates));

	buffer_copy_string_len(b, CONST_STR_LEN(
				 "<!DOCTYPE html>\n"
				 "<html lang=\"en\">\n"
				 " <head>\n"
				 "  <meta charset=\"UTF-8\" />\n"
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

	if (!buffer_is_blank(&r->uri.query) && 0 == memcmp(r->uri.query.ptr, CONST_STR_LEN("refresh="))) {
		/* Note: Refresh is an historical, but non-standard HTTP header
		 * References (meta http-equiv="refresh" use is deprecated):
		 *   https://www.w3.org/TR/WCAG10-HTML-TECHS/#meta-element
		 *   https://www.w3.org/TR/WCAG10-CORE-TECHS/#auto-page-refresh
		 *   https://www.w3.org/QA/Tips/reback
		 */
		const long refresh = strtol(r->uri.query.ptr+sizeof("refresh=")-1, NULL, 10);
		if (refresh > 0) {
			buffer_append_string_len(b, CONST_STR_LEN("<meta http-equiv=\"refresh\" content=\""));
			buffer_append_int(b, refresh < 604800 ? refresh : 604800);
			buffer_append_string_len(b, CONST_STR_LEN("\">\n"));
		}
	}

	if (pconf->sort) {
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
				 "<body>\n"));



	/* connection listing */
	buffer_append_string_len(b,
	                      CONST_STR_LEN("<h1>Server-Status"));
	if (r->conf.server_tag)
		buffer_append_str3(b, CONST_STR_LEN(
			      " ("),
	                      BUF_PTR_LEN(r->conf.server_tag),
	                      CONST_STR_LEN(
			      ")"));
	buffer_append_string_len(b,
	                      CONST_STR_LEN("</h1>"
	                                    "<table summary=\"status\" class=\"status\">"
	                                    "<tr><td>Hostname</td><td class=\"string\">"));
	buffer_append_string_encoded(b, BUF_PTR_LEN(&r->uri.authority), ENCODING_HTML);
	if (!buffer_is_blank(r->server_name) && r->server_name != &r->uri.authority) {
		buffer_append_string_len(b, CONST_STR_LEN(" ("));
		buffer_append_string_encoded(b, BUF_PTR_LEN(r->server_name), ENCODING_HTML);
		buffer_append_char(b, ')');
	}
	buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"
	                                          "<tr><td>Uptime</td><td class=\"string\">"));

	ts = cur_ts - srv->startup_ts;

	days = ts / (60 * 60 * 24);
	ts %= (60 * 60 * 24);

	hours = ts / (60 * 60);
	ts %= (60 * 60);

	mins = ts / (60);
	seconds = ts % (60);

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
	buffer_append_string_len(b, CONST_STR_LEN(" s"
	                                          "</td></tr>\n"
	                                          "<tr><td>Started at</td><td class=\"string\">"));

	ts = srv->startup_ts;

	struct tm tm;
  #ifdef __MINGW32__
	buffer_append_strftime(b, "%Y-%m-%d %H:%M:%S", localtime64_r(&ts, &tm));
  #else
	buffer_append_strftime(b, "%F %T", localtime64_r(&ts, &tm));
  #endif
	buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"
	                                          "<tr><th colspan=\"2\">absolute (since start)</th></tr>\n"
	                                          "<tr><td>Requests</td><td class=\"string\">"));
	avg = (double)p->abs_requests;
	mod_status_get_multiplier(b, avg, 1000);
	buffer_append_string_len(b, CONST_STR_LEN("req</td></tr>\n"
	                                          "<tr><td>Traffic</td><td class=\"string\">"));
	avg = (double)p->abs_traffic_out;
	mod_status_get_multiplier(b, avg, 1024);
	buffer_append_string_len(b, CONST_STR_LEN("byte</td></tr>\n"
	                                          "<tr><th colspan=\"2\">average (since start)</th></tr>\n"
	                                          "<tr><td>Requests</td><td class=\"string\">"));
	avg = (double)p->abs_requests / (cur_ts - srv->startup_ts);
	mod_status_get_multiplier(b, avg, 1000);
	buffer_append_string_len(b, CONST_STR_LEN("req/s</td></tr>\n"
	                                          "<tr><td>Traffic</td><td class=\"string\">"));
	avg = (double)p->abs_traffic_out / (cur_ts - srv->startup_ts);
	mod_status_get_multiplier(b, avg, 1024);
	buffer_append_string_len(b, CONST_STR_LEN("byte/s</td></tr>\n"
	                                          "<tr><th colspan=\"2\">average (5s sliding average)</th></tr>\n"));

	avg = (double)(p->requests_5s[0]
	             + p->requests_5s[1]
	             + p->requests_5s[2]
	             + p->requests_5s[3]
	             + p->requests_5s[4]);
	avg /= 5;
	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Requests</td><td class=\"string\">"));
	mod_status_get_multiplier(b, avg, 1000);
	buffer_append_string_len(b, CONST_STR_LEN("req/s</td></tr>\n"));

	avg = (double)(p->traffic_out_5s[0]
	             + p->traffic_out_5s[1]
	             + p->traffic_out_5s[2]
	             + p->traffic_out_5s[3]
	             + p->traffic_out_5s[4]);
	avg /= 5;
	buffer_append_string_len(b, CONST_STR_LEN("<tr><td>Traffic</td><td class=\"string\">"));
	mod_status_get_multiplier(b, avg, 1024);
	buffer_append_string_len(b, CONST_STR_LEN("byte/s</td></tr>\n"
	                                          "</table>\n"
	                                          "<hr />\n<pre>\n"
	                                          "<b>"));
	buffer_append_int(b, srv->srvconf.max_conns - srv->lim_conns);
	buffer_append_string_len(b, CONST_STR_LEN(" connections</b>\n"));

	int per_line = 50;
	char *s = buffer_extend(b, srv->srvconf.max_conns - srv->lim_conns
	                         +(srv->srvconf.max_conns - srv->lim_conns)/50);
	for (const connection *c = srv->conns; c; c = c->next) {
		const request_st * const cr = &c->request;
		if (http_con_state_is_keep_alive(c)) {
			*s++ = 'k';
			++cstates[CON_STATE_CLOSE+2];
		} else {
			*s++ = *(http_request_state_short(cr->state));
			++cstates[(cr->state <= CON_STATE_CLOSE ? cr->state : CON_STATE_CLOSE+1)];
		}

		if (0 == --per_line) {
			per_line = 50;
			*s++ = '\n';
		}
	}
	buffer_append_string_len(b, CONST_STR_LEN("\n\n<table>\n"
	                                          "<tr><td style=\"text-align:right\">"));
	buffer_append_int(b, cstates[CON_STATE_CLOSE+2]);
	buffer_append_string_len(b, CONST_STR_LEN("<td>&nbsp;&nbsp;k = keep-alive</td></tr>\n"));
	for (int j = 0; j < CON_STATE_CLOSE+2; ++j) {
		/*(skip "unknown" state if there are none; there should not be any unknown)*/
		if (0 == cstates[j] && j == CON_STATE_CLOSE+1) continue;
		buffer_append_string_len(b, CONST_STR_LEN("<tr><td style=\"text-align:right\">"));
		buffer_append_int(b, cstates[j]);
		buffer_append_str3(b, CONST_STR_LEN("</td><td>&nbsp;&nbsp;"),
		                      http_request_state_short(j), 1,
		                      CONST_STR_LEN(" = "));
		http_request_state_append(b, j);
		buffer_append_string_len(b, CONST_STR_LEN("</td></tr>\n"));
	}
	buffer_append_string_len(b, CONST_STR_LEN(
	  "</table>\n"
	  "</pre><hr />\n<h2>Connections</h2>\n"
	  "<table summary=\"status\" class=\"status\">\n"
	  "<tr>"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("Client IP"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("Read"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("Written"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("State"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("Time"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("Host"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("URI"));
	mod_status_header_append_sort(b, pconf, CONST_STR_LEN("File"));
	buffer_append_string_len(b, CONST_STR_LEN("</tr>\n"));

	chunkqueue_append_buffer_commit(&r->write_queue);
	/* connection table might be large, so buffer separately */

	mod_status_html_rtable(r, srv, cur_ts);

	http_chunk_append_mem(r, CONST_STR_LEN(
		      "</table>\n"
		      "</body>\n"
		      "</html>\n"
		      ));

	http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));

	return 0;
}


static handler_t mod_status_handle_server_status_text(server *srv, request_st * const r, const plugin_data * const p) {
	buffer *b = chunkqueue_append_buffer_open(&r->write_queue);

	/* output total number of requests */
	buffer_append_string_len(b, CONST_STR_LEN("Total Accesses: "));
	buffer_append_int(b, (intmax_t)p->abs_requests);

	buffer_append_string_len(b, CONST_STR_LEN("\nTotal kBytes: "));
	buffer_append_int(b, (intmax_t)(p->abs_traffic_out / 1024));

	buffer_append_string_len(b, CONST_STR_LEN("\nUptime: "));
	buffer_append_int(b, log_epoch_secs - srv->startup_ts);

	buffer_append_string_len(b, CONST_STR_LEN("\nBusyServers: "));
	buffer_append_int(b, srv->srvconf.max_conns - srv->lim_conns);

	buffer_append_string_len(b, CONST_STR_LEN("\nIdleServers: "));
	buffer_append_int(b, srv->lim_conns); /*(could omit)*/

	buffer_append_string_len(b, CONST_STR_LEN("\nScoreboard: "));
	char *s = buffer_extend(b, srv->srvconf.max_conns+1);
	for (const connection *c = srv->conns; c; c = c->next)
		*s++ = *(http_con_state_short(c));
	memset(s, '_', srv->lim_conns); /*(could omit)*/
	s += srv->lim_conns;
	*s = '\n';

	chunkqueue_append_buffer_commit(&r->write_queue);

	/* set text/plain output */
	http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/plain"));

	return 0;
}


static handler_t mod_status_handle_server_status_json(server *srv, request_st * const r, const plugin_data * const p) {
	buffer *b = chunkqueue_append_buffer_open(&r->write_queue);
	off_t avg;
	unsigned int jsonp = 0;

	if (buffer_clen(&r->uri.query) >= sizeof("jsonp=")-1
	    && 0 == memcmp(r->uri.query.ptr, CONST_STR_LEN("jsonp="))) {
		/* not a full parse of query string for multiple parameters,
		* not URL-decoding param and not XML-encoding (XSS protection),
		* so simply ensure that json function name isalnum() or '_' */
		const char *f = r->uri.query.ptr + sizeof("jsonp=")-1;
		int len = 0;
		while (light_isalnum(f[len]) || f[len] == '_') ++len;
		if (0 != len && light_isalpha(f[0]) && f[len] == '\0') {
			buffer_append_str2(b, f, len, CONST_STR_LEN("("));
			jsonp = 1;
		}
	}

	buffer_append_string_len(b, CONST_STR_LEN("{\n\t\"RequestsTotal\": "));
	buffer_append_int(b, (intmax_t)p->abs_requests);

	buffer_append_string_len(b, CONST_STR_LEN(",\n\t\"TrafficTotal\": "));
	buffer_append_int(b, (intmax_t)(p->abs_traffic_out / 1024));

	buffer_append_string_len(b, CONST_STR_LEN(",\n\t\"Uptime\": "));
	buffer_append_int(b, log_epoch_secs - srv->startup_ts);

	buffer_append_string_len(b, CONST_STR_LEN(",\n\t\"BusyServers\": "));
	buffer_append_int(b, srv->srvconf.max_conns - srv->lim_conns);

	buffer_append_string_len(b, CONST_STR_LEN(",\n\t\"IdleServers\": "));
	buffer_append_int(b, srv->lim_conns); /*(could omit)*/
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	avg = p->requests_5s[0]
	    + p->requests_5s[1]
	    + p->requests_5s[2]
	    + p->requests_5s[3]
	    + p->requests_5s[4];
	avg /= 5;

	buffer_append_string_len(b, CONST_STR_LEN("\t\"RequestAverage5s\":"));
	buffer_append_int(b, avg);
	buffer_append_string_len(b, CONST_STR_LEN(",\n"));

	avg = p->traffic_out_5s[0]
	    + p->traffic_out_5s[1]
	    + p->traffic_out_5s[2]
	    + p->traffic_out_5s[3]
	    + p->traffic_out_5s[4];
	avg /= 5;

	buffer_append_string_len(b, CONST_STR_LEN("\t\"TrafficAverage5s\":"));
	buffer_append_int(b, avg / 1024); /* kbps */
	buffer_append_string_len(b, CONST_STR_LEN("\n}"));

	if (jsonp) buffer_append_string_len(b, CONST_STR_LEN(");"));

	chunkqueue_append_buffer_commit(&r->write_queue);
	http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
	                         CONST_STR_LEN("Content-Type"),
	                         CONST_STR_LEN("application/javascript"));
	return 0;
}


static handler_t mod_status_handle_server_statistics(request_st * const r) {
	http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
	                         CONST_STR_LEN("Content-Type"),
	                         CONST_STR_LEN("text/plain"));

	const array * const st = &plugin_stats;
	if (0 == st->used) {
		/* we have nothing to send */
		http_status_set_fin(r, 204);
		return HANDLER_FINISHED;
	}

	buffer * const b = chunkqueue_append_buffer_open(&r->write_queue);
	for (uint32_t i = 0; i < st->used; ++i) {
		buffer_append_str2(b, BUF_PTR_LEN(&st->sorted[i]->key),
		                      CONST_STR_LEN(": "));
		buffer_append_int(b, ((data_integer *)st->sorted[i])->value);
		buffer_append_char(b, '\n');
	}
	chunkqueue_append_buffer_commit(&r->write_queue);

	http_status_set_fin(r, 200);
	return HANDLER_FINISHED;
}


static handler_t mod_status_handle_server_status(request_st * const r, const plugin_data * const p, const plugin_config * const pconf) {
	server * const srv = r->con->srv;
	if (buffer_is_equal_string(&r->uri.query, CONST_STR_LEN("auto"))) {
		mod_status_handle_server_status_text(srv, r, p);
	} else if (buffer_clen(&r->uri.query) >= sizeof("json")-1
		   && 0 == memcmp(r->uri.query.ptr, CONST_STR_LEN("json"))) {
		mod_status_handle_server_status_json(srv, r, p);
	} else {
		mod_status_handle_server_status_html(srv, r, p, pconf);
	}

	http_status_set_fin(r, 200);
	return HANDLER_FINISHED;
}


static void mod_status_row_append(buffer *b, const char *k, size_t klen, const char *v, size_t vlen)
{
    struct const_iovec iov[] = {
      { CONST_STR_LEN("   <tr>\n"
                      "    <td><b>") }
     ,{ k, klen }
     ,{ CONST_STR_LEN("</b></td>\n"
                      "    <td>") }
     ,{ v, vlen }
     ,{ CONST_STR_LEN("</td>\n"
                      "   </tr>\n") }
    };
    buffer_append_iovec(b, iov, sizeof(iov)/sizeof(*iov));
}

static void mod_status_header_append(buffer *b, const char *k, size_t klen)
{
    buffer_append_str3(b,
      CONST_STR_LEN("   <tr>\n"
	            "    <th colspan=\"2\">"),
      k, klen,
      CONST_STR_LEN("</th>\n"
	            "   </tr>\n"));
}

static handler_t mod_status_handle_server_config(request_st * const r) {
	server * const srv = r->con->srv;
	buffer * const tb = r->tmp_buf;
	buffer_clear(tb);
	for (uint32_t i = 0; i < srv->plugins.used; ++i) {
		const char *name = ((plugin **)srv->plugins.ptr)[i]->name;
		if (i != 0) {
			buffer_append_string_len(tb, CONST_STR_LEN("<br />"));
		}
		buffer_append_string_len(tb, name, strlen(name));
	}

	buffer *b = chunkqueue_append_buffer_open(&r->write_queue);

	/*(could expand the following into a single buffer_append_iovec(),
	 * but this routine is not expected to be under high load)*/

	buffer_append_string_len(b, CONST_STR_LEN(
			   "<!DOCTYPE html>\n"
			   "<html lang=\"en\">\n"
			   " <head>\n"
			   "  <meta charset=\"UTF-8\" />\n"
			   "  <title>Status</title>\n"
			   " </head>\n"
			   " <body>\n"));

	if (r->conf.server_tag)
		buffer_append_str3(b, CONST_STR_LEN(
			   "  <h1>"),
	                   BUF_PTR_LEN(r->conf.server_tag),
	                   CONST_STR_LEN(
			   "  </h1>\n"));

	buffer_append_string_len(b, CONST_STR_LEN(
			   "  <table summary=\"status\" border=\"1\">\n"));

	mod_status_header_append(b, CONST_STR_LEN("Server-Features"));
#ifdef HAVE_PCRE
	mod_status_row_append(b, CONST_STR_LEN("RegEx Conditionals"), CONST_STR_LEN("enabled"));
#else
	mod_status_row_append(b, CONST_STR_LEN("RegEx Conditionals"), CONST_STR_LEN("disabled - pcre missing"));
#endif
	mod_status_header_append(b, CONST_STR_LEN("Network Engine"));

	mod_status_row_append(b, CONST_STR_LEN("fd-Event-Handler"),
                                 srv->srvconf.event_handler,
                                 strlen(srv->srvconf.event_handler));

	mod_status_header_append(b, CONST_STR_LEN("Config-File-Settings"));

	mod_status_row_append(b, CONST_STR_LEN("Loaded Modules"), BUF_PTR_LEN(tb));

	buffer_append_string_len(b, CONST_STR_LEN(
		      "  </table>\n"
		      " </body>\n"
		      "</html>\n"
		      ));

	chunkqueue_append_buffer_commit(&r->write_queue);

	http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));

	http_status_set_fin(r, 200);
	return HANDLER_FINISHED;
}

static handler_t mod_status_handler(request_st * const r, void *p_d) {
	if (NULL != r->handler_module) return HANDLER_GO_ON;

	plugin_config pconf;
	mod_status_patch_config(r, p_d, &pconf);

	if (pconf.status_url &&
	    buffer_is_equal(pconf.status_url, &r->uri.path)) {
		return mod_status_handle_server_status(r, p_d, &pconf);
	}
	else if (pconf.config_url &&
	    buffer_is_equal(pconf.config_url, &r->uri.path)) {
		return mod_status_handle_server_config(r);
	}
	else if (pconf.statistics_url &&
	    buffer_is_equal(pconf.statistics_url, &r->uri.path)) {
		return mod_status_handle_server_statistics(r);
	}

	return HANDLER_GO_ON;
}

TRIGGER_FUNC(mod_status_trigger) {
    plugin_data * const p = p_d;

    /* check all connections */
    for (const connection *c = srv->conns; c; c = c->next)
        p->bytes_written_1s += c->bytes_written_cur_second;

    /* used in calculating sliding average */
    p->traffic_out_5s[p->ndx_5s] = p->bytes_written_1s;
    p->requests_5s   [p->ndx_5s] = p->requests_1s;
    if (++p->ndx_5s == 5) p->ndx_5s = 0;

    p->abs_traffic_out += p->bytes_written_1s;
    p->abs_requests += p->requests_1s;

    p->bytes_written_1s = 0;
    p->requests_1s = 0;

    return HANDLER_GO_ON;
}

REQUESTDONE_FUNC(mod_status_account) {
    plugin_data * const p = p_d;
    const connection * const con = r->con;

    /* thread-safety todo: atomics, or lock around modification */
    ++p->requests_1s;
    if (r == &con->request) /*(HTTP/1.x or only HTTP/2 stream 0)*/
        p->bytes_written_1s += con->bytes_written_cur_second;

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
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
