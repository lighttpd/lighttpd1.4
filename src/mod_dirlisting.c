#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "fdevent.h"
#include "http_header.h"

#include "plugin.h"

#include "stat_cache.h"

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

/**
 * this is a dirlisting for a lighttpd plugin
 */

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
#endif

#ifdef HAVE_SYS_EXTATTR_H
#include <sys/extattr.h>
#endif

typedef struct {
	char dir_listing;
	char hide_dot_files;
	char hide_readme_file;
	char encode_readme;
	char hide_header_file;
	char encode_header;
	char auto_layout;

      #ifdef HAVE_PCRE_H
	pcre **excludes;
      #else
	void *excludes;
      #endif

	const buffer *show_readme;
	const buffer *show_header;
	const buffer *external_css;
	const buffer *external_js;
	const buffer *encoding;
	const buffer *set_footer;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config defaults;
	plugin_config conf;

	buffer tmp_buf;
} plugin_data;

#ifdef HAVE_PCRE_H

static pcre ** mod_dirlisting_parse_excludes(server *srv, const array *a) {
    pcre **regexes = calloc(a->used + 1, sizeof(pcre *));
    force_assert(regexes);
    for (uint32_t j = 0; j < a->used; ++j) {
        const data_string *ds = (const data_string *)a->data[j];
        const char *errptr;
        int erroff;
        regexes[j] = pcre_compile(ds->value.ptr, 0, &errptr, &erroff, NULL);
        if (NULL == regexes[j]) {
            log_error(srv->errh, __FILE__, __LINE__,
              "pcre_compile failed for: %s", ds->value.ptr);
            for (pcre **regex = regexes; *regex; ++regex) pcre_free(*regex);
            free(regexes);
            return NULL;
        }
    }
    return regexes;
}

static int mod_dirlisting_exclude(log_error_st *errh, pcre **regex, const char *name, size_t len) {
    for(; *regex; ++regex) {
        #define N 10
        int ovec[N * 3];
        int n;
        if ((n = pcre_exec(*regex, NULL, name, len, 0, 0, ovec, 3 * N)) < 0) {
            if (n == PCRE_ERROR_NOMATCH) continue;

            log_error(errh, __FILE__, __LINE__,
              "execution error while matching: %d", n);
            /* aborting would require a lot of manual cleanup here.
             * skip instead (to not leak names that break pcre matching)
             */
        }
        return 1;
        #undef N
    }
    return 0; /* no match */
}

#else

#define mod_dirlisting_exclude(a, b, c, d) 0

#endif


INIT_FUNC(mod_dirlisting_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_dirlisting_free) {
    plugin_data * const p = p_d;
    free(p->tmp_buf.ptr);
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
             #ifdef HAVE_PCRE_H
              case 2: /* dir-listing.exclude */
                if (cpv->vtype != T_CONFIG_LOCAL) continue;
                for (pcre **regex = cpv->v.v; *regex; ++regex)
                    pcre_free(*regex);
                free(cpv->v.v);
                break;
             #endif
              default:
                break;
            }
        }
    }
}

static void mod_dirlisting_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* dir-listing.activate */
      case 1: /* server.dir-listing *//*(historical)*/
        pconf->dir_listing = (char)cpv->v.u;
        break;
      case 2: /* dir-listing.exclude */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->excludes = cpv->v.v;
        break;
      case 3: /* dir-listing.hide-dotfiles */
        pconf->hide_dot_files = (char)cpv->v.u;
        break;
      case 4: /* dir-listing.external-css */
        pconf->external_css = cpv->v.b;
        break;
      case 5: /* dir-listing.external-js */
        pconf->external_js = cpv->v.b;
        break;
      case 6: /* dir-listing.encoding */
        pconf->encoding = cpv->v.b;
        break;
      case 7: /* dir-listing.show-readme */
        pconf->show_readme = cpv->v.b;
        break;
      case 8: /* dir-listing.hide-readme-file */
        pconf->hide_readme_file = (char)cpv->v.u;
        break;
      case 9: /* dir-listing.show-header */
        pconf->show_header = cpv->v.b;
        break;
      case 10:/* dir-listing.hide-header-file */
        pconf->hide_header_file = (char)cpv->v.u;
        break;
      case 11:/* dir-listing.set-footer */
        pconf->set_footer = cpv->v.b;
        break;
      case 12:/* dir-listing.encode-readme */
        pconf->encode_readme = (char)cpv->v.u;
        break;
      case 13:/* dir-listing.encode-header */
        pconf->encode_header = (char)cpv->v.u;
        break;
      case 14:/* dir-listing.auto-layout */
        pconf->auto_layout = (char)cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_dirlisting_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_dirlisting_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_dirlisting_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_dirlisting_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_dirlisting_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("dir-listing.activate"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.dir-listing"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.exclude"),
        T_CONFIG_ARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.hide-dot-files"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.external-css"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.external-js"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.encoding"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.show-readme"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.hide-readme-file"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.show-header"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.hide-header-file"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.set-footer"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.encode-readme"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.encode-header"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("dir-listing.auto-layout"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_dirlisting"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* dir-listing.activate */
              case 1: /* server.dir-listing *//*(historical)*/
                break;
              case 2: /* dir-listing.exclude */
                if (!array_is_vlist(cpv->v.a)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s; "
                      "expected list of \"regex\"", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
               #ifndef HAVE_PCRE_H
                if (cpv->v.a->used > 0) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "pcre support is missing for: %s, "
                      "please install libpcre and the headers",
                      cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
               #else
                cpv->v.v = mod_dirlisting_parse_excludes(srv, cpv->v.a);
                if (NULL == cpv->v.v) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "unexpected value for %s", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                cpv->vtype = T_CONFIG_LOCAL;
               #endif
                break;
              case 3: /* dir-listing.hide-dotfiles */
              case 4: /* dir-listing.external-css */
              case 5: /* dir-listing.external-js */
              case 6: /* dir-listing.encoding */
              case 7: /* dir-listing.show-readme */
                if (!buffer_string_is_empty(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    if (buffer_is_equal_string(b, CONST_STR_LEN("enable")))
                        buffer_copy_string_len(b, CONST_STR_LEN("README.txt"));
                    else if (buffer_is_equal_string(b,CONST_STR_LEN("disable")))
                        buffer_clear(b);
                }
                break;
              case 8: /* dir-listing.hide-readme-file */
                break;
              case 9: /* dir-listing.show-header */
                if (!buffer_string_is_empty(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    if (buffer_is_equal_string(b, CONST_STR_LEN("enable")))
                        buffer_copy_string_len(b, CONST_STR_LEN("HEADER.txt"));
                    else if (buffer_is_equal_string(b,CONST_STR_LEN("disable")))
                        buffer_clear(b);
                }
                break;
              case 10:/* dir-listing.hide-header-file */
              case 11:/* dir-listing.set-footer */
              case 12:/* dir-listing.encode-readme */
              case 13:/* dir-listing.encode-header */
              case 14:/* dir-listing.auto-layout */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.dir_listing = 0;
    p->defaults.hide_dot_files = 1;
    p->defaults.hide_readme_file = 0;
    p->defaults.hide_header_file = 0;
    p->defaults.encode_readme = 1;
    p->defaults.encode_header = 1;
    p->defaults.auto_layout = 1;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_dirlisting_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

typedef struct {
	size_t  namelen;
	time_t  mtime;
	off_t   size;
} dirls_entry_t;

typedef struct {
	dirls_entry_t **ent;
	size_t used;
	size_t size;
} dirls_list_t;

#define DIRLIST_ENT_NAME(ent)	((char*)(ent) + sizeof(dirls_entry_t))
#define DIRLIST_BLOB_SIZE		16

/* simple combsort algorithm */
static void http_dirls_sort(dirls_entry_t **ent, int num) {
	int gap = num;
	int i, j;
	int swapped;
	dirls_entry_t *tmp;

	do {
		gap = (gap * 10) / 13;
		if (gap == 9 || gap == 10)
			gap = 11;
		if (gap < 1)
			gap = 1;
		swapped = 0;

		for (i = 0; i < num - gap; i++) {
			j = i + gap;
			if (strcmp(DIRLIST_ENT_NAME(ent[i]), DIRLIST_ENT_NAME(ent[j])) > 0) {
				tmp = ent[i];
				ent[i] = ent[j];
				ent[j] = tmp;
				swapped = 1;
			}
		}

	} while (gap > 1 || swapped);
}

/* buffer must be able to hold "999.9K"
 * conversion is simple but not perfect
 */
static int http_list_directory_sizefmt(char *buf, size_t bufsz, off_t size) {
	const char unit[] = " KMGTPE";	/* Kilo, Mega, Giga, Tera, Peta, Exa */
	const char *u = unit;		/* u will always increment at least once */
	int remain;
	size_t buflen;

	if (size < 100)
		size += 99;
	if (size < 100)
		size = 0;

	while (1) {
		remain = (int) size & 1023;
		size >>= 10;
		u++;
		if ((size & (~0 ^ 1023)) == 0)
			break;
	}

	remain /= 100;
	if (remain > 9)
		remain = 9;
	if (size > 999) {
		size   = 0;
		remain = 9;
		u++;
	}

	li_itostrn(buf, bufsz, size);
	buflen = strlen(buf);
	if (buflen + 3 >= bufsz) return buflen;
	buf[buflen+0] = '.';
	buf[buflen+1] = remain + '0';
	buf[buflen+2] = *u;
	buf[buflen+3] = '\0';

	return buflen + 3;
}

static void http_list_directory_include_file(buffer *out, int symlinks, const buffer *path, const char *classname, int encode) {
	int fd = fdevent_open_cloexec(path->ptr, symlinks, O_RDONLY, 0);
	ssize_t rd;
	char buf[8192];

	if (-1 == fd) return;

	if (encode) {
		buffer_append_string_len(out, CONST_STR_LEN("<pre class=\""));
		buffer_append_string(out, classname);
		buffer_append_string_len(out, CONST_STR_LEN("\">"));
	}

	while ((rd = read(fd, buf, sizeof(buf))) > 0) {
		if (encode) {
			buffer_append_string_encoded(out, buf, (size_t)rd, ENCODING_MINIMAL_XML);
		} else {
			buffer_append_string_len(out, buf, (size_t)rd);
		}
	}
	close(fd);

	if (encode) {
		buffer_append_string_len(out, CONST_STR_LEN("</pre>"));
	}
}

/* portions copied from mod_status
 * modified and specialized for stable dirlist sorting by name */
static const char js_simple_table_resort[] = \
"var click_column;\n" \
"var name_column = 0;\n" \
"var date_column = 1;\n" \
"var size_column = 2;\n" \
"var type_column = 3;\n" \
"var prev_span = null;\n" \
"\n" \
"if (typeof(String.prototype.localeCompare) === 'undefined') {\n" \
" String.prototype.localeCompare = function(str, locale, options) {\n" \
"   return ((this == str) ? 0 : ((this > str) ? 1 : -1));\n" \
" };\n" \
"}\n" \
"\n" \
"if (typeof(String.prototype.toLocaleUpperCase) === 'undefined') {\n" \
" String.prototype.toLocaleUpperCase = function() {\n" \
"  return this.toUpperCase();\n" \
" };\n" \
"}\n" \
"\n" \
"function get_inner_text(el) {\n" \
" if((typeof el == 'string')||(typeof el == 'undefined'))\n" \
"  return el;\n" \
" if(el.innerText)\n" \
"  return el.innerText;\n" \
" else {\n" \
"  var str = \"\";\n" \
"  var cs = el.childNodes;\n" \
"  var l = cs.length;\n" \
"  for (i=0;i<l;i++) {\n" \
"   if (cs[i].nodeType==1) str += get_inner_text(cs[i]);\n" \
"   else if (cs[i].nodeType==3) str += cs[i].nodeValue;\n" \
"  }\n" \
" }\n" \
" return str;\n" \
"}\n" \
"\n" \
"function isdigit(c) {\n" \
" return (c >= '0' && c <= '9');\n" \
"}\n" \
"\n" \
"function unit_multiplier(unit) {\n" \
" return (unit=='K') ? 1000\n" \
"      : (unit=='M') ? 1000000\n" \
"      : (unit=='G') ? 1000000000\n" \
"      : (unit=='T') ? 1000000000000\n" \
"      : (unit=='P') ? 1000000000000000\n" \
"      : (unit=='E') ? 1000000000000000000 : 1;\n" \
"}\n" \
"\n" \
"var li_date_regex=/(\\d{4})-(\\w{3})-(\\d{2}) (\\d{2}):(\\d{2}):(\\d{2})/;\n" \
"\n" \
"var li_mon = ['Jan','Feb','Mar','Apr','May','Jun',\n" \
"              'Jul','Aug','Sep','Oct','Nov','Dec'];\n" \
"\n" \
"function li_mon_num(mon) {\n" \
" var i; for (i = 0; i < 12 && mon != li_mon[i]; ++i); return i;\n" \
"}\n" \
"\n" \
"function li_date_cmp(s1, s2) {\n" \
" var dp1 = li_date_regex.exec(s1)\n" \
" var dp2 = li_date_regex.exec(s2)\n" \
" for (var i = 1; i < 7; ++i) {\n" \
"  var cmp = (2 != i)\n" \
"   ? parseInt(dp1[i]) - parseInt(dp2[i])\n" \
"   : li_mon_num(dp1[2]) - li_mon_num(dp2[2]);\n" \
"  if (0 != cmp) return cmp;\n" \
" }\n" \
" return 0;\n" \
"}\n" \
"\n" \
"function sortfn_then_by_name(a,b,sort_column) {\n" \
" if (sort_column == name_column || sort_column == type_column) {\n" \
"  var ad = (a.cells[type_column].innerHTML === 'Directory');\n" \
"  var bd = (b.cells[type_column].innerHTML === 'Directory');\n" \
"  if (ad != bd) return (ad ? -1 : 1);\n" \
" }\n" \
" var at = get_inner_text(a.cells[sort_column]);\n" \
" var bt = get_inner_text(b.cells[sort_column]);\n" \
" var cmp;\n" \
" if (sort_column == name_column) {\n" \
"  if (at == '..') return -1;\n" \
"  if (bt == '..') return  1;\n" \
" }\n" \
" if (a.cells[sort_column].className == 'int') {\n" \
"  cmp = parseInt(at)-parseInt(bt);\n" \
" } else if (sort_column == date_column) {\n" \
"  var ad = isdigit(at.substr(0,1));\n" \
"  var bd = isdigit(bt.substr(0,1));\n" \
"  if (ad != bd) return (!ad ? -1 : 1);\n" \
"  cmp = li_date_cmp(at,bt);\n" \
" } else if (sort_column == size_column) {\n" \
"  var ai = parseInt(at, 10) * unit_multiplier(at.substr(-1,1));\n" \
"  var bi = parseInt(bt, 10) * unit_multiplier(bt.substr(-1,1));\n" \
"  if (at.substr(0,1) == '-') ai = -1;\n" \
"  if (bt.substr(0,1) == '-') bi = -1;\n" \
"  cmp = ai - bi;\n" \
" } else {\n" \
"  cmp = at.toLocaleUpperCase().localeCompare(bt.toLocaleUpperCase());\n" \
"  if (0 != cmp) return cmp;\n" \
"  cmp = at.localeCompare(bt);\n" \
" }\n" \
" if (0 != cmp || sort_column == name_column) return cmp;\n" \
" return sortfn_then_by_name(a,b,name_column);\n" \
"}\n" \
"\n" \
"function sortfn(a,b) {\n" \
" return sortfn_then_by_name(a,b,click_column);\n" \
"}\n" \
"\n" \
"function resort(lnk) {\n" \
" var span = lnk.childNodes[1];\n" \
" var table = lnk.parentNode.parentNode.parentNode.parentNode;\n" \
" var rows = new Array();\n" \
" for (j=1;j<table.rows.length;j++)\n" \
"  rows[j-1] = table.rows[j];\n" \
" click_column = lnk.parentNode.cellIndex;\n" \
" rows.sort(sortfn);\n" \
"\n" \
" if (prev_span != null) prev_span.innerHTML = '';\n" \
" if (span.getAttribute('sortdir')=='down') {\n" \
"  span.innerHTML = '&uarr;';\n" \
"  span.setAttribute('sortdir','up');\n" \
"  rows.reverse();\n" \
" } else {\n" \
"  span.innerHTML = '&darr;';\n" \
"  span.setAttribute('sortdir','down');\n" \
" }\n" \
" for (i=0;i<rows.length;i++)\n" \
"  table.tBodies[0].appendChild(rows[i]);\n" \
" prev_span = span;\n" \
"}\n";

/* portions copied from mod_dirlist (lighttpd2) */
static const char js_simple_table_init_sort[] = \
"\n" \
"function init_sort(init_sort_column, ascending) {\n" \
" var tables = document.getElementsByTagName(\"table\");\n" \
" for (var i = 0; i < tables.length; i++) {\n" \
"  var table = tables[i];\n" \
"  //var c = table.getAttribute(\"class\")\n" \
"  //if (-1 != c.split(\" \").indexOf(\"sort\")) {\n" \
"   var row = table.rows[0].cells;\n" \
"   for (var j = 0; j < row.length; j++) {\n" \
"    var n = row[j];\n" \
"    if (n.childNodes.length == 1 && n.childNodes[0].nodeType == 3) {\n" \
"     var link = document.createElement(\"a\");\n" \
"     var title = n.childNodes[0].nodeValue.replace(/:$/, \"\");\n" \
"     link.appendChild(document.createTextNode(title));\n" \
"     link.setAttribute(\"href\", \"#\");\n" \
"     link.setAttribute(\"class\", \"sortheader\");\n" \
"     link.setAttribute(\"onclick\", \"resort(this);return false;\");\n" \
"     var arrow = document.createElement(\"span\");\n" \
"     arrow.setAttribute(\"class\", \"sortarrow\");\n" \
"     arrow.appendChild(document.createTextNode(\":\"));\n" \
"     link.appendChild(arrow)\n" \
"     n.replaceChild(link, n.firstChild);\n" \
"    }\n" \
"   }\n" \
"   var lnk = row[init_sort_column].firstChild;\n" \
"   if (ascending) {\n" \
"    var span = lnk.childNodes[1];\n" \
"    span.setAttribute('sortdir','down');\n" \
"   }\n" \
"   resort(lnk);\n" \
"  //}\n" \
" }\n" \
"}\n";

static void http_dirlist_append_js_table_resort (buffer *b, connection *con) {
	char col = '0';
	char ascending = '0';
	if (!buffer_string_is_empty(con->uri.query)) {
		const char *qs = con->uri.query->ptr;
		do {
			if (qs[0] == 'C' && qs[1] == '=') {
				switch (qs[2]) {
				case 'N': col = '0'; break;
				case 'M': col = '1'; break;
				case 'S': col = '2'; break;
				case 'T':
				case 'D': col = '3'; break;
				default:  break;
				}
			}
			else if (qs[0] == 'O' && qs[1] == '=') {
				switch (qs[2]) {
				case 'A': ascending = '1'; break;
				case 'D': ascending = '0'; break;
				default:  break;
				}
			}
		} while ((qs = strchr(qs, '&')) && *++qs);
	}

	buffer_append_string_len(b, CONST_STR_LEN("\n<script type=\"text/javascript\">\n// <!--\n\n"));
	buffer_append_string_len(b, js_simple_table_resort, sizeof(js_simple_table_resort)-1);
	buffer_append_string_len(b, js_simple_table_init_sort, sizeof(js_simple_table_init_sort)-1);
	buffer_append_string_len(b, CONST_STR_LEN("\ninit_sort("));
	buffer_append_string_len(b, &col, 1);
	buffer_append_string_len(b, CONST_STR_LEN(", "));
	buffer_append_string_len(b, &ascending, 1);
	buffer_append_string_len(b, CONST_STR_LEN(");\n\n// -->\n</script>\n\n"));
}

static void http_list_directory_header(connection *con, plugin_data *p, buffer *out) {

	if (p->conf.auto_layout) {
		buffer_append_string_len(out, CONST_STR_LEN(
			"<!DOCTYPE html>\n"
			"<html>\n"
			"<head>\n"
		));
		if (!buffer_string_is_empty(p->conf.encoding)) {
			buffer_append_string_len(out, CONST_STR_LEN("<meta charset=\""));
			buffer_append_string_buffer(out, p->conf.encoding);
			buffer_append_string_len(out, CONST_STR_LEN("\">\n"));
		}
		buffer_append_string_len(out, CONST_STR_LEN("<title>Index of "));
		buffer_append_string_encoded(out, CONST_BUF_LEN(con->uri.path), ENCODING_MINIMAL_XML);
		buffer_append_string_len(out, CONST_STR_LEN("</title>\n"));

		if (!buffer_string_is_empty(p->conf.external_css)) {
			buffer_append_string_len(out, CONST_STR_LEN("<meta name=\"viewport\" content=\"initial-scale=1\">"));
			buffer_append_string_len(out, CONST_STR_LEN("<link rel=\"stylesheet\" type=\"text/css\" href=\""));
			buffer_append_string_buffer(out, p->conf.external_css);
			buffer_append_string_len(out, CONST_STR_LEN("\">\n"));
		} else {
			buffer_append_string_len(out, CONST_STR_LEN(
				"<style type=\"text/css\">\n"
				"a, a:active {text-decoration: none; color: blue;}\n"
				"a:visited {color: #48468F;}\n"
				"a:hover, a:focus {text-decoration: underline; color: red;}\n"
				"body {background-color: #F5F5F5;}\n"
				"h2 {margin-bottom: 12px;}\n"
				"table {margin-left: 12px;}\n"
				"th, td {"
				" font: 90% monospace;"
				" text-align: left;"
				"}\n"
				"th {"
				" font-weight: bold;"
				" padding-right: 14px;"
				" padding-bottom: 3px;"
				"}\n"
				"td {padding-right: 14px;}\n"
				"td.s, th.s {text-align: right;}\n"
				"div.list {"
				" background-color: white;"
				" border-top: 1px solid #646464;"
				" border-bottom: 1px solid #646464;"
				" padding-top: 10px;"
				" padding-bottom: 14px;"
				"}\n"
				"div.foot {"
				" font: 90% monospace;"
				" color: #787878;"
				" padding-top: 4px;"
				"}\n"
				"</style>\n"
			));
		}

		buffer_append_string_len(out, CONST_STR_LEN("</head>\n<body>\n"));
	}

	if (!buffer_string_is_empty(p->conf.show_header)) {
		/* if we have a HEADER file, display it in <pre class="header"></pre> */

		const buffer *hb = p->conf.show_header;
		if (hb->ptr[0] != '/') {
			hb = &p->tmp_buf;
			buffer_copy_buffer(&p->tmp_buf, con->physical.path);
			buffer_append_path_len(&p->tmp_buf, CONST_BUF_LEN(p->conf.show_header));
		}

		http_list_directory_include_file(out, con->conf.follow_symlink, hb, "header", p->conf.encode_header);
	}

	buffer_append_string_len(out, CONST_STR_LEN("<h2>Index of "));
	buffer_append_string_encoded(out, CONST_BUF_LEN(con->uri.path), ENCODING_MINIMAL_XML);
	buffer_append_string_len(out, CONST_STR_LEN(
		"</h2>\n"
		"<div class=\"list\">\n"
		"<table summary=\"Directory Listing\" cellpadding=\"0\" cellspacing=\"0\">\n"
		"<thead>"
		"<tr>"
			"<th class=\"n\">Name</th>"
			"<th class=\"m\">Last Modified</th>"
			"<th class=\"s\">Size</th>"
			"<th class=\"t\">Type</th>"
		"</tr>"
		"</thead>\n"
		"<tbody>\n"
	));
	if (!buffer_is_equal_string(con->uri.path, CONST_STR_LEN("/"))) {
		buffer_append_string_len(out, CONST_STR_LEN(
		"<tr class=\"d\">"
			"<td class=\"n\"><a href=\"../\">..</a>/</td>"
			"<td class=\"m\">&nbsp;</td>"
			"<td class=\"s\">- &nbsp;</td>"
			"<td class=\"t\">Directory</td>"
		"</tr>\n"
		));
	}
}

static void http_list_directory_footer(connection *con, plugin_data *p, buffer *out) {

	buffer_append_string_len(out, CONST_STR_LEN(
		"</tbody>\n"
		"</table>\n"
		"</div>\n"
	));

	if (!buffer_string_is_empty(p->conf.show_readme)) {
		/* if we have a README file, display it in <pre class="readme"></pre> */

		const buffer *rb = p->conf.show_readme;
		if (rb->ptr[0] != '/') {
			rb = &p->tmp_buf;
			buffer_copy_buffer(&p->tmp_buf,  con->physical.path);
			buffer_append_path_len(&p->tmp_buf, CONST_BUF_LEN(p->conf.show_readme));
		}

		http_list_directory_include_file(out, con->conf.follow_symlink, rb, "readme", p->conf.encode_readme);
	}

	if(p->conf.auto_layout) {

		buffer_append_string_len(out, CONST_STR_LEN(
			"<div class=\"foot\">"
		));

		if (!buffer_string_is_empty(p->conf.set_footer)) {
			buffer_append_string_buffer(out, p->conf.set_footer);
		} else {
			buffer_append_string_buffer(out, con->conf.server_tag);
		}

		buffer_append_string_len(out, CONST_STR_LEN(
			"</div>\n"
		));

		if (!buffer_string_is_empty(p->conf.external_js)) {
			buffer_append_string_len(out, CONST_STR_LEN("<script type=\"text/javascript\" src=\""));
			buffer_append_string_buffer(out, p->conf.external_js);
			buffer_append_string_len(out, CONST_STR_LEN("\"></script>\n"));
		} else if (buffer_is_empty(p->conf.external_js)) {
			http_dirlist_append_js_table_resort(out, con);
		}

		buffer_append_string_len(out, CONST_STR_LEN(
			"</body>\n"
			"</html>\n"
		));
	}
}

static int http_list_directory(server *srv, connection *con, plugin_data *p, buffer *dir) {
	DIR *dp;
	buffer *out;
	struct dirent *dent;
	struct stat st;
	char *path, *path_file;
	size_t i;
	int hide_dotfiles = p->conf.hide_dot_files;
	dirls_list_t dirs, files, *list;
	dirls_entry_t *tmp;
	char sizebuf[sizeof("999.9K")];
	char datebuf[sizeof("2005-Jan-01 22:23:24")];
	const char *content_type;
	long name_max;
	log_error_st * const errh = con->conf.errh;
#if defined(HAVE_XATTR) || defined(HAVE_EXTATTR)
	char attrval[128];
	int attrlen;
#endif
#ifdef HAVE_LOCALTIME_R
	struct tm tm;
#endif
	UNUSED(srv);

	if (buffer_string_is_empty(dir)) return -1;

	i = buffer_string_length(dir);

#ifdef HAVE_PATHCONF
	if (0 >= (name_max = pathconf(dir->ptr, _PC_NAME_MAX))) {
		/* some broken fs (fuse) return 0 instead of -1 */
#ifdef NAME_MAX
		name_max = NAME_MAX;
#else
		name_max = 255; /* stupid default */
#endif
	}
#elif defined __WIN32
	name_max = FILENAME_MAX;
#else
	name_max = NAME_MAX;
#endif

	path = malloc(i + name_max + 1);
	force_assert(NULL != path);
	memcpy(path, dir->ptr, i+1);
	path_file = path + i;

	if (NULL == (dp = opendir(path))) {
		log_error(errh, __FILE__, __LINE__,
		  "opendir failed: %s", dir->ptr);

		free(path);
		return -1;
	}

	dirs.ent   = (dirls_entry_t**) malloc(sizeof(dirls_entry_t*) * DIRLIST_BLOB_SIZE);
	force_assert(dirs.ent);
	dirs.size  = DIRLIST_BLOB_SIZE;
	dirs.used  = 0;
	files.ent  = (dirls_entry_t**) malloc(sizeof(dirls_entry_t*) * DIRLIST_BLOB_SIZE);
	force_assert(files.ent);
	files.size = DIRLIST_BLOB_SIZE;
	files.used = 0;

	while ((dent = readdir(dp)) != NULL) {
		if (dent->d_name[0] == '.') {
			if (hide_dotfiles)
				continue;
			if (dent->d_name[1] == '\0')
				continue;
			if (dent->d_name[1] == '.' && dent->d_name[2] == '\0')
				continue;
		}

		if (p->conf.hide_readme_file && !buffer_string_is_empty(p->conf.show_readme)) {
			if (strcmp(dent->d_name, p->conf.show_readme->ptr) == 0)
				continue;
		}
		if (p->conf.hide_header_file && !buffer_string_is_empty(p->conf.show_header)) {
			if (strcmp(dent->d_name, p->conf.show_header->ptr) == 0)
				continue;
		}

		i = strlen(dent->d_name);

		/* compare d_name against excludes array
		 * elements, skipping any that match.
		 */
		if (p->conf.excludes
		    && mod_dirlisting_exclude(errh, p->conf.excludes, dent->d_name, i))
			continue;

		/* NOTE: the manual says, d_name is never more than NAME_MAX
		 *       so this should actually not be a buffer-overflow-risk
		 */
		if (i > (size_t)name_max) continue;

		memcpy(path_file, dent->d_name, i + 1);
		if (stat(path, &st) != 0)
			continue;

		list = &files;
		if (S_ISDIR(st.st_mode))
			list = &dirs;

		if (list->used == list->size) {
			list->size += DIRLIST_BLOB_SIZE;
			list->ent   = (dirls_entry_t**) realloc(list->ent, sizeof(dirls_entry_t*) * list->size);
			force_assert(list->ent);
		}

		tmp = (dirls_entry_t*) malloc(sizeof(dirls_entry_t) + 1 + i);
		tmp->mtime = st.st_mtime;
		tmp->size  = st.st_size;
		tmp->namelen = i;
		memcpy(DIRLIST_ENT_NAME(tmp), dent->d_name, i + 1);

		list->ent[list->used++] = tmp;
	}
	closedir(dp);

	if (dirs.used) http_dirls_sort(dirs.ent, dirs.used);

	if (files.used) http_dirls_sort(files.ent, files.used);

	out = chunkqueue_append_buffer_open(con->write_queue);
	http_list_directory_header(con, p, out);

	/* directories */
	for (i = 0; i < dirs.used; i++) {
		tmp = dirs.ent[i];

#ifdef HAVE_LOCALTIME_R
		localtime_r(&(tmp->mtime), &tm);
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", &tm);
#else
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", localtime(&(tmp->mtime)));
#endif

		buffer_append_string_len(out, CONST_STR_LEN("<tr class=\"d\"><td class=\"n\"><a href=\""));
		buffer_append_string_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen, ENCODING_REL_URI_PART);
		buffer_append_string_len(out, CONST_STR_LEN("/\">"));
		buffer_append_string_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen, ENCODING_MINIMAL_XML);
		buffer_append_string_len(out, CONST_STR_LEN("</a>/</td><td class=\"m\">"));
		buffer_append_string_len(out, datebuf, sizeof(datebuf) - 1);
		buffer_append_string_len(out, CONST_STR_LEN("</td><td class=\"s\">- &nbsp;</td><td class=\"t\">Directory</td></tr>\n"));

		free(tmp);
	}

	/* files */
	for (i = 0; i < files.used; i++) {
		tmp = files.ent[i];

		content_type = NULL;
#if defined(HAVE_XATTR)
		if (con->conf.use_xattr) {
			memcpy(path_file, DIRLIST_ENT_NAME(tmp), tmp->namelen + 1);
			attrlen = sizeof(attrval) - 1;
			if (attr_get(path, srv->srvconf.xattr_name, attrval, &attrlen, 0) == 0) {
				attrval[attrlen] = '\0';
				content_type = attrval;
			}
		}
#elif defined(HAVE_EXTATTR)
		if (con->conf.use_xattr) {
			memcpy(path_file, DIRLIST_ENT_NAME(tmp), tmp->namelen + 1);
			if(-1 != (attrlen = extattr_get_file(path, EXTATTR_NAMESPACE_USER, srv->srvconf.xattr_name, attrval, sizeof(attrval)-1))) {
				attrval[attrlen] = '\0';
				content_type = attrval;
			}
		}
#endif

		if (content_type == NULL) {
			const buffer *type = stat_cache_mimetype_by_ext(con, DIRLIST_ENT_NAME(tmp), tmp->namelen);
			content_type = NULL != type ? type->ptr : "application/octet-stream";
		}

#ifdef HAVE_LOCALTIME_R
		localtime_r(&(tmp->mtime), &tm);
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", &tm);
#else
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", localtime(&(tmp->mtime)));
#endif
		http_list_directory_sizefmt(sizebuf, sizeof(sizebuf), tmp->size);

		buffer_append_string_len(out, CONST_STR_LEN("<tr><td class=\"n\"><a href=\""));
		buffer_append_string_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen, ENCODING_REL_URI_PART);
		buffer_append_string_len(out, CONST_STR_LEN("\">"));
		buffer_append_string_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen, ENCODING_MINIMAL_XML);
		buffer_append_string_len(out, CONST_STR_LEN("</a></td><td class=\"m\">"));
		buffer_append_string_len(out, datebuf, sizeof(datebuf) - 1);
		buffer_append_string_len(out, CONST_STR_LEN("</td><td class=\"s\">"));
		buffer_append_string(out, sizebuf);
		buffer_append_string_len(out, CONST_STR_LEN("</td><td class=\"t\">"));
		buffer_append_string(out, content_type);
		buffer_append_string_len(out, CONST_STR_LEN("</td></tr>\n"));

		free(tmp);
	}

	free(files.ent);
	free(dirs.ent);
	free(path);

	http_list_directory_footer(con, p, out);

	/* Insert possible charset to Content-Type */
	if (buffer_string_is_empty(p->conf.encoding)) {
		http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	} else {
		buffer_copy_string_len(&p->tmp_buf, CONST_STR_LEN("text/html; charset="));
		buffer_append_string_buffer(&p->tmp_buf, p->conf.encoding);
		http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(&p->tmp_buf));
	}

	chunkqueue_append_buffer_commit(con->write_queue);
	con->file_finished = 1;

	return 0;
}



URIHANDLER_FUNC(mod_dirlisting_subrequest) {
	plugin_data *p = p_d;
	stat_cache_entry *sce = NULL;

	/* we only handle GET and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}

	if (con->mode != DIRECT) return HANDLER_GO_ON;

	if (buffer_is_empty(con->physical.path)) return HANDLER_GO_ON;
	if (buffer_is_empty(con->uri.path)) return HANDLER_GO_ON;
	if (con->uri.path->ptr[buffer_string_length(con->uri.path) - 1] != '/') return HANDLER_GO_ON;

	mod_dirlisting_patch_config(con, p);

	if (!p->conf.dir_listing) return HANDLER_GO_ON;

	if (con->conf.log_request_handling) {
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "-- handling the request as Dir-Listing");
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "URI          : %s", con->uri.path->ptr);
	}

	if (HANDLER_ERROR == stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
		log_error(con->conf.errh, __FILE__, __LINE__,
		  "stat_cache_get_entry failed: %s", con->physical.path->ptr);
		con->http_status = 500;
		return HANDLER_FINISHED;
	}

	if (!S_ISDIR(sce->st.st_mode)) return HANDLER_GO_ON;

	if (http_list_directory(srv, con, p, con->physical.path)) {
		/* dirlisting failed */
		con->http_status = 403;
	}

	buffer_reset(con->physical.path);

	/* not found */
	return HANDLER_FINISHED;
}


int mod_dirlisting_plugin_init(plugin *p);
int mod_dirlisting_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "dirlisting";

	p->init        = mod_dirlisting_init;
	p->handle_subrequest_start  = mod_dirlisting_subrequest;
	p->set_defaults  = mod_dirlisting_set_defaults;
	p->cleanup     = mod_dirlisting_free;

	return 0;
}
