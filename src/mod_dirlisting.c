#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "config.h"
#include "response.h"
#include "stat_cache.h"
#include "stream.h"

/**
 * this is a dirlisting for a lighttpd plugin
 */


#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
#endif

/* plugin config for all request/connections */

typedef struct {
	unsigned short dir_listing;
	unsigned short hide_dot_files;
	unsigned short show_readme;
	
	buffer *external_css;
	buffer *encoding;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	buffer *tmp_buf;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_dirlisting_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	p->tmp_buf = buffer_init();
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_dirlisting_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			if (!s) continue;
			
			buffer_free(s->external_css);
			buffer_free(s->encoding);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	buffer_free(p->tmp_buf);
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_dirlisting_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ "dir-listing.activate",        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ "dir-listing.hide-dotfiles",   NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ "dir-listing.external-css",    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },  /* 2 */
		{ "dir-listing.encoding",        NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },  /* 3 */
		{ "dir-listing.show-readme",     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
		{ "server.dir-listing",          NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 5 */
		
		{ NULL,                          NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		s->dir_listing = 0;
		s->external_css = buffer_init();
		s->hide_dot_files = 0;
		s->show_readme = 0;
		s->encoding = buffer_init();
		
		cv[0].destination = &(s->dir_listing);
		cv[1].destination = &(s->hide_dot_files);
		cv[2].destination = s->external_css;
		cv[3].destination = s->encoding;
		cv[4].destination = &(s->show_readme);
		cv[5].destination = &(s->dir_listing); /* old name */
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}
	
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_dirlisting_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];

	PATCH(dir_listing);
	PATCH(external_css);
	PATCH(hide_dot_files);
	PATCH(encoding);
	PATCH(show_readme);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("dir-listing.activate")) ||
			    buffer_is_equal_string(du->key, CONST_STR_LEN("server.dir-listing"))) {
				PATCH(dir_listing);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("dir-listing.hide-dotfiles"))) {
				PATCH(hide_dot_files);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("dir-listing.external-css"))) {
				PATCH(external_css);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("dir-listing.encoding"))) {
				PATCH(encoding);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("dir-listing.show-readme"))) {
				PATCH(show_readme);
			}
		}
	}
	
	return 0;
}
#undef PATCH

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
static int http_list_directory_sizefmt(char *buf, off_t size) {
	const char unit[] = "KMGTPE";	/* Kilo, Mega, Tera, Peta, Exa */
	const char *u = unit - 1;		/* u will always increment at least once */
	int remain;
	char *out = buf;

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

	out   += ltostr(out, size);
	out[0] = '.';
	out[1] = remain + '0';
	out[2] = *u;
	out[3] = '\0';

	return (out + 3 - buf);
}

static void http_list_directory_header(server *srv, connection *con, plugin_data *p, buffer *out) {
	UNUSED(srv);
	
	BUFFER_APPEND_STRING_CONST(out,
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
		"<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n"
		"<head>\n"
		"<title>Index of "
	);
	buffer_append_string_html_encoded(out, CONST_BUF_LEN(con->uri.path));
	BUFFER_APPEND_STRING_CONST(out, "</title>\n");

	if (p->conf.external_css->used > 1) {
		BUFFER_APPEND_STRING_CONST(out, "<link rel=\"stylesheet\" type=\"text/css\" href=\"");
		buffer_append_string_buffer(out, p->conf.external_css);
		BUFFER_APPEND_STRING_CONST(out, "\" />\n");
	} else {
		BUFFER_APPEND_STRING_CONST(out,
			"<style type=\"text/css\">\n"
			"a, a:active {text-decoration: none; color: blue;}\n"
			"a:visited {color: #48468F;}\n"
			"a:hover, a:focus {text-decoration: underline; color: red;}\n"
			"body {background-color: #F5F5F5;}\n"
			"h2 {margin-bottom: 12px;}\n"
			"table {margin-left: 12px;}\n"
			"th, td {"
			" font-family: \"Courier New\", Courier, monospace;"
			" font-size: 10pt;"
			" text-align: left;"
			"}\n"
			"th {"
			" font-weight: bold;"
			" padding-right: 14px;"
			" padding-bottom: 3px;"
			"}\n"
		);
		BUFFER_APPEND_STRING_CONST(out,
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
			" font-family: \"Courier New\", Courier, monospace;"
			" font-size: 10pt;"
			" color: #787878;"
			" padding-top: 4px;"
			"}\n"
			"</style>\n"
		);
	}

	BUFFER_APPEND_STRING_CONST(out, "</head>\n<body>\n<h2>Index of ");
	buffer_append_string_html_encoded(out, CONST_BUF_LEN(con->uri.path));
	BUFFER_APPEND_STRING_CONST(out,
		"</h2>\n"
		"<div class=\"list\">\n"
		"<table cellpadding=\"0\" cellspacing=\"0\">\n"
		"<thead>"
		"<tr>"
			"<th class=\"n\">Name</th>"
			"<th class=\"m\">Last Modified</th>"
			"<th class=\"s\">Size</th>"
			"<th class=\"t\">Type</th>"
		"</tr>"
		"</thead>\n"
		"<tbody>\n"
		"<tr>"
			"<td class=\"n\"><a href=\"../\">Parent Directory</a>/</td>"
			"<td class=\"m\">&nbsp;</td>"
			"<td class=\"s\">- &nbsp;</td>"
			"<td class=\"t\">Directory</td>"
		"</tr>\n"
	);
}

static void http_list_directory_footer(server *srv, connection *con, plugin_data *p, buffer *out) {
	UNUSED(srv);
	
	BUFFER_APPEND_STRING_CONST(out,
		"</tbody>\n"
		"</table>\n"
		"</div>\n"
	);
	
	if (p->conf.show_readme) {
		stream s;
		/* if we have a README file, display it in <pre class="readme"></pre> */
		
		buffer_copy_string_buffer(p->tmp_buf,  con->physical.path);
		BUFFER_APPEND_SLASH(p->tmp_buf);
		BUFFER_APPEND_STRING_CONST(p->tmp_buf, "README.txt");
		
		if (-1 != stream_open(&s, p->tmp_buf)) {
			BUFFER_APPEND_STRING_CONST(out, "<pre class=\"readme\">");
			buffer_append_string_html_encoded(out, s.start, s.size);
			BUFFER_APPEND_STRING_CONST(out, "</pre>");
		}
		stream_close(&s);
	}
	
	BUFFER_APPEND_STRING_CONST(out,
		"<div class=\"foot\">"
	);

	if (buffer_is_empty(con->conf.server_tag)) {
		BUFFER_APPEND_STRING_CONST(out, PACKAGE_NAME "/" PACKAGE_VERSION);
	} else {
		buffer_append_string_buffer(out, con->conf.server_tag);
	}

	BUFFER_APPEND_STRING_CONST(out,
		"</div>\n"
		"</body>\n"
		"</html>\n"
	);
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
	size_t k;
	const char *content_type;
	long name_max;
#ifdef HAVE_XATTR
	char attrval[128];
	int attrlen;
#endif
#ifdef HAVE_LOCALTIME_R
	struct tm tm;
#endif

	if (dir->used == 0) return -1;
	
	i = dir->used - 1;

#ifdef HAVE_PATHCONF
	name_max = pathconf(dir->ptr, _PC_NAME_MAX);
#elif defined __WIN32
	name_max = FILENAME_MAX;
#else
	name_max = NAME_MAX;
#endif
	
	path = malloc(dir->used + name_max);
	assert(path);
	strcpy(path, dir->ptr);
	path_file = path + i;

	if (NULL == (dp = opendir(path))) {
		log_error_write(srv, __FILE__, __LINE__, "sbs", 
			"opendir failed:", dir, strerror(errno));

		free(path);
		return -1;
	}

	dirs.ent   = (dirls_entry_t**) malloc(sizeof(dirls_entry_t*) * DIRLIST_BLOB_SIZE);
	assert(dirs.ent);
	dirs.size  = DIRLIST_BLOB_SIZE;
	dirs.used  = 0;
	files.ent  = (dirls_entry_t**) malloc(sizeof(dirls_entry_t*) * DIRLIST_BLOB_SIZE);
	assert(files.ent);
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

		
		i = strlen(dent->d_name);
		
		/* NOTE: the manual says, d_name is never more than NAME_MAX
		 *       so this should actually not be a buffer-overflow-risk
		 */
		if (i > name_max) continue;
		
		memcpy(path_file, dent->d_name, i + 1);
		if (stat(path, &st) != 0)
			continue;

		list = &files;
		if (S_ISDIR(st.st_mode))
			list = &dirs;

		if (list->used == list->size) {
			list->size += DIRLIST_BLOB_SIZE;
			list->ent   = (dirls_entry_t**) realloc(list->ent, sizeof(dirls_entry_t*) * list->size);
			assert(list->ent);
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

	out = chunkqueue_get_append_buffer(con->write_queue);
	BUFFER_COPY_STRING_CONST(out, "<?xml version=\"1.0\" encoding=\"");
	if (buffer_is_empty(p->conf.encoding)) {
		BUFFER_APPEND_STRING_CONST(out, "iso-8859-1");
	} else {
		buffer_append_string_buffer(out, p->conf.encoding);
	}
	BUFFER_APPEND_STRING_CONST(out, "\"?>\n");
	http_list_directory_header(srv, con, p, out);

	/* directories */
	for (i = 0; i < dirs.used; i++) {
		tmp = dirs.ent[i];

#ifdef HAVE_LOCALTIME_R
		localtime_r(&(tmp->mtime), &tm);
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", &tm);
#else
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", localtime(&(tmp->mtime)));
#endif
		
		BUFFER_APPEND_STRING_CONST(out, "<tr><td class=\"n\"><a href=\"");
		buffer_append_string_url_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen);
		BUFFER_APPEND_STRING_CONST(out, "/\">");
		buffer_append_string_html_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen);
		BUFFER_APPEND_STRING_CONST(out, "</a>/</td><td class=\"m\">");
		buffer_append_string_len(out, datebuf, sizeof(datebuf) - 1);
		BUFFER_APPEND_STRING_CONST(out, "</td><td class=\"s\">- &nbsp;</td><td class=\"t\">Directory</td></tr>\n");

		free(tmp);
	}

	/* files */
	for (i = 0; i < files.used; i++) {
		tmp = files.ent[i];

		content_type = NULL;
#ifdef HAVE_XATTR
		
		if (con->conf.use_xattr) {
			memcpy(path_file, DIRLIST_ENT_NAME(tmp), tmp->namelen + 1);
			attrlen = sizeof(attrval) - 1;
			if (attr_get(path, "Content-Type", attrval, &attrlen, 0) == 0) {
				attrval[attrlen] = '\0';
				content_type = attrval;
			}
		}
#endif
		
		if (content_type == NULL) {
			content_type = "application/octet-stream";
			for (k = 0; k < con->conf.mimetypes->used; k++) {
				data_string *ds = (data_string *)con->conf.mimetypes->data[k];
				size_t ct_len;

				if (ds->key->used == 0)
					continue;

				ct_len = ds->key->used - 1;
				if (tmp->namelen < ct_len)
					continue;

				if (0 == strncasecmp(DIRLIST_ENT_NAME(tmp) + tmp->namelen - ct_len, ds->key->ptr, ct_len)) {
					content_type = ds->value->ptr;
					break;
				}
			}
		}
			
#ifdef HAVE_LOCALTIME_R
		localtime_r(&(tmp->mtime), &tm);
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", &tm);
#else
		strftime(datebuf, sizeof(datebuf), "%Y-%b-%d %H:%M:%S", localtime(&(tmp->mtime)));
#endif
		http_list_directory_sizefmt(sizebuf, tmp->size);

		BUFFER_APPEND_STRING_CONST(out, "<tr><td class=\"n\"><a href=\"");
		buffer_append_string_url_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen);
		BUFFER_APPEND_STRING_CONST(out, "\">");
		buffer_append_string_html_encoded(out, DIRLIST_ENT_NAME(tmp), tmp->namelen);
		BUFFER_APPEND_STRING_CONST(out, "</a></td><td class=\"m\">");
		buffer_append_string_len(out, datebuf, sizeof(datebuf) - 1);
		BUFFER_APPEND_STRING_CONST(out, "</td><td class=\"s\">");
		buffer_append_string(out, sizebuf);
		BUFFER_APPEND_STRING_CONST(out, "</td><td class=\"t\">");
		buffer_append_string(out, content_type);
		BUFFER_APPEND_STRING_CONST(out, "</td></tr>\n");

		free(tmp);
	}

	free(files.ent);
	free(dirs.ent);
	free(path);

	http_list_directory_footer(srv, con, p, out);
	response_header_insert(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
	con->file_finished = 1;

	return 0;
}



URIHANDLER_FUNC(mod_dirlisting_subrequest) {
	plugin_data *p = p_d;
	stat_cache_entry *sce = NULL;
	
	UNUSED(srv);
	
	if (con->physical.path->used == 0) return HANDLER_GO_ON;
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	if (con->uri.path->ptr[con->uri.path->used - 2] != '/') return HANDLER_GO_ON;
	
	mod_dirlisting_patch_connection(srv, con, p);

	if (!p->conf.dir_listing) return HANDLER_GO_ON;
	
	if (con->conf.log_request_handling) {
		log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling the request as Dir-Listing");
		log_error_write(srv, __FILE__, __LINE__,  "sb", "URI          :", con->uri.path);
	}
	
	if (HANDLER_ERROR == stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
		fprintf(stderr, "%s.%d: %s\n", __FILE__, __LINE__, con->physical.path->ptr);
		SEGFAULT();
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

/* this function is called at dlopen() time and inits the callbacks */

int mod_dirlisting_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("dirlisting");
	
	p->init        = mod_dirlisting_init;
	p->handle_subrequest_start  = mod_dirlisting_subrequest;
	p->set_defaults  = mod_dirlisting_set_defaults;
	p->cleanup     = mod_dirlisting_free;
	
	p->data        = NULL;
	
	return 0;
}
