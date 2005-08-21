#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "config.h"
#if defined(HAVE_LIBXML_H) && defined(HAVE_SQLITE3_H)
#define USE_PROPPATCH
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <sqlite3.h>
#endif


#include "base.h"
#include "log.h"
#include "buffer.h"
#include "response.h"

#include "plugin.h"

#include "stream.h"
#include "stat_cache.h"


/**
 * this is a webdav for a lighttpd plugin
 *
 * at least a very basic one. 
 * - for now it is read-only and we only support PROPFIND
 * 
 */



/* plugin config for all request/connections */

typedef struct {
	unsigned short enabled;
	unsigned short is_readonly;

	buffer *sqlite_db_name;
#ifdef USE_PROPPATCH
	sqlite3 *sql;
	sqlite3_stmt *stmt_update_prop;
	sqlite3_stmt *stmt_delete_prop;
	sqlite3_stmt *stmt_select_prop;
	sqlite3_stmt *stmt_select_propnames;
	
	sqlite3_stmt *stmt_delete_uri;
	sqlite3_stmt *stmt_move_uri;
	sqlite3_stmt *stmt_copy_uri;
#endif
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	buffer *tmp_buf;
	request_uri uri;
	physical physical;

	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_webdav_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->tmp_buf = buffer_init();

	p->uri.scheme = buffer_init();
	p->uri.path_raw = buffer_init();
	p->uri.path = buffer_init();
	p->uri.authority = buffer_init();
	
	p->physical.path = buffer_init();
	p->physical.rel_path = buffer_init();
	p->physical.doc_root = buffer_init();
	p->physical.basedir = buffer_init();
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_webdav_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;
	
#ifdef USE_PROPPATCH
			if (s->sql) {	
				sqlite3_finalize(s->stmt_delete_prop);
				sqlite3_finalize(s->stmt_delete_uri);
				sqlite3_finalize(s->stmt_update_prop);
				sqlite3_finalize(s->stmt_select_prop);
				sqlite3_finalize(s->stmt_select_propnames);
				sqlite3_close(s->sql);
			}
#endif	
			free(s);
		}
		free(p->config_storage);
	}
	
	buffer_free(p->tmp_buf);
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_webdav_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ "webdav.activate",            NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "webdav.is-readonly",         NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ "webdav.sqlite-db-name",      NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		s->sqlite_db_name = buffer_init();
		
		cv[0].destination = &(s->enabled);
		cv[1].destination = &(s->is_readonly);
		cv[2].destination = s->sqlite_db_name;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}

		if (!buffer_is_empty(s->sqlite_db_name)) {
#ifdef USE_PROPPATCH
			const char *next_stmt;
			char *err;

			if (SQLITE_OK != sqlite3_open(s->sqlite_db_name->ptr, &(s->sql))) {
				log_error_write(srv, __FILE__, __LINE__, "s", "sqlite3_open failed");
				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("SELECT value FROM properties WHERE resource = ? AND prop = ? AND ns = ?"), 
				&(s->stmt_select_prop), &next_stmt)) {
				/* prepare failed */

				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed:", sqlite3_errmsg(s->sql));
				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("SELECT ns, prop FROM properties WHERE resource = ?"), 
				&(s->stmt_select_propnames), &next_stmt)) {
				/* prepare failed */

				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed:", sqlite3_errmsg(s->sql));
				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_exec(s->sql, 
					"CREATE TABLE properties ("
					"  resource TEXT NOT NULL,"
					"  prop TEXT NOT NULL,"
					"  ns TEXT NOT NULL,"
					"  value TEXT NOT NULL,"
					"  PRIMARY KEY(resource, prop, ns))",
					NULL, NULL, &err)) {

				if (0 != strcmp(err, "table properties already exists")) {
					log_error_write(srv, __FILE__, __LINE__, "ss", "can't open transaction:", err);
					sqlite3_free(err);

					return HANDLER_ERROR;
				}
			}
	
			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("REPLACE INTO properties (resource, prop, ns, value) VALUES (?, ?, ?, ?)"), 
				&(s->stmt_update_prop), &next_stmt)) {
				/* prepare failed */

				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed:", sqlite3_errmsg(s->sql));
				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("DELETE FROM properties WHERE resource = ? AND prop = ? AND ns = ?"), 
				&(s->stmt_delete_prop), &next_stmt)) {
				/* prepare failed */
				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed", sqlite3_errmsg(s->sql));

				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("DELETE FROM properties WHERE resource = ?"), 
				&(s->stmt_delete_uri), &next_stmt)) {
				/* prepare failed */
				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed", sqlite3_errmsg(s->sql));

				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("INSERT INTO properties SELECT ?, prop, ns, value FROM properties WHERE resource = ?"), 
				&(s->stmt_copy_uri), &next_stmt)) {
				/* prepare failed */
				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed", sqlite3_errmsg(s->sql));

				return HANDLER_ERROR;
			}

			if (SQLITE_OK != sqlite3_prepare(s->sql, 
				CONST_STR_LEN("UPDATE properties SET resource = ? WHERE resource = ?"), 
				&(s->stmt_move_uri), &next_stmt)) {
				/* prepare failed */
				log_error_write(srv, __FILE__, __LINE__, "ss", "sqlite3_prepare failed", sqlite3_errmsg(s->sql));

				return HANDLER_ERROR;
			}
#else
			log_error_write(srv, __FILE__, __LINE__, "s", "Sorry, no sqlite3 and libxml2 support include, compile with --with-webdav-props");
			return HANDLER_ERROR;
#endif
		}
	}
	
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_webdav_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	
	PATCH(enabled);
	PATCH(is_readonly);
	
#ifdef USE_PROPPATCH
	PATCH(sql);
	PATCH(stmt_update_prop);
	PATCH(stmt_delete_prop);
	PATCH(stmt_select_prop);
	PATCH(stmt_select_propnames);

	PATCH(stmt_delete_uri);
	PATCH(stmt_move_uri);
	PATCH(stmt_copy_uri);
#endif
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.activate"))) {
				PATCH(enabled);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.is-readonly"))) {
				PATCH(is_readonly);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.sqlite-db-name"))) {
#ifdef USE_PROPPATCH
				PATCH(sql);
				PATCH(stmt_update_prop);
				PATCH(stmt_delete_prop);
				PATCH(stmt_select_prop);
				PATCH(stmt_select_propnames);
				
				PATCH(stmt_delete_uri);
				PATCH(stmt_move_uri);
				PATCH(stmt_copy_uri);
#endif
			}
		}
	}
	
	return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_webdav_uri_handler) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	
	mod_webdav_patch_connection(srv, con, p);

	if (!p->conf.enabled) return HANDLER_GO_ON;

	switch (con->request.http_method) {
	case HTTP_METHOD_OPTIONS:
		/* we fake a little bit but it makes MS W2k happy and it let's us mount the volume */
		response_header_overwrite(srv, con, CONST_STR_LEN("DAV"), CONST_STR_LEN("1,2"));
		response_header_overwrite(srv, con, CONST_STR_LEN("MS-Author-Via"), CONST_STR_LEN("DAV"));

		if (p->conf.is_readonly) {
			response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("PROPFIND"));
		} else {
			response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH"));
		}
		break;
	default:
		break;
	}
	
	/* not found */
	return HANDLER_GO_ON;
}
static int webdav_gen_prop_tag(server *srv, connection *con, 
		char *prop_name, 
		char *prop_ns, 
		char *value, 
		buffer *b) {

	UNUSED(srv);
	UNUSED(con);

	if (value) {
		buffer_append_string(b,"<");
		buffer_append_string(b, prop_name);
		buffer_append_string(b, " xmlns=\"");
		buffer_append_string(b, prop_ns);
		buffer_append_string(b, "\">");

		buffer_append_string(b, value);

		buffer_append_string(b,"</");
		buffer_append_string(b, prop_name);
		buffer_append_string(b, ">");
	} else {
		buffer_append_string(b,"<");
		buffer_append_string(b, prop_name);
		buffer_append_string(b, " xmlns=\"");
		buffer_append_string(b, prop_ns);
		buffer_append_string(b, "\"/>");
	}

	return 0;
}


static int webdav_gen_response_status_tag(server *srv, connection *con, physical *dst, int status, buffer *b) {
	UNUSED(srv);

	buffer_append_string(b,"<D:response xmlns:ns0=\"urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/\">\n");

	buffer_append_string(b,"<D:href>\n");
	buffer_append_string_buffer(b, dst->rel_path);
	buffer_append_string(b,"</D:href>\n");
	buffer_append_string(b,"<D:status>\n");
	
	if (con->request.http_version == HTTP_VERSION_1_1) {
		BUFFER_COPY_STRING_CONST(b, "HTTP/1.1 ");
	} else {
		BUFFER_COPY_STRING_CONST(b, "HTTP/1.0 ");
	}
	buffer_append_long(b, status);
	BUFFER_APPEND_STRING_CONST(b, " ");
	buffer_append_string(b, get_http_status_name(status));

	buffer_append_string(b,"</D:status>\n");
	buffer_append_string(b,"</D:response>\n");

	return 0;
}

static int webdav_delete_file(server *srv, connection *con, plugin_data *p, physical *dst, buffer *b) {
	int status = 0;

	/* try to unlink it */
	if (-1 == unlink(dst->path->ptr)) {
		switch(errno) {
		case EACCES:
		case EPERM:
			/* 403 */
			status = 403;
			break;
		default:
			status = 501;
			break;
		}
		webdav_gen_response_status_tag(srv, con, dst, status, b);
	} else {
#ifdef USE_PROPPATCH
		sqlite3_stmt *stmt = p->conf.stmt_delete_uri;

		sqlite3_reset(stmt);

		/* bind the values to the insert */

		sqlite3_bind_text(stmt, 1, 
				  dst->rel_path->ptr, 
				  dst->rel_path->used - 1,
				  SQLITE_TRANSIENT);
									
		if (SQLITE_DONE != sqlite3_step(stmt)) {
			/* */
			WP();
		}
#endif
	}

	return (status != 0);
}

static int webdav_delete_dir(server *srv, connection *con, plugin_data *p, physical *dst, buffer *b) {
	DIR *dir;
	int have_multi_status = 0;
	physical d;

	d.path = buffer_init();
	d.rel_path = buffer_init();

	if (NULL != (dir = opendir(dst->path->ptr))) {
		struct dirent *de;

		while(NULL != (de = readdir(dir))) {
			struct stat st;
			int status = 0;

			if ((de->d_name[0] == '.' && de->d_name[1] == '\0')  ||
			    (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == '\0')) {
				continue;
				/* ignore the parent dir */
			} 

			buffer_copy_string_buffer(d.path, dst->path);
			BUFFER_APPEND_SLASH(d.path);
			buffer_append_string(d.path, de->d_name);
			
			buffer_copy_string_buffer(d.rel_path, dst->rel_path);
			BUFFER_APPEND_SLASH(d.rel_path);
			buffer_append_string(d.rel_path, de->d_name);

			/* stat and unlink afterwards */
			if (-1 == stat(d.path->ptr, &st)) {
				/* don't about it yet, rmdir will fail too */
			} else if (S_ISDIR(st.st_mode)) {
				have_multi_status = webdav_delete_dir(srv, con, p, &d, b);
					
				/* try to unlink it */
				if (-1 == rmdir(d.path->ptr)) {
					switch(errno) {
					case EACCES:
					case EPERM:
						/* 403 */
						status = 403;
						break;
					default:
						status = 501;
						break;
					}
					have_multi_status = 1;

					webdav_gen_response_status_tag(srv, con, &d, status, b);
				} else {
#ifdef USE_PROPPATCH
					sqlite3_stmt *stmt = p->conf.stmt_delete_uri;

					status = 0;

					sqlite3_reset(stmt);

					/* bind the values to the insert */

					sqlite3_bind_text(stmt, 1, 
							  d.rel_path->ptr, 
							  d.rel_path->used - 1,
							  SQLITE_TRANSIENT);
													
					if (SQLITE_DONE != sqlite3_step(stmt)) {
						/* */
						WP();
					}
#endif
				}
			} else {
				have_multi_status = webdav_delete_file(srv, con, p, &d, b);
			}
		}
		closedir(dir);

		buffer_free(d.path);
		buffer_free(d.rel_path);
	}

	return have_multi_status;
}

static int webdav_copy_file(server *srv, connection *con, plugin_data *p, physical *src, physical *dst, int overwrite) {
	stream s;
	int status = 0, ofd;

	UNUSED(con);

	if (stream_open(&s, src->path)) {
		return 403;
	}
			
	if (-1 == (ofd = open(dst->path->ptr, O_WRONLY|O_TRUNC|O_CREAT|(overwrite ? 0 : O_EXCL), 0600))) {
		/* opening the destination failed for some reason */
		switch(errno) {
		case EEXIST:
			status = 412;
			break;
		case EISDIR:
			status = 409;
			break;
		case ENOENT:
			/* at least one part in the middle wasn't existing */
			status = 409;
			break;
		default:
			status = 403;
			break;
		}
		stream_close(&s);
		return status;
	}

	if (-1 == write(ofd, s.start, s.size)) {
		switch(errno) {
		case ENOSPC:
			status = 507;
			break;
		default:
			status = 403;
			break;
		}
	}
	
	stream_close(&s);
	close(ofd);

#ifdef USE_PROPPATCH
	if (0 == status) {
		/* copy worked fine, copy connected properties */
		sqlite3_stmt *stmt = p->conf.stmt_copy_uri;

		sqlite3_reset(stmt);

		/* bind the values to the insert */
		sqlite3_bind_text(stmt, 1, 
				  dst->rel_path->ptr, 
				  dst->rel_path->used - 1,
				  SQLITE_TRANSIENT);

		sqlite3_bind_text(stmt, 2, 
				  src->rel_path->ptr, 
				  src->rel_path->used - 1,
				  SQLITE_TRANSIENT);
													
		if (SQLITE_DONE != sqlite3_step(stmt)) {
			/* */
			WP();
		}
	}
#endif
	return status;
}

static int webdav_copy_dir(server *srv, connection *con, plugin_data *p, physical *src, physical *dst, int overwrite) {
	DIR *srcdir;
	int status = 0;

	if (NULL != (srcdir = opendir(src->path->ptr))) {
		struct dirent *de;
		physical s, d;

		s.path = buffer_init();
		s.rel_path = buffer_init();

		d.path = buffer_init();
		d.rel_path = buffer_init();

		while (NULL != (de = readdir(srcdir))) {
			struct stat st;

			if ((de->d_name[0] == '.' && de->d_name[1] == '\0') ||
		            (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == '\0')) {
				continue;
			}
			
			buffer_copy_string_buffer(s.path, src->path);
			BUFFER_APPEND_SLASH(s.path);
			buffer_append_string(s.path, de->d_name);

			buffer_copy_string_buffer(d.path, dst->path);
			BUFFER_APPEND_SLASH(d.path);
			buffer_append_string(d.path, de->d_name);

			buffer_copy_string_buffer(s.rel_path, src->rel_path);
			BUFFER_APPEND_SLASH(s.rel_path);
			buffer_append_string(s.rel_path, de->d_name);

			buffer_copy_string_buffer(d.rel_path, dst->rel_path);
			BUFFER_APPEND_SLASH(d.rel_path);
			buffer_append_string(d.rel_path, de->d_name);

			if (-1 == stat(s.path->ptr, &st)) {
				/* why ? */
			} else if (S_ISDIR(st.st_mode)) {
				/* a directory */
				if (-1 == mkdir(d.path->ptr, 0700) &&
				    errno != EEXIST) {
					/* WTH ? */
				} else {
#ifdef USE_PROPPATCH
					sqlite3_stmt *stmt = p->conf.stmt_copy_uri;

					if (0 != (status = webdav_copy_dir(srv, con, p, &s, &d, overwrite))) {
						break;
					}
					/* directory is copied, copy the properties too */
				
					sqlite3_reset(stmt);

					/* bind the values to the insert */
					sqlite3_bind_text(stmt, 1, 
						  dst->rel_path->ptr, 
						  dst->rel_path->used - 1,
						  SQLITE_TRANSIENT);

					sqlite3_bind_text(stmt, 2, 
						  src->rel_path->ptr, 
						  src->rel_path->used - 1,
						  SQLITE_TRANSIENT);
													
					if (SQLITE_DONE != sqlite3_step(stmt)) {
						/* */
						WP();
					}
#endif
				}
			} else if (S_ISREG(st.st_mode)) {
				/* a plain file */
				if (0 != (status = webdav_copy_file(srv, con, p, &s, &d, overwrite))) {
					break;
				}
			}
		}

		buffer_free(s.path);
		buffer_free(s.rel_path);
		buffer_free(d.path);
		buffer_free(d.rel_path);
		
		closedir(srcdir);
	}

	return status;
}

static int webdav_get_live_property(server *srv, connection *con, plugin_data *p, physical *dst, char *prop_name, buffer *b) {
	stat_cache_entry *sce = NULL;
	int found = 0;

	if (HANDLER_ERROR != (stat_cache_get_entry(srv, con, dst->path, &sce))) {
		char ctime_buf[] = "2005-08-18T07:27:16Z";
		char mtime_buf[] = "Thu, 18 Aug 2005 07:27:16 GMT";
		size_t k;

		if (0 == strcmp(prop_name, "resourcetype")) {
			if (S_ISDIR(sce->st.st_mode)) {
				buffer_append_string(b, "<D:resourcetype><D:collection/></D:resourcetype>");
				found = 1;
			}
		} else if (0 == strcmp(prop_name, "getcontenttype")) {
			if (S_ISDIR(sce->st.st_mode)) {
				buffer_append_string(b, "<D:getcontenttype>httpd/unix-directory</D:getcontenttype>");
				found = 1;
			} else if(S_ISREG(sce->st.st_mode)) { 
				for (k = 0; k < con->conf.mimetypes->used; k++) {
					data_string *ds = (data_string *)con->conf.mimetypes->data[k];
		
					if (ds->key->used == 0) continue;
				
					if (buffer_is_equal_right_len(dst->path, ds->key, ds->key->used - 1)) {
						buffer_append_string(b,"<D:getcontenttype>");
						buffer_append_string_buffer(b, ds->value);
						buffer_append_string(b, "</D:getcontenttype>");
						found = 1;

						break;
					}
				}
			}
		} else if (0 == strcmp(prop_name, "creationdate")) {
			buffer_append_string(b, "<D:creationdate ns0:dt=\"dateTime.tz\">");
			strftime(ctime_buf, sizeof(ctime_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&(sce->st.st_ctime)));
			buffer_append_string(b, ctime_buf);
			buffer_append_string(b, "</D:creationdate>");
			found = 1;
		} else if (0 == strcmp(prop_name, "getlastmodified")) {
			buffer_append_string(b,"<D:getlastmodified ns0:dt=\"dateTime.rfc1123\">");
			strftime(mtime_buf, sizeof(mtime_buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&(sce->st.st_mtime)));
			buffer_append_string(b, mtime_buf);
			buffer_append_string(b, "</D:getlastmodified>");
			found = 1;
		} else if (0 == strcmp(prop_name, "getcontentlength")) {
			buffer_append_string(b,"<D:getcontentlength>");
			buffer_append_off_t(b, sce->st.st_size);
			buffer_append_string(b, "</D:getcontentlength>");
			found = 1;
		} else if (0 == strcmp(prop_name, "getcontentlanguage")) {
			buffer_append_string(b,"<D:getcontentlanguage>");
			buffer_append_string(b, "en");
			buffer_append_string(b, "</D:getcontentlanguage>");
			found = 1;
		}
	}

	return found ? 0 : -1;
}

static int webdav_get_property(server *srv, connection *con, plugin_data *p, physical *dst, char *prop_name, char *prop_ns, buffer *b) {
	if (0 == strcmp(prop_ns, "DAV:")) {
		/* a local 'live' property */
		return webdav_get_live_property(srv, con, p, dst, prop_name, b);
	} else {
		int found = 0;
#ifdef USE_PROPPATCH
		/* perhaps it is in sqlite3 */
		sqlite3_reset(p->conf.stmt_select_prop);

		/* bind the values to the insert */

		sqlite3_bind_text(p->conf.stmt_select_prop, 1, 
				  dst->rel_path->ptr, 
				  dst->rel_path->used - 1,
				  SQLITE_TRANSIENT);
		sqlite3_bind_text(p->conf.stmt_select_prop, 2, 
				  prop_name,
				  strlen(prop_name),
				  SQLITE_TRANSIENT);
		sqlite3_bind_text(p->conf.stmt_select_prop, 3, 
				  prop_ns,
				  strlen(prop_ns),
				  SQLITE_TRANSIENT);

		/* it is the PK */
		while (SQLITE_ROW == sqlite3_step(p->conf.stmt_select_prop)) {
			/* there is a row for us, we only expect a single col 'value' */
			webdav_gen_prop_tag(srv, con, prop_name, prop_ns, (char *)sqlite3_column_text(p->conf.stmt_select_prop, 0), b);
			found = 1;
		}
#endif
		return found ? 0 : -1;
	}

	/* not found */
	return -1;
}

typedef struct {
	char *ns;
	char *prop;
} webdav_property;

webdav_property live_properties[] = { 
	{ "DAV:", "creationdate" },
	{ "DAV:", "displayname" },
	{ "DAV:", "getcontentlanguage" },
	{ "DAV:", "getcontentlength" },
	{ "DAV:", "getcontenttype" },
	{ "DAV:", "getetag" },
	{ "DAV:", "getlastmodified" },
	{ "DAV:", "resourcetype" },
	{ "DAV:", "lockdiscovery" },
	{ "DAV:", "source" },
	{ "DAV:", "supportedlock" },

	{ NULL, NULL }
};

typedef struct {
	webdav_property **ptr;

	size_t used;
	size_t size;
} webdav_properties;

static int webdav_get_props(server *srv, connection *con, plugin_data *p, physical *dst, webdav_properties *props, buffer *b_200, buffer *b_404) {
	size_t i;

	if (props) {
		for (i = 0; i < props->used; i++) {
			webdav_property *prop;

			prop = props->ptr[i];
			
			if (0 != webdav_get_property(srv, con, p, 
				dst, prop->prop, prop->ns, b_200)) {
				webdav_gen_prop_tag(srv, con, prop->prop, prop->ns, NULL, b_404);
			}
		}
	} else {
		for (i = 0; live_properties[i].prop; i++) {
			/* a local 'live' property */
			webdav_get_live_property(srv, con, p, dst, live_properties[i].prop, b_200);
		}
	}

	return 0;
}

URIHANDLER_FUNC(mod_webdav_subrequest_handler) {
	plugin_data *p = p_d;
	buffer *b;
	DIR *dir;
	data_string *ds;
	int depth = -1;
	struct stat st;
	buffer *prop_200;
	buffer *prop_404;
	webdav_properties *req_props;
	
	UNUSED(srv);

	if (!p->conf.enabled) return HANDLER_GO_ON;
	/* physical path is setup */
	if (con->physical.path->used == 0) return HANDLER_GO_ON;

	/* PROPFIND need them */
	if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Depth"))) {
		depth = strtol(ds->value->ptr, NULL, 10);
	}

	switch (con->request.http_method) {
	case HTTP_METHOD_PROPFIND:
		/* they want to know the properties of the directory */
		req_props = NULL;

		/* is there a content-body ? */
	
#ifdef USE_PROPPATCH
		/* any special requests or just allprop ? */
		if (con->request.content_length) {
			xmlDocPtr xml;
			buffer *xmldoc = con->request.content;

			if (NULL != (xml = xmlReadMemory(xmldoc->ptr, xmldoc->used - 1, "DAV", NULL, 0))) {
				xmlNode *rootnode = xmlDocGetRootElement(xml);

				if (0 == xmlStrcmp(rootnode->name, BAD_CAST "propfind")) {
					xmlNode *cmd;

					req_props = calloc(1, sizeof(*req_props));

					for (cmd = rootnode->children; cmd; cmd = cmd->next) {

						if (0 == xmlStrcmp(cmd->name, BAD_CAST "prop")) {
							/* get prop by name */
							xmlNode *prop;

							for (prop = cmd->children; prop; prop = prop->next) {
								if (prop->type == XML_TEXT_NODE) continue; /* ignore WS */

								if (prop->ns &&
								    (0 == xmlStrcmp(prop->ns->href, BAD_CAST "")) &&
								    (0 != xmlStrcmp(prop->ns->prefix, BAD_CAST ""))) {
									size_t i;
									log_error_write(srv, __FILE__, __LINE__, "ss",
											"no name space for:",
											prop->name);

									xmlFreeDoc(xml);

									for (i = 0; i < req_props->used; i++) {
										free(req_props->ptr[i]->ns);
										free(req_props->ptr[i]->prop);
										free(req_props->ptr[i]);
									}
									free(req_props->ptr);
									free(req_props);

									con->http_status = 400;
									return HANDLER_FINISHED;
								}

								/* add property to requested list */
								if (req_props->size == 0) {
									req_props->size = 16;
									req_props->ptr = malloc(sizeof(*(req_props->ptr)) * req_props->size);
								} else if (req_props->used == req_props->size) {
									req_props->size += 16;
									req_props->ptr = realloc(req_props->ptr, sizeof(*(req_props->ptr)) * req_props->size);
								}

								req_props->ptr[req_props->used] = malloc(sizeof(webdav_property));
								req_props->ptr[req_props->used]->ns = (char *)xmlStrdup(prop->ns ? prop->ns->href : (xmlChar *)"");
								req_props->ptr[req_props->used]->prop = (char *)xmlStrdup(prop->name);
								req_props->used++;
							}
						} else if (0 == xmlStrcmp(cmd->name, BAD_CAST "propname")) {
							/* get all property names (EMPTY) */
							sqlite3_reset(p->conf.stmt_select_propnames);
							/* bind the values to the insert */

							sqlite3_bind_text(p->conf.stmt_select_propnames, 1, 
									  con->uri.path->ptr, 
									  con->uri.path->used - 1,
									  SQLITE_TRANSIENT);
						
							if (SQLITE_DONE != sqlite3_step(p->conf.stmt_select_propnames)) {
								WP();
							}

						} else if (0 == xmlStrcmp(cmd->name, BAD_CAST "allprop")) {
							/* get all properties (EMPTY) */
						}
					}
				}

				xmlFreeDoc(xml);
			} else {
				con->http_status = 400;
				return HANDLER_FINISHED;
			}
		}
#endif
		con->http_status = 207;

		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml; charset=\"utf-8\""));

		b = chunkqueue_get_append_buffer(con->write_queue);
				
		buffer_copy_string(b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

		buffer_append_string(b,"<D:multistatus xmlns:D=\"DAV:\" xmlns:ns0=\"urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/\">\n");

		/* allprop */
		
		prop_200 = buffer_init();
		prop_404 = buffer_init();

		switch(depth) {
		case 0:
			/* Depth: 0 */
			webdav_get_props(srv, con, p, &(con->physical), req_props, prop_200, prop_404);
	
			buffer_append_string(b,"<D:response>\n");
			buffer_append_string(b,"<D:href>");
			buffer_append_string_buffer(b, con->uri.scheme);
			buffer_append_string(b,"://");
			buffer_append_string_buffer(b, con->uri.authority);
			buffer_append_string_buffer(b, con->uri.path);
			buffer_append_string(b,"</D:href>\n");

			if (!buffer_is_empty(prop_200)) {
				buffer_append_string(b,"<D:propstat>\n");
				buffer_append_string(b,"<D:prop>\n");

				buffer_append_string_buffer(b, prop_200);

				buffer_append_string(b,"</D:prop>\n");
	
				buffer_append_string(b,"<D:status>HTTP/1.1 200 OK</D:status>\n");
	
				buffer_append_string(b,"</D:propstat>\n");
			}
			if (!buffer_is_empty(prop_404)) {
				buffer_append_string(b,"<D:propstat>\n");
				buffer_append_string(b,"<D:prop>\n");

				buffer_append_string_buffer(b, prop_404);

				buffer_append_string(b,"</D:prop>\n");
	
				buffer_append_string(b,"<D:status>HTTP/1.1 404 Not Found</D:status>\n");
	
				buffer_append_string(b,"</D:propstat>\n");
			}

			buffer_append_string(b,"</D:response>\n");

			break;
		case 1:	
			if (NULL != (dir = opendir(con->physical.path->ptr))) {
				struct dirent *de;
				physical d;
				physical *dst = &(con->physical);

				d.path = buffer_init();
				d.rel_path = buffer_init();

				while(NULL != (de = readdir(dir))) {
					if ((de->d_name[0] == '.' && de->d_name[1] == '\0')  ||
					    (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == '\0')) {
						continue;
						/* ignore the parent dir */
					} 

					buffer_copy_string_buffer(d.path, dst->path);
					BUFFER_APPEND_SLASH(d.path);
					buffer_append_string(d.path, de->d_name);
			
					buffer_copy_string_buffer(d.rel_path, dst->rel_path);
					BUFFER_APPEND_SLASH(d.rel_path);
					buffer_append_string(d.rel_path, de->d_name);

					buffer_reset(prop_200);
					buffer_reset(prop_404);

					webdav_get_props(srv, con, p, &d, req_props, prop_200, prop_404);
					
					buffer_append_string(b,"<D:response>\n");
					buffer_append_string(b,"<D:href>");
					buffer_append_string_buffer(b, con->uri.scheme);
					buffer_append_string(b,"://");
					buffer_append_string_buffer(b, con->uri.authority);
					buffer_append_string_buffer(b, d.rel_path);
					buffer_append_string(b,"</D:href>\n");

					if (!buffer_is_empty(prop_200)) {
						buffer_append_string(b,"<D:propstat>\n");
						buffer_append_string(b,"<D:prop>\n");

						buffer_append_string_buffer(b, prop_200);

						buffer_append_string(b,"</D:prop>\n");
			
						buffer_append_string(b,"<D:status>HTTP/1.1 200 OK</D:status>\n");
			
						buffer_append_string(b,"</D:propstat>\n");
					}
					if (!buffer_is_empty(prop_404)) {
						buffer_append_string(b,"<D:propstat>\n");
						buffer_append_string(b,"<D:prop>\n");

						buffer_append_string_buffer(b, prop_404);

						buffer_append_string(b,"</D:prop>\n");
	
						buffer_append_string(b,"<D:status>HTTP/1.1 404 Not Found</D:status>\n");
	
						buffer_append_string(b,"</D:propstat>\n");
					}

					buffer_append_string(b,"</D:response>\n");
				}
				closedir(dir);
				buffer_free(d.path);
				buffer_free(d.rel_path);
			}
			break;
		}

		if (req_props) {
			size_t i;
			for (i = 0; i < req_props->used; i++) {
				free(req_props->ptr[i]->ns);
				free(req_props->ptr[i]->prop);
				free(req_props->ptr[i]);
			}
			free(req_props->ptr);
			free(req_props);
		}

		buffer_append_string(b,"</D:multistatus>\n");

		con->file_finished = 1;

		return HANDLER_FINISHED;
	case HTTP_METHOD_MKCOL:
		if (p->conf.is_readonly) {
			con->http_status = 403;
			return HANDLER_FINISHED;
		}

		if (con->request.content_length != 0) {
			/* we don't support MKCOL with a body */
			con->http_status = 415;

			return HANDLER_FINISHED;
		}
	
		/* let's create the directory */

		if (-1 == mkdir(con->physical.path->ptr, 0700)) {
			switch(errno) {
			case EPERM:
				con->http_status = 403;
				break;
			case ENOENT:
			case ENOTDIR:
				con->http_status = 409;
				break;
			case EEXIST:
			default:
				con->http_status = 405; /* not allowed */
				break;
			}
		} else {
			con->http_status = 201;
		}

		return HANDLER_FINISHED;
	case HTTP_METHOD_DELETE:
		if (p->conf.is_readonly) {
			con->http_status = 403;
			return HANDLER_FINISHED;
		}
		
		/* stat and unlink afterwards */
		if (-1 == stat(con->physical.path->ptr, &st)) {
			/* don't about it yet, unlink will fail too */
			switch(errno) {
			case ENOENT:
				 con->http_status = 404;
				 break;
			default:
				 con->http_status = 403;
				 break;
			}
		} else if (S_ISDIR(st.st_mode)) {
			buffer *multi_status_resp = buffer_init();

			if (webdav_delete_dir(srv, con, p, &(con->physical), multi_status_resp)) {
				/* we got an error somewhere in between, build a 207 */
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml; charset=\"utf-8\""));

				b = chunkqueue_get_append_buffer(con->write_queue);
			
				buffer_copy_string(b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

				buffer_append_string(b,"<D:multistatus xmlns:D=\"DAV:\">\n");

				buffer_append_string_buffer(b, multi_status_resp);

				buffer_append_string(b,"</D:multistatus>\n");
			
				con->http_status = 207;
				con->file_finished = 1;
			} else {
				/* everything went fine, remove the directory */
	
				if (-1 == rmdir(con->physical.path->ptr)) {
					switch(errno) {
					case ENOENT:
						con->http_status = 404;
						break;
					default:
						con->http_status = 501;
						break;
					}
				} else {
					con->http_status = 204;
				}
			}

			buffer_free(multi_status_resp);
		} else if (-1 == unlink(con->physical.path->ptr)) {
			switch(errno) {
			case EPERM:
				con->http_status = 403;
				break;
			case ENOENT:
				con->http_status = 404;
				break;
			default:
				con->http_status = 501;
				break;
			}
		} else {
			con->http_status = 204;
		}
		return HANDLER_FINISHED;
	case HTTP_METHOD_PUT: {
		int fd;

		if (p->conf.is_readonly) {
			con->http_status = 403;
			return HANDLER_FINISHED;
		}
		
		/* taken what we have in the request-body and write it to a file */
		if (-1 == (fd = open(con->physical.path->ptr, O_WRONLY|O_CREAT|O_TRUNC, 0600))) {
			/* we can't open the file */
			con->http_status = 403;
		} else {
			con->http_status = 201; /* created */

			if (-1 == (write(fd, con->request.content->ptr, con->request.content->used - 1))) {
				switch(errno) {
				case ENOSPC:
					con->http_status = 507;

					break;
				default:
					con->http_status = 403;
					break;
				}
			}
			close(fd);
		}
		return HANDLER_FINISHED;
	}
	case HTTP_METHOD_MOVE: 
	case HTTP_METHOD_COPY: {
		buffer *destination = NULL;
		char *sep, *start;
		int overwrite = 1;

		if (p->conf.is_readonly) {
			con->http_status = 403;
			return HANDLER_FINISHED;
		}
		
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Destination"))) {
			destination = ds->value;
		} else {
			con->http_status = 400;
			return HANDLER_FINISHED;
		}

		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Overwrite"))) {
			if (ds->value->used != 2 ||
			    (ds->value->ptr[0] != 'F' &&
			     ds->value->ptr[0] != 'T') )  {
				con->http_status = 400;
				return HANDLER_FINISHED;
			}
			overwrite = (ds->value->ptr[0] == 'F' ? 0 : 1);
		}
		/* let's parse the Destination
		 *
		 * http://127.0.0.1:1025/dav/litmus/copydest
		 *
		 * - host has to be the same as the Host: header we got
		 * - we have to stay inside the document root
		 * - the query string is thrown away
		 *  */

		buffer_reset(p->uri.scheme);
		buffer_reset(p->uri.path_raw);
		buffer_reset(p->uri.authority);

		start = destination->ptr;

		if (NULL == (sep = strstr(start, "://"))) {
			con->http_status = 400;
			return HANDLER_FINISHED;
		}
		buffer_copy_string_len(p->uri.scheme, start, sep - start);

		start = sep + 3;

		if (NULL == (sep = strchr(start, '/'))) {
			con->http_status = 400;
			return HANDLER_FINISHED;
		}
		buffer_copy_string_len(p->uri.authority, start, sep - start);

		start = sep + 1;

		if (NULL == (sep = strchr(start, '?'))) {
			/* no query string, good */
			buffer_copy_string(p->uri.path_raw, start);
		} else {
			buffer_copy_string_len(p->uri.path_raw, start, sep - start);
		}

		if (!buffer_is_equal(p->uri.authority, con->uri.authority)) {
			/* not the same host */
			con->http_status = 502;
			return HANDLER_FINISHED;
		}

		buffer_copy_string_buffer(p->tmp_buf, p->uri.path_raw);
		buffer_urldecode_path(p->tmp_buf);
		buffer_path_simplify(p->uri.path, p->tmp_buf);

		/* we now have a URI which is clean. transform it into a physical path */
		buffer_copy_string_buffer(p->physical.doc_root, con->conf.document_root);
		buffer_copy_string_buffer(p->physical.rel_path, p->uri.path);

		if (con->conf.force_lower_case) {
			buffer_to_lower(p->physical.rel_path);
		}

		buffer_copy_string_buffer(p->physical.path, p->physical.doc_root);
		BUFFER_APPEND_SLASH(p->physical.path);
		buffer_copy_string_buffer(p->physical.basedir, p->physical.path);

		/* don't add a second / */ 
		if (p->physical.rel_path->ptr[0] == '/') {
			buffer_append_string_len(p->physical.path, p->physical.rel_path->ptr + 1, p->physical.rel_path->used - 2);
		} else {
			buffer_append_string_buffer(p->physical.path, p->physical.rel_path);
		}

		/* let's see if the source is a directory
		 * if yes, we fail with 501 */

		if (-1 == stat(con->physical.path->ptr, &st)) {
			/* don't about it yet, unlink will fail too */
			switch(errno) {
			case ENOENT:
				 con->http_status = 404;
				 break;
			default:
				 con->http_status = 403;
				 break;
			}
		} else if (S_ISDIR(st.st_mode)) {
			int r;
			/* src is a directory */

			if (-1 == stat(p->physical.path->ptr, &st)) {
				if (-1 == mkdir(p->physical.path->ptr, 0700)) {
					con->http_status = 403;
					return HANDLER_FINISHED;
				}
			} else if (!S_ISDIR(st.st_mode)) {
				if (overwrite == 0) {
					/* copying into a non-dir ? */
					con->http_status = 409;
					return HANDLER_FINISHED;
				} else {
					unlink(p->physical.path->ptr);
					if (-1 == mkdir(p->physical.path->ptr, 0700)) {
						con->http_status = 403;
						return HANDLER_FINISHED;
					}
				}
			}

			/* copy the content of src to dest */
			if (0 != (r = webdav_copy_dir(srv, con, p, &(con->physical), &(p->physical), overwrite))) {
				con->http_status = r;
				return HANDLER_FINISHED;
			}
			if (con->request.http_method == HTTP_METHOD_MOVE) {
				b = buffer_init();
				webdav_delete_dir(srv, con, p, &(con->physical), b); /* content */
				buffer_free(b);

				rmdir(con->physical.path->ptr);
			}
			con->http_status = 201;
		} else {
			/* it is just a file, good */
			int r;

			/* destination exists */
			if (0 == (r = stat(p->physical.path->ptr, &st))) {
				if (S_ISDIR(st.st_mode)) {
					/* file to dir/
					 * append basename to physical path */

					if (NULL != (sep = strrchr(con->physical.path->ptr, '/'))) {
						buffer_append_string(p->physical.path, sep);
						r = stat(p->physical.path->ptr, &st);
					}
				}
			}

			if (-1 == r) {
				con->http_status = 201; /* we will create a new one */

				switch(errno) {
				case ENOTDIR:
					con->http_status = 409;
					return HANDLER_FINISHED;
				}
			} else if (overwrite == 0) {
				/* destination exists, but overwrite is not set */ 
				con->http_status = 412;
				return HANDLER_FINISHED;
			} else {
				con->http_status = 204; /* resource already existed */
			}

			if (con->request.http_method == HTTP_METHOD_MOVE) {
				/* try a rename */

				if (0 == rename(con->physical.path->ptr, p->physical.path->ptr)) {
#ifdef USE_PROPPATCH
					sqlite3_stmt *stmt = p->conf.stmt_move_uri;

					sqlite3_reset(stmt);

					/* bind the values to the insert */
					sqlite3_bind_text(stmt, 1, 
							  p->uri.path->ptr, 
							  p->uri.path->used - 1,
							  SQLITE_TRANSIENT);

					sqlite3_bind_text(stmt, 2, 
							  con->uri.path->ptr, 
							  con->uri.path->used - 1,
							  SQLITE_TRANSIENT);
					
					if (SQLITE_DONE != sqlite3_step(stmt)) {
						log_error_write(srv, __FILE__, __LINE__, "ss", "sql-move failed:", sqlite3_errmsg(p->conf.sql));
					}
#endif
					return HANDLER_FINISHED;
				}

				/* rename failed, fall back to COPY + DELETE */
			}

			if (0 != (r = webdav_copy_file(srv, con, p, &(con->physical), &(p->physical), overwrite))) {
				con->http_status = r;

				return HANDLER_FINISHED;
			}

			if (con->request.http_method == HTTP_METHOD_MOVE) {
				b = buffer_init();
				webdav_delete_file(srv, con, p, &(con->physical), b);
				buffer_free(b);
			}
		}

		return HANDLER_FINISHED;
	}
	case HTTP_METHOD_PROPPATCH: {
		if (p->conf.is_readonly) {
			con->http_status = 403;
			return HANDLER_FINISHED;
		}

		/* check if destination exists */
		if (-1 == stat(con->physical.path->ptr, &st)) {
			switch(errno) {
			case ENOENT:
				con->http_status = 404;
				break;
			}
		}

#ifdef USE_PROPPATCH
		if (con->request.content_length) {
			xmlDocPtr xml;
			buffer *xmldoc = con->request.content;

			if (NULL != (xml = xmlReadMemory(xmldoc->ptr, xmldoc->used - 1, "DAV", NULL, 0))) {
				xmlNode *rootnode = xmlDocGetRootElement(xml);

				if (0 == xmlStrcmp(rootnode->name, BAD_CAST "propertyupdate")) {
					xmlNode *cmd;
					char *err = NULL;
					int empty_ns = 0; /* send 400 on a empty namespace attribute */

					/* start response */

					if (SQLITE_OK != sqlite3_exec(p->conf.sql, "BEGIN TRANSACTION", NULL, NULL, &err)) {
						log_error_write(srv, __FILE__, __LINE__, "ss", "can't open transaction:", err);
						sqlite3_free(err);

						goto propmatch_cleanup;
					}

					/* a UPDATE request, we know 'set' and 'remove' */
					for (cmd = rootnode->children; cmd; cmd = cmd->next) {
						xmlNode *props;
						/* either set or remove */

						if ((0 == xmlStrcmp(cmd->name, BAD_CAST "set")) ||
						    (0 == xmlStrcmp(cmd->name, BAD_CAST "remove"))) {

							sqlite3_stmt *stmt;

							stmt = (0 == xmlStrcmp(cmd->name, BAD_CAST "remove")) ? 
								p->conf.stmt_delete_prop : p->conf.stmt_update_prop;

							for (props = cmd->children; props; props = props->next) {
								if (0 == xmlStrcmp(props->name, BAD_CAST "prop")) {
									xmlNode *prop;
									int r;

									prop = props->children;

									if (prop->ns &&
									    (0 == xmlStrcmp(prop->ns->href, BAD_CAST "")) &&
									    (0 != xmlStrcmp(prop->ns->prefix, BAD_CAST ""))) {
										log_error_write(srv, __FILE__, __LINE__, "ss",
												"no name space for:",
												prop->name);

										empty_ns = 1;
										break;
									}

									sqlite3_reset(stmt);

									/* bind the values to the insert */

									sqlite3_bind_text(stmt, 1, 
											  con->uri.path->ptr, 
											  con->uri.path->used - 1,
											  SQLITE_TRANSIENT);
									sqlite3_bind_text(stmt, 2, 
											  (char *)prop->name,
											  strlen((char *)prop->name),
											  SQLITE_TRANSIENT);
									if (prop->ns) {
										sqlite3_bind_text(stmt, 3, 
												  (char *)prop->ns->href,
												  strlen((char *)prop->ns->href),
												  SQLITE_TRANSIENT);
									} else {
										sqlite3_bind_text(stmt, 3, 
												  "",
												  0,
												  SQLITE_TRANSIENT);
									}
									if (stmt == p->conf.stmt_update_prop) {
										sqlite3_bind_text(stmt, 4, 
											  (char *)xmlNodeGetContent(prop),
											  strlen((char *)xmlNodeGetContent(prop)),
											  SQLITE_TRANSIENT);
									}
								
									if (SQLITE_DONE != (r = sqlite3_step(stmt))) {
										log_error_write(srv, __FILE__, __LINE__, "ss", "sql-set failed:", sqlite3_errmsg(p->conf.sql));
									}
								}
							}
							if (empty_ns) break;
						}
					}

					if (empty_ns) {
						if (SQLITE_OK != sqlite3_exec(p->conf.sql, "ROLLBACK", NULL, NULL, &err)) {
							log_error_write(srv, __FILE__, __LINE__, "ss", "can't rollback transaction:", err);
							sqlite3_free(err);

							goto propmatch_cleanup;
						}
	
						con->http_status = 400;
					} else {
						if (SQLITE_OK != sqlite3_exec(p->conf.sql, "COMMIT", NULL, NULL, &err)) {
							log_error_write(srv, __FILE__, __LINE__, "ss", "can't commit transaction:", err);
							sqlite3_free(err);

							goto propmatch_cleanup;
						}
						con->http_status = 200;
					}
					con->file_finished = 1;

					return HANDLER_FINISHED;
				}

propmatch_cleanup:
				xmlFreeDoc(xml);
			} else {
				con->http_status = 400;
				return HANDLER_FINISHED;
			}
		}
#endif
		con->http_status = 501;
		return HANDLER_FINISHED;
	}
	default:
		break;
	}
	
	/* not found */
	return HANDLER_GO_ON;
}


/* this function is called at dlopen() time and inits the callbacks */

int mod_webdav_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("webdav");
	
	p->init        = mod_webdav_init;
	p->handle_uri_clean  = mod_webdav_uri_handler;
	p->handle_physical   = mod_webdav_subrequest_handler;
	p->set_defaults  = mod_webdav_set_defaults;
	p->cleanup     = mod_webdav_free;
	
	p->data        = NULL;
	
	return 0;
}
