#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "response.h"

#include "plugin.h"

#include "config.h"

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
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	buffer *tmp_buf;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_webdav_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->tmp_buf = buffer_init();
	
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
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		
		cv[0].destination = &(s->enabled);
		cv[1].destination = &(s->is_readonly);
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
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
			response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("PROPFIND, DELETE, MKCOL"));
		}
		break;
	default:
		break;
	}
	
	/* not found */
	return HANDLER_GO_ON;
}

static int get_response_entry(server *srv, connection *con, plugin_data *p, buffer *b, const char *filename) {
	struct stat st;

	UNUSED(srv);

	buffer_append_string(b,"<D:response xmlns:ns0=\"urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/\">\n");

	buffer_append_string(b,"<D:href>\n");
	buffer_append_string_buffer(b, con->uri.path);
	BUFFER_APPEND_SLASH(b);
	buffer_append_string(b, filename);
	buffer_append_string(b,"</D:href>\n");
	buffer_append_string(b,"<D:propstat>\n");
	/* we have to stat now */

	buffer_copy_string_buffer(p->tmp_buf, con->physical.path);
	BUFFER_APPEND_SLASH(p->tmp_buf);
	buffer_append_string(p->tmp_buf, filename);

	if (0 == stat(p->tmp_buf->ptr, &st)) {
		char ctime_buf[] = "2005-08-18T07:27:16Z";
		char mtime_buf[] = "Thu, 18 Aug 2005 07:27:16 GMT";
		size_t k;

		buffer_append_string(b,"<D:prop>\n");
		if (S_ISDIR(st.st_mode)) {
			buffer_append_string(b, "<D:resourcetype><D:collection/></D:resourcetype>"
					        "<D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n");
		}

		buffer_append_string(b, "<D:creationdate ns0:dt=\"dateTime.tz\">");
		strftime(ctime_buf, sizeof(ctime_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&st.st_ctime));
		buffer_append_string(b, ctime_buf);
		buffer_append_string(b, "</D:creationdate>");
		
		buffer_append_string(b,"<D:getlastmodified ns0:dt=\"dateTime.rfc1123\">");
		strftime(mtime_buf, sizeof(mtime_buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&st.st_mtime));
		buffer_append_string(b, mtime_buf);
		buffer_append_string(b, "</D:getlastmodified>");

		buffer_append_string(b,"<D:getcontentlength>");
		buffer_append_off_t(b, st.st_size);
		buffer_append_string(b, "</D:getcontentlength>");

		buffer_append_string(b,"<D:getcontentlanguage>");
		buffer_append_string(b, "en");
		buffer_append_string(b, "</D:getcontentlanguage>");

		for (k = 0; k < con->conf.mimetypes->used; k++) {
			data_string *ds = (data_string *)con->conf.mimetypes->data[k];
		
			if (ds->key->used == 0) continue;
				
			if (buffer_is_equal_right_len(p->tmp_buf, ds->key, ds->key->used - 1)) {
				buffer_append_string(b,"<D:contenttype>");
				buffer_append_string_buffer(b, ds->value);
				buffer_append_string(b, "</D:contenttype>");

				break;
			}
		}
	
		buffer_append_string(b,"</D:prop>\n");

		buffer_append_string(b,"<D:status>HTTP/1.1 200 OK</D:status>\n");
	} else {
		buffer_append_string(b,"<D:status>HTTP/1.1 404 Not Found</D:status>\n");
	}
	buffer_append_string(b,"</D:propstat>\n");
		
	buffer_append_string(b,"</D:response>\n");

	return 0;
}

static int webdav_unlink_dir(server *srv, connection *con, buffer *subdir, buffer *b) {
	DIR *dir;
	buffer *dirname;
	int have_multi_status = 0;

	dirname = buffer_init();

	buffer_copy_string_buffer(dirname, con->physical.path);
	BUFFER_APPEND_SLASH(dirname);
	if (subdir) buffer_append_string_buffer(dirname, subdir);

	if (NULL != (dir = opendir(dirname->ptr))) {
		struct dirent *de;

		while(NULL != (de = readdir(dir))) {
			if (de->d_name[0] == '.' && de->d_name[1] == '\0') {
				/* ignore the current dir */
			} else if (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == '\0') {
				/* ignore the parent dir */
			} else {
				struct stat st;
				buffer *next_subdir = buffer_init();
				int status = 0;

				if (subdir) {
					buffer_copy_string_buffer(next_subdir, subdir);
				} else {
					buffer_copy_string(next_subdir, "/");
				}
				BUFFER_APPEND_SLASH(next_subdir);
				buffer_append_string(next_subdir, de->d_name);
				
				/* physical name of the resource */
				buffer_copy_string_buffer(dirname, con->physical.path);
				BUFFER_APPEND_SLASH(dirname);
				buffer_append_string_buffer(dirname, next_subdir);

				/* stat and unlink afterwards */
				if (-1 == stat(dirname->ptr, &st)) {
					/* don't about it yet, unlink will fail too */
				} else if (S_ISDIR(st.st_mode)) {
					have_multi_status = webdav_unlink_dir(srv, con, next_subdir, b);
					
					/* try to unlink it */
					if (-1 == rmdir(dirname->ptr)) {
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
					} else {
						status = 0;
					}
				} else {
					/* try to unlink it */
					if (-1 == unlink(dirname->ptr)) {
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
					} else {
						status = 0;
					}
				}

				if (status) {
					have_multi_status = 1;

					buffer_append_string(b,"<D:response xmlns:ns0=\"urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/\">\n");

					buffer_append_string(b,"<D:href>\n");
					buffer_append_string_buffer(b, con->uri.path);
					BUFFER_APPEND_SLASH(b);
					buffer_append_string_buffer(b, next_subdir);
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
				}
				buffer_free(next_subdir);
			}
		}
		closedir(dir);
	}

	buffer_free(dirname);

	return have_multi_status;
}
URIHANDLER_FUNC(mod_webdav_subrequest_handler) {
	plugin_data *p = p_d;
	buffer *b;
	DIR *dir;
	data_string *ds;
	int depth = -1;
	struct stat st;
	
	UNUSED(srv);

	if (!p->conf.enabled) return HANDLER_GO_ON;
	/* physical path is setup */
	if (con->physical.path->used == 0) return HANDLER_GO_ON;

	/* PROPFIND and DELETE need them */
	if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Depth"))) {
		depth = strtol(ds->value->ptr, NULL, 10);
	}

	switch (con->request.http_method) {
	case HTTP_METHOD_PROPFIND:
		/* they want to know the properties of the directory */
		
		con->http_status = 207;

		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml; charset=\"utf-8\""));

		b = chunkqueue_get_append_buffer(con->write_queue);
				
		buffer_copy_string(b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

		buffer_append_string(b,"<D:multistatus xmlns:D=\"DAV:\">\n");

		switch(depth) {
		case 0:
			/* Depth: 0 */
			get_response_entry(srv, con, p, b, "");
			break;
		case 1:
			if (NULL != (dir = opendir(con->physical.path->ptr))) {
				struct dirent *de;

				while(NULL != (de = readdir(dir))) {
					if (de->d_name[0] == '.' && de->d_name[1] == '\0') {
						/* ignore the current dir */
					} else if (de->d_name[0] == '.' && de->d_name[1] == '.' && de->d_name[2] == '\0') {
						/* ignore the parent dir */
					} else {
						get_response_entry(srv, con, p, b, de->d_name);
					}
				}
				closedir(dir);
			}
			break;
		}
		
		buffer_append_string(b,"</D:multistatus>\n");

		con->file_finished = 1;

		return HANDLER_FINISHED;
	case HTTP_METHOD_MKCOL:
		if (p->conf.is_readonly) break;

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
		if (p->conf.is_readonly) break;

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

			if (webdav_unlink_dir(srv, con, NULL, multi_status_resp)) {
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
