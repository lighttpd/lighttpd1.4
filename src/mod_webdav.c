#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

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
	unsigned short *enabled;
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
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		
		cv[0].destination = &(s->enabled);
		
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
		response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("PROPFIND"));
		break;
	default:
		break;
	}
	
	/* not found */
	return HANDLER_GO_ON;
}

static int get_response_entry(server *srv, connection *con, plugin_data *p, buffer *b, const char *filename) {
	struct stat st;

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

URIHANDLER_FUNC(mod_webdav_subrequest_handler) {
	plugin_data *p = p_d;
	buffer *b;
	DIR *dir;
	data_string *ds;
	int depth = -1;
	
	UNUSED(srv);

	if (!p->conf.enabled) return HANDLER_GO_ON;
	/* physical path is setup */
	if (con->physical.path->used == 0) return HANDLER_GO_ON;
	
	switch (con->request.http_method) {
	case HTTP_METHOD_PROPFIND:
		/* they want to know the properties of the directory */
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Depth"))) {
			depth = strtol(ds->value->ptr, NULL, 10);
		}
		
		con->http_status = 207;

		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/xml; charset=\"utf-8\""));

		b = chunkqueue_get_append_buffer(con->write_queue);
				
		buffer_copy_string(b, 
				   "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

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
						/* ignore the currrent dir */
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
