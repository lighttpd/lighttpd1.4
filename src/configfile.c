#include "first.h"

#include "base.h"
#include "burl.h"
#include "fdevent.h"
#include "keyvalue.h"
#include "log.h"
#include "stream.h"

#include "configparser.h"
#include "configfile.h"
#include "stat_cache.h"
#include "sys-crypto.h"

#include <sys/stat.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <glob.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(HAVE_MYSQL) || (defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER))
static void config_warn_authn_module (server *srv, const char *module, size_t len) {
	for (size_t i = 0; i < srv->config_context->used; ++i) {
		const data_config *config = (data_config const*)srv->config_context->data[i];
		const data_unset *du = array_get_element(config->value, "auth.backend");
		if (NULL != du && du->type == TYPE_STRING) {
			data_string *ds = (data_string *)du;
			if (buffer_is_equal_string(ds->value, module, len)) {
				buffer_copy_string_len(srv->tmp_buf, CONST_STR_LEN("mod_authn_"));
				buffer_append_string_len(srv->tmp_buf, module, len);
				array_insert_value(srv->srvconf.modules, CONST_BUF_LEN(srv->tmp_buf));
				log_error_write(srv, __FILE__, __LINE__, "SSSsSSS", "Warning: please add \"mod_authn_", module, "\" to server.modules list in lighttpd.conf.  A future release of lighttpd 1.4.x will not automatically load mod_authn_", module, "and lighttpd will fail to start up since your lighttpd.conf uses auth.backend = \"", module, "\".");
				return;
			}
		}
	}
}
#endif

#ifdef USE_OPENSSL_CRYPTO
static void config_warn_openssl_module (server *srv) {
	for (size_t i = 0; i < srv->config_context->used; ++i) {
		const data_config *config = (data_config const*)srv->config_context->data[i];
		for (size_t j = 0; j < config->value->used; ++j) {
			data_unset *du = config->value->data[j];
			if (0 == strncmp(du->key->ptr, "ssl.", sizeof("ssl.")-1)) {
				/* mod_openssl should be loaded after mod_extforward */
				array_insert_value(srv->srvconf.modules, CONST_STR_LEN("mod_openssl"));
				log_error_write(srv, __FILE__, __LINE__, "S", "Warning: please add \"mod_openssl\" to server.modules list in lighttpd.conf.  A future release of lighttpd 1.4.x *will not* automatically load mod_openssl and lighttpd *will not* use SSL/TLS where your lighttpd.conf contains ssl.* directives");
				return;
			}
		}
	}
}
#endif

static int config_http_parseopts (server *srv, array *a) {
    unsigned short int opts = srv->srvconf.http_url_normalize;
    unsigned short int decode_2f = 1;
    int rc = 1;
    if (!array_is_kvstring(a)) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        "unexpected value for server.http-parseopts; "
                        "expected list of \"key\" => \"[enable|disable]\"");
        return 0;
    }
    for (size_t i = 0; i < a->used; ++i) {
        const data_string * const ds = (data_string *)a->data[i];
        unsigned short int opt;
        int val = 0;
        if (buffer_is_equal_string(ds->value, CONST_STR_LEN("enable")))
            val = 1;
        else if (buffer_is_equal_string(ds->value, CONST_STR_LEN("disable")))
            val = 0;
        else {
            log_error_write(srv, __FILE__, __LINE__, "sbsbs",
                            "unrecognized value for server.http-parseopts:",
                            ds->key, "=>", ds->value,
                            "(expect \"[enable|disable]\")");
            rc = 0;
        }
        if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-normalize")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-normalize-unreserved")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-normalize-required")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-ctrls-reject")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-path-backslash-trans")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_BACKSLASH_TRANS;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-path-2f-decode")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-path-2f-reject")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-path-dotseg-remove")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-path-dotseg-reject")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("url-query-20-plus")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS;
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("header-strict"))) {
            srv->srvconf.http_header_strict = val;
            continue;
        }
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("host-strict"))) {
            srv->srvconf.http_host_strict = val;
            continue;
        }
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("host-normalize"))) {
            srv->srvconf.http_host_normalize = val;
            continue;
        }
        else if (buffer_is_equal_string(ds->key, CONST_STR_LEN("method-get-body"))) {
            srv->srvconf.http_method_get_body = val;
            continue;
        }
        else {
            log_error_write(srv, __FILE__, __LINE__, "sb",
                            "unrecognized key for server.http-parseopts:",
                            ds->key);
            rc = 0;
            continue;
        }
        if (val)
            opts |= opt;
        else {
            opts &= ~opt;
            if (opt == HTTP_PARSEOPT_URL_NORMALIZE) {
                opts = 0;
                break;
            }
            if (opt == HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE) {
                decode_2f = 0;
            }
        }
    }
    if (opts != 0) {
        opts |= HTTP_PARSEOPT_URL_NORMALIZE;
        if ((opts & (HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE
                    |HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT))
                 == (HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE
                    |HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT)) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "conflicting options in server.http-parseopts:"
                            "url-path-2f-decode, url-path-2f-reject");
            rc = 0;
        }
        if ((opts & (HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE
                    |HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT))
                 == (HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE
                    |HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT)) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "conflicting options in server.http-parseopts:"
                            "url-path-dotseg-remove, url-path-dotseg-reject");
            rc = 0;
        }
        if (!(opts & (HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED
                     |HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED))) {
            opts |= HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED;
            if (decode_2f
                && !(opts & HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT))
                opts |= HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE;
        }
    }
    srv->srvconf.http_url_normalize = opts;
    return rc;
}

static int config_insert(server *srv) {
	size_t i;
	int ret = 0;
	buffer *stat_cache_string;
	array *http_parseopts;
	unsigned int chunk_sz = 0;

	config_values_t cv[] = {
		{ "server.bind",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 0 */
		{ "server.errorlog",                   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 1 */
		{ "server.errorfile-prefix",           NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 2 */
		{ "server.chroot",                     NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 3 */
		{ "server.username",                   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 4 */
		{ "server.groupname",                  NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 5 */
		{ "server.port",                       NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_SERVER     }, /* 6 */
		{ "server.tag",                        NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 7 */
		{ "server.use-ipv6",                   NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 8 */
		{ "server.modules",                    NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_SERVER     }, /* 9 */

		{ "server.event-handler",              NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 10 */
		{ "server.pid-file",                   NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 11 */
		{ "server.max-request-size",           NULL, T_CONFIG_INT,     T_CONFIG_SCOPE_CONNECTION }, /* 12 */
		{ "server.max-worker",                 NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_SERVER     }, /* 13 */
		{ "server.document-root",              NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 14 */
		{ "server.force-lowercase-filenames",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 15 */
		{ "debug.log-condition-handling",      NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 16 */
		{ "server.max-keep-alive-requests",    NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 17 */
		{ "server.name",                       NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 18 */
		{ "server.max-keep-alive-idle",        NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 19 */

		{ "server.max-read-idle",              NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 20 */
		{ "server.max-write-idle",             NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 21 */
		{ "server.error-handler",              NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 22 */
		{ "server.max-fds",                    NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_SERVER     }, /* 23 */
#ifdef HAVE_LSTAT
		{ "server.follow-symlink",             NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 24 */
#else
		{ "server.follow-symlink",
			"Your system lacks lstat(). We can not differ symlinks from files."
			"Please remove server.follow-symlinks from your config.",
			T_CONFIG_UNSUPPORTED, T_CONFIG_SCOPE_UNSET },
#endif
		{ "server.kbytes-per-second",          NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 25 */
		{ "connection.kbytes-per-second",      NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 26 */
		{ "mimetype.use-xattr",                NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 27 */
		{ "mimetype.assign",                   NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_CONNECTION }, /* 28 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 29 */

		{ "ssl.engine",                        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 30 */
		{ "debug.log-file-not-found",          NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 31 */
		{ "debug.log-request-handling",        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 32 */
		{ "debug.log-response-header",         NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 33 */
		{ "debug.log-request-header",          NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 34 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 35 */
		{ "server.protocol-http11",            NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 36 */
		{ "debug.log-request-header-on-error", NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 37 */
		{ "debug.log-state-handling",          NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 38 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 39 */

		{ "server.errorlog-use-syslog",        NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 40 */
		{ "server.range-requests",             NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 41 */
		{ "server.stat-cache-engine",          NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 42 */
		{ "server.max-connections",            NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_SERVER     }, /* 43 */
		{ "server.network-backend",            NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 44 */
		{ "server.upload-dirs",                NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_SERVER     }, /* 45 */
		{ "server.core-files",                 NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 46 */
		{ "server.compat-module-load",         NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 47 */
		{ "server.chunkqueue-chunk-sz",        NULL, T_CONFIG_INT,     T_CONFIG_SCOPE_SERVER     }, /* 48 */
		{ "etag.use-inode",                    NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 49 */

		{ "etag.use-mtime",                    NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 50 */
		{ "etag.use-size",                     NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 51 */
		{ "server.reject-expect-100-with-417", NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 52 */
		{ "debug.log-timeouts",                NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 53 */
		{ "server.defer-accept",               NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 54 */
		{ "server.breakagelog",                NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 55 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 56 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 57 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 58 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 59 */

		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 60 */
		{ "server.set-v6only",                 NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 61 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 62 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 63 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 64 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 65 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 66 */
		{ "unused-slot-moved-to-mod-openssl",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 67 */
		{ "server.upload-temp-file-size",      NULL, T_CONFIG_INT,     T_CONFIG_SCOPE_SERVER     }, /* 68 */
		{ "mimetype.xattr-name",               NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 69 */
		{ "server.listen-backlog",             NULL, T_CONFIG_INT,     T_CONFIG_SCOPE_CONNECTION }, /* 70 */
		{ "server.error-handler-404",          NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 71 */
		{ "server.http-parseopt-header-strict",NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 72 */
		{ "server.http-parseopt-host-strict",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 73 */
		{ "server.http-parseopt-host-normalize",NULL,T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 74 */
		{ "server.bsd-accept-filter",          NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 75 */
		{ "server.stream-request-body",        NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 76 */
		{ "server.stream-response-body",       NULL, T_CONFIG_SHORT,   T_CONFIG_SCOPE_CONNECTION }, /* 77 */
		{ "server.max-request-field-size",     NULL, T_CONFIG_INT,     T_CONFIG_SCOPE_SERVER     }, /* 78 */
		{ "server.error-intercept",            NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 79 */
		{ "server.syslog-facility",            NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_SERVER     }, /* 80 */
		{ "server.socket-perms",               NULL, T_CONFIG_STRING,  T_CONFIG_SCOPE_CONNECTION }, /* 81 */
		{ "server.http-parseopts",             NULL, T_CONFIG_ARRAY,   T_CONFIG_SCOPE_SERVER     }, /* 82 */
		{ "server.systemd-socket-activation",  NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_SERVER     }, /* 83 */

		{ NULL,                                NULL, T_CONFIG_UNSET,   T_CONFIG_SCOPE_UNSET      }
	};

	/* all T_CONFIG_SCOPE_SERVER options */
	cv[0].destination = srv->srvconf.bindhost;
	cv[1].destination = srv->srvconf.errorlog_file;
	cv[3].destination = srv->srvconf.changeroot;
	cv[4].destination = srv->srvconf.username;
	cv[5].destination = srv->srvconf.groupname;
	cv[6].destination = &(srv->srvconf.port);
	cv[9].destination = srv->srvconf.modules;

	cv[10].destination = srv->srvconf.event_handler;
	cv[11].destination = srv->srvconf.pid_file;
	cv[13].destination = &(srv->srvconf.max_worker);

	cv[23].destination = &(srv->srvconf.max_fds);

	cv[37].destination = &(srv->srvconf.log_request_header_on_error);
	cv[38].destination = &(srv->srvconf.log_state_handling);

	cv[40].destination = &(srv->srvconf.errorlog_use_syslog);
	stat_cache_string = buffer_init();
	cv[42].destination = stat_cache_string;
	cv[43].destination = &(srv->srvconf.max_conns);
	cv[44].destination = srv->srvconf.network_backend;
	cv[45].destination = srv->srvconf.upload_tempdirs;
	cv[46].destination = &(srv->srvconf.enable_cores);
	cv[47].destination = &(srv->srvconf.compat_module_load);
	cv[48].destination = &chunk_sz;

	cv[52].destination = &(srv->srvconf.reject_expect_100_with_417);
	cv[55].destination = srv->srvconf.breakagelog_file;

	cv[68].destination = &(srv->srvconf.upload_temp_file_size);
	cv[69].destination = srv->srvconf.xattr_name;
	cv[72].destination = &(srv->srvconf.http_header_strict);
	cv[73].destination = &(srv->srvconf.http_host_strict);
	cv[74].destination = &(srv->srvconf.http_host_normalize);
	cv[78].destination = &(srv->srvconf.max_request_field_size);
	cv[80].destination = srv->srvconf.syslog_facility;
	http_parseopts = array_init();
	cv[82].destination = http_parseopts;
	cv[83].destination = &(srv->srvconf.systemd_socket_activation);

	srv->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

	force_assert(srv->config_storage);
	force_assert(srv->config_context->used); /* static analysis hint for ccc
-analyzer */

	for (i = 0; i < srv->config_context->used; i++) {
		data_config * const config = (data_config *)srv->config_context->data[i];
		specific_config *s;

		s = calloc(1, sizeof(specific_config));
		force_assert(s);
		s->document_root = buffer_init();
		s->mimetypes     = array_init();
		s->server_name   = buffer_init();
		s->error_handler = buffer_init();
		s->error_handler_404 = buffer_init();
		s->server_tag    = buffer_init();
		s->errorfile_prefix = buffer_init();
	      #if defined(__FreeBSD__) || defined(__NetBSD__) \
	       || defined(__OpenBSD__) || defined(__DragonFly__)
		s->bsd_accept_filter = (i == 0)
		  ? buffer_init()
		  : buffer_init_buffer(srv->config_storage[0]->bsd_accept_filter);
	      #endif
		s->socket_perms = (i == 0 || buffer_string_is_empty(srv->config_storage[0]->socket_perms))
		  ? buffer_init()
		  : buffer_init_buffer(srv->config_storage[0]->socket_perms);
		s->max_keep_alive_requests = 100;
		s->max_keep_alive_idle = 5;
		s->max_read_idle = 60;
		s->max_write_idle = 360;
		s->max_request_size = 0;
		s->use_xattr     = 0;
		s->ssl_enabled   = 0;
		s->use_ipv6      = (i == 0) ? 0 : srv->config_storage[0]->use_ipv6;
		s->set_v6only    = (i == 0) ? 1 : srv->config_storage[0]->set_v6only;
		s->defer_accept  = (i == 0) ? 0 : srv->config_storage[0]->defer_accept;
		s->follow_symlink = 1;
		s->kbytes_per_second = 0;
		s->allow_http11  = 1;
		s->etag_use_inode = 1;
		s->etag_use_mtime = 1;
		s->etag_use_size  = 1;
		s->range_requests = 1;
		s->force_lowercase_filenames = (i == 0) ? 2 : 0; /* we wan't to detect later if user changed this for global section */
		s->global_kbytes_per_second = 0;
		s->global_bytes_per_second_cnt = 0;
		s->global_bytes_per_second_cnt_ptr = &s->global_bytes_per_second_cnt;
		s->listen_backlog = (0 == i ? 1024 : srv->config_storage[0]->listen_backlog);
		s->stream_request_body = 0;
		s->stream_response_body = 0;
		s->error_intercept = 0;

		/* all T_CONFIG_SCOPE_CONNECTION options */
		cv[2].destination = s->errorfile_prefix;
		cv[7].destination = s->server_tag;
		cv[8].destination = &(s->use_ipv6);

		cv[12].destination = &(s->max_request_size);
		cv[14].destination = s->document_root;
		cv[15].destination = &(s->force_lowercase_filenames);
		cv[16].destination = &(s->log_condition_handling);
		cv[17].destination = &(s->max_keep_alive_requests);
		cv[18].destination = s->server_name;
		cv[19].destination = &(s->max_keep_alive_idle);

		cv[20].destination = &(s->max_read_idle);
		cv[21].destination = &(s->max_write_idle);
		cv[22].destination = s->error_handler;
		cv[24].destination = &(s->follow_symlink);
		cv[25].destination = &(s->global_kbytes_per_second);
		cv[26].destination = &(s->kbytes_per_second);
		cv[27].destination = &(s->use_xattr);
		cv[28].destination = s->mimetypes;
		/*cv[29].destination = s->unused;*/

		cv[30].destination = &(s->ssl_enabled);
		cv[31].destination = &(s->log_file_not_found);
		cv[32].destination = &(s->log_request_handling);
		cv[33].destination = &(s->log_response_header);
		cv[34].destination = &(s->log_request_header);
		/*cv[35].destination = &(s->unused);*/
		cv[36].destination = &(s->allow_http11);
		/*cv[39].destination = s->unused;*/

		cv[41].destination = &(s->range_requests);
		/*cv[47].destination = s->unused;*/
		/*cv[48].destination = &(s->unused);*/
		cv[49].destination = &(s->etag_use_inode);

		cv[50].destination = &(s->etag_use_mtime);
		cv[51].destination = &(s->etag_use_size);
		cv[53].destination = &(s->log_timeouts);
		cv[54].destination = &(s->defer_accept);
		/*cv[56].destination = &(s->unused);*/
		/*cv[57].destination = &(s->unused);*/
		/*cv[58].destination = &(s->unused);*/
		/*cv[59].destination = s->unused;*/

		/*cv[60].destination = &(s->unused);*/
		cv[61].destination = &(s->set_v6only);
		/*cv[62].destination = &(s->unused);*/
		/*cv[63].destination = s->unused;*/
		/*cv[64].destination = s->unused;*/
		/*cv[65].destination = &(s->unused);*/
		/*cv[66].destination = &(s->unused);*/
		/*cv[67].destination = &(s->unused);*/
		cv[70].destination = &(s->listen_backlog);
		cv[71].destination = s->error_handler_404;
	      #if defined(__FreeBSD__) || defined(__NetBSD__) \
	       || defined(__OpenBSD__) || defined(__DragonFly__)
		cv[75].destination = s->bsd_accept_filter;
	      #endif
		cv[76].destination = &(s->stream_request_body);
		cv[77].destination = &(s->stream_response_body);
		cv[79].destination = &(s->error_intercept);
		cv[81].destination = s->socket_perms;

		srv->config_storage[i] = s;

		if (0 != (ret = config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION))) {
			break;
		}

		if (s->stream_request_body & FDEVENT_STREAM_REQUEST_BUFMIN) {
			s->stream_request_body |= FDEVENT_STREAM_REQUEST;
		}
		if (s->stream_response_body & FDEVENT_STREAM_RESPONSE_BUFMIN) {
			s->stream_response_body |= FDEVENT_STREAM_RESPONSE;
		}

		if (!array_is_kvstring(s->mimetypes)) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"unexpected value for mimetype.assign; expected list of \"ext\" => \"mimetype\"");
		}

		if (!buffer_string_is_empty(s->server_tag)) {
			for (char *t = strchr(s->server_tag->ptr,'\n'); NULL != t; t = strchr(t+2,'\n')) {
				/* not expecting admin to define multi-line server.tag,
				 * but ensure server_tag has proper header continuation,
				 * if needed */
				off_t off = t - s->server_tag->ptr;
				size_t len;
				if (t[1] == ' ' || t[1] == '\t') continue;
				len = buffer_string_length(s->server_tag);
				buffer_string_prepare_append(s->server_tag, 1);
				t = s->server_tag->ptr+off;
				memmove(t+2, t+1, len - off - 1);
				t[1] = ' ';
				buffer_commit(s->server_tag, 1);
			}
		}

		if (0 == i) {
                    if (!config_http_parseopts(srv, http_parseopts)) {
			ret = HANDLER_ERROR;
			break;
                    }
                }

		if (srv->srvconf.http_url_normalize
		    && COMP_HTTP_QUERY_STRING == config->comp) {
			switch(config->cond) {
			case CONFIG_COND_NE:
			case CONFIG_COND_EQ:
				/* (can use this routine as long as it does not perform
				 *  any regex-specific normalization of first arg) */
				pcre_keyvalue_burl_normalize_key(config->string, srv->tmp_buf);
				break;
			case CONFIG_COND_NOMATCH:
			case CONFIG_COND_MATCH:
				pcre_keyvalue_burl_normalize_key(config->string, srv->tmp_buf);
				if (!data_config_pcre_compile(config)) {
					ret = HANDLER_ERROR;
				}
				break;
			default:
				break;
			}
			if (HANDLER_ERROR == ret) break;
		}

	      #ifndef USE_OPENSSL_CRYPTO
		if (s->ssl_enabled) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"ssl support is missing, recompile with e.g. --with-openssl");
			ret = HANDLER_ERROR;
			break;
		}
	      #endif
	}
	array_free(http_parseopts);

	{
		specific_config *s = srv->config_storage[0];
		s->http_parseopts= /*(global, but stored in con->conf.http_parseopts)*/
		   (srv->srvconf.http_header_strict  ?(HTTP_PARSEOPT_HEADER_STRICT) :0)
		  |(srv->srvconf.http_host_strict    ?(HTTP_PARSEOPT_HOST_STRICT
		                                      |HTTP_PARSEOPT_HOST_NORMALIZE):0)
		  |(srv->srvconf.http_host_normalize ?(HTTP_PARSEOPT_HOST_NORMALIZE):0)
		  |(srv->srvconf.http_method_get_body?(HTTP_PARSEOPT_METHOD_GET_BODY):0);
		s->http_parseopts |= srv->srvconf.http_url_normalize;

		if (s->log_request_handling || s->log_request_header)
			srv->srvconf.log_request_header_on_error = 1;
	}

	if (0 != chunk_sz) {
		chunkqueue_set_chunk_size(chunk_sz);
	}

	if (0 != stat_cache_choose_engine(srv, stat_cache_string)) {
		ret = HANDLER_ERROR;
	}
	buffer_free(stat_cache_string);

	if (!array_is_vlist(srv->srvconf.upload_tempdirs)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"unexpected value for server.upload-dirs; expected list of \"path\" strings");
		ret = HANDLER_ERROR;
	}

	if (!array_is_vlist(srv->srvconf.modules)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"unexpected value for server.modules; expected list of \"mod_xxxxxx\" strings");
		ret = HANDLER_ERROR;
	} else if (srv->srvconf.compat_module_load) {
		data_string *ds;
		int prepend_mod_indexfile = 1;
		int append_mod_dirlisting = 1;
		int append_mod_staticfile = 1;
		int append_mod_authn_file = 1;
		int append_mod_authn_ldap = 1;
		int append_mod_authn_mysql = 1;
		int append_mod_openssl = 1;
		int contains_mod_auth = 0;

		/* prepend default modules */
		for (i = 0; i < srv->srvconf.modules->used; i++) {
			ds = (data_string *)srv->srvconf.modules->data[i];

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_indexfile"))) {
				prepend_mod_indexfile = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_staticfile"))) {
				append_mod_staticfile = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_dirlisting"))) {
				append_mod_dirlisting = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_openssl"))) {
				append_mod_openssl = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_authn_file"))) {
				append_mod_authn_file = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_authn_ldap"))) {
				append_mod_authn_ldap = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_authn_mysql"))) {
				append_mod_authn_mysql = 0;
			}

			if (buffer_is_equal_string(ds->value, CONST_STR_LEN("mod_auth"))) {
				contains_mod_auth = 1;
			}

			if (0 == prepend_mod_indexfile &&
			    0 == append_mod_dirlisting &&
			    0 == append_mod_staticfile &&
			    0 == append_mod_openssl &&
			    0 == append_mod_authn_file &&
			    0 == append_mod_authn_ldap &&
			    0 == append_mod_authn_mysql &&
			    1 == contains_mod_auth) {
				break;
			}
		}

		if (prepend_mod_indexfile) {
			/* mod_indexfile has to be loaded before mod_fastcgi and friends */
			array *modules = array_init();
			array_insert_value(modules, CONST_STR_LEN("mod_indexfile"));

			for (i = 0; i < srv->srvconf.modules->used; i++) {
				ds = (data_string *)srv->srvconf.modules->data[i];
				array_insert_value(modules, CONST_BUF_LEN(ds->value));
			}

			array_free(srv->srvconf.modules);
			srv->srvconf.modules = modules;
		}

		/* append default modules */
		if (append_mod_dirlisting) {
			array_insert_value(srv->srvconf.modules, CONST_STR_LEN("mod_dirlisting"));
		}

		if (append_mod_staticfile) {
			array_insert_value(srv->srvconf.modules, CONST_STR_LEN("mod_staticfile"));
		}

		if (append_mod_openssl) {
		      #ifdef USE_OPENSSL_CRYPTO
			config_warn_openssl_module(srv);
		      #endif
		}

		/* mod_auth.c,http_auth.c auth backends were split into separate modules
		 * Automatically load auth backend modules for compatibility with
		 * existing lighttpd 1.4.x configs */
		if (contains_mod_auth) {
			if (append_mod_authn_file) {
				array_insert_value(srv->srvconf.modules, CONST_STR_LEN("mod_authn_file"));
			}
			if (append_mod_authn_ldap) {
			      #if defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER)
				config_warn_authn_module(srv, CONST_STR_LEN("ldap"));
			      #endif
			}
			if (append_mod_authn_mysql) {
			      #if defined(HAVE_MYSQL)
				config_warn_authn_module(srv, CONST_STR_LEN("mysql"));
			      #endif
			}
		}
	}

	return ret;

}


#define PATCH(x) con->conf.x = s->x
int config_setup_connection(server *srv, connection *con) {
	specific_config *s = srv->config_storage[0];

	PATCH(http_parseopts);

	PATCH(allow_http11);
	PATCH(mimetypes);
	PATCH(document_root);
	PATCH(high_precision_timestamps);
	PATCH(max_keep_alive_requests);
	PATCH(max_keep_alive_idle);
	PATCH(max_read_idle);
	PATCH(max_write_idle);
	PATCH(max_request_size);
	PATCH(use_xattr);
	PATCH(error_handler);
	PATCH(error_handler_404);
	PATCH(error_intercept);
	PATCH(errorfile_prefix);
	PATCH(follow_symlink);
	PATCH(server_tag);
	PATCH(kbytes_per_second);
	PATCH(global_kbytes_per_second);
	PATCH(global_bytes_per_second_cnt);

	con->conf.global_bytes_per_second_cnt_ptr = &s->global_bytes_per_second_cnt;
	buffer_copy_buffer(con->server_name, s->server_name);

	PATCH(log_request_header);
	PATCH(log_response_header);
	PATCH(log_request_handling);
	PATCH(log_condition_handling);
	PATCH(log_file_not_found);
	PATCH(log_timeouts);

	PATCH(range_requests);
	PATCH(force_lowercase_filenames);
	/*PATCH(listen_backlog);*//*(not necessary; used only at startup)*/
	PATCH(stream_request_body);
	PATCH(stream_response_body);
	PATCH(socket_perms);

	PATCH(etag_use_inode);
	PATCH(etag_use_mtime);
	PATCH(etag_use_size);

	return 0;
}

int config_patch_connection(server *srv, connection *con) {
	size_t i, j;

	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		specific_config *s = srv->config_storage[i];

		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;

		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];

			if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.document-root"))) {
				PATCH(document_root);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.range-requests"))) {
				PATCH(range_requests);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.error-handler"))) {
				PATCH(error_handler);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.error-handler-404"))) {
				PATCH(error_handler_404);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.error-intercept"))) {
				PATCH(error_intercept);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.errorfile-prefix"))) {
				PATCH(errorfile_prefix);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("mimetype.assign"))) {
				PATCH(mimetypes);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.max-keep-alive-requests"))) {
				PATCH(max_keep_alive_requests);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.max-keep-alive-idle"))) {
				PATCH(max_keep_alive_idle);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.max-write-idle"))) {
				PATCH(max_write_idle);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.max-read-idle"))) {
				PATCH(max_read_idle);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.max-request-size"))) {
				PATCH(max_request_size);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("mimetype.use-xattr"))) {
				PATCH(use_xattr);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("etag.use-inode"))) {
				PATCH(etag_use_inode);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("etag.use-mtime"))) {
				PATCH(etag_use_mtime);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("etag.use-size"))) {
				PATCH(etag_use_size);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.follow-symlink"))) {
				PATCH(follow_symlink);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.name"))) {
				buffer_copy_buffer(con->server_name, s->server_name);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.tag"))) {
				PATCH(server_tag);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.stream-request-body"))) {
				PATCH(stream_request_body);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.stream-response-body"))) {
				PATCH(stream_response_body);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("connection.kbytes-per-second"))) {
				PATCH(kbytes_per_second);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-request-handling"))) {
				PATCH(log_request_handling);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-request-header"))) {
				PATCH(log_request_header);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-response-header"))) {
				PATCH(log_response_header);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-condition-handling"))) {
				PATCH(log_condition_handling);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-file-not-found"))) {
				PATCH(log_file_not_found);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("debug.log-timeouts"))) {
				PATCH(log_timeouts);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.protocol-http11"))) {
				PATCH(allow_http11);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.force-lowercase-filenames"))) {
				PATCH(force_lowercase_filenames);
		      #if 0 /*(not necessary; used only at startup)*/
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.listen-backlog"))) {
				PATCH(listen_backlog);
		      #endif
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.kbytes-per-second"))) {
				PATCH(global_kbytes_per_second);
				PATCH(global_bytes_per_second_cnt);
				con->conf.global_bytes_per_second_cnt_ptr = &s->global_bytes_per_second_cnt;
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("server.socket-perms"))) {
				PATCH(socket_perms);
			}
		}
	}

		con->etag_flags = (con->conf.etag_use_mtime ? ETAG_USE_MTIME : 0) |
				  (con->conf.etag_use_inode ? ETAG_USE_INODE : 0) |
				  (con->conf.etag_use_size  ? ETAG_USE_SIZE  : 0);

	return 0;
}
#undef PATCH

typedef struct {
	int foo;
	int bar;

	const buffer *source;
	const char *input;
	size_t offset;
	size_t size;

	int line_pos;
	int line;

	int in_key;
	int in_brace;
	int in_cond;
	int simulate_eol;
} tokenizer_t;

#if 0
static int tokenizer_open(server *srv, tokenizer_t *t, buffer *basedir, const char *fn) {
	if (buffer_string_is_empty(basedir) ||
			(fn[0] == '/' || fn[0] == '\\') ||
			(fn[0] == '.' && (fn[1] == '/' || fn[1] == '\\'))) {
		t->file = buffer_init_string(fn);
	} else {
		t->file = buffer_init_buffer(basedir);
		buffer_append_string(t->file, fn);
	}

	if (0 != stream_open(&(t->s), t->file)) {
		log_error_write(srv, __FILE__, __LINE__, "sbss",
				"opening configfile ", t->file, "failed:", strerror(errno));
		buffer_free(t->file);
		return -1;
	}

	t->input = t->s.start;
	t->offset = 0;
	t->size = t->s.size;
	t->line = 1;
	t->line_pos = 1;

	t->in_key = 1;
	t->in_brace = 0;
	t->in_cond = 0;
	return 0;
}

static int tokenizer_close(server *srv, tokenizer_t *t) {
	UNUSED(srv);

	buffer_free(t->file);
	return stream_close(&(t->s));
}
#endif
static int config_skip_newline(tokenizer_t *t) {
	int skipped = 1;
	force_assert(t->input[t->offset] == '\r' || t->input[t->offset] == '\n');
	if (t->input[t->offset] == '\r' && t->input[t->offset + 1] == '\n') {
		skipped ++;
		t->offset ++;
	}
	t->offset ++;
	return skipped;
}

static int config_skip_comment(tokenizer_t *t) {
	int i;
	force_assert(t->input[t->offset] == '#');
	for (i = 1; t->input[t->offset + i] &&
	     (t->input[t->offset + i] != '\n' && t->input[t->offset + i] != '\r');
	     i++);
	t->offset += i;
	return i;
}

static int config_tokenizer(server *srv, tokenizer_t *t, int *token_id, buffer *token) {
	int tid = 0;
	size_t i;

	if (t->simulate_eol) {
		t->simulate_eol = 0;
		t->in_key = 1;
		tid = TK_EOL;
		buffer_copy_string_len(token, CONST_STR_LEN("(EOL)"));
	}

	while (tid == 0 && t->offset < t->size && t->input[t->offset]) {
		char c = t->input[t->offset];
		const char *start = NULL;

		switch (c) {
		case '=':
			if (t->in_brace) {
				if (t->input[t->offset + 1] == '>') {
					t->offset += 2;

					buffer_copy_string_len(token, CONST_STR_LEN("=>"));

					tid = TK_ARRAY_ASSIGN;
				} else {
					log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
							"source:", t->source,
							"line:", t->line, "pos:", t->line_pos,
							"use => for assignments in arrays");
					return -1;
				}
			} else if (t->in_cond) {
				if (t->input[t->offset + 1] == '=') {
					t->offset += 2;

					buffer_copy_string_len(token, CONST_STR_LEN("=="));

					tid = TK_EQ;
				} else if (t->input[t->offset + 1] == '~') {
					t->offset += 2;

					buffer_copy_string_len(token, CONST_STR_LEN("=~"));

					tid = TK_MATCH;
				} else {
					log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
							"source:", t->source,
							"line:", t->line, "pos:", t->line_pos,
							"only =~ and == are allowed in the condition");
					return -1;
				}
				t->in_key = 1;
				t->in_cond = 0;
			} else if (t->in_key) {
				tid = TK_ASSIGN;

				buffer_copy_string_len(token, t->input + t->offset, 1);

				t->offset++;
				t->line_pos++;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
						"source:", t->source,
						"line:", t->line, "pos:", t->line_pos,
						"unexpected equal-sign: =");
				return -1;
			}

			break;
		case '!':
			if (t->in_cond) {
				if (t->input[t->offset + 1] == '=') {
					t->offset += 2;

					buffer_copy_string_len(token, CONST_STR_LEN("!="));

					tid = TK_NE;
				} else if (t->input[t->offset + 1] == '~') {
					t->offset += 2;

					buffer_copy_string_len(token, CONST_STR_LEN("!~"));

					tid = TK_NOMATCH;
				} else {
					log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
							"source:", t->source,
							"line:", t->line, "pos:", t->line_pos,
							"only !~ and != are allowed in the condition");
					return -1;
				}
				t->in_key = 1;
				t->in_cond = 0;
			} else {
				log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
						"source:", t->source,
						"line:", t->line, "pos:", t->line_pos,
						"unexpected exclamation-marks: !");
				return -1;
			}

			break;
		case '\t':
		case ' ':
			t->offset++;
			t->line_pos++;
			break;
		case '\n':
		case '\r':
			if (t->in_brace == 0) {
				int done = 0;
				while (!done && t->offset < t->size) {
					switch (t->input[t->offset]) {
					case '\r':
					case '\n':
						config_skip_newline(t);
						t->line_pos = 1;
						t->line++;
						break;

					case '#':
						t->line_pos += config_skip_comment(t);
						break;

					case '\t':
					case ' ':
						t->offset++;
						t->line_pos++;
						break;

					default:
						done = 1;
					}
				}
				t->in_key = 1;
				tid = TK_EOL;
				buffer_copy_string_len(token, CONST_STR_LEN("(EOL)"));
			} else {
				config_skip_newline(t);
				t->line_pos = 1;
				t->line++;
			}
			break;
		case ',':
			if (t->in_brace > 0) {
				tid = TK_COMMA;

				buffer_copy_string_len(token, CONST_STR_LEN("(COMMA)"));
			}

			t->offset++;
			t->line_pos++;
			break;
		case '"':
			/* search for the terminating " */
			start = t->input + t->offset + 1;
			buffer_copy_string_len(token, CONST_STR_LEN(""));

			for (i = 1; t->input[t->offset + i]; i++) {
				if (t->input[t->offset + i] == '\\' &&
				    t->input[t->offset + i + 1] == '"') {

					buffer_append_string_len(token, start, t->input + t->offset + i - start);

					start = t->input + t->offset + i + 1;

					/* skip the " */
					i++;
					continue;
				}


				if (t->input[t->offset + i] == '"') {
					tid = TK_STRING;

					buffer_append_string_len(token, start, t->input + t->offset + i - start);

					break;
				}
			}

			if (t->input[t->offset + i] == '\0') {
				/* ERROR */

				log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
						"source:", t->source,
						"line:", t->line, "pos:", t->line_pos,
						"missing closing quote");

				return -1;
			}

			t->offset += i + 1;
			t->line_pos += i + 1;

			break;
		case '(':
			t->offset++;
			t->in_brace++;

			tid = TK_LPARAN;

			buffer_copy_string_len(token, CONST_STR_LEN("("));
			break;
		case ')':
			t->offset++;
			t->in_brace--;

			tid = TK_RPARAN;

			buffer_copy_string_len(token, CONST_STR_LEN(")"));
			break;
		case '$':
			t->offset++;

			tid = TK_DOLLAR;
			t->in_cond = 1;
			t->in_key = 0;

			buffer_copy_string_len(token, CONST_STR_LEN("$"));

			break;

		case '+':
			if (t->input[t->offset + 1] == '=') {
				t->offset += 2;
				buffer_copy_string_len(token, CONST_STR_LEN("+="));
				tid = TK_APPEND;
			} else {
				t->offset++;
				tid = TK_PLUS;
				buffer_copy_string_len(token, CONST_STR_LEN("+"));
			}
			break;

		case ':':
			if (t->input[t->offset+1] == '=') {
				t->offset += 2;
				tid = TK_FORCE_ASSIGN;
				buffer_copy_string_len(token, CONST_STR_LEN(":="));
			}
			break;

		case '{':
			t->offset++;

			tid = TK_LCURLY;

			buffer_copy_string_len(token, CONST_STR_LEN("{"));

			break;

		case '}':
			t->offset++;

			tid = TK_RCURLY;

			buffer_copy_string_len(token, CONST_STR_LEN("}"));

			for (; t->offset < t->size; ++t->offset,++t->line_pos) {
				c = t->input[t->offset];
				if (c == '\r' || c == '\n') {
					break;
				}
				else if (c == '#') {
					t->line_pos += config_skip_comment(t);
					break;
				}
				else if (c != ' ' && c != '\t') {
					t->simulate_eol = 1;
					break;
				} /* else (c == ' ' || c == '\t') */
			}

			break;

		case '[':
			t->offset++;

			tid = TK_LBRACKET;

			buffer_copy_string_len(token, CONST_STR_LEN("["));

			break;

		case ']':
			t->offset++;

			tid = TK_RBRACKET;

			buffer_copy_string_len(token, CONST_STR_LEN("]"));

			break;
		case '#':
			t->line_pos += config_skip_comment(t);

			break;
		default:
			if (t->in_cond) {
				for (i = 0; t->input[t->offset + i] &&
				     (isalpha((unsigned char)t->input[t->offset + i])
				      || t->input[t->offset + i] == '_'); ++i);

				if (i && t->input[t->offset + i]) {
					tid = TK_SRVVARNAME;
					buffer_copy_string_len(token, t->input + t->offset, i);

					t->offset += i;
					t->line_pos += i;
				} else {
					/* ERROR */
					log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
							"source:", t->source,
							"line:", t->line, "pos:", t->line_pos,
							"invalid character in condition");
					return -1;
				}
			} else if (isdigit((unsigned char)c)) {
				/* take all digits */
				for (i = 0; t->input[t->offset + i] && isdigit((unsigned char)t->input[t->offset + i]);  i++);

				/* was there it least a digit ? */
				if (i) {
					tid = TK_INTEGER;

					buffer_copy_string_len(token, t->input + t->offset, i);

					t->offset += i;
					t->line_pos += i;
				}
			} else {
				/* the key might consist of [-.0-9a-z] */
				for (i = 0; t->input[t->offset + i] &&
				     (isalnum((unsigned char)t->input[t->offset + i]) ||
				      t->input[t->offset + i] == '.' ||
				      t->input[t->offset + i] == '_' || /* for env.* */
				      t->input[t->offset + i] == '-'
				      ); i++);

				if (i && t->input[t->offset + i]) {
					buffer_copy_string_len(token, t->input + t->offset, i);

					if (strcmp(token->ptr, "include") == 0) {
						tid = TK_INCLUDE;
					} else if (strcmp(token->ptr, "include_shell") == 0) {
						tid = TK_INCLUDE_SHELL;
					} else if (strcmp(token->ptr, "global") == 0) {
						tid = TK_GLOBAL;
					} else if (strcmp(token->ptr, "else") == 0) {
						tid = TK_ELSE;
					} else {
						tid = TK_LKEY;
					}

					t->offset += i;
					t->line_pos += i;
				} else {
					/* ERROR */
					log_error_write(srv, __FILE__, __LINE__, "sbsdsds",
							"source:", t->source,
							"line:", t->line, "pos:", t->line_pos,
							"invalid character in variable name");
					return -1;
				}
			}
			break;
		}
	}

	if (tid) {
		*token_id = tid;
#if 0
		log_error_write(srv, __FILE__, __LINE__, "sbsdsdbdd",
				"source:", t->source,
				"line:", t->line, "pos:", t->line_pos,
				token, token->used - 1, tid);
#endif

		return 1;
	} else if (t->offset < t->size) {
		log_error_write(srv, __FILE__, __LINE__, "Dsb", tid, ",", token);
	}
	return 0;
}

static int config_parse(server *srv, config_t *context, tokenizer_t *t) {
	void *pParser;
	int token_id;
	buffer *token, *lasttoken;
	int ret;

	pParser = configparserAlloc( malloc );
	force_assert(pParser);
	lasttoken = buffer_init();
	token = buffer_init();
	while((1 == (ret = config_tokenizer(srv, t, &token_id, token))) && context->ok) {
		buffer_copy_buffer(lasttoken, token);
		configparser(pParser, token_id, token, context);

		token = buffer_init();
	}
	buffer_free(token);

	if (ret != -1 && context->ok) {
		/* add an EOL at EOF, better than say sorry */
		configparser(pParser, TK_EOL, buffer_init_string("(EOL)"), context);
		if (context->ok) {
			configparser(pParser, 0, NULL, context);
		}
	}
	configparserFree(pParser, free);

	if (ret == -1) {
		log_error_write(srv, __FILE__, __LINE__, "sb",
				"configfile parser failed at:", lasttoken);
	} else if (context->ok == 0) {
		log_error_write(srv, __FILE__, __LINE__, "sbsdsdsb",
				"source:", t->source,
				"line:", t->line, "pos:", t->line_pos,
				"parser failed somehow near here:", lasttoken);
		ret = -1;
	}
	buffer_free(lasttoken);

	return ret == -1 ? -1 : 0;
}

static int tokenizer_init(tokenizer_t *t, const buffer *source, const char *input, size_t size) {

	t->source = source;
	t->input = input;
	t->size = size;
	t->offset = 0;
	t->line = 1;
	t->line_pos = 1;

	t->in_key = 1;
	t->in_brace = 0;
	t->in_cond = 0;
	t->simulate_eol = 0;
	return 0;
}

static int config_parse_file_stream(server *srv, config_t *context, const buffer *filename) {
	tokenizer_t t;
	stream s;
	int ret;

	if (0 != stream_open(&s, filename)) {
		log_error_write(srv, __FILE__, __LINE__, "sbss",
				"opening configfile ", filename, "failed:", strerror(errno));
		return -1;
	} else {
		tokenizer_init(&t, filename, s.start, s.size);
		ret = config_parse(srv, context, &t);
	}

	stream_close(&s);
	return ret;
}

int config_parse_file(server *srv, config_t *context, const char *fn) {
	buffer *filename;
	size_t i;
	int ret = -1;
      #ifdef GLOB_BRACE
	int flags = GLOB_BRACE;
      #else
	int flags = 0;
      #endif
	glob_t gl;

	if ((fn[0] == '/' || fn[0] == '\\') ||
	    (fn[0] == '.' && (fn[1] == '/' || fn[1] == '\\')) ||
	    (fn[0] == '.' && fn[1] == '.' && (fn[2] == '/' || fn[2] == '\\'))) {
		filename = buffer_init_string(fn);
	} else {
		filename = buffer_init_buffer(context->basedir);
		buffer_append_string(filename, fn);
	}

	switch (glob(filename->ptr, flags, NULL, &gl)) {
	case 0:
		for (i = 0; i < gl.gl_pathc; ++i) {
			buffer_copy_string(filename, gl.gl_pathv[i]);
			ret = config_parse_file_stream(srv, context, filename);
			if (0 != ret) break;
		}
		globfree(&gl);
		break;
	case GLOB_NOMATCH:
		if (filename->ptr[strcspn(filename->ptr, "*?[]{}")] != '\0') { /*(contains glob metachars)*/
			ret = 0; /* not an error if no files match glob pattern */
		}
		else {
			log_error_write(srv, __FILE__, __LINE__, "sb", "include file not found: ", filename);
		}
		break;
	case GLOB_ABORTED:
	case GLOB_NOSPACE:
		log_error_write(srv, __FILE__, __LINE__, "sbss", "glob()", filename, "failed:", strerror(errno));
		break;
	}

	buffer_free(filename);
	return ret;
}

#ifdef __CYGWIN__

static char* getCWD(char *buf, size_t sz) {
    if (NULL == getcwd(buf, sz)) {
        return NULL;
    }
    for (size_t i = 0; buf[i]; ++i) {
        if (buf[i] == '\\') buf[i] = '/';
    }
    return buf;
}

#define getcwd(buf, sz) getCWD((buf),(sz))

#endif /* __CYGWIN__ */

int config_parse_cmd(server *srv, config_t *context, const char *cmd) {
	int ret = 0;
	int fds[2];
	char oldpwd[PATH_MAX];

	if (NULL == getcwd(oldpwd, sizeof(oldpwd))) {
		log_error_write(srv, __FILE__, __LINE__, "s",
			"cannot get cwd", strerror(errno));
		return -1;
	}

	if (!buffer_string_is_empty(context->basedir)) {
		if (0 != chdir(context->basedir->ptr)) {
			log_error_write(srv, __FILE__, __LINE__, "sbs",
				"cannot change directory to", context->basedir, strerror(errno));
			return -1;
		}
	}

	if (pipe(fds)) {
		log_error_write(srv, __FILE__, __LINE__, "ss",
				"pipe failed: ", strerror(errno));
		ret = -1;
	}
	else {
		char *shell = getenv("SHELL");
		char *args[4];
		pid_t pid;
		*(const char **)&args[0] = shell ? shell : "/bin/sh";
		*(const char **)&args[1] = "-c";
		*(const char **)&args[2] = cmd;
		args[3] = NULL;

		fdevent_setfd_cloexec(fds[0]);
		pid = fdevent_fork_execve(args[0], args, NULL, -1, fds[1], -1, -1);
		if (-1 == pid) {
			log_error_write(srv, __FILE__, __LINE__, "SSss",
					"fork/exec(", cmd, "):", strerror(errno));
			ret = -1;
		}
		else {
			ssize_t rd;
			pid_t wpid;
			int wstatus;
			buffer *out = buffer_init();
			close(fds[1]);
			fds[1] = -1;
			do {
				rd = read(fds[0], buffer_string_prepare_append(out, 1023), 1023);
				if (rd >= 0) buffer_commit(out, (size_t)rd);
			} while (rd > 0 || (-1 == rd && errno == EINTR));
			if (0 != rd) {
				log_error_write(srv, __FILE__, __LINE__, "SSss",
						"read \"", cmd, "\" failed:", strerror(errno));
				ret = -1;
			}
			close(fds[0]);
			fds[0] = -1;
			while (-1 == (wpid = waitpid(pid, &wstatus, 0)) && errno == EINTR) ;
			if (wpid != pid) {
				log_error_write(srv, __FILE__, __LINE__, "SSss",
						"waitpid \"", cmd, "\" failed:", strerror(errno));
				ret = -1;
			}
			if (0 != wstatus) {
				log_error_write(srv, __FILE__, __LINE__, "SSsd",
						"command \"", cmd, "\" exited non-zero:", WEXITSTATUS(wstatus));
				ret = -1;
			}

			if (-1 != ret) {
				buffer *source = buffer_init_string(cmd);
				tokenizer_t t;
				tokenizer_init(&t, source, CONST_BUF_LEN(out));
				ret = config_parse(srv, context, &t);
				buffer_free(source);
			}
			buffer_free(out);
		}
		if (-1 != fds[0]) close(fds[0]);
		if (-1 != fds[1]) close(fds[1]);
	}

	if (0 != chdir(oldpwd)) {
		log_error_write(srv, __FILE__, __LINE__, "sss",
			"cannot change directory to", oldpwd, strerror(errno));
		ret = -1;
	}
	return ret;
}

static void context_init(server *srv, config_t *context) {
	context->srv = srv;
	context->ok = 1;
	vector_config_weak_init(&context->configs_stack);
	context->basedir = buffer_init();
}

static void context_free(config_t *context) {
	vector_config_weak_clear(&context->configs_stack);
	buffer_free(context->basedir);
}

int config_read(server *srv, const char *fn) {
	config_t context;
	data_config *dc;
	buffer *dcwd;
	int ret;
	char *pos;
	buffer *filename;

	context_init(srv, &context);
	context.all_configs = srv->config_context;

#ifdef __WIN32
	pos = strrchr(fn, '\\');
#else
	pos = strrchr(fn, '/');
#endif
	if (pos) {
		buffer_copy_string_len(context.basedir, fn, pos - fn + 1);
	}

	dc = data_config_init();
	buffer_copy_string_len(dc->key, CONST_STR_LEN("global"));

	force_assert(context.all_configs->used == 0);
	dc->context_ndx = context.all_configs->used;
	array_insert_unique(context.all_configs, (data_unset *)dc);
	context.current = dc;

	/* default context */
	*array_get_int_ptr(dc->value, CONST_STR_LEN("var.PID")) = getpid();

	dcwd = srv->tmp_buf;
	buffer_string_prepare_copy(dcwd, PATH_MAX-1);
	if (NULL != getcwd(dcwd->ptr, buffer_string_space(dcwd)+1)) {
		buffer_commit(dcwd, strlen(dcwd->ptr));
		array_set_key_value(dc->value, CONST_STR_LEN("var.CWD"), CONST_BUF_LEN(dcwd));
	}

	filename = buffer_init_string(fn);
	ret = config_parse_file_stream(srv, &context, filename);
	buffer_free(filename);

	/* remains nothing if parser is ok */
	force_assert(!(0 == ret && context.ok && 0 != context.configs_stack.used));
	context_free(&context);

	if (0 != ret) {
		return ret;
	}

	if (0 != config_insert(srv)) {
		return -1;
	}

	return 0;
}

int config_set_defaults(server *srv) {
	size_t i;
	specific_config *s = srv->config_storage[0];
	struct stat st1, st2;

	force_assert(sizeof(((connection *)0)->conditional_is_valid) >= COMP_LAST_ELEMENT);

	if (0 != fdevent_config(srv)) return -1;

	if (!buffer_string_is_empty(srv->srvconf.changeroot)) {
		if (-1 == stat(srv->srvconf.changeroot->ptr, &st1)) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"server.chroot doesn't exist:", srv->srvconf.changeroot);
			return -1;
		}
		if (!S_ISDIR(st1.st_mode)) {
			log_error_write(srv, __FILE__, __LINE__, "sb",
					"server.chroot isn't a directory:", srv->srvconf.changeroot);
			return -1;
		}
	}

	if (!srv->srvconf.upload_tempdirs->used) {
		const char *tmpdir = getenv("TMPDIR");
		if (NULL == tmpdir) tmpdir = "/var/tmp";
		array_insert_value(srv->srvconf.upload_tempdirs, tmpdir, strlen(tmpdir));
	}

	if (srv->srvconf.upload_tempdirs->used) {
		buffer * const b = srv->tmp_buf;
		size_t len;
		buffer_clear(b);
		if (!buffer_string_is_empty(srv->srvconf.changeroot)) {
			buffer_copy_buffer(b, srv->srvconf.changeroot);
			buffer_append_slash(b);
		}
		len = buffer_string_length(b);

		for (i = 0; i < srv->srvconf.upload_tempdirs->used; ++i) {
			const data_string * const ds = (data_string *)srv->srvconf.upload_tempdirs->data[i];
			buffer_string_set_length(b, len); /*(truncate)*/
			buffer_append_string_buffer(b, ds->value);
			if (-1 == stat(b->ptr, &st1)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					"server.upload-dirs doesn't exist:", b);
			} else if (!S_ISDIR(st1.st_mode)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					"server.upload-dirs isn't a directory:", b);
			}
		}
	}

	chunkqueue_set_tempdirs_default(
		srv->srvconf.upload_tempdirs,
		srv->srvconf.upload_temp_file_size);

	if (buffer_string_is_empty(s->document_root)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"a default document-root has to be set");

		return -1;
	}

	buffer_copy_buffer(srv->tmp_buf, s->document_root);

	buffer_to_lower(srv->tmp_buf);

	if (2 == s->force_lowercase_filenames) { /* user didn't configure it in global section? */
		s->force_lowercase_filenames = 0; /* default to 0 */

		if (0 == stat(srv->tmp_buf->ptr, &st1)) {
			int is_lower = 0;

			is_lower = buffer_is_equal(srv->tmp_buf, s->document_root);

			/* lower-case existed, check upper-case */
			buffer_copy_buffer(srv->tmp_buf, s->document_root);

			buffer_to_upper(srv->tmp_buf);

			/* we have to handle the special case that upper and lower-casing results in the same filename
			 * as in server.document-root = "/" or "/12345/" */

			if (is_lower && buffer_is_equal(srv->tmp_buf, s->document_root)) {
				/* lower-casing and upper-casing didn't result in
				 * an other filename, no need to stat(),
				 * just assume it is case-sensitive. */

				s->force_lowercase_filenames = 0;
			} else if (0 == stat(srv->tmp_buf->ptr, &st2)) {

				/* upper case exists too, doesn't the FS handle this ? */

				/* upper and lower have the same inode -> case-insensitve FS */

				if (st1.st_ino == st2.st_ino) {
					/* upper and lower have the same inode -> case-insensitve FS */

					s->force_lowercase_filenames = 1;
				}
			}
		}
	}

	if (srv->srvconf.port == 0) {
		srv->srvconf.port = s->ssl_enabled ? 443 : 80;
	}

	return 0;
}
