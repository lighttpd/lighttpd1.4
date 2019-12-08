#include "first.h"

#include "base.h"
#include "burl.h"
#include "fdevent.h"
#include "keyvalue.h"
#include "log.h"
#include "stream.h"

#include "configparser.h"
#include "configfile.h"
#include "plugin.h"
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

typedef struct {
    PLUGIN_DATA;
    specific_config defaults;
} config_data_base;

static void config_free_config(void * const p_d) {
    plugin_data_base * const p = p_d;
    if (NULL == p) return;
    if (NULL == p->cvlist) { free(p); return; }
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 18:/* server.kbytes-per-second */
                if (cpv->vtype == T_CONFIG_LOCAL) free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
    free(p->cvlist);
    free(p);
}

void config_reset_config_bytes_sec(void * const p_d) {
    plugin_data_base * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 18:/* server.kbytes-per-second */
                if (cpv->vtype == T_CONFIG_LOCAL) ((off_t *)cpv->v.v)[0] = 0;
                break;
              default:
                break;
            }
        }
    }
}

static void config_merge_config_cpv(specific_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* server.document-root */
        pconf->document_root = cpv->v.b;
        break;
      case 1: /* server.name */
        pconf->server_name = cpv->v.b;
        break;
      case 2: /* server.tag */
        pconf->server_tag = cpv->v.b;
        break;
      case 3: /* server.max-request-size */
        pconf->max_request_size = cpv->v.u;
        break;
      case 4: /* server.max-keep-alive-requests */
        pconf->max_keep_alive_requests = cpv->v.shrt;
        break;
      case 5: /* server.max-keep-alive-idle */
        pconf->max_keep_alive_idle = cpv->v.shrt;
        break;
      case 6: /* server.max-read-idle */
        pconf->max_read_idle = cpv->v.shrt;
        break;
      case 7: /* server.max-write-idle */
        pconf->max_write_idle = cpv->v.shrt;
        break;
      case 8: /* server.errorfile-prefix */
        pconf->errorfile_prefix = cpv->v.b;
        break;
      case 9: /* server.error-handler */
        pconf->error_handler = cpv->v.b;
        break;
      case 10:/* server.error-handler-404 */
        pconf->error_handler_404 = cpv->v.b;
        break;
      case 11:/* server.error-intercept */
        pconf->error_intercept = (0 != cpv->v.u);
        break;
      case 12:/* server.force-lowercase-filenames */
        pconf->force_lowercase_filenames = (0 != cpv->v.u);
        break;
      case 13:/* server.follow-symlink */
        pconf->follow_symlink = (0 != cpv->v.u);
        break;
      case 14:/* server.protocol-http11 */
        pconf->allow_http11 = (0 != cpv->v.u);
        break;
      case 15:/* server.range-requests */
        pconf->range_requests = (0 != cpv->v.u);
        break;
      case 16:/* server.stream-request-body */
        pconf->stream_request_body = cpv->v.shrt;
        break;
      case 17:/* server.stream-response-body */
        pconf->stream_response_body = cpv->v.shrt;
        break;
      case 18:/* server.kbytes-per-second */
        pconf->global_bytes_per_second = (unsigned int)((off_t *)cpv->v.v)[1];
        pconf->global_bytes_per_second_cnt_ptr = cpv->v.v;
        break;
      case 19:/* connection.kbytes-per-second */
        pconf->bytes_per_second = (unsigned int)cpv->v.shrt << 10;/* (*=1024) */
        break;
      case 20:/* mimetype.assign */
        pconf->mimetypes = cpv->v.a;
        break;
      case 21:/* mimetype.use-xattr */
        pconf->use_xattr = (0 != cpv->v.u);
        break;
      case 22:/* etag.use-inode */
        cpv->v.u
          ? (pconf->etag_flags |=  ETAG_USE_INODE)
          : (pconf->etag_flags &= ~ETAG_USE_INODE);
        break;
      case 23:/* etag.use-mtime */
        cpv->v.u
          ? (pconf->etag_flags |=  ETAG_USE_MTIME)
          : (pconf->etag_flags &= ~ETAG_USE_MTIME);
        break;
      case 24:/* etag.use-size */
        cpv->v.u
          ? (pconf->etag_flags |=  ETAG_USE_SIZE)
          : (pconf->etag_flags &= ~ETAG_USE_SIZE);
        break;
      case 25:/* debug.log-condition-handling */
        pconf->log_condition_handling = (0 != cpv->v.u);
        break;
      case 26:/* debug.log-file-not-found */
        pconf->log_file_not_found = (0 != cpv->v.u);
        break;
      case 27:/* debug.log-request-handling */
        pconf->log_request_handling = (0 != cpv->v.u);
        break;
      case 28:/* debug.log-request-header */
        pconf->log_request_header = (0 != cpv->v.u);
        break;
      case 29:/* debug.log-response-header */
        pconf->log_response_header = (0 != cpv->v.u);
        break;
      case 30:/* debug.log-timeouts */
        pconf->log_timeouts = (0 != cpv->v.u);
        break;
      default:/* should not happen */
        return;
    }
}

static void config_merge_config(specific_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        config_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

void config_patch_config(connection * const con) {
    config_data_base * const p = con->config_data_base;

    /* performed by config_reset_config() */
    /*memcpy(&con->conf, &p->defaults, sizeof(specific_config));*/

    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            config_merge_config(&con->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

void config_reset_config(connection * const con) {
    /* initialize specific_config (con->conf) from top-level specific_config */
    config_data_base * const p = con->config_data_base;
    con->server_name = p->defaults.server_name;
    memcpy(&con->conf, &p->defaults, sizeof(specific_config));
}

static int config_burl_normalize_cond (server *srv) {
    buffer * const tb = srv->tmp_buf;
    for (uint32_t i = 0; i < srv->config_context->used; ++i) {
        data_config * const config =(data_config *)srv->config_context->data[i];
        if (COMP_HTTP_QUERY_STRING != config->comp) continue;
        switch(config->cond) {
        case CONFIG_COND_NE:
        case CONFIG_COND_EQ:
            /* (can use this routine as long as it does not perform
             *  any regex-specific normalization of first arg) */
            pcre_keyvalue_burl_normalize_key(&config->string, tb);
            break;
        case CONFIG_COND_NOMATCH:
        case CONFIG_COND_MATCH:
            pcre_keyvalue_burl_normalize_key(&config->string, tb);
            if (!data_config_pcre_compile(config)) return 0;
            break;
        default:
            break;
        }
    }

    return 1;
}

#if defined(HAVE_MYSQL) || (defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER))
static void config_warn_authn_module (server *srv, const char *module, size_t len) {
	for (uint32_t i = 0; i < srv->config_context->used; ++i) {
		const data_config *config = (data_config const*)srv->config_context->data[i];
		const data_unset *du = array_get_element_klen(config->value, CONST_STR_LEN("auth.backend"));
		if (NULL != du && du->type == TYPE_STRING) {
			data_string *ds = (data_string *)du;
			if (buffer_is_equal_string(&ds->value, module, len)) {
				buffer * const tb = srv->tmp_buf;
				buffer_copy_string_len(tb, CONST_STR_LEN("mod_authn_"));
				buffer_append_string_len(tb, module, len);
				array_insert_value(srv->srvconf.modules, CONST_BUF_LEN(tb));
				log_error(srv->errh, __FILE__, __LINE__,
				  "Warning: please add \"mod_authn_%s\" to server.modules list "
				  "in lighttpd.conf.  A future release of lighttpd 1.4.x will "
				  "not automatically load mod_authn_%s and lighttpd will fail "
				  "to start up since your lighttpd.conf uses "
				  "auth.backend = \"%s\".", module, module, module);
				return;
			}
		}
	}
}
#endif

#ifdef USE_OPENSSL_CRYPTO
static void config_warn_openssl_module (server *srv) {
	for (uint32_t i = 0; i < srv->config_context->used; ++i) {
		const data_config *config = (data_config const*)srv->config_context->data[i];
		for (uint32_t j = 0; j < config->value->used; ++j) {
			data_unset *du = config->value->data[j];
			if (0 == strncmp(du->key.ptr, "ssl.", sizeof("ssl.")-1)) {
				/* mod_openssl should be loaded after mod_extforward */
				array_insert_value(srv->srvconf.modules, CONST_STR_LEN("mod_openssl"));
				log_error(srv->errh, __FILE__, __LINE__,
				  "Warning: please add \"mod_openssl\" to server.modules list "
				  "in lighttpd.conf.  A future release of lighttpd 1.4.x "
				  "*will not* automatically load mod_openssl and lighttpd "
				  "*will not* use SSL/TLS where your lighttpd.conf contains "
				  "ssl.* directives");
				return;
			}
		}
	}
}
#endif

static void config_compat_module_load (server *srv) {
    int prepend_mod_indexfile  = 1;
    int append_mod_dirlisting  = 1;
    int append_mod_staticfile  = 1;
    int append_mod_authn_file  = 1;
    int append_mod_authn_ldap  = 1;
    int append_mod_authn_mysql = 1;
    int append_mod_openssl     = 1;
    int contains_mod_auth      = 0;

    for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
        buffer *m = &((data_string *)srv->srvconf.modules->data[i])->value;

        if (buffer_eq_slen(m, CONST_STR_LEN("mod_indexfile")))
            prepend_mod_indexfile = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_staticfile")))
            append_mod_staticfile = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_dirlisting")))
            append_mod_dirlisting = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_openssl")))
            append_mod_openssl = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_authn_file")))
            append_mod_authn_file = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_authn_ldap")))
            append_mod_authn_ldap = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_authn_mysql")))
            append_mod_authn_mysql = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_auth")))
            contains_mod_auth = 1;

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

    /* prepend default modules */

    if (prepend_mod_indexfile) {
        /* mod_indexfile has to be loaded before mod_fastcgi and friends */
        array *modules = array_init(srv->srvconf.modules->used+4);
        array_insert_value(modules, CONST_STR_LEN("mod_indexfile"));

        for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
            data_string *ds = (data_string *)srv->srvconf.modules->data[i];
            array_insert_value(modules, CONST_BUF_LEN(&ds->value));
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

static int config_http_parseopts (server *srv, const array *a) {
    unsigned short int opts = srv->srvconf.http_url_normalize;
    unsigned short int decode_2f = 1;
    int rc = 1;
    for (size_t i = 0; i < a->used; ++i) {
        const data_string * const ds = (const data_string *)a->data[i];
        const buffer *k = &ds->key;
        const buffer *v = &ds->value;
        unsigned short int opt;
        int val = 0;
        if (buffer_eq_slen(v, CONST_STR_LEN("enable")))
            val = 1;
        else if (buffer_eq_slen(v, CONST_STR_LEN("disable")))
            val = 0;
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "unrecognized value for server.http-parseopts: "
              "%s => %s (expect \"[enable|disable]\")", k->ptr, v->ptr);
            rc = 0;
        }
        if (buffer_eq_slen(k, CONST_STR_LEN("url-normalize")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-normalize-unreserved")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-normalize-required")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_REQUIRED;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-ctrls-reject")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-path-backslash-trans")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_BACKSLASH_TRANS;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-path-2f-decode")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-path-2f-reject")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_REJECT;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-path-dotseg-remove")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-path-dotseg-reject")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT;
        else if (buffer_eq_slen(k, CONST_STR_LEN("url-query-20-plus")))
            opt = HTTP_PARSEOPT_URL_NORMALIZE_QUERY_20_PLUS;
        else if (buffer_eq_slen(k, CONST_STR_LEN("header-strict"))) {
            srv->srvconf.http_header_strict = val;
            continue;
        }
        else if (buffer_eq_slen(k, CONST_STR_LEN("host-strict"))) {
            srv->srvconf.http_host_strict = val;
            continue;
        }
        else if (buffer_eq_slen(k, CONST_STR_LEN("host-normalize"))) {
            srv->srvconf.http_host_normalize = val;
            continue;
        }
        else if (buffer_eq_slen(k, CONST_STR_LEN("method-get-body"))) {
            srv->srvconf.http_method_get_body = val;
            continue;
        }
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "unrecognized key for server.http-parseopts: %s", k->ptr);
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
            log_error(srv->errh, __FILE__, __LINE__,
              "conflicting options in server.http-parseopts:"
              "url-path-2f-decode, url-path-2f-reject");
            rc = 0;
        }
        if ((opts & (HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE
                    |HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT))
                 == (HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE
                    |HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REJECT)) {
            log_error(srv->errh, __FILE__, __LINE__,
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

static int config_insert_srvconf(server *srv) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("server.modules"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.compat-module-load"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.systemd-socket-activation"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.port"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.bind"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.network-backend"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.chroot"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.username"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.groupname"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.errorlog"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.breakagelog"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.errorlog-use-syslog"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.syslog-facility"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.core-files"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.event-handler"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.pid-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.max-worker"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.max-fds"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.max-connections"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.max-request-field-size"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.chunkqueue-chunk-sz"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.upload-temp-file-size"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.upload-dirs"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.http-parseopts"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.http-parseopt-header-strict"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.http-parseopt-host-strict"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.http-parseopt-host-normalize"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.reject-expect-100-with-417"), /*(ignored)*/
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.stat-cache-engine"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("mimetype.xattr-name"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("ssl.engine"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-request-header-on-error"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("debug.log-state-handling"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_SERVER }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    int rc = 0;
    plugin_data_base srvplug;
    memset(&srvplug, 0, sizeof(srvplug));
    plugin_data_base * const p = &srvplug;
    if (!config_plugin_values_init(srv, p, cpk, "global"))
        return HANDLER_ERROR;

    int ssl_enabled = 0; /*(directive checked here only to set default port)*/

    /* process and validate T_CONFIG_SCOPE_SERVER config directives */
    if (p->cvlist[0].v.u2[1]) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[0].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* server.modules */
                array_copy_array(srv->srvconf.modules, cpv->v.a);
                break;
              case 1: /* server.compat-module-load */
                srv->srvconf.compat_module_load = (unsigned short)cpv->v.u;
                break;
              case 2: /* server.systemd-socket-activation */
                srv->srvconf.systemd_socket_activation=(unsigned short)cpv->v.u;
                break;
              case 3: /* server.port */
                srv->srvconf.port = cpv->v.shrt;
                break;
              case 4: /* server.bind */
                srv->srvconf.bindhost = cpv->v.b;
                break;
              case 5: /* server.network-backend */
                srv->srvconf.network_backend = cpv->v.b;
                break;
              case 6: /* server.chroot */
                srv->srvconf.changeroot = cpv->v.b;
                break;
              case 7: /* server.username */
                srv->srvconf.username = cpv->v.b;
                break;
              case 8: /* server.groupname */
                srv->srvconf.groupname = cpv->v.b;
                break;
              case 9: /* server.errorlog */
                srv->srvconf.errorlog_file = cpv->v.b;
                break;
              case 10:/* server.breakagelog */
                srv->srvconf.breakagelog_file = cpv->v.b;
                break;
              case 11:/* server.errorlog-use-syslog */
                srv->srvconf.errorlog_use_syslog = (unsigned short)cpv->v.u;
                break;
              case 12:/* server.syslog-facility */
                srv->srvconf.syslog_facility = cpv->v.b;
                break;
              case 13:/* server.core-files */
                srv->srvconf.enable_cores = (unsigned short)cpv->v.u;
                break;
              case 14:/* server.event-handler */
                srv->srvconf.event_handler = cpv->v.b->ptr;
                break;
              case 15:/* server.pid-file */
                *(const buffer **)&srv->srvconf.pid_file = cpv->v.b;
                break;
              case 16:/* server.max-worker */
                srv->srvconf.max_worker = (unsigned short)cpv->v.u;
                break;
              case 17:/* server.max-fds */
                srv->srvconf.max_fds = (unsigned short)cpv->v.u;
                break;
              case 18:/* server.max-connections */
                srv->srvconf.max_conns = (unsigned short)cpv->v.u;
                break;
              case 19:/* server.max-request-field-size */
                srv->srvconf.max_request_field_size = cpv->v.u;
                break;
              case 20:/* server.chunkqueue-chunk-sz */
                chunkqueue_set_chunk_size(cpv->v.u);
                break;
              case 21:/* server.upload-temp-file-size */
                srv->srvconf.upload_temp_file_size = cpv->v.u;
                break;
              case 22:/* server.upload-dirs */
                array_copy_array(srv->srvconf.upload_tempdirs, cpv->v.a);
                break;
              case 23:/* server.http-parseopts */
                if (!config_http_parseopts(srv, cpv->v.a))
                    rc = HANDLER_ERROR;
                break;
              case 24:/* server.http-parseopt-header-strict */
                srv->srvconf.http_header_strict = (0 != cpv->v.u);
                break;
              case 25:/* server.http-parseopt-host-strict */
                srv->srvconf.http_host_strict = (0 != cpv->v.u);
                break;
              case 26:/* server.http-parseopt-host-normalize */
                srv->srvconf.http_host_normalize = (0 != cpv->v.u);
                break;
              case 27:/* server.reject-expect-100-with-417 *//*(ignored)*/
                break;
              case 28:/* server.stat-cache-engine */
                if (0 != stat_cache_choose_engine(srv, cpv->v.b))
                    rc = HANDLER_ERROR;
                break;
              case 29:/* mimetype.xattr-name */
                stat_cache_xattrname(cpv->v.b->ptr);
                break;
              case 30:/* ssl.engine */
                ssl_enabled = (0 != cpv->v.u);
               #ifndef USE_OPENSSL_CRYPTO
                if (ssl_enabled) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "ssl support is missing; "
                      "recompile with e.g. --with-openssl");
                    rc = HANDLER_ERROR;
                    break;
                }
               #endif
                break;
              case 31:/* debug.log-request-header-on-error */
                srv->srvconf.log_request_header_on_error = (0 != cpv->v.u);
                break;
              case 32:/* debug.log-state-handling */
                srv->srvconf.log_state_handling = (0 != cpv->v.u);
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    if (0 == srv->srvconf.port)
        srv->srvconf.port = ssl_enabled ? 443 : 80;

    if (srv->srvconf.compat_module_load)
        config_compat_module_load(srv);

    if (srv->srvconf.http_url_normalize && !config_burl_normalize_cond(srv))
        rc = HANDLER_ERROR;

    free(srvplug.cvlist);
    return rc;
}

static int config_insert(server *srv) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("server.document-root"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.name"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.tag"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.max-request-size"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.max-keep-alive-requests"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.max-keep-alive-idle"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.max-read-idle"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.max-write-idle"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.errorfile-prefix"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.error-handler"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.error-handler-404"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.error-intercept"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.force-lowercase-filenames"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.follow-symlink"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.protocol-http11"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.range-requests"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.stream-request-body"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.stream-response-body"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.kbytes-per-second"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("connection.kbytes-per-second"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mimetype.assign"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mimetype.use-xattr"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("etag.use-inode"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("etag.use-mtime"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("etag.use-size"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-condition-handling"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-file-not-found"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-request-handling"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-request-header"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-response-header"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-timeouts"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    int rc = 0;
    config_data_base * const p = calloc(1, sizeof(config_data_base));
    force_assert(p);
    srv->config_data_base = p;

    if (!config_plugin_values_init(srv, p, cpk, "base"))
        return HANDLER_ERROR;

    /* process and validate T_CONFIG_SCOPE_CONNECTION config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* server.document-root */
              case 1: /* server.name */
                break;
              case 2: /* server.tag */
                if (!buffer_string_is_empty(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    for (char *t=strchr(b->ptr,'\n'); t; t=strchr(t+2,'\n')) {
                        /* not expecting admin to define multi-line server.tag,
                         * but ensure server_tag has proper header continuation,
                         * if needed */
                        if (t[1] == ' ' || t[1] == '\t') continue;
                        off_t off = t - b->ptr;
                        size_t len = buffer_string_length(b);
                        buffer_string_prepare_append(b, 1);
                        t = b->ptr+off;
                        memmove(t+2, t+1, len - off - 1);
                        t[1] = ' ';
                        buffer_commit(b, 1);
                    }
                }
                break;
              case 3: /* server.max-request-size */
              case 4: /* server.max-keep-alive-requests */
              case 5: /* server.max-keep-alive-idle */
              case 6: /* server.max-read-idle */
              case 7: /* server.max-write-idle */
              case 8: /* server.errorfile-prefix */
              case 9: /* server.error-handler */
              case 10:/* server.error-handler-404 */
              case 11:/* server.error-intercept */
                break;
              case 12:/* server.force-lowercase-filenames */
               #ifndef HAVE_LSTAT
                if (0 == cpv->v.u)
                    log_error(srv->errh, __FILE__, __LINE__,
                      "Your system lacks lstat(). "
                      "We can not differ symlinks from files. "
                      "Please remove server.follow-symlinks from your config.");
               #endif
                break;
              case 13:/* server.follow-symlink */
              case 14:/* server.protocol-http11 */
              case 15:/* server.range-requests */
                break;
              case 16:/* server.stream-request-body */
                if (cpv->v.shrt & FDEVENT_STREAM_REQUEST_BUFMIN)
                    cpv->v.shrt |=FDEVENT_STREAM_REQUEST;
                break;
              case 17:/* server.stream-response-body */
                if (cpv->v.shrt & FDEVENT_STREAM_RESPONSE_BUFMIN)
                    cpv->v.shrt |=FDEVENT_STREAM_RESPONSE;
                break;
              case 18:{/*server.kbytes-per-second */
                off_t * const cnt = malloc(2*sizeof(off_t));
                force_assert(cnt);
                cnt[0] = 0;
                cnt[1] = (off_t)cpv->v.shrt << 10;
                cpv->v.v = cnt;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              }
              case 19:/* connection.kbytes-per-second */
              case 20:/* mimetype.assign */
              case 21:/* mimetype.use-xattr */
              case 22:/* etag.use-inode */
              case 23:/* etag.use-mtime */
              case 24:/* etag.use-size */
              case 25:/* debug.log-condition-handling */
              case 26:/* debug.log-file-not-found */
              case 27:/* debug.log-request-handling */
              case 28:/* debug.log-request-header */
              case 29:/* debug.log-response-header */
              case 30:/* debug.log-timeouts */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.errh = srv->errh;
    p->defaults.max_keep_alive_requests = 100;
    p->defaults.max_keep_alive_idle = 5;
    p->defaults.max_read_idle = 60;
    p->defaults.max_write_idle = 360;
    p->defaults.follow_symlink = 1;
    p->defaults.allow_http11 = 1;
    p->defaults.etag_flags = ETAG_USE_INODE | ETAG_USE_MTIME | ETAG_USE_SIZE;
    p->defaults.range_requests = 1;
    /* use 2 to detect later if value is set by user config in global section */
    p->defaults.force_lowercase_filenames = 2;

    /*(global, but store in con->conf.http_parseopts)*/
    p->defaults.http_parseopts =
        (srv->srvconf.http_header_strict   ?  HTTP_PARSEOPT_HEADER_STRICT   :0)
      | (srv->srvconf.http_host_strict     ? (HTTP_PARSEOPT_HOST_STRICT
                                             |HTTP_PARSEOPT_HOST_NORMALIZE) :0)
      | (srv->srvconf.http_host_normalize  ?  HTTP_PARSEOPT_HOST_NORMALIZE  :0)
      | (srv->srvconf.http_method_get_body ?  HTTP_PARSEOPT_METHOD_GET_BODY :0);
    p->defaults.http_parseopts |= srv->srvconf.http_url_normalize;
    p->defaults.mimetypes = &srv->srvconf.empty_array; /*(must not be NULL)*/

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            config_merge_config(&p->defaults, cpv);
    }

    /* (after processing config defaults) */
    if (p->defaults.log_request_handling || p->defaults.log_request_header)
        srv->srvconf.log_request_header_on_error = 1;

    return rc;
}

int config_finalize(server *srv, const buffer *default_server_tag) {
    /* (call after plugins_call_set_defaults()) */

    config_data_base * const p = srv->config_data_base;

    /* settings might be enabled during plugins_call_set_defaults() */
    p->defaults.high_precision_timestamps =
      srv->srvconf.high_precision_timestamps;

    /* configure default server_tag if not set
     * (if configured to blank, unset server_tag)*/
    if (buffer_is_empty(p->defaults.server_tag))
        p->defaults.server_tag = default_server_tag;
    else if (buffer_string_is_empty(p->defaults.server_tag))
        p->defaults.server_tag = NULL;

    /* dump unused config keys */
    for (uint32_t i = 0; i < srv->config_context->used; ++i) {
        array *config = ((data_config *)srv->config_context->data[i])->value;
        for (uint32_t j = 0; config && j < config->used; ++j) {
            const buffer * const k = &config->data[j]->key;

            /* all var.* is known as user defined variable */
            if (strncmp(k->ptr, "var.", sizeof("var.") - 1) == 0)
                continue;

            if (!array_get_element_klen(srv->srvconf.config_touched,
                                        CONST_BUF_LEN(k)))
                log_error(srv->errh, __FILE__, __LINE__,
                  "WARNING: unknown config-key: %s (ignored)", k->ptr);
        }
    }

    array_free(srv->srvconf.config_touched);
    srv->srvconf.config_touched = NULL;

    if (srv->srvconf.config_unsupported || srv->srvconf.config_deprecated) {
        if (srv->srvconf.config_unsupported)
            log_error(srv->errh, __FILE__, __LINE__,
              "Configuration contains unsupported keys. Going down.");
        if (srv->srvconf.config_deprecated)
            log_error(srv->errh, __FILE__, __LINE__,
              "Configuration contains deprecated keys. Going down.");
        return 0;
    }

    return 1;
}

void config_print(server *srv) {
    data_unset *dc = srv->config_context->data[0];
    dc->fn->print(dc, 0);
}

void config_free(server *srv) {
    config_free_config(srv->config_data_base);

    array_free(srv->config_context);
    array_free(srv->srvconf.config_touched);
    array_free(srv->srvconf.modules);
    buffer_free(srv->srvconf.modules_dir);
    array_free(srv->srvconf.upload_tempdirs);
}

void config_init(server *srv) {
    srv->config_context = array_init(16);
    srv->srvconf.config_touched = array_init(128);

    srv->srvconf.port = 0;
    srv->srvconf.dont_daemonize = 0;
    srv->srvconf.preflight_check = 0;
    srv->srvconf.compat_module_load = 1;
    srv->srvconf.systemd_socket_activation = 0;

    srv->srvconf.high_precision_timestamps = 0;
    srv->srvconf.max_request_field_size = 8192;

    srv->srvconf.http_header_strict  = 1;
    srv->srvconf.http_host_strict    = 1; /*(implies http_host_normalize)*/
    srv->srvconf.http_host_normalize = 0;
    srv->srvconf.http_url_normalize =
        HTTP_PARSEOPT_URL_NORMALIZE
      | HTTP_PARSEOPT_URL_NORMALIZE_UNRESERVED
      | HTTP_PARSEOPT_URL_NORMALIZE_CTRLS_REJECT
      | HTTP_PARSEOPT_URL_NORMALIZE_PATH_2F_DECODE
      | HTTP_PARSEOPT_URL_NORMALIZE_PATH_DOTSEG_REMOVE;

    srv->srvconf.modules = array_init(16);
    srv->srvconf.modules_dir = buffer_init_string(LIBRARY_DIR);
    srv->srvconf.upload_tempdirs = array_init(2);
}



typedef struct {
	const char *source;
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

__attribute_cold__
static int config_tokenizer_err(server *srv, const char *file, unsigned int line, tokenizer_t *t, const char *msg) {
    log_error(srv->errh, file, line, "source: %s line: %d pos: %d %s",
              t->source, t->line, t->line_pos, msg);
    return -1;
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
					return config_tokenizer_err(srv, __FILE__, __LINE__, t,
							"use => for assignments in arrays");
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
					return config_tokenizer_err(srv, __FILE__, __LINE__, t,
							"only =~ and == are allowed in the condition");
				}
				t->in_key = 1;
				t->in_cond = 0;
			} else if (t->in_key) {
				tid = TK_ASSIGN;

				buffer_copy_string_len(token, t->input + t->offset, 1);

				t->offset++;
				t->line_pos++;
			} else {
				return config_tokenizer_err(srv, __FILE__, __LINE__, t,
						"unexpected equal-sign: =");
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
					return config_tokenizer_err(srv, __FILE__, __LINE__, t,
							"only !~ and != are allowed in the condition");
				}
				t->in_key = 1;
				t->in_cond = 0;
			} else {
				return config_tokenizer_err(srv, __FILE__, __LINE__, t,
						"unexpected exclamation-marks: !");
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
				return config_tokenizer_err(srv, __FILE__, __LINE__, t,
						"missing closing quote");
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
			} else {
				return config_tokenizer_err(srv, __FILE__, __LINE__, t,
						"unexpected character ':'");
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
					return config_tokenizer_err(srv, __FILE__, __LINE__, t,
							"invalid character in condition");
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
					return config_tokenizer_err(srv, __FILE__, __LINE__, t,
							"invalid character in variable name");
				}
			}
			break;
		}
	}

	if (tid) {
		*token_id = tid;
		return 1;
	} else if (t->offset < t->size) {
		log_error(srv->errh, __FILE__, __LINE__, "%d, %s", tid, token->ptr);
	}
	return 0;
}

static int config_parse(server *srv, config_t *context, const char *source, const char *input, size_t isize) {
	void *pParser;
	buffer *token, *lasttoken;
	int token_id = 0;
	int ret;
	tokenizer_t t;

	t.source = source;
	t.input = input;
	t.size = isize;
	t.offset = 0;
	t.line = 1;
	t.line_pos = 1;

	t.in_key = 1;
	t.in_brace = 0;
	t.in_cond = 0;
	t.simulate_eol = 0;

	pParser = configparserAlloc( malloc );
	force_assert(pParser);
	lasttoken = buffer_init();
	token = buffer_init();
	while((1 == (ret = config_tokenizer(srv, &t, &token_id, token))) && context->ok) {
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
		log_error(srv->errh, __FILE__, __LINE__,
		          "configfile parser failed at: %s", lasttoken->ptr);
	} else if (context->ok == 0) {
		log_error(srv->errh, __FILE__, __LINE__, "source: %s line: %d pos: %d "
		          "parser failed somehow near here: %s",
		          t.source, t.line, t.line_pos, lasttoken->ptr);
		ret = -1;
	}
	buffer_free(lasttoken);

	return ret == -1 ? -1 : 0;
}

static int config_parse_file_stream(server *srv, config_t *context, const char *fn) {
	stream s;

	if (0 != stream_open(&s, fn)) {
		log_perror(srv->errh, __FILE__, __LINE__,
		  "opening configfile %s failed", fn);
		return -1;
	}

	int ret = config_parse(srv, context, fn, s.start, (size_t)s.size);
	stream_close(&s);
	return ret;
}

int config_parse_file(server *srv, config_t *context, const char *fn) {
	buffer *filename;
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
		for (size_t i = 0; i < gl.gl_pathc; ++i) {
			ret = config_parse_file_stream(srv, context, gl.gl_pathv[i]);
			if (0 != ret) break;
		}
		globfree(&gl);
		break;
	case GLOB_NOMATCH:
		if (filename->ptr[strcspn(filename->ptr, "*?[]{}")] != '\0') { /*(contains glob metachars)*/
			ret = 0; /* not an error if no files match glob pattern */
		}
		else {
			log_error(srv->errh, __FILE__, __LINE__, "include file not found: %s", filename->ptr);
		}
		break;
	case GLOB_ABORTED:
	case GLOB_NOSPACE:
		log_perror(srv->errh, __FILE__, __LINE__, "glob() %s failed", filename->ptr);
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
		log_perror(srv->errh, __FILE__, __LINE__, "getcwd()");
		return -1;
	}

	if (!buffer_string_is_empty(context->basedir)) {
		if (0 != chdir(context->basedir->ptr)) {
			log_perror(srv->errh, __FILE__, __LINE__,
			  "cannot change directory to %s", context->basedir->ptr);
			return -1;
		}
	}

	if (pipe(fds)) {
		log_perror(srv->errh, __FILE__, __LINE__, "pipe()");
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
			log_perror(srv->errh, __FILE__, __LINE__, "fork/exec(%s)", cmd);
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
				log_perror(srv->errh, __FILE__, __LINE__, "read \"%s\"", cmd);
				ret = -1;
			}
			close(fds[0]);
			fds[0] = -1;
			while (-1 == (wpid = waitpid(pid, &wstatus, 0)) && errno == EINTR) ;
			if (wpid != pid) {
				log_perror(srv->errh, __FILE__, __LINE__, "waitpid \"%s\"",cmd);
				ret = -1;
			}
			if (0 != wstatus) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "command \"%s\" exited non-zero: %d",
				  cmd, WEXITSTATUS(wstatus));
				ret = -1;
			}

			if (-1 != ret) {
				ret = config_parse(srv, context, cmd, CONST_BUF_LEN(out));
			}
			buffer_free(out);
		}
		if (-1 != fds[0]) close(fds[0]);
		if (-1 != fds[1]) close(fds[1]);
	}

	if (0 != chdir(oldpwd)) {
		log_perror(srv->errh, __FILE__, __LINE__,
		  "cannot change directory to %s", oldpwd);
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
	buffer_copy_string_len(&dc->key, CONST_STR_LEN("global"));

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

	ret = config_parse_file_stream(srv, &context, fn);

	/* remains nothing if parser is ok */
	force_assert(!(0 == ret && context.ok && 0 != context.configs_stack.used));
	context_free(&context);

	if (0 != ret) {
		return ret;
	}

	if (0 != config_insert_srvconf(srv)) {
		return -1;
	}

	if (0 != config_insert(srv)) {
		return -1;
	}

	return 0;
}

int config_set_defaults(server *srv) {
	size_t i;
	specific_config *s = &((config_data_base *)srv->config_data_base)->defaults;
	struct stat st1, st2;

	if (0 != fdevent_config(srv)) return -1;

	if (!buffer_string_is_empty(srv->srvconf.changeroot)) {
		if (-1 == stat(srv->srvconf.changeroot->ptr, &st1)) {
			log_error(srv->errh, __FILE__, __LINE__,
			  "server.chroot doesn't exist: %s",
			  srv->srvconf.changeroot->ptr);
			return -1;
		}
		if (!S_ISDIR(st1.st_mode)) {
			log_error(srv->errh, __FILE__, __LINE__,
			  "server.chroot isn't a directory: %s",
			  srv->srvconf.changeroot->ptr);
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
			buffer_append_string_buffer(b, &ds->value);
			if (-1 == stat(b->ptr, &st1)) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "server.upload-dirs doesn't exist: %s", b->ptr);
			} else if (!S_ISDIR(st1.st_mode)) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "server.upload-dirs isn't a directory: %s", b->ptr);
			}
		}
	}

	chunkqueue_set_tempdirs_default(
		srv->srvconf.upload_tempdirs,
		srv->srvconf.upload_temp_file_size);

	if (buffer_string_is_empty(s->document_root)) {
		log_error(srv->errh, __FILE__, __LINE__, "document-root is not set");
		return -1;
	}

	buffer * const tb = srv->tmp_buf;
	buffer_copy_buffer(tb, s->document_root);

	buffer_to_lower(tb);

	if (2 == s->force_lowercase_filenames) { /* user didn't configure it in global section? */
		s->force_lowercase_filenames = 0; /* default to 0 */

		if (0 == stat(tb->ptr, &st1)) {
			int is_lower = 0;

			is_lower = buffer_is_equal(tb, s->document_root);

			/* lower-case existed, check upper-case */
			buffer_copy_buffer(tb, s->document_root);

			buffer_to_upper(tb);

			/* we have to handle the special case that upper and lower-casing results in the same filename
			 * as in server.document-root = "/" or "/12345/" */

			if (is_lower && buffer_is_equal(tb, s->document_root)) {
				/* lower-casing and upper-casing didn't result in
				 * an other filename, no need to stat(),
				 * just assume it is case-sensitive. */

				s->force_lowercase_filenames = 0;
			} else if (0 == stat(tb->ptr, &st2)) {

				/* upper case exists too, doesn't the FS handle this ? */

				/* upper and lower have the same inode -> case-insensitve FS */

				if (st1.st_ino == st2.st_ino) {
					/* upper and lower have the same inode -> case-insensitve FS */

					s->force_lowercase_filenames = 1;
				}
			}
		}
	}

	return 0;
}
