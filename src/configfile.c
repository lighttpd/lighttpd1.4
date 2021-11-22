#include "first.h"

#include "base.h"
#include "burl.h"
#include "chunk.h"
#include "ck.h"
#include "fdevent.h"
#include "fdlog.h"
#include "http_etag.h"
#include "keyvalue.h"
#include "log.h"

#include "configparser.h"
#include "configfile.h"
#include "plugin.h"
#include "reqpool.h"
#include "sock_addr.h"
#include "stat_cache.h"
#include "sys-crypto.h"

#include <sys/stat.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <glob.h>

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef HAVE_PCRE2_H
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    PLUGIN_DATA;
    request_config defaults;
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

static void config_merge_config_cpv(request_config * const pconf, const config_plugin_value_t * const cpv) {
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
      case 31:/* debug.log-state-handling */
        pconf->log_state_handling = (0 != cpv->v.u);
        break;
      case 32:/* server.errorlog */
        if (cpv->vtype == T_CONFIG_LOCAL) pconf->errh = cpv->v.v;
        break;
      case 33:/* server.breakagelog */
        if (cpv->vtype == T_CONFIG_LOCAL) pconf->serrh = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void config_merge_config(request_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        config_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

void config_patch_config(request_st * const r) {
    config_data_base * const p = r->con->config_data_base;

    /* performed by request_config_reset() */
    /*memcpy(&r->conf, &p->defaults, sizeof(request_config));*/

    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            config_merge_config(&r->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

#if 0 /*(moved to reqpool.c:request_config_reset())*/
void config_reset_config(request_st * const r) {
    /* initialize request_config (r->conf) from top-level request_config */
    config_data_base * const p = r->con->config_data_base;
    memcpy(&r->conf, &p->defaults, sizeof(request_config));
}
#endif

static void config_burl_normalize_cond (server * const srv) {
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
            break;
        default:
            break;
        }
    }
}

static int config_pcre_keyvalue (server * const srv) {
    const int pcre_jit = config_feature_bool(srv, "server.pcre_jit", 1);
    for (uint32_t i = 0; i < srv->config_context->used; ++i) {
        data_config * const dc = (data_config *)srv->config_context->data[i];
        if (dc->cond != CONFIG_COND_NOMATCH && dc->cond != CONFIG_COND_MATCH)
            continue;
        if (!data_config_pcre_compile(dc, pcre_jit, srv->errh))
            return 0;
    }

    return 1;
}

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

static void config_check_module_duplicates (server *srv) {
    int dups = 0;
    data_string ** const data = (data_string **)srv->srvconf.modules->data;
    const uint32_t used = srv->srvconf.modules->used;
    for (uint32_t i = 0; i < used; ++i) {
        const buffer * const m = &data[i]->value;
        for (uint32_t j = i+1; j < used; ++j) {
            if (buffer_is_equal(m, &data[j]->value)) {
                ++dups;
                break;
            }
        }
    }
    if (!dups) return;

    array * const modules = array_init(used - dups);
    for (uint32_t i = 0; i < used; ++i) {
        const buffer * const m = &data[i]->value;
        uint32_t j;
        for (j = 0; j < modules->used; ++j) {
            buffer *n = &((data_string *)modules->data[j])->value;
            if (buffer_is_equal(m, n)) break; /* duplicate */
        }
        if (j == modules->used)
            array_insert_value(modules, BUF_PTR_LEN(m));
    }
    array_free(srv->srvconf.modules);
    srv->srvconf.modules = modules;
}

__attribute_pure__
static const char * config_has_opt_and_value (const server * const srv, const char * const opt, const uint32_t olen, const char * const v, const uint32_t vlen) {
    for (uint32_t i = 0; i < srv->config_context->used; ++i) {
        const data_config * const config =
            (data_config const *)srv->config_context->data[i];
        const data_string * const ds =
            (data_string *)array_get_element_klen(config->value, opt, olen);
        if (NULL != ds && ds->type == TYPE_STRING
            && buffer_eq_slen(&ds->value, v, vlen))
            return v;
    }
    return NULL;
}

static void config_compat_module_prepend (server *srv, const char *module, uint32_t len) {
    array *modules = array_init(srv->srvconf.modules->used+4);
    array_insert_value(modules, module, len);

    for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
        data_string *ds = (data_string *)srv->srvconf.modules->data[i];
        array_insert_value(modules, BUF_PTR_LEN(&ds->value));
    }

    array_free(srv->srvconf.modules);
    srv->srvconf.modules = modules;
}

static void config_warn_authn_module (server *srv, const char *module, uint32_t len, const char *v) {
    buffer * const tb = srv->tmp_buf;
    buffer_copy_string_len(tb, CONST_STR_LEN("mod_authn_"));
    buffer_append_string_len(tb, module, len);
    array_insert_value(srv->srvconf.modules, BUF_PTR_LEN(tb));
    log_error(srv->errh, __FILE__, __LINE__,
      "Warning: please add \"mod_authn_%s\" to server.modules list "
      "in lighttpd.conf.  A future release of lighttpd 1.4.x will "
      "not automatically load mod_authn_%s and lighttpd will fail "
      "to start up since your lighttpd.conf uses auth.backend = \"%s\".",
      module, module, v);
}

static void config_compat_module_load (server *srv) {
    int prepend_mod_indexfile  = 1;
    int append_mod_dirlisting  = 1;
    int append_mod_staticfile  = 1;
    int append_mod_authn_file  = 1;
    int append_mod_authn_ldap  = 1;
    int append_mod_authn_mysql = 1;
    int append_mod_openssl     = 1;
    int contains_mod_auth      = 0;
    int prepend_mod_auth       = 0;
    int prepend_mod_vhostdb    = 0;

    for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
        buffer *m = &((data_string *)srv->srvconf.modules->data[i])->value;

        if (buffer_eq_slen(m, CONST_STR_LEN("mod_indexfile")))
            prepend_mod_indexfile = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_staticfile")))
            append_mod_staticfile = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_dirlisting")))
            append_mod_dirlisting = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_gnutls")))
            append_mod_openssl = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_mbedtls")))
            append_mod_openssl = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_nss")))
            append_mod_openssl = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_openssl")))
            append_mod_openssl = 0;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_wolfssl")))
            append_mod_openssl = 0;
        else if (0 == strncmp(m->ptr, "mod_auth", sizeof("mod_auth")-1)) {
            if (buffer_eq_slen(m, CONST_STR_LEN("mod_auth")))
                contains_mod_auth = 1;
            else if (!contains_mod_auth)
                prepend_mod_auth = 1;

            if (buffer_eq_slen(m, CONST_STR_LEN("mod_authn_file")))
                append_mod_authn_file = 0;
            else if (buffer_eq_slen(m, CONST_STR_LEN("mod_authn_ldap")))
                append_mod_authn_ldap = 0;
            else if (buffer_eq_slen(m, CONST_STR_LEN("mod_authn_mysql")))
                append_mod_authn_mysql = 0;
        }
        else if (0 == strncmp(m->ptr, "mod_vhostdb", sizeof("mod_vhostdb")-1)) {
            if (buffer_eq_slen(m, CONST_STR_LEN("mod_vhostdb")))
                prepend_mod_vhostdb |= 2;
            else if (!(prepend_mod_vhostdb & 2))
                prepend_mod_vhostdb |= 1;
        }
        else if (   0 == strncmp(m->ptr, "mod_ajp13",
                                         sizeof("mod_ajp13")-1)
                 || 0 == strncmp(m->ptr, "mod_cgi",
                                         sizeof("mod_cgi")-1)
                 || 0 == strncmp(m->ptr, "mod_fastcgi",
                                         sizeof("mod_fastcgi")-1)
                 || 0 == strncmp(m->ptr, "mod_proxy",
                                         sizeof("mod_proxy")-1)
                 || 0 == strncmp(m->ptr, "mod_scgi",
                                         sizeof("mod_scgi")-1)
                 || 0 == strncmp(m->ptr, "mod_sockproxy",
                                         sizeof("mod_sockproxy")-1)
                 || 0 == strncmp(m->ptr, "mod_wstunnel",
                                         sizeof("mod_wstunnel")-1)) {
            if (!contains_mod_auth) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "Warning: mod_auth should be listed in server.modules before "
                  "dynamic backends such as %s", m->ptr);
            }
        }
    }

    /* prepend default modules */

    if (prepend_mod_indexfile) {
        /* mod_indexfile has to be loaded before mod_fastcgi and friends */
        config_compat_module_prepend(srv, CONST_STR_LEN("mod_indexfile"));
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

    /* mod_auth.c,mod_auth_api.c auth backends were split into separate modules
     * Automatically load auth backend modules for compatibility with
     * existing lighttpd 1.4.x configs */
    if (contains_mod_auth) {
        if (append_mod_authn_file) {
            const char *v;
            if (  (v=config_has_opt_and_value(srv,CONST_STR_LEN("auth.backend"),
                                                  CONST_STR_LEN("htdigest")))
                ||(v=config_has_opt_and_value(srv,CONST_STR_LEN("auth.backend"),
                                                  CONST_STR_LEN("htpasswd")))
                ||(v=config_has_opt_and_value(srv,CONST_STR_LEN("auth.backend"),
                                                  CONST_STR_LEN("plain"))))
                config_warn_authn_module(srv, CONST_STR_LEN("file"), v);
        }
        if (append_mod_authn_ldap) {
          #if defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER)
            if (config_has_opt_and_value(srv, CONST_STR_LEN("auth.backend"),
                                              CONST_STR_LEN("ldap")))
                config_warn_authn_module(srv, CONST_STR_LEN("ldap"), "ldap");
          #endif
        }
        if (append_mod_authn_mysql) {
          #if defined(HAVE_MYSQL)
            if (config_has_opt_and_value(srv, CONST_STR_LEN("auth.backend"),
                                              CONST_STR_LEN("mysql")))
                config_warn_authn_module(srv, CONST_STR_LEN("mysql"), "mysql");
          #endif
        }
    }

    if (prepend_mod_auth) {
        config_compat_module_prepend(srv, CONST_STR_LEN("mod_auth"));
    }

    if (prepend_mod_vhostdb & 1) {
        config_compat_module_prepend(srv, CONST_STR_LEN("mod_vhostdb"));
    }
}

static void config_deprecate_module_compress (server *srv) {
    int mod_compress_idx = -1;
    int mod_deflate_idx = -1;
    for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
        buffer *m = &((data_string *)srv->srvconf.modules->data[i])->value;
        if (buffer_eq_slen(m, CONST_STR_LEN("mod_compress")))
            mod_compress_idx = (int)i;
        else if (buffer_eq_slen(m, CONST_STR_LEN("mod_deflate")))
            mod_deflate_idx = (int)i;
    }
    if (mod_compress_idx < 0) return;

    int has_compress_directive = 0;
    for (uint32_t i = 0; i < srv->config_context->used; ++i) {
        const data_config *config =
          (data_config const *)srv->config_context->data[i];
        for (uint32_t j = 0; j < config->value->used; ++j) {
            buffer *k = &config->value->data[j]->key;
            if (0 == strncmp(k->ptr, "compress.", sizeof("compress.")-1)) {
                has_compress_directive = 1;
                break;
            }
        }
        if (has_compress_directive) {
            log_error(srv->errh, __FILE__, __LINE__,
              "Warning: \"mod_compress\" is DEPRECATED and has been replaced "
              "with \"mod_deflate\".  A future release of lighttpd 1.4.x will "
              "not contain mod_compress and lighttpd may fail to start up");
            break;
        }
    }

    if (mod_deflate_idx >= 0 || !has_compress_directive) {
        /* create new modules value list without mod_compress */
        array *a = array_init(srv->srvconf.modules->used-1);
        for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
            buffer *m = &((data_string *)srv->srvconf.modules->data[i])->value;
            if (buffer_eq_slen(m, CONST_STR_LEN("mod_compress")))
                continue;
            array_insert_value(a, BUF_PTR_LEN(m));
        }
        array_free(srv->srvconf.modules);
        srv->srvconf.modules = a;
    }
    else {
        /* replace "mod_compress" value with "mod_deflate" value */
        buffer *m = &((data_string *)srv->srvconf.modules->data[mod_compress_idx])->value;
        buffer_copy_string_len(m, CONST_STR_LEN("mod_deflate"));
    }
}

static int config_http_parseopts (server *srv, const array *a) {
    unsigned short int opts = srv->srvconf.http_url_normalize;
    unsigned short int decode_2f = 1;
    int rc = 1;
    for (size_t i = 0; i < a->used; ++i) {
        const data_string * const ds = (const data_string *)a->data[i];
        const buffer *k = &ds->key;
        unsigned short int opt;
        int val = config_plugin_value_tobool((data_unset *)ds, 2);
        if (2 == val) {
            log_error(srv->errh, __FILE__, __LINE__,
              "unrecognized value for server.http-parseopts: "
              "%s => %s (expect \"[enable|disable]\")", k->ptr, ds->value.ptr);
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
     ,{ CONST_STR_LEN("server.errorlog-placeholder-moved-to-config-insert"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ CONST_STR_LEN("server.breakagelog-placeholder-moved-to-config-insert"),
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
     ,{ CONST_STR_LEN("server.feature-flags"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_SERVER }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    srv->srvconf.h2proto = 2; /* enable HTTP/2 and h2c by default */

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
                if (!buffer_is_blank(cpv->v.b))
                    srv->srvconf.bindhost = cpv->v.b;
                break;
              case 5: /* server.network-backend */
                if (!buffer_is_blank(cpv->v.b))
                    srv->srvconf.network_backend = cpv->v.b;
                break;
              case 6: /* server.chroot */
                if (!buffer_is_blank(cpv->v.b))
                    srv->srvconf.changeroot = cpv->v.b;
                break;
              case 7: /* server.username */
                if (!buffer_is_blank(cpv->v.b))
                    srv->srvconf.username = cpv->v.b;
                break;
              case 8: /* server.groupname */
                if (!buffer_is_blank(cpv->v.b))
                    srv->srvconf.groupname = cpv->v.b;
                break;
              case 9: /* server.errorlog */    /* moved to config_insert() */
                /*srv->srvconf.errorlog_file = cpv->v.b;*/
                break;
              case 10:/* server.breakagelog */ /* moved to config_insert() */
                /*srv->srvconf.breakagelog_file = cpv->v.b;*/
                break;
              case 11:/* server.errorlog-use-syslog */
                srv->srvconf.errorlog_use_syslog = (unsigned short)cpv->v.u;
                break;
              case 12:/* server.syslog-facility */
                if (!buffer_is_blank(cpv->v.b))
                    srv->srvconf.syslog_facility = cpv->v.b;
                break;
              case 13:/* server.core-files */
                srv->srvconf.enable_cores = (unsigned short)cpv->v.u;
                break;
              case 14:/* server.event-handler */
                srv->srvconf.event_handler = cpv->v.b->ptr;
                break;
              case 15:/* server.pid-file */
                if (!buffer_is_blank(cpv->v.b))
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
                if (0 != stat_cache_choose_engine(cpv->v.b, srv->errh))
                    rc = HANDLER_ERROR;
                break;
              case 29:/* mimetype.xattr-name */
                stat_cache_xattrname(cpv->v.b->ptr);
                break;
              case 30:/* ssl.engine */
                ssl_enabled = (0 != cpv->v.u);
               #if !defined(USE_OPENSSL_CRYPTO) \
                && !defined(USE_MBEDTLS_CRYPTO) \
                && !defined(USE_NSS_CRYPTO) \
                && !defined(USE_GNUTLS_CRYPTO) \
                && !defined(USE_WOLFSSL_CRYPTO)
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
              case 32:/* server.feature-flags */
                srv->srvconf.feature_flags = cpv->v.a;
                srv->srvconf.h2proto =
                  config_plugin_value_tobool(
                    array_get_element_klen(cpv->v.a,
                                           CONST_STR_LEN("server.h2proto")), 1);
                if (srv->srvconf.h2proto)
                    srv->srvconf.h2proto +=
                      config_plugin_value_tobool(
                        array_get_element_klen(cpv->v.a,
                                               CONST_STR_LEN("server.h2c")), 1);
                srv->srvconf.absolute_dir_redirect =
                  config_plugin_value_tobool(
                    array_get_element_klen(cpv->v.a,
                      CONST_STR_LEN("server.absolute-dir-redirect")), 0);
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    if (0 == srv->srvconf.port)
        srv->srvconf.port = ssl_enabled ? 443 : 80;

    config_check_module_duplicates(srv);

    if (srv->srvconf.compat_module_load)
        config_compat_module_load(srv);

    config_deprecate_module_compress(srv);

    if (srv->srvconf.http_url_normalize)
        config_burl_normalize_cond(srv);

    if (!config_pcre_keyvalue(srv))
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
     ,{ CONST_STR_LEN("debug.log-state-handling"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.errorlog"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("server.breakagelog"),
        T_CONFIG_STRING,
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
                break;
              case 1: /* server.name */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 2: /* server.tag */
                if (!buffer_is_blank(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    for (char *t=strchr(b->ptr,'\n'); t; t=strchr(t+2,'\n')) {
                        /* not expecting admin to define multi-line server.tag,
                         * but ensure server_tag has proper header continuation,
                         * if needed */
                        if (t[1] == ' ' || t[1] == '\t') continue;
                        off_t off = t - b->ptr;
                        size_t len = buffer_clen(b);
                        buffer_string_prepare_append(b, 1);
                        t = b->ptr+off;
                        memmove(t+2, t+1, len - off - 1);
                        t[1] = ' ';
                        buffer_commit(b, 1);
                    }
                    char *t = b->ptr; /*(make empty if tag is whitespace-only)*/
                    while (*t==' ' || *t=='\t' || *t=='\r' || *t=='\n') ++t;
                    if (*t == '\0') buffer_truncate(b, 0);
                }
                else if (0 != i)
                    cpv->v.b = NULL;
                break;
              case 3: /* server.max-request-size */
              case 4: /* server.max-keep-alive-requests */
              case 5: /* server.max-keep-alive-idle */
              case 6: /* server.max-read-idle */
              case 7: /* server.max-write-idle */
                break;
              case 8: /* server.errorfile-prefix */
              case 9: /* server.error-handler */
              case 10:/* server.error-handler-404 */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 11:/* server.error-intercept */
              case 12:/* server.force-lowercase-filenames */
                break;
              case 13:/* server.follow-symlink */
               #ifndef HAVE_LSTAT
                if (0 == cpv->v.u)
                    log_error(srv->errh, __FILE__, __LINE__,
                      "Your system lacks lstat(). "
                      "We can not differ symlinks from files. "
                      "Please remove server.follow-symlinks from your config.");
               #endif
                break;
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
              case 31:/* debug.log-state-handling */
              case 32:/* server.errorlog *//*must match config_log_error_open*/
              case 33:/* server.breakagelog */ /* match config_log_error_open*/
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

    /*(global, but store in r->conf.http_parseopts)*/
    p->defaults.http_parseopts =
        (srv->srvconf.http_header_strict   ?  HTTP_PARSEOPT_HEADER_STRICT   :0)
      | (srv->srvconf.http_host_strict     ? (HTTP_PARSEOPT_HOST_STRICT
                                             |HTTP_PARSEOPT_HOST_NORMALIZE) :0)
      | (srv->srvconf.http_host_normalize  ?  HTTP_PARSEOPT_HOST_NORMALIZE  :0)
      | (srv->srvconf.http_method_get_body ?  HTTP_PARSEOPT_METHOD_GET_BODY :0);
    p->defaults.http_parseopts |= srv->srvconf.http_url_normalize;
    p->defaults.mimetypes = &srv->srvconf.empty_array; /*(must not be NULL)*/
    p->defaults.h2proto = srv->srvconf.h2proto;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            config_merge_config(&p->defaults, cpv);
    }

    /* (after processing config defaults) */
    p->defaults.max_request_field_size = srv->srvconf.max_request_field_size;
    p->defaults.log_request_header_on_error =
      srv->srvconf.log_request_header_on_error;
    if (p->defaults.log_request_handling || p->defaults.log_request_header)
        p->defaults.log_request_header_on_error = 1;

    request_config_set_defaults(&p->defaults);

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
    if (!p->defaults.server_tag)
        p->defaults.server_tag = default_server_tag;
    else if (buffer_is_blank(p->defaults.server_tag))
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
                                        BUF_PTR_LEN(k)))
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

  #ifdef HAVE_PCRE2_H
    for (uint32_t i = 1; i < srv->config_context->used; ++i) {
        data_config * const dc =
          (data_config *)srv->config_context->data[i];
        if ((dc->cond == CONFIG_COND_MATCH || dc->cond == CONFIG_COND_NOMATCH)
            && 0 == dc->capture_idx) {
            if (__builtin_expect( (NULL == srv->match_data), 0)) {
              #if 0
                /* calculate max output vector size to save a few bytes;
                 * currently using hard-coded ovec_max = 10 below
                 * (increase in code size is probably more than bytes saved) */
                uint32_t ovec_max = 0;
                for (uint32_t j = i; j < srv->config_context->used; ++j) {
                    const data_config * const dc =
                      (data_config *)srv->config_context->data[j];
                    if ((dc->cond == CONFIG_COND_MATCH
                         || dc->cond == CONFIG_COND_NOMATCH)
                        && 0 == dc->capture_idx) {
                        uint32_t v;
                        if (0==pcre2_pattern_info(dc->code,
                                                  PCRE2_INFO_CAPTURECOUNT,&v)) {
                            if (ovec_max < v)
                                ovec_max = v;
                        }
                    }
                }
              #else
                uint32_t ovec_max = 10;
              #endif
                srv->match_data = pcre2_match_data_create(ovec_max, NULL);
                force_assert(srv->match_data);
            }
            dc->match_data = srv->match_data;
        }
    }
  #endif

    return 1;
}


/* Save some bytes using buffer_append_string() in cold funcs to print config
 * (instead of buffer_append_string_len() w/ CONST_STR_LEN() on constant strs)*/

static void config_print_by_type(const data_unset *du, buffer *b, int depth);

static void config_print_indent(buffer *b, int depth) {
    depth <<= 2;
    memset(buffer_extend(b, depth), ' ', depth);
}

__attribute_pure__
static uint32_t config_print_array_max_klen(const array * const a) {
    uint32_t maxlen = 0;
    for (uint32_t i = 0; i < a->used; ++i) {
        uint32_t len = buffer_clen(&a->data[i]->key);
        if (maxlen < len)
            maxlen = len;
    }
    return maxlen;
}

static void config_print_array(const array * const a, buffer * const b, int depth) {
    if (a->used <= 5 && (!a->used || buffer_is_unset(&a->data[0]->key))) {
        int oneline = 1;
        for (uint32_t i = 0; i < a->used; ++i) {
            data_unset *du = a->data[i];
            if (du->type != TYPE_STRING && du->type != TYPE_INTEGER) {
                oneline = 0;
                break;
            }
        }
        if (oneline) {
            buffer_append_string(b, "(");
            for (uint32_t i = 0; i < a->used; ++i) {
                if (i != 0)
                    buffer_append_string(b, ", ");
                config_print_by_type(a->data[i], b, depth + 1);
            }
            buffer_append_string(b, ")");
            return;
        }
    }

    const uint32_t maxlen = config_print_array_max_klen(a);
    buffer_append_string(b, "(\n");
    for (uint32_t i = 0; i < a->used; ++i) {
        config_print_indent(b, depth + 1);
        data_unset *du = a->data[i];
        if (!buffer_is_unset(&du->key)) {
            buffer_append_str3(b, CONST_STR_LEN("\""),
                                  BUF_PTR_LEN(&du->key),
                                  CONST_STR_LEN("\""));
            int indent = (int)(maxlen - buffer_clen(&du->key));
            if (indent > 0)
                memset(buffer_extend(b, indent), ' ', indent);
            buffer_append_string(b, " => ");
        }
        config_print_by_type(du, b, depth + 1);
        buffer_append_string(b, ",\n");
    }
    config_print_indent(b, depth);
    buffer_append_string(b, ")");
}

static void config_print_config(const data_unset *d, buffer * const b, int depth) {
    data_config *dc = (data_config *)d;
    array *a = (array *)dc->value;

    if (0 == dc->context_ndx) {
        buffer_append_string(b, "config {\n");
    }
    else {
        if (dc->cond != CONFIG_COND_ELSE) {
            buffer_append_string(b, dc->comp_key);
            buffer_append_string(b, " ");
        }
        buffer_append_string(b, "{\n");
        config_print_indent(b, depth + 1);
        buffer_append_string(b, "# block ");
        buffer_append_int(b, dc->context_ndx);
        buffer_append_string(b, "\n");
    }
    ++depth;

    const uint32_t maxlen = config_print_array_max_klen(a);
    for (uint32_t i = 0; i < a->used; ++i) {
        config_print_indent(b, depth);
        data_unset *du = a->data[i];
        buffer_append_string_buffer(b, &du->key);
        int indent = (int)(maxlen - buffer_clen(&du->key));
        if (indent > 0)
            memset(buffer_extend(b, indent), ' ', indent);
        buffer_append_string(b, " = ");
        config_print_by_type(du, b, depth);
        buffer_append_string(b, "\n");
    }

    buffer_append_string(b, "\n");
    for (uint32_t i = 0; i < dc->children.used; ++i) {
        data_config *dcc = dc->children.data[i];

        /* only the 1st block of chaining */
        if (NULL == dcc->prev) {
            buffer_append_string(b, "\n");
            config_print_indent(b, depth);
            config_print_by_type((data_unset *) dcc, b, depth);
            buffer_append_string(b, "\n");
        }
    }

    --depth;
    config_print_indent(b, depth);
    buffer_append_string(b, "}");
    if (0 != dc->context_ndx) {
        buffer_append_string(b, " # end of ");
        buffer_append_string(b, (dc->cond != CONFIG_COND_ELSE)
                                ? dc->comp_key
                                : "else");
    }

    if (dc->next) {
        buffer_append_string(b, "\n");
        config_print_indent(b, depth);
        buffer_append_string(b, "else ");
        config_print_by_type((data_unset *)dc->next, b, depth);
    }
}

static void config_print_string(const data_unset *du, buffer * const b) {
    /* print out the string as is, except prepend '"' with backslash */
    const buffer * const vb = &((data_string *)du)->value;
    char *dst = buffer_string_prepare_append(b, buffer_clen(vb)*2);
    uint32_t n = 0;
    dst[n++] = '"';
    if (vb->ptr) {
        for (const char *p = vb->ptr; *p; ++p) {
            if (*p == '"')
                dst[n++] = '\\';
            dst[n++] = *p;
        }
    }
    dst[n++] = '"';
    buffer_commit(b, n);
}

__attribute_cold__
static void config_print_by_type(const data_unset * const du, buffer * const b, int depth) {
    switch (du->type) {
      case TYPE_STRING:
        config_print_string(du, b);
        break;
      case TYPE_INTEGER:
        buffer_append_int(b, ((data_integer *)du)->value);
        break;
      case TYPE_ARRAY:
        config_print_array(&((data_array *)du)->value, b, depth);
        break;
      case TYPE_CONFIG:
        config_print_config(du, b, depth);
        break;
      default:
        /*if (du->fn->print) du->fn->print(du, b, depth);*/
        break;
    }
}

void config_print(server *srv) {
    buffer_clear(srv->tmp_buf);
    data_unset *dc = srv->config_context->data[0];
    config_print_by_type(dc, srv->tmp_buf, 0);
}

void config_free(server *srv) {
    /*request_config_set_defaults(NULL);*//*(not necessary)*/
    config_free_config(srv->config_data_base);

    array_free(srv->config_context);
    array_free(srv->srvconf.config_touched);
    array_free(srv->srvconf.modules);
    buffer_free(srv->srvconf.modules_dir);
    array_free(srv->srvconf.upload_tempdirs);
  #ifdef HAVE_PCRE2_H
    if (NULL == srv->match_data) pcre2_match_data_free(srv->match_data);
  #endif
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

/**
 * open the errorlog
 *
 * we have 4 possibilities:
 * - stderr (default)
 * - syslog
 * - logfile
 * - pipe
 *
 */

static void config_log_error_open_syslog(server *srv, log_error_st *errh, const buffer *syslog_facility) {
  #ifdef HAVE_SYSLOG_H
    /*assert(errh->mode == FDLOG_FD);*/
    /*assert(errh->fd == STDERR_FILENO);*/
    errh->mode = FDLOG_SYSLOG;
    errh->fd = -1;
    /* perhaps someone wants to use syslog() */
    int facility = -1;
    if (syslog_facility) {
        static const struct facility_name_st {
          const char *name;
          int val;
        } facility_names[] = {
            { "auth",     LOG_AUTH }
          #ifdef LOG_AUTHPRIV
           ,{ "authpriv", LOG_AUTHPRIV }
          #endif
          #ifdef LOG_CRON
           ,{ "cron",     LOG_CRON }
          #endif
           ,{ "daemon",   LOG_DAEMON }
          #ifdef LOG_FTP
           ,{ "ftp",      LOG_FTP }
          #endif
          #ifdef LOG_KERN
           ,{ "kern",     LOG_KERN }
          #endif
          #ifdef LOG_LPR
           ,{ "lpr",      LOG_LPR }
          #endif
          #ifdef LOG_MAIL
           ,{ "mail",     LOG_MAIL }
          #endif
          #ifdef LOG_NEWS
           ,{ "news",     LOG_NEWS }
          #endif
           ,{ "security", LOG_AUTH }           /* DEPRECATED */
          #ifdef LOG_SYSLOG
           ,{ "syslog",   LOG_SYSLOG }
          #endif
          #ifdef LOG_USER
           ,{ "user",     LOG_USER }
          #endif
          #ifdef LOG_UUCP
           ,{ "uucp",     LOG_UUCP }
          #endif
           ,{ "local0",   LOG_LOCAL0 }
           ,{ "local1",   LOG_LOCAL1 }
           ,{ "local2",   LOG_LOCAL2 }
           ,{ "local3",   LOG_LOCAL3 }
           ,{ "local4",   LOG_LOCAL4 }
           ,{ "local5",   LOG_LOCAL5 }
           ,{ "local6",   LOG_LOCAL6 }
           ,{ "local7",   LOG_LOCAL7 }
        };
        for (unsigned int i = 0; i < sizeof(facility_names)/sizeof(facility_names[0]); ++i) {
            const struct facility_name_st *f = facility_names+i;
            if (0 == strcmp(syslog_facility->ptr, f->name)) {
                facility = f->val;
                break;
            }
        }
        if (-1 == facility) {
            log_error(srv->errh, __FILE__, __LINE__,
              "unrecognized server.syslog-facility: \"%s\"; "
              "defaulting to \"daemon\" facility",
              syslog_facility->ptr);
        }
    }
    openlog("lighttpd", LOG_CONS|LOG_PID, -1==facility ? LOG_DAEMON : facility);
  #endif
}

int config_log_error_open(server *srv) {
    /* logs are opened after preflight check (srv->srvconf.preflight_check)
     * and after dropping privileges instead of being opened during config
     * processing */
  #ifdef __clang_analyzer__
    force_assert(srv->errh);
  #endif

    config_data_base * const p = srv->config_data_base;
    log_error_st *serrh = NULL;

    /* future: might be slightly faster to have allocated array of open files
     * rather than walking config, but only might matter with many directives */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            const char *fn = NULL;
            log_error_st *errh = NULL;
            switch (cpv->k_id) {
              /* NB: these indexes are repeated below switch() block
               *     and all must stay in sync with configfile.c */
              case 32:/* server.errorlog */
                if (0 == i) {
                    if (srv->srvconf.errorlog_use_syslog) continue;
                    errh = srv->errh;
                }
                __attribute_fallthrough__
              case 33:/* server.breakagelog */
                if (!buffer_is_blank(cpv->v.b)) fn = cpv->v.b->ptr;
                break;
              default:
                break;
            }

            if (NULL == fn) continue;

            fdlog_st * const fdlog = fdlog_open(fn);
            if (NULL == fdlog) {
                log_perror(srv->errh, __FILE__, __LINE__,
                  "opening errorlog '%s' failed", fn);
                return -1;
            }

            if (errh) {
                /*(logfiles are opened early in setup; this function is called
                 * prior to set_defaults hook, and modules should not save a
                 * pointer to srv->errh until set_defaults hook or later)*/
                p->defaults.errh = srv->errh = fdlog;
                log_set_global_errh(srv->errh, 0);
            }
            cpv->v.v = errh = fdlog;
            cpv->vtype = T_CONFIG_LOCAL;

            if (0 == i && errh != srv->errh) /*(top-level server.breakagelog)*/
                serrh = errh;
        }
    }

    if (config_feature_bool(srv, "server.errorlog-high-precision", 0))
        log_set_global_errh(srv->errh, 1);

    if (srv->srvconf.errorlog_use_syslog) /*(restricted to global scope)*/
        config_log_error_open_syslog(srv, srv->errh,
                                     srv->srvconf.syslog_facility);
    else if (srv->errh->mode == FDLOG_FD && !srv->srvconf.dont_daemonize)
        srv->errh->fd = -1;
        /* We can only log to stderr in dont-daemonize mode;
         * if we do daemonize and no errorlog file is specified,
         * we log into /dev/null
         */

    /* Note: serrh should not be stored in p->defaults.serrh
     * If left as NULL, scripts (e.g. mod_cgi and mod_ssi exec) will inherit
     * the current STDERR_FILENO, which already is the top-level breakagelog. */
    /*p->defaults.serrh = serrh;*/

    int errfd;
    if (NULL != serrh) {
        if (srv->errh->mode == FDLOG_FD) {
            srv->errh->fd = dup(STDERR_FILENO);
            fdevent_setfd_cloexec(srv->errh->fd);
        }

        errfd = serrh->fd;
        if (*serrh->fn == '|') fdlog_pipe_serrh(errfd); /* breakagelog */
    }
    else if (!srv->srvconf.dont_daemonize) {
        /* move STDERR_FILENO to /dev/null */
        if (-1 == (errfd = fdevent_open_devnull())) {
            log_perror(srv->errh,__FILE__,__LINE__,"opening /dev/null failed");
            return -1;
        }
    }
    else {
        /*(leave STDERR_FILENO as-is)*/
        errfd = -1;
    }

    if (0 != fdevent_set_stdin_stdout_stderr(-1, -1, errfd)) {
        log_perror(srv->errh, __FILE__, __LINE__, "setting stderr failed");
      #ifdef FD_CLOEXEC
        if (-1 != errfd && NULL == serrh) close(errfd);
      #endif
        return -1;
    }
  #ifdef FD_CLOEXEC
    if (-1 != errfd && NULL == serrh) close(errfd);
  #endif

    if (NULL != serrh) {
        close(errfd); /* serrh->fd */
        serrh->fd = STDERR_FILENO;
    }

    return 0;
}

void config_log_error_close(server *srv) {
    config_data_base * const p = srv->config_data_base;
    if (NULL == p) return;

    /*(reset serrh just in case; should not be used after this func returns)*/
    p->defaults.serrh = NULL;

    fdlog_closeall(srv->errh); /*(close all except srv->errh)*/

    if (srv->errh->mode == FDLOG_SYSLOG) {
        srv->errh->mode = FDLOG_FD;
        srv->errh->fd = STDERR_FILENO;
      #ifdef HAVE_SYSLOG_H
        closelog();
      #endif
    }
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
				} else if (0 == i
				           && ((uint8_t *)t->input)[t->offset+0] == 0xc2
				           && ((uint8_t *)t->input)[t->offset+1] == 0xa0) {
					/* treat U+00A0	(c2 a0) "NO-BREAK SPACE" as whitespace */
					/* http://www.fileformat.info/info/unicode/char/a0/index.htm */
					t->offset+=2;
					t->line_pos+=2;
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

__attribute_cold__
static int config_parse_stdin(server *srv, config_t *context) {
    buffer * const b = chunk_buffer_acquire();
    size_t dlen;
    ssize_t n = -1;
    do {
        if (n > 0)
            buffer_commit(b, n);
        size_t avail = buffer_string_space(b);
        dlen = buffer_clen(b);
        if (__builtin_expect( (avail < 1024), 0)) {
            /*(arbitrary limit: 32 MB file; expect < 1 MB)*/
            if (dlen >= 32*1024*1024) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "config read from stdin is way too large");
                break;
            }
            avail = chunk_buffer_prepare_append(b, b->size+avail);
        }
        n = read(STDIN_FILENO, b->ptr+dlen, avail);
    } while (n > 0 || (n == -1 && errno == EINTR));
    int rc = -1;
    if (0 == n)
        rc = dlen ? config_parse(srv, context, "-", b->ptr, dlen) : 0;
    else
        log_perror(srv->errh, __FILE__, __LINE__, "config read from stdin");

    if (dlen)
        ck_memzero(b->ptr, dlen);
    chunk_buffer_release(b);
    return rc;
}

static int config_parse_file_stream(server *srv, config_t *context, const char *fn) {
    off_t dlen = 32*1024*1024;/*(arbitrary limit: 32 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, NULL, malloc, free);
    if (NULL == data) {
        log_perror(srv->errh, __FILE__, __LINE__,
          "opening configfile %s failed", fn);
        return -1;
    }

    int rc = 0;
    if (dlen) {
        rc = config_parse(srv, context, fn, data, (size_t)dlen);
        ck_memzero(data, (size_t)dlen);
    }
    free(data);
    return rc;
}

int config_parse_file(server *srv, config_t *context, const char *fn) {
	buffer * const filename = buffer_init();
	const size_t fnlen = strlen(fn);
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
		buffer_copy_string_len(filename, fn, fnlen);
	} else {
		buffer_copy_path_len2(filename, BUF_PTR_LEN(context->basedir),
		                                fn, fnlen);
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

	if (!buffer_is_blank(context->basedir)) {
		if (0 != chdir(context->basedir->ptr)) {
			log_perror(srv->errh, __FILE__, __LINE__,
			  "cannot change directory to %s", context->basedir->ptr);
			return -1;
		}
	}

	if (fdevent_pipe_cloexec(fds, 65536)) {
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

		pid = fdevent_fork_execve(args[0], args, NULL, -1, fds[1], -1, -1);
		if (-1 == pid) {
			log_perror(srv->errh, __FILE__, __LINE__, "fork/exec(%s)", cmd);
			ret = -1;
		}
		else {
			ssize_t rd;
			int wstatus = 0;
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
			if (pid != fdevent_waitpid(pid, &wstatus, 0)) {
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
				ret = config_parse(srv, context, cmd, BUF_PTR_LEN(out));
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

static int config_remoteip_normalize_ipv6(buffer * const b, buffer * const tb) {
    /* $HTTP["remote-ip"] IPv6 accepted with or without '[]' for config compat
     * http_request_host_normalize() expects IPv6 with '[]',
     * and config processing at runtime expects COMP_HTTP_REMOTE_IP
     * compared without '[]', so strip '[]' after normalization */
    buffer_clear(tb);
    if (b->ptr[0] != '[')
        buffer_append_str3(tb,
                           CONST_STR_LEN("["),
                           BUF_PTR_LEN(b),
                           CONST_STR_LEN("]"));
    else
        buffer_append_string_buffer(tb, b);

    int rc = http_request_host_normalize(tb, 0);
    if (0 == rc) {
        /* remove surrounding '[]' */
        size_t blen = buffer_clen(tb);
        if (blen > 1) buffer_copy_string_len(b, tb->ptr+1, blen-2);
    }
    return rc;
}

int config_remoteip_normalize(buffer * const b, buffer * const tb) {
    if (b->ptr[0] == '/') return 1; /*(skip AF_UNIX /path/file)*/

    const char * const slash = strchr(b->ptr, '/'); /* CIDR mask */
    const char * const colon = strchr(b->ptr, ':'); /* IPv6 */
    unsigned long nm_bits = 0;

    if (NULL != slash) {
        char *nptr;
        nm_bits = strtoul(slash + 1, &nptr, 10);
        if (*nptr || 0 == nm_bits || nm_bits > (NULL != colon ? 128 : 32)) {
            /*(also rejects (slash+1 == nptr) which results in nm_bits = 0)*/
            return -1;
        }
        buffer_truncate(b, (size_t)(slash - b->ptr));
    }

    int family = colon ? AF_INET6 : AF_INET;
    int rc = (family == AF_INET)
        ? http_request_host_normalize(b, 0)
        : config_remoteip_normalize_ipv6(b, tb);

    uint32_t len = buffer_clen(b); /*(save len before adding CIDR mask)*/
    if (nm_bits) {
        buffer_append_string_len(b, CONST_STR_LEN("/"));
        buffer_append_int(b, (int)nm_bits);
    }

    if (0 != rc) {
        return -1;
    }

    /* extend b to hold structured data after end of string:
     * nm_bits and memory-aligned sock_addr for AF_INET or AF_INET6 (28 bytes)*/
    char *after = buffer_string_prepare_append(b, 1 + 7 + 28);
    ++after; /*(increment to pos after string end '\0')*/
    *(unsigned char *)after = (unsigned char)nm_bits;
    sock_addr * const addr = (sock_addr *)(((uintptr_t)after+1+7) & ~7);
    if (nm_bits) b->ptr[len] = '\0'; /*(sock_addr_inet_pton() w/o CIDR mask)*/
    rc = sock_addr_inet_pton(addr, b->ptr, family, 0);
    if (nm_bits) b->ptr[len] = '/';
    return (1 == rc);
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

__attribute_noinline__
static void config_vars_init (array *a) {
    char dcwd[PATH_MAX];
    if (NULL != getcwd(dcwd, sizeof(dcwd)))
        array_set_key_value(a, CONST_STR_LEN("var.CWD"), dcwd, strlen(dcwd));

    *array_get_int_ptr(a, CONST_STR_LEN("var.PID")) = getpid();
}

int config_read(server *srv, const char *fn) {
	config_t context;
	data_config *dc;
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
	config_vars_init(dc->value); /* default context */

	force_assert(context.all_configs->used == 0);
	dc->context_ndx = context.all_configs->used;
	array_insert_unique(context.all_configs, (data_unset *)dc);
	context.current = dc;

	ret = (0 != strcmp(fn, "-")) /*(incompatible with one-shot mode)*/
	  ? config_parse_file_stream(srv, &context, fn)
	  : config_parse_stdin(srv, &context);

	/* remains nothing if parser is ok */
	force_assert(!(0 == ret && context.ok && 0 != context.configs_stack.used));
	context_free(&context);

	if (0 != ret) {
		return ret;
	}

	/* reorder dc->context_ndx to match srv->config_context->data[] index.
	 * srv->config_context->data[] may have been re-ordered in configparser.y.
	 * Since the dc->context_ndx (id) is reused by config_insert*() and by
	 * plugins to index into srv->config_context->data[], reorder into the
	 * order encountered during config file parsing for least surprise to
	 * end-users writing config files.  Note: this manipulation *breaks* the
	 * srv->config_context->sorted[] structure, so searching the array by key
	 * is no longer valid. */
	for (uint32_t i = 0; i < srv->config_context->used; ++i) {
		dc = (data_config *)srv->config_context->data[i];
		if (dc->context_ndx == (int)i) continue;
		for (uint32_t j = i; j < srv->config_context->used; ++j) {
			dc = (data_config *)srv->config_context->data[j];
			if (dc->context_ndx == (int)i) {
				srv->config_context->data[j] = srv->config_context->data[i];
				srv->config_context->data[i] = (data_unset *)dc;
				break;
			}
		}
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
	request_config *s = &((config_data_base *)srv->config_data_base)->defaults;
	struct stat st1, st2;

	if (fdevent_config(&srv->srvconf.event_handler, srv->errh) <= 0)
		return -1;

	if (srv->srvconf.changeroot) {
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
		buffer * const tb = srv->tmp_buf;
		buffer_clear(tb);
		if (srv->srvconf.changeroot) {
			buffer_copy_buffer(tb, srv->srvconf.changeroot);
		}
		const size_t len = buffer_clen(tb);

		for (i = 0; i < srv->srvconf.upload_tempdirs->used; ++i) {
			const data_string * const ds = (data_string *)srv->srvconf.upload_tempdirs->data[i];
			if (len) {
				buffer_truncate(tb, len);
				buffer_append_path_len(tb, BUF_PTR_LEN(&ds->value));
			} else {
				buffer_copy_buffer(tb, &ds->value);
			}
			if (-1 == stat(tb->ptr, &st1)) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "server.upload-dirs doesn't exist: %s", tb->ptr);
			} else if (!S_ISDIR(st1.st_mode)) {
				log_error(srv->errh, __FILE__, __LINE__,
				  "server.upload-dirs isn't a directory: %s", tb->ptr);
			}
		}
	}

	chunkqueue_set_tempdirs_default(
		srv->srvconf.upload_tempdirs,
		srv->srvconf.upload_temp_file_size);

	if (!s->document_root || buffer_is_blank(s->document_root)) {
		log_error(srv->errh, __FILE__, __LINE__, "server.document-root is not set");
		return -1;
	}

	if (2 == s->force_lowercase_filenames) { /* user didn't configure it in global section? */
		s->force_lowercase_filenames = 0; /* default to 0 */

		buffer * const tb = srv->tmp_buf;
		buffer_copy_string_len_lc(tb, BUF_PTR_LEN(s->document_root));

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
