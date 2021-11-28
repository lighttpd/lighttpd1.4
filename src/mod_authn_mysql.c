/* mod_authn_mysql
 * 
 * KNOWN LIMITATIONS:
 * - no mechanism provided to configure SSL connection to a remote MySQL db
 *
 * FUTURE POTENTIAL PERFORMANCE ENHANCEMENTS:
 * - database response is not cached
 *   TODO: db response caching (for limited time) to reduce load on db
 *     (only cache successful logins to prevent cache bloat?)
 *     (or limit number of entries (size) of cache)
 *     (maybe have negative cache (limited size) of names not found in database)
 * - database query is synchronous and blocks waiting for response
 *   TODO: https://mariadb.com/kb/en/mariadb/using-the-non-blocking-library/
 * - opens and closes connection to MySQL db for each request (inefficient)
 *   (fixed) one-element cache for persistent connection open to last used db
 *   TODO: db connection pool (if asynchronous requests)
 */
#include "first.h"

#if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT)
#ifndef _XOPEN_CRYPT
#define _XOPEN_CRYPT 1
#endif
#include <unistd.h>     /* crypt() */
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <mysql.h>

#include "mod_auth_api.h"
#include "sys-crypto-md.h"

#include "base.h"
#include "ck.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    int auth_mysql_port;
    const char *auth_mysql_host;
    const char *auth_mysql_user;
    const char *auth_mysql_pass;
    const char *auth_mysql_db;
    const char *auth_mysql_socket;
    const char *auth_mysql_users_table;
    const char *auth_mysql_col_user;
    const char *auth_mysql_col_pass;
    const char *auth_mysql_col_realm;
    log_error_st *errh;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    MYSQL *mysql_conn;
    const char *mysql_conn_host;
    const char *mysql_conn_user;
    const char *mysql_conn_pass;
    const char *mysql_conn_db;
    int mysql_conn_port;
} plugin_data;

static void mod_authn_mysql_sock_close(void *p_d) {
    plugin_data * const p = p_d;
    if (NULL != p->mysql_conn) {
        mysql_close(p->mysql_conn);
        p->mysql_conn = NULL;
    }
}

static MYSQL * mod_authn_mysql_sock_connect(plugin_data *p) {
    plugin_config * const pconf = &p->conf;
    if (NULL != p->mysql_conn) {
        /* reuse open db connection if same ptrs to host user pass db port */
        if (   p->mysql_conn_host == pconf->auth_mysql_host
            && p->mysql_conn_user == pconf->auth_mysql_user
            && p->mysql_conn_pass == pconf->auth_mysql_pass
            && p->mysql_conn_db   == pconf->auth_mysql_db
            && p->mysql_conn_port == pconf->auth_mysql_port) {
            return p->mysql_conn;
        }
        mod_authn_mysql_sock_close(p);
    }

    /* !! mysql_init() is not thread safe !! (see MySQL doc) */
    p->mysql_conn = mysql_init(NULL);
    if (mysql_real_connect(p->mysql_conn,
                           pconf->auth_mysql_host,
                           pconf->auth_mysql_user,
                           pconf->auth_mysql_pass,
                           pconf->auth_mysql_db,
                           pconf->auth_mysql_port,
                           (pconf->auth_mysql_socket && *pconf->auth_mysql_socket)
                             ? pconf->auth_mysql_socket
                             : NULL,
                           CLIENT_IGNORE_SIGPIPE)) {
        /* (copy ptrs to plugin data (has lifetime until server shutdown)) */
        p->mysql_conn_host = pconf->auth_mysql_host;
        p->mysql_conn_user = pconf->auth_mysql_user;
        p->mysql_conn_pass = pconf->auth_mysql_pass;
        p->mysql_conn_db   = pconf->auth_mysql_db;
        p->mysql_conn_port = pconf->auth_mysql_port;
        return p->mysql_conn;
    }
    else {
        /*(note: any of these params might be NULL)*/
        log_error(pconf->errh, __FILE__, __LINE__,
          "opening connection to mysql: %s user: %s db: %s failed: %s",
          pconf->auth_mysql_host ? pconf->auth_mysql_host : "",
          pconf->auth_mysql_user ? pconf->auth_mysql_user : "",
          /*"pass:",*//*(omit pass from logs)*/
          /*p->conf.auth_mysql_pass ? p->conf.auth_mysql_pass : "",*/
          pconf->auth_mysql_db ? pconf->auth_mysql_db : "",
          mysql_error(p->mysql_conn));
        mod_authn_mysql_sock_close(p);
        return NULL;
    }
}

static MYSQL * mod_authn_mysql_sock_acquire(plugin_data *p) {
    return mod_authn_mysql_sock_connect(p);
}

static void mod_authn_mysql_sock_release(plugin_data *p) {
    UNUSED(p);
    /*(empty; leave db connection open)*/
    /* Note: mod_authn_mysql_result() calls mod_authn_mysql_sock_error()
     *       on error, so take that into account if making changes here.
     *       Must check if (NULL == p->mysql_conn) */
}

__attribute_cold__
static void mod_authn_mysql_sock_error(plugin_data *p) {
    mod_authn_mysql_sock_close(p);
}

static handler_t mod_authn_mysql_basic(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);
static handler_t mod_authn_mysql_digest(request_st *r, void *p_d, http_auth_info_t *dig);

INIT_FUNC(mod_authn_mysql_init) {
    static http_auth_backend_t http_auth_backend_mysql =
      { "mysql", mod_authn_mysql_basic, mod_authn_mysql_digest, NULL };
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_auth_backend_mysql */
    http_auth_backend_mysql.p_d = p;
    http_auth_backend_set(&http_auth_backend_mysql);

    return p;
}

static void mod_authn_mysql_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.mysql.host */
        pconf->auth_mysql_host = cpv->v.b->ptr;
        break;
      case 1: /* auth.backend.mysql.user */
        pconf->auth_mysql_user = cpv->v.b->ptr;
        break;
      case 2: /* auth.backend.mysql.pass */
        pconf->auth_mysql_pass = cpv->v.b->ptr;
        break;
      case 3: /* auth.backend.mysql.db */
        pconf->auth_mysql_db = cpv->v.b->ptr;
        break;
      case 4: /* auth.backend.mysql.port */
        pconf->auth_mysql_port = (int)cpv->v.shrt;
        break;
      case 5: /* auth.backend.mysql.socket */
        pconf->auth_mysql_socket = cpv->v.b->ptr;
        break;
      case 6: /* auth.backend.mysql.users_table */
        pconf->auth_mysql_users_table = cpv->v.b->ptr;
        break;
      case 7: /* auth.backend.mysql.col_user */
        pconf->auth_mysql_col_user = cpv->v.b->ptr;
        break;
      case 8: /* auth.backend.mysql.col_pass */
        pconf->auth_mysql_col_pass = cpv->v.b->ptr;
        break;
      case 9: /* auth.backend.mysql.col_realm */
        pconf->auth_mysql_col_realm = cpv->v.b->ptr;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_authn_mysql_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_authn_mysql_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_authn_mysql_patch_config(request_st * const r, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_mysql_merge_config(&p->conf,
                                        p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_authn_mysql_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.mysql.host"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.user"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.pass"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.db"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.port"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.socket"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.users_table"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.col_user"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.col_pass"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.mysql.col_realm"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_mysql"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.mysql.host */
              case 1: /* auth.backend.mysql.user */
              case 2: /* auth.backend.mysql.pass */
              case 3: /* auth.backend.mysql.db */
              case 4: /* auth.backend.mysql.port */
              case 5: /* auth.backend.mysql.socket */
              case 6: /* auth.backend.mysql.users_table */
                break;
              case 7: /* auth.backend.mysql.col_user */
              case 8: /* auth.backend.mysql.col_pass */
              case 9: /* auth.backend.mysql.col_realm */
                if (buffer_is_blank(cpv->v.b)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s must not be blank", cpk[cpv->k_id].k);
                    return HANDLER_ERROR;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.auth_mysql_col_user = "user";
    p->defaults.auth_mysql_col_pass = "password";
    p->defaults.auth_mysql_col_realm = "realm";
    p->defaults.errh = srv->errh;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_mysql_merge_config(&p->defaults, cpv);
    }

    log_error(srv->errh, __FILE__, __LINE__,
      "Warning: mod_%s is deprecated "
      "and will be removed from a future lighttpd release in early 2022. "
      "https://wiki.lighttpd.net/Docs_ModAuth#mysql-mod_authn_mysql-since-lighttpd-1442",
      p->self->name);

    return HANDLER_GO_ON;
}

static int mod_authn_mysql_password_cmp(const char *userpw, unsigned long userpwlen, const char *reqpw) {
  #if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT)
    if (userpwlen >= 3 && userpw[0] == '$') {
        char *crypted = crypt(reqpw, userpw);
        size_t crypwlen = (NULL != crypted) ? strlen(crypted) : 0;
        int rc = (crypwlen == userpwlen) ? memcmp(crypted, userpw, crypwlen) : -1;
        if (crypwlen >= 13) ck_memzero(crypted, crypwlen);
        return rc;
    }
    else
  #endif
    if (32 == userpwlen) {
        /* plain md5 */
        unsigned char HA1[MD5_DIGEST_LENGTH];
        unsigned char md5pw[MD5_DIGEST_LENGTH];
        MD5_once(HA1, reqpw, strlen(reqpw));

        /*(compare 16-byte MD5 binary instead of converting to hex strings
         * in order to then have to do case-insensitive hex str comparison)*/
        return (0 == li_hex2bin(md5pw, sizeof(md5pw), userpw, 32))
          ? ck_memeq_const_time_fixed_len(HA1, md5pw, sizeof(md5pw)) ? 0 : 1
          : -1;
    }

    return -1;
}

static int mod_authn_mysql_result(plugin_data *p, http_auth_info_t *ai, const char *pw) {
    MYSQL_RES *result = mysql_store_result(p->mysql_conn);
    int rc = -1;
    my_ulonglong num_rows;

    if (NULL == result) {
        /*(future: might log mysql_error() string)*/
      #if 0
        log_error(errh, __FILE__, __LINE__,
          "mysql_store_result: %s", mysql_error(p->mysql_conn));
      #endif
        mod_authn_mysql_sock_error(p);
        return -1;
    }

    num_rows = mysql_num_rows(result);
    if (1 == num_rows) {
        MYSQL_ROW row = mysql_fetch_row(result);
        unsigned long *lengths = mysql_fetch_lengths(result);
        if (NULL == lengths) {
            /*(error; should not happen)*/
        }
        else if (pw) {  /* used with HTTP Basic auth */
            rc = mod_authn_mysql_password_cmp(row[0], lengths[0], pw);
        }
        else {          /* used with HTTP Digest auth */
            /*(currently supports only single row, single digest algorithm)*/
            if (lengths[0] == (ai->dlen << 1)) {
                rc = li_hex2bin(ai->digest, sizeof(ai->digest),
                                row[0], lengths[0]);
            }
        }
    }
    else if (0 == num_rows) {
        /* user,realm not found */
    }
    else {
        /* (multiple rows returned, which should not happen) */
        /* (future: might log if multiple rows returned; unexpected result) */
    }
    mysql_free_result(result);
    return rc;
}

static handler_t mod_authn_mysql_query(request_st * const r, void *p_d, http_auth_info_t * const ai, const char * const pw) {
    plugin_data *p = (plugin_data *)p_d;
    int rc = -1;

    mod_authn_mysql_patch_config(r, p);
    p->conf.errh = r->conf.errh;

    if (NULL == p->conf.auth_mysql_users_table) {
        /*(auth.backend.mysql.host, auth.backend.mysql.db might be NULL; do not log)*/
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth config missing auth.backend.mysql.users_table for uri: %s",
          r->target.ptr);
        return HANDLER_ERROR;
    }

    do {
        char uname[512], urealm[512];
        unsigned long mrc;

        if (ai->ulen > sizeof(uname)/2-1)
            return HANDLER_ERROR;
        if (ai->rlen > sizeof(urealm)/2-1)
            return HANDLER_ERROR;

        if (!mod_authn_mysql_sock_acquire(p)) {
            return HANDLER_ERROR;
        }

      #if 0
        mrc = mysql_real_escape_string_quote(p->mysql_conn, uname,
                                             ai->username, ai->ulen, '\'');
        if ((unsigned long)~0 == mrc) break;

        mrc = mysql_real_escape_string_quote(p->mysql_conn, urealm,
                                             ai->realm, ai->rlen, '\'');
        if ((unsigned long)~0 == mrc) break;
      #else
        mrc = mysql_real_escape_string(p->mysql_conn, uname,
                                       ai->username, ai->ulen);
        if ((unsigned long)~0 == mrc) break;

        mrc = mysql_real_escape_string(p->mysql_conn, urealm,
                                       ai->realm, ai->rlen);
        if ((unsigned long)~0 == mrc) break;
      #endif

        buffer * const tb = r->tmp_buf;
        buffer_clear(tb);
        struct const_iovec iov[] = {
          { CONST_STR_LEN("SELECT ") }
         ,{ p->conf.auth_mysql_col_pass, strlen(p->conf.auth_mysql_col_pass) }
         ,{ CONST_STR_LEN(" FROM ") }
         ,{ p->conf.auth_mysql_users_table, strlen(p->conf.auth_mysql_users_table) }
         ,{ CONST_STR_LEN(" WHERE ") }
         ,{ p->conf.auth_mysql_col_user, strlen(p->conf.auth_mysql_col_user) }
         ,{ CONST_STR_LEN("='") }
         ,{ uname, strlen(uname) }
         ,{ CONST_STR_LEN("' AND ") }
         ,{ p->conf.auth_mysql_col_realm, strlen(p->conf.auth_mysql_col_realm) }
         ,{ CONST_STR_LEN("='") }
         ,{ urealm, strlen(urealm) }
         ,{ CONST_STR_LEN("'") }
        };
        buffer_append_iovec(tb, iov, sizeof(iov)/sizeof(*iov));
        char * const q = tb->ptr;

        /* for now we stay synchronous */
        if (0 != mysql_query(p->mysql_conn, q)) {
            /* reconnect to db and retry once if query error occurs */
            mod_authn_mysql_sock_error(p);
            if (!mod_authn_mysql_sock_acquire(p)) {
                rc = -1;
                break;
            }
            if (0 != mysql_query(p->mysql_conn, q)) {
                /*(note: any of these params might be bufs w/ b->ptr == NULL)*/
                log_error(r->conf.errh, __FILE__, __LINE__,
                  "mysql_query host: %s user: %s db: %s query: %s failed: %s",
                  p->conf.auth_mysql_host ? p->conf.auth_mysql_host : "",
                  p->conf.auth_mysql_user ? p->conf.auth_mysql_user : "",
                  /*"pass:",*//*(omit pass from logs)*/
                  /*p->conf.auth_mysql_pass ? p->conf.auth_mysql_pass : "",*/
                  p->conf.auth_mysql_db ? p->conf.auth_mysql_db : "",
                  q, mysql_error(p->mysql_conn));
                rc = -1;
                break;
            }
        }

        rc = mod_authn_mysql_result(p, ai, pw);

    } while (0);

    mod_authn_mysql_sock_release(p);

    return (0 == rc) ? HANDLER_GO_ON : HANDLER_ERROR;
}

static handler_t mod_authn_mysql_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    handler_t rc;
    http_auth_info_t ai;
    ai.dalgo    = HTTP_AUTH_DIGEST_NONE;
    ai.dlen     = 0;
    ai.username = username->ptr;
    ai.ulen     = buffer_clen(username);
    ai.realm    = require->realm->ptr;
    ai.rlen     = buffer_clen(require->realm);
    ai.userhash = 0;
    rc = mod_authn_mysql_query(r, p_d, &ai, pw);
    if (HANDLER_GO_ON != rc) return rc;
    return http_auth_match_rules(require, username->ptr, NULL, NULL)
      ? HANDLER_GO_ON  /* access granted */
      : HANDLER_ERROR;
}

static handler_t mod_authn_mysql_digest(request_st * const r, void *p_d, http_auth_info_t * const ai) {
    return mod_authn_mysql_query(r, p_d, ai, NULL);
}

int mod_authn_mysql_plugin_init(plugin *p);
int mod_authn_mysql_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "authn_mysql";
    p->init        = mod_authn_mysql_init;
    p->set_defaults= mod_authn_mysql_set_defaults;
    p->cleanup     = mod_authn_mysql_sock_close;

    return 0;
}
