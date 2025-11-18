/*
 * mod_vhostdb_mysql - virtual hosts mapping from backend MySQL/MariaDB database
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <string.h>
#include <stdlib.h>

#include <mysql.h>

#include "mod_vhostdb_api.h"
#include "base.h"
#include "fdevent.h"
#include "log.h"
#include "plugin.h"

/*
 * virtual host plugin using MySQL/MariaDB for domain to directory lookups
 */

typedef struct {
    MYSQL *dbconn;
    const buffer *sqlquery;
} vhostdb_config;

typedef struct {
    void *vdata;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

static void mod_vhostdb_dbconf_free (void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    if (!dbconf) return;
    mysql_close(dbconf->dbconn);
    free(dbconf);
}

static int mod_vhostdb_dbconf_setup (server *srv, const array *opts, void **vdata)
{
    const buffer *sqlquery = NULL;
    const char *dbname=NULL, *user=NULL, *pass=NULL, *host=NULL, *sock=NULL;
    unsigned int port = 0;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING && !buffer_is_blank(&ds->value)) {
            if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("sql"))) {
                sqlquery = &ds->value;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("dbname"))) {
                dbname = ds->value.ptr;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("user"))) {
                user = ds->value.ptr;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("password"))) {
                pass = ds->value.ptr;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("host"))) {
                host = ds->value.ptr;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("port"))) {
                port = strtoul(ds->value.ptr, NULL, 10);
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("sock"))) {
                sock = ds->value.ptr;
            }
        }
    }

    /* required:
     * - sql    (sql query)
     * - dbname
     * - user
     *
     * optional:
     * - password, default: empty
     * - socket, default: mysql default
     * - hostname, if set overrides socket
     * - port, default: 3306
     */

    if (NULL != sqlquery && !buffer_is_blank(sqlquery)
        && dbname && *dbname && user && *user) {
        vhostdb_config *dbconf;
        MYSQL *dbconn = mysql_init(NULL);
        if (NULL == dbconn) {
            log_error(srv->errh, __FILE__, __LINE__,
              "mysql_init() failed, exiting...");
            return -1;
        }

      #if MYSQL_VERSION_ID >= 50013
        /* in mysql versions above 5.0.3 the reconnect flag is off by default */
        {
            char reconnect = 1;
            mysql_options(dbconn, MYSQL_OPT_RECONNECT, &reconnect);
        }
      #endif

        /* CLIENT_MULTI_STATEMENTS first appeared in 4.1 */
      #if MYSQL_VERSION_ID < 40100
        #ifndef CLIENT_MULTI_STATEMENTS
        #define CLIENT_MULTI_STATEMENTS 0
        #endif
      #endif
        if (!mysql_real_connect(dbconn, host, user, pass, dbname, port, sock,
                                CLIENT_MULTI_STATEMENTS)) {
            log_error(srv->errh, __FILE__, __LINE__, "%s", mysql_error(dbconn));
            mysql_close(dbconn);
            return -1;
        }

      #ifdef LIBMARIADB
        my_socket sfd = mysql_get_socket(dbconn);
      #else
        my_socket sfd = dbconn->net.fd;
      #endif
        (void)fdevent_socket_set_cloexec(sfd);

        dbconf = (vhostdb_config *)ck_calloc(1, sizeof(*dbconf));
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        *vdata = dbconf;
    }

    return 0;
}

static void mod_vhostdb_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf);

static int mod_vhostdb_mysql_query(request_st * const r, void *p_d, buffer *docroot)
{
    vhostdb_config *dbconf;
    unsigned  cols;
    MYSQL_ROW row;
    MYSQL_RES *result;

    /*(reuse buffer for sql query before generating docroot result)*/
    buffer *sqlquery = docroot;
    buffer_clear(sqlquery); /*(also resets docroot (alias))*/

    plugin_config pconf;
    mod_vhostdb_patch_config(r, p_d, &pconf);
    if (NULL == pconf.vdata) return 0; /*(after resetting docroot)*/
    dbconf = (vhostdb_config *)pconf.vdata;

    for (char *b = dbconf->sqlquery->ptr, *d; *b; b = d+1) {
        if (NULL != (d = strchr(b, '?'))) {
            /* escape the uri.authority */
            unsigned long len;
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            buffer_string_prepare_append(sqlquery,
                                         buffer_clen(&r->uri.authority) * 2);
            len = mysql_real_escape_string(dbconf->dbconn,
                    sqlquery->ptr + buffer_clen(sqlquery),
                    BUF_PTR_LEN(&r->uri.authority));
            if ((unsigned long)~0 == len) return -1;
            buffer_commit(sqlquery, len);
        } else {
            d = dbconf->sqlquery->ptr + buffer_clen(dbconf->sqlquery);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            break;
        }
    }

    if (mysql_real_query(dbconf->dbconn, BUF_PTR_LEN(sqlquery))) {
        log_error(r->conf.errh, __FILE__, __LINE__, "%s",
          mysql_error(dbconf->dbconn));
        buffer_clear(docroot); /*(reset buffer; no result)*/
        return -1;
    }

    buffer_clear(docroot); /*(reset buffer to store result)*/

    result = mysql_store_result(dbconf->dbconn);
    cols = mysql_num_fields(result);
    row = mysql_fetch_row(result);
    if (row && cols >= 1) {
        buffer_copy_string(docroot, row[0]);
    } /* else no such virtual host */

    mysql_free_result(result);
  #if MYSQL_VERSION_ID >= 40100
    while (0 == mysql_next_result(dbconf->dbconn)) ;
  #endif
    return 0;
}




INIT_FUNC(mod_vhostdb_init) {
    static http_vhostdb_backend_t http_vhostdb_backend_mysql =
      { "mysql", mod_vhostdb_mysql_query, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_mysql */
    http_vhostdb_backend_mysql.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_mysql);

    return p;
}

FREE_FUNC(mod_vhostdb_cleanup) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0: /* vhostdb.<db> */
                mod_vhostdb_dbconf_free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static void mod_vhostdb_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* vhostdb.<db> */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->vdata = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_vhostdb_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_vhostdb_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_vhostdb_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_vhostdb_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_vhostdb_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("vhostdb.mysql"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_vhostdb_mysql"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* vhostdb.<db> */
                if (cpv->v.a->used) {
                    if (0 != mod_vhostdb_dbconf_setup(srv, cpv->v.a, &cpv->v.v))
                        return HANDLER_ERROR;
                    if (NULL != cpv->v.v)
                        cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_vhostdb_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_vhostdb_mysql_plugin_init (plugin *p);
int mod_vhostdb_mysql_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = "vhostdb_mysql";

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
