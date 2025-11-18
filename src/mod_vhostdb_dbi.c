/*
 * mod_vhostdb_dbi - virtual hosts mapping from backend DBI interface
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <string.h>
#include <stdlib.h>

#ifdef __has_include
#if __has_include(<dbi/dbi.h>)
#include <dbi/dbi.h>
#else
#include <dbi.h>
#endif
#else
#include <dbi/dbi.h>
#endif

#include "mod_vhostdb_api.h"
#include "base.h"
#include "fdevent.h"
#include "log.h"
#include "plugin.h"

/*
 * virtual host plugin using DBI for domain to directory lookups
 *
 * e.g.
 *   vhostdb.dbi = ( "sql"    => "SELECT docroot FROM vhosts WHERE host='?'"
 *                   "dbtype" => "sqlite3",
 *                   "dbname" => "mydb.sqlite",
 *                   "sqlite3_dbdir" => "/path/to/sqlite/dbs/" )
 */

typedef struct {
    dbi_conn dbconn;
    dbi_inst dbinst;
    const buffer *sqlquery;
    log_error_st *errh;
    short reconnect_count;
} vhostdb_config;

typedef struct {
    void *vdata;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

/* used to reconnect to the database when we get disconnected */
static void mod_vhostdb_dbi_error_callback (dbi_conn dbconn, void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    const char *errormsg = NULL;
    /*assert(dbconf->dbconn == dbconn);*/

    while (++dbconf->reconnect_count <= 3) { /* retry */
        if (0 == dbi_conn_connect(dbconn)) {
            /* _WIN32: ok if SOCKET (unsigned long long) actually <= INT_MAX */
            (void)fdevent_socket_set_cloexec(dbi_conn_get_socket(dbconn));
            return;
        }
    }

    dbi_conn_error(dbconn, &errormsg);
    log_error(dbconf->errh,__FILE__,__LINE__,"dbi_conn_connect(): %s",errormsg);
}

static void mod_vhostdb_dbconf_free (void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    if (!dbconf) return;
    dbi_conn_close(dbconf->dbconn);
    dbi_shutdown_r(dbconf->dbinst);
    free(dbconf);
}

static int mod_vhostdb_dbconf_setup (server *srv, const array *opts, void **vdata)
{
    const buffer *sqlquery = NULL;
    const buffer *dbtype=NULL, *dbname=NULL;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING) {
            if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("sql"))) {
                sqlquery = &ds->value;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("dbname"))) {
                dbname = &ds->value;
            } else if (buffer_is_equal_caseless_string(&ds->key, CONST_STR_LEN("dbtype"))) {
                dbtype = &ds->value;
            }
        }
    }

    /* required:
     * - sql    (sql query)
     * - dbtype
     * - dbname
     *
     * optional:
     * - username, some databases don't require this (sqlite)
     * - password, default: empty
     * - socket, default: database type default
     * - hostname, if set overrides socket
     * - port, default: database default
     * - encoding, default: database default
     */

    if (sqlquery && !buffer_is_blank(sqlquery) && dbname && dbtype) {
        /* create/initialise database */
        vhostdb_config *dbconf;
        dbi_inst dbinst = NULL;
        dbi_conn dbconn;
        if (dbi_initialize_r(NULL, &dbinst) < 1) {
            log_error(srv->errh, __FILE__, __LINE__,
              "dbi_initialize_r() failed.  "
              "Do you have the DBD for this db type installed?");
            return -1;
        }
        dbconn = dbi_conn_new_r(dbtype->ptr, dbinst);
        if (NULL == dbconn) {
            log_error(srv->errh, __FILE__, __LINE__,
              "dbi_conn_new_r() failed.  "
              "Do you have the DBD for this db type installed?");
            dbi_shutdown_r(dbinst);
            return -1;
        }

        /* set options */
        for (size_t j = 0; j < opts->used; ++j) {
            data_unset *du = opts->data[j];
            const buffer *opt = &du->key;
            if (!buffer_is_blank(opt)) {
                if (du->type == TYPE_INTEGER) {
                    data_integer *di = (data_integer *)du;
                    dbi_conn_set_option_numeric(dbconn, opt->ptr, di->value);
                } else if (du->type == TYPE_STRING) {
                    data_string *ds = (data_string *)du;
                    if (&ds->value != sqlquery && &ds->value != dbtype) {
                        dbi_conn_set_option(dbconn, opt->ptr, ds->value.ptr);
                    }
                }
            }
        }

        dbconf = (vhostdb_config *)ck_calloc(1, sizeof(*dbconf));
        dbconf->dbinst = dbinst;
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        dbconf->errh = srv->errh;
        dbconf->reconnect_count = 0;
        *vdata = dbconf;

        /* used to automatically reconnect to the database */
        dbi_conn_error_handler(dbconn, mod_vhostdb_dbi_error_callback, dbconf);

        /* connect to database */
        mod_vhostdb_dbi_error_callback(dbconn, dbconf);
        if (dbconf->reconnect_count > 3) {
            mod_vhostdb_dbconf_free(dbconf);
            return -1;
        }
    }

    return 0;
}

static void mod_vhostdb_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf);

static int mod_vhostdb_dbi_query(request_st * const r, void *p_d, buffer *docroot)
{
    vhostdb_config *dbconf;
    dbi_result result;
    unsigned long long nrows;
    int retry_count = 0;

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
            char *esc = NULL;
            size_t len = dbi_conn_escape_string_copy(dbconf->dbconn,
                                                     r->uri.authority.ptr,&esc);
            buffer_append_str2(sqlquery, b, (size_t)(d - b), esc, len);
            free(esc);
            if (0 == len) return -1;
        } else {
            d = dbconf->sqlquery->ptr + buffer_clen(dbconf->sqlquery);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            break;
        }
    }

    /* reset our reconnect-attempt counter, this is a new query. */
    dbconf->reconnect_count = 0;

    do {
        result = dbi_conn_query(dbconf->dbconn, sqlquery->ptr);
    } while (!result && ++retry_count < 2);

    buffer_clear(docroot); /*(reset buffer to store result)*/

    if (!result) {
        const char *errmsg;
        dbi_conn_error(dbconf->dbconn, &errmsg);
        log_error(r->conf.errh, __FILE__, __LINE__, "%s", errmsg);
        return -1;
    }

    nrows = dbi_result_get_numrows(result);
    if (nrows && nrows != DBI_ROW_ERROR && dbi_result_next_row(result)) {
        buffer_copy_string(docroot, dbi_result_get_string_idx(result, 1));
    } /* else no such virtual host */

    dbi_result_free(result);
    return 0;
}




INIT_FUNC(mod_vhostdb_init) {
    static http_vhostdb_backend_t http_vhostdb_backend_dbi =
      { "dbi", mod_vhostdb_dbi_query, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_dbi */
    http_vhostdb_backend_dbi.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_dbi);

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
      { CONST_STR_LEN("vhostdb.dbi"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_vhostdb_dbi"))
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
int mod_vhostdb_dbi_plugin_init (plugin *p);
int mod_vhostdb_dbi_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = "vhostdb_dbi";

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
