/*
 * mod_vhostdb_pgsql - virtual hosts mapping from backend PostgreSQL database
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <string.h>
#include <stdlib.h>

#include <libpq-fe.h>

#include "mod_vhostdb_api.h"
#include "base.h"
#include "log.h"
#include "plugin.h"

/*
 * virtual host plugin using PostgreSQL for domain to directory lookups
 */

typedef struct {
    PGconn *dbconn;
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
    PQfinish(dbconf->dbconn);
    free(dbconf);
}

static int mod_vhostdb_dbconf_setup (server *srv, const array *opts, void **vdata)
{
    const buffer *sqlquery = NULL;
    const char *dbname=NULL, *user=NULL, *pass=NULL, *host=NULL, *port=NULL;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING) {
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
                port = ds->value.ptr;
            }
        }
    }

    /* required:
     * - sql    (sql query)
     * - dbname
     * - user   (unless dbname is a pgsql conninfo URI)
     *
     * optional:
     * - password, default: empty
     * - hostname
     * - port, default: 5432
     */

    if (NULL != sqlquery && !buffer_is_blank(sqlquery) && NULL != dbname) {
        vhostdb_config *dbconf;
        PGconn *dbconn = PQsetdbLogin(host,port,NULL,NULL,dbname,user,pass);
        if (NULL == dbconn) {
            log_error(srv->errh, __FILE__, __LINE__,
              "PGsetdbLogin() failed, exiting...");
            return -1;
        }

        if (CONNECTION_OK != PQstatus(dbconn)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "Failed to login to database, exiting...");
            PQfinish(dbconn);
            return -1;
        }

        /* Postgres sets FD_CLOEXEC on database socket descriptors */

        dbconf = (vhostdb_config *)ck_calloc(1, sizeof(*dbconf));
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        *vdata = dbconf;
    }

    return 0;
}

static void mod_vhostdb_patch_config(request_st * const r, const plugin_data * const p, plugin_config * const pconf);

static int mod_vhostdb_pgsql_query(request_st * const r, void *p_d, buffer *docroot)
{
    vhostdb_config *dbconf;
    PGresult *res;
    int cols, rows;

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
            size_t len;
            int err;
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            buffer_string_prepare_append(sqlquery,
                                         buffer_clen(&r->uri.authority) * 2);
            len = PQescapeStringConn(dbconf->dbconn,
                    sqlquery->ptr + buffer_clen(sqlquery),
                    BUF_PTR_LEN(&r->uri.authority), &err);
            buffer_commit(sqlquery, len);
            if (0 != err) return -1;
        } else {
            d = dbconf->sqlquery->ptr + buffer_clen(dbconf->sqlquery);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            break;
        }
    }

    res = PQexec(dbconf->dbconn, sqlquery->ptr);

    buffer_clear(docroot); /*(reset buffer to store result)*/

    if (PGRES_TUPLES_OK != PQresultStatus(res)) {
        log_error(r->conf.errh, __FILE__, __LINE__, "%s",
          PQerrorMessage(dbconf->dbconn));
        PQclear(res);
        return -1;
    }

    cols = PQnfields(res);
    rows = PQntuples(res);
    if (rows == 1 && cols >= 1) {
        buffer_copy_string(docroot, PQgetvalue(res, 0, 0));
    } /* else no such virtual host */

    PQclear(res);
    return 0;
}




INIT_FUNC(mod_vhostdb_init) {
    static http_vhostdb_backend_t http_vhostdb_backend_pgsql =
      { "pgsql", mod_vhostdb_pgsql_query, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_pgsql */
    http_vhostdb_backend_pgsql.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_pgsql);

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
      { CONST_STR_LEN("vhostdb.pgsql"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_vhostdb_pgsql"))
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
int mod_vhostdb_pgsql_plugin_init (plugin *p);
int mod_vhostdb_pgsql_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = "vhostdb_pgsql";

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
