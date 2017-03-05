#include "first.h"

#include <libpq-fe.h>

#include <string.h>
#include <stdlib.h>

#include "base.h"
#include "http_vhostdb.h"
#include "log.h"
#include "plugin.h"

/*
 * virtual host plugin using Postgres for domain to directory lookups
 */

typedef struct {
    PGconn *dbconn;
    buffer *sqlquery;
} vhostdb_config;

typedef struct {
    void *vdata;
    array *options;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

static void mod_vhostdb_dbconf_free (void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    if (!dbconf) return;
    PQfinish(dbconf->dbconn);
    free(dbconf);
}

static int mod_vhostdb_dbconf_setup (server *srv, array *opts, void **vdata)
{
    buffer *sqlquery = NULL;
    const char *dbname=NULL, *user=NULL, *pass=NULL, *host=NULL, *port=NULL;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING) {
            if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("sql"))) {
                sqlquery = ds->value;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("dbname"))) {
                dbname = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("user"))) {
                user = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("password"))) {
                pass = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("host"))) {
                host = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("port"))) {
                port = ds->value->ptr;
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

    if (!buffer_string_is_empty(sqlquery) && NULL != dbname) {
        vhostdb_config *dbconf;
        PGconn *dbconn = PQsetdbLogin(host,port,NULL,NULL,dbname,user,pass);
        if (NULL == dbconn) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "PGsetdbLogin() failed, exiting...");
            return -1;
        }

        if (CONNECTION_OK != PQstatus(dbconn)) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "Failed to login to database, exiting...");
            PQfinish(dbconn);
            return -1;
        }

        /* Postgres sets FD_CLOEXEC on database socket descriptors */

        dbconf = (vhostdb_config *)calloc(1, sizeof(*dbconf));
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        *vdata = dbconf;
    }

    return 0;
}

static void mod_vhostdb_patch_connection (server *srv, connection *con, plugin_data *p);

static int mod_vhostdb_pgsql_query(server *srv, connection *con, void *p_d, buffer *docroot)
{
    plugin_data *p = (plugin_data *)p_d;
    vhostdb_config *dbconf;
    PGresult *res;
    int cols, rows;

    /*(reuse buffer for sql query before generating docroot result)*/
    buffer *sqlquery = docroot;
    buffer_string_set_length(sqlquery, 0); /*(also resets docroot (alias))*/

    mod_vhostdb_patch_connection(srv, con, p);
    if (NULL == p->conf.vdata) return 0; /*(after resetting docroot)*/
    dbconf = (vhostdb_config *)p->conf.vdata;

    for (char *b = dbconf->sqlquery->ptr, *d; *b; b = d+1) {
        if (NULL != (d = strchr(b, '?'))) {
            /* escape the uri.authority */
            size_t len;
            int err;
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            buffer_string_prepare_append(sqlquery, buffer_string_length(con->uri.authority) * 2);
            len = PQescapeStringConn(dbconf->dbconn,
                    sqlquery->ptr + buffer_string_length(sqlquery),
                    CONST_BUF_LEN(con->uri.authority), &err);
            buffer_commit(sqlquery, len);
            if (0 != err) return -1;
        } else {
            d = dbconf->sqlquery->ptr + buffer_string_length(dbconf->sqlquery);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            break;
        }
    }

    res = PQexec(dbconf->dbconn, sqlquery->ptr);

    buffer_string_set_length(docroot, 0); /*(reset buffer to store result)*/

    if (PGRES_TUPLES_OK != PQresultStatus(res)) {
        log_error_write(srv, __FILE__, __LINE__, "s",
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
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_pgsql */
    http_vhostdb_backend_pgsql.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_pgsql);

    return p;
}

FREE_FUNC(mod_vhostdb_cleanup) {
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];
            if (!s) continue;
            mod_vhostdb_dbconf_free(s->vdata);
            array_free(s->options);
            free(s);
        }
        free(p->config_storage);
    }
    free(p);

    UNUSED(srv);
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_vhostdb_set_defaults) {
    plugin_data *p = p_d;

    config_values_t cv[] = {
        { "vhostdb.pgsql",  NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },
        { NULL,             NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

    for (size_t i = 0; i < srv->config_context->used; ++i) {
        data_config const *config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));

        s->options = array_init();
        cv[0].destination = s->options;

        p->config_storage[i] = s;

        if (config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

	if (!array_is_kvstring(s->options)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"unexpected value for vhostdb.pgsql; expected list of \"option\" => \"value\"");
		return HANDLER_ERROR;
	}

        if (s->options->used
            && 0 != mod_vhostdb_dbconf_setup(srv, s->options, &s->vdata)) {
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static void mod_vhostdb_patch_connection (server *srv, connection *con, plugin_data *p)
{
    plugin_config *s = p->config_storage[0];
    PATCH(vdata);

    /* skip the first, the global context */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key,CONST_STR_LEN("vhostdb.pgsql"))){
                PATCH(vdata);
            }
        }
    }
}
#undef PATCH

/* this function is called at dlopen() time and inits the callbacks */
int mod_vhostdb_pgsql_plugin_init (plugin *p);
int mod_vhostdb_pgsql_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("vhostdb_pgsql");

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
