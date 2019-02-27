#include "first.h"

#include <dbi/dbi.h>

#include <string.h>
#include <stdlib.h>

#include "base.h"
#include "http_vhostdb.h"
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
 *                   "sqlite_dbdir" => "/path/to/sqlite/dbs/" )
 */

typedef struct {
    dbi_conn dbconn;
    dbi_inst dbinst;
    buffer *sqlquery;
    server *srv;
    short reconnect_count;
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

/* used to reconnect to the database when we get disconnected */
static void mod_vhostdb_dbi_error_callback (dbi_conn dbconn, void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    const char *errormsg = NULL;
    /*assert(dbconf->dbconn == dbconn);*/

    while (++dbconf->reconnect_count <= 3) { /* retry */
        if (0 == dbi_conn_connect(dbconn)) {
            fdevent_setfd_cloexec(dbi_conn_get_socket(dbconn));
            return;
        }
    }

    dbi_conn_error(dbconn, &errormsg);
    log_error_write(dbconf->srv, __FILE__, __LINE__, "ss",
                    "dbi_conn_connect():", errormsg);
}

static void mod_vhostdb_dbconf_free (void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    if (!dbconf) return;
    dbi_conn_close(dbconf->dbconn);
    dbi_shutdown_r(dbconf->dbinst);
    free(dbconf);
}

static int mod_vhostdb_dbconf_setup (server *srv, array *opts, void **vdata)
{
    buffer *sqlquery = NULL;
    const buffer *dbtype=NULL, *dbname=NULL;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING) {
            if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("sql"))) {
                sqlquery = ds->value;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("dbname"))) {
                dbname = ds->value;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("dbtype"))) {
                dbtype = ds->value;
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

    if (!buffer_string_is_empty(sqlquery)
        && !buffer_is_empty(dbname) && !buffer_is_empty(dbtype)) {
        /* create/initialise database */
        vhostdb_config *dbconf;
        dbi_inst dbinst = NULL;
        dbi_conn dbconn;
        if (dbi_initialize_r(NULL, &dbinst) < 1) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "dbi_initialize_r() failed.  "
                            "Do you have the DBD for this db type installed?");
            return -1;
        }
        dbconn = dbi_conn_new_r(dbtype->ptr, dbinst);
        if (NULL == dbconn) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "dbi_conn_new_r() failed.  "
                            "Do you have the DBD for this db type installed?");
            dbi_shutdown_r(dbinst);
            return -1;
        }

        /* set options */
        for (size_t j = 0; j < opts->used; ++j) {
            data_unset *du = opts->data[j];
            const buffer *opt = du->key;
            if (!buffer_string_is_empty(opt)) {
                if (du->type == TYPE_INTEGER) {
                    data_integer *di = (data_integer *)du;
                    dbi_conn_set_option_numeric(dbconn, opt->ptr, di->value);
                } else if (du->type == TYPE_STRING) {
                    data_string *ds = (data_string *)du;
                    if (ds->value != sqlquery && ds->value != dbtype) {
                        dbi_conn_set_option(dbconn, opt->ptr, ds->value->ptr);
                    }
                }
            }
        }

        dbconf = (vhostdb_config *)calloc(1, sizeof(*dbconf));
        dbconf->dbinst = dbinst;
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        dbconf->srv = srv;
        dbconf->reconnect_count = 0;
        *vdata = dbconf;

        /* used to automatically reconnect to the database */
        dbi_conn_error_handler(dbconn, mod_vhostdb_dbi_error_callback, dbconf);

        /* connect to database */
        mod_vhostdb_dbi_error_callback(dbconn, dbconf);
        if (dbconf->reconnect_count >= 3) return -1;
    }

    return 0;
}

static void mod_vhostdb_patch_connection (server *srv, connection *con, plugin_data *p);

static int mod_vhostdb_dbi_query(server *srv, connection *con, void *p_d, buffer *docroot)
{
    plugin_data *p = (plugin_data *)p_d;
    vhostdb_config *dbconf;
    dbi_result result;
    unsigned long long nrows;
    int retry_count = 0;

    /*(reuse buffer for sql query before generating docroot result)*/
    buffer *sqlquery = docroot;
    buffer_clear(sqlquery); /*(also resets docroot (alias))*/

    mod_vhostdb_patch_connection(srv, con, p);
    if (NULL == p->conf.vdata) return 0; /*(after resetting docroot)*/
    dbconf = (vhostdb_config *)p->conf.vdata;

    for (char *b = dbconf->sqlquery->ptr, *d; *b; b = d+1) {
        if (NULL != (d = strchr(b, '?'))) {
            /* escape the uri.authority */
            char *esc = NULL;
            size_t len = dbi_conn_escape_string_copy(dbconf->dbconn, con->uri.authority->ptr, &esc);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            buffer_append_string_len(sqlquery, esc, len);
            free(esc);
            if (0 == len) return -1;
        } else {
            d = dbconf->sqlquery->ptr + buffer_string_length(dbconf->sqlquery);
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
        log_error_write(srv, __FILE__, __LINE__, "s", errmsg);
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
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_dbi */
    http_vhostdb_backend_dbi.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_dbi);

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
        { "vhostdb.dbi",    NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },
        { NULL,             NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));

    for (size_t i = 0; i < srv->config_context->used; ++i) {
        data_config const *config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));

        s->options = array_init();
        cv[0].destination = s->options;

        p->config_storage[i] = s;

        if (config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

	if (!array_is_kvany(s->options)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"unexpected value for vhostdb.dbi; expected list of \"option\" => \"value\"");
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

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("vhostdb.dbi"))) {
                PATCH(vdata);
            }
        }
    }
}
#undef PATCH

/* this function is called at dlopen() time and inits the callbacks */
int mod_vhostdb_dbi_plugin_init (plugin *p);
int mod_vhostdb_dbi_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("vhostdb_dbi");

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
