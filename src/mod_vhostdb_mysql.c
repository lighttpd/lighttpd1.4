#include "first.h"

#include <mysql.h>

#include <string.h>
#include <stdlib.h>

#include "base.h"
#include "http_vhostdb.h"
#include "fdevent.h"
#include "log.h"
#include "plugin.h"

/*
 * virtual host plugin using MySQL for domain to directory lookups
 */

typedef struct {
    MYSQL *dbconn;
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
    mysql_close(dbconf->dbconn);
    free(dbconf);
}

static int mod_vhostdb_dbconf_setup (server *srv, array *opts, void **vdata)
{
    buffer *sqlquery = NULL;
    const char *dbname=NULL, *user=NULL, *pass=NULL, *host=NULL, *sock=NULL;
    unsigned int port = 0;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING && !buffer_string_is_empty(ds->value)) {
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
                port = strtoul(ds->value->ptr, NULL, 10);
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("sock"))) {
                sock = ds->value->ptr;
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

    if (!buffer_string_is_empty(sqlquery)
        && dbname && *dbname && user && *user) {
        vhostdb_config *dbconf;
        MYSQL *dbconn = mysql_init(NULL);
        if (NULL == dbconn) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "mysql_init() failed, exiting...");
            return -1;
        }

      #if MYSQL_VERSION_ID >= 50013
        /* in mysql versions above 5.0.3 the reconnect flag is off by default */
        {
            my_bool reconnect = 1;
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
            log_error_write(srv, __FILE__, __LINE__, "s",
                            mysql_error(dbconn));
            mysql_close(dbconn);
            return -1;
        }

        fdevent_setfd_cloexec(dbconn->net.fd);

        dbconf = (vhostdb_config *)calloc(1, sizeof(*dbconf));
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        *vdata = dbconf;
    }

    return 0;
}

static void mod_vhostdb_patch_connection (server *srv, connection *con, plugin_data *p);

static int mod_vhostdb_mysql_query(server *srv, connection *con, void *p_d, buffer *docroot)
{
    plugin_data *p = (plugin_data *)p_d;
    vhostdb_config *dbconf;
    unsigned  cols;
    MYSQL_ROW row;
    MYSQL_RES *result;

    /*(reuse buffer for sql query before generating docroot result)*/
    buffer *sqlquery = docroot;
    buffer_string_set_length(sqlquery, 0); /*(also resets docroot (alias))*/

    mod_vhostdb_patch_connection(srv, con, p);
    if (NULL == p->conf.vdata) return 0; /*(after resetting docroot)*/
    dbconf = (vhostdb_config *)p->conf.vdata;

    for (char *b = dbconf->sqlquery->ptr, *d; *b; b = d+1) {
        if (NULL != (d = strchr(b, '?'))) {
            /* escape the uri.authority */
            unsigned long len;
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            buffer_string_prepare_append(sqlquery, buffer_string_length(con->uri.authority) * 2);
            len = mysql_real_escape_string(dbconf->dbconn,
                    sqlquery->ptr + buffer_string_length(sqlquery),
                    CONST_BUF_LEN(con->uri.authority));
            if ((unsigned long)~0 == len) return -1;
            buffer_commit(sqlquery, len);
        } else {
            d = dbconf->sqlquery->ptr + buffer_string_length(dbconf->sqlquery);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            break;
        }
    }

    if (mysql_real_query(dbconf->dbconn, CONST_BUF_LEN(sqlquery))) {
        log_error_write(srv, __FILE__, __LINE__, "s",
                        mysql_error(dbconf->dbconn));
        buffer_string_set_length(docroot, 0); /*(reset buffer; no result)*/
        return -1;
    }

    buffer_string_set_length(docroot, 0); /*(reset buffer to store result)*/

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
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_mysql */
    http_vhostdb_backend_mysql.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_mysql);

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
        { "vhostdb.mysql",  NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },
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
				"unexpected value for vhostdb.mysql; expected list of \"option\" => \"value\"");
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

            if (buffer_is_equal_string(du->key,CONST_STR_LEN("vhostdb.mysql"))){
                PATCH(vdata);
            }
        }
    }
}
#undef PATCH

/* this function is called at dlopen() time and inits the callbacks */
int mod_vhostdb_mysql_plugin_init (plugin *p);
int mod_vhostdb_mysql_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("vhostdb_mysql");

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
