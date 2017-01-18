#include "first.h"

#include "plugin.h"
#include "http_vhostdb.h"
#include "log.h"
#include "stat_cache.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * vhostdb framework
 */

typedef struct {
    buffer *vhostdb_backend_conf;

    /* generated */
    const http_vhostdb_backend_t *vhostdb_backend;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;

    buffer *tmp_buf;
} plugin_data;

INIT_FUNC(mod_vhostdb_init) {
    plugin_data *p = calloc(1, sizeof(*p));
    p->tmp_buf = buffer_init();
    return p;
}

FREE_FUNC(mod_vhostdb_free) {
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        size_t i;
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];
            if (NULL == s) continue;
            buffer_free(s->vhostdb_backend_conf);
            free(s);
        }
        free(p->config_storage);
    }

    free(p->tmp_buf);
    free(p);

    UNUSED(srv);
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_vhostdb_set_defaults) {
    plugin_data *p = p_d;
    config_values_t cv[] = {
        { "vhostdb.backend",                NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */

        { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));

    for (size_t i = 0; i < srv->config_context->used; ++i) {
        data_config const *config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));
        s->vhostdb_backend_conf = buffer_init();

        cv[0].destination = s->vhostdb_backend_conf;

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (!buffer_string_is_empty(s->vhostdb_backend_conf)) {
            s->vhostdb_backend =
              http_vhostdb_backend_get(s->vhostdb_backend_conf);
            if (NULL == s->vhostdb_backend) {
                log_error_write(srv, __FILE__, __LINE__, "sb",
                                "vhostdb.backend not supported:",
                                s->vhostdb_backend_conf);
                return HANDLER_ERROR;
            }
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_vhostdb_patch_connection(server *srv, connection *con, plugin_data *p) {
    plugin_config *s = p->config_storage[0];
    PATCH(vhostdb_backend);

    /* skip the first, the global context */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("vhostdb.backend"))) {
                PATCH(vhostdb_backend);
            }
        }
    }

    return 0;
}
#undef PATCH

typedef struct {
    buffer *server_name;
    buffer *document_root;
} vhostdb_entry;

static vhostdb_entry * vhostdb_entry_init (void)
{
    vhostdb_entry *ve = calloc(1, sizeof(*ve));
    ve->server_name = buffer_init();
    ve->document_root = buffer_init();
    return ve;
}

static void vhostdb_entry_free (vhostdb_entry *ve)
{
    buffer_free(ve->server_name);
    buffer_free(ve->document_root);
    free(ve);
}

CONNECTION_FUNC(mod_vhostdb_handle_connection_close) {
    plugin_data *p = p_d;
    vhostdb_entry *ve;

    if ((ve = con->plugin_ctx[p->id])) {
        con->plugin_ctx[p->id] = NULL;
        vhostdb_entry_free(ve);
    }

    UNUSED(srv);
    return HANDLER_GO_ON;
}

static handler_t mod_vhostdb_error_500 (connection *con)
{
    con->http_status = 500; /* Internal Server Error */
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

static handler_t mod_vhostdb_found (connection *con, vhostdb_entry *ve)
{
    /* fix virtual server and docroot */
    buffer_copy_buffer(con->server_name, ve->server_name);
    buffer_copy_buffer(con->physical.doc_root, ve->document_root);
    return HANDLER_GO_ON;
}

CONNECTION_FUNC(mod_vhostdb_handle_docroot) {
    plugin_data *p = p_d;
    vhostdb_entry *ve;
    const http_vhostdb_backend_t *backend;
    buffer *b;
    stat_cache_entry *sce;

    /* no host specified? */
    if (buffer_string_is_empty(con->uri.authority)) return HANDLER_GO_ON;

    /* XXX: future: implement larger, managed cache
     * of database responses (positive and negative) */

    /* check if cached this connection */
    ve = con->plugin_ctx[p->id];
    if (ve && buffer_is_equal(ve->server_name, con->uri.authority)) {
        return mod_vhostdb_found(con, ve); /* HANDLER_GO_ON */
    }

    mod_vhostdb_patch_connection(srv, con, p);
    if (!p->conf.vhostdb_backend) return HANDLER_GO_ON;

    b = p->tmp_buf;
    backend = p->conf.vhostdb_backend;
    if (0 != backend->query(srv, con, backend->p_d, b)) {
        return mod_vhostdb_error_500(con); /* HANDLER_FINISHED */
    }

    if (buffer_string_is_empty(b)) {
        /* no such virtual host */
        return HANDLER_GO_ON;
    }

    /* sanity check that really is a directory */
    buffer_append_slash(b);
    if (HANDLER_ERROR == stat_cache_get_entry(srv, con, b, &sce)) {
        log_error_write(srv, __FILE__, __LINE__, "sb", strerror(errno), b);
        return mod_vhostdb_error_500(con); /* HANDLER_FINISHED */
    }
    if (!S_ISDIR(sce->st.st_mode)) {
        log_error_write(srv, __FILE__, __LINE__, "sb", "Not a directory", b);
        return mod_vhostdb_error_500(con); /* HANDLER_FINISHED */
    }

    /* cache the data */
    if (!ve) con->plugin_ctx[p->id] = ve = vhostdb_entry_init();
    buffer_copy_buffer(ve->server_name, con->uri.authority);
    buffer_copy_buffer(ve->document_root, b);

    return mod_vhostdb_found(con, ve); /* HANDLER_GO_ON */
}

int mod_vhostdb_plugin_init(plugin *p);
int mod_vhostdb_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("vhostdb");
    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_free;
    p->set_defaults     = mod_vhostdb_set_defaults;
    p->handle_docroot   = mod_vhostdb_handle_docroot;
    p->connection_reset = mod_vhostdb_handle_connection_close;

    p->data             = NULL;

    return 0;
}
