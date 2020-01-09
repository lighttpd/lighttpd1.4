#include "first.h"

#include "base.h"
#include "plugin.h"
#include "http_vhostdb.h"
#include "log.h"
#include "stat_cache.h"

#include <stdlib.h>
#include <string.h>

/**
 * vhostdb framework
 */

typedef struct {
    const http_vhostdb_backend_t *vhostdb_backend;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;

    buffer tmp_buf;
} plugin_data;

INIT_FUNC(mod_vhostdb_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_vhostdb_free) {
    plugin_data *p = p_d;
    free(p->tmp_buf.ptr);
}

static void mod_vhostdb_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* vhostdb.backend */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->vhostdb_backend = cpv->v.v;
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

static void mod_vhostdb_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_vhostdb_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_vhostdb_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("vhostdb.backend"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_vhostdb"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* vhostdb.backend */
                if (!buffer_string_is_empty(cpv->v.b)) {
                    const buffer * const b = cpv->v.b;
                    *(const void **)&cpv->v.v = http_vhostdb_backend_get(b);
                    if (NULL == cpv->v.v) {
                        log_error(srv->errh, __FILE__, __LINE__,
                          "vhostdb.backend not supported: %s", b->ptr);
                        return HANDLER_ERROR;
                    }
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
    con->request.server_name = con->request.server_name_buf;
    buffer_copy_buffer(con->request.server_name_buf, ve->server_name);
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

    mod_vhostdb_patch_config(con, p);
    if (!p->conf.vhostdb_backend) return HANDLER_GO_ON;

    b = &p->tmp_buf;
    backend = p->conf.vhostdb_backend;
    if (0 != backend->query(con, backend->p_d, b)) {
        return mod_vhostdb_error_500(con); /* HANDLER_FINISHED */
    }

    if (buffer_string_is_empty(b)) {
        /* no such virtual host */
        return HANDLER_GO_ON;
    }

    /* sanity check that really is a directory */
    buffer_append_slash(b);
    sce = stat_cache_get_entry(b);
    if (NULL == sce) {
        log_perror(con->conf.errh, __FILE__, __LINE__, "%s", b->ptr);
        return mod_vhostdb_error_500(con); /* HANDLER_FINISHED */
    }
    if (!S_ISDIR(sce->st.st_mode)) {
        log_error(con->conf.errh, __FILE__, __LINE__,
          "Not a directory: %s", b->ptr);
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
    p->name             = "vhostdb";
    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_free;
    p->set_defaults     = mod_vhostdb_set_defaults;
    p->handle_docroot   = mod_vhostdb_handle_docroot;
    p->connection_reset = mod_vhostdb_handle_connection_close;

    return 0;
}
