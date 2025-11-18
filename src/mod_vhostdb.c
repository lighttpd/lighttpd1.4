/*
 * mod_vhostdb - virtual hosts mapping from backend database
 *
 * Copyright(c) 2017 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "mod_vhostdb_api.h"
#include "base.h"
#include "http_status.h"
#include "plugin.h"
#include "plugin_config.h"
#include "log.h"
#include "stat_cache.h"
#include "algo_splaytree.h"

/**
 * vhostdb framework
 */

typedef struct {
    splay_tree *sptree; /* data in nodes of tree are (vhostdb_cache_entry *) */
    time_t max_age;
} vhostdb_cache;

typedef struct {
    const http_vhostdb_backend_t *vhostdb_backend;
    vhostdb_cache *vhostdb_cache;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

typedef struct {
    char *server_name;
    char *document_root;
    uint32_t slen;
    uint32_t dlen;
    unix_time64_t ctime;
} vhostdb_cache_entry;

static vhostdb_cache_entry *
vhostdb_cache_entry_init (const buffer * const server_name, const buffer * const docroot)
{
    const uint32_t slen = buffer_clen(server_name);
    const uint32_t dlen = buffer_clen(docroot);
    vhostdb_cache_entry * const ve =
      ck_malloc(sizeof(vhostdb_cache_entry) + slen + dlen);
    ve->ctime = log_monotonic_secs;
    ve->slen = slen;
    ve->dlen = dlen;
    ve->server_name   = (char *)(ve + 1);
    ve->document_root = ve->server_name + slen;
    memcpy(ve->server_name,   server_name->ptr, slen);
    memcpy(ve->document_root, docroot->ptr,     dlen);
    return ve;
}

static void
vhostdb_cache_entry_free (vhostdb_cache_entry *ve)
{
    free(ve);
}

static void
vhostdb_cache_free (vhostdb_cache *vc)
{
    splay_tree *sptree = vc->sptree;
    while (sptree) {
        vhostdb_cache_entry_free(sptree->data);
        sptree = splaytree_delete_splayed_node(sptree);
    }
    free(vc);
}

static vhostdb_cache *
vhostdb_cache_init (const array *opts)
{
    vhostdb_cache *vc = ck_malloc(sizeof(vhostdb_cache));
    vc->sptree = NULL;
    vc->max_age = 600; /* 10 mins */
    for (uint32_t i = 0, used = opts->used; i < used; ++i) {
        data_unset *du = opts->data[i];
        if (buffer_is_equal_string(&du->key, CONST_STR_LEN("max-age")))
            vc->max_age = (time_t)
              config_plugin_value_to_int32(du, 600); /* 10 min if invalid num */
    }
    return vc;
}

static vhostdb_cache_entry *
mod_vhostdb_cache_query (request_st * const r, plugin_config * const pconf)
{
    const int ndx = splaytree_djbhash(BUF_PTR_LEN(&r->uri.authority));
    splay_tree ** const sptree = &pconf->vhostdb_cache->sptree;
    *sptree = splaytree_splay(*sptree, ndx);
    vhostdb_cache_entry * const ve =
      (*sptree && (*sptree)->key == ndx) ? (*sptree)->data : NULL;

    return ve
        && buffer_is_equal_string(&r->uri.authority, ve->server_name, ve->slen)
      ? ve
      : NULL;
}

static void
mod_vhostdb_cache_insert (request_st * const r, plugin_config * const pconf, vhostdb_cache_entry * const ve)
{
    const int ndx = splaytree_djbhash(BUF_PTR_LEN(&r->uri.authority));
    splay_tree ** const sptree = &pconf->vhostdb_cache->sptree;
    /*(not necessary to re-splay (with current usage) since single-threaded
     * and splaytree has not been modified since mod_vhostdb_cache_query())*/
    /* *sptree = splaytree_splay(*sptree, ndx); */
    if (NULL == *sptree || (*sptree)->key != ndx)
        *sptree = splaytree_insert_splayed(*sptree, ndx, ve);
    else { /* collision; replace old entry */
        vhostdb_cache_entry_free((*sptree)->data);
        (*sptree)->data = ve;
    }
}

INIT_FUNC(mod_vhostdb_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

FREE_FUNC(mod_vhostdb_free) {
    plugin_data *p = p_d;

    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 1: /* vhostdb.cache */
                vhostdb_cache_free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }

    http_vhostdb_dumbdata_reset();
}

static void mod_vhostdb_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* vhostdb.backend */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->vhostdb_backend = cpv->v.v;
        break;
      case 1: /* vhostdb.cache */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->vhostdb_cache = cpv->v.v;
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
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_vhostdb_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_vhostdb_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("vhostdb.backend"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("vhostdb.cache"),
        T_CONFIG_ARRAY,
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
                if (!buffer_is_blank(cpv->v.b)) {
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
              case 1: /* vhostdb.cache */
                cpv->v.v = vhostdb_cache_init(cpv->v.a);
                cpv->vtype = T_CONFIG_LOCAL;
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

REQUEST_FUNC(mod_vhostdb_handle_request_reset) {
    plugin_data *p = p_d;
    vhostdb_cache_entry *ve;

    if ((ve = r->plugin_ctx[p->id])) {
        r->plugin_ctx[p->id] = NULL;
        vhostdb_cache_entry_free(ve);
    }

    return HANDLER_GO_ON;
}

__attribute_cold__
static handler_t mod_vhostdb_error_500 (request_st * const r)
{
    return http_status_set_err(r, 500); /* Internal Server Error */
}

static handler_t mod_vhostdb_found (request_st * const r, vhostdb_cache_entry * const ve)
{
    /* fix virtual server and docroot */
    if (ve->slen) {
        r->server_name = &r->server_name_buf;
        buffer_copy_string_len(&r->server_name_buf, ve->server_name, ve->slen);
    }
    buffer_copy_string_len(&r->physical.doc_root, ve->document_root, ve->dlen);
    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_vhostdb_handle_docroot) {
    const plugin_data * const p = p_d;
    vhostdb_cache_entry *ve;

    /* no host specified? */
    if (buffer_is_blank(&r->uri.authority)) return HANDLER_GO_ON;

    /* check if cached this connection */
    ve = r->plugin_ctx[p->id];
    if (ve
        && buffer_is_equal_string(&r->uri.authority, ve->server_name, ve->slen))
        return mod_vhostdb_found(r, ve); /* HANDLER_GO_ON */

    plugin_config pconf;
    mod_vhostdb_patch_config(r, p, &pconf);
    if (!pconf.vhostdb_backend) return HANDLER_GO_ON;

    if (pconf.vhostdb_cache && (ve = mod_vhostdb_cache_query(r, &pconf)))
        return mod_vhostdb_found(r, ve); /* HANDLER_GO_ON */

    buffer * const b = r->tmp_buf; /*(cleared before use in backend->query())*/
    const http_vhostdb_backend_t * const backend = pconf.vhostdb_backend;
    if (0 != backend->query(r, backend->p_d, b)) {
        return mod_vhostdb_error_500(r); /* HANDLER_FINISHED */
    }

    if (buffer_is_blank(b)) {
        /* no such virtual host */
        return HANDLER_GO_ON;
    }

    /* sanity check that really is a directory */
    buffer_append_slash(b);
    if (!stat_cache_path_isdir(b)) {
        log_perror(r->conf.errh, __FILE__, __LINE__, "%s", b->ptr);
        return mod_vhostdb_error_500(r); /* HANDLER_FINISHED */
    }

    if (ve && !pconf.vhostdb_cache)
        vhostdb_cache_entry_free(ve);

    ve = vhostdb_cache_entry_init(&r->uri.authority, b);

    if (!pconf.vhostdb_cache)
        r->plugin_ctx[p->id] = ve;
    else
        mod_vhostdb_cache_insert(r, &pconf, ve);

    return mod_vhostdb_found(r, ve); /* HANDLER_GO_ON */
}

/* walk though cache, collect expired ids, and remove them in a second loop */
static void
mod_vhostdb_tag_old_entries (splay_tree * const t, int * const keys, int * const ndx, const time_t max_age, const unix_time64_t cur_ts)
{
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/
    if (t->left)
        mod_vhostdb_tag_old_entries(t->left, keys, ndx, max_age, cur_ts);
    if (t->right)
        mod_vhostdb_tag_old_entries(t->right, keys, ndx, max_age, cur_ts);
    if (*ndx == 8192) return; /*(must match num array entries in keys[])*/

    const vhostdb_cache_entry * const ve = t->data;
    if (cur_ts - ve->ctime > max_age)
        keys[(*ndx)++] = t->key;
}

__attribute_noinline__
static void
mod_vhostdb_periodic_cleanup(splay_tree **sptree_ptr, const time_t max_age, const unix_time64_t cur_ts)
{
    splay_tree *sptree = *sptree_ptr;
    int max_ndx, i;
    int keys[8192]; /* 32k size on stack */
    do {
        if (!sptree) break;
        max_ndx = 0;
        mod_vhostdb_tag_old_entries(sptree, keys, &max_ndx, max_age, cur_ts);
        for (i = 0; i < max_ndx; ++i) {
            sptree = splaytree_splay_nonnull(sptree, keys[i]);
            vhostdb_cache_entry_free(sptree->data);
            sptree = splaytree_delete_splayed_node(sptree);
        }
    } while (max_ndx == sizeof(keys)/sizeof(int));
    *sptree_ptr = sptree;
}

TRIGGER_FUNC(mod_vhostdb_periodic)
{
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_monotonic_secs;
    if (cur_ts & 0x7) return HANDLER_GO_ON; /*(continue once each 8 sec)*/
    UNUSED(srv);

    /* future: might construct array of (vhostdb_cache *) at startup
     *         to avoid the need to search for them here */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    if (NULL == p->cvlist) return HANDLER_GO_ON;
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; cpv->k_id != -1; ++cpv) {
            if (cpv->k_id != 1) continue; /* k_id == 1 for vhostdb.cache */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            vhostdb_cache *vc = cpv->v.v;
            mod_vhostdb_periodic_cleanup(&vc->sptree, vc->max_age, cur_ts);
        }
    }

    return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_vhostdb_plugin_init(plugin *p);
int mod_vhostdb_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = "vhostdb";
    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_free;
    p->set_defaults     = mod_vhostdb_set_defaults;
    p->handle_trigger   = mod_vhostdb_periodic;
    p->handle_docroot   = mod_vhostdb_handle_docroot;
    p->handle_request_reset = mod_vhostdb_handle_request_reset;

    return 0;
}
