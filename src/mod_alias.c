#include "first.h"

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "log.h"

#include "plugin.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const array *alias;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
} plugin_data;

INIT_FUNC(mod_alias_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

static void mod_alias_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* alias.url */
        pconf->alias = cpv->v.a;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_alias_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_alias_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_alias_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    *pconf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(pconf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_alias_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static int mod_alias_check_order(server * const srv, const array * const a) {
    for (uint32_t j = 0; j < a->used; ++j) {
        const buffer * const prefix = &a->data[j]->key;
        const size_t plen = buffer_clen(prefix);
        for (uint32_t k = j + 1; k < a->used; ++k) {
            const buffer * const key = &a->data[k]->key;
            if (buffer_clen(key) < plen) {
                break;
            }
            if (memcmp(key->ptr, prefix->ptr, plen) != 0) {
                break;
            }
            /* ok, they have same prefix. check position */
            const data_unset *dj = a->data[j];
            const data_unset *dk = a->data[k];
            const data_unset **data = (const data_unset **)a->data;
            while (*data != dj && *data != dk) ++data;
            if (*data == dj) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "alias.url: `%s' will never match as `%s' matched first",
                  key->ptr, prefix->ptr);
                return 0;
            }
        }
    }
    return 1;
}

SETDEFAULTS_FUNC(mod_alias_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("alias.url"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_alias"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* alias.url */
                if (cpv->v.a->used >= 2 && !mod_alias_check_order(srv,cpv->v.a))
                    return HANDLER_ERROR;
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
            mod_alias_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

static handler_t
mod_alias_remap (request_st * const r, const array * const aliases)
{
    /* do not include trailing slash on basedir */
    uint32_t basedir_len = buffer_clen(&r->physical.basedir);
    if (buffer_has_pathsep_suffix(&r->physical.basedir)) --basedir_len;

    const uint32_t path_len = buffer_clen(&r->physical.path);
    if (0 == path_len || path_len < basedir_len) return HANDLER_GO_ON;

    const uint32_t uri_len = path_len - basedir_len;
    const char *uri_ptr = r->physical.path.ptr + basedir_len;
    data_string * const ds = (data_string *)
      (!r->conf.force_lowercase_filenames
        ? array_match_key_prefix_klen(aliases, uri_ptr, uri_len)
        : array_match_key_prefix_nc_klen(aliases, uri_ptr, uri_len));
    if (NULL == ds) return HANDLER_GO_ON;

    /* matched */

    const uint32_t alias_len = buffer_clen(&ds->key);
    const uint32_t vlen = buffer_clen(&ds->value);

    /* check for path traversal in url-path following alias if key
     * does not end in slash, but replacement value ends in slash */
    if (uri_ptr[alias_len] == '.') {
        const char *s = uri_ptr + alias_len + 1;
        if (*s == '.') ++s;
        if (*s == '/' || *s == '\0') {
            if (0 != alias_len && ds->key.ptr[alias_len-1] != '/'
                && 0 != vlen && ds->value.ptr[vlen-1] == '/') {
                r->http_status = 403;
                return HANDLER_FINISHED;
            }
        }
    }

    /*(not buffer_append_path_len();
     * alias could be prefix instead of complete path segment,
     * (though resulting r->physical.basedir would not be a dir))*/
    if (vlen != basedir_len + alias_len) {
        const uint32_t nlen = vlen + uri_len - alias_len;
        if (path_len + buffer_string_space(&r->physical.path) < nlen) {
            buffer_string_prepare_append(&r->physical.path, nlen - path_len);
            uri_ptr = r->physical.path.ptr + basedir_len;/*(refresh if alloc)*/
        }
        memmove(r->physical.path.ptr + vlen,
                uri_ptr + alias_len, uri_len - alias_len);
        buffer_truncate(&r->physical.path, nlen);
    }
    memcpy(r->physical.path.ptr, ds->value.ptr, vlen);

    buffer_copy_string_len(&r->physical.basedir, ds->value.ptr, vlen);

    return HANDLER_GO_ON;
}

PHYSICALPATH_FUNC(mod_alias_physical_handler) {
    plugin_config pconf;
    mod_alias_patch_config(r, p_d, &pconf);
    return pconf.alias ? mod_alias_remap(r, pconf.alias) : HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_alias_plugin_init(plugin *p);
int mod_alias_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "alias";

	p->init           = mod_alias_init;
	p->handle_physical= mod_alias_physical_handler;
	p->set_defaults   = mod_alias_set_defaults;

	return 0;
}
