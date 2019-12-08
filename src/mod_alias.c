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
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_alias_init) {
    return calloc(1, sizeof(plugin_data));
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

static void mod_alias_patch_config(connection * const con, plugin_data * const p) {
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(con, (uint32_t)p->cvlist[i].k_id))
            mod_alias_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static int mod_alias_check_order(server * const srv, const array * const a) {
    for (uint32_t j = 0; j < a->used; ++j) {
        const buffer * const prefix = &a->sorted[j]->key;
        const size_t plen = buffer_string_length(prefix);
        for (uint32_t k = j + 1; k < a->used; ++k) {
            const buffer * const key = &a->sorted[k]->key;
            if (buffer_string_length(key) < plen) {
                break;
            }
            if (memcmp(key->ptr, prefix->ptr, plen) != 0) {
                break;
            }
            /* ok, they have same prefix. check position */
            const data_unset *dj = a->sorted[j];
            const data_unset *dk = a->sorted[k];
            const data_unset **data = (const data_unset **)a->data;
            while (*data != dj && *data != dk) ++data;
            if (*data == dj) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "url.alias: `%s' will never match as `%s' matched first",
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

PHYSICALPATH_FUNC(mod_alias_physical_handler) {
	plugin_data *p = p_d;
	char *uri_ptr;
	size_t uri_len = buffer_string_length(con->physical.path);
	size_t basedir_len, alias_len;
	data_string *ds;

	if (0 == uri_len) return HANDLER_GO_ON;

	mod_alias_patch_config(con, p);
	if (NULL == p->conf.alias) return HANDLER_GO_ON;

	/* do not include trailing slash on basedir */
	basedir_len = buffer_string_length(con->physical.basedir);
	if ('/' == con->physical.basedir->ptr[basedir_len-1]) --basedir_len;
	uri_len -= basedir_len;
	uri_ptr = con->physical.path->ptr + basedir_len;

	ds = (!con->conf.force_lowercase_filenames)
	   ? (data_string *)array_match_key_prefix_klen(p->conf.alias, uri_ptr, uri_len)
	   : (data_string *)array_match_key_prefix_nc_klen(p->conf.alias, uri_ptr, uri_len);
	if (NULL == ds) { return HANDLER_GO_ON; }

			/* matched */

			/* check for path traversal in url-path following alias if key
			 * does not end in slash, but replacement value ends in slash */
			alias_len = buffer_string_length(&ds->key);
			if (uri_ptr[alias_len] == '.') {
				char *s = uri_ptr + alias_len + 1;
				if (*s == '.') ++s;
				if (*s == '/' || *s == '\0') {
					size_t vlen = buffer_string_length(&ds->value);
					if (0 != alias_len && ds->key.ptr[alias_len-1] != '/'
					    && 0 != vlen && ds->value.ptr[vlen-1] == '/') {
						con->http_status = 403;
						return HANDLER_FINISHED;
					}
				}
			}

			buffer * const tb = con->srv->tmp_buf;
			buffer_copy_buffer(con->physical.basedir, &ds->value);
			buffer_copy_buffer(tb, &ds->value);
			buffer_append_string(tb, uri_ptr + alias_len);
			buffer_copy_buffer(con->physical.path, tb);

			return HANDLER_GO_ON;
}


int mod_alias_plugin_init(plugin *p);
int mod_alias_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "alias";

	p->init           = mod_alias_init;
	p->handle_physical= mod_alias_physical_handler;
	p->set_defaults   = mod_alias_set_defaults;

	return 0;
}
