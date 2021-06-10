#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "rand.h"
#include "http_header.h"

#include "plugin.h"

#include "sys-crypto-md.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	const buffer *cookie_name;
	const buffer *cookie_attrs;
	const buffer *cookie_domain;
	unsigned int cookie_max_age;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

INIT_FUNC(mod_usertrack_init) {
    return calloc(1, sizeof(plugin_data));
}

static void mod_usertrack_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* usertrack.cookie-name */
        pconf->cookie_name = cpv->v.b;
        break;
      case 1: /* usertrack.cookie-max-age */
        pconf->cookie_max_age = cpv->v.u;
        break;
      case 2: /* usertrack.cookie-domain */
        pconf->cookie_domain = cpv->v.b;
        break;
      case 3: /* usertrack.cookie-attrs */
        pconf->cookie_attrs = cpv->v.b;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_usertrack_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_usertrack_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_usertrack_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_usertrack_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_usertrack_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("usertrack.cookie-name"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("usertrack.cookie-max-age"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("usertrack.cookie-domain"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("usertrack.cookie-attrs"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_usertrack"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* usertrack.cookie-name */
                if (!buffer_is_blank(cpv->v.b)) {
                    const char * const ptr = cpv->v.b->ptr;
                    const size_t len = buffer_clen(cpv->v.b);
                    for (size_t j = 0; j < len; ++j) {
                        if (!light_isalpha(ptr[j])) {
                            log_error(srv->errh, __FILE__, __LINE__,
                              "invalid character in %s: %s",
                               cpk[cpv->k_id].k, ptr);
                            return HANDLER_ERROR;
                        }
                    }
                }
                else
                    cpv->v.b = NULL;
                break;
              case 1: /* usertrack.cookie-max-age */
                break;
              case 2: /* usertrack.cookie-domain */
                if (!buffer_is_blank(cpv->v.b)) {
                    const char * const ptr = cpv->v.b->ptr;
                    const size_t len = buffer_clen(cpv->v.b);
                    for (size_t j = 0; j < len; ++j) {
                        const char c = ptr[j];
                        if (c <= 32 || c >= 127 || c == '"' || c == '\\') {
                            log_error(srv->errh, __FILE__, __LINE__,
                              "invalid character in %s: %s",
                               cpk[cpv->k_id].k, ptr);
                            return HANDLER_ERROR;
                        }
                    }
                }
                else
                    cpv->v.b = NULL;
                break;
              case 3: /* usertrack.cookie-attrs */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
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
            mod_usertrack_merge_config(&p->defaults, cpv);
    }
    if (NULL == p->defaults.cookie_name) {
        static const struct { const char *ptr; uint32_t used; uint32_t size; }
          default_cookie_name = { "TRACKID", sizeof("TRACKID"), 0 };
        *((const buffer **)&p->defaults.cookie_name) =
          (const buffer *)&default_cookie_name;
    }

    return HANDLER_GO_ON;
}

__attribute_noinline__
static handler_t mod_usertrack_set_cookie(request_st * const r, plugin_data * const p) {

	/* generate shared-secret */
	/* (reference mod_auth.c) */
	int rnd = li_rand_pseudo();
	struct const_iovec iov[] = {
	  { BUF_PTR_LEN(&r->uri.path) }
	 ,{ "+", 1 }
	 ,{ &log_epoch_secs, sizeof(log_epoch_secs) }
	 ,{ &rnd, sizeof(rnd) }
	};
	unsigned char h[MD5_DIGEST_LENGTH];
	MD5_iov(h, iov, sizeof(iov)/sizeof(*iov));

	/* set a cookie */
	buffer * const cookie = r->tmp_buf;
	buffer_clear(cookie);
	buffer_append_str2(cookie, BUF_PTR_LEN(p->conf.cookie_name),
                                   CONST_STR_LEN("="));
	buffer_append_string_encoded_hex_lc(cookie, (char *)h, sizeof(h));

	/* usertrack.cookie-attrs, if set, replaces all other attrs */
	if (p->conf.cookie_attrs) {
		buffer_append_string_buffer(cookie, p->conf.cookie_attrs);
		http_header_response_insert(r, HTTP_HEADER_SET_COOKIE, CONST_STR_LEN("Set-Cookie"), BUF_PTR_LEN(cookie));
		return HANDLER_GO_ON;
	}

	buffer_append_string_len(cookie, CONST_STR_LEN("; Path=/; Version=1"));

	if (p->conf.cookie_domain) {
		buffer_append_string_len(cookie, CONST_STR_LEN("; Domain="));
		buffer_append_string_encoded(cookie, BUF_PTR_LEN(p->conf.cookie_domain), ENCODING_REL_URI);
	}

	if (p->conf.cookie_max_age) {
		buffer_append_string_len(cookie, CONST_STR_LEN("; max-age="));
		buffer_append_int(cookie, p->conf.cookie_max_age);
	}

	http_header_response_insert(r, HTTP_HEADER_SET_COOKIE, CONST_STR_LEN("Set-Cookie"), BUF_PTR_LEN(cookie));

	return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_usertrack_uri_handler) {
    plugin_data * const p = p_d;

    mod_usertrack_patch_config(r, p);
    if (!p->conf.cookie_name) return HANDLER_GO_ON;

    const buffer * const b =
      http_header_request_get(r, HTTP_HEADER_COOKIE, CONST_STR_LEN("Cookie"));
    if (NULL != b) {
        /* parse the cookie (fuzzy; not precise using strstr() below)
         * check for cookiename + (WS | '=')
         */
        const char * const g = strstr(b->ptr, p->conf.cookie_name->ptr);
        if (NULL != g) {
            const char *nc = g+buffer_clen(p->conf.cookie_name);
            while (*nc == ' ' || *nc == '\t') ++nc; /* skip WS */
            if (*nc == '=') { /* ok, found the key of our own cookie */
                if (strlen(nc) > 32) {
                    /* i'm lazy */
                    return HANDLER_GO_ON;
                }
            }
        }
    }

    return mod_usertrack_set_cookie(r, p);
}


int mod_usertrack_plugin_init(plugin *p);
int mod_usertrack_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "usertrack";

	p->init        = mod_usertrack_init;
	p->handle_uri_clean  = mod_usertrack_uri_handler;
	p->set_defaults  = mod_usertrack_set_defaults;

	return 0;
}
