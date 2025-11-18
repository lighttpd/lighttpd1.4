#include "first.h"

#include <string.h>
#include <stdlib.h>

#include "gw_backend.h"
#include "base.h"
#include "array.h"
#include "buffer.h"
#include "fdevent.h"
#include "http_kv.h"
#include "http_header.h"
#include "http_status.h"
#include "log.h"
#include "sock_addr.h"

/**
 *
 * HTTP reverse proxy
 *
 * TODO:      - HTTP/1.1
 *            - HTTP/1.1 persistent connection with upstream servers
 */

/* (future: might split struct and move part to http-header-glue.c) */
typedef struct http_header_remap_opts {
    const array *urlpaths;
    const array *hosts_request;
    const array *hosts_response;
    int force_http10;
    int https_remap;
    int upgrade;
    int connect_method;
    /*(not used in plugin_config, but used in handler_ctx)*/
    const buffer *http_host;
    const buffer *forwarded_host;
    const data_string *forwarded_urlpath;
} http_header_remap_opts;

typedef enum {
	PROXY_FORWARDED_NONE         = 0x00,
	PROXY_FORWARDED_FOR          = 0x01,
	PROXY_FORWARDED_PROTO        = 0x02,
	PROXY_FORWARDED_HOST         = 0x04,
	PROXY_FORWARDED_BY           = 0x08,
	PROXY_FORWARDED_REMOTE_USER  = 0x10
} proxy_forwarded_t;

typedef struct {
    gw_plugin_config gw; /* start must match layout of gw_plugin_config */
    unsigned int replace_http_host;
    unsigned int forwarded;
    http_header_remap_opts header;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    pid_t srv_pid; /* must match layout of gw_plugin_data to defaults member */
    plugin_config defaults;
} plugin_data;

static int proxy_check_extforward;

typedef struct {
	gw_handler_ctx gw;
	plugin_config conf;
} handler_ctx;


INIT_FUNC(mod_proxy_init) {
    return ck_calloc(1, sizeof(plugin_data));
}


static void mod_proxy_free_config(plugin_data * const p)
{
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 5: /* proxy.header */
                if (cpv->vtype == T_CONFIG_LOCAL) free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}


FREE_FUNC(mod_proxy_free) {
    plugin_data * const p = p_d;
    mod_proxy_free_config(p);
    gw_free(p);
}

static void mod_proxy_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv)
{
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* proxy.server */
        if (cpv->vtype == T_CONFIG_LOCAL) {
            gw_plugin_config * const gw = cpv->v.v;
            pconf->gw.exts      = gw->exts;
            pconf->gw.exts_auth = gw->exts_auth;
            pconf->gw.exts_resp = gw->exts_resp;
        }
        break;
      case 1: /* proxy.balance */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->gw.balance = (int)cpv->v.u;
        break;
      case 2: /* proxy.debug */
        pconf->gw.debug = (int)cpv->v.u;
        break;
      case 3: /* proxy.map-extensions */
        pconf->gw.ext_mapping = cpv->v.a;
        break;
      case 4: /* proxy.forwarded */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
            pconf->forwarded = cpv->v.u;
        break;
      case 5: /* proxy.header */
        /*if (cpv->vtype == T_CONFIG_LOCAL)*//*always true here for this param*/
        pconf->header = *(http_header_remap_opts *)cpv->v.v; /*(copies struct)*/
        pconf->gw.upgrade = pconf->header.upgrade;
        break;
      case 6: /* proxy.replace-http-host */
        pconf->replace_http_host = cpv->v.u;
        break;
      default:/* should not happen */
        return;
    }
}


static void mod_proxy_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv)
{
    do {
        mod_proxy_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void mod_proxy_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf)
{
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_proxy_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


static unsigned int mod_proxy_parse_forwarded(server *srv, const array *a)
{
    unsigned int forwarded = 0;
    for (uint32_t j = 0, used = a->used; j < used; ++j) {
        proxy_forwarded_t param;
        data_unset *du = a->data[j];
        if (buffer_eq_slen(&du->key, CONST_STR_LEN("by")))
            param = PROXY_FORWARDED_BY;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("for")))
            param = PROXY_FORWARDED_FOR;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("host")))
            param = PROXY_FORWARDED_HOST;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("proto")))
            param = PROXY_FORWARDED_PROTO;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("remote_user")))
            param = PROXY_FORWARDED_REMOTE_USER;
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "proxy.forwarded keys must be one of: "
              "by, for, host, proto, remote_user, but not: %s", du->key.ptr);
            return UINT_MAX;
        }
        int val = config_plugin_value_to_bool(du, 2);
        if (2 == val) {
            log_error(srv->errh, __FILE__, __LINE__,
              "proxy.forwarded values must be one of: "
              "0, 1, enable, disable; error for key: %s", du->key.ptr);
            return UINT_MAX;
        }
        if (val)
            forwarded |= param;
    }
    return forwarded;
}


static http_header_remap_opts * mod_proxy_parse_header_opts(server *srv, const array *a)
{
    http_header_remap_opts header;
    memset(&header, 0, sizeof(header));
    for (uint32_t j = 0, used = a->used; j < used; ++j) {
        data_array *da = (data_array *)a->data[j];
        if (buffer_eq_slen(&da->key, CONST_STR_LEN("https-remap"))) {
            int val = config_plugin_value_to_bool((data_unset *)da, 2);
            if (2 == val) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "unexpected value for proxy.header; "
                  "expected \"https-remap\" => \"enable\" or \"disable\"");
                return NULL;
            }
            header.https_remap = val;
            continue;
        }
        else if (buffer_eq_slen(&da->key, CONST_STR_LEN("force-http10"))) {
            int val = config_plugin_value_to_bool((data_unset *)da, 2);
            if (2 == val) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "unexpected value for proxy.header; "
                  "expected \"force-http10\" => \"enable\" or \"disable\"");
                return NULL;
            }
            header.force_http10 = val;
            continue;
        }
        else if (buffer_eq_slen(&da->key, CONST_STR_LEN("upgrade"))) {
            int val = config_plugin_value_to_bool((data_unset *)da, 2);
            if (2 == val) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "unexpected value for proxy.header; "
                  "expected \"upgrade\" => \"enable\" or \"disable\"");
                return NULL;
            }
            header.upgrade = val;
            continue;
        }
        else if (buffer_eq_slen(&da->key, CONST_STR_LEN("connect"))) {
            int val = config_plugin_value_to_bool((data_unset *)da, 2);
            if (2 == val) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "unexpected value for proxy.header; "
                  "expected \"connect\" => \"enable\" or \"disable\"");
                return NULL;
            }
            header.connect_method = val;
            continue;
        }
        if (da->type != TYPE_ARRAY || !array_is_kvstring(&da->value)) {
            log_error(srv->errh, __FILE__, __LINE__,
              "unexpected value for proxy.header; "
              "expected ( \"param\" => ( \"key\" => \"value\" ) ) near key %s",
              da->key.ptr);
            return NULL;
        }
        if (buffer_eq_slen(&da->key, CONST_STR_LEN("map-urlpath"))) {
            header.urlpaths = &da->value;
        }
        else if (buffer_eq_slen(&da->key, CONST_STR_LEN("map-host-request"))) {
            header.hosts_request = &da->value;
        }
        else if (buffer_eq_slen(&da->key, CONST_STR_LEN("map-host-response"))) {
            header.hosts_response = &da->value;
        }
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "unexpected key for proxy.header; "
              "expected ( \"param\" => ( \"key\" => \"value\" ) ) near key %s",
              da->key.ptr);
            return NULL;
        }
    }

    http_header_remap_opts *opts = ck_malloc(sizeof(header));
    memcpy(opts, &header, sizeof(header));
    return opts;
}


SETDEFAULTS_FUNC(mod_proxy_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("proxy.server"),
        T_CONFIG_ARRAY_KVARRAY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("proxy.balance"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("proxy.debug"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("proxy.map-extensions"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("proxy.forwarded"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("proxy.header"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("proxy.replace-http-host"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_proxy"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        gw_plugin_config *gw = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* proxy.server */
                gw = ck_calloc(1, sizeof(gw_plugin_config));
                if (!gw_set_defaults_backend(srv, (gw_plugin_data *)p, cpv->v.a,
                                             gw, 0, cpk[cpv->k_id].k)) {
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                /* error if "mode" = "authorizer";
                 * proxy can not act as authorizer */
                /*(check after gw_set_defaults_backend())*/
                if (gw->exts_auth && gw->exts_auth->used) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "%s must not define any hosts with "
                      "attribute \"mode\" = \"authorizer\"", cpk[cpv->k_id].k);
                    gw_plugin_config_free(gw);
                    return HANDLER_ERROR;
                }
                cpv->v.v = gw;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* proxy.balance */
                cpv->v.u = (unsigned int)gw_get_defaults_balance(srv, cpv->v.b);
                break;
              case 2: /* proxy.debug */
              case 3: /* proxy.map-extensions */
                break;
              case 4: /* proxy.forwarded */
                cpv->v.u = mod_proxy_parse_forwarded(srv, cpv->v.a);
                if (UINT_MAX == cpv->v.u) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 5: /* proxy.header */
                cpv->v.v = mod_proxy_parse_header_opts(srv, cpv->v.a);
                if (NULL == cpv->v.v) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 6: /* proxy.replace-http-host */
                break;
              default:/* should not happen */
                break;
            }
        }

        /* disable check-local for all exts (default enabled) */
        if (gw && gw->exts) { /*(check after gw_set_defaults_backend())*/
            gw_exts_clear_check_local(gw->exts);
        }
    }

    /* default is 0 */
    /*p->defaults.balance = (unsigned int)gw_get_defaults_balance(srv, NULL);*/

    p->defaults.header.force_http10 =
      config_feature_bool(srv, "proxy.force-http10", 0);

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_proxy_merge_config(&p->defaults, cpv);
    }

    /* special-case behavior if mod_extforward is loaded */
    for (uint32_t i = 0; i < srv->srvconf.modules->used; ++i) {
        buffer *m = &((data_string *)srv->srvconf.modules->data[i])->value;
        if (buffer_eq_slen(m, CONST_STR_LEN("mod_extforward"))) {
            proxy_check_extforward = 1;
            break;
        }
    }

    return HANDLER_GO_ON;
}


/* (future: might move to http-header-glue.c) */
static const buffer * http_header_remap_host_match (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req, size_t alen)
{
    const array *hosts = is_req
      ? remap_hdrs->hosts_request
      : remap_hdrs->hosts_response;
    if (hosts) {
        const char * const s = b->ptr+off;
        for (size_t i = 0, used = hosts->used; i < used; ++i) {
            const data_string * const ds = (data_string *)hosts->data[i];
            const buffer *k = &ds->key;
            size_t mlen = buffer_clen(k);
            if (1 == mlen && k->ptr[0] == '-') {
                /* match with authority provided in Host (if is_req)
                 * (If no Host in client request, then matching against empty
                 *  string will probably not match, and no remap will be
                 *  performed) */
                k = is_req || NULL == remap_hdrs->forwarded_host
                  ? remap_hdrs->http_host
                  : remap_hdrs->forwarded_host;
                if (NULL == k) continue;
                mlen = buffer_clen(k);
            }
            if (buffer_eq_icase_ss(s, alen, k->ptr, mlen)) {
                if (buffer_is_equal_string(&ds->value, CONST_STR_LEN("-"))) {
                    return remap_hdrs->http_host;
                }
                else if (!buffer_is_blank(&ds->value)) {
                    /*(save first matched request host for response match)*/
                    if (is_req && NULL == remap_hdrs->forwarded_host)
                        remap_hdrs->forwarded_host = &ds->value;
                    return &ds->value;
                } /*(else leave authority as-is and stop matching)*/
                break;
            }
        }
    }
    return NULL;
}


/* (future: might move to http-header-glue.c) */
static size_t http_header_remap_host (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req, size_t alen)
{
    const buffer * const m =
      http_header_remap_host_match(b, off, remap_hdrs, is_req, alen);
    if (NULL == m) return alen; /*(no match; return original authority length)*/

    buffer_substr_replace(b, off, alen, m);
    return buffer_clen(m); /*(length of replacement authority)*/
}


/* (future: might move to http-header-glue.c) */
static size_t http_header_remap_urlpath (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req)
{
    const array *urlpaths = remap_hdrs->urlpaths;
    if (urlpaths) {
        const char * const s = b->ptr+off;
        const size_t plen = buffer_clen(b) - off; /*(urlpath len)*/
        if (is_req) { /* request */
            for (size_t i = 0, used = urlpaths->used; i < used; ++i) {
                const data_string * const ds = (data_string *)urlpaths->data[i];
                const size_t mlen = buffer_clen(&ds->key);
                if (mlen <= plen && 0 == memcmp(s, ds->key.ptr, mlen)) {
                    if (NULL == remap_hdrs->forwarded_urlpath)
                        remap_hdrs->forwarded_urlpath = ds;
                    buffer_substr_replace(b, off, mlen, &ds->value);
                    return buffer_clen(&ds->value);/*(replacement len)*/
                }
            }
        }
        else {        /* response; perform reverse map */
            if (NULL != remap_hdrs->forwarded_urlpath) {
                const data_string * const ds = remap_hdrs->forwarded_urlpath;
                const size_t mlen = buffer_clen(&ds->value);
                if (mlen <= plen && 0 == memcmp(s, ds->value.ptr, mlen)) {
                    buffer_substr_replace(b, off, mlen, &ds->key);
                    return buffer_clen(&ds->key); /*(replacement len)*/
                }
            }
            for (size_t i = 0, used = urlpaths->used; i < used; ++i) {
                const data_string * const ds = (data_string *)urlpaths->data[i];
                const size_t mlen = buffer_clen(&ds->value);
                if (mlen <= plen && 0 == memcmp(s, ds->value.ptr, mlen)) {
                    buffer_substr_replace(b, off, mlen, &ds->key);
                    return buffer_clen(&ds->key); /*(replacement len)*/
                }
            }
        }
    }
    return 0;
}


/* (future: might move to http-header-glue.c) */
static void http_header_remap_uri (buffer *b, size_t off, http_header_remap_opts *remap_hdrs, int is_req)
{
    /* find beginning of URL-path (might be preceded by scheme://authority
     * (caller should make sure any leading whitespace is prior to offset) */
    if (b->ptr[off] != '/') {
        char *s = b->ptr+off;
        size_t alen; /*(authority len (host len))*/
        size_t slen; /*(scheme len)*/
        const buffer *m;
        /* skip over scheme and authority of URI to find beginning of URL-path
         * (value might conceivably be relative URL-path instead of URI) */
        if (NULL == (s = strchr(s, ':')) || s[1] != '/' || s[2] != '/') return;
        slen = s - (b->ptr+off);
        s += 3;
        off = (size_t)(s - b->ptr);
        if (NULL != (s = strchr(s, '/'))) {
            alen = (size_t)(s - b->ptr) - off;
            if (0 == alen) return; /*(empty authority, e.g. "http:///")*/
        }
        else {
            alen = buffer_clen(b) - off;
            if (0 == alen) return; /*(empty authority, e.g. "http:///")*/
            buffer_append_char(b, '/');
        }

        /* remap authority (if configured) and set offset to url-path */
        m = http_header_remap_host_match(b, off, remap_hdrs, is_req, alen);
        if (NULL != m) {
            if (remap_hdrs->https_remap
                && (is_req ? 5==slen && 0==memcmp(b->ptr+off-slen-3,"https",5)
                           : 4==slen && 0==memcmp(b->ptr+off-slen-3,"http",4))){
                if (is_req) {
                    memcpy(b->ptr+off-slen-3+4,"://",3);  /*("https"=>"http")*/
                    --off;
                    ++alen;
                }
                else {/*(!is_req)*/
                    memcpy(b->ptr+off-slen-3+4,"s://",4); /*("http" =>"https")*/
                    ++off;
                    --alen;
                }
            }
            buffer_substr_replace(b, off, alen, m);
            alen = buffer_clen(m);/*(length of replacement authority)*/
        }
        off += alen;
    }

    /* remap URLs (if configured) */
    http_header_remap_urlpath(b, off, remap_hdrs, is_req);
}


/* (future: might move to http-header-glue.c) */
static void http_header_remap_setcookie (buffer *b, size_t off, http_header_remap_opts *remap_hdrs)
{
    /* Given the special-case of Set-Cookie and the (too) loosely restricted
     * characters allowed, for best results, the Set-Cookie value should be the
     * entire string in b from offset to end of string.  In response headers,
     * lighttpd may concatenate multiple Set-Cookie headers into single entry
     * in r->resp_headers, separated by "\r\nSet-Cookie: " */
    for (char *s = b->ptr+off, *e; *s; s = e) {
        size_t len;
        {
            while (*s != ';' && *s != '\n' && *s != '\0') ++s;
            if (*s == '\n') {
                /*(include +1 for '\n', but leave ' ' for ++s below)*/
                s += sizeof("Set-Cookie:");
            }
            if ('\0' == *s) return;
            do { ++s; } while (*s == ' ' || *s == '\t');
            if ('\0' == *s) return;
            e = s+1;
            if ('=' == *s) continue;
            /*(interested only in Domain and Path attributes)*/
            while (*e != '=' && *e != '\0') ++e;
            if ('\0' == *e) return;
            ++e;
            switch ((int)(e - s - 1)) {
              case 4:
                if (buffer_eq_icase_ssn(s, "path", 4)) {
                    if (*e == '"') ++e;
                    if (*e != '/') continue;
                    off = (size_t)(e - b->ptr);
                    len = http_header_remap_urlpath(b, off, remap_hdrs, 0);
                    e = b->ptr+off+len; /*(b may have been reallocated)*/
                    continue;
                }
                break;
              case 6:
                if (buffer_eq_icase_ssn(s, "domain", 6)) {
                    size_t alen = 0;
                    if (*e == '"') ++e;
                    if (*e == '.') ++e;
                    if (*e == ';') continue;
                    off = (size_t)(e - b->ptr);
                    for (char c; (c = e[alen]) != ';' && c != ' ' && c != '\t'
                                          && c != '\r' && c != '\0'; ++alen);
                    len = http_header_remap_host(b, off, remap_hdrs, 0, alen);
                    e = b->ptr+off+len; /*(b may have been reallocated)*/
                    continue;
                }
                break;
              default:
                break;
            }
        }
    }
}


static void buffer_append_string_backslash_escaped(buffer *b, const char *s, size_t len) {
    /* (future: might move to buffer.c) */
    size_t j = 0;
    char * const p = buffer_string_prepare_append(b, len*2 + 4);

    for (size_t i = 0; i < len; ++i) {
        int c = s[i];
        if (c == '"' || c == '\\' || c == 0x7F || (c < 0x20 && c != '\t'))
            p[j++] = '\\';
        p[j++] = c;
    }

    buffer_commit(b, j);
}

static void proxy_set_Forwarded(connection * const con, request_st * const r, const unsigned int flags) {
    buffer *b = NULL;
    buffer * const efor = (proxy_check_extforward)
      ? http_header_env_get(r, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_FOR"))
      : NULL;
    int semicolon = 0;

    /* note: set "Forwarded" prior to updating X-Forwarded-For (below) */

    if (flags)
        b = http_header_request_get(r, HTTP_HEADER_FORWARDED, CONST_STR_LEN("Forwarded"));

    if (flags && NULL == b) {
        const buffer *xff =
          http_header_request_get(r, HTTP_HEADER_X_FORWARDED_FOR, CONST_STR_LEN("X-Forwarded-For"));
        b = http_header_request_set_ptr(r, HTTP_HEADER_FORWARDED,
                                        CONST_STR_LEN("Forwarded"));
        if (NULL != xff) {
            /* use X-Forwarded-For contents to seed Forwarded */
            char *s = xff->ptr;
            size_t used = buffer_clen(xff);
            for (size_t i=0, j, ipv6; i < used; ++i) {
                while (s[i] == ' ' || s[i] == '\t' || s[i] == ',') ++i;
                if (s[i] == '\0') break;
                j = i;
                do {
                    ++i;
                } while (s[i]!=' ' && s[i]!='\t' && s[i]!=',' && s[i]!='\0');
                /* over-simplified test expecting only IPv4 or IPv6 addresses,
                 * (not expecting :port, so treat existence of colon as IPv6,
                 *  and not expecting unix paths, especially not containing ':')
                 * quote all strings, backslash-escape since IPs not validated*/
                ipv6 = (NULL != memchr(s+j, ':', i-j)); /*(over-simplified) */
                ipv6
                  ? buffer_append_string_len(b, CONST_STR_LEN("for=\"["))
                  : buffer_append_string_len(b, CONST_STR_LEN("for=\""));
                buffer_append_string_backslash_escaped(b, s+j, i-j);
                ipv6
                  ? buffer_append_string_len(b, CONST_STR_LEN("]\", "))
                  : buffer_append_string_len(b, CONST_STR_LEN("\", "));
            }
        }
    } else if (flags) { /*(NULL != b)*/
        buffer_append_string_len(b, CONST_STR_LEN(", "));
    }

    if (flags & PROXY_FORWARDED_FOR) {
        int family = sock_addr_get_family(&con->dst_addr);
        buffer_append_string_len(b, CONST_STR_LEN("for="));
        if (NULL != efor) {
            /* over-simplified test expecting only IPv4 or IPv6 addresses,
             * (not expecting :port, so treat existence of colon as IPv6,
             *  and not expecting unix paths, especially not containing ':')
             * quote all strings and backslash-escape since IPs not validated
             * (should be IP from original con->dst_addr_buf,
             *  so trustable and without :port) */
            int ipv6 = (NULL != strchr(efor->ptr, ':'));
            ipv6
              ? buffer_append_string_len(b, CONST_STR_LEN("\"["))
              : buffer_append_char(b, '"');
            buffer_append_string_backslash_escaped(b, BUF_PTR_LEN(efor));
            ipv6
              ? buffer_append_string_len(b, CONST_STR_LEN("]\""))
              : buffer_append_char(b, '"');
        } else if (family == AF_INET) {
            /*(Note: if :port is added, then must be quoted-string:
             * e.g. for="...:port")*/
            buffer_append_string_buffer(b, &con->dst_addr_buf);
        } else if (family == AF_INET6) {
            buffer_append_str3(b, CONST_STR_LEN("\"["),
                                  BUF_PTR_LEN(&con->dst_addr_buf),
                                  CONST_STR_LEN("]\""));
        } else {
            buffer_append_char(b, '"');
            buffer_append_string_backslash_escaped(
              b, BUF_PTR_LEN(&con->dst_addr_buf));
            buffer_append_char(b, '"');
        }
        semicolon = 1;
    }

    if (flags & PROXY_FORWARDED_BY) {
        /* Note: getsockname() and inet_ntop() are expensive operations.
         * (recommendation: do not to enable by=... unless required)
         * future: might use con->srv_socket->srv_token if addr is not
         *   INADDR_ANY or in6addr_any, but must omit optional :port
         *   from con->srv_socket->srv_token for consistency */

        if (semicolon) buffer_append_char(b, ';');
        buffer_append_string_len(b, CONST_STR_LEN("by=\""));
      #ifdef HAVE_SYS_UN_H
        /* special-case: might need to encode unix domain socket path */
        int family = sock_addr_get_family(&con->srv_socket->addr);
        if (family == AF_UNIX) {
            buffer_append_string_backslash_escaped(
              b, BUF_PTR_LEN(con->srv_socket->srv_token));
        }
        else
      #endif
        {
            sock_addr addr;
            socklen_t addrlen = sizeof(addr);
            if (0 == getsockname(con->fd,(struct sockaddr *)&addr, &addrlen)) {
                sock_addr_stringify_append_buffer(b, &addr);
            }
        }
        buffer_append_char(b, '"');
        semicolon = 1;
    }

    if (flags & PROXY_FORWARDED_PROTO) {
        const buffer * const eproto = (proxy_check_extforward)
          ? http_header_env_get(r, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_PROTO"))
          : NULL;
        /* expecting "http" or "https"
         * (not checking if quoted-string and encoding needed) */
        if (semicolon) buffer_append_char(b, ';');
        if (NULL != eproto) {
            buffer_append_str2(b, CONST_STR_LEN("proto="), BUF_PTR_LEN(eproto));
        } else if (con->srv_socket->is_ssl) {
            buffer_append_string_len(b, CONST_STR_LEN("proto=https"));
        } else {
            buffer_append_string_len(b, CONST_STR_LEN("proto=http"));
        }
        semicolon = 1;
    }

    if (flags & PROXY_FORWARDED_HOST) {
        const buffer * const ehost = (proxy_check_extforward)
          ? http_header_env_get(r, CONST_STR_LEN("_L_EXTFORWARD_ACTUAL_HOST"))
          : NULL;
        if (NULL != ehost) {
            if (semicolon)
                buffer_append_char(b, ';');
            buffer_append_string_len(b, CONST_STR_LEN("host=\""));
            buffer_append_string_backslash_escaped(
              b, BUF_PTR_LEN(ehost));
            buffer_append_char(b, '"');
            semicolon = 1;
        } else if (r->http_host && !buffer_is_blank(r->http_host)) {
            if (semicolon)
                buffer_append_char(b, ';');
            buffer_append_string_len(b, CONST_STR_LEN("host=\""));
            buffer_append_string_backslash_escaped(
              b, BUF_PTR_LEN(r->http_host));
            buffer_append_char(b, '"');
            semicolon = 1;
        }
    }

    if (flags & PROXY_FORWARDED_REMOTE_USER) {
        const buffer *remote_user =
          http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
        if (NULL != remote_user) {
            if (semicolon)
                buffer_append_char(b, ';');
            buffer_append_string_len(b, CONST_STR_LEN("remote_user=\""));
            buffer_append_string_backslash_escaped(
              b, BUF_PTR_LEN(remote_user));
            buffer_append_char(b, '"');
            /*semicolon = 1;*/
        }
    }

    /* legacy X-* headers, including X-Forwarded-For */

    b = (NULL != efor) ? efor : &con->dst_addr_buf;
    http_header_request_append(r, HTTP_HEADER_X_FORWARDED_FOR,
                               CONST_STR_LEN("X-Forwarded-For"),
                               BUF_PTR_LEN(b));

    b = r->http_host;
    if (b && !buffer_is_blank(b)) {
        http_header_request_set(r, HTTP_HEADER_OTHER,
                                CONST_STR_LEN("X-Host"),
                                BUF_PTR_LEN(b));
        http_header_request_set(r, HTTP_HEADER_OTHER,
                                CONST_STR_LEN("X-Forwarded-Host"),
                                BUF_PTR_LEN(b));
    }

    b = &r->uri.scheme;
    http_header_request_set(r, HTTP_HEADER_X_FORWARDED_PROTO,
                            CONST_STR_LEN("X-Forwarded-Proto"),
                            BUF_PTR_LEN(b));
}


static handler_t proxy_stdin_append(gw_handler_ctx *hctx) {
    /*handler_ctx *hctx = (handler_ctx *)gwhctx;*/
    chunkqueue * const req_cq = &hctx->r->reqbody_queue;
    const off_t req_cqlen = chunkqueue_length(req_cq);
    if (req_cqlen) {
        /* XXX: future: use http_chunk_len_append() */
        buffer * const tb = hctx->r->tmp_buf;
        buffer_clear(tb);
        buffer_append_uint_hex_lc(tb, (uintmax_t)req_cqlen);
        buffer_append_string_len(tb, CONST_STR_LEN("\r\n"));

        const off_t len = (off_t)buffer_clen(tb)
                        + 2 /*(+2 end chunk "\r\n")*/
                        + req_cqlen;
        if (-1 != hctx->wb_reqlen)
            hctx->wb_reqlen += (hctx->wb_reqlen >= 0) ? len : -len;

        (chunkqueue_is_empty(&hctx->wb) || hctx->wb.first->type == MEM_CHUNK)
                                          /* else FILE_CHUNK for temp file */
          ? chunkqueue_append_mem(&hctx->wb, BUF_PTR_LEN(tb))
          : chunkqueue_append_mem_min(&hctx->wb, BUF_PTR_LEN(tb));
        chunkqueue_steal(&hctx->wb, req_cq, req_cqlen);

        chunkqueue_append_mem_min(&hctx->wb, CONST_STR_LEN("\r\n"));
    }

    if (hctx->wb.bytes_in == hctx->wb_reqlen) {/*hctx->r->reqbody_length >= 0*/
        /* terminate STDIN */
      #if 0
        /* future: if request trailers were to have been set aside, add here */
        /* Note: there could be Content-Length with HTTP/2, but subsequent
         * trailers would not be sent to HTTP/1.1 backend since lighttpd would
         * send Content-Length instead of chunked encoding.  While lighttpd
         * could check for Trailer header and HTTP/2 in proxy_create_env(), and
         * could choose to unset Content-Length, this is not currently done.
         * An HTTP/2 client sending trailers could avoid setting Content-Length.
         * (There is no Content-Length with HTTP/1.1 Transfer-Encoding: chunked
         *  and subsequent trailers.) */
        if (array_get_element_klen(&r->env, CONST_STR_LEN("_L_TRAILERS"))) {
            /*(look up twice if exists, but (potentially) avoid copying buffer,
             * and free underlying value ptr sooner)*/
            buffer * const vb =
              array_get_buf_ptr(&r->env, CONST_STR_LEN("_L_TRAILERS"));
            hctx->wb_reqlen += buffer_clen(vb); /*(before buffer move)*/
            chunkqueue_append_mem(&hctx->wb, CONST_STR_LEN("0\r\n"));
            chunkqueue_append_buffer(&hctx->wb, CONST_BUF_LEN(vb));
            chunkqueue_append_mem(&hctx->wb, CONST_STR_LEN("\r\n"));
        }
        else
      #endif
            chunkqueue_append_mem(&hctx->wb, CONST_STR_LEN("0\r\n\r\n"));
        hctx->wb_reqlen += (int)sizeof("0\r\n\r\n");
    }

    return HANDLER_GO_ON;
}


static handler_t proxy_create_env(gw_handler_ctx *gwhctx) {
	handler_ctx *hctx = (handler_ctx *)gwhctx;
	request_st * const r = hctx->gw.r;
	const int remap_headers = (NULL != hctx->conf.header.urlpaths
				   || NULL != hctx->conf.header.hosts_request);
	size_t rsz = (size_t)(r->read_queue.bytes_out - hctx->gw.wb.bytes_in);
	if (rsz >= 65536) rsz = r->rqst_header_len;
	buffer * const b = chunkqueue_prepend_buffer_open_sz(&hctx->gw.wb, rsz);

	/* build header */

	/* request line */
	const buffer * const m =
	  http_method_buf(!r->h2_connect_ext
			  ? r->http_method
			  : HTTP_METHOD_GET); /*(translate HTTP/2 CONNECT ext)*/
	buffer_append_str3(b,
	                   BUF_PTR_LEN(m),
	                   CONST_STR_LEN(" "),
	                   BUF_PTR_LEN(&r->target));
	if (remap_headers)
		http_header_remap_uri(b, buffer_clen(b) - buffer_clen(&r->target),
		                      &hctx->conf.header, 1);

	buffer_append_string_len(b, !hctx->conf.header.force_http10
	                            ? " HTTP/1.1" : " HTTP/1.0",
	                            sizeof(" HTTP/1.1")-1);

	if (hctx->conf.replace_http_host && !buffer_is_blank(hctx->gw.host->id)) {
		if (hctx->gw.conf.debug > 1) {
			log_error(r->conf.errh, __FILE__, __LINE__,
			  "proxy - using \"%s\" as HTTP Host", hctx->gw.host->id->ptr);
		}
		buffer_append_str2(b, CONST_STR_LEN("\r\nHost: "),
		                      BUF_PTR_LEN(hctx->gw.host->id));
	} else if (r->http_host && !buffer_is_unset(r->http_host)) {
		buffer_append_str2(b, CONST_STR_LEN("\r\nHost: "),
		                      BUF_PTR_LEN(r->http_host));
		if (remap_headers) {
			size_t alen = buffer_clen(r->http_host);
			http_header_remap_host(b, buffer_clen(b) - alen, &hctx->conf.header, 1, alen);
		}
	} else {
		/* no Host header available; must send HTTP/1.0 request */
		b->ptr[b->used-2] = '0'; /*(overwrite end of request line)*/
	}

	if (hctx->gw.gw_mode == GW_AUTHORIZER) {
		buffer_append_string_len(b, CONST_STR_LEN("\r\nContent-Length: 0"));
	}
	else if (r->reqbody_length > 0
	         || (0 == r->reqbody_length
		     && !http_method_get_or_head(r->http_method))) {
		/* set Content-Length if client sent Transfer-Encoding: chunked
		 * and not streaming to backend (request body has been fully received) */
		const buffer *vb = http_header_request_get(r, HTTP_HEADER_CONTENT_LENGTH, CONST_STR_LEN("Content-Length"));
		if (NULL == vb) {
			buffer_append_int(
			  http_header_request_set_ptr(r, HTTP_HEADER_CONTENT_LENGTH,
			                              CONST_STR_LEN("Content-Length")),
			  r->reqbody_length);
		}
	}
	else if (r->h2_connect_ext) {
	}
	else if (r->reqbody_length < 0
	         && (r->conf.stream_request_body
	             & (FDEVENT_STREAM_REQUEST | FDEVENT_STREAM_REQUEST_BUFMIN))) {
		if (__builtin_expect( (hctx->conf.header.force_http10), 0)) {
			if (-1 == r->reqbody_length)
				return http_response_reqbody_read_error(r, 411);
		}
		else {
			hctx->gw.stdin_append = proxy_stdin_append; /* stream chunked body */
			buffer_append_string_len(b, CONST_STR_LEN("\r\nTransfer-Encoding: chunked"));
		}
	}

	/* "Forwarded" and legacy X- headers */
	proxy_set_Forwarded(r->con, r, hctx->conf.forwarded);

	/* request header */
	const buffer *connhdr = NULL;
	const buffer *te = NULL;
	const buffer *upgrade = NULL;
	for (size_t i = 0, used = r->rqst_headers.used; i < used; ++i) {
		const data_string * const ds = (data_string *)r->rqst_headers.data[i];
		switch (ds->ext) {
		default:
			break;
		case HTTP_HEADER_HOST:
			continue; /*(handled further above)*/
		case HTTP_HEADER_CONTENT_LENGTH:
			if (hctx->gw.gw_mode == GW_AUTHORIZER)
				continue; /*(handled further above)*/
			break;
		case HTTP_HEADER_OTHER:
			if (__builtin_expect( ('p' == (ds->key.ptr[0] | 0x20)), 0)) {
				if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Proxy-Connection"))) continue;
				/* Do not emit HTTP_PROXY in environment.
				 * Some executables use HTTP_PROXY to configure
				 * outgoing proxy.  See also https://httpoxy.org/ */
				if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Proxy"))) continue;
			}
			break;
		case HTTP_HEADER_TE:
			if (hctx->conf.header.force_http10 || r->http_version == HTTP_VERSION_1_0) continue;
			/* ignore if not exactly "trailers" */
			if (!buffer_eq_icase_slen(&ds->value, CONST_STR_LEN("trailers"))) continue;
			/*if (!buffer_is_blank(&ds->value)) te = &ds->value;*/
			te = &ds->value; /*("trailers")*/
			break;
		case HTTP_HEADER_UPGRADE:
			/*(already unset in gw_check_extension if not allowed)*/
			if (hctx->conf.header.force_http10) continue;
			if (!buffer_is_blank(&ds->value)) upgrade = &ds->value;
			break;
		case HTTP_HEADER_CONNECTION:
			connhdr = &ds->value;
			continue;
		case HTTP_HEADER_SET_COOKIE:
			continue; /*(response header only; avoid accidental reflection)*/
		}

		const uint32_t klen = buffer_clen(&ds->key);
		const uint32_t vlen = buffer_clen(&ds->value);
		if (0 == klen || 0 == vlen) continue;
		char * restrict s = buffer_extend(b, klen+vlen+4);
		s[0] = '\r';
		s[1] = '\n';
		memcpy(s+2, ds->key.ptr, klen);
		s += 2+klen;
		s[0] = ':';
		s[1] = ' ';
		memcpy(s+2, ds->value.ptr, vlen);

		if (!remap_headers) continue;

		/* check for hdrs for which to remap URIs in-place after append to b */

		switch (klen) {
		default:
			continue;
	      #if 0 /* "URI" is HTTP response header (non-standard; historical in Apache) */
		case 3:
			if (ds->ext == HTTP_HEADER_OTHER && buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("URI"))) break;
			continue;
	      #endif
	      #if 0 /* "Location" is HTTP response header */
		case 8:
			if (ds->ext == HTTP_HEADER_LOCATION) break;
			continue;
	      #endif
		case 11: /* "Destination" is WebDAV request header */
			if (ds->ext == HTTP_HEADER_OTHER && buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Destination"))) break;
			continue;
		case 16: /* "Content-Location" may be HTTP request or response header */
			if (ds->ext == HTTP_HEADER_CONTENT_LOCATION) break;
			continue;
		}

		http_header_remap_uri(b, buffer_clen(b) - vlen, &hctx->conf.header, 1);
	}

	if (connhdr && !hctx->conf.header.force_http10 && r->http_version >= HTTP_VERSION_1_1
	    && !buffer_eq_icase_slen(connhdr, CONST_STR_LEN("close"))) {
		/* mod_proxy always sends Connection: close to backend */
		buffer_append_string_len(b, CONST_STR_LEN("\r\nConnection: close"));
		/* (future: might be pedantic and also check Connection header for each
		 * token using http_header_str_contains_token() */
		if (te)
			buffer_append_string_len(b, CONST_STR_LEN(", te"));
		if (upgrade)
			buffer_append_string_len(b, CONST_STR_LEN(", upgrade"));
		buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));
	}
	else if (r->h2_connect_ext) {
		/* https://datatracker.ietf.org/doc/html/rfc6455#section-4.1
		 * 7. The request MUST include a header field with the name
		 *    |Sec-WebSocket-Key|.  The value of this header field MUST be a
		 *    nonce consisting of a randomly selected 16-byte value that has
		 *    been base64-encoded (see Section 4 of [RFC4648]).  The nonce
		 *    MUST be selected randomly for each connection.
		 * Note: Sec-WebSocket-Key is not used in RFC8441;
		 *       include Sec-WebSocket-Key for HTTP/1.1 compatibility;
		 *       !!not random!! base64-encoded "0000000000000000" */
		if (!http_header_request_get(r, HTTP_HEADER_OTHER,
		                             CONST_STR_LEN("Sec-WebSocket-Key")))
			buffer_append_string_len(b, CONST_STR_LEN(
			  "\r\nSec-WebSocket-Key: MDAwMDAwMDAwMDAwMDAwMA=="));
		buffer_append_string_len(b, CONST_STR_LEN(
		                              "\r\nUpgrade: websocket"
		                              "\r\nConnection: close, upgrade\r\n\r\n"));
	}
	else    /* mod_proxy always sends Connection: close to backend */
		buffer_append_string_len(b, CONST_STR_LEN("\r\nConnection: close\r\n\r\n"));

	hctx->gw.wb_reqlen = buffer_clen(b);
	chunkqueue_prepend_buffer_commit(&hctx->gw.wb);

	if (r->reqbody_length && hctx->gw.gw_mode != GW_AUTHORIZER) {
		if (r->reqbody_length > 0)
			hctx->gw.wb_reqlen += r->reqbody_length; /* total req size */
		else /* as-yet-unknown total request size (Transfer-Encoding: chunked)*/
			hctx->gw.wb_reqlen = -hctx->gw.wb_reqlen;
		if (hctx->gw.stdin_append == proxy_stdin_append)
			proxy_stdin_append(&hctx->gw);
		else
			chunkqueue_append_chunkqueue(&hctx->gw.wb, &r->reqbody_queue);
	}

	plugin_stats_inc("proxy.requests");
	return HANDLER_GO_ON;
}


static handler_t proxy_create_env_connect(gw_handler_ctx *gwhctx) {
	handler_ctx *hctx = (handler_ctx *)gwhctx;
	request_st * const r = hctx->gw.r;
	r->http_status = 200; /* OK */
	r->resp_body_started = 1;
	gw_set_transparent(&hctx->gw);
	http_response_upgrade_read_body_unknown(r);

	plugin_stats_inc("proxy.requests");
	return HANDLER_GO_ON;
}


static handler_t proxy_response_headers(request_st * const r, struct http_response_opts_t *opts) {
    /* response headers just completed */
    handler_ctx *hctx = (handler_ctx *)opts->pdata;
    http_header_remap_opts * const remap_hdrs = &hctx->conf.header;

    /*(see gw_response_headers_upgrade())*/
    if (opts->upgrade == 2)
        gw_set_transparent(&hctx->gw);

    /* rewrite paths, if needed */

    if (NULL == remap_hdrs->urlpaths && NULL == remap_hdrs->hosts_response)
        return HANDLER_GO_ON;

    buffer *vb;
    if (light_btst(r->resp_htags, HTTP_HEADER_LOCATION)) {
        vb = http_header_response_get(r, HTTP_HEADER_LOCATION,
                                         CONST_STR_LEN("Location"));
        if (vb) http_header_remap_uri(vb, 0, remap_hdrs, 0);
    }
    if (light_btst(r->resp_htags, HTTP_HEADER_CONTENT_LOCATION)) {
        vb = http_header_response_get(r, HTTP_HEADER_CONTENT_LOCATION,
                                         CONST_STR_LEN("Content-Location"));
        if (vb) http_header_remap_uri(vb, 0, remap_hdrs, 0);
    }
    if (light_btst(r->resp_htags, HTTP_HEADER_SET_COOKIE)) {
        vb = http_header_response_get(r, HTTP_HEADER_SET_COOKIE,
                                         CONST_STR_LEN("Set-Cookie"));
        if (vb) http_header_remap_setcookie(vb, 0, remap_hdrs);
    }

    return HANDLER_GO_ON;
}

static handler_t mod_proxy_check_extension(request_st * const r, void *p_d) {
	if (NULL != r->handler_module) return HANDLER_GO_ON;

	plugin_config pconf;
	mod_proxy_patch_config(r, p_d, &pconf);
	if (NULL == pconf.gw.exts) return HANDLER_GO_ON;

	handler_t rc =
	  gw_check_extension(r, (gw_plugin_config *)&pconf,
	                     p_d, 1, sizeof(handler_ctx));
	if (HANDLER_GO_ON != rc) return rc;

	const plugin_data * const p = p_d;
	if (r->handler_module == p->self) {
		handler_ctx *hctx = r->plugin_ctx[p->id];
		hctx->gw.create_env = proxy_create_env;
		hctx->gw.response = chunk_buffer_acquire();
		hctx->gw.opts.backend = BACKEND_PROXY;
		hctx->gw.opts.pdata = hctx;
		hctx->gw.opts.headers = proxy_response_headers;

		memcpy(&hctx->conf, &pconf, sizeof(plugin_config));
		hctx->conf.header.http_host = r->http_host;
		/* mod_proxy currently sends all backend requests as http.
		 * https-remap is a flag since it might not be needed if backend
		 * honors Forwarded or X-Forwarded-Proto headers, e.g. by using
		 * lighttpd mod_extforward or similar functionality in backend*/
		if (hctx->conf.header.https_remap) {
			hctx->conf.header.https_remap =
			  buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https"));
		}

		if (r->http_method == HTTP_METHOD_CONNECT) {
			/*(note: not requiring HTTP/1.1 due to too many non-compliant
			 * clients such as 'openssl s_client')*/
			if (r->h2_connect_ext
			    && (hctx->conf.header.connect_method =
			          hctx->conf.header.upgrade)) { /*(405 if not set)*/
				/*(not bothering to check (!hctx->conf.header.force_http10))*/
				/*hctx->gw.create_env = proxy_create_env;*/ /*(preserve)*/
			}
			else if (hctx->conf.header.connect_method) {
				hctx->gw.create_env = proxy_create_env_connect;
			}
			else {
				return http_status_set_err(r, 405); /* Method Not Allowed */
			}
		}
	}

	return HANDLER_GO_ON;
}


__attribute_cold__
__declspec_dllexport__
int mod_proxy_plugin_init(plugin *p);
int mod_proxy_plugin_init(plugin *p) {
	p->version      = LIGHTTPD_VERSION_ID;
	p->name         = "proxy";

	p->init         = mod_proxy_init;
	p->cleanup      = mod_proxy_free;
	p->set_defaults = mod_proxy_set_defaults;
	p->handle_request_reset    = gw_handle_request_reset;
	p->handle_uri_clean        = mod_proxy_check_extension;
	p->handle_subrequest       = gw_handle_subrequest;
	p->handle_trigger          = gw_handle_trigger;
	p->handle_waitpid          = gw_handle_waitpid_cb;

	return 0;
}
