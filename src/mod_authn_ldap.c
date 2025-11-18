/*
 * mod_authn_ldap - HTTP Auth LDAP backend
 *
 * Fully-rewritten from original
 * Copyright(c) 2016 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
#include "first.h"

#include <stdlib.h>
#include <string.h>

#include <ldap.h>

#include "mod_auth_api.h"
#include "base.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    LDAP *ldap;
    log_error_st *errh;
    const char *auth_ldap_hostname;
    const char *auth_ldap_binddn;
    const char *auth_ldap_bindpw;
    const char *auth_ldap_cafile;
    int auth_ldap_starttls;
    struct timeval auth_ldap_timeout;
} plugin_config_ldap;

typedef struct {
    plugin_config_ldap *ldc;
    const char *auth_ldap_basedn;
    const buffer *auth_ldap_filter;
    const buffer *auth_ldap_groupmember;
    int auth_ldap_allow_empty_pw;

    int auth_ldap_starttls;
    const char *auth_ldap_binddn;
    const char *auth_ldap_bindpw;
    const char *auth_ldap_cafile;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;

    buffer ldap_filter;
} plugin_data;

static const char *default_cafile;

static handler_t mod_authn_ldap_basic(request_st * const r, void *p_d, const http_auth_require_t *require, const buffer *username, const char *pw);

INIT_FUNC(mod_authn_ldap_init) {
    static http_auth_backend_t http_auth_backend_ldap =
      { "ldap", mod_authn_ldap_basic, NULL, NULL };
    plugin_data *p = ck_calloc(1, sizeof(*p));

    /* register http_auth_backend_ldap */
    http_auth_backend_ldap.p_d = p;
    http_auth_backend_set(&http_auth_backend_ldap);

    return p;
}

FREE_FUNC(mod_authn_ldap_free) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.ldap.hostname */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_config_ldap *s = cpv->v.v;
                    if (NULL != s->ldap) ldap_unbind_ext_s(s->ldap, NULL, NULL);
                    free(s);
                }
                break;
              default:
                break;
            }
        }
    }

    free(p->ldap_filter.ptr);
    default_cafile = NULL;
}

static void mod_authn_ldap_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.ldap.hostname */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ldc = cpv->v.v;
        break;
      case 1: /* auth.backend.ldap.base-dn */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->auth_ldap_basedn = cpv->v.v;
        break;
      case 2: /* auth.backend.ldap.filter */
        pconf->auth_ldap_filter = cpv->v.v;
        break;
      case 3: /* auth.backend.ldap.ca-file */
        pconf->auth_ldap_cafile = cpv->v.v;
        break;
      case 4: /* auth.backend.ldap.starttls */
        pconf->auth_ldap_starttls = (int)cpv->v.u;
        break;
      case 5: /* auth.backend.ldap.bind-dn */
        pconf->auth_ldap_binddn = cpv->v.v;
        break;
      case 6: /* auth.backend.ldap.bind-pw */
        pconf->auth_ldap_bindpw = cpv->v.v;
        break;
      case 7: /* auth.backend.ldap.allow-empty-pw */
        pconf->auth_ldap_allow_empty_pw = (int)cpv->v.u;
        break;
      case 8: /* auth.backend.ldap.groupmember */
        pconf->auth_ldap_groupmember = cpv->v.b;
        break;
      case 9: /* auth.backend.ldap.timeout */
        /*(not implemented as any-scope override;
         * supported in same scope as auth.backend.ldap.hostname)*/
        /*pconf->auth_ldap_timeout = cpv->v.b;*/
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_authn_ldap_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_authn_ldap_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_authn_ldap_patch_config (request_st * const r, const plugin_data * const p, plugin_config * const pconf) {
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_ldap_merge_config(pconf,
                                        p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

/*(copied from mod_vhostdb_ldap.c)*/
static void mod_authn_add_scheme (server *srv, buffer *host)
{
    if (!buffer_is_blank(host)) {
        /* reformat hostname(s) as LDAP URIs (scheme://host:port) */
        static const char *schemes[] = {
          "ldap://", "ldaps://", "ldapi://", "cldap://"
        };
        char *b, *e = host->ptr;
        buffer * const tb = srv->tmp_buf;
        buffer_clear(tb);
        while (*(b = e)) {
            unsigned int j;
            while (*b==' '||*b=='\t'||*b=='\r'||*b=='\n'||*b==',') ++b;
            if (*b == '\0') break;
            e = b;
            while (*e!=' '&&*e!='\t'&&*e!='\r'&&*e!='\n'&&*e!=','&&*e!='\0')
                ++e;
            if (!buffer_is_blank(tb))
                buffer_append_char(tb, ',');
            for (j = 0; j < sizeof(schemes)/sizeof(char *); ++j) {
                if (buffer_eq_icase_ssn(b, schemes[j], strlen(schemes[j]))) {
                    break;
                }
            }
            if (j == sizeof(schemes)/sizeof(char *))
                buffer_append_string_len(tb, CONST_STR_LEN("ldap://"));
            buffer_append_string_len(tb, b, (size_t)(e - b));
        }
        buffer_copy_buffer(host, tb);
    }
}

__attribute_cold__
static void mod_authn_ldap_err(log_error_st *errh, const char *file, unsigned long line, const char *fn, int err);

SETDEFAULTS_FUNC(mod_authn_ldap_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.ldap.hostname"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.base-dn"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.filter"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.ca-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.starttls"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.bind-dn"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.bind-pw"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.allow-empty-pw"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.groupmember"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.ldap.timeout"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_ldap"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        plugin_config_ldap *ldc = NULL;
        char *binddn = NULL, *bindpw = NULL, *cafile = NULL;
        int starttls = 0;
        long timeout = 2000000; /* set 2 sec default timeout (not infinite) */
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.ldap.hostname */
                if (!buffer_is_blank(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    mod_authn_add_scheme(srv, b);
                    ldc = ck_calloc(1, sizeof(plugin_config_ldap));
                    ldc->errh = srv->errh;
                    ldc->auth_ldap_hostname = b->ptr;
                    cpv->v.v = ldc;
                }
                else {
                    cpv->v.v = NULL;
                }
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* auth.backend.ldap.base-dn */
                cpv->vtype = T_CONFIG_LOCAL;
                cpv->v.v = !buffer_is_blank(cpv->v.b)
                  ? cpv->v.b->ptr
                  : NULL;
                break;
              case 2: /* auth.backend.ldap.filter */
                if (!buffer_is_blank(cpv->v.b)) {
                    buffer *b;
                    *(const buffer **)&b = cpv->v.b;
                    if (*b->ptr != ',') {
                        /*(translate $ to ? for consistency w/ other modules)*/
                        char *d = b->ptr;
                        for (; NULL != (d = strchr(d, '$')); ++d) *d = '?';
                        if (NULL == strchr(b->ptr, '?')) {
                            log_error(srv->errh, __FILE__, __LINE__,
                              "ldap: %s is missing a replace-operator '?'",
                              cpk[cpv->k_id].k);
                            return HANDLER_ERROR;
                        }
                    }
                    cpv->v.v = b;
                }
                else {
                    cpv->v.v = NULL;
                }
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 3: /* auth.backend.ldap.ca-file */
                cafile = !buffer_is_blank(cpv->v.b)
                  ? cpv->v.b->ptr
                  : NULL;
                cpv->vtype = T_CONFIG_LOCAL;
                cpv->v.v = cafile;
                break;
              case 4: /* auth.backend.ldap.starttls */
                starttls = (int)cpv->v.u;
                break;
              case 5: /* auth.backend.ldap.bind-dn */
                binddn = !buffer_is_blank(cpv->v.b)
                  ? cpv->v.b->ptr
                  : NULL;
                cpv->vtype = T_CONFIG_LOCAL;
                cpv->v.v = binddn;
                break;
              case 6: /* auth.backend.ldap.bind-pw */
                cpv->vtype = T_CONFIG_LOCAL;
                cpv->v.v = bindpw = cpv->v.b->ptr;
                break;
              case 7: /* auth.backend.ldap.allow-empty-pw */
                break;
              case 8: /* auth.backend.ldap.groupmember */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 9: /* auth.backend.ldap.timeout */
                timeout = strtol(cpv->v.b->ptr, NULL, 10);
                break;
              default:/* should not happen */
                break;
            }
        }

        if (ldc) {
            ldc->auth_ldap_binddn = binddn;
            ldc->auth_ldap_bindpw = bindpw;
            ldc->auth_ldap_cafile = cafile;
            ldc->auth_ldap_starttls = starttls;
            ldc->auth_ldap_timeout.tv_sec  = timeout / 1000000;
            ldc->auth_ldap_timeout.tv_usec = timeout % 1000000;
        }
    }

    static const struct { const char *ptr; uint32_t used; uint32_t size; }
      memberUid = { "memberUid", sizeof("memberUid"), 0 };
    *(const buffer **)&p->defaults.auth_ldap_groupmember =
      (const buffer *)&memberUid;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_ldap_merge_config(&p->defaults, cpv);
    }

    if (p->defaults.auth_ldap_starttls && p->defaults.auth_ldap_cafile) {
        const int ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE,
                                        p->defaults.auth_ldap_cafile);
        if (LDAP_OPT_SUCCESS != ret) {
            mod_authn_ldap_err(srv->errh, __FILE__, __LINE__,
              "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE)", ret);
            return HANDLER_ERROR;
        }
        default_cafile = p->defaults.auth_ldap_cafile;
    }

    return HANDLER_GO_ON;
}

__attribute_cold__
static void mod_authn_ldap_err(log_error_st *errh, const char *file, unsigned long line, const char *fn, int err)
{
    log_error(errh, file, line, "ldap: %s: %s", fn, ldap_err2string(err));
}

__attribute_cold__
static void mod_authn_ldap_opt_err(log_error_st *errh, const char *file, unsigned long line, const char *fn, LDAP *ld)
{
    int err;
    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
    mod_authn_ldap_err(errh, file, line, fn, err);
}

static void mod_authn_append_ldap_dn_escape(buffer * const filter, const buffer * const raw) {
    /* [RFC4514] 2.4 Converting an AttributeValue from ASN.1 to a String
     *
     * https://www.ldap.com/ldap-dns-and-rdns
     * http://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
     */
    const char * const b = raw->ptr;
    const size_t rlen = buffer_clen(raw);
    if (0 == rlen) return;

    if (b[0] == ' ') { /* || b[0] == '#' handled below for MS Active Directory*/
        /* escape leading ' ' */
        buffer_append_char(filter, '\\');
    }

    for (size_t i = 0; i < rlen; ++i) {
        size_t len = i;
        int bs = 0;
        do {
            /* encode all UTF-8 chars with high bit set
             * (instead of validating UTF-8 and escaping only invalid UTF-8) */
            if (((unsigned char *)b)[len] > 0x7f)
                break;
            switch (b[len]) {
              default:
                continue;
              case '"': case '+': case ',': case ';': case '\\':
              case '<': case '>':
              case '=': case '#': /* (for MS Active Directory) */
                bs = 1;
                break;
              case '\0':
                break;
            }
            break;
        } while (++len < rlen);
        len -= i;

        if (len) {
            buffer_append_string_len(filter, b+i, len);
            if ((i += len) == rlen) break;
        }

        if (bs) {
            buffer_append_char(filter, '\\');
            buffer_append_char(filter, b[i]);
        }
        else {
            /* escape NUL ('\0') (and all UTF-8 chars with high bit set) */
            char *f;
            f = buffer_extend(filter, 3);
            f[0] = '\\';
            f[1] = "0123456789abcdef"[(((unsigned char *)b)[i] >> 4) & 0xf];
            f[2] = "0123456789abcdef"[(((unsigned char *)b)[i]     ) & 0xf];
        }
    }

    if (rlen > 1 && b[rlen-1] == ' ') {
        /* escape trailing ' ' */
        filter->ptr[buffer_clen(filter)-1] = '\\';
        buffer_append_char(filter, ' ');
    }
}

static void mod_authn_append_ldap_filter_escape(buffer * const filter, const buffer * const raw) {
    /* [RFC4515] 3. String Search Filter Definition
     *
     * [...]
     *
     * The <valueencoding> rule ensures that the entire filter string is a
     * valid UTF-8 string and provides that the octets that represent the
     * ASCII characters "*" (ASCII 0x2a), "(" (ASCII 0x28), ")" (ASCII
     * 0x29), "\" (ASCII 0x5c), and NUL (ASCII 0x00) are represented as a
     * backslash "\" (ASCII 0x5c) followed by the two hexadecimal digits
     * representing the value of the encoded octet.
     *
     * [...]
     *
     * As indicated by the <valueencoding> rule, implementations MUST escape
     * all octets greater than 0x7F that are not part of a valid UTF-8
     * encoding sequence when they generate a string representation of a
     * search filter.  Implementations SHOULD accept as input strings that
     * are not valid UTF-8 strings.  This is necessary because RFC 2254 did
     * not clearly define the term "string representation" (and in
     * particular did not mention that the string representation of an LDAP
     * search filter is a string of UTF-8-encoded Unicode characters).
     *
     *
     * https://www.ldap.com/ldap-filters
     * Although not required, you may escape any other characters that you want
     * in the assertion value (or substring component) of a filter. This may be
     * accomplished by prefixing the hexadecimal representation of each byte of
     * the UTF-8 encoding of the character to escape with a backslash character.
     */
    const char * const b = raw->ptr;
    const size_t rlen = buffer_clen(raw);
    for (size_t i = 0; i < rlen; ++i) {
        size_t len = i;
        char *f;
        do {
            /* encode all UTF-8 chars with high bit set
             * (instead of validating UTF-8 and escaping only invalid UTF-8) */
            if (((unsigned char *)b)[len] > 0x7f)
                break;
            switch (b[len]) {
              default:
                continue;
              case '\0': case '(': case ')': case '*': case '\\':
                break;
            }
            break;
        } while (++len < rlen);
        len -= i;

        if (len) {
            buffer_append_string_len(filter, b+i, len);
            if ((i += len) == rlen) break;
        }

        /* escape * ( ) \ NUL ('\0') (and all UTF-8 chars with high bit set) */
        f = buffer_extend(filter, 3);
        f[0] = '\\';
        f[1] = "0123456789abcdef"[(((unsigned char *)b)[i] >> 4) & 0xf];
        f[2] = "0123456789abcdef"[(((unsigned char *)b)[i]     ) & 0xf];
    }
}

static LDAP * mod_authn_ldap_host_init(log_error_st *errh, plugin_config_ldap *s) {
    LDAP *ld;
    int ret;

    if (NULL == s->auth_ldap_hostname) return NULL;

    if (LDAP_SUCCESS != ldap_initialize(&ld, s->auth_ldap_hostname)) {
        log_perror(errh, __FILE__, __LINE__, "ldap: ldap_initialize()");
        return NULL;
    }

    ret = LDAP_VERSION3;
    ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ret);
    if (LDAP_OPT_SUCCESS != ret) {
        mod_authn_ldap_err(errh, __FILE__, __LINE__, "ldap_set_option()", ret);
        ldap_destroy(ld);
        return NULL;
    }

    /* restart ldap functions if interrupted by a signal, e.g. SIGCHLD */
    ldap_set_option(ld, LDAP_OPT_RESTART, LDAP_OPT_ON);

  #ifdef LDAP_OPT_NETWORK_TIMEOUT /* OpenLDAP-specific */
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &s->auth_ldap_timeout);
  #endif

  #ifdef LDAP_OPT_TIMEOUT /* OpenLDAP-specific; OpenLDAP 2.4+ */
    ldap_set_option(ld, LDAP_OPT_TIMEOUT, &s->auth_ldap_timeout);
  #endif

    if (s->auth_ldap_starttls) {
        /* if no CA file is given, it is ok, as we will use encryption
         * if the server requires a CAfile it will tell us */
        if (s->auth_ldap_cafile
            && (!default_cafile
                || 0 != strcmp(s->auth_ldap_cafile, default_cafile))) {
            ret = ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE,
                                  s->auth_ldap_cafile);
            if (LDAP_OPT_SUCCESS != ret) {
                mod_authn_ldap_err(errh, __FILE__, __LINE__,
                                   "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE)",
                                   ret);
                ldap_destroy(ld);
                return NULL;
            }
        }

        ret = ldap_start_tls_s(ld, NULL,  NULL);
        if (LDAP_OPT_SUCCESS != ret) {
            mod_authn_ldap_err(errh,__FILE__,__LINE__,"ldap_start_tls_s()",ret);
            ldap_destroy(ld);
            return NULL;
        }
    }

    return ld;
}

static int mod_authn_ldap_bind(log_error_st *errh, LDAP *ld, const char *dn, const char *pw) {
    struct berval creds;
    int ret;

    if (NULL != pw) {
        *((const char **)&creds.bv_val) = pw; /*(cast away const)*/
        creds.bv_len = strlen(pw);
    } else {
        creds.bv_val = NULL;
        creds.bv_len = 0;
    }

    /* RFE: add functionality: LDAP_SASL_EXTERNAL (or GSS-SPNEGO, etc.) */

    ret = ldap_sasl_bind_s(ld,dn,LDAP_SASL_SIMPLE,&creds,NULL,NULL,NULL);
    if (ret != LDAP_SUCCESS) {
        mod_authn_ldap_err(errh, __FILE__, __LINE__, "ldap_sasl_bind_s()", ret);
    }

    return ret;
}

static int mod_authn_ldap_rebind_proc (LDAP *ld, LDAP_CONST char *url, ber_tag_t ldap_request, ber_int_t msgid, void *params) {
    const plugin_config_ldap *s = (const plugin_config_ldap *)params;
    UNUSED(url);
    UNUSED(ldap_request);
    UNUSED(msgid);
    return s->auth_ldap_binddn
      ? mod_authn_ldap_bind(s->errh, ld,
                            s->auth_ldap_binddn,
                            s->auth_ldap_bindpw)
      : mod_authn_ldap_bind(s->errh, ld, NULL, NULL);
}

static LDAPMessage * mod_authn_ldap_search(log_error_st *errh, plugin_config_ldap *s, const char *base, const char *filter) {
    LDAPMessage *lm = NULL;
    char *attrs[] = { LDAP_NO_ATTRS, NULL };
    int ret;

    /*
     * 1. connect anonymously (if not already connected)
     *    (ldap connection is kept open unless connection-level error occurs)
     * 2. issue search using filter
     */

    if (s->ldap != NULL) {
        ret = ldap_search_ext_s(s->ldap, base, LDAP_SCOPE_SUBTREE, filter,
                                attrs, 0, NULL, NULL, NULL, 0, &lm);
        if (LDAP_SUCCESS == ret) {
            return lm;
        } else if (LDAP_SERVER_DOWN != ret) {
            /* try again (or initial request);
             * ldap lib sometimes fails for the first call but reconnects */
            ret = ldap_search_ext_s(s->ldap, base, LDAP_SCOPE_SUBTREE, filter,
                                    attrs, 0, NULL, NULL, NULL, 0, &lm);
            if (LDAP_SUCCESS == ret) {
                return lm;
            }
        }

        ldap_unbind_ext_s(s->ldap, NULL, NULL);
    }

    s->ldap = mod_authn_ldap_host_init(errh, s);
    if (NULL == s->ldap) {
        return NULL;
    }

    ldap_set_rebind_proc(s->ldap, mod_authn_ldap_rebind_proc, s);
    ret = mod_authn_ldap_rebind_proc(s->ldap, NULL, 0, 0, s);
    if (LDAP_SUCCESS != ret) {
        ldap_destroy(s->ldap);
        s->ldap = NULL;
        return NULL;
    }

    ret = ldap_search_ext_s(s->ldap, base, LDAP_SCOPE_SUBTREE, filter,
                            attrs, 0, NULL, NULL, NULL, 0, &lm);
    if (LDAP_SUCCESS != ret) {
        log_error(errh, __FILE__, __LINE__,
          "ldap: %s; filter: %s", ldap_err2string(ret), filter);
        ldap_unbind_ext_s(s->ldap, NULL, NULL);
        s->ldap = NULL;
        return NULL;
    }

    return lm;
}

static char * mod_authn_ldap_get_dn(log_error_st *errh, plugin_config_ldap *s, const char *base, const char *filter) {
    LDAP *ld;
    LDAPMessage *lm, *first;
    char *dn;
    int count;

    lm = mod_authn_ldap_search(errh, s, base, filter);
    if (NULL == lm) {
        return NULL;
    }

    ld = s->ldap; /*(must be after mod_authn_ldap_search(); might reconnect)*/

    count = ldap_count_entries(ld, lm);
    if (0 == count) { /*(no entries found)*/
        ldap_msgfree(lm);
        return NULL;
    } else if (count > 1) {
        log_error(errh, __FILE__, __LINE__,
          "ldap: more than one record returned.  "
          "you might have to refine the filter: %s", filter);
    }

    if (NULL == (first = ldap_first_entry(ld, lm))) {
        mod_authn_ldap_opt_err(errh,__FILE__,__LINE__,"ldap_first_entry()",ld);
        ldap_msgfree(lm);
        return NULL;
    }

    if (NULL == (dn = ldap_get_dn(ld, first))) {
        mod_authn_ldap_opt_err(errh,__FILE__,__LINE__,"ldap_get_dn()",ld);
        ldap_msgfree(lm);
        return NULL;
    }

    ldap_msgfree(lm);
    return dn;
}

static handler_t mod_authn_ldap_memberOf(log_error_st *errh, plugin_config *s, const http_auth_require_t *require, const buffer *username, const char *userdn) {
    if (!s->auth_ldap_groupmember) return HANDLER_ERROR;
    const array *groups = &require->group;
    buffer *filter = buffer_init();
    handler_t rc = HANDLER_ERROR;

    buffer_append_char(filter, '(');
    buffer_append_string_buffer(filter, s->auth_ldap_groupmember);
    buffer_append_char(filter, '=');
    if (buffer_is_equal_string(s->auth_ldap_groupmember,
                               CONST_STR_LEN("member"))) {
        buffer_append_string(filter, userdn);
    } else { /*(assume "memberUid"; consider validating in SETDEFAULTS_FUNC)*/
        mod_authn_append_ldap_filter_escape(filter, username);
    }
    buffer_append_char(filter, ')');

    plugin_config_ldap * const ldc = s->ldc;
    for (size_t i = 0; i < groups->used; ++i) {
        const char *base = ((data_string *)groups->data[i])->value.ptr;
        LDAPMessage *lm = mod_authn_ldap_search(errh, ldc, base, filter->ptr);
        if (NULL != lm) {
            int count = ldap_count_entries(ldc->ldap, lm);
            ldap_msgfree(lm);
            if (count > 0) {
                rc = HANDLER_GO_ON;
                break;
            }
        }
    }

    buffer_free(filter);
    return rc;
}

static handler_t mod_authn_ldap_basic(request_st * const r, void *p_d, const http_auth_require_t * const require, const buffer * const username, const char * const pw) {
    LDAP *ld;
    char *dn;

    plugin_config pconf;
    mod_authn_ldap_patch_config(r, p_d, &pconf);

    if (pw[0] == '\0' && !pconf.auth_ldap_allow_empty_pw)
        return HANDLER_ERROR;

    const buffer * const template = pconf.auth_ldap_filter;
    if (NULL == template)
        return HANDLER_ERROR;

    log_error_st * const errh = r->conf.errh;

    /* build filter to get DN for uid = username */
    /* thread-safety todo: ldap_filter per-thread or allocate or borrow chunk */
    plugin_data *p = (plugin_data *)p_d;
    buffer * const ldap_filter = &p->ldap_filter;
    buffer_clear(ldap_filter);
    if (*template->ptr == ',') {
        /* special-case filter template beginning with ',' to be explicit DN */
        buffer_append_string_len(ldap_filter, CONST_STR_LEN("uid="));
        mod_authn_append_ldap_dn_escape(ldap_filter, username);
        buffer_append_string_buffer(ldap_filter, template);
        dn = ldap_filter->ptr;
    }
    else {
        for (const char *b = template->ptr, *d; *b; b = d+1) {
            if (NULL != (d = strchr(b, '?'))) {
                buffer_append_string_len(ldap_filter, b, (size_t)(d - b));
                mod_authn_append_ldap_filter_escape(ldap_filter, username);
            }
            else {
                d = template->ptr + buffer_clen(template);
                buffer_append_string_len(ldap_filter, b, (size_t)(d - b));
                break;
            }
        }

        /* ldap_search for DN (synchronous; blocking) */
        dn = mod_authn_ldap_get_dn(errh, pconf.ldc,
                                   pconf.auth_ldap_basedn, ldap_filter->ptr);
        if (NULL == dn) return HANDLER_ERROR;
    }

    /*(Check ldc here rather than further up to preserve historical behavior
     * where pconf.ldc above (was p->anon_conf above) is set of directives in
     * same context as auth_ldap_hostname.  Preference: admin intentions are
     * clearer if directives are always together in a set in same context)*/

    plugin_config_ldap * const ldc_base = pconf.ldc;
    plugin_config_ldap ldc_custom;

    if ( pconf.ldc->auth_ldap_starttls != pconf.auth_ldap_starttls
        || pconf.ldc->auth_ldap_binddn != pconf.auth_ldap_binddn
        || pconf.ldc->auth_ldap_bindpw != pconf.auth_ldap_bindpw
        || pconf.ldc->auth_ldap_cafile != pconf.auth_ldap_cafile ) {
        ldc_custom.ldap = NULL;
        ldc_custom.errh = errh;
        ldc_custom.auth_ldap_hostname = ldc_base->auth_ldap_hostname;
        ldc_custom.auth_ldap_starttls = pconf.auth_ldap_starttls;
        ldc_custom.auth_ldap_binddn = pconf.auth_ldap_binddn;
        ldc_custom.auth_ldap_bindpw = pconf.auth_ldap_bindpw;
        ldc_custom.auth_ldap_cafile = pconf.auth_ldap_cafile;
        ldc_custom.auth_ldap_timeout= ldc_base->auth_ldap_timeout;
        pconf.ldc = &ldc_custom;
    }

    handler_t rc = HANDLER_ERROR;
    do {
        /* auth against LDAP server (synchronous; blocking) */

        ld = mod_authn_ldap_host_init(errh, pconf.ldc);
        if (NULL == ld)
            break;

        /* Disable referral tracking; target user should be in provided scope */
        int ret = ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
        if (LDAP_OPT_SUCCESS != ret) {
            mod_authn_ldap_err(errh,__FILE__,__LINE__,"ldap_set_option()",ret);
            break;
        }

        if (LDAP_SUCCESS != mod_authn_ldap_bind(errh, ld, dn, pw))
            break;

        ldap_unbind_ext_s(ld, NULL, NULL); /* disconnect */
        ld = NULL;

        if (http_auth_match_rules(require, username->ptr, NULL, NULL)) {
            rc = HANDLER_GO_ON; /* access granted */
        }
        else if (require->group.used) {
            /*(must not re-use ldap_filter, since it might be used for dn)*/
            rc = mod_authn_ldap_memberOf(errh, &pconf, require, username, dn);
        }
    } while (0);

    if (NULL != ld) ldap_destroy(ld);
    if (ldc_base != pconf.ldc && NULL != pconf.ldc->ldap)
        ldap_unbind_ext_s(pconf.ldc->ldap, NULL, NULL);
    if (dn != ldap_filter->ptr) ldap_memfree(dn);
    return rc;
}


__attribute_cold__
__declspec_dllexport__
int mod_authn_ldap_plugin_init(plugin *p);
int mod_authn_ldap_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "authn_ldap";
    p->init        = mod_authn_ldap_init;
    p->set_defaults = mod_authn_ldap_set_defaults;
    p->cleanup     = mod_authn_ldap_free;

    return 0;
}
