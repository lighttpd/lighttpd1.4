#include "first.h"

#include <ldap.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "base.h"
#include "http_vhostdb.h"
#include "log.h"
#include "plugin.h"

/*
 * virtual host plugin using LDAP for domain to directory lookups
 */

typedef struct {
    LDAP *ldap;
    buffer *filter;
    server *srv;

    const char *attr;
    const char *host;
    const char *basedn;
    const char *binddn;
    const char *bindpw;
    const char *cafile;
    unsigned short starttls;
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
    if (NULL != dbconf->ldap) ldap_unbind_ext_s(dbconf->ldap, NULL, NULL);
    free(dbconf);
}

/*(copied from mod_authn_ldap.c)*/
static void mod_vhostdb_dbconf_add_scheme (server *srv, buffer *host)
{
    if (!buffer_string_is_empty(host)) {
        /* reformat hostname(s) as LDAP URIs (scheme://host:port) */
        static const char *schemes[] = {
          "ldap://", "ldaps://", "ldapi://", "cldap://"
        };
        char *b, *e = host->ptr;
        buffer_clear(srv->tmp_buf);
        while (*(b = e)) {
            unsigned int j;
            while (*b==' '||*b=='\t'||*b=='\r'||*b=='\n'||*b==',') ++b;
            if (*b == '\0') break;
            e = b;
            while (*e!=' '&&*e!='\t'&&*e!='\r'&&*e!='\n'&&*e!=','&&*e!='\0')
                ++e;
            if (!buffer_string_is_empty(srv->tmp_buf))
                buffer_append_string_len(srv->tmp_buf, CONST_STR_LEN(","));
            for (j = 0; j < sizeof(schemes)/sizeof(char *); ++j) {
                if (buffer_eq_icase_ssn(b, schemes[j], strlen(schemes[j]))) {
                    break;
                }
            }
            if (j == sizeof(schemes)/sizeof(char *))
                buffer_append_string_len(srv->tmp_buf,
                                         CONST_STR_LEN("ldap://"));
            buffer_append_string_len(srv->tmp_buf, b, (size_t)(e - b));
        }
        buffer_copy_buffer(host, srv->tmp_buf);
    }
}

static int mod_vhostdb_dbconf_setup (server *srv, array *opts, void **vdata)
{
    buffer *filter = NULL;
    const char *attr = "documentRoot";
    const char *basedn=NULL,*binddn=NULL,*bindpw=NULL,*host=NULL,*cafile=NULL;
    unsigned short starttls = 0;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING) {
            if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("filter"))) {
                filter = ds->value;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("attr"))) {
                if (!buffer_string_is_empty(ds->value)) attr   = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("host"))) {
                mod_vhostdb_dbconf_add_scheme(srv, ds->value);
                host   = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("base-dn"))) {
                if (!buffer_string_is_empty(ds->value)) basedn = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("bind-dn"))) {
                if (!buffer_string_is_empty(ds->value)) binddn = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("bind-pw"))) {
                bindpw = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("ca-file"))) {
                if (!buffer_string_is_empty(ds->value)) cafile = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("starttls"))) {
                starttls = !buffer_is_equal_string(ds->value, CONST_STR_LEN("disable"))
                        && !buffer_is_equal_string(ds->value, CONST_STR_LEN("0"));
            }
        }
    }

    /* required:
     * - host
     * - filter (LDAP query)
     * - base-dn
     *
     * optional:
     * - attr   (LDAP attribute with docroot; default "documentRoot")
     * - bind-dn
     * - bind-pw
     * - ca-file
     * - starttls
     */

    if (!buffer_string_is_empty(filter) && NULL != host && NULL != basedn) {
        vhostdb_config *dbconf;

        if (NULL == strchr(filter->ptr, '?')) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "ldap: filter is missing a replace-operator '?'");
            return -1;
        }

        /* openldap sets FD_CLOEXEC on database socket descriptors
         * (still race between creation of socket and fcntl FD_CLOEXEC)
         * (YMMV with other LDAP client libraries) */

        dbconf = (vhostdb_config *)calloc(1, sizeof(*dbconf));
        dbconf->ldap     = NULL;
        dbconf->filter   = filter;
        dbconf->attr     = attr;
        dbconf->host     = host;
        dbconf->basedn   = basedn;
        dbconf->binddn   = binddn;
        dbconf->bindpw   = bindpw;
        dbconf->cafile   = cafile;
        dbconf->starttls = starttls;
        *vdata = dbconf;
    }
    return 0;
}

/*
 * Note: a large portion of the LDAP code is copied verbatim from mod_authn_ldap
 * with only changes being use of vhostdb_config instead of plugin_config struct
 * and (const char *) strings in vhostdb_config instead of (buffer *).
 */

static void mod_authn_ldap_err(server *srv, const char *file, unsigned long line, const char *fn, int err)
{
    log_error_write(srv,file,line,"sSss","ldap:",fn,":",ldap_err2string(err));
}

static void mod_authn_ldap_opt_err(server *srv, const char *file, unsigned long line, const char *fn, LDAP *ld)
{
    int err;
    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
    mod_authn_ldap_err(srv, file, line, fn, err);
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
    const size_t rlen = buffer_string_length(raw);
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
        buffer_string_prepare_append(filter, 3);
        f = filter->ptr + buffer_string_length(filter);
        f[0] = '\\';
        f[1] = "0123456789abcdef"[(((unsigned char *)b)[i] >> 4) & 0xf];
        f[2] = "0123456789abcdef"[(((unsigned char *)b)[i]     ) & 0xf];
        buffer_commit(filter, 3);
    }
}

static LDAP * mod_authn_ldap_host_init(server *srv, vhostdb_config *s) {
    LDAP *ld;
    int ret;

    ret = ldap_initialize(&ld, s->host);
    if (LDAP_SUCCESS != ret) {
        log_error_write(srv, __FILE__, __LINE__, "sss", "ldap:",
                        "ldap_initialize():", strerror(errno));
        return NULL;
    }

    ret = LDAP_VERSION3;
    ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ret);
    if (LDAP_OPT_SUCCESS != ret) {
        mod_authn_ldap_err(srv, __FILE__, __LINE__, "ldap_set_options()", ret);
        ldap_destroy(ld);
        return NULL;
    }

    /* restart ldap functions if interrupted by a signal, e.g. SIGCHLD */
    ldap_set_option(ld, LDAP_OPT_RESTART, LDAP_OPT_ON);

    if (s->starttls) {
        /* if no CA file is given, it is ok, as we will use encryption
         * if the server requires a CAfile it will tell us */
        if (s->cafile) {
            ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, s->cafile);
            if (LDAP_OPT_SUCCESS != ret) {
                mod_authn_ldap_err(srv, __FILE__, __LINE__,
                                   "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE)",
                                   ret);
                ldap_destroy(ld);
                return NULL;
            }
        }

        ret = ldap_start_tls_s(ld, NULL,  NULL);
        if (LDAP_OPT_SUCCESS != ret) {
            mod_authn_ldap_err(srv,__FILE__,__LINE__,"ldap_start_tls_s()",ret);
            ldap_destroy(ld);
            return NULL;
        }
    }

    return ld;
}

static int mod_authn_ldap_bind(server *srv, LDAP *ld, const char *dn, const char *pw) {
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
        mod_authn_ldap_err(srv, __FILE__, __LINE__, "ldap_sasl_bind_s()", ret);
    }

    return ret;
}

static int mod_authn_ldap_rebind_proc (LDAP *ld, LDAP_CONST char *url, ber_tag_t ldap_request, ber_int_t msgid, void *params) {
    vhostdb_config *s = (vhostdb_config *)params;
    UNUSED(url);
    UNUSED(ldap_request);
    UNUSED(msgid);
    return mod_authn_ldap_bind(s->srv, ld, s->binddn, s->bindpw);
}

static LDAPMessage * mod_authn_ldap_search(server *srv, vhostdb_config *s, char *base, char *filter) {
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

    s->ldap = mod_authn_ldap_host_init(srv, s);
    if (NULL == s->ldap) {
        return NULL;
    }

    ldap_set_rebind_proc(s->ldap, mod_authn_ldap_rebind_proc, s);
    ret = mod_authn_ldap_bind(srv, s->ldap, s->binddn, s->bindpw);
    if (LDAP_SUCCESS != ret) {
        ldap_destroy(s->ldap);
        s->ldap = NULL;
        return NULL;
    }

    ret = ldap_search_ext_s(s->ldap, base, LDAP_SCOPE_SUBTREE, filter,
                            attrs, 0, NULL, NULL, NULL, 0, &lm);
    if (LDAP_SUCCESS != ret) {
        log_error_write(srv, __FILE__, __LINE__, "sSss",
                        "ldap:", ldap_err2string(ret), "; filter:", filter);
        ldap_unbind_ext_s(s->ldap, NULL, NULL);
        s->ldap = NULL;
        return NULL;
    }

    return lm;
}

static void mod_vhostdb_patch_connection (server *srv, connection *con, plugin_data *p);

static int mod_vhostdb_ldap_query(server *srv, connection *con, void *p_d, buffer *docroot)
{
    plugin_data *p = (plugin_data *)p_d;
    vhostdb_config *dbconf;
    LDAP *ld;
    LDAPMessage *lm, *first;
    struct berval **vals;
    int count;
    char *basedn;
    buffer *template;

    /*(reuse buffer for ldap query before generating docroot result)*/
    buffer *filter = docroot;
    buffer_clear(filter); /*(also resets docroot (alias))*/

    mod_vhostdb_patch_connection(srv, con, p);
    if (NULL == p->conf.vdata) return 0; /*(after resetting docroot)*/
    dbconf = (vhostdb_config *)p->conf.vdata;
    dbconf->srv = srv;

    template = dbconf->filter;
    for (char *b = template->ptr, *d; *b; b = d+1) {
        if (NULL != (d = strchr(b, '?'))) {
            buffer_append_string_len(filter, b, (size_t)(d - b));
            mod_authn_append_ldap_filter_escape(filter, con->uri.authority);
        } else {
            d = template->ptr + buffer_string_length(template);
            buffer_append_string_len(filter, b, (size_t)(d - b));
            break;
        }
    }

    /* (cast away const for poor LDAP ldap_search_ext_s() prototype) */
    *(const char **)&basedn = dbconf->basedn;

    /* ldap_search (synchronous; blocking) */
    lm = mod_authn_ldap_search(srv, dbconf, basedn, filter->ptr);
    if (NULL == lm) {
        return -1;
    }

    /*(must be after mod_authn_ldap_search(); might reconnect)*/
    ld = dbconf->ldap;

    count = ldap_count_entries(ld, lm);
    if (count > 1) {
        log_error_write(srv, __FILE__, __LINE__, "ssb",
                        "ldap:", "more than one record returned.  "
                        "you might have to refine the filter:", filter);
    }

    buffer_clear(docroot); /*(reset buffer to store result)*/

    if (0 == count) { /*(no entries found)*/
        ldap_msgfree(lm);
        return 0;
    }

    if (NULL == (first = ldap_first_entry(ld, lm))) {
        mod_authn_ldap_opt_err(srv,__FILE__,__LINE__,"ldap_first_entry()",ld);
        ldap_msgfree(lm);
        return -1;
    }

    if (NULL != (vals = ldap_get_values_len(ld, first, dbconf->attr))) {
        buffer_copy_string_len(docroot, vals[0]->bv_val, vals[0]->bv_len);
        ldap_value_free_len(vals);
    }

    ldap_msgfree(lm);
    return 0;
}




INIT_FUNC(mod_vhostdb_init) {
    static http_vhostdb_backend_t http_vhostdb_backend_ldap =
      { "ldap", mod_vhostdb_ldap_query, NULL };
    plugin_data *p = calloc(1, sizeof(*p));

    /* register http_vhostdb_backend_ldap */
    http_vhostdb_backend_ldap.p_d = p;
    http_vhostdb_backend_set(&http_vhostdb_backend_ldap);

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
        { "vhostdb.ldap",  NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },
        { NULL,            NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
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

	if (!array_is_kvstring(s->options)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"unexpected value for vhostdb.ldap; expected list of \"option\" => \"value\"");
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

            if (buffer_is_equal_string(du->key,CONST_STR_LEN("vhostdb.ldap"))) {
                PATCH(vdata);
            }
        }
    }
}
#undef PATCH

/* this function is called at dlopen() time and inits the callbacks */
int mod_vhostdb_ldap_plugin_init (plugin *p);
int mod_vhostdb_ldap_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("vhostdb_ldap");

    p->init             = mod_vhostdb_init;
    p->cleanup          = mod_vhostdb_cleanup;
    p->set_defaults     = mod_vhostdb_set_defaults;

    return 0;
}
