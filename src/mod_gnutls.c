/*
 * mod_gnutls - GnuTLS support for lighttpd
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 */
/*
 * GnuTLS manual: https://www.gnutls.org/documentation.html
 *
 * Note: If session tickets are -not- disabled with
 *     ssl.openssl.ssl-conf-cmd = ("Options" => "-SessionTicket")
 *   mod_gnutls rotates server ticket encryption key (STEK) every 18 hours.
 *   (https://gnutls.org/manual/html_node/Session-resumption.html)
 *   This is fine for use with a single lighttpd instance, but with multiple
 *   lighttpd workers, no coordinated STEK (server ticket encryption key)
 *   rotation occurs unless ssl.stek-file is defined and maintained (preferred),
 *   or if some external job restarts lighttpd.  Restarting lighttpd generates a
 *   new key that is shared by lighttpd workers for the lifetime of the new key.
 *   If the rotation period expires and lighttpd has not been restarted, and if
 *   ssl.stek-file is not in use, then lighttpd workers will generate new
 *   independent keys, making session tickets less effective for session
 *   resumption, since clients have a lower chance for future connections to
 *   reach the same lighttpd worker.  However, things will still work, and a new
 *   session will be created if session resumption fails.  Admins should plan to
 *   restart lighttpd at least every 18 hours if session tickets are enabled and
 *   multiple lighttpd workers are configured.  Since that is likely disruptive,
 *   if multiple lighttpd workers are configured, ssl.stek-file should be
 *   defined and the file maintained externally.
 *
 * future possible enhancements to lighttpd mod_gnutls:
 * - session cache (though session tickets are implemented)
 *     See gnutls_db_set_store_function() and gnutls_db_set_retrieve_function()
 *     (and do not enable unless server.feature-flags ssl.session-cache enabled)
 */
#include "first.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>      /* vsnprintf() */
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>
#include <gnutls/abstract.h>

#ifdef GNUTLS_SKIP_GLOBAL_INIT
GNUTLS_SKIP_GLOBAL_INIT
#endif

#include "base.h"
#include "fdevent.h"
#include "http_header.h"
#include "http_kv.h"
#include "log.h"
#include "plugin.h"

typedef struct {
    /* SNI per host: with COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    gnutls_certificate_credentials_t ssl_cred;
    char trust_inited;
    char must_staple;
    gnutls_datum_t *ssl_pemfile_x509;
    gnutls_privkey_t ssl_pemfile_pkey;
    const buffer *ssl_stapling_file;
    unix_time64_t ssl_stapling_loadts;
    unix_time64_t ssl_stapling_nextts;
} plugin_cert;

typedef struct {
    int8_t ssl_session_ticket;
    /*(preserved here for deinit at server shutdown)*/
    gnutls_priority_t priority_cache;
  #if GNUTLS_VERSION_NUMBER < 0x030600
    gnutls_dh_params_t dh_params;
  #endif
} plugin_ssl_ctx;

typedef struct {
    plugin_cert *pc;

    /*(used only during startup; not patched)*/
    unsigned char ssl_enabled; /* only interesting for setting up listening sockets. don't use at runtime */
    unsigned char ssl_honor_cipher_order; /* determine SSL cipher in server-preferred order, not client-order */
    unsigned char ssl_empty_fragments;
    unsigned char ssl_use_sslv2;
    unsigned char ssl_use_sslv3;
    const buffer *ssl_cipher_list;
    const buffer *ssl_dh_file;
    const buffer *ssl_ec_curve;
    array *ssl_conf_cmd;

    /*(copied from plugin_data for socket ssl_ctx config)*/
    gnutls_priority_t priority_cache;
    unsigned char ssl_session_ticket;
    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;

    const char *priority_base;
    buffer *priority_override;
    buffer priority_str;
  #if GNUTLS_VERSION_NUMBER < 0x030600
    gnutls_dh_params_t dh_params;
  #endif
} plugin_config_socket; /*(used at startup during configuration)*/

typedef struct {
    /* SNI per host: w/ COMP_SERVER_SOCKET, COMP_HTTP_SCHEME, COMP_HTTP_HOST */
    plugin_cert *pc;
    gnutls_datum_t *ssl_ca_file;    /* .data is (gnutls_x509_crt_t) */
    gnutls_datum_t *ssl_ca_dn_file; /* .data is (gnutls_x509_crt_t) */
    gnutls_datum_t *ssl_ca_crl_file;/* .data is (gnutls_x509_crl_t) */

    unsigned char ssl_verifyclient;
    unsigned char ssl_verifyclient_enforce;
    unsigned char ssl_verifyclient_depth;
    unsigned char ssl_verifyclient_export_cert;
    unsigned char ssl_read_ahead;
    unsigned char ssl_log_noise;
    unsigned char ssl_disable_client_renegotiation;
    const buffer *ssl_verifyclient_username;
    const buffer *ssl_acme_tls_1;
  #if GNUTLS_VERSION_NUMBER < 0x030600
    gnutls_dh_params_t dh_params;
  #endif
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_ssl_ctx *ssl_ctxs;
    plugin_config defaults;
    server *srv;
    const char *ssl_stek_file;
} plugin_data;

static int ssl_is_init;
/* need assigned p->id for deep access of module handler_ctx for connection
 *   i.e. handler_ctx *hctx = con->plugin_ctx[plugin_data_singleton->id]; */
static plugin_data *plugin_data_singleton;
#define LOCAL_SEND_BUFSIZE 16384 /* DEFAULT_MAX_RECORD_SIZE */
static char *local_send_buffer;

typedef struct {
    gnutls_session_t ssl;      /* gnutls request/connection context */
    request_st *r;
    connection *con;
    int8_t close_notify;
    uint8_t alpn;
    int8_t ssl_session_ticket;
    int handshake;
    size_t pending_write;
    plugin_config conf;
    unsigned int verify_status;
    buffer *tmp_buf;
    log_error_st *errh;
    gnutls_certificate_credentials_t acme_tls_1_cred;
} handler_ctx;


static handler_ctx *
handler_ctx_init (void)
{
    handler_ctx *hctx = calloc(1, sizeof(*hctx));
    force_assert(hctx);
    return hctx;
}


static void
handler_ctx_free (handler_ctx *hctx)
{
    gnutls_deinit(hctx->ssl);
    if (hctx->acme_tls_1_cred)
        gnutls_certificate_free_credentials(hctx->acme_tls_1_cred);
    free(hctx);
}


__attribute_cold__
static void elog(log_error_st * const errh,
                 const char * const file, const int line,
                 const int rc, const char * const msg)
{
    /* error logging convenience function that decodes gnutls result codes */
    log_error(errh, file, line, "GnuTLS: %s: (%s) %s",
              msg, gnutls_strerror_name(rc), gnutls_strerror(rc));
}


__attribute_cold__
__attribute_format__((__printf__, 5, 6))
static void elogf(log_error_st * const errh,
                  const char * const file, const int line,
                  const int rc, const char * const fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    elog(errh, file, line, rc, msg);
}


/* gnutls func gnutls_load_file() loads file contents into a gnutls_datum_t.
 * The data loaded could be sensitive, e.g. a private key included in a pemfile.
 * However, gnutls_load_file() is not careful about zeroizing memory on error,
 * might use realloc() (which does not guarantee to zeroize memory released),
 * and silently continues on short read, so provide our own.  Updates to
 * gnutls 3.6.14 may be more careful with private key files, but do not
 * extend the same care to pemfiles which might contain private keys.
 * Related, see also mod_gnutls_datum_wipe() below.
 *   https://gitlab.com/gnutls/gnutls/-/issues/1001
 *   https://gitlab.com/gnutls/gnutls/-/issues/1002
 *   https://gitlab.com/gnutls/gnutls/-/merge_requests/1270
 */
static int
mod_gnutls_load_file (const char * const fn, gnutls_datum_t * const d, log_error_st *errh)
{
  #if 0
    int rc = gnutls_load_file(fn, d);
    if (rc < 0)
        elogf(errh, __FILE__, __LINE__, rc, "%s() %s", __func__, fn);
    return rc;
  #else
    off_t dlen = 512*1024*1024;/*(arbitrary limit: 512 MB file; expect < 1 MB)*/
    char *data = fdevent_load_file(fn, &dlen, errh, gnutls_malloc, gnutls_free);
    if (NULL == data) return GNUTLS_E_FILE_ERROR;
    d->data = (unsigned char *)data;
    d->size = (unsigned int)dlen;
    return 0;
  #endif
}


/* GnuTLS does not expose _gnutls_free_key_datum() so provide our own */
static void
mod_gnutls_datum_wipe (gnutls_datum_t * const d)
{
    if (NULL == d) return;
    if (d->data) {
        if (d->size) gnutls_memset(d->data, 0, d->size);
        gnutls_free(d->data);
        d->data = NULL;
    }
    d->size = 0;
}


/* session tickets
 *
 * gnutls expects 64 bytes of random data in gnutls_datum_t passed to
 * gnutls_session_ticket_enable_server()
 *
 * (private) session ticket definitions from lib/gnutls_int.h
 * #define TICKET_MASTER_KEY_SIZE (TICKET_KEY_NAME_SIZE+TICKET_CIPHER_KEY_SIZE+TICKET_MAC_SECRET_SIZE)
 * #define TICKET_KEY_NAME_SIZE 16
 * #define TICKET_CIPHER_KEY_SIZE 32
 * #define TICKET_MAC_SECRET_SIZE 16
 */
#define TICKET_MASTER_KEY_SIZE 64

#define TLSEXT_KEYNAME_LENGTH  16
#define TLSEXT_TICK_KEY_LENGTH 32

/* construct our own session ticket encryption key structure
 * to store keys that are not yet active
 * (mirror from mod_openssl, even though not all bits are used here) */
typedef struct tlsext_ticket_key_st {
    unix_time64_t active_ts; /* tickets not issued w/ key until activation ts*/
    unix_time64_t expire_ts; /* key not valid after expiration timestamp */
    unsigned char tick_key_name[TLSEXT_KEYNAME_LENGTH];
    unsigned char tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    unsigned char tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
} tlsext_ticket_key_t;

static tlsext_ticket_key_t session_ticket_keys[1]; /* temp store until active */
static unix_time64_t stek_rotate_ts;

static gnutls_datum_t session_ticket_key;


static void
mod_gnutls_session_ticket_key_free (void)
{
    mod_gnutls_datum_wipe(&session_ticket_key);
}
static void
mod_gnutls_session_ticket_key_init (server *srv)
{
    int rc = gnutls_session_ticket_key_generate(&session_ticket_key);
    if (rc < 0) {
        /*(should not happen, but if it does, disable session ticket)*/
        session_ticket_key.size = 0;
        elog(srv->errh, __FILE__, __LINE__, rc,
             "gnutls_session_ticket_key_generate()");
    }
}
static void
mod_gnutls_session_ticket_key_rotate (server *srv)
{
    mod_gnutls_session_ticket_key_free();
    mod_gnutls_session_ticket_key_init(srv);
}


static int
mod_gnutls_session_ticket_key_file (const char *fn)
{
    /* session ticket encryption key (STEK)
     *
     * STEK file should be stored in non-persistent storage,
     *   e.g. /dev/shm/lighttpd/stek-file  (in memory)
     * with appropriate permissions set to keep stek-file from being
     * read by other users.  Where possible, systems should also be
     * configured without swap.
     *
     * admin should schedule an independent job to periodically
     *   generate new STEK up to 3 times during key lifetime
     *   (lighttpd stores up to 3 keys)
     *
     * format of binary file is:
     *    4-byte - format version (always 0; for use if format changes)
     *    4-byte - activation timestamp
     *    4-byte - expiration timestamp
     *   16-byte - session ticket key name
     *   32-byte - session ticket HMAC encrpytion key
     *   32-byte - session ticket AES encrpytion key
     *
     * STEK file can be created with a command such as:
     *   dd if=/dev/random bs=1 count=80 status=none | \
     *     perl -e 'print pack("iii",0,time()+300,time()+86400),<>' \
     *     > STEK-file.$$ && mv STEK-file.$$ STEK-file
     *
     * The above delays activation time by 5 mins (+300 sec) to allow file to
     * be propagated to other machines.  (admin must handle this independently)
     * If STEK generation is performed immediately prior to starting lighttpd,
     * admin should activate keys immediately (without +300).
     */
    int buf[23]; /* 92 bytes */
    int rc = 0; /*(will retry on next check interval upon any error)*/
    if (0 != fdevent_load_file_bytes((char *)buf,(off_t)sizeof(buf),0,fn,NULL))
        return rc;
    if (buf[0] == 0) { /*(format version 0)*/
        session_ticket_keys[0].active_ts = TIME64_CAST(buf[1]);
        session_ticket_keys[0].expire_ts = TIME64_CAST(buf[2]);
      #ifndef __COVERITY__
        memcpy(&session_ticket_keys[0].tick_key_name, buf+3, 80);
      #else
        memcpy(&session_ticket_keys[0].tick_key_name,
               buf+3, TLSEXT_KEYNAME_LENGTH);
        memcpy(&session_ticket_keys[0].tick_hmac_key,
               buf+7, TLSEXT_TICK_KEY_LENGTH);
        memcpy(&session_ticket_keys[0].tick_aes_key,
               buf+15, TLSEXT_TICK_KEY_LENGTH);
      #endif
        rc = 1;
    }

    gnutls_memset(buf, 0, sizeof(buf));
    return rc;
}


static void
mod_gnutls_session_ticket_key_check (server *srv, const plugin_data *p, const unix_time64_t cur_ts)
{
    static unix_time64_t detect_retrograde_ts;
    if (detect_retrograde_ts > cur_ts && detect_retrograde_ts - cur_ts > 28800)
        stek_rotate_ts = 0;
    detect_retrograde_ts = cur_ts;

    if (p->ssl_stek_file) {
        struct stat st;
        if (0 == stat(p->ssl_stek_file, &st)
            && TIME64_CAST(st.st_mtime) > stek_rotate_ts
            && mod_gnutls_session_ticket_key_file(p->ssl_stek_file)) {
            stek_rotate_ts = cur_ts;
        }

        tlsext_ticket_key_t *stek = session_ticket_keys;
        if (stek->active_ts != 0 && stek->active_ts - 63 <= cur_ts) {
            if (NULL == session_ticket_key.data) {
                session_ticket_key.data = gnutls_malloc(TICKET_MASTER_KEY_SIZE);
                if (NULL == session_ticket_key.data) return;
                session_ticket_key.size = TICKET_MASTER_KEY_SIZE;
            }
          #ifndef __COVERITY__
            memcpy(session_ticket_key.data,
                   stek->tick_key_name, TICKET_MASTER_KEY_SIZE);
            gnutls_memset(stek->tick_key_name, 0, TICKET_MASTER_KEY_SIZE);
          #else
            char * const data = (char *)session_ticket_key.data;
            memcpy(data,
                   stek->tick_key_name, TLSEXT_KEYNAME_LENGTH);
            memcpy(data+TLSEXT_KEYNAME_LENGTH,
                   stek->tick_hmac_key, TLSEXT_TICK_KEY_LENGTH);
            memcpy(data+TLSEXT_KEYNAME_LENGTH+TLSEXT_TICK_KEY_LENGTH,
                   stek->tick_aes_key,
                   TICKET_MASTER_KEY_SIZE
                    - (TLSEXT_KEYNAME_LENGTH + TLSEXT_TICK_KEY_LENGTH));
            gnutls_memset(stek->tick_key_name, 0, TLSEXT_KEYNAME_LENGTH);
            gnutls_memset(stek->tick_hmac_key, 0, TLSEXT_TICK_KEY_LENGTH);
            gnutls_memset(stek->tick_aes_key, 0, TLSEXT_TICK_KEY_LENGTH);
          #endif
        }
        if (stek->expire_ts < cur_ts)
            mod_gnutls_session_ticket_key_free();
    }
    else if (cur_ts - 86400 >= stek_rotate_ts     /*(24 hours)*/
             || 0 == stek_rotate_ts) {
        mod_gnutls_session_ticket_key_rotate(srv);
        stek_rotate_ts = cur_ts;
    }
}


INIT_FUNC(mod_gnutls_init)
{
    plugin_data_singleton = (plugin_data *)calloc(1, sizeof(plugin_data));
    return plugin_data_singleton;
}


static int mod_gnutls_init_once_gnutls (void)
{
    if (ssl_is_init) return 1;
    ssl_is_init = 1;

    /* Note: on systems with support for weak symbols, GNUTLS_SKIP_GLOBAL_INIT
     * is set near top of this file to inhibit GnuTLS implicit initialization
     * in a library constructor.  On systems without support for weak symbols,
     * set GNUTLS_NO_EXPLICIT_INIT=1 in the environment before starting lighttpd
     * (GnuTLS 3.3.0 or later) */

    if (gnutls_global_init() != GNUTLS_E_SUCCESS)
        return 0;

    local_send_buffer = malloc(LOCAL_SEND_BUFSIZE);
    force_assert(NULL != local_send_buffer);

    return 1;
}


static void mod_gnutls_free_gnutls (void)
{
    if (!ssl_is_init) return;

    gnutls_memset(session_ticket_keys, 0, sizeof(session_ticket_keys));
    mod_gnutls_session_ticket_key_free();
    stek_rotate_ts = 0;

    gnutls_global_deinit();

    free(local_send_buffer);
    ssl_is_init = 0;
}


static void
mod_gnutls_free_config_crts (gnutls_datum_t *d)
{
    if (NULL == d) return;
    gnutls_x509_crt_t *crts = (gnutls_x509_crt_t *)(void *)d->data;
    unsigned int u = d->size;
    for (unsigned int i = 0; i < u; ++i)
        gnutls_x509_crt_deinit(crts[i]);
    gnutls_free(crts);
    gnutls_free(d);
}


static void
mod_gnutls_free_config_crls (gnutls_datum_t *d)
{
    if (NULL == d) return;
    gnutls_x509_crl_t *crls = (gnutls_x509_crl_t *)(void *)d->data;
    unsigned int u = d->size;
    for (unsigned int i = 0; i < u; ++i)
        gnutls_x509_crl_deinit(crls[i]);
    gnutls_free(crls);
    gnutls_free(d);
}


static gnutls_datum_t *
mod_gnutls_load_config_crts (const char *fn, log_error_st *errh)
{
    /*(very similar to other mod_gnutls_load_config_*())*/
    if (!mod_gnutls_init_once_gnutls()) return NULL;

    gnutls_datum_t f = { NULL, 0 };
    int rc = mod_gnutls_load_file(fn, &f, errh);
    if (rc < 0) return NULL;
    gnutls_datum_t *d = gnutls_malloc(sizeof(gnutls_datum_t));
    if (d == NULL) {
        mod_gnutls_datum_wipe(&f);
        return NULL;
    }
    d->data = NULL;
    d->size = 0;
    rc = gnutls_x509_crt_list_import2((gnutls_x509_crt_t **)&d->data, &d->size,
                                      &f, GNUTLS_X509_FMT_PEM,
                                      GNUTLS_X509_CRT_LIST_SORT);
    mod_gnutls_datum_wipe(&f);
    if (rc < 0) {
        elogf(errh, __FILE__, __LINE__, rc,
              "gnutls_x509_crt_list_import2() %s", fn);
        mod_gnutls_free_config_crts(d);
        return NULL;
    }

    return d;
}


static gnutls_datum_t *
mod_gnutls_load_config_crls (const char *fn, log_error_st *errh)
{
    /*(very similar to other mod_gnutls_load_config_*())*/
    if (!mod_gnutls_init_once_gnutls()) return NULL;

    gnutls_datum_t f = { NULL, 0 };
    int rc = mod_gnutls_load_file(fn, &f, errh);
    if (rc < 0) return NULL;
    gnutls_datum_t *d = gnutls_malloc(sizeof(gnutls_datum_t));
    if (d == NULL) {
        mod_gnutls_datum_wipe(&f);
        return NULL;
    }
    d->data = NULL;
    d->size = 0;
    rc = gnutls_x509_crl_list_import2((gnutls_x509_crl_t **)&d->data, &d->size,
                                      &f, GNUTLS_X509_FMT_PEM, 0);
    mod_gnutls_datum_wipe(&f);
    if (rc < 0) {
        elogf(errh, __FILE__, __LINE__, rc,
              "gnutls_x509_crl_list_import2() %s", fn);
        mod_gnutls_free_config_crls(d);
        return NULL;
    }

    return d;
}


static gnutls_privkey_t
mod_gnutls_load_config_pkey (const char *fn, log_error_st *errh)
{
    /*(very similar to other mod_gnutls_load_config_*())*/
    if (!mod_gnutls_init_once_gnutls()) return NULL;

    gnutls_datum_t f = { NULL, 0 };
    int rc = mod_gnutls_load_file(fn, &f, errh);
    if (rc < 0) return NULL;
    gnutls_privkey_t pkey;
    rc = gnutls_privkey_init(&pkey);
    if (rc < 0) {
        mod_gnutls_datum_wipe(&f);
        return NULL;
    }
    rc = gnutls_privkey_import_x509_raw(pkey, &f, GNUTLS_X509_FMT_PEM, NULL, 0);
    mod_gnutls_datum_wipe(&f);
    if (rc < 0) {
        elogf(errh, __FILE__, __LINE__, rc,
              "gnutls_privkey_import_x509_raw() %s", fn);
        gnutls_privkey_deinit(pkey);
        return NULL;
    }

    return pkey;
}


static void
mod_gnutls_free_config (server *srv, plugin_data * const p)
{
    if (NULL != p->ssl_ctxs) {
        gnutls_priority_t pcache_global_scope = p->ssl_ctxs->priority_cache;
        /* free from $SERVER["socket"] (if not copy of global scope) */
        for (uint32_t i = 1; i < srv->config_context->used; ++i) {
            plugin_ssl_ctx * const s = p->ssl_ctxs + i;
            if (s->priority_cache && s->priority_cache != pcache_global_scope) {
                if (s->priority_cache)
                    gnutls_priority_deinit(s->priority_cache);
              #if GNUTLS_VERSION_NUMBER < 0x030600
                if (s->dh_params)
                    gnutls_dh_params_deinit(s->dh_params);
              #endif
            }
        }
        /* free from global scope */
        if (pcache_global_scope) {
            if (p->ssl_ctxs[0].priority_cache)
                gnutls_priority_deinit(p->ssl_ctxs[0].priority_cache);
          #if GNUTLS_VERSION_NUMBER < 0x030600
            if (p->ssl_ctxs[0].dh_params)
                gnutls_dh_params_deinit(p->ssl_ctxs[0].dh_params);
          #endif
        }
        free(p->ssl_ctxs);
    }

    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (cpv->vtype == T_CONFIG_LOCAL) {
                    plugin_cert *pc = cpv->v.v;
                    gnutls_certificate_free_credentials(pc->ssl_cred);
                    mod_gnutls_free_config_crts(pc->ssl_pemfile_x509);
                    gnutls_privkey_deinit(pc->ssl_pemfile_pkey);
                    free(pc);
                }
                break;
              case 2: /* ssl.ca-file */
              case 3: /* ssl.ca-dn-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    mod_gnutls_free_config_crts(cpv->v.v);
                break;
              case 4: /* ssl.ca-crl-file */
                if (cpv->vtype == T_CONFIG_LOCAL)
                    mod_gnutls_free_config_crls(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}


FREE_FUNC(mod_gnutls_free)
{
    plugin_data *p = p_d;
    if (NULL == p->srv) return;
    mod_gnutls_free_config(p->srv, p);
    mod_gnutls_free_gnutls();
}


static void
mod_gnutls_merge_config_cpv (plugin_config * const pconf, const config_plugin_value_t * const cpv)
{
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* ssl.pemfile */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->pc = cpv->v.v;
        break;
      case 1: /* ssl.privkey */
        break;
      case 2: /* ssl.ca-file */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ssl_ca_file = cpv->v.v;
        break;
      case 3: /* ssl.ca-dn-file */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ssl_ca_dn_file = cpv->v.v;
        break;
      case 4: /* ssl.ca-crl-file */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->ssl_ca_crl_file = cpv->v.v;
        break;
      case 5: /* ssl.read-ahead */
        pconf->ssl_read_ahead = (0 != cpv->v.u);
        break;
      case 6: /* ssl.disable-client-renegotiation */
        pconf->ssl_disable_client_renegotiation = (0 != cpv->v.u);
        break;
      case 7: /* ssl.verifyclient.activate */
        pconf->ssl_verifyclient = (0 != cpv->v.u);
        break;
      case 8: /* ssl.verifyclient.enforce */
        pconf->ssl_verifyclient_enforce = (0 != cpv->v.u);
        break;
      case 9: /* ssl.verifyclient.depth */
        pconf->ssl_verifyclient_depth = (unsigned char)cpv->v.shrt;
        break;
      case 10:/* ssl.verifyclient.username */
        pconf->ssl_verifyclient_username = cpv->v.b;
        break;
      case 11:/* ssl.verifyclient.exportcert */
        pconf->ssl_verifyclient_export_cert = (0 != cpv->v.u);
        break;
      case 12:/* ssl.acme-tls-1 */
        pconf->ssl_acme_tls_1 = cpv->v.b;
        break;
      case 13:/* ssl.stapling-file */
        break;
      case 14:/* debug.log-ssl-noise */
        pconf->ssl_log_noise = (unsigned char)cpv->v.shrt;
        break;
     #if 0    /*(cpk->k_id remapped in mod_gnutls_set_defaults())*/
      case 15:/* ssl.verifyclient.ca-file */
      case 16:/* ssl.verifyclient.ca-dn-file */
      case 17:/* ssl.verifyclient.ca-crl-file */
        break;
     #endif
      default:/* should not happen */
        return;
    }
}


static void
mod_gnutls_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv)
{
    do {
        mod_gnutls_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_gnutls_patch_config (request_st * const r, plugin_config * const pconf)
{
    plugin_data * const p = plugin_data_singleton;
    memcpy(pconf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_gnutls_merge_config(pconf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


static int
mod_gnutls_verify_set_tlist (handler_ctx *hctx, int req)
{
    /* XXX GnuTLS interfaces appear to be better for client-side use than for
     * server-side use.  If gnutls_x509_trust_list_t were available to attach
     * to a gnutls_session_t (without copying), then there would not be race
     * conditions swapping trust lists on the credential *shared* between
     * connections when ssl.ca-dn-file and ssl.ca-file are both set.  If both
     * are set, current code attempts to set ssl.ca-dn-file right before sending
     * client cert request, and sets ssl.ca-file right before client cert verify
     *
     * Architecture would be cleaner if the trust list for verifying client cert
     * (gnutls_x509_trust_list_t) were available to attach to a gnutls_session_t
     * instead of attaching to a gnutls_certificate_credentials_t.
     */
    if (hctx->conf.pc->trust_inited) return GNUTLS_E_SUCCESS;

    gnutls_datum_t *d;
    int rc;

    /* set trust list using ssl_ca_dn_file, if set, for client cert request
     * (when req is true) (for CAs sent by server to client in cert request)
     * (trust is later replaced by ssl_ca_file for client cert verification) */
    d = req && hctx->conf.ssl_ca_dn_file
      ? hctx->conf.ssl_ca_dn_file
      : hctx->conf.ssl_ca_file;
    if (NULL == d) {
        log_error(hctx->r->conf.errh, __FILE__, __LINE__,
          "GnuTLS: can't verify client without ssl.verifyclient.ca-file "
          "for TLS server name %s",
          hctx->r->uri.authority.ptr); /*(might not be set yet if no SNI)*/
        return GNUTLS_E_INTERNAL_ERROR;
    }

    gnutls_x509_trust_list_t tlist = NULL;
    rc = gnutls_x509_trust_list_init(&tlist, 0);
    if (rc < 0) {
        elog(hctx->r->conf.errh, __FILE__, __LINE__, rc,
             "gnutls_x509_trust_list_init()");
        return rc;
    }

    gnutls_x509_crt_t *clist = (gnutls_x509_crt_t *)(void *)d->data;
    rc = gnutls_x509_trust_list_add_cas(tlist, clist, d->size, 0);
    if (rc < 0) {
        elog(hctx->r->conf.errh, __FILE__, __LINE__, rc,
             "gnutls_x509_trust_list_add_cas()");
        gnutls_x509_trust_list_deinit(tlist, 0);
        return rc;
    }

    d = hctx->conf.ssl_ca_crl_file;
    if (NULL != d && req && hctx->conf.ssl_ca_dn_file) {
        /*(check req and ssl_ca_dn_file to see if tlist will be replaced later,
         * and, if so, defer setting crls until later)*/
        gnutls_x509_crl_t *crl_list = (gnutls_x509_crl_t *)(void *)d->data;
        rc = gnutls_x509_trust_list_add_crls(tlist, crl_list, d->size, 0, 0);
        if (rc < 0) {
            elog(hctx->r->conf.errh, __FILE__, __LINE__, rc,
                 "gnutls_x509_trust_list_add_crls()");
            gnutls_x509_trust_list_deinit(tlist, 0);
            return rc;
        }
    }

    /* gnutls limitation; wasteful to have to copy into each cred */
    /* (would be better to share list with session, instead of with cred) */
    gnutls_certificate_credentials_t ssl_cred = hctx->conf.pc->ssl_cred;
    gnutls_certificate_set_trust_list(ssl_cred, tlist, 0); /* transfer tlist */

    /* (must flip trust lists back and forth b/w DN names and verify CAs) */
    if (NULL == hctx->conf.ssl_ca_dn_file)
        hctx->conf.pc->trust_inited = 1;

    return GNUTLS_E_SUCCESS;
}


static int
mod_gnutls_verify_cb (gnutls_session_t ssl)
{
    handler_ctx * const hctx = gnutls_session_get_ptr(ssl);
    if (!hctx->conf.ssl_verifyclient) return 0;

    if (gnutls_auth_client_get_type(ssl) != GNUTLS_CRD_CERTIFICATE)
        return GNUTLS_E_SUCCESS;

    int rc;

    /* gnutls limitation; wasteful to have to copy into each cred */
    /* (would be better to share list with session, instead of with cred) */
    if (hctx->conf.ssl_ca_dn_file) {
        rc = mod_gnutls_verify_set_tlist(hctx, 0); /* for client cert verify */
        if (rc < 0) return rc;
    }

    /* gnutls_certificate_verify_peers2() includes processing OCSP staping,
     * as well as certificate depth verification before getting internal
     * flags and calling gnutls_x509_trust_list_verify_crt2()
     * advanced reference:
     *   gnutls lib/cert-sessions.c:_gnutls_x509_cert_verify_peers()
     * XXX: if GnuTLS provided a more advanced interface which permitted
     * providing trust list, verify depth, and flags, we could avoid copying
     * ca chain and crls into each credential, using
     *   gnutls_x509_trust_list_add_cas()
     *   gnutls_x509_trust_list_add_crls()
     *   gnutls_x509_trust_list_verify_crt2()
     * See also GnuTLS manual Section 7.3.4 Advanced certificate verification
     */

    rc = gnutls_certificate_verify_peers2(ssl, &hctx->verify_status);
    if (rc < 0) return rc;

    if (hctx->verify_status == 0 && hctx->conf.ssl_ca_dn_file) {
        /* verify that client cert is issued by CA in ssl.ca-dn-file
         * if both ssl.ca-dn-file and ssl.ca-file were configured */
        gnutls_x509_crt_t *CA_list =
          (gnutls_x509_crt_t *)(void *)hctx->conf.ssl_ca_dn_file->data;
        unsigned int len = hctx->conf.ssl_ca_dn_file->size;
        unsigned int i;
        gnutls_x509_dn_t issuer, subject;
        unsigned int crt_size = 0;
        const gnutls_datum_t *crts;
        gnutls_x509_crt_t crt = NULL;
        crts = gnutls_certificate_get_peers(ssl, &crt_size);
        if (0 == crt_size
            || gnutls_x509_crt_init(&crt) < 0
            || gnutls_x509_crt_import(crt, &crts[0], GNUTLS_X509_FMT_DER) < 0
            || gnutls_x509_crt_get_subject(crt, &issuer) < 0)
            len = 0; /*(trigger failure path below)*/
        for (i = 0; i < len; ++i) {
            if (gnutls_x509_crt_get_subject(CA_list[i], &subject) >= 0
                && 0 == memcmp(&subject, &issuer, sizeof(issuer)))
                break;
        }
        if (i == len)
            hctx->verify_status |= GNUTLS_CERT_SIGNER_NOT_CA;
        if (crt) gnutls_x509_crt_deinit(crt);
    }

    if (hctx->verify_status != 0 && hctx->conf.ssl_verifyclient_enforce) {
        /* (not looping on GNUTLS_E_INTERRUPTED or GNUTLS_E_AGAIN
         *  since we do not want to block here (and not expecting to have to))*/
        (void)gnutls_alert_send(ssl, GNUTLS_AL_FATAL, GNUTLS_A_ACCESS_DENIED);
        return GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR;
    }

    return GNUTLS_E_SUCCESS;
}


#if GNUTLS_VERSION_NUMBER < 0x030603
static time_t
mod_gnutls_ocsp_next_update (plugin_cert *pc, log_error_st *errh)
{
    gnutls_datum_t f = { NULL, 0 };
    int rc = mod_gnutls_load_file(pc->ssl_stapling_file->ptr, &f, errh);
    if (rc < 0) return (time_t)-1;

    gnutls_ocsp_resp_t resp = NULL;
    time_t nextupd;
    if (   gnutls_ocsp_resp_init(&resp) < 0
        || gnutls_ocsp_resp_import(resp, &f) < 0
        || gnutls_ocsp_resp_get_single(resp, 0, NULL, NULL, NULL, NULL, NULL,
                                       NULL, &nextupd, NULL, NULL) < 0)
        nextupd = (time_t)-1;
    gnutls_ocsp_resp_deinit(resp);
    mod_gnutls_datum_wipe(&f);
    return nextupd;
}
#endif


__attribute_cold__
static void
mod_gnutls_expire_stapling_file (server *srv, plugin_cert *pc)
{
  #if 0
    /* discard expired OCSP stapling response */
    /* Does GnuTLS detect expired OCSP response? */
    /* or must we rebuild gnutls_certificate_credentials_t ? */
  #endif
    if (pc->must_staple)
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate marked OCSP Must-Staple, "
                  "but OCSP response expired from ssl.stapling-file %s",
                  pc->ssl_stapling_file->ptr);
}


static int
mod_gnutls_reload_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
  #if GNUTLS_VERSION_NUMBER < 0x030603
    /* load file into gnutls_ocsp_resp_t before loading into
     * gnutls_certificate_credentials_t for safety.  Still ToC-ToU since file
     * is loaded twice, but unlikely condition.  (GnuTLS limitation does not
     * expose access to OCSP response from gnutls_certificate_credentials_t
     * before GnuTLS 3.6.3) */
    time_t nextupd = mod_gnutls_ocsp_next_update(pc, srv->errh);
  #else
    UNUSED(srv);
  #endif

    /* GnuTLS 3.5.6 added the ability to include multiple OCSP responses for
     * certificate chain as allowed in TLSv1.3, but that is not utilized here.
     * If implemented, it will probably operate on a new directive,
     *   e.g. ssl.stapling-pemfile
     * GnuTLS 3.6.3 added gnutls_certificate_set_ocsp_status_request_file2()
     * GnuTLS 3.6.3 added gnutls_certificate_set_ocsp_status_request_mem()
     * GnuTLS 3.6.3 added gnutls_certificate_get_ocsp_expiration() */

    /* gnutls_certificate_get_ocsp_expiration() code comments:
     *   Note that the credentials structure should be read-only when in
     *   use, thus when reloading, either the credentials structure must not
     *   be in use by any sessions, or a new credentials structure should be
     *   allocated for new sessions.
     * XXX: lighttpd is not threaded, so this is probably not an issue (?)
     */

  #if 0
    gnutls_certificate_set_flags(pc->ssl_cred,
                                 GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK);
  #endif

    const char *fn = pc->ssl_stapling_file->ptr;
    int rc = gnutls_certificate_set_ocsp_status_request_file(pc->ssl_cred,fn,0);
    if (rc < 0)
        return rc;

  #if GNUTLS_VERSION_NUMBER >= 0x030603
    time_t nextupd =
      gnutls_certificate_get_ocsp_expiration(pc->ssl_cred, 0, 0, 0);
    if (nextupd == (time_t)-2) nextupd = (time_t)-1;
  #endif

    pc->ssl_stapling_loadts = cur_ts;
    pc->ssl_stapling_nextts = nextupd;
    if (pc->ssl_stapling_nextts == -1) {
        /* "Next Update" might not be provided by OCSP responder
         * Use 3600 sec (1 hour) in that case. */
        /* retry in 1 hour if unable to determine Next Update */
        pc->ssl_stapling_nextts = cur_ts + 3600;
        pc->ssl_stapling_loadts = 0;
    }
    else if (pc->ssl_stapling_nextts < cur_ts)
        mod_gnutls_expire_stapling_file(srv, pc);

    return 0;
}


static int
mod_gnutls_refresh_stapling_file (server *srv, plugin_cert *pc, const unix_time64_t cur_ts)
{
    if (pc->ssl_stapling_nextts > cur_ts + 256)
        return 0; /* skip check for refresh unless close to expire */
    struct stat st;
    if (0 != stat(pc->ssl_stapling_file->ptr, &st)
        || TIME64_CAST(st.st_mtime) <= pc->ssl_stapling_loadts) {
        if (pc->ssl_stapling_nextts < cur_ts)
            mod_gnutls_expire_stapling_file(srv, pc);
        return 0;
    }
    return mod_gnutls_reload_stapling_file(srv, pc, cur_ts);
}


static void
mod_gnutls_refresh_stapling_files (server *srv, const plugin_data *p, const unix_time64_t cur_ts)
{
    /* future: might construct array of (plugin_cert *) at startup
     *         to avoid the need to search for them here */
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    if (NULL == p->cvlist) return;
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; cpv->k_id != -1; ++cpv) {
            if (cpv->k_id != 0) continue; /* k_id == 0 for ssl.pemfile */
            if (cpv->vtype != T_CONFIG_LOCAL) continue;
            plugin_cert *pc = cpv->v.v;
            if (pc->ssl_stapling_file)
                mod_gnutls_refresh_stapling_file(srv, pc, cur_ts);
        }
    }
}


static int
mod_gnutls_crt_must_staple (gnutls_x509_crt_t crt)
{
    /* Look for TLS features X.509 extension with value 5
     * RFC 7633 https://tools.ietf.org/html/rfc7633#appendix-A
     * 5 = OCSP Must-Staple (security mechanism) */

    int rc;

  #if GNUTLS_VERSION_NUMBER < 0x030501

    unsigned int i;
    char oid[128];
    size_t oidsz;
    for (i = 0; ; ++i) {
        oidsz = sizeof(oid);
        rc = gnutls_x509_crt_get_extension_info(crt, i, oid, &oidsz, NULL);
        if (rc < 0 || 0 == strcmp(oid, GNUTLS_X509EXT_OID_TLSFEATURES)) break;
    }
    /* ext not found if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) */
    if (rc < 0) return rc;

    gnutls_datum_t der = { NULL, 0 };
    rc = gnutls_x509_crt_get_extension_data2(crt, i, &der);
    if (rc < 0) return rc;

    /* DER encoding (Tag, Length, Value (TLV)) expecting: 30:03:02:01:05
     * [TL[TLV]] (30=Sequence, Len=03, (02=Integer, Len=01, Value=05))
     * XXX: This is not future-proof if TLS feature list values are extended */
    /*const char must_staple[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };*/
    /*rc = (der.size == 5 && 0 == memcmp(der.data, must_staple, 5))*/
    rc = (der.size >= 5 && der.data[0] == 0x30 && der.data[1] >= 0x03
          && der.data[2] == 0x2 && der.data[3] == 0x1 && der.data[4] == 0x5)
      ? 1
      : 0;

    gnutls_free(der.data);

  #else

    gnutls_x509_tlsfeatures_t f;
    rc = gnutls_x509_tlsfeatures_init(&f);
    if (rc < 0) return rc;
    rc = gnutls_x509_tlsfeatures_add(f, 5); /* 5 = OCSP Must-Staple */
    if (rc < 0) return rc;
    rc = (0 != gnutls_x509_tlsfeatures_check_crt(f, crt));
    gnutls_x509_tlsfeatures_deinit(f);

  #endif

    return rc; /* 1 if OCSP Must-Staple found; 0 if not */
}


static int
mod_gnutls_construct_crt_chain (plugin_cert *pc, gnutls_datum_t *d, log_error_st *errh)
{
    /* Historically, openssl will use the cert chain in (SSL_CTX *) if a cert
     * does not have a chain configured in (SSL *).  Attempt to provide
     * compatible behavior here.  This may be called after startup since
     * ssl.pemfile might be defined in a config scope without ssl.ca-file,
     * and at runtime is when ssl.ca-file (e.g. from matching $SERVER["socket"])
     * would be known along with ssl.pemfile (e.g. from $HTTP["host"]) */

    gnutls_certificate_credentials_t ssl_cred;
    int rc = gnutls_certificate_allocate_credentials(&ssl_cred);
    if (rc < 0) return rc;
    unsigned int ncrt = (d ? d->size : 0);
    unsigned int off = (d == pc->ssl_pemfile_x509) ? 0 : 1;
    gnutls_pcert_st * const pcert_list =
      gnutls_malloc(sizeof(gnutls_pcert_st) * (off+ncrt));
    if (NULL == pcert_list) {
        gnutls_certificate_free_credentials(ssl_cred);
        return GNUTLS_E_MEMORY_ERROR;
    }
    memset(pcert_list, 0, sizeof(gnutls_pcert_st) * (off+ncrt));
    rc = 0;

    if (off) { /*(add crt to chain if different from d)*/
        /*assert(pc->ssl_pemfile_x509->size == 1)*/
        gnutls_x509_crt_t *crts =
          (gnutls_x509_crt_t *)(void *)pc->ssl_pemfile_x509->data;
        rc = gnutls_pcert_import_x509(pcert_list, crts[0], 0);
    }

    if (0 == rc && ncrt) {
        gnutls_x509_crt_t *crts = (gnutls_x509_crt_t *)(void *)d->data;
      #if GNUTLS_VERSION_NUMBER < 0x030400
        /*(GNUTLS_X509_CRT_LIST_SORT not needed; crts sorted when file read)*/
        rc = gnutls_pcert_import_x509_list(pcert_list+off, crts, &ncrt, 0);
      #else /* manually import list, but note that sorting is not implemented */
        rc = 0;
        for (unsigned int i = 0; i < ncrt; ++i) {
            rc = gnutls_pcert_import_x509(pcert_list+off+i, crts[i], 0);
            if (rc < 0) break;
        }
      #endif
    }
    ncrt += off;
    if (0 == rc)
        rc = gnutls_certificate_set_key(ssl_cred, NULL, 0, pcert_list, ncrt,
                                        pc->ssl_pemfile_pkey);
    if (rc < 0) {
        for (unsigned int i = 0; i < ncrt; ++i)
            gnutls_pcert_deinit(pcert_list+i);
        gnutls_free(pcert_list);
        gnutls_certificate_free_credentials(ssl_cred);
        elog(errh, __FILE__, __LINE__, rc, "gnutls_certificate_set_key()");
        return rc;
    }
    /* XXX: gnutls_certificate_set_key() has an inconsistent implementation.
     * On success, key ownership is transferred, and so should not be freed,
     * but pcert_list is a shallow memcpy(), so gnutls_pcert_deinit() should
     * not be run on gnutls_pcert_st in list, though top-level list storage
     * should be freed.  On failure, ownership is not transferred for either. */
    gnutls_free(pcert_list);
    pc->ssl_pemfile_pkey = NULL;
    pc->ssl_cred = ssl_cred;

    /* release lists used to configure pc->ssl_cred */
    mod_gnutls_free_config_crts(pc->ssl_pemfile_x509);
    pc->ssl_pemfile_x509 = NULL;

    return 0;
}


static void *
network_gnutls_load_pemfile (server *srv, const buffer *pemfile, const buffer *privkey, const buffer *ssl_stapling_file)
{
  #if 0 /* see comments in mod_gnutls_construct_crt_chain() above */

    gnutls_certificate_credentials_t ssl_cred = NULL;
    int rc;

    rc = gnutls_certificate_allocate_credentials(&ssl_cred);
    if (rc < 0) return NULL;

    rc = gnutls_certificate_set_x509_key_file2(ssl_cred,
                                               pemfile->ptr, privkey->ptr,
                                               GNUTLS_X509_FMT_PEM, NULL, 0);
    if (rc < 0) {
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "gnutls_certificate_set_x509_key_file2(%s, %s)",
              pemfile->ptr, privkey->ptr);
        gnutls_certificate_free_credentials(ssl_cred);
        return NULL;
    }

    plugin_cert *pc = malloc(sizeof(plugin_cert));
    force_assert(pc);
    pc->ssl_cred = ssl_cred;
    pc->trust_inited = 0;

    return pc;

  #else

    gnutls_datum_t *d = mod_gnutls_load_config_crts(pemfile->ptr, srv->errh);
    if (NULL == d) return NULL;
    if (0 == d->size) {
        mod_gnutls_free_config_crts(d);
        return NULL;
    }

    gnutls_privkey_t pkey = mod_gnutls_load_config_pkey(privkey->ptr,srv->errh);
    if (NULL == pkey) {
        mod_gnutls_free_config_crts(d);
        return NULL;
    }

    plugin_cert *pc = malloc(sizeof(plugin_cert));
    force_assert(pc);
    pc->ssl_cred = NULL;
    pc->trust_inited = 0;
    pc->ssl_pemfile_x509 = d;
    pc->ssl_pemfile_pkey = pkey;
    pc->ssl_stapling_file= ssl_stapling_file;
    pc->ssl_stapling_loadts = 0;
    pc->ssl_stapling_nextts = 0;
    pc->must_staple =
      mod_gnutls_crt_must_staple(((gnutls_x509_crt_t *)(void *)d->data)[0]);

    if (d->size > 1) { /*(certificate chain provided)*/
        int rc = mod_gnutls_construct_crt_chain(pc, d, srv->errh);
        if (rc < 0) {
            mod_gnutls_free_config_crts(d);
            gnutls_privkey_deinit(pkey);
            free(pc);
            return NULL;
        }
    }

    if (pc->ssl_stapling_file) {
        if (mod_gnutls_reload_stapling_file(srv, pc, log_epoch_secs) < 0) {
            /* continue without OCSP response if there is an error */
        }
    }
    else if (pc->must_staple) {
        log_error(srv->errh, __FILE__, __LINE__,
                  "certificate %s marked OCSP Must-Staple, "
                  "but ssl.stapling-file not provided", pemfile->ptr);
    }

    return pc;

  #endif
}


#if GNUTLS_VERSION_NUMBER >= 0x030200

static int
mod_gnutls_acme_tls_1 (handler_ctx *hctx)
{
    buffer * const b = hctx->tmp_buf;
    const buffer * const name = &hctx->r->uri.authority;
    log_error_st * const errh = hctx->r->conf.errh;
    int rc = GNUTLS_E_INVALID_REQUEST;

    /* check if acme-tls/1 protocol is enabled (path to dir of cert(s) is set)*/
    if (!hctx->conf.ssl_acme_tls_1)
        return 0;

    /* check if SNI set server name (required for acme-tls/1 protocol)
     * and perform simple path checks for no '/'
     * and no leading '.' (e.g. ignore "." or ".." or anything beginning '.') */
    if (buffer_is_blank(name))          return rc;
    if (NULL != strchr(name->ptr, '/')) return rc;
    if (name->ptr[0] == '.')            return rc;
  #if 0
    if (0 != http_request_host_policy(name, hctx->r->conf.http_parseopts, 443))
        return rc;
  #endif
    buffer_copy_path_len2(b, BUF_PTR_LEN(hctx->conf.ssl_acme_tls_1),
                             BUF_PTR_LEN(name));

  #if 0

    buffer *privkey = buffer_init_buffer(b);
    buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));
    buffer_append_string_len(privkey, CONST_STR_LEN(".key.pem"));

    /*(similar to network_gnutls_load_pemfile() but propagates rc)*/
    gnutls_certificate_credentials_t ssl_cred = NULL;
    rc = gnutls_certificate_allocate_credentials(&ssl_cred);
    if (rc < 0) { buffer_free(privkey); return rc; }
    rc = gnutls_certificate_set_x509_key_file2(ssl_cred,
                                               b->ptr, privkey->ptr,
                                               GNUTLS_X509_FMT_PEM, NULL, 0);
    if (rc < 0) {
        elogf(errh, __FILE__, __LINE__, rc,
              "failed to load acme-tls/1 cert (%s, %s)",
              b->ptr, privkey->ptr);
        buffer_free(privkey);
        gnutls_certificate_free_credentials(ssl_cred);
        return rc;
    }
    buffer_free(privkey);

  #else

    /* gnutls_certificate_set_x509_key_file2() does not securely wipe
     * sensitive data from memory, so take a few extra steps */

    /* similar to network_gnutls_load_pemfile() */

    uint32_t len = buffer_clen(b);
    buffer_append_string_len(b, CONST_STR_LEN(".crt.pem"));

    gnutls_datum_t *d = mod_gnutls_load_config_crts(b->ptr, errh);
    if (NULL == d) return GNUTLS_E_FILE_ERROR;
    if (0 == d->size) {
        mod_gnutls_free_config_crts(d);
        return GNUTLS_E_FILE_ERROR;
    }

    buffer_truncate(b, len);
    buffer_append_string_len(b, CONST_STR_LEN(".key.pem"));

    gnutls_privkey_t pkey = mod_gnutls_load_config_pkey(b->ptr, errh);
    if (NULL == pkey) {
        mod_gnutls_free_config_crts(d);
        return GNUTLS_E_FILE_ERROR;
    }

    plugin_cert pc;
    pc.ssl_cred = NULL;
    pc.trust_inited = 0;
    pc.ssl_pemfile_x509 = d;
    pc.ssl_pemfile_pkey = pkey;

    rc = mod_gnutls_construct_crt_chain(&pc, d, errh);
    if (rc < 0) {
        mod_gnutls_free_config_crts(d);
        gnutls_privkey_deinit(pkey);
        return rc;
    }

    gnutls_certificate_credentials_t ssl_cred = pc.ssl_cred;

  #endif

    hctx->acme_tls_1_cred = ssl_cred; /*(save ptr and free later)*/

    gnutls_credentials_clear(hctx->ssl);
    rc = gnutls_credentials_set(hctx->ssl, GNUTLS_CRD_CERTIFICATE, ssl_cred);
    if (rc < 0) {
        elogf(hctx->r->conf.errh, __FILE__, __LINE__, rc,
              "failed to set acme-tls/1 certificate for TLS server name %s",
              hctx->r->uri.authority.ptr);
        return rc;
    }

    /*(acme-tls/1 is separate from certificate auth access to website)*/
    gnutls_certificate_server_set_request(hctx->ssl, GNUTLS_CERT_IGNORE);

    return GNUTLS_E_SUCCESS; /* 0 */
}


static int
mod_gnutls_alpn_h2_policy (handler_ctx * const hctx)
{
    /*(currently called after handshake has completed)*/
  #if 0 /* SNI omitted by client when connecting to IP instead of to name */
    if (buffer_is_blank(&hctx->r->uri.authority)) {
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: error ALPN h2 without SNI");
        return -1;
    }
  #endif
    if (gnutls_protocol_get_version(hctx->ssl) < GNUTLS_TLS1_2) {
        /*(future: if DTLS supported by lighttpd, add DTLS condition)*/
        log_error(hctx->errh, __FILE__, __LINE__,
          "SSL: error ALPN h2 requires TLSv1.2 or later");
        return -1;
    }

    return 0;
}


enum {
  MOD_GNUTLS_ALPN_HTTP11      = 1
 ,MOD_GNUTLS_ALPN_HTTP10      = 2
 ,MOD_GNUTLS_ALPN_H2          = 3
 ,MOD_GNUTLS_ALPN_ACME_TLS_1  = 4
};


/* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
static int
mod_gnutls_ALPN (handler_ctx * const hctx, const unsigned char * const in, const unsigned int inlen)
{
    /*(skip first two bytes which should match inlen-2)*/
    for (unsigned int i = 2, n; i < inlen; i += n) {
        n = in[i++];
        if (i+n > inlen || 0 == n) break;

        switch (n) {
          case 2:  /* "h2" */
            if (in[i] == 'h' && in[i+1] == '2') {
                if (!hctx->r->conf.h2proto) continue;
                hctx->alpn = MOD_GNUTLS_ALPN_H2;
                hctx->r->http_version = HTTP_VERSION_2;
                return GNUTLS_E_SUCCESS;
            }
            continue;
          case 8:  /* "http/1.1" "http/1.0" */
            if (0 == memcmp(in+i, "http/1.", 7)) {
                if (in[i+7] == '1') {
                    hctx->alpn = MOD_GNUTLS_ALPN_HTTP11;
                    return GNUTLS_E_SUCCESS;
                }
                if (in[i+7] == '0') {
                    hctx->alpn = MOD_GNUTLS_ALPN_HTTP10;
                    return GNUTLS_E_SUCCESS;
                }
            }
            continue;
          case 10: /* "acme-tls/1" */
            if (0 == memcmp(in+i, "acme-tls/1", 10)) {
                int rc = mod_gnutls_acme_tls_1(hctx);
                if (0 == rc) {
                    hctx->alpn = MOD_GNUTLS_ALPN_ACME_TLS_1;
                    return GNUTLS_E_SUCCESS;
                }
                return rc;
            }
            continue;
          default:
            continue;
        }
    }

    return GNUTLS_E_SUCCESS;
}

#endif /* GNUTLS_VERSION_NUMBER >= 0x030200 */


static int
mod_gnutls_SNI(handler_ctx * const hctx,
               const unsigned char *servername, unsigned int len)
{
    /* https://www.gnutls.org/manual/gnutls.html#Virtual-hosts-and-credentials
     * figure the advertized name - the following hack relies on the fact that
     * this extension only supports DNS names, and due to a protocol bug cannot
     * be extended to support anything else. */
    if (len < 5) return 0;
    len -= 5;
    servername += 5;
    request_st * const r = hctx->r;
    buffer_copy_string_len(&r->uri.scheme, CONST_STR_LEN("https"));

    if (len >= 1024) { /*(expecting < 256; TLSEXT_MAXLEN_host_name is 255)*/
        log_error(r->conf.errh, __FILE__, __LINE__,
                  "GnuTLS: SNI name too long %.*s", (int)len, servername);
        return GNUTLS_E_INVALID_REQUEST;
    }

    /* use SNI to patch mod_gnutls config and then reset COMP_HTTP_HOST */
    buffer_copy_string_len_lc(&r->uri.authority, (const char *)servername, len);
  #if 0
    /*(r->uri.authority used below for configuration before request read;
     * revisit for h2)*/
    if (0 != http_request_host_policy(&r->uri.authority,
                                      r->conf.http_parseopts, 443))
        return GNUTLS_E_INVALID_REQUEST;
  #endif

    r->conditional_is_valid |= (1 << COMP_HTTP_SCHEME)
                            |  (1 << COMP_HTTP_HOST);

    mod_gnutls_patch_config(r, &hctx->conf);
    /* reset COMP_HTTP_HOST so that conditions re-run after request hdrs read */
    /*(done in configfile-glue.c:config_cond_cache_reset() after request hdrs read)*/
    /*config_cond_cache_reset_item(r, COMP_HTTP_HOST);*/
    /*buffer_clear(&r->uri.authority);*/

    return 0;
}


static int
mod_gnutls_client_hello_ext_cb(void *ctx, unsigned int tls_id,
                               const unsigned char *data, unsigned int dlen)
{
    switch (tls_id) {
      case 0:  /* Server Name */
        return mod_gnutls_SNI((handler_ctx *)ctx, data, dlen);
     #if GNUTLS_VERSION_NUMBER >= 0x030200
      case 16: /* ALPN */
        return mod_gnutls_ALPN((handler_ctx *)ctx, data, dlen);
     #endif
      /*case 35:*/ /* Session Ticket */
      default:
        break;
    }

    return GNUTLS_E_SUCCESS; /* 0 */
}


static int
mod_gnutls_client_hello_hook(gnutls_session_t ssl, unsigned int htype,
                             unsigned when, unsigned int incoming,
                             const gnutls_datum_t *msg)
{
    /*assert(htype == GNUTLS_HANDSHAKE_CLIENT_HELLO);*/
    /*assert(when == GNUTLS_HOOK_PRE);*/
    UNUSED(htype);
    UNUSED(when);
    UNUSED(incoming);

    handler_ctx * const hctx = gnutls_session_get_ptr(ssl);
  #if GNUTLS_VERSION_NUMBER >= 0x030200
    /*(do not repeat if acme-tls/1 creds have been set
     * and still in handshake (hctx->alpn not unset yet))*/
    if (hctx->alpn == MOD_GNUTLS_ALPN_ACME_TLS_1)
        return GNUTLS_E_SUCCESS; /* 0 */
  #endif
    /* ??? why might this be called more than once ??? renegotiation? */
    void *existing_cred = NULL;
    if (0 == gnutls_credentials_get(ssl, GNUTLS_CRD_CERTIFICATE, &existing_cred)
        && existing_cred)
        return GNUTLS_E_SUCCESS; /* 0 */

    int rc = gnutls_ext_raw_parse(hctx, mod_gnutls_client_hello_ext_cb, msg,
                                  GNUTLS_EXT_RAW_FLAG_TLS_CLIENT_HELLO);
    if (rc < 0) {
        log_error_st *errh = hctx->r->conf.errh;
        elog(errh, __FILE__, __LINE__, rc, "gnutls_ext_raw_parse()");
        return rc;
    }

  #if GNUTLS_VERSION_NUMBER >= 0x030200
    /* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
    static const gnutls_datum_t alpn_protos_http_acme[] = {
      { (unsigned char *)CONST_STR_LEN("h2") }
     ,{ (unsigned char *)CONST_STR_LEN("http/1.1") }
     ,{ (unsigned char *)CONST_STR_LEN("http/1.0") }
     ,{ (unsigned char *)CONST_STR_LEN("acme-tls/1") }
    };
    unsigned int n = hctx->conf.ssl_acme_tls_1 ? 4 : 3;
    const gnutls_datum_t *alpn_protos = alpn_protos_http_acme;
    if (!hctx->r->conf.h2proto) {
        ++alpn_protos;
        --n;
    }
    /*unsigned int flags = GNUTLS_ALPN_SERVER_PRECEDENCE;*/
    rc = gnutls_alpn_set_protocols(hctx->ssl, alpn_protos, n, 0);
    if (rc < 0) {
        log_error_st *errh = hctx->r->conf.errh;
        elog(errh, __FILE__, __LINE__, rc, "gnutls_alpn_set_protocols()");
        return rc;
    }
    /*(skip below if creds already set for acme-tls/1
     * via mod_gnutls_client_hello_ext_cb())*/
    if (hctx->alpn == MOD_GNUTLS_ALPN_ACME_TLS_1)
        return GNUTLS_E_SUCCESS; /* 0 */
  #endif

  #if 0 /* must enable before GnuTLS client hello hook */
    /* GnuTLS returns an error here if TLSv1.3 (? key already set ?) */
    /* see mod_gnutls_handle_con_accept() */
    /* future: ? handle in mod_gnutls_client_hello_ext_cb() */
    if (hctx->ssl_session_ticket && session_ticket_key.size) {
        /* XXX: NOT done: parse client hello for session ticket extension
         *      and choose from among multiple keys */
        rc = gnutls_session_ticket_enable_server(ssl, &session_ticket_key);
        if (rc < 0) {
            elog(hctx->r->conf.errh, __FILE__, __LINE__, rc,
                 "gnutls_session_ticket_enable_server()");
            return rc;
        }
    }
  #endif

    if (NULL == hctx->conf.pc->ssl_cred) {
        rc = mod_gnutls_construct_crt_chain(hctx->conf.pc,
                                            hctx->conf.ssl_ca_file,
                                            hctx->r->conf.errh);
        if (rc < 0) return rc;
    }

    gnutls_certificate_credentials_t ssl_cred = hctx->conf.pc->ssl_cred;

    hctx->verify_status = ~0u;
    gnutls_certificate_request_t req = GNUTLS_CERT_IGNORE;
    if (hctx->conf.ssl_verifyclient) {
        /*(cred shared; settings should be consistent across site using cred)*/
        /*(i.e. settings for client certs must not differ under this cred)*/
        req = hctx->conf.ssl_verifyclient_enforce
          ? GNUTLS_CERT_REQUIRE
          : GNUTLS_CERT_REQUEST;
        gnutls_certificate_set_verify_function(ssl_cred, mod_gnutls_verify_cb);
        gnutls_certificate_set_verify_limits(ssl_cred, 8200 /*(default)*/,
                                             hctx->conf.ssl_verifyclient_depth);
        rc = mod_gnutls_verify_set_tlist(hctx, 1); /* for client cert request */
        if (rc < 0) return rc;
    }
    gnutls_certificate_server_set_request(ssl, req);

  #if GNUTLS_VERSION_NUMBER < 0x030600
    if (hctx->conf.dh_params)
        gnutls_certificate_set_dh_params(ssl_cred, hctx->conf.dh_params);
   #if GNUTLS_VERSION_NUMBER >= 0x030506
    else
        gnutls_certificate_set_known_dh_params(ssl_cred, GNUTLS_SEC_PARAM_HIGH);
   #endif
  #endif

    rc = gnutls_credentials_set(ssl, GNUTLS_CRD_CERTIFICATE, ssl_cred);
    if (rc < 0) {
        elogf(hctx->r->conf.errh, __FILE__, __LINE__, rc,
              "failed to set SNI certificate for TLS server name %s",
              hctx->r->uri.authority.ptr);
        return rc;
    }

    return GNUTLS_E_SUCCESS; /* 0 */
}


static int
mod_gnutls_ssl_conf_ciphersuites (server *srv, plugin_config_socket *s, buffer *ciphersuites, const buffer *cipherstring);


static int
mod_gnutls_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist);


static void
mod_gnutls_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *minb, const buffer *maxb);


static int
mod_gnutls_ssl_conf_cmd (server *srv, plugin_config_socket *s)
{
    /* reference:
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_CONF_cmd.html */
    int rc = 0;
    buffer *cipherstring = NULL;
    buffer *ciphersuites = NULL;
    buffer *minb = NULL;
    buffer *maxb = NULL;
    buffer *curves = NULL;

    for (size_t i = 0; i < s->ssl_conf_cmd->used; ++i) {
        data_string *ds = (data_string *)s->ssl_conf_cmd->data[i];
        if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("CipherString")))
            cipherstring = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Ciphersuites")))
            ciphersuites = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Curves"))
              || buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Groups")))
            curves = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MaxProtocol")))
            maxb = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("MinProtocol")))
            minb = &ds->value;
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Protocol"))) {
            /* openssl config for Protocol=... is complex and deprecated */
            log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: ssl.openssl.ssl-conf-cmd %s ignored; "
                      "use MinProtocol=... and MaxProtocol=... instead",
                      ds->key.ptr);
        }
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("Options"))) {
            for (char *v = ds->value.ptr, *e; *v; v = e) {
                while (*v == ' ' || *v == '\t' || *v == ',') ++v;
                int flag = 1;
                if (*v == '-') {
                    flag = 0;
                    ++v;
                }
                for (e = v; light_isalpha(*e); ++e) ;
                switch ((int)(e-v)) {
                  case 11:
                    if (buffer_eq_icase_ssn(v, "Compression", 11)) {
                        /* GnuTLS 3.6.0+ no longer implements
                         * any support for compression */
                        if (!flag) continue;
                    }
                    break;
                  case 13:
                    if (buffer_eq_icase_ssn(v, "SessionTicket", 13)) {
                        /*(translates to "%NO_TICKETS" priority str if !flag)*/
                        s->ssl_session_ticket = flag;
                        continue;
                    }
                    break;
                  case 16:
                    if (buffer_eq_icase_ssn(v, "ServerPreference", 16)) {
                        /*(translates to "%SERVER_PRECEDENCE" priority string)*/
                        s->ssl_honor_cipher_order = flag;
                        continue;
                    }
                    break;
                  default:
                    break;
                }
                /* warn if not explicitly handled or ignored above */
                if (!flag) --v;
                log_error(srv->errh, __FILE__, __LINE__,
                          "GnuTLS: ssl.openssl.ssl-conf-cmd Options %.*s "
                          "ignored", (int)(e-v), v);
            }
        }
        else if (buffer_eq_icase_slen(&ds->key,
                                      CONST_STR_LEN("gnutls-override"))) {
            s->priority_override = &ds->value;
        }
      #if 0
        else if (buffer_eq_icase_slen(&ds->key, CONST_STR_LEN("..."))) {
        }
      #endif
        else {
            /* warn if not explicitly handled or ignored above */
            log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: ssl.openssl.ssl-conf-cmd %s ignored",
                      ds->key.ptr);
        }
    }

    if (minb || maxb) /*(if at least one was set)*/
        mod_gnutls_ssl_conf_proto(srv, s, minb, maxb);

    if (!mod_gnutls_ssl_conf_ciphersuites(srv, s, ciphersuites, cipherstring))
        rc = -1;

    if (curves) {
        if (!s->ssl_ec_curve)
            buffer_append_string_len(&s->priority_str,
                                     CONST_STR_LEN("-CURVE-ALL:"));
        if (!mod_gnutls_ssl_conf_curves(srv, s, curves))
            rc = -1;
    }

    return rc;
}


static int
network_init_ssl (server *srv, plugin_config_socket *s, plugin_data *p)
{
    int rc;
    UNUSED(p);

    /* construct GnuTLS "priority" string
     *
     * default: NORMAL (since GnuTLS 3.3.0, could also use NULL for defaults)
     * SUITEB128 and SUITEB192 are stricter than NORMAL
     * (and are attempted to be supported in mod_gnutls_ssl_conf_ciphersuites())
     *
     * gnutls defaults to %PARTIAL_RENEGOTIATION (see manual)
     * mod_gnutls does not attempt to support
     *   hctx->conf.ssl_disable_client_renegotiation == 0
     * though possible with %UNSAFE_RENEGOTATION
     */

  #if GNUTLS_VERSION_NUMBER < 0x030600
    /* GnuTLS 3.6.0+ no longer implements any support for compression,
     * but we still explicitly disable for earlier versions */
    buffer_append_string_len(&s->priority_str,
                             CONST_STR_LEN("-COMP_ALL:+COMP-NULL:"));
  #endif

    if (s->ssl_cipher_list) {
        if (!mod_gnutls_ssl_conf_ciphersuites(srv,s,NULL,s->ssl_cipher_list))
            return -1;
    }

  #if GNUTLS_VERSION_NUMBER < 0x030600
    if (s->ssl_dh_file) {
        /* "Prior to GnuTLS 3.6.0 for the ephemeral or anonymous Diffie-Hellman
         * (DH) TLS ciphersuites the application was required to generate or
         * provide DH parameters. That is no longer necessary as GnuTLS utilizes
         * DH parameters and negotiation from [RFC7919]."
         */
        /* In other words, the following should not be used in 3.6.0 or later:
         *   gnutls_certificate_set_dh_params()
         *   gnutls_certificate_set_known_dh_params()
         * However, if support is implemented in mod_gnutls, must also free in
         * mod_gnutls_free_config() as gnutls_certificate_free_credentials()
         * does not free RSA or DH params manually associated with credential */
        gnutls_datum_t f = { NULL, 0 };
        rc = gnutls_dh_params_init(&s->dh_params);
        if (rc < 0) return -1;
        rc = mod_gnutls_load_file(s->ssl_dh_file->ptr, &f, srv->errh);
        if (rc < 0) return -1;
        rc = gnutls_dh_params_import_pkcs3(s->dh_params,&f,GNUTLS_X509_FMT_PEM);
        mod_gnutls_datum_wipe(&f);
        if (rc < 0) {
            elogf(srv->errh, __FILE__, __LINE__, rc,
                  "gnutls_dh_params_import_pkcs3() %s", s->ssl_dh_file->ptr);
            return -1;
        }
    }
    else {
      #if GNUTLS_VERSION_NUMBER < 0x030506
        /* (this might take a while; you should upgrade to newer gnutls) */
        rc = gnutls_dh_params_init(&s->dh_params);
        if (rc < 0) return -1;
        unsigned int bits =
          gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_HIGH);
        rc = gnutls_dh_params_generate2(s->dh_params, bits);
        if (rc < 0) {
            elogf(srv->errh, __FILE__, __LINE__, rc,
                  "gnutls_dh_params_generate2()");
            return -1;
        }
      #endif
    }
  #endif /* GNUTLS_VERSION_NUMBER < 0x030600 */

    if (s->ssl_ec_curve) {
        buffer_append_string_len(&s->priority_str,
                                 CONST_STR_LEN("-CURVE-ALL:"));
        if (!mod_gnutls_ssl_conf_curves(srv, s, s->ssl_ec_curve))
            return -1;
    }

    if (s->ssl_conf_cmd && s->ssl_conf_cmd->used) {
        if (0 != mod_gnutls_ssl_conf_cmd(srv, s)) return -1;
    }

    if (s->ssl_honor_cipher_order)
        buffer_append_string_len(&s->priority_str,
                                 CONST_STR_LEN("%SERVER_PRECEDENCE:"));

    if (!s->ssl_session_ticket)
        buffer_append_string_len(&s->priority_str,
                                 CONST_STR_LEN("%NO_TICKETS:"));

    if (!s->ssl_use_sslv3 && !s->ssl_use_sslv2
        && NULL == strstr(s->priority_str.ptr, "-VERS-ALL:"))
        mod_gnutls_ssl_conf_proto(srv, s, NULL, NULL);

    /* explicitly disable SSLv3 unless enabled in config
     * (gnutls library would also need to be compiled with legacy support) */
    if (!s->ssl_use_sslv3)
        buffer_append_string_len(&s->priority_str,
                                 CONST_STR_LEN("-VERS-SSL3.0:"));

    /* gnutls_priority_init2() is available since GnuTLS 3.6.3 and could be
     * called once with s->priority_base, and a second time with s->priority_str
     * and GNUTLS_PRIORITY_INIT_DEF_APPEND, but preserve compat with earlier
     * GnuTLS by concatenating into a single priority string */

    buffer *b = srv->tmp_buf;
    if (NULL == s->priority_base) s->priority_base = "NORMAL";
    buffer_copy_string_len(b, s->priority_base, strlen(s->priority_base));
    if (!buffer_is_blank(&s->priority_str)) {
        buffer_append_string_len(b, CONST_STR_LEN(":"));
        uint32_t len = buffer_clen(&s->priority_str);
        if (s->priority_str.ptr[len-1] == ':')
            --len; /* remove trailing ':' */
        buffer_append_string_len(b, s->priority_str.ptr, len);
    }

    if (s->priority_override && !buffer_is_blank(s->priority_override)) {
        b = s->priority_override;
        s->ssl_session_ticket = (NULL == strstr(b->ptr, "%NO_TICKET"));
    }

    if (p->defaults.ssl_log_noise)
        log_error(srv->errh, __FILE__, __LINE__,
                  "debug: GnuTLS priority string: %s", b->ptr);

    const char *err_pos;
    rc = gnutls_priority_init(&s->priority_cache, b->ptr, &err_pos);
    if (rc < 0) {
        elogf(srv->errh, __FILE__, __LINE__, rc,
              "gnutls_priority_init() error near %s", err_pos);
        return -1;
    }

    return 0;
}


static int
mod_gnutls_set_defaults_sockets(server *srv, plugin_data *p)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.engine"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.cipher-list"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.honor-cipher-order"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.dh-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ec-curve"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.openssl.ssl-conf-cmd"),
        T_CONFIG_ARRAY_KVSTRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.pemfile"), /* included to process global scope */
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.empty-fragments"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.use-sslv2"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.use-sslv3"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.stek-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_SERVER }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };
    static const buffer default_ssl_cipher_list = { CONST_STR_LEN("HIGH"), 0 };

    p->ssl_ctxs = calloc(srv->config_context->used, sizeof(plugin_ssl_ctx));
    force_assert(p->ssl_ctxs);

    int rc = HANDLER_GO_ON;
    plugin_data_base srvplug;
    memset(&srvplug, 0, sizeof(srvplug));
    plugin_data_base * const ps = &srvplug;
    if (!config_plugin_values_init(srv, ps, cpk, "mod_gnutls"))
        return HANDLER_ERROR;

    plugin_config_socket defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.ssl_honor_cipher_order = 1; /* default server preference for PFS */
    defaults.ssl_session_ticket     = 1; /* enabled by default */
    defaults.ssl_cipher_list        = &default_ssl_cipher_list;

    /* process and validate config directives for global and $SERVER["socket"]
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !ps->cvlist[0].v.u2[1]; i < ps->nconfig; ++i) {
        config_cond_info cfginfo;
        config_get_config_cond_info(&cfginfo, (uint32_t)ps->cvlist[i].k_id);
        int is_socket_scope = (0 == i || cfginfo.comp == COMP_SERVER_SOCKET);
        int count_not_engine = 0;

        plugin_config_socket conf;
        memcpy(&conf, &defaults, sizeof(conf));

        /*(preserve prior behavior; not inherited)*/
        /*(forcing inheritance might break existing configs where SSL is enabled
         * by default in the global scope, but not $SERVER["socket"]=="*:80") */
        conf.ssl_enabled = 0;

        config_plugin_value_t *cpv = ps->cvlist + ps->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            /* ignore ssl.pemfile (k_id=6); included to process global scope */
            if (!is_socket_scope && cpv->k_id != 6) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: %s is valid only in global scope or "
                  "$SERVER[\"socket\"] condition", cpk[cpv->k_id].k);
                continue;
            }
            ++count_not_engine;
            switch (cpv->k_id) {
              case 0: /* ssl.engine */
                conf.ssl_enabled = (0 != cpv->v.u);
                --count_not_engine;
                break;
              case 1: /* ssl.cipher-list */
                if (!buffer_is_blank(cpv->v.b))
                    conf.ssl_cipher_list = cpv->v.b;
                break;
              case 2: /* ssl.honor-cipher-order */
                conf.ssl_honor_cipher_order = (0 != cpv->v.u);
                break;
              case 3: /* ssl.dh-file */
               #if GNUTLS_VERSION_NUMBER < 0x030600
                if (!buffer_is_blank(cpv->v.b))
                    conf.ssl_dh_file = cpv->v.b;
               #else
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: ignoring ssl.dh-file; "
                  "obsoleted in GnuTLS 3.6.0 and later implementing RFC7919");
               #endif
                break;
              case 4: /* ssl.ec-curve */
                if (!buffer_is_blank(cpv->v.b))
                    conf.ssl_ec_curve = cpv->v.b;
                break;
              case 5: /* ssl.openssl.ssl-conf-cmd */
                *(const array **)&conf.ssl_conf_cmd = cpv->v.a;
                break;
              case 6: /* ssl.pemfile */
                /* ignore here; included to process global scope when
                 * ssl.pemfile is set, but ssl.engine is not "enable" */
                break;
              case 7: /* ssl.empty-fragments */
                conf.ssl_empty_fragments = (0 != cpv->v.u);
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: ignoring ssl.empty-fragments; openssl-specific "
                  "counter-measure against a SSL 3.0/TLS 1.0 protocol "
                  "vulnerability affecting CBC ciphers, which cannot be handled"
                  " by some broken (Microsoft) SSL implementations.");
                break;
              case 8: /* ssl.use-sslv2 */
                conf.ssl_use_sslv2 = (0 != cpv->v.u);
                log_error(srv->errh, __FILE__, __LINE__, "GnuTLS: "
                  "ssl.use-sslv2 is deprecated and will soon be removed.  "
                  "Many modern TLS libraries no longer support SSLv2.");
                break;
              case 9: /* ssl.use-sslv3 */
                conf.ssl_use_sslv3 = (0 != cpv->v.u);
                log_error(srv->errh, __FILE__, __LINE__, "GnuTLS: "
                  "ssl.use-sslv3 is deprecated and will soon be removed.  "
                  "Many modern TLS libraries no longer support SSLv3.  "
                  "If needed, use: "
                  "ssl.openssl.ssl-conf-cmd = (\"MinProtocol\" => \"SSLv3\")");
                break;
              case 10:/* ssl.stek-file */
                if (!buffer_is_blank(cpv->v.b))
                    p->ssl_stek_file = cpv->v.b->ptr;
                break;
              default:/* should not happen */
                break;
            }
        }
        if (HANDLER_GO_ON != rc) break;
        if (0 == i) memcpy(&defaults, &conf, sizeof(conf));

        if (0 != i && !conf.ssl_enabled) continue;

        /* fill plugin_config_socket with global context then $SERVER["socket"]
         * only for directives directly in current $SERVER["socket"] condition*/

        /*conf.pc                     = p->defaults.pc;*/
        conf.ssl_verifyclient         = p->defaults.ssl_verifyclient;
        conf.ssl_verifyclient_enforce = p->defaults.ssl_verifyclient_enforce;
        conf.ssl_verifyclient_depth   = p->defaults.ssl_verifyclient_depth;

        int sidx = ps->cvlist[i].k_id;
        for (int j = !p->cvlist[0].v.u2[1]; j < p->nconfig; ++j) {
            if (p->cvlist[j].k_id != sidx) continue;
            /*if (0 == sidx) break;*//*(repeat to get ssl_pemfile,ssl_privkey)*/
            cpv = p->cvlist + p->cvlist[j].v.u2[0];
            for (; -1 != cpv->k_id; ++cpv) {
                ++count_not_engine;
                switch (cpv->k_id) {
                  case 0: /* ssl.pemfile */
                    if (cpv->vtype == T_CONFIG_LOCAL)
                        conf.pc = cpv->v.v;
                    break;
                  case 7: /* ssl.verifyclient.activate */
                    conf.ssl_verifyclient = (0 != cpv->v.u);
                    break;
                  case 8: /* ssl.verifyclient.enforce */
                    conf.ssl_verifyclient_enforce = (0 != cpv->v.u);
                    break;
                  case 9: /* ssl.verifyclient.depth */
                    conf.ssl_verifyclient_depth = (unsigned char)cpv->v.shrt;
                    break;
                  default:
                    break;
                }
            }
            break;
        }

        if (NULL == conf.pc) {
            if (0 == i && !conf.ssl_enabled) continue;
            if (0 != i) {
                /* inherit ssl settings from global scope
                 * (if only ssl.engine = "enable" and no other ssl.* settings)
                 * (This is for convenience when defining both IPv4 and IPv6
                 *  and desiring to inherit the ssl config from global context
                 *  without having to duplicate the directives)*/
                if (count_not_engine
                    || (conf.ssl_enabled
                        && NULL == p->ssl_ctxs[0].priority_cache)) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: ssl.pemfile has to be set in same "
                      "$SERVER[\"socket\"] scope as other ssl.* directives, "
                      "unless only ssl.engine is set, inheriting ssl.* from "
                      "global scope");
                    rc = HANDLER_ERROR;
                    continue;
                }
                plugin_ssl_ctx * const s = p->ssl_ctxs + sidx;
                *s = *p->ssl_ctxs;/*(copy struct of ssl_ctx from global scope)*/
                continue;
            }
            /* PEM file is required */
            log_error(srv->errh, __FILE__, __LINE__,
              "GnuTLS: ssl.pemfile has to be set when ssl.engine = \"enable\"");
            rc = HANDLER_ERROR;
            continue;
        }

        /* (initialize once if module enabled) */
        if (!mod_gnutls_init_once_gnutls()) {
            rc = HANDLER_ERROR;
            break;
        }

        /* configure ssl_ctx for socket */

        /*conf.ssl_ctx = NULL;*//*(filled by network_init_ssl() even on error)*/
        if (0 == network_init_ssl(srv, &conf, p)) {
            plugin_ssl_ctx * const s = p->ssl_ctxs + sidx;
            s->ssl_session_ticket = conf.ssl_session_ticket;
            s->priority_cache     = conf.priority_cache;
          #if GNUTLS_VERSION_NUMBER < 0x030600
            s->dh_params          = conf.dh_params;
          #endif
        }
        else {
            gnutls_priority_deinit(conf.priority_cache);
          #if GNUTLS_VERSION_NUMBER < 0x030600
            gnutls_dh_params_deinit(conf.dh_params);
          #endif
            rc = HANDLER_ERROR;
        }
        free(conf.priority_str.ptr);
    }

    if (rc == HANDLER_GO_ON && ssl_is_init)
        mod_gnutls_session_ticket_key_check(srv, p, log_epoch_secs);

    free(srvplug.cvlist);
    return rc;
}


SETDEFAULTS_FUNC(mod_gnutls_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("ssl.pemfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.privkey"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-dn-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.ca-crl-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.read-ahead"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.disable-client-renegotiation"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.activate"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.enforce"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.depth"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.username"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.exportcert"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.acme-tls-1"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.stapling-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("debug.log-ssl-noise"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.ca-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.ca-dn-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("ssl.verifyclient.ca-crl-file"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    p->srv = srv;
    if (!config_plugin_values_init(srv, p, cpk, "mod_gnutls"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        config_plugin_value_t *pemfile = NULL;
        config_plugin_value_t *privkey = NULL;
        const buffer *ssl_stapling_file = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* ssl.pemfile */
                if (!buffer_is_blank(cpv->v.b)) pemfile = cpv;
                break;
              case 1: /* ssl.privkey */
                if (!buffer_is_blank(cpv->v.b)) privkey = cpv;
                break;
              case 15:/* ssl.verifyclient.ca-file */
                if (cpv->k_id == 15) cpv->k_id = 2;
                __attribute_fallthrough__
              case 16:/* ssl.verifyclient.ca-dn-file */
                if (cpv->k_id == 16) cpv->k_id = 3;
                __attribute_fallthrough__
              case 2: /* ssl.ca-file */
              case 3: /* ssl.ca-dn-file */
                if (!buffer_is_blank(cpv->v.b)) {
                    gnutls_datum_t *d =
                      mod_gnutls_load_config_crts(cpv->v.b->ptr, srv->errh);
                    if (d != NULL) {
                        cpv->vtype = T_CONFIG_LOCAL;
                        cpv->v.v = d;
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__,
                                  "%s = %s", cpk[cpv->k_id].k, cpv->v.b->ptr);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 17:/* ssl.verifyclient.ca-crl-file */
                cpv->k_id = 4;
                __attribute_fallthrough__
              case 4: /* ssl.ca-crl-file */
                if (!buffer_is_blank(cpv->v.b)) {
                    gnutls_datum_t *d =
                      mod_gnutls_load_config_crls(cpv->v.b->ptr, srv->errh);
                    if (d != NULL) {
                        cpv->vtype = T_CONFIG_LOCAL;
                        cpv->v.v = d;
                    }
                    else {
                        log_error(srv->errh, __FILE__, __LINE__,
                                  "%s = %s", cpk[cpv->k_id].k, cpv->v.b->ptr);
                        return HANDLER_ERROR;
                    }
                }
                break;
              case 5: /* ssl.read-ahead */
                break;
              case 6: /* ssl.disable-client-renegotiation */
                /* (force disabled, the default, if HTTP/2 enabled in server) */
                if (srv->srvconf.h2proto)
                    cpv->v.u = 1; /* disable client renegotiation */
                break;
              case 7: /* ssl.verifyclient.activate */
              case 8: /* ssl.verifyclient.enforce */
                break;
              case 9: /* ssl.verifyclient.depth */
                if (cpv->v.shrt > 255) {
                    log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: %s is absurdly large (%hu); limiting to 255",
                      cpk[cpv->k_id].k, cpv->v.shrt);
                    cpv->v.shrt = 255;
                }
                break;
              case 10:/* ssl.verifyclient.username */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 11:/* ssl.verifyclient.exportcert */
                break;
              case 12:/* ssl.acme-tls-1 */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 13:/* ssl.stapling-file */
                if (!buffer_is_blank(cpv->v.b))
                    ssl_stapling_file = cpv->v.b;
                break;
              case 14:/* debug.log-ssl-noise */
             #if 0    /*(handled further above)*/
              case 15:/* ssl.verifyclient.ca-file */
              case 16:/* ssl.verifyclient.ca-dn-file */
              case 17:/* ssl.verifyclient.ca-crl-file */
             #endif
                break;
              default:/* should not happen */
                break;
            }
        }

        if (pemfile) {
            if (NULL == privkey) privkey = pemfile;
            pemfile->v.v =
              network_gnutls_load_pemfile(srv, pemfile->v.b, privkey->v.b,
                                          ssl_stapling_file);
            if (pemfile->v.v)
                pemfile->vtype = T_CONFIG_LOCAL;
            else
                return HANDLER_ERROR;
        }
    }

    p->defaults.ssl_verifyclient = 0;
    p->defaults.ssl_verifyclient_enforce = 1;
    p->defaults.ssl_verifyclient_depth = 9;
    p->defaults.ssl_verifyclient_export_cert = 0;
    p->defaults.ssl_disable_client_renegotiation = 1;
    p->defaults.ssl_read_ahead = 0;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_gnutls_merge_config(&p->defaults, cpv);
    }

    return mod_gnutls_set_defaults_sockets(srv, p);
}


    /* local_send_buffer is a static buffer of size (LOCAL_SEND_BUFSIZE)
     *
     * buffer is allocated once, is NOT realloced (note: not thread-safe)
     * */

            /* copy small mem chunks into single large buffer
             * before gnutls_record_send() to reduce number times
             * write() called underneath gnutls_record_send() and
             * potentially reduce number of packets generated if TCP_NODELAY
             * Alternatively, GnuTLS provides gnutls_record_cork() and
             * gnutls_record_uncork(), not currently used by mod_gnutls */


__attribute_cold__
static int
mod_gnutls_write_err(connection *con, handler_ctx *hctx, int wr, size_t wr_len)
{
    switch (wr) {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
        if (gnutls_record_get_direction(hctx->ssl))
            con->is_writable = -1;
        else
            con->is_readable = -1;
        break; /* try again later */
      default:
       #if 0
        /* ??? how to check for EPIPE or ECONNRESET and skip logging ??? */
        if (hctx->conf.ssl_log_noise)
            elog(hctx->r->conf.errh, __FILE__, __LINE__, wr, __func__);
       #endif
        elog(hctx->r->conf.errh, __FILE__, __LINE__, wr, __func__);
        return -1;
    }

    /* partial write; save attempted wr_len */
    hctx->pending_write = wr_len;

    return 0; /* try again later */
}


__attribute_cold__
static int
mod_gnutls_read_err(connection *con, handler_ctx *hctx, int rc)
{
    switch (rc) {
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
        if (gnutls_record_get_direction(hctx->ssl))
            con->is_writable = -1;
        con->is_readable = 0;
        return 0;
     #if 0
      case GNUTLS_E_SESSION_EOF: /*(not exposed by library)*/
        /* XXX: future: save state to avoid future read after response? */
        con->is_readable = 0;
        r->keep_alive = 0;
        return (hctx->handshake ? -2 : -1); /*(-1 error if during handshake)*/
     #endif
      case GNUTLS_E_REHANDSHAKE:
        if (!hctx->handshake) return -1; /*(not expected during handshake)*/
        if (hctx->conf.ssl_disable_client_renegotiation)/*(mod_gnutls default)*/
            return -1;
       #if 0
        if (gnutls_safe_renegotiation_status(hctx->ssl)) {
            hctx->handshake = 0;
            return con->network_read(con, cq, max_bytes);
        }
       #else
        return 0; /*(ignore client renegotiation request; generally unsafe)*/
       #endif
      case GNUTLS_E_WARNING_ALERT_RECEIVED:
      case GNUTLS_E_FATAL_ALERT_RECEIVED:
        {
            const char *str;
            gnutls_alert_description_t alert = gnutls_alert_get(hctx->ssl);
            switch (alert) {
              case GNUTLS_A_NO_RENEGOTIATION:
                return 0; /*(ignore non-fatal alert from client)*/
              case GNUTLS_A_HANDSHAKE_FAILURE:
              case GNUTLS_A_CLOSE_NOTIFY: /*(not exposed by library)*/
              case GNUTLS_A_UNKNOWN_CA:
              case GNUTLS_A_CERTIFICATE_UNKNOWN:
              case GNUTLS_A_BAD_CERTIFICATE:
                if (!hctx->conf.ssl_log_noise) return -1;
                __attribute_fallthrough__
              default:
                str = gnutls_alert_get_name(alert);
                elogf(hctx->r->conf.errh, __FILE__, __LINE__, rc,
                      "%s(): alert %s", __func__, str ? str : "(unknown)");
                return -1;
            }
        }
      case GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET:
      case GNUTLS_E_UNKNOWN_CIPHER_SUITE: /* GNUTLS_A_HANDSHAKE_FAILURE */
      case GNUTLS_E_PREMATURE_TERMINATION:
        if (!hctx->conf.ssl_log_noise) return -1;
        __attribute_fallthrough__
      case GNUTLS_E_GOT_APPLICATION_DATA: /*(not expected with current use)*/
        /*if (hctx->handshake) return -1;*//*(accept only during handshake)*/
      default:
        elog(hctx->r->conf.errh, __FILE__, __LINE__, rc, __func__);
        return -1;
    }
}


static int
mod_gnutls_close_notify(handler_ctx *hctx);


static int
connection_write_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[plugin_data_singleton->id];
    gnutls_session_t const ssl = hctx->ssl;
    if (!hctx->handshake) return 0;

    if (hctx->pending_write) {
        int wr = gnutls_record_send(ssl, NULL, 0);
        if (wr <= 0)
            return mod_gnutls_write_err(con, hctx, wr, hctx->pending_write);
        max_bytes -= wr;
        hctx->pending_write = 0;
        chunkqueue_mark_written(cq, wr);
    }

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_gnutls_close_notify(hctx);

    const size_t lim = gnutls_record_get_max_size(ssl);

    /* future: for efficiency/performance might consider using GnuTLS corking
     *   gnutls_record_cork()
     *   gnutls_record_uncork()
     *   gnutls_record_check_corked()
     * though chunkqueue_peek_data() already will read a mix of MEM_CHUNK and
     * FILE_CHUNK into the buffer before sending, e.g. to send header response
     * headers and beginning of files, but does so for LOCAL_SEND_BUFSIZE (16k)
     * More might be possible to send before uncorking.
     */

    log_error_st * const errh = hctx->errh;
    while (max_bytes > 0 && !chunkqueue_is_empty(cq)) {
        char *data = local_send_buffer;
        uint32_t data_len = LOCAL_SEND_BUFSIZE < max_bytes
          ? LOCAL_SEND_BUFSIZE
          : (uint32_t)max_bytes;
        int wr;

        if (0 != chunkqueue_peek_data(cq, &data, &data_len, errh)) return -1;
        if (__builtin_expect( (0 == data_len), 0)) {
            chunkqueue_remove_finished_chunks(cq);
            continue;
        }

        /* gnutls_record_send() copies the data, up to max record size, but if
         * (temporarily) unable to write the entire record, it is documented
         * that the caller must call gnutls_record_send() again, later, with the
         * same arguments, or with NULL ptr and 0 data_len.  The func may return
         * GNUTLS_E_AGAIN or GNUTLS_E_INTERRUPTED to indicate that caller should
         * wait for fd to be readable/writable before calling the func again,
         * which is why those (temporary) errors are returned instead of telling
         * the caller that the data was successfully copied.
         * Additionally, to be accurate, the size must fit into a record which
         * is why we restrict ourselves to sending max out record payload each
         * iteration.
         * XXX: above comments modified from mod_mbedtls; should be verified
         */

        int wr_total = 0;
        do {
            size_t wr_len = (data_len > lim) ? lim : data_len;
            wr = gnutls_record_send(ssl, data, wr_len);
            if (wr <= 0) {
                if (wr_total) chunkqueue_mark_written(cq, wr_total);
                return mod_gnutls_write_err(con, hctx, wr, wr_len);
            }
            wr_total += wr;
            data += wr;
        } while ((data_len -= wr));
        chunkqueue_mark_written(cq, wr_total);
        max_bytes -= wr_total;
    }

    return 0;
}


static int
mod_gnutls_ssl_handshake (handler_ctx *hctx)
{
    int rc = gnutls_handshake(hctx->ssl);
    if (rc < 0)
        return mod_gnutls_read_err(hctx->con, hctx, rc);

    /*(rc == GNUTLS_E_SUCCESS)*/

    hctx->handshake = 1;
  #if GNUTLS_VERSION_NUMBER >= 0x030200
    if (hctx->alpn == MOD_GNUTLS_ALPN_H2) {
        if (0 != mod_gnutls_alpn_h2_policy(hctx))
            return -1;
    }
    else if (hctx->alpn == MOD_GNUTLS_ALPN_ACME_TLS_1) {
        /* Once TLS handshake is complete, return -1 to result in
         * CON_STATE_ERROR so that socket connection is quickly closed */
        return -1;
    }
    hctx->alpn = 0;
  #endif
    return 1; /* continue reading */
}


static int
connection_read_cq_ssl (connection * const con, chunkqueue * const cq, off_t max_bytes)
{
    handler_ctx * const hctx = con->plugin_ctx[plugin_data_singleton->id];

    UNUSED(max_bytes);

    if (__builtin_expect( (0 != hctx->close_notify), 0))
        return mod_gnutls_close_notify(hctx);

    if (!hctx->handshake) {
        int rc = mod_gnutls_ssl_handshake(hctx);
        if (1 != rc) return rc; /* !hctx->handshake; not done, or error */
    }

    gnutls_session_t ssl = hctx->ssl;
    ssize_t len;
    char *mem = NULL;
    size_t mem_len = 0;
    size_t pend = gnutls_record_check_pending(ssl);
    do {
        mem_len = pend < 2048 ? 2048 : pend;
        chunk * const ckpt = cq->last;
        mem = chunkqueue_get_memory(cq, &mem_len);

        len = gnutls_record_recv(ssl, mem, mem_len);
        if (len > 0) {
            chunkqueue_use_memory(cq, ckpt, len);
            con->bytes_read += len;
        } else {
            chunkqueue_use_memory(cq, ckpt, 0);
        }
    } while (len > 0 && (pend = gnutls_record_check_pending(ssl)));

    if (len < 0) {
        return mod_gnutls_read_err(con, hctx, (int)len);
    } else if (len == 0) {
        con->is_readable = 0;
        /* the other end closed the connection -> KEEP-ALIVE */

        return -2;
    } else {
        return 0;
    }
}


static void
mod_gnutls_debug_cb(int level, const char *str)
{
    UNUSED(level);
    log_error_st *errh = plugin_data_singleton->srv->errh;
    log_error(errh, __FILE__, __LINE__, "GnuTLS: %s", str);
}


CONNECTION_FUNC(mod_gnutls_handle_con_accept)
{
    const server_socket *srv_sock = con->srv_socket;
    if (!srv_sock->is_ssl) return HANDLER_GO_ON;

    plugin_data *p = p_d;
    handler_ctx * const hctx = handler_ctx_init();
    request_st * const r = &con->request;
    hctx->r = r;
    hctx->con = con;
    hctx->tmp_buf = con->srv->tmp_buf;
    hctx->errh = r->conf.errh;
    con->plugin_ctx[p->id] = hctx;
    buffer_blank(&r->uri.authority);

    plugin_ssl_ctx * const s = p->ssl_ctxs + srv_sock->sidx;
    hctx->ssl_session_ticket = s->ssl_session_ticket;
    int flags = GNUTLS_SERVER | GNUTLS_NO_SIGNAL | GNUTLS_NONBLOCK;
             /* ??? add feature: GNUTLS_ENABLE_EARLY_START ??? */
    int rc = gnutls_init(&hctx->ssl, flags);
    if (rc < 0) {
        elog(r->conf.errh, __FILE__, __LINE__, rc, "gnutls_init()");
        return HANDLER_ERROR;
    }

    rc = gnutls_priority_set(hctx->ssl, s->priority_cache);
    if (rc < 0) {
        elog(r->conf.errh, __FILE__, __LINE__, rc, "gnutls_priority_set()");
        return HANDLER_ERROR;
    }

    /* generic func replaces gnutls_handshake_set_post_client_hello_function()*/
    gnutls_handshake_set_hook_function(hctx->ssl, GNUTLS_HANDSHAKE_CLIENT_HELLO,
                                       GNUTLS_HOOK_PRE,
                                       mod_gnutls_client_hello_hook);

    gnutls_session_set_ptr(hctx->ssl, hctx);
    gnutls_transport_set_int(hctx->ssl, con->fd);

    con->network_read = connection_read_cq_ssl;
    con->network_write = connection_write_cq_ssl;
    con->proto_default_port = 443; /* "https" */
    mod_gnutls_patch_config(r, &hctx->conf);

  #if GNUTLS_VERSION_NUMBER < 0x030600
    hctx->conf.dh_params = s->dh_params;
  #endif

    /* debug logging is global.  Once enabled, debug hook will remain so, though
     * different connection might overwrite level, if configured differently.
     * If GNUTLS_DEBUG_LEVEL is set in environment (and ssl_log_noise not set),
     * then debugging will go to stderr */
    if (hctx->conf.ssl_log_noise) {/* volume level for debug message callback */
        gnutls_global_set_log_function(mod_gnutls_debug_cb);
        gnutls_global_set_log_level(hctx->conf.ssl_log_noise);
    }

    /* GnuTLS limitation: must set session ticket encryption key before GnuTLS
     * client hello hook runs if TLSv1.3 (? key already set by then ?) */
    if (hctx->ssl_session_ticket && session_ticket_key.size) {
        rc = gnutls_session_ticket_enable_server(hctx->ssl,&session_ticket_key);
        if (rc < 0) {
            elog(r->conf.errh, __FILE__, __LINE__, rc,
                 "gnutls_session_ticket_enable_server()");
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}


static void
mod_gnutls_detach(handler_ctx *hctx)
{
    /* step aside from further SSL processing
     * (used after handle_connection_shut_wr hook) */
    /* future: might restore prior network_read and network_write fn ptrs */
    hctx->con->is_ssl_sock = 0;
    /* if called after handle_connection_shut_wr hook, shutdown SHUT_WR */
    if (-1 == hctx->close_notify) shutdown(hctx->con->fd, SHUT_WR);
    hctx->close_notify = 1;
}


CONNECTION_FUNC(mod_gnutls_handle_con_shut_wr)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    hctx->close_notify = -2;
    if (hctx->handshake) {
        mod_gnutls_close_notify(hctx);
    }
    else {
        mod_gnutls_detach(hctx);
    }

    return HANDLER_GO_ON;
}


static int
mod_gnutls_close_notify (handler_ctx *hctx)
{
    if (1 == hctx->close_notify) return -2;

    int rc = gnutls_bye(hctx->ssl, GNUTLS_SHUT_WR);
    switch (rc) {
      case GNUTLS_E_SUCCESS:
        mod_gnutls_detach(hctx);
        return -2;
      case GNUTLS_E_AGAIN:
      case GNUTLS_E_INTERRUPTED:
        return 0;
      default:
        elog(hctx->r->conf.errh, __FILE__, __LINE__, rc,
             "mod_gnutls_close_notify()");
        __attribute_fallthrough__
      case GNUTLS_E_PUSH_ERROR: /*(noisy; probably connection reset)*/
        mod_gnutls_detach(hctx);
        return -1;
    }
}


CONNECTION_FUNC(mod_gnutls_handle_con_close)
{
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];
    if (NULL != hctx) {
        con->plugin_ctx[p->id] = NULL;
        if (1 != hctx->close_notify)
            mod_gnutls_close_notify(hctx); /*(one final try)*/
        handler_ctx_free(hctx);
    }

    return HANDLER_GO_ON;
}


__attribute_noinline__
static void
https_add_ssl_client_cert (request_st * const r, const gnutls_x509_crt_t peer)
{
    gnutls_datum_t d;
    if (gnutls_x509_crt_export2(peer, GNUTLS_X509_FMT_PEM, &d) >= 0)
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_CERT"),
                            (char *)d.data, d.size);
    if (d.data) gnutls_free(d.data);
}


/* modified from gnutls tests/dn.c:print_dn() */
static void
https_add_ssl_client_subject (request_st * const r, gnutls_x509_dn_t dn)
{
    int irdn = 0, i, rc;
    gnutls_x509_ava_st ava;
    const size_t prelen = sizeof("SSL_CLIENT_S_DN_")-1;
    char key[64] = "SSL_CLIENT_S_DN_";
    char buf[512]; /*(expecting element value len <= 256)*/

    /* add components of client Subject DN */

    /* man gnutls_x509_dn_get_rdn_ava()
     *   The X.509 distinguished name is a sequence of sequences of strings and
     *   this is what the  irdn and  iava indexes model.
     *   This is a low-level function that requires the caller to do the value
     *   conversions when necessary (e.g. from UCS-2).
     * XXX: value conversions not done below; unprintable chars replaced w/ '?'
     */

    do {
        for (i=0; (rc = gnutls_x509_dn_get_rdn_ava(dn,irdn,i,&ava)) == 0; ++i) {
            const char *name =
              gnutls_x509_dn_oid_name((char *)ava.oid.data,
                                      GNUTLS_X509_DN_OID_RETURN_OID);
            const size_t len = strlen(name);
            if (prelen+len >= sizeof(key)) continue;
            memcpy(key+prelen, name, len); /*(not '\0'-terminated)*/

            unsigned int v, n = 0;
            for (v = 0; v < ava.value.size && n < sizeof(buf)-1; ++n) {
                unsigned char c = ava.value.data[v];
                buf[n] = (c < 32 || c == 127 || (c > 128 && c < 160)) ? '?' : c;
            }

            http_header_env_set(r, key, prelen+len, buf, n);
        }
        ++irdn;
    } while (rc == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND && i > 0);

    if (rc != GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
        elog(r->conf.errh, __FILE__, __LINE__, rc,
             "gnutls_x509_dn_get_rdn_ava()");
}


__attribute_cold__
static void
https_add_ssl_client_verify_err (buffer * const b, unsigned int status)
{
  #if GNUTLS_VERSION_NUMBER >= 0x030104
    /* get failure string and translate newline to ':', removing last one */
    /* (preserving behavior from mod_openssl) */
    gnutls_datum_t msg = { NULL, 0 };
    if (gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509,
                                                     &msg, 0) >= 0) {
        size_t sz = msg.size-1; /* '\0'-terminated string */
        for (char *nl=(char *)msg.data; NULL != (nl=strchr(nl, '\n')); ++nl)
            nl[0] = ('\0' == nl[1] ? (--sz, '\0') : ':');
        buffer_append_string_len(b, (char *)msg.data, sz);
    }
    if (msg.data) gnutls_free(msg.data);
  #else
    UNUSED(b);
    UNUSED(status);
  #endif
}


__attribute_noinline__
static void
https_add_ssl_client_entries (request_st * const r, handler_ctx * const hctx)
{
    gnutls_session_t ssl = hctx->ssl;
    unsigned int crt_size = 0;
    const gnutls_datum_t *crts = NULL;
    buffer *vb = http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_VERIFY"));

    if (hctx->verify_status != ~0u)
        crts = gnutls_certificate_get_peers(ssl, &crt_size);
    if (0 == crt_size) { /* || hctx->verify_status == ~0u) */
        /*(e.g. no cert, or verify result not available)*/
        buffer_copy_string_len(vb, CONST_STR_LEN("NONE"));
        return;
    }
    else if (0 != hctx->verify_status) {
        buffer_copy_string_len(vb, CONST_STR_LEN("FAILED:"));
        https_add_ssl_client_verify_err(vb, hctx->verify_status);
        return;
    }
    else {
        buffer_copy_string_len(vb, CONST_STR_LEN("SUCCESS"));
    }

    gnutls_x509_crt_t crt;
    if (gnutls_x509_crt_init(&crt) < 0)
        return;
    if (crts && gnutls_x509_crt_import(crt, &crts[0], GNUTLS_X509_FMT_DER) < 0){
        gnutls_x509_crt_deinit(crt);
        return;
    }

    int rc;
    gnutls_datum_t d = { NULL, 0 };
    char buf[512];
    /*rc = gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_ONELINE, &d);*//* ??? */
  #if GNUTLS_VERSION_NUMBER < 0x030507
    d.data = buf;
    d.size = sizeof(buf);
    rc = gnutls_x509_crt_get_dn(crt, buf, &d.size);
  #else
    rc = gnutls_x509_crt_get_dn3(crt, &d, 0);
  #endif
    if (rc >= 0)
        http_header_env_set(r,
                            CONST_STR_LEN("SSL_CLIENT_S_DN"),
                            (char *)d.data, d.size);
    if (d.data && d.data != (void *)buf) gnutls_free(d.data);

    gnutls_x509_dn_t dn;
    rc = gnutls_x509_crt_get_subject(crt, &dn);
    if (rc >= 0)
        https_add_ssl_client_subject(r, dn);

    size_t sz = sizeof(buf);
    if (gnutls_x509_crt_get_serial(crt, buf, &sz) >= 0)
        buffer_append_string_encoded_hex_uc(
          http_header_env_set_ptr(r, CONST_STR_LEN("SSL_CLIENT_M_SERIAL")),
          buf, sz);

    if (hctx->conf.ssl_verifyclient_username) {
        /* pick one of the exported values as "REMOTE_USER", for example
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_UID"
         * or
         *   ssl.verifyclient.username = "SSL_CLIENT_S_DN_emailAddress"
         */
        const buffer *varname = hctx->conf.ssl_verifyclient_username;
        vb = http_header_env_get(r, BUF_PTR_LEN(varname));
        if (vb) { /* same as mod_auth_api.c:http_auth_setenv() */
            http_header_env_set(r,
                                CONST_STR_LEN("REMOTE_USER"),
                                BUF_PTR_LEN(vb));
            http_header_env_set(r,
                                CONST_STR_LEN("AUTH_TYPE"),
                                CONST_STR_LEN("SSL_CLIENT_VERIFY"));
        }
    }

    /* if (NULL != crt) (e.g. not PSK-based ciphersuite) */
    if (hctx->conf.ssl_verifyclient_export_cert && NULL != crt)
        https_add_ssl_client_cert(r, crt);

    gnutls_x509_crt_deinit(crt);
}


static void
http_cgi_ssl_env (request_st * const r, handler_ctx * const hctx)
{
    gnutls_session_t ssl = hctx->ssl;
    gnutls_protocol_t version = gnutls_protocol_get_version(ssl);
    gnutls_cipher_algorithm_t cipher = gnutls_cipher_get(ssl);
    gnutls_kx_algorithm_t kx = gnutls_kx_get(ssl);
    gnutls_mac_algorithm_t mac = gnutls_mac_get(ssl);
    const char *s;

    s = gnutls_protocol_get_name(version);
    if (s) http_header_env_set(r, CONST_STR_LEN("SSL_PROTOCOL"), s, strlen(s));

    s = gnutls_cipher_suite_get_name(kx, cipher, mac);
    if (s) http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER"), s, strlen(s));

    /* SSL_CIPHER_ALGKEYSIZE - Number of cipher bits (possible) */
    /* SSL_CIPHER_USEKEYSIZE - Number of cipher bits (actually used) */
    /* (always the same in extra/gnutls_openssl.c:SSL_CIPHER_get_bits())
     * (The values are the same except for very old, weak ciphers, i.e. if you
     *  care about this, then you instead ought to be using stronger ciphers)*/
    /* ??? gnutls_x509_crt_get_pk_algorithm(crt, &usekeysize); ??? */
    size_t algkeysize = 8 * gnutls_cipher_get_key_size(cipher);
    size_t usekeysize = algkeysize;
    char buf[LI_ITOSTRING_LENGTH];
    http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_USEKEYSIZE"),
                        buf, li_utostrn(buf, sizeof(buf), usekeysize));
    http_header_env_set(r, CONST_STR_LEN("SSL_CIPHER_ALGKEYSIZE"),
                        buf, li_utostrn(buf, sizeof(buf), algkeysize));
}


REQUEST_FUNC(mod_gnutls_handle_request_env)
{
    plugin_data *p = p_d;
    /* simple flag for request_env_patched */
    if (r->plugin_ctx[p->id]) return HANDLER_GO_ON;
    handler_ctx *hctx = r->con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;
    r->plugin_ctx[p->id] = (void *)(uintptr_t)1u;

    http_cgi_ssl_env(r, hctx);
    if (hctx->conf.ssl_verifyclient) {
        https_add_ssl_client_entries(r, hctx);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_gnutls_handle_uri_raw)
{
    /* mod_gnutls must be loaded prior to mod_auth
     * if mod_gnutls is configured to set REMOTE_USER based on client cert */
    /* mod_gnutls must be loaded after mod_extforward
     * if mod_gnutls config is based on lighttpd.conf remote IP conditional
     * using remote IP address set by mod_extforward, *unless* PROXY protocol
     * is enabled with extforward.hap-PROXY = "enable", in which case the
     * reverse is true: mod_extforward must be loaded after mod_gnutls */
    plugin_data *p = p_d;
    handler_ctx *hctx = r->con->plugin_ctx[p->id];
    if (NULL == hctx) return HANDLER_GO_ON;

    mod_gnutls_patch_config(r, &hctx->conf);
    if (hctx->conf.ssl_verifyclient) {
        mod_gnutls_handle_request_env(r, p);
    }

    return HANDLER_GO_ON;
}


REQUEST_FUNC(mod_gnutls_handle_request_reset)
{
    plugin_data *p = p_d;
    r->plugin_ctx[p->id] = NULL; /* simple flag for request_env_patched */
    return HANDLER_GO_ON;
}


TRIGGER_FUNC(mod_gnutls_handle_trigger) {
    const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_epoch_secs;
    if (cur_ts & 0x3f) return HANDLER_GO_ON; /*(continue once each 64 sec)*/

    mod_gnutls_session_ticket_key_check(srv, p, cur_ts);
    mod_gnutls_refresh_stapling_files(srv, p, cur_ts);

    return HANDLER_GO_ON;
}


int mod_gnutls_plugin_init (plugin *p);
int mod_gnutls_plugin_init (plugin *p)
{
    p->version      = LIGHTTPD_VERSION_ID;
    p->name         = "gnutls";
    p->init         = mod_gnutls_init;
    p->cleanup      = mod_gnutls_free;
    p->priv_defaults= mod_gnutls_set_defaults;

    p->handle_connection_accept  = mod_gnutls_handle_con_accept;
    p->handle_connection_shut_wr = mod_gnutls_handle_con_shut_wr;
    p->handle_connection_close   = mod_gnutls_handle_con_close;
    p->handle_uri_raw            = mod_gnutls_handle_uri_raw;
    p->handle_request_env        = mod_gnutls_handle_request_env;
    p->handle_request_reset      = mod_gnutls_handle_request_reset;
    p->handle_trigger            = mod_gnutls_handle_trigger;

    return 0;
}


/* cipher suites
 *
 * (extremely coarse (and very possibly incorrect) mapping to openssl labels)
 */

/* TLSv1.3 cipher list (supported in gnutls) */
static const char suite_TLSv13[] =
  "+CHACHA20-POLY1305:"
  "+AES-256-GCM:"
  "+AES-256-CCM:"
  "+AES-256-CCM-8:"
  "+AES-128-GCM:"
  "+AES-128-CCM:"
  "+AES-128-CCM-8:"
;

/* TLSv1.2 cipher list (supported in gnutls) */
static const char suite_TLSv12[] =
  "+CHACHA20-POLY1305:"
  "+AES-256-GCM:"
  "+AES-256-CCM:"
  "+AES-256-CBC:"
  "+AES-256-CCM-8:"
  "+CAMELLIA-256-GCM:"
  "+CAMELLIA-256-CBC:"
  "+AES-128-GCM:"
  "+AES-128-CCM:"
  "+AES-128-CBC:"
  "+AES-128-CCM-8:"
  "+CAMELLIA-128-GCM:"
  "+CAMELLIA-128-CBC:"
;

/* TLSv1.0 cipher list (supported in gnutls) */
/* XXX: intentionally not including overlapping eNULL ciphers */
static const char suite_TLSv10[] =
  "+AES-256-CBC:"
  "+AES-128-CBC:"
  "+CAMELLIA-256-CBC:"
  "+CAMELLIA-128-CBC:"
;

/* SSLv3 cipher list (supported in gnutls) */
/* XXX: intentionally not including overlapping eNULL ciphers */
static const char suite_SSLv3[] =
  "+AES-256-CBC:"
  "+AES-128-CBC:"
  "+CAMELLIA-256-CBC:"
  "+CAMELLIA-128-CBC:"
  "+3DES-CBC:"
  "+DES-CBC:"
;

/* HIGH cipher list (mapped from openssl list to gnutls) */
static const char suite_HIGH[] =
  "+CHACHA20-POLY1305:"
  "+AES-256-GCM:"
  "+AES-256-CCM:"
  "+AES-256-CBC:"
  "+AES-256-CCM-8:"
  "+CAMELLIA-256-CBC:"
  "+AES-128-GCM:"
  "+AES-128-CCM:"
  "+AES-128-CBC:"
  "+AES-128-CCM-8:"
  "+CAMELLIA-128-CBC:"
;


static int
mod_gnutls_ssl_conf_ciphersuites (server *srv, plugin_config_socket *s, buffer *ciphersuites, const buffer *cipherstring)
{
    /* reference: https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
     * Attempt to parse *some* keywords from Ciphersuites and CipherString
     * !!! openssl uses a *different* naming scheme than does GnuTLS !!!
     * Ciphersuites in openssl takes only TLSv1.3 suites.
     * Note that CipherString does allow cipher suites to be listed,
     * and this code does not currently attempt to provide mapping */

    buffer * const plist = &s->priority_str;
    char n[128]; /*(most ciphersuite names are about 40 chars)*/

    if (ciphersuites) {
        buffer *b = ciphersuites;
        buffer_to_upper(b); /*(ciphersuites are all uppercase (currently))*/
        for (const char *e = b->ptr-1; e; ) {
            const char * const p = e+1;
            e = strchr(p, ':');
            size_t len = e ? (size_t)(e - p) : strlen(p);

            if (buffer_eq_icase_ss(p, len,
                  CONST_STR_LEN("TLS_CHACHA20_POLY1305_SHA256")))
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+CHACHA20-POLY1305:"));
            else if (buffer_eq_icase_ss(p, len,
                  CONST_STR_LEN("TLS_AES_256_GCM_SHA384")))
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-256-GCM:"));
            else if (buffer_eq_icase_ss(p, len,
                  CONST_STR_LEN("TLS_AES_128_GCM_SHA256")))
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-128-GCM:"));
            else if (buffer_eq_icase_ss(p, len,
                  CONST_STR_LEN("TLS_AES_128_CCM_SHA256")))
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-128-CCM:"));
            else if (buffer_eq_icase_ss(p, len,
                  CONST_STR_LEN("TLS_AES_128_CCM_8_SHA256")))
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-128-CCM-8:"));
            else
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: skipped ciphersuite; not recognized: %.*s",
                  (int)len, p);
        }
    }

    /* XXX: openssl config for CipherString=... is excessively complex.
     * If there is a need to enable specific ciphersuites, then that
     * can be accomplished with mod_gnutls by specifying the list in
     * Ciphersuites=... in the ssl.openssl.ssl-conf-cmd directive.
     *
     * The tokens parsed here are a quick attempt to handle a few cases
     *
     * XXX: not done: could make a list of ciphers with bitflag of attributes
     *      to make future combining easier */
    if (cipherstring && !buffer_is_blank(cipherstring)) {
        const buffer *b = cipherstring;
        const char *e = b->ptr;

        /* XXX: not done: no checking for duplication of ciphersuites
         * even if tokens overlap or are repeated */

        /* XXX: not done: might walk string and build up exclude list of !xxxxx
         * ciphersuites and walk string again, excluding as result list built */

        /* manually handle first token, since one-offs apply */
        /* (openssl syntax NOT fully supported) */
        #define strncmp_const(s,cs) strncmp((s),(cs),sizeof(cs)-1)
        if (0 == strncmp_const(e, "!ALL") || 0 == strncmp_const(e, "-ALL")) {
            /* "!ALL" excluding all ciphers is empty list */
            e += sizeof("!ALL")-1; /* same as sizeof("-ALL")-1 */
            buffer_append_string_len(plist, CONST_STR_LEN("-CIPHER-ALL:"));
        }
        else if (0 == strncmp_const(e, "!DEFAULT")
              || 0 == strncmp_const(e, "-DEFAULT")) {
            /* "!DEFAULT" excluding default ciphers is empty list */
            e += sizeof("!DEFAULT")-1; /* same as sizeof("-DEFAULT")-1 */
            buffer_append_string_len(plist, CONST_STR_LEN("-CIPHER-ALL:"));
        }
        else if (0 == strncmp_const(e, "DEFAULT")) {
            e += sizeof("DEFAULT")-1;
            s->priority_base = "NORMAL";
        }
        else if (0 == /* effectively the same as "DEFAULT" */
                 strncmp_const(e, "ALL:!COMPLEMENTOFDEFAULT:!eNULL")) {
            e += sizeof("ALL:!COMPLEMENTOFDEFAULT:!eNULL")-1;
            s->priority_base = "NORMAL";
        }
        else if (0 == strncmp_const(e, "SUITEB128")
              || 0 == strncmp_const(e, "SUITEB128ONLY")
              || 0 == strncmp_const(e, "SUITEB192")) {
            s->priority_base = (0 == strncmp_const(e, "SUITEB192"))
              ? "SUITEB192"
              : "SUITEB128";
            e += (0 == strncmp_const(e, "SUITEB128ONLY"))
                 ? sizeof("SUITEB128ONLY")-1
                 : sizeof("SUITEB128")-1;
            if (*e)
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: ignoring cipher string after SUITEB: %s", e);
            return 1;
        }
        else if (0 == strncmp_const(e,
                  "ECDHE+AESGCM:ECDHE+AES256:CHACHA20:!SHA1:!SHA256:!SHA384")
              || 0 == strncmp_const(e,
                  "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")) {
            e += sizeof(
                  "EECDH+AESGCM:AES256+EECDH:CHACHA20:!SHA1:!SHA256:!SHA384")-1;
            buffer_append_string_len(plist,
              CONST_STR_LEN("+AES-256-GCM:+AES-128-GCM:+AES-256-CCM:+AES-256-CCM-8:+CHACHA20-POLY1305:"));
        }

        if (e != b->ptr && *e != ':' && *e != '\0') {
            log_error(srv->errh, __FILE__, __LINE__,
              "GnuTLS: error: missing support for cipher list: %s", b->ptr);
            return 0;
        }

        /* not handled: "ALL" is "DEFAULT" and "RC4" */
        /* not handled: "COMPLEMENTOFALL" is "eNULL" */

        int rc = 1;
        if (e == b->ptr || *e == '\0') --e; /*initial condition for loop below*/
        do {
            const char * const p = e+1;
            e = strchr(p, ':');
            size_t len = e ? (size_t)(e - p) : strlen(p);
            if (0 == len) continue;
            if (len >= sizeof(n)) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: skipped ciphersuite; too long: %.*s",
                  (int)len, p);
                continue;
            }
            char c = (*p == '!' || *p == '-' || *p == '+') ? *p : 0;
            size_t nlen = c ? len-1 : len;
            memcpy(n, c ? p+1 : p, nlen);
            n[nlen] = '\0';

            /* not handled: !xxxxx -xxxxx and most +xxxxx */
            if (c) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: error: missing support for cipher list: %s", b->ptr);
            }

            /* ignore @STRENGTH sorting and ignore @SECLEVEL=n */
            char *a = strchr(n, '@');
            if (a) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: ignored %s in %.*s", a, (int)len, p);
                *a = '\0';
                nlen = (size_t)(a - n);
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("TLSv1.3"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN(suite_TLSv13));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("TLSv1.2"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN(suite_TLSv12));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("TLSv1.0"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN(suite_TLSv10));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("SSLv3"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN(suite_SSLv3));
                continue;
            }

            /* handle a popular recommendations
             *   ssl.cipher-list = "EECDH+AESGCM:EDH+AESGCM"
             *   ssl.cipher-list = "AES256+EECDH:AES256+EDH"
             * which uses AES hardware acceleration built into popular CPUs */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("ECDHE+AESGCM"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("EECDH+AESGCM"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-256-GCM:+AES-128-GCM:"));
                continue;
            }
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("DHE+AESGCM"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("EDH+AESGCM"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-256-GCM:+AES-128-GCM:"));
                continue;
            }
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES256+EECDH"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-256-GCM:+AES-256-CCM:+AES-256-CBC:+AES-256-CCM-8:"));
                continue;
            }
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES256+EDH"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-256-GCM:+AES-256-CCM:+AES-256-CBC:+AES-256-CCM-8:"));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("HIGH"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN(suite_HIGH));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES256"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-256-GCM:+AES-256-CCM:+AES-256-CBC:+AES-256-CCM-8:"));
                if (nlen == sizeof("AES256")-1) continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES128"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("AES"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+AES-128-GCM:+AES-128-CCM:+AES-128-CBC:+AES-128-CCM-8:"));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA256"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+CAMELLIA-256-GCM:+CAMELLIA-256-CBC:"));
                if (nlen == sizeof("CAMELLIA256")-1) continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA128"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CAMELLIA"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+CAMELLIA-128-GCM:+CAMELLIA-128-CBC:"));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("CHACHA20"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+CHACHA20-POLY1305:"));
                continue;
            }

            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("3DES"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+3DES-CBC:"));
                continue;
            }

            /* not recommended, but permitted if explicitly requested */
            if (buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("NULL"))
             || buffer_eq_icase_ss(n, nlen, CONST_STR_LEN("eNULL"))) {
                buffer_append_string_len(plist,
                  CONST_STR_LEN("+NULL:"));
                continue;
            }

            {
                log_error(srv->errh, __FILE__, __LINE__,
                  "GnuTLS: error: missing support for cipher list: %.*s",
                  (int)len, p);
                rc = 0;
                continue;
            }
        } while (e);
        if (0 == rc) return 0;
    }

    return 1;
}


static int
mod_gnutls_ssl_conf_curves(server *srv, plugin_config_socket *s, const buffer *curvelist)
{
    /* map NIST name (e.g. P-256) or OpenSSL OID name (e.g. prime256v1)
     * to GnuTLS name of supported curves/groups */
    static const char *names[] = {
      "P-192",      "CURVE-SECP192R1",
      "P-224",      "CURVE-SECP224R1",
      "P-256",      "GROUP-SECP256R1", /* CURVE-SECP256R1 */
      "P-384",      "GROUP-SECP384R1", /* CURVE-SECP384R1 */
      "P-521",      "GROUP-SECP521R1", /* CURVE-SECP521R1 */
      "X25519",     "GROUP-X25519",    /* CURVE-X25519 */
      "X448",       "GROUP-X448",      /* CURVE-X448 */
      "prime192v1", "CURVE-SECP192R1",
      "secp224r1",  "CURVE-SECP224R1",
      "prime256v1", "GROUP-SECP256R1", /* CURVE-SECP256R1 */
      "secp384r1",  "GROUP-SECP384R1", /* CURVE-SECP384R1 */
      "secp521r1",  "GROUP-SECP521R1", /* CURVE-SECP521R1 */
      "ffdhe2048",  "GROUP-FFDHE2048",
      "ffdhe3072",  "GROUP-FFDHE3072",
      "ffdhe4096",  "GROUP-FFDHE4096",
      "ffdhe6144",  "GROUP-FFDHE6144",
      "ffdhe8192",  "GROUP-FFDHE8192",
    };

    buffer * const plist = &s->priority_str;
    const buffer * const b = curvelist;
    for (const char *e = b->ptr-1; e; ) {
        const char * const n = e+1;
        e = strchr(n, ':');
        size_t len = e ? (size_t)(e - n) : strlen(n);
        uint32_t i;
        for (i = 0; i < sizeof(names)/sizeof(*names)/2; i += 2) {
            if (0 == strncmp(names[i], n, len) && names[i][len] == '\0')
                break;
        }
        if (i == sizeof(names)/sizeof(*names)/2) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: unrecognized curve: %.*s; ignored", (int)len, n);
            continue;
        }

        buffer_append_string_len(plist, CONST_STR_LEN("+"));
        buffer_append_string_len(plist, names[i+1], strlen(names[i+1]));
        buffer_append_string_len(plist, CONST_STR_LEN(":"));
    }

    return 1;
}


static int
mod_gnutls_ssl_conf_proto_val (server *srv, plugin_config_socket *s, const buffer *b, int max)
{
    if (NULL == b) /* default: min TLSv1.2, max TLSv1.3 */
        return max ? GNUTLS_TLS1_3 : GNUTLS_TLS1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("None"))) /*"disable" limit*/
        return max
          ? GNUTLS_TLS1_3
          : (s->ssl_use_sslv3 ? GNUTLS_SSL3 : GNUTLS_TLS1_0);
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("SSLv3")))
        return GNUTLS_SSL3;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.0")))
        return GNUTLS_TLS1_0;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.1")))
        return GNUTLS_TLS1_1;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.2")))
        return GNUTLS_TLS1_2;
    else if (buffer_eq_icase_slen(b, CONST_STR_LEN("TLSv1.3")))
        return GNUTLS_TLS1_3;
    else {
        if (buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1"))
            || buffer_eq_icase_slen(b, CONST_STR_LEN("DTLSv1.2")))
            log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: ssl.openssl.ssl-conf-cmd %s %s ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
        else
            log_error(srv->errh, __FILE__, __LINE__,
                      "GnuTLS: ssl.openssl.ssl-conf-cmd %s %s invalid; ignored",
                      max ? "MaxProtocol" : "MinProtocol", b->ptr);
    }
    return max ? GNUTLS_TLS1_3 : GNUTLS_TLS1_2;
}


static void
mod_gnutls_ssl_conf_proto (server *srv, plugin_config_socket *s, const buffer *minb, const buffer *maxb)
{
    /* use of SSL v3 should be avoided, and SSL v2 is not supported */
    int n = mod_gnutls_ssl_conf_proto_val(srv, s, minb, 0);
    int x = mod_gnutls_ssl_conf_proto_val(srv, s, maxb, 1);
    if (n < 0) return;
    if (x < 0) return;
    buffer * const b = &s->priority_str;
    buffer_append_string_len(b, CONST_STR_LEN("-VERS-ALL:"));
    switch (n) {
      case GNUTLS_SSL3:
        buffer_append_string_len(b, CONST_STR_LEN("+VERS-SSL3.0:"));
        __attribute_fallthrough__
      case GNUTLS_TLS1_0:
        if (x < GNUTLS_TLS1_0) break;
        buffer_append_string_len(b, CONST_STR_LEN("+VERS-TLS1.0:"));
        __attribute_fallthrough__
      case GNUTLS_TLS1_1:
        if (x < GNUTLS_TLS1_1) break;
        buffer_append_string_len(b, CONST_STR_LEN("+VERS-TLS1.1:"));
        __attribute_fallthrough__
      case GNUTLS_TLS1_2:
        if (x < GNUTLS_TLS1_2) break;
        buffer_append_string_len(b, CONST_STR_LEN("+VERS-TLS1.2:"));
        __attribute_fallthrough__
      case GNUTLS_TLS1_3:
        if (x < GNUTLS_TLS1_3) break;
        buffer_append_string_len(b, CONST_STR_LEN("+VERS-TLS1.3:"));
        break;
    }
}
