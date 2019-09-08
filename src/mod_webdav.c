/*
 * mod_webdav
 */

/*
 * Note: This plugin is a basic implementation of [RFC4918] WebDAV
 *
 *       Version Control System (VCS) backing WebDAV is recommended instead
 *       and Subversion (svn) is one such VCS supporting WebDAV.
 *
 * status: *** EXPERIMENTAL *** (and likely insecure encoding/decoding)
 *
 * future:
 *
 * TODO: moving props should delete any existing props instead of
 *       preserving any that are not overwritten with UPDATE OR REPLACE
 *       (and, if merging directories, be careful when doing so)
 * TODO: add proper support for locks with "shared" lockscope
 *       (instead of treating match of any shared lock as sufficient,
 *        even when there are different lockroots)
 * TODO: does libxml2 xml-decode (html-decode),
 *       or must I do so to normalize input?
 * TODO: add strict enforcement of property names to be valid XML tags
 *       (or encode as such before putting into database)
 *       &amp; &quot; &lt; &gt;
 * TODO: should we be using xmlNodeListGetString() or xmlBufNodeDump()
 *       and how does it handle encoding and entity-inlining of external refs?
 *       Must xml decode/encode (normalize) before storing user data in database
 *       if going to add that data verbatim to xml doc returned in queries
 * TODO: when walking xml nodes, should add checks for "DAV:" namespace
 * TODO: consider where it might be useful/informative to check
 *       SQLITE_OK != sqlite3_reset() or SQLITE_OK != sqlite3_bind_...() or ...
 *       (in some cases no rows returned is ok, while in other cases it is not)
 * TODO: Unsupported: !con->conf.follow_symlink is not currently honored;
 *       symlinks are followed.  Supporting !con->conf.follow_symlinks would
 *       require operating system support for POSIX.1-2008 *at() commands,
 *       and reworking the mod_webdav code to exclusively operate with *at()
 *       commands, for example, replacing unlink() with unlinkat().
 *
 * RFE: add config option whether or not to include locktoken and ownerinfo
 *      in PROPFIND lockdiscovery
 *
 * deficiencies
 * - incomplete "shared" lock support
 * - review code for proper decoding/encoding of elements from/to XML and db
 * - preserve XML info in scope on dead properties, e.g. xml:lang
 *
 * [RFC4918] 4.3 Property Values
 *   Servers MUST preserve the following XML Information Items (using the
 *   terminology from [REC-XML-INFOSET]) in storage and transmission of dead
 *   properties: ...
 * [RFC4918] 14.26 set XML Element
 *   The 'set' element MUST contain only a 'prop' element. The elements
 *   contained by the 'prop' element inside the 'set' element MUST specify the
 *   name and value of properties that are set on the resource identified by
 *   Request-URI. If a property already exists, then its value is replaced.
 *   Language tagging information appearing in the scope of the 'prop' element
 *   (in the "xml:lang" attribute, if present) MUST be persistently stored along
 *   with the property, and MUST be subsequently retrievable using PROPFIND.
 * [RFC4918] F.2 Changes for Server Implementations
 *   Strengthened server requirements for storage of property values, in
 *   particular persistence of language information (xml:lang), whitespace, and
 *   XML namespace information (see Section 4.3).
 *
 * resource usage containment
 * - filesystem I/O operations might take a non-trivial amount of time,
 *   blocking the server from responding to other requests during this time.
 *   Potential solution: have a thread dedicated to handling webdav requests
 *   and serialize such requests in each thread dedicated to handling webdav.
 *   (Limit number of such dedicated threads.)  Remove write interest from
 *   connection during this period so that server will not trigger any timeout
 *   on the connection.
 * - recursive directory operations are depth-first and may consume a large
 *   number of file descriptors if the directory hierarchy is deep.
 *   Potential solution: serialize webdav requests into dedicated thread (above)
 *   Potential solution: perform breadth-first directory traversal and pwrite()
 *   directory paths into a temporary file.  After reading each directory,
 *   close() the dirhandle and pread() next directory from temporary file.
 *   (Keeping list of directories in memory might result in large memory usage)
 * - flush response to client (or to intermediate temporary file) at regular
 *   intervals or triggers to avoid response consume large amount of memory
 *   during operations on large collection hierarchies (with lots of nested
 *   directories)
 *
 * beware of security concerns involved in enabling WebDAV
 * on publicly accessible servers
 * - (general)      [RFC4918] 20 Security Considersations
 * - (specifically) [RFC4918] 20.6 Implications of XML Entities
 * - TODO review usage of xml libs for security, resource usage, containment
 *   libxml2 vs expat vs ...
 *     http://xmlbench.sourceforge.net/
 *     http://stackoverflow.com/questions/399704/xml-parser-for-c
 *     http://tibleiz.net/asm-xml/index.html
 *     http://dev.yorhel.nl/yxml
 * - how might mod_webdav be affected by mod_openssl setting REMOTE_USER?
 * - when encoding href in responses, also ensure proper XML encoding
 *     (do we need to ENCODING_REL_URI and then ENCODING_MINIMAL_XML?)
 * - TODO: any (non-numeric) data that goes into database should be encoded
 *     before being sent back to user, not just href.  Perhaps anything that
 *     is not an href should be stored in database in XML-encoded form.
 *
 * consider implementing a set of (reasonable) limits on such things as
 * - max number of collections
 * - max number of objects in a collection
 * - max number of properties per object
 * - max length of property name
 * - max length of property value
 * - max length of locktoken, lockroot, ownerinfo
 * - max number of locks held by a client, or by an owner
 * - max number of locks on a resource (shared locks)
 * - ...
 *
 * robustness
 * - should check return value from sqlite3_reset(stmt) for REPLACE, UPDATE,
 *   DELETE statements (which is when commit occurs and locks are obtained/fail)
 * - handle SQLITE_BUSY (e.g. other processes modifying db and hold locks)
 *   https://www.sqlite.org/lang_transaction.html
 *   https://www.sqlite.org/rescode.html#busy
 *   https://www.sqlite.org/c3ref/busy_handler.html
 *   https://www.sqlite.org/c3ref/busy_timeout.html
 * - periodically execute query to delete expired locks
 *   (MOD_WEBDAV_SQLITE_LOCKS_DELETE_EXPIRED)
 *   (should defend against removing locks protecting long-running operations
 *    that are in progress on the server)
 * - having all requests go through database, including GET and HEAD would allow
 *   for better transactional semantics, instead of the current race conditions
 *   inherent in multiple (and many) filesystem operations.  All queries would
 *   go through database, which would map to objects on disk, and copy and move
 *   would simply be database entries to objects with reference counts and
 *   copy-on-write semantics (instead of potential hard-links on disk).
 *   lstat() information could also be stored in database.  Right now, if a file
 *   is copied or moved or deleted, the status of the property update in the db
 *   is discarded, whether it succeeds or not, since file operation succeeded.
 *   (Then again, it might also be okay if props do not exist on a given file.)
 *   On the other hand, if everything went through database, then etag could be
 *   stored in database and could be updated upon PUT (or MOVE/COPY/DELETE).
 *   There would also need to be a way to trigger a rescan of filesystem to
 *   bring the database into sync with any out-of-band changes.
 *
 *
 * notes:
 *
 * - lstat() used instead of stat_cache_*() since the stat_cache might have
 *   expired data, as stat_cache is not invalidated by outside modifications,
 *   such as WebDAV PUT method (unless FAM is used)
 *
 * - SQLite database can be run in WAL mode (https://sqlite.org/wal.html)
 *   though mod_webdav does not provide a mechanism to configure WAL.
 *   Instead, once lighttpd starts up mod_webdav and creates the database,
 *   set WAL mode on the database from the command and then restart lighttpd.
 */


/* linkat() fstatat() unlinkat() fdopendir() NAME_MAX */
#if !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE-0 < 700
#undef  _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
/* DT_UNKNOWN DTTOIF() */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "first.h"  /* first */
#include "sys-mmap.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>      /* rename() */
#include <stdlib.h>     /* strtol() */
#include <string.h>
#include <unistd.h>     /* getpid() linkat() rmdir() unlinkat() */

#ifndef _D_EXACT_NAMLEN
#ifdef _DIRENT_HAVE_D_NAMLEN
#define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
#else
#define _D_EXACT_NAMLEN(d) (strlen ((d)->d_name))
#endif
#endif

#if defined(HAVE_LIBXML_H) && defined(HAVE_SQLITE3_H)

#define USE_PROPPATCH
/* minor: libxml2 includes stdlib.h in headers, too */
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <sqlite3.h>

#if defined(HAVE_LIBUUID) && defined(HAVE_UUID_UUID_H)
#define USE_LOCKS
#include <uuid/uuid.h>
#endif

#endif /* defined(HAVE_LIBXML_H) && defined(HAVE_SQLITE3_H) */

#include "base.h"
#include "buffer.h"
#include "chunk.h"
#include "fdevent.h"
#include "http_header.h"
#include "etag.h"
#include "log.h"
#include "connections.h"/* connection_handle_read_post_state() */
#include "request.h"
#include "response.h"   /* http_response_redirect_to_directory() */
#include "stat_cache.h" /* stat_cache_mimetype_by_ext() */

#include "configfile.h"
#include "plugin.h"

#define http_status_get(con)           ((con)->http_status)
#define http_status_set_fin(con, code) ((con)->file_finished = 1,  \
                                        (con)->mode = DIRECT,      \
                                        (con)->http_status = (code))
#define http_status_set(con, code)     ((con)->http_status = (code))
#define http_status_unset(con)         ((con)->http_status = 0)
#define http_status_is_set(con)        (0 != (con)->http_status)
__attribute_cold__
__attribute_noinline__
static int http_status_set_error (connection *con, int status) {
    return http_status_set_fin(con, status);
}

typedef physical physical_st;

INIT_FUNC(mod_webdav_init);
FREE_FUNC(mod_webdav_free);
SETDEFAULTS_FUNC(mod_webdav_set_defaults);
SERVER_FUNC(mod_webdav_worker_init);
URIHANDLER_FUNC(mod_webdav_uri_handler);
PHYSICALPATH_FUNC(mod_webdav_physical_handler);
SUBREQUEST_FUNC(mod_webdav_subrequest_handler);
CONNECTION_FUNC(mod_webdav_handle_reset);

int mod_webdav_plugin_init(plugin *p);
int mod_webdav_plugin_init(plugin *p) {
    p->version           = LIGHTTPD_VERSION_ID;
    p->name              = buffer_init_string("webdav");

    p->init              = mod_webdav_init;
    p->cleanup           = mod_webdav_free;
    p->set_defaults      = mod_webdav_set_defaults;
    p->worker_init       = mod_webdav_worker_init;
    p->handle_uri_clean  = mod_webdav_uri_handler;
    p->handle_physical   = mod_webdav_physical_handler;
    p->handle_subrequest = mod_webdav_subrequest_handler;
    p->connection_reset  = mod_webdav_handle_reset;

    p->data              = NULL;

    return 0;
}


#define WEBDAV_FILE_MODE  S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define WEBDAV_DIR_MODE   S_IRWXU|S_IRWXG|S_IRWXO

#define WEBDAV_FLAG_LC_NAMES     0x01
#define WEBDAV_FLAG_OVERWRITE    0x02
#define WEBDAV_FLAG_MOVE_RENAME  0x04
#define WEBDAV_FLAG_COPY_LINK    0x08
#define WEBDAV_FLAG_MOVE_XDEV    0x10
#define WEBDAV_FLAG_COPY_XDEV    0x20

#define webdav_xmlstrcmp_fixed(s, fixed) \
        strncmp((const char *)(s), (fixed), sizeof(fixed))

#include <ctype.h>      /* isupper() tolower() */
static void
webdav_str_len_to_lower (char * const restrict s, const uint32_t len)
{
    /*(caller must ensure that len not truncated to (int);
     * for current intended use, NAME_MAX typically <= 255)*/
    for (int i = 0; i < (int)len; ++i) {
        if (isupper(s[i]))
            s[i] = tolower(s[i]);
    }
}

typedef struct {
  #ifdef USE_PROPPATCH
    sqlite3 *sqlh;
    sqlite3_stmt *stmt_props_select_propnames;
    sqlite3_stmt *stmt_props_select_props;
    sqlite3_stmt *stmt_props_select_prop;
    sqlite3_stmt *stmt_props_update_prop;
    sqlite3_stmt *stmt_props_delete_prop;

    sqlite3_stmt *stmt_props_copy;
    sqlite3_stmt *stmt_props_move;
    sqlite3_stmt *stmt_props_move_col;
    sqlite3_stmt *stmt_props_delete;

    sqlite3_stmt *stmt_locks_acquire;
    sqlite3_stmt *stmt_locks_refresh;
    sqlite3_stmt *stmt_locks_release;
    sqlite3_stmt *stmt_locks_read;
    sqlite3_stmt *stmt_locks_read_uri;
    sqlite3_stmt *stmt_locks_read_uri_infinity;
    sqlite3_stmt *stmt_locks_read_uri_members;
    sqlite3_stmt *stmt_locks_delete_uri;
    sqlite3_stmt *stmt_locks_delete_uri_col;
  #else
    int dummy;
  #endif
} sql_config;

/* plugin config for all request/connections */

typedef struct {
    int config_context_idx;
    uint32_t directives;
    unsigned short enabled;
    unsigned short is_readonly;
    unsigned short log_xml;
    unsigned short deprecated_unsafe_partial_put_compat;

    sql_config *sql;
    server *srv;
    buffer *tmpb;
    buffer *sqlite_db_name; /* not used after worker init */
    array *opts;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    int nconfig;
    plugin_config **config_storage;
} plugin_data;


/* init the plugin data */
INIT_FUNC(mod_webdav_init) {
    return calloc(1, sizeof(plugin_data));
}


/* destroy the plugin data */
FREE_FUNC(mod_webdav_free) {
    plugin_data *p = (plugin_data *)p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
      #ifdef USE_PROPPATCH
        for (int i = 0; i < p->nconfig; ++i) {
            plugin_config * const s = p->config_storage[i];
            if (NULL == s) continue;
            buffer_free(s->sqlite_db_name);
            array_free(s->opts);

            sql_config * const sql = s->sql;
            if (!sql || !sql->sqlh) {
                free(sql);
                continue;
            }

            sqlite3_finalize(sql->stmt_props_select_propnames);
            sqlite3_finalize(sql->stmt_props_select_props);
            sqlite3_finalize(sql->stmt_props_select_prop);
            sqlite3_finalize(sql->stmt_props_update_prop);
            sqlite3_finalize(sql->stmt_props_delete_prop);
            sqlite3_finalize(sql->stmt_props_copy);
            sqlite3_finalize(sql->stmt_props_move);
            sqlite3_finalize(sql->stmt_props_move_col);
            sqlite3_finalize(sql->stmt_props_delete);

            sqlite3_finalize(sql->stmt_locks_acquire);
            sqlite3_finalize(sql->stmt_locks_refresh);
            sqlite3_finalize(sql->stmt_locks_release);
            sqlite3_finalize(sql->stmt_locks_read);
            sqlite3_finalize(sql->stmt_locks_read_uri);
            sqlite3_finalize(sql->stmt_locks_read_uri_infinity);
            sqlite3_finalize(sql->stmt_locks_read_uri_members);
            sqlite3_finalize(sql->stmt_locks_delete_uri);
            sqlite3_finalize(sql->stmt_locks_delete_uri_col);
            sqlite3_close(sql->sqlh);
            free(sql);
        }
      #endif
        free(p->config_storage);
    }

    free(p);

    UNUSED(srv);
    return HANDLER_GO_ON;
}


__attribute_cold__
static handler_t mod_webdav_sqlite3_init (plugin_config * restrict s, log_error_st *errh);

/* handle plugin config and check values */
SETDEFAULTS_FUNC(mod_webdav_set_defaults) {

  #ifdef USE_PROPPATCH
    int sqlrc = sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
    if (sqlrc != SQLITE_OK) {
        log_error(srv->errh, __FILE__, __LINE__, "sqlite3_config(): %s",
                  sqlite3_errstr(sqlrc));
        /*(performance option since our use is not threaded; not fatal)*/
        /*return HANDLER_ERROR;*/
    }
  #endif

    config_values_t cv[] = {
      { "webdav.activate",       NULL, T_CONFIG_BOOLEAN,    T_CONFIG_SCOPE_CONNECTION },
      { "webdav.is-readonly",    NULL, T_CONFIG_BOOLEAN,    T_CONFIG_SCOPE_CONNECTION },
      { "webdav.log-xml",        NULL, T_CONFIG_BOOLEAN,    T_CONFIG_SCOPE_CONNECTION },
      { "webdav.sqlite-db-name", NULL, T_CONFIG_STRING,     T_CONFIG_SCOPE_CONNECTION },
      { "webdav.opts",           NULL, T_CONFIG_ARRAY,      T_CONFIG_SCOPE_CONNECTION },

      { NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = (plugin_data *)p_d;
    p->config_storage = calloc(srv->config_context->used, sizeof(plugin_config *));
    force_assert(p->config_storage);

    const size_t n_context = p->nconfig = srv->config_context->used;
    for (size_t i = 0; i < n_context; ++i) {
        data_config const *config =
          (data_config const *)srv->config_context->data[i];
        plugin_config * const restrict s = calloc(1, sizeof(plugin_config));
        force_assert(s);
        p->config_storage[i] = s;
        s->sqlite_db_name = buffer_init();
        s->opts = array_init();

        cv[0].destination = &(s->enabled);
        cv[1].destination = &(s->is_readonly);
        cv[2].destination = &(s->log_xml);
        cv[3].destination = s->sqlite_db_name;
        cv[4].destination = s->opts;

        if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (!buffer_is_empty(s->sqlite_db_name)) {
            if (mod_webdav_sqlite3_init(s, srv->errh) == HANDLER_ERROR)
                return HANDLER_ERROR;
        }

        for (size_t j = 0, used = s->opts->used; j < used; ++j) {
            data_string *ds = (data_string *)s->opts->data[j];
            if (buffer_is_equal_string(ds->key,
                  CONST_STR_LEN("deprecated-unsafe-partial-put"))
                && buffer_is_equal_string(ds->value, CONST_STR_LEN("enable"))) {
                s->deprecated_unsafe_partial_put_compat = 1;
                continue;
            }
            log_error(srv->errh, __FILE__, __LINE__,
                      "unrecognized webdav.opts: %.*s",
                      BUFFER_INTLEN_PTR(ds->key));
            return HANDLER_ERROR;
        }
    }
    if (n_context) {
        p->config_storage[0]->srv  = srv;
        p->config_storage[0]->tmpb = srv->tmp_buf;
    }

    return HANDLER_GO_ON;
}


#define PATCH_OPTION(x) pconf->x = s->x;
static void
mod_webdav_patch_connection (server * const restrict srv,
                             connection * const restrict con,
                             const plugin_data * const restrict p,
                             plugin_config * const restrict pconf)
{
    const plugin_config *s = p->config_storage[0];
    memcpy(pconf, s, sizeof(*s));
    data_config ** const restrict context_data =
      (data_config **)srv->config_context->data;

    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config * const dc = context_data[i];
        if (!config_check_cond(srv, con, dc))
            continue; /* condition did not match */

        s = p->config_storage[i];

        /* merge config */
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];
            if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.activate"))) {
                PATCH_OPTION(enabled);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.is-readonly"))) {
                PATCH_OPTION(is_readonly);
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.log-xml"))) {
                PATCH_OPTION(log_xml);
          #ifdef USE_PROPPATCH
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.sqlite-db-name"))) {
                PATCH_OPTION(sql);
          #endif
            } else if (buffer_is_equal_string(du->key, CONST_STR_LEN("webdav.opts"))) {
                PATCH_OPTION(deprecated_unsafe_partial_put_compat);
            }
        }
    }
}


URIHANDLER_FUNC(mod_webdav_uri_handler)
{
    UNUSED(srv);
    if (con->request.http_method != HTTP_METHOD_OPTIONS)
        return HANDLER_GO_ON;

    plugin_config pconf;
    mod_webdav_patch_connection(srv, con, (plugin_data *)p_d, &pconf);
    if (!pconf.enabled) return HANDLER_GO_ON;

    /* [RFC4918] 18 DAV Compliance Classes */
    http_header_response_set(con, HTTP_HEADER_OTHER,
      CONST_STR_LEN("DAV"),
     #ifdef USE_LOCKS
      CONST_STR_LEN("1,2,3")
     #else
      CONST_STR_LEN("1,3")
     #endif
    );

    /* instruct MS Office Web Folders to use DAV
     * (instead of MS FrontPage Extensions)
     * http://www.zorched.net/2006/03/01/more-webdav-tips-tricks-and-bugs/ */
    http_header_response_set(con, HTTP_HEADER_OTHER,
                             CONST_STR_LEN("MS-Author-Via"),
                             CONST_STR_LEN("DAV"));

    if (pconf.is_readonly)
        http_header_response_append(con, HTTP_HEADER_OTHER,
          CONST_STR_LEN("Allow"),
          CONST_STR_LEN("PROPFIND"));
    else
        http_header_response_append(con, HTTP_HEADER_OTHER,
          CONST_STR_LEN("Allow"),
      #ifdef USE_PROPPATCH
       #ifdef USE_LOCKS
          CONST_STR_LEN(
            "PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK")
       #else
          CONST_STR_LEN(
            "PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH")
       #endif
      #else
          CONST_STR_LEN(
            "PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY")
      #endif
        );

    return HANDLER_GO_ON;
}


#ifdef USE_LOCKS

typedef struct webdav_lockdata {
  buffer locktoken;
  buffer lockroot;
  buffer ownerinfo;
  buffer *owner;
  const buffer *lockscope; /* future: might use enum, store int in db */
  const buffer *locktype;  /* future: might use enum, store int in db */
  int depth;
  int timeout;           /* offset from now, not absolute time_t */
} webdav_lockdata;

typedef struct { const char *ptr; uint32_t used; uint32_t size; } tagb;

static const tagb lockscope_exclusive =
  { "exclusive", sizeof("exclusive"), 0 };
static const tagb lockscope_shared =
  { "shared",    sizeof("shared"),    0 };
static const tagb locktype_write =
  { "write",     sizeof("write"),     0 };

#endif

typedef struct {
    const char *ns;
    const char *name;
    uint32_t nslen;
    uint32_t namelen;
} webdav_property_name;

typedef struct {
    webdav_property_name *ptr;
    int used;
    int size;
} webdav_property_names;

/*
 * http://www.w3.org/TR/1998/NOTE-XML-data-0105/
 *   The datatype attribute "dt" is defined in the namespace named
 *   "urn:uuid:C2F41010-65B3-11d1-A29F-00AA00C14882/".
 *   (See the XML Namespaces Note at the W3C site for details of namespaces.)
 *   The full URN of the attribute is
 *   "urn:uuid:C2F41010-65B3-11d1-A29F-00AA00C14882/dt".
 * http://www.w3.org/TR/1998/NOTE-xml-names-0119
 * http://www.w3.org/TR/1998/WD-xml-names-19980327
 * http://lists.xml.org/archives/xml-dev/200101/msg00924.html
 * http://lists.xml.org/archives/xml-dev/200101/msg00929.html
 * http://lists.xml.org/archives/xml-dev/200101/msg00930.html
 * (Microsoft) Namespace Guidelines
 *   https://msdn.microsoft.com/en-us/library/ms879470%28v=exchg.65%29.aspx
 * (Microsoft) XML Persistence Format
 *   https://msdn.microsoft.com/en-us/library/ms676547%28v=vs.85%29.aspx
 * http://www.xml.com/pub/a/2002/06/26/vocabularies.html
 *   The "Uuid" namespaces is the namespace
 *   "uuid:C2F41010-65B3-11d1-A29F-00AA00C14882",
 *   mainly found in association with the MS Office
 *   namespace on the http://www.omg.org website.
 * http://www.data2type.de/en/xml-xslt-xslfo/wordml/wordml-introduction/the-root-element/
 *   xmlns:dt="uuid:C2F41010-65B3-11d1-A29F-00AA00C14882"
 *   By using the prefix dt, the namespace declares an attribute which
 *   determines the data type of a value. The name of the underlying schema
 *   is dt.xsd and it can be found in the folder for Excel schemas.
 */
#define MOD_WEBDAV_XMLNS_NS0 "xmlns:ns0=\"urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/\""


static void
webdav_xml_doctype (buffer * const b, connection * const con)
{
    http_header_response_set(con, HTTP_HEADER_CONTENT_TYPE,
      CONST_STR_LEN("Content-Type"),
      CONST_STR_LEN("application/xml; charset=\"utf-8\""));

    buffer_copy_string_len(b, CONST_STR_LEN(
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"));
}


static void
webdav_xml_prop (buffer * const b,
                 const webdav_property_name * const prop,
                 const char * const value, const uint32_t vlen)
{
    buffer_append_string_len(b, CONST_STR_LEN("<"));
    buffer_append_string_len(b, prop->name, prop->namelen);
    buffer_append_string_len(b, CONST_STR_LEN(" xmlns=\""));
    buffer_append_string_len(b, prop->ns, prop->nslen);
    if (0 == vlen) {
        buffer_append_string_len(b, CONST_STR_LEN("\"/>"));
    }
    else {
        buffer_append_string_len(b, CONST_STR_LEN("\">"));
        buffer_append_string_len(b, value, vlen);
        buffer_append_string_len(b, CONST_STR_LEN("</"));
        buffer_append_string_len(b, prop->name, prop->namelen);
        buffer_append_string_len(b, CONST_STR_LEN(">"));
    }
}


#ifdef USE_LOCKS
static void
webdav_xml_href_raw (buffer * const b, const buffer * const href)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:href>"));
    buffer_append_string_len(b, CONST_BUF_LEN(href));
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:href>\n"));
}
#endif


static void
webdav_xml_href (buffer * const b, const buffer * const href)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:href>"));
    buffer_append_string_encoded(b, CONST_BUF_LEN(href), ENCODING_REL_URI);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:href>\n"));
}


static void
webdav_xml_status (buffer * const b, const int status)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:status>HTTP/1.1 "));
    http_status_append(b, status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:status>\n"));
}


#ifdef USE_PROPPATCH
__attribute_cold__
static void
webdav_xml_propstat_protected (buffer * const b, const char * const propname,
                               const uint32_t len, const int status)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:propstat>\n"
      "<D:prop><DAV:"));
    buffer_append_string_len(b, propname, len);
    buffer_append_string_len(b, CONST_STR_LEN(
      "/></D:prop>\n"
      "<D:error><DAV:cannot-modify-protected-property/></D:error>\n"));
    webdav_xml_status(b, status); /* 403 */
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:propstat>\n"));
}
#endif


#ifdef USE_PROPPATCH
__attribute_cold__
static void
webdav_xml_propstat_status (buffer * const b, const char * const ns,
                            const char * const name, const int status)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:propstat>\n"
      "<D:prop><"));
    buffer_append_string(b, ns);
    buffer_append_string(b, name);
    buffer_append_string_len(b, CONST_STR_LEN(
      "/></D:prop>\n"));
    webdav_xml_status(b, status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:propstat>\n"));
}
#endif


static void
webdav_xml_propstat (buffer * const b, buffer * const value, const int status)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:propstat>\n"
      "<D:prop>\n"));
    buffer_append_string_buffer(b, value);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:prop>\n"));
    webdav_xml_status(b, status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:propstat>\n"));
}


__attribute_cold__
static void
webdav_xml_response_status (buffer * const b,
                            const buffer * const href,
                            const int status)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:response>\n"));
    webdav_xml_href(b, href);
    webdav_xml_status(b, status);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:response>\n"));
}


#ifdef USE_LOCKS
static void
webdav_xml_activelock (buffer * const b,
                       const webdav_lockdata * const lockdata,
                       const char * const tbuf, uint32_t tbuf_len)
{
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:activelock>\n"
      "<D:lockscope>"
      "<D:"));
    buffer_append_string_buffer(b, lockdata->lockscope);
    buffer_append_string_len(b, CONST_STR_LEN(
      "/>"
      "</D:lockscope>\n"
      "<D:locktype>"
      "<D:"));
    buffer_append_string_buffer(b, lockdata->locktype);
    buffer_append_string_len(b, CONST_STR_LEN(
      "/>"
      "</D:locktype>\n"
      "<D:depth>"));
    if (0 == lockdata->depth)
        buffer_append_string_len(b, CONST_STR_LEN("0"));
    else
        buffer_append_string_len(b, CONST_STR_LEN("infinity"));
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:depth>\n"
      "<D:timeout>"));
    if (0 != tbuf_len)
        buffer_append_string_len(b, tbuf, tbuf_len); /* "Second-..." */
    else {
        buffer_append_string_len(b, CONST_STR_LEN("Second-"));
        buffer_append_int(b, lockdata->timeout);
    }
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:timeout>\n"
      "<D:owner>"));
    if (!buffer_string_is_empty(&lockdata->ownerinfo))
        buffer_append_string_buffer(b, &lockdata->ownerinfo);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:owner>\n"
      "<D:locktoken>\n"));
    webdav_xml_href_raw(b, &lockdata->locktoken); /*(as-is; not URL-encoded)*/
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:locktoken>\n"
      "<D:lockroot>\n"));
    webdav_xml_href(b, &lockdata->lockroot);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:lockroot>\n"
      "</D:activelock>\n"));
}
#endif


static void
webdav_xml_doc_multistatus (connection * const con,
                            const plugin_config * const pconf,
                            buffer * const ms)
{
    http_status_set_fin(con, 207); /* Multi-status */

    buffer * const b = /*(optimization; buf extended as needed)*/
      chunkqueue_append_buffer_open_sz(con->write_queue, 128 + ms->used);

    webdav_xml_doctype(b, con);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:multistatus xmlns:D=\"DAV:\">\n"));
    buffer_append_string_buffer(b, ms);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:multistatus>\n"));

    if (pconf->log_xml)
        log_error(con->errh, __FILE__, __LINE__,
                  "XML-response-body: %.*s", BUFFER_INTLEN_PTR(b));

    chunkqueue_append_buffer_commit(con->write_queue);
}


#ifdef USE_PROPPATCH
static void
webdav_xml_doc_multistatus_response (connection * const con,
                                     const plugin_config * const pconf,
                                     buffer * const ms)
{
    http_status_set_fin(con, 207); /* Multi-status */

    buffer * const b = /*(optimization; buf extended as needed)*/
      chunkqueue_append_buffer_open_sz(con->write_queue, 128 + ms->used);

    webdav_xml_doctype(b, con);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:multistatus xmlns:D=\"DAV:\">\n"
      "<D:response>\n"));
    webdav_xml_href(b, con->physical.rel_path);
    buffer_append_string_buffer(b, ms);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:response>\n"
      "</D:multistatus>\n"));

    if (pconf->log_xml)
        log_error(con->errh, __FILE__, __LINE__,
                  "XML-response-body: %.*s", BUFFER_INTLEN_PTR(b));

    chunkqueue_append_buffer_commit(con->write_queue);
}
#endif


#ifdef USE_LOCKS
static void
webdav_xml_doc_lock_acquired (connection * const con,
                              const plugin_config * const pconf,
                              const webdav_lockdata * const lockdata)
{
    /*(http_status is set by caller to 200 OK or 201 Created)*/

    char tbuf[32] = "Second-";
    li_itostrn(tbuf+sizeof("Second-")-1, sizeof(tbuf)-(sizeof("Second-")-1),
               lockdata->timeout);
    const uint32_t tbuf_len = strlen(tbuf);
    http_header_response_set(con, HTTP_HEADER_OTHER,
      CONST_STR_LEN("Timeout"),
      tbuf, tbuf_len);

    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, 1024);

    webdav_xml_doctype(b, con);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:prop xmlns:D=\"DAV:\">\n"
      "<D:lockdiscovery>\n"));
    webdav_xml_activelock(b, lockdata, tbuf, tbuf_len);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:lockdiscovery>\n"
      "</D:prop>\n"));

    if (pconf->log_xml)
        log_error(con->errh, __FILE__, __LINE__,
                  "XML-response-body: %.*s", BUFFER_INTLEN_PTR(b));

    chunkqueue_append_buffer_commit(con->write_queue);
}
#endif


/*
 * [RFC4918] 16 Precondition/Postcondition XML Elements
 */


/*
 * 403 Forbidden
 * "<D:error><DAV:cannot-modify-protected-property/></D:error>"
 *
 * 403 Forbidden
 * "<D:error><DAV:no-external-entities/></D:error>"
 *
 * 409 Conflict
 * "<D:error><DAV:preserved-live-properties/></D:error>"
 */


__attribute_cold__
static void
webdav_xml_doc_error_propfind_finite_depth (connection * const con)
{
    http_status_set(con, 403); /* Forbidden */
    con->file_finished = 1;

    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, 256);
    webdav_xml_doctype(b, con);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:error><DAV:propfind-finite-depth/></D:error>\n"));
    chunkqueue_append_buffer_commit(con->write_queue);
}


#ifdef USE_LOCKS
__attribute_cold__
static void
webdav_xml_doc_error_lock_token_matches_request_uri (connection * const con)
{
    http_status_set(con, 409); /* Conflict */
    con->file_finished = 1;

    buffer * const b =
      chunkqueue_append_buffer_open_sz(con->write_queue, 256);
    webdav_xml_doctype(b, con);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:error><DAV:lock-token-matches-request-uri/></D:error>\n"));
    chunkqueue_append_buffer_commit(con->write_queue);
}
#endif


#ifdef USE_LOCKS
__attribute_cold__
static void
webdav_xml_doc_423_locked (connection * const con, buffer * const hrefs,
                           const char * const errtag, const uint32_t errtaglen)
{
    http_status_set(con, 423); /* Locked */
    con->file_finished = 1;

    buffer * const b = /*(optimization; buf extended as needed)*/
      chunkqueue_append_buffer_open_sz(con->write_queue, 256 + hrefs->used);

    webdav_xml_doctype(b, con);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:error xmlns:D=\"DAV:\">\n"
      "<D:"));
    buffer_append_string_len(b, errtag, errtaglen);
    buffer_append_string_len(b, CONST_STR_LEN(
      ">\n"));
    buffer_append_string_buffer(b, hrefs);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:"));
    buffer_append_string_len(b, errtag, errtaglen);
    buffer_append_string_len(b, CONST_STR_LEN(
      ">\n"
      "</D:error>\n"));

    chunkqueue_append_buffer_commit(con->write_queue);
}
#endif


#ifdef USE_LOCKS
__attribute_cold__
static void
webdav_xml_doc_error_lock_token_submitted (connection * const con,
                                           buffer * const hrefs)
{
    webdav_xml_doc_423_locked(con, hrefs,
                              CONST_STR_LEN("lock-token-submitted"));
}
#endif


#ifdef USE_LOCKS
__attribute_cold__
static void
webdav_xml_doc_error_no_conflicting_lock (connection * const con,
                                          buffer * const hrefs)
{
    webdav_xml_doc_423_locked(con, hrefs,
                              CONST_STR_LEN("no-conflicting-lock"));
}
#endif


#ifdef USE_PROPPATCH

  #define MOD_WEBDAV_SQLITE_CREATE_TABLE_PROPERTIES \
    "CREATE TABLE IF NOT EXISTS properties ("       \
    "  resource TEXT NOT NULL,"                     \
    "  prop TEXT NOT NULL,"                         \
    "  ns TEXT NOT NULL,"                           \
    "  value TEXT NOT NULL,"                        \
    "  PRIMARY KEY(resource, prop, ns))"

  #define MOD_WEBDAV_SQLITE_CREATE_TABLE_LOCKS \
    "CREATE TABLE IF NOT EXISTS locks ("       \
    "  locktoken TEXT NOT NULL,"               \
    "  resource TEXT NOT NULL,"                \
    "  lockscope TEXT NOT NULL,"               \
    "  locktype TEXT NOT NULL,"                \
    "  owner TEXT NOT NULL,"                   \
    "  ownerinfo TEXT NOT NULL,"               \
    "  depth INT NOT NULL,"                    \
    "  timeout TIMESTAMP NOT NULL,"            \
    "  PRIMARY KEY(locktoken))"

  #define MOD_WEBDAV_SQLITE_PROPS_SELECT_PROPNAMES \
    "SELECT prop, ns FROM properties WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_SELECT_PROP \
    "SELECT value FROM properties WHERE resource = ? AND prop = ? AND ns = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_SELECT_PROPS \
    "SELECT prop, ns, value FROM properties WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_UPDATE_PROP \
    "REPLACE INTO properties (resource, prop, ns, value) VALUES (?, ?, ?, ?)"

  #define MOD_WEBDAV_SQLITE_PROPS_DELETE_PROP \
    "DELETE FROM properties WHERE resource = ? AND prop = ? AND ns = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_DELETE \
    "DELETE FROM properties WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_COPY \
    "INSERT INTO properties"           \
    "  SELECT ?, prop, ns, value FROM properties WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_MOVE \
    "UPDATE OR REPLACE properties SET resource = ? WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_PROPS_MOVE_COL                                 \
    "UPDATE OR REPLACE properties SET resource = ? || SUBSTR(resource, ?)" \
    "  WHERE SUBSTR(resource, 1, ?) = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_ACQUIRE                                     \
    "INSERT INTO locks"                                                       \
    "  (locktoken,resource,lockscope,locktype,owner,ownerinfo,depth,timeout)" \
    "  VALUES (?,?,?,?,?,?,?, CURRENT_TIME + ?)"

  #define MOD_WEBDAV_SQLITE_LOCKS_REFRESH \
    "UPDATE locks SET timeout = CURRENT_TIME + ? WHERE locktoken = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_RELEASE \
    "DELETE FROM locks WHERE locktoken = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_READ \
    "SELECT resource, owner, depth"    \
    "  FROM locks WHERE locktoken = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_READ_URI                           \
    "SELECT"                                                         \
    "  locktoken,resource,lockscope,locktype,owner,ownerinfo,depth," \
        "timeout - CURRENT_TIME"                                     \
    "  FROM locks WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_READ_URI_INFINITY                  \
    "SELECT"                                                         \
    "  locktoken,resource,lockscope,locktype,owner,ownerinfo,depth," \
        "timeout - CURRENT_TIME"                                     \
    "  FROM locks"                                                   \
    "  WHERE depth = -1 AND resource = SUBSTR(?, 1, LENGTH(resource))"

  #define MOD_WEBDAV_SQLITE_LOCKS_READ_URI_MEMBERS                   \
    "SELECT"                                                         \
    "  locktoken,resource,lockscope,locktype,owner,ownerinfo,depth," \
        "timeout - CURRENT_TIME"                                     \
    "  FROM locks WHERE SUBSTR(resource, 1, ?) = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_DELETE_URI \
    "DELETE FROM locks WHERE resource = ?"

  #define MOD_WEBDAV_SQLITE_LOCKS_DELETE_URI_COL \
    "DELETE FROM locks WHERE SUBSTR(resource, 1, ?) = ?"
    /*"DELETE FROM locks WHERE locktoken LIKE ? || '%'"*/

  /*(not currently used)*/
  #define MOD_WEBDAV_SQLITE_LOCKS_DELETE_EXPIRED \
    "DELETE FROM locks WHERE timeout < CURRENT_TIME"

#endif /* USE_PROPPATCH */


__attribute_cold__
static handler_t
mod_webdav_sqlite3_init (plugin_config * const restrict s,
                         log_error_st * const errh)
{
  #ifndef USE_PROPPATCH

    log_error(errh, __FILE__, __LINE__,
              "Sorry, no sqlite3 and libxml2 support include, "
              "compile with --with-webdav-props");
    UNUSED(s);
    return HANDLER_ERROR;

  #else /* USE_PROPPATCH */

  /*(expects (plugin_config *s) (log_error_st *errh) (char *err))*/
  #define MOD_WEBDAV_SQLITE_CREATE_TABLE(query, label)                   \
    if (sqlite3_exec(sql->sqlh, query, NULL, NULL, &err) != SQLITE_OK) { \
        if (0 != strcmp(err, "table " label " already exists")) {        \
            log_error(errh, __FILE__, __LINE__,                          \
                      "create table " label ": %s", err);                \
            sqlite3_free(err);                                           \
            return HANDLER_ERROR;                                        \
        }                                                                \
        sqlite3_free(err);                                               \
    }

    sql_config * const sql = s->sql = (sql_config *)calloc(1, sizeof(*sql));
    force_assert(sql);
    int sqlrc = sqlite3_open_v2(s->sqlite_db_name->ptr, &sql->sqlh,
                                SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
    if (sqlrc != SQLITE_OK) {
        log_error(errh, __FILE__, __LINE__, "sqlite3_open() '%.*s': %s",
                  BUFFER_INTLEN_PTR(s->sqlite_db_name),
                  sql->sqlh
                    ? sqlite3_errmsg(sql->sqlh)
                    : sqlite3_errstr(sqlrc));
        return HANDLER_ERROR;
    }

    char *err = NULL;
    MOD_WEBDAV_SQLITE_CREATE_TABLE( MOD_WEBDAV_SQLITE_CREATE_TABLE_PROPERTIES,
                                    "properties");
    MOD_WEBDAV_SQLITE_CREATE_TABLE( MOD_WEBDAV_SQLITE_CREATE_TABLE_LOCKS,
                                    "locks");

    /* add ownerinfo column to locks table (update older mod_webdav sqlite db)
     * (could check if 'PRAGMA user_version;' is 0, add column, and increment)*/
  #define MOD_WEBDAV_SQLITE_SELECT_LOCKS_OWNERINFO_TEST \
    "SELECT COUNT(*) FROM locks WHERE ownerinfo = \"\""
  #define MOD_WEBDAV_SQLITE_ALTER_TABLE_LOCKS \
    "ALTER TABLE locks ADD COLUMN ownerinfo TEXT NOT NULL DEFAULT \"\""
    if (sqlite3_exec(sql->sqlh, MOD_WEBDAV_SQLITE_SELECT_LOCKS_OWNERINFO_TEST,
                     NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err); /* "no such column: ownerinfo" */
        if (sqlite3_exec(sql->sqlh, MOD_WEBDAV_SQLITE_ALTER_TABLE_LOCKS,
                         NULL, NULL, &err) != SQLITE_OK) {
            log_error(errh, __FILE__, __LINE__, "alter table locks: %s", err);
            sqlite3_free(err);
            return HANDLER_ERROR;
        }
    }

    sqlite3_close(sql->sqlh);
    sql->sqlh = NULL;

    return HANDLER_GO_ON;

  #endif /* USE_PROPPATCH */
}


#ifdef USE_PROPPATCH
__attribute_cold__
static handler_t
mod_webdav_sqlite3_prep (sql_config * const restrict sql,
                         const buffer * const sqlite_db_name,
                         log_error_st * const errh)
{
  /*(expects (plugin_config *s) (log_error_st *errh))*/
  #define MOD_WEBDAV_SQLITE_PREPARE_STMT(query, stmt)                      \
    if (sqlite3_prepare_v2(sql->sqlh, query, sizeof(query)-1, &stmt, NULL) \
        != SQLITE_OK) {                                                    \
        log_error(errh, __FILE__, __LINE__, "sqlite3_prepare_v2(): %s",    \
                  sqlite3_errmsg(sql->sqlh));                              \
        return HANDLER_ERROR;                                              \
    }

    int sqlrc = sqlite3_open_v2(sqlite_db_name->ptr, &sql->sqlh,
                                SQLITE_OPEN_READWRITE, NULL);
    if (sqlrc != SQLITE_OK) {
        log_error(errh, __FILE__, __LINE__, "sqlite3_open() '%.*s': %s",
                  BUFFER_INTLEN_PTR(sqlite_db_name),
                  sql->sqlh
                    ? sqlite3_errmsg(sql->sqlh)
                    : sqlite3_errstr(sqlrc));
        return HANDLER_ERROR;
    }

    /* future: perhaps not all statements should be prepared;
     * infrequently executed statements could be run with sqlite3_exec(),
     * or prepared and finalized on each use, as needed */

    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_SELECT_PROPNAMES,
                                    sql->stmt_props_select_propnames);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_SELECT_PROPS,
                                    sql->stmt_props_select_props);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_SELECT_PROP,
                                    sql->stmt_props_select_prop);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_UPDATE_PROP,
                                    sql->stmt_props_update_prop);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_DELETE_PROP,
                                    sql->stmt_props_delete_prop);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_COPY,
                                    sql->stmt_props_copy);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_MOVE,
                                    sql->stmt_props_move);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_MOVE_COL,
                                    sql->stmt_props_move_col);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_PROPS_DELETE,
                                    sql->stmt_props_delete);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_ACQUIRE,
                                    sql->stmt_locks_acquire);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_REFRESH,
                                    sql->stmt_locks_refresh);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_RELEASE,
                                    sql->stmt_locks_release);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_READ,
                                    sql->stmt_locks_read);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_READ_URI,
                                    sql->stmt_locks_read_uri);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_READ_URI_INFINITY,
                                    sql->stmt_locks_read_uri_infinity);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_READ_URI_MEMBERS,
                                    sql->stmt_locks_read_uri_members);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_DELETE_URI,
                                    sql->stmt_locks_delete_uri);
    MOD_WEBDAV_SQLITE_PREPARE_STMT( MOD_WEBDAV_SQLITE_LOCKS_DELETE_URI_COL,
                                    sql->stmt_locks_delete_uri_col);

    return HANDLER_GO_ON;

}
#endif /* USE_PROPPATCH */


SERVER_FUNC(mod_webdav_worker_init)
{
  #ifdef USE_PROPPATCH
    /* open sqlite databases and prepare SQL statements in each worker process
     *
     * https://www.sqlite.org/faq.html
     *   Under Unix, you should not carry an open SQLite database
     *   across a fork() system call into the child process.
     */
    plugin_data * const p = (plugin_data *)p_d;
    for (int i = 0; i < p->nconfig; ++i) {
        plugin_config *s = p->config_storage[i];
        if (!buffer_is_empty(s->sqlite_db_name)
            && mod_webdav_sqlite3_prep(s->sql, s->sqlite_db_name, srv->errh)
               == HANDLER_ERROR)
            return HANDLER_ERROR;
    }
  #else
    UNUSED(srv);
    UNUSED(p_d);
  #endif /* USE_PROPPATCH */
    return HANDLER_GO_ON;
}


#ifdef USE_PROPPATCH
static int
webdav_db_transaction (const plugin_config * const pconf,
                       const char * const action)
{
    if (!pconf->sql)
        return 1;
    char *err = NULL;
    if (SQLITE_OK == sqlite3_exec(pconf->sql->sqlh, action, NULL, NULL, &err))
        return 1;
    else {
      #if 0
        fprintf(stderr, "%s: %s: %s\n", __func__, action, err);
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s: %s\n", __func__, action, err);
      #endif
        sqlite3_free(err);
        return 0;
    }
}

#define webdav_db_transaction_begin(pconf) \
        webdav_db_transaction(pconf, "BEGIN;")

#define webdav_db_transaction_begin_immediate(pconf) \
        webdav_db_transaction(pconf, "BEGIN IMMEDIATE;")

#define webdav_db_transaction_commit(pconf) \
        webdav_db_transaction(pconf, "COMMIT;")

#define webdav_db_transaction_rollback(pconf) \
        webdav_db_transaction(pconf, "ROLLBACK;")

#else

#define webdav_db_transaction_begin(pconf)            1
#define webdav_db_transaction_begin_immediate(pconf)  1
#define webdav_db_transaction_commit(pconf)           1
#define webdav_db_transaction_rollback(pconf)         1

#endif


#ifdef USE_LOCKS
static int
webdav_lock_match (const plugin_config * const pconf,
                   const webdav_lockdata * const lockdata)
{
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_locks_read;
    if (!stmt)
        return 0;

    sqlite3_bind_text(
      stmt, 1, CONST_BUF_LEN(&lockdata->locktoken), SQLITE_STATIC);

    int status = -1; /* if lock does not exist */
    if (SQLITE_ROW == sqlite3_step(stmt)) {
        const char *text = (char *)sqlite3_column_text(stmt, 0); /* resource */
        uint32_t text_len = (uint32_t) sqlite3_column_bytes(stmt, 0);
        if (text_len < lockdata->lockroot.used
            && 0 == memcmp(lockdata->lockroot.ptr, text, text_len)
            && (text_len == lockdata->lockroot.used-1
                || -1 == sqlite3_column_int(stmt, 2))) { /* depth */
            text = (char *)sqlite3_column_text(stmt, 1); /* owner */
            text_len = (uint32_t)sqlite3_column_bytes(stmt, 1);
            if (0 == text_len /*(if no auth required to lock; not recommended)*/
                || buffer_is_equal_string(lockdata->owner, text, text_len))
                status = 0; /* success; lock match */
            else {
                /*(future: might check if owner is a privileged admin user)*/
                status = -3; /* not lock owner; not authorized */
            }
        }
        else
            status = -2; /* URI is not in scope of lock */
    }

    sqlite3_reset(stmt);

    /* status
     *    0 lock exists and uri in scope and owner is privileged/owns lock
     *   -1 lock does not exist
     *   -2 URI is not in scope of lock
     *   -3 owner does not own lock/is not privileged
     */
    return status;
}
#endif


#ifdef USE_LOCKS
static void
webdav_lock_activelocks_lockdata (sqlite3_stmt * const stmt,
                                  webdav_lockdata * const lockdata)
{
    lockdata->locktoken.ptr  = (char *)sqlite3_column_text(stmt, 0);
    lockdata->locktoken.used = sqlite3_column_bytes(stmt, 0);
    lockdata->lockroot.ptr   = (char *)sqlite3_column_text(stmt, 1);
    lockdata->lockroot.used  = sqlite3_column_bytes(stmt, 1);
    lockdata->lockscope      =
      (sqlite3_column_bytes(stmt, 2) == (int)sizeof("exclusive")-1)
        ? (const buffer *)&lockscope_exclusive
        : (const buffer *)&lockscope_shared;
    lockdata->locktype       = (const buffer *)&locktype_write;
    lockdata->owner->ptr     = (char *)sqlite3_column_text(stmt, 4);
    lockdata->owner->used    = sqlite3_column_bytes(stmt, 4);
    lockdata->ownerinfo.ptr  = (char *)sqlite3_column_text(stmt, 5);
    lockdata->ownerinfo.used = sqlite3_column_bytes(stmt, 5);
    lockdata->depth          = sqlite3_column_int(stmt, 6);
    lockdata->timeout        = sqlite3_column_int(stmt, 7);

    if (lockdata->locktoken.used) ++lockdata->locktoken.used;
    if (lockdata->lockroot.used)  ++lockdata->lockroot.used;
    if (lockdata->owner->used)    ++lockdata->owner->used;
    if (lockdata->ownerinfo.used) ++lockdata->ownerinfo.used;
}


typedef
  void webdav_lock_activelocks_cb(void * const vdata,
                                  const webdav_lockdata * const lockdata);

static void
webdav_lock_activelocks (const plugin_config * const pconf,
                         const buffer * const uri,
                         const int expand_checks,
                         webdav_lock_activelocks_cb * const lock_cb,
                         void * const vdata)
{
    webdav_lockdata lockdata;
    buffer owner = { NULL, 0, 0 };
    lockdata.locktoken.size = 0;
    lockdata.lockroot.size  = 0;
    lockdata.ownerinfo.size = 0;
    lockdata.owner = &owner;

    if (!pconf->sql)
        return;

    /* check for locks with Depth: 0 (and Depth: infinity if 0==expand_checks)*/
    sqlite3_stmt *stmt = pconf->sql->stmt_locks_read_uri;
    if (!stmt || !pconf->sql->stmt_locks_read_uri_infinity
              || !pconf->sql->stmt_locks_read_uri_members)
        return;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri), SQLITE_STATIC);

    while (SQLITE_ROW == sqlite3_step(stmt)) {
        /* (avoid duplication with query below if infinity lock on collection)
         * (infinity locks are rejected on non-collections elsewhere) */
        if (0 != expand_checks && -1 == sqlite3_column_int(stmt, 6) /*depth*/)
            continue;

        webdav_lock_activelocks_lockdata(stmt, &lockdata);
        if (lockdata.timeout > 0)
            lock_cb(vdata, &lockdata);
    }

    sqlite3_reset(stmt);

    if (0 == expand_checks)
        return;

    /* check for locks with Depth: infinity
     * (i.e. collections: self (if collection) or containing collections) */
    stmt = pconf->sql->stmt_locks_read_uri_infinity;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri), SQLITE_STATIC);

    while (SQLITE_ROW == sqlite3_step(stmt)) {
        webdav_lock_activelocks_lockdata(stmt, &lockdata);
        if (lockdata.timeout > 0)
            lock_cb(vdata, &lockdata);
    }

    sqlite3_reset(stmt);

    if (1 == expand_checks)
        return;

  #ifdef __COVERITY__
    force_assert(0 != uri->used);
  #endif

    /* check for locks on members within (internal to) collection */
    stmt = pconf->sql->stmt_locks_read_uri_members;

    sqlite3_bind_int( stmt, 1, (int)uri->used-1);
    sqlite3_bind_text(stmt, 2, CONST_BUF_LEN(uri), SQLITE_STATIC);

    while (SQLITE_ROW == sqlite3_step(stmt)) {
        /* (avoid duplication with query above for exact resource match) */
        if (uri->used-1 == (uint32_t)sqlite3_column_bytes(stmt, 1) /*resource*/)
            continue;

        webdav_lock_activelocks_lockdata(stmt, &lockdata);
        if (lockdata.timeout > 0)
            lock_cb(vdata, &lockdata);
    }

    sqlite3_reset(stmt);
}
#endif


static int
webdav_lock_delete_uri (const plugin_config * const pconf,
                        const buffer * const uri)
{
  #ifdef USE_LOCKS

    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_locks_delete_uri;
    if (!stmt)
        return 0;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri), SQLITE_STATIC);

    int status = 1;
    while (SQLITE_DONE != sqlite3_step(stmt)) {
        status = 0;
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    return status;

  #else
    UNUSED(pconf);
    UNUSED(uri);
    return 1;
  #endif
}


static int
webdav_lock_delete_uri_col (const plugin_config * const pconf,
                            const buffer * const uri)
{
  #ifdef USE_LOCKS

    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_locks_delete_uri_col;
    if (!stmt)
        return 0;

  #ifdef __COVERITY__
    force_assert(0 != uri->used);
  #endif

    sqlite3_bind_int( stmt, 1, (int)uri->used-1);
    sqlite3_bind_text(stmt, 2, CONST_BUF_LEN(uri), SQLITE_STATIC);

    int status = 1;
    while (SQLITE_DONE != sqlite3_step(stmt)) {
        status = 0;
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    return status;

  #else
    UNUSED(pconf);
    UNUSED(uri);
    return 1;
  #endif
}


#ifdef USE_LOCKS
static int
webdav_lock_acquire (const plugin_config * const pconf,
                     const webdav_lockdata * const lockdata)
{
    /*
     * future:
     * only lockscope:"exclusive" and locktype:"write" currently supported,
     * so inserting strings into database is extraneous, and anyway should
     * be enums instead of strings, since there are limited supported values
     */

    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_locks_acquire;
    if (!stmt)
        return 0;

    sqlite3_bind_text(
      stmt, 1, CONST_BUF_LEN(&lockdata->locktoken),     SQLITE_STATIC);
    sqlite3_bind_text(
      stmt, 2, CONST_BUF_LEN(&lockdata->lockroot),      SQLITE_STATIC);
    sqlite3_bind_text(
      stmt, 3, CONST_BUF_LEN(lockdata->lockscope),      SQLITE_STATIC);
    sqlite3_bind_text(
      stmt, 4, CONST_BUF_LEN(lockdata->locktype),       SQLITE_STATIC);
    if (lockdata->owner->used)
        sqlite3_bind_text(
          stmt, 5, CONST_BUF_LEN(lockdata->owner),      SQLITE_STATIC);
    else
        sqlite3_bind_text(
          stmt, 5, CONST_STR_LEN(""),                   SQLITE_STATIC);
    if (lockdata->ownerinfo.used)
        sqlite3_bind_text(
          stmt, 6, CONST_BUF_LEN(&lockdata->ownerinfo), SQLITE_STATIC);
    else
        sqlite3_bind_text(
          stmt, 6, CONST_STR_LEN(""),                   SQLITE_STATIC);
    sqlite3_bind_int(
      stmt, 7, lockdata->depth);
    sqlite3_bind_int(
      stmt, 8, lockdata->timeout);

    int status = 1;
    if (SQLITE_DONE != sqlite3_step(stmt)) {
        status = 0;
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    return status;
}
#endif


#ifdef USE_LOCKS
static int
webdav_lock_refresh (const plugin_config * const pconf,
                     webdav_lockdata * const lockdata)
{
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_locks_refresh;
    if (!stmt)
        return 0;

    const buffer * const locktoken = &lockdata->locktoken;
    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(locktoken),  SQLITE_STATIC);
    sqlite3_bind_int( stmt, 2, lockdata->timeout);

    int status = 1;
    if (SQLITE_DONE != sqlite3_step(stmt)) {
        status = 0;
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    /*(future: fill in lockscope, locktype, depth from database)*/

    return status;
}
#endif


#ifdef USE_LOCKS
static int
webdav_lock_release (const plugin_config * const pconf,
                     const webdav_lockdata * const lockdata)
{
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_locks_release;
    if (!stmt)
        return 0;

    sqlite3_bind_text(
      stmt, 1, CONST_BUF_LEN(&lockdata->locktoken), SQLITE_STATIC);

    int status = 0;
    if (SQLITE_DONE == sqlite3_step(stmt))
        status = (0 != sqlite3_changes(pconf->sql->sqlh));
    else {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    return status;
}
#endif


static int
webdav_prop_move_uri (const plugin_config * const pconf,
                      const buffer * const src,
                      const buffer * const dst)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_move;
    if (!stmt)
        return 0;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(dst), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, CONST_BUF_LEN(src), SQLITE_STATIC);

    if (SQLITE_DONE != sqlite3_step(stmt)) {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

  #else
    UNUSED(pconf);
    UNUSED(src);
    UNUSED(dst);
  #endif

    return 0;
}


static int
webdav_prop_move_uri_col (const plugin_config * const pconf,
                          const buffer * const src,
                          const buffer * const dst)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_move_col;
    if (!stmt)
        return 0;

  #ifdef __COVERITY__
    force_assert(0 != src->used);
  #endif

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(dst), SQLITE_STATIC);
    sqlite3_bind_int( stmt, 2, (int)src->used);
    sqlite3_bind_int( stmt, 3, (int)src->used-1);
    sqlite3_bind_text(stmt, 4, CONST_BUF_LEN(src), SQLITE_STATIC);

    if (SQLITE_DONE != sqlite3_step(stmt)) {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

  #else
    UNUSED(pconf);
    UNUSED(src);
    UNUSED(dst);
  #endif

    return 0;
}


static int
webdav_prop_delete_uri (const plugin_config * const pconf,
                        const buffer * const uri)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_delete;
    if (!stmt)
        return 0;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri), SQLITE_STATIC);

    if (SQLITE_DONE != sqlite3_step(stmt)) {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

  #else
    UNUSED(pconf);
    UNUSED(uri);
  #endif

    return 0;
}


static int
webdav_prop_copy_uri (const plugin_config * const pconf,
                      const buffer * const src,
                      const buffer * const dst)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_copy;
    if (!stmt)
        return 0;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(dst), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, CONST_BUF_LEN(src), SQLITE_STATIC);

    if (SQLITE_DONE != sqlite3_step(stmt)) {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

  #else
    UNUSED(pconf);
    UNUSED(dst);
    UNUSED(src);
  #endif

    return 0;
}


#ifdef USE_PROPPATCH
static int
webdav_prop_delete (const plugin_config * const pconf,
                    const buffer * const uri,
                    const char * const prop_name,
                    const char * const prop_ns)
{
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_delete_prop;
    if (!stmt)
        return 0;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri),           SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, prop_name, strlen(prop_name), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, prop_ns,   strlen(prop_ns),   SQLITE_STATIC);

    if (SQLITE_DONE != sqlite3_step(stmt)) {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    return 0;
}
#endif


#ifdef USE_PROPPATCH
static int
webdav_prop_update (const plugin_config * const pconf,
                    const buffer * const uri,
                    const char * const prop_name,
                    const char * const prop_ns,
                    const char * const prop_value)
{
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_update_prop;
    if (!stmt)
        return 0;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri),             SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, prop_name,  strlen(prop_name),  SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, prop_ns,    strlen(prop_ns),    SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, prop_value, strlen(prop_value), SQLITE_STATIC);

    if (SQLITE_DONE != sqlite3_step(stmt)) {
      #if 0
        fprintf(stderr, "%s: %s\n", __func__, sqlite3_errmsg(pconf->sql->sqlh));
        log_error(pconf->errh, __FILE__, __LINE__,
                  "%s: %s", __func__, sqlite3_errmsg(pconf->sql->sqlh));
      #endif
    }

    sqlite3_reset(stmt);

    return 0;
}
#endif


static int
webdav_prop_select_prop (const plugin_config * const pconf,
                         const buffer * const uri,
                         const webdav_property_name * const prop,
                         buffer * const b)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return -1;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_select_prop;
    if (!stmt)
        return -1; /* not found */

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri),        SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, prop->name, prop->namelen, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, prop->ns,   prop->nslen,   SQLITE_STATIC);

    if (SQLITE_ROW == sqlite3_step(stmt)) {
        webdav_xml_prop(b, prop, (char *)sqlite3_column_text(stmt, 0),
                                 (uint32_t)sqlite3_column_bytes(stmt, 0));
        sqlite3_reset(stmt);
        return 0; /* found */
    }
    sqlite3_reset(stmt);
  #else
    UNUSED(pconf);
    UNUSED(uri);
    UNUSED(prop);
    UNUSED(b);
  #endif
    return -1; /* not found */
}


static void
webdav_prop_select_props (const plugin_config * const pconf,
                          const buffer * const uri,
                          buffer * const b)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_select_props;
    if (!stmt)
        return;

    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri), SQLITE_STATIC);

    while (SQLITE_ROW == sqlite3_step(stmt)) {
        webdav_property_name prop;
        prop.ns      = (char *)sqlite3_column_text(stmt, 1);
        prop.name    = (char *)sqlite3_column_text(stmt, 0);
        prop.nslen   = (uint32_t)sqlite3_column_bytes(stmt, 1);
        prop.namelen = (uint32_t)sqlite3_column_bytes(stmt, 0);
        webdav_xml_prop(b, &prop, (char *)sqlite3_column_text(stmt, 2),
                                  (uint32_t)sqlite3_column_bytes(stmt, 2));
    }

    sqlite3_reset(stmt);
  #else
    UNUSED(pconf);
    UNUSED(uri);
    UNUSED(b);
  #endif
}


static int
webdav_prop_select_propnames (const plugin_config * const pconf,
                              const buffer * const uri,
                              buffer * const b)
{
  #ifdef USE_PROPPATCH
    if (!pconf->sql)
        return 0;
    sqlite3_stmt * const stmt = pconf->sql->stmt_props_select_propnames;
    if (!stmt)
        return 0;

    /* get all property names (EMPTY) */
    sqlite3_bind_text(stmt, 1, CONST_BUF_LEN(uri), SQLITE_STATIC);

    while (SQLITE_ROW == sqlite3_step(stmt)) {
        webdav_property_name prop;
        prop.ns      = (char *)sqlite3_column_text(stmt, 1);
        prop.name    = (char *)sqlite3_column_text(stmt, 0);
        prop.nslen   = (uint32_t)sqlite3_column_bytes(stmt, 1);
        prop.namelen = (uint32_t)sqlite3_column_bytes(stmt, 0);
        webdav_xml_prop(b, &prop, NULL, 0);
    }

    sqlite3_reset(stmt);

  #else
    UNUSED(pconf);
    UNUSED(uri);
    UNUSED(b);
  #endif

    return 0;
}


#if defined(__APPLE__) && defined(__MACH__)
#include <copyfile.h>     /* fcopyfile() *//* OS X 10.5+ */
#endif
#ifdef HAVE_ELFTC_COPYFILE/* __FreeBSD__ */
#include <libelftc.h>     /* elftc_copyfile() */
#endif
#ifdef __linux__
#include <sys/sendfile.h> /* sendfile() */
#endif

/* file copy (blocking)
 * fds should point to regular files (S_ISREG()) (not dir, symlink, or other)
 * fds should not have O_NONBLOCK flag set
 *   (unless O_NONBLOCK not relevant for files on a given operating system)
 * isz should be size of input file, and is a param to avoid extra fstat()
 *   since size is needed for Linux sendfile(), as well as posix_fadvise().
 * caller should handler fchmod() and copying extended attribute, if desired
 */
__attribute_noinline__
static int
webdav_fcopyfile_sz (int ifd, int ofd, off_t isz)
{
    if (0 == isz)
        return 0;

  #ifdef _WIN32
    /* Windows CopyFile() not usable here; operates on filenames, not fds */
  #else
    /*(file descriptors to *regular files* on most OS ignore O_NONBLOCK)*/
    /*fcntl(ifd, F_SETFL, fcntl(ifd, F_GETFL, 0) & ~O_NONBLOCK);*/
    /*fcntl(ofd, F_SETFL, fcntl(ofd, F_GETFL, 0) & ~O_NONBLOCK);*/
  #endif

  #if defined(__APPLE__) && defined(__MACH__)
    if (0 == fcopyfile(ifd, ofd, NULL, COPYFILE_ALL))
        return 0;

    if (0 != lseek(ifd, 0, SEEK_SET)) return -1;
    if (0 != lseek(ofd, 0, SEEK_SET)) return -1;
  #endif

  #ifdef HAVE_ELFTC_COPYFILE /* __FreeBSD__ */
    if (0 == elftc_copyfile(ifd, ofd))
        return 0;

    if (0 != lseek(ifd, 0, SEEK_SET)) return -1;
    if (0 != lseek(ofd, 0, SEEK_SET)) return -1;
  #endif

  #ifdef __linux__ /* Linux 2.6.33+ sendfile() supports file-to-file copy */
    off_t offset = 0;
    while (offset < isz && sendfile(ifd,ofd,&offset,(size_t)(isz-offset)) >= 0);
    if (offset == isz)
        return 0;

    /*lseek(ifd, 0, SEEK_SET);*/ /*(ifd offset not modified due to &offset arg)*/
    if (0 != lseek(ofd, 0, SEEK_SET)) return -1;
  #endif

    ssize_t rd, wr, off;
    char buf[16384];
    do {
        do {
            rd = read(ifd, buf, sizeof(buf));
        } while (-1 == rd && errno == EINTR);
        if (rd < 0) return rd;

        off = 0;
        do {
            wr = write(ofd, buf+off, (size_t)(rd-off));
        } while (wr >= 0 ? (off += wr) != rd : errno == EINTR);
        if (wr < 0) return -1;
    } while (rd > 0);
    return rd;
}


static int
webdav_if_match_or_unmodified_since (connection * const con, struct stat *st)
{
    buffer *im = (0 != con->etag_flags)
      ? http_header_request_get(con, HTTP_HEADER_OTHER,
                                CONST_STR_LEN("If-Match"))
      : NULL;

    buffer *inm = (0 != con->etag_flags)
      ? http_header_request_get(con, HTTP_HEADER_IF_NONE_MATCH,
                                CONST_STR_LEN("If-None-Match"))
      : NULL;

    buffer *ius =
      http_header_request_get(con, HTTP_HEADER_OTHER,
                              CONST_STR_LEN("If-Unmodified-Since"));

    if (NULL == im && NULL == inm && NULL == ius) return 0;

    struct stat stp;
    if (NULL == st)
        st = (0 == lstat(con->physical.path->ptr, &stp)) ? &stp : NULL;

    buffer *etagb = con->physical.etag;
    if (NULL != st && (NULL != im || NULL != inm)) {
        etag_create(etagb, st, con->etag_flags);
        etag_mutate(etagb, etagb);
    }

    if (NULL != im) {
        if (NULL == st || !etag_is_equal(etagb, im->ptr, 0))
            return 412; /* Precondition Failed */
    }

    if (NULL != inm) {
        if (NULL == st
            ? !buffer_is_equal_string(inm,CONST_STR_LEN("*"))
              || (errno != ENOENT && errno != ENOTDIR)
            : etag_is_equal(etagb, inm->ptr, 1))
            return 412; /* Precondition Failed */
    }

    if (NULL != ius) {
        if (NULL == st)
            return 412; /* Precondition Failed */
        struct tm itm, *ftm = gmtime(&st->st_mtime);
        if (NULL == strptime(ius->ptr, "%a, %d %b %Y %H:%M:%S GMT", &itm)
            || mktime(ftm) > mktime(&itm)) { /* timegm() not standard */
            return 412; /* Precondition Failed */
        }
    }

    return 0;
}


static void
webdav_response_etag (const plugin_config * const pconf,
                      connection * const con, struct stat *st)
{
    server *srv = pconf->srv;
    if (0 != con->etag_flags) {
        buffer *etagb = con->physical.etag;
        etag_create(etagb, st, con->etag_flags);
        stat_cache_update_entry(srv,CONST_BUF_LEN(con->physical.path),st,etagb);
        etag_mutate(etagb, etagb);
        http_header_response_set(con, HTTP_HEADER_ETAG,
                                 CONST_STR_LEN("ETag"),
                                 CONST_BUF_LEN(etagb));
    }
    else {
        stat_cache_update_entry(srv,CONST_BUF_LEN(con->physical.path),st,NULL);
    }
}


static void
webdav_parent_modified (const plugin_config * const pconf, const buffer *path)
{
    size_t dirlen = buffer_string_length(path);
    const char *fn = path->ptr;
    /*force_assert(0 != dirlen);*/
    /*force_assert(fn[0] == '/');*/
    if (fn[dirlen-1] == '/') --dirlen;
    if (0 != dirlen) while (fn[--dirlen] != '/') ;
    if (0 == dirlen) dirlen = 1; /* root dir ("/") */
    stat_cache_invalidate_entry(pconf->srv, fn, dirlen);
}


static int
webdav_parse_Depth (connection * const con)
{
    /* Depth = "Depth" ":" ("0" | "1" | "infinity") */
    const buffer * const h =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Depth"));
    if (NULL != h) {
        /* (leading LWS is removed during header parsing in request.c) */
        switch (*h->ptr) {
          case  '0': return 0;
          case  '1': return 1;
          /*case 'i':*/ /* e.g. "infinity" */
          /*case 'I':*/ /* e.g. "Infinity" */
          default:   return -1;/* treat not-'0' and not-'1' as "infinity" */
        }
    }

    return -1; /* default value is -1 to represent "infinity" */
}


static int
webdav_unlinkat (const plugin_config * const pconf, const buffer * const uri,
                 const int dfd, const char * const d_name, size_t len)
{
    if (0 == unlinkat(dfd, d_name, 0)) {
        stat_cache_delete_entry(pconf->srv, d_name, len);
        return webdav_prop_delete_uri(pconf, uri);
    }

    switch(errno) {
      case EACCES: case EPERM: return 403; /* Forbidden */
      case ENOENT:             return 404; /* Not Found */
      default:                 return 501; /* Not Implemented */
    }
}


static int
webdav_delete_file (const plugin_config * const pconf,
                    const physical_st * const dst)
{
    if (0 == unlink(dst->path->ptr)) {
        stat_cache_delete_entry(pconf->srv, CONST_BUF_LEN(dst->path));
        return webdav_prop_delete_uri(pconf, dst->rel_path);
    }

    switch(errno) {
      case EACCES: case EPERM: return 403; /* Forbidden */
      case ENOENT:             return 404; /* Not Found */
      default:                 return 501; /* Not Implemented */
    }
}


static int
webdav_delete_dir (const plugin_config * const pconf,
                   physical_st * const dst,
                   buffer * const b,
                   const int flags)
{
    int multi_status = 0;
    const int dfd = fdevent_open_dirname(dst->path->ptr, 0);
    DIR * const dir = (dfd >= 0) ? fdopendir(dfd) : NULL;
    if (NULL == dir) {
        if (dfd >= 0) close(dfd);
        webdav_xml_response_status(b, dst->rel_path, 403);
        return 1;
    }

    /* dst is modified in place to extend path,
     * so be sure to restore to base each loop iter */
    const uint32_t dst_path_used     = dst->path->used;
    const uint32_t dst_rel_path_used = dst->rel_path->used;
    int s_isdir;
    struct dirent *de;
    while (NULL != (de = readdir(dir))) {
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue; /* ignore "." and ".." */

      #ifdef _DIRENT_HAVE_D_TYPE
        if (de->d_type != DT_UNKNOWN)
            s_isdir = (de->d_type == DT_DIR);
        else
      #endif
        {
            struct stat st;
            if (0 != fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
                continue; /* file *just* disappeared? */
                /* parent rmdir() will fail later if file still exists
                 * and fstatat() failed for other reasons */
            s_isdir = S_ISDIR(st.st_mode);
        }

        const uint32_t len = (uint32_t) _D_EXACT_NAMLEN(de);
        if (flags & WEBDAV_FLAG_LC_NAMES) /*(needed at least for rel_path)*/
            webdav_str_len_to_lower(de->d_name, len);
        buffer_append_string_len(dst->path, de->d_name, len);
        buffer_append_string_len(dst->rel_path, de->d_name, len);

        if (s_isdir) {
            buffer_append_string_len(dst->path, CONST_STR_LEN("/"));
            buffer_append_string_len(dst->rel_path, CONST_STR_LEN("/"));
            multi_status |= webdav_delete_dir(pconf, dst, b, flags);
        }
        else {
            int status =
              webdav_unlinkat(pconf, dst->rel_path, dfd, de->d_name, len);
            if (0 != status) {
                webdav_xml_response_status(b, dst->rel_path, status);
                multi_status = 1;
            }
        }

        dst->path->ptr[    (dst->path->used     = dst_path_used)    -1] = '\0';
        dst->rel_path->ptr[(dst->rel_path->used = dst_rel_path_used)-1] = '\0';
    }
    closedir(dir);

    if (0 == multi_status) {
        int rmdir_status;
        if (0 == rmdir(dst->path->ptr))
            rmdir_status = webdav_prop_delete_uri(pconf, dst->rel_path);
        else {
            switch(errno) {
              case EACCES:
              case EPERM:  rmdir_status = 403; break; /* Forbidden */
              case ENOENT: rmdir_status = 404; break; /* Not Found */
              default:     rmdir_status = 501; break; /* Not Implemented */
            }
        }
        if (0 != rmdir_status) {
            webdav_xml_response_status(b, dst->rel_path, rmdir_status);
            multi_status = 1;
        }
    }

    return multi_status;
}


static int
webdav_linktmp_rename (const plugin_config * const pconf,
                       const buffer * const src,
                       const buffer * const dst)
{
    buffer * const tmpb = pconf->tmpb;
    int rc = -1; /*(not zero)*/

    buffer_copy_buffer(tmpb, dst);
    buffer_append_string_len(tmpb, CONST_STR_LEN("."));
    buffer_append_int(tmpb, (long)getpid());
    buffer_append_string_len(tmpb, CONST_STR_LEN("."));
    buffer_append_uint_hex_lc(tmpb, (uintptr_t)pconf); /*(stack/heap addr)*/
    buffer_append_string_len(tmpb, CONST_STR_LEN("~"));
    if (buffer_string_length(tmpb) < PATH_MAX
        && 0 == linkat(AT_FDCWD, src->ptr, AT_FDCWD, tmpb->ptr, 0)) {

        rc = rename(tmpb->ptr, dst->ptr);

        /* unconditionally unlink() src if rename() succeeds, just in case
         * dst previously existed and was already hard-linked to src.  From
         * 'man -s 2 rename':
         *   If oldpath and newpath are existing hard links referring to the
         *   same file, then rename() does nothing, and returns a success
         *   status.
         * This introduces a small race condition between the rename() and
         * unlink() should new file have been created at src in the middle,
         * though unlikely if locks are used since locks have not yet been
         * released. */
        unlink(tmpb->ptr);
    }
    return rc;
}


static int
webdav_copytmp_rename (const plugin_config * const pconf,
                       const physical_st * const src,
                       const physical_st * const dst,
                       const int overwrite)
{
    buffer * const tmpb = pconf->tmpb;
    buffer_copy_buffer(tmpb, dst->path);
    buffer_append_string_len(tmpb, CONST_STR_LEN("."));
    buffer_append_int(tmpb, (long)getpid());
    buffer_append_string_len(tmpb, CONST_STR_LEN("."));
    buffer_append_uint_hex_lc(tmpb, (uintptr_t)pconf); /*(stack/heap addr)*/
    buffer_append_string_len(tmpb, CONST_STR_LEN("~"));
    if (buffer_string_length(tmpb) >= PATH_MAX)
        return 414; /* URI Too Long */

    /* code does not currently support symlinks in webdav collections;
     * disallow symlinks as target when opening src and dst */
    struct stat st;
    const int ifd = fdevent_open_cloexec(src->path->ptr, 0, O_RDONLY, 0);
    if (ifd < 0)
        return 403; /* Forbidden */
    if (0 != fstat(ifd, &st) || !S_ISREG(st.st_mode)) {
        close(ifd);
        return 403; /* Forbidden */
    }
    const int ofd = fdevent_open_cloexec(tmpb->ptr, 0,
                                         O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
                                         WEBDAV_FILE_MODE);
    if (ofd < 0) {
        close(ifd);
        return 403; /* Forbidden */
    }

    /* perform *blocking* copy (not O_NONBLOCK);
     * blocks server from doing any other work until after copy completes
     * (should reach here only if unable to use link() and rename()
     *  due to copy/move crossing device boundaries within the workspace) */
    int rc = webdav_fcopyfile_sz(ifd, ofd, st.st_size);

    close(ifd);
    const int wc = close(ofd);

    if (0 != rc || 0 != wc) {
        /* error reading or writing files */
        rc = (0 != wc && wc == ENOSPC) ? 507 : 403;
        unlink(tmpb->ptr);
        return rc;
    }

  #ifndef RENAME_NOREPLACE /*(renameat2() not well-supported yet)*/
    if (!overwrite) {
        struct stat stb;
        if (0 == lstat(dst->path->ptr, &stb) || errno != ENOENT)
            return 412; /* Precondition Failed */
        /* TOC-TOU race between lstat() and rename(),
         * but this is reasonable attempt to not overwrite existing entity */
    }
    if (0 == rename(tmpb->ptr, dst->path->ptr))
  #else
    if (0 == renameat2(AT_FDCWD, tmpb->ptr,
                       AT_FDCWD, dst->path->ptr,
                       overwrite ? 0 : RENAME_NOREPLACE))
  #endif
    {
        /* unconditional stat cache deletion
         * (not worth extra syscall/race to detect overwritten or not) */
        stat_cache_delete_entry(pconf->srv, CONST_BUF_LEN(dst->path));
        return 0;
    }
    else {
        const int errnum = errno;
        unlink(tmpb->ptr);
        switch (errnum) {
          case ENOENT:
          case ENOTDIR:
          case EISDIR: return 409; /* Conflict */
          case EEXIST: return 412; /* Precondition Failed */
          default:     return 403; /* Forbidden */
        }
    }
}


static int
webdav_copymove_file (const plugin_config * const pconf,
                      const physical_st * const src,
                      const physical_st * const dst,
                      int * const flags)
{
    const int overwrite = (*flags & WEBDAV_FLAG_OVERWRITE);
    if (*flags & WEBDAV_FLAG_MOVE_RENAME) {
      #ifndef RENAME_NOREPLACE /*(renameat2() not well-supported yet)*/
        if (!overwrite) {
            struct stat st;
            if (0 == lstat(dst->path->ptr, &st) || errno != ENOENT)
                return 412; /* Precondition Failed */
            /* TOC-TOU race between lstat() and rename(),
             * but this is reasonable attempt to not overwrite existing entity*/
        }
        if (0 == rename(src->path->ptr, dst->path->ptr))
      #else
        if (0 == renameat2(AT_FDCWD, src->path->ptr,
                           AT_FDCWD, dst->path->ptr,
                           overwrite ? 0 : RENAME_NOREPLACE))
      #endif
        {
            /* unconditionally unlink() src if rename() succeeds, just in case
             * dst previously existed and was already hard-linked to src.  From
             * 'man -s 2 rename':
             *   If oldpath and newpath are existing hard links referring to the
             *   same file, then rename() does nothing, and returns a success
             *   status.
             * This introduces a small race condition between the rename() and
             * unlink() should new file have been created at src in the middle,
             * though unlikely if locks are used since locks have not yet been
             * released. */
            if (overwrite) unlink(src->path->ptr);
            /* unconditional stat cache deletion
             * (not worth extra syscall/race to detect overwritten or not) */
            stat_cache_delete_entry(pconf->srv, CONST_BUF_LEN(dst->path));
            stat_cache_delete_entry(pconf->srv, CONST_BUF_LEN(src->path));
            webdav_prop_move_uri(pconf, src->rel_path, dst->rel_path);
            return 0;
        }
        else if (errno == EEXIST)
            return 412; /* Precondition Failed */
    }
    else if (*flags & WEBDAV_FLAG_COPY_LINK) {
        if (0 == linkat(AT_FDCWD, src->path->ptr, AT_FDCWD, dst->path->ptr, 0)){
            webdav_prop_copy_uri(pconf, src->rel_path, dst->rel_path);
            return 0;
        }
        else if (errno == EEXIST) {
            if (!overwrite)
                return 412; /* Precondition Failed */
            if (0 == webdav_linktmp_rename(pconf, src->path, dst->path)) {
                webdav_prop_copy_uri(pconf, src->rel_path, dst->rel_path);
                return 0;
            }
        }
        else if (errno == EXDEV) {
            *flags &= ~WEBDAV_FLAG_COPY_LINK;
            *flags |= WEBDAV_FLAG_COPY_XDEV;
        }
    }

    /* link() or rename() failed; fall back to copy to tempfile and rename() */
    int status = webdav_copytmp_rename(pconf, src, dst, overwrite);
    if (0 == status) {
        webdav_prop_copy_uri(pconf, src->rel_path, dst->rel_path);
        if (*flags & (WEBDAV_FLAG_MOVE_RENAME|WEBDAV_FLAG_MOVE_XDEV))
            webdav_delete_file(pconf, src);
            /*(copy successful, but how should we report if delete fails?)*/
    }
    return status;
}


static int
webdav_mkdir (const plugin_config * const pconf,
              const physical_st * const dst,
              const int overwrite)
{
    if (0 == mkdir(dst->path->ptr, WEBDAV_DIR_MODE)) {
        webdav_parent_modified(pconf, dst->path);
        return 0;
    }

    switch (errno) {
      case EEXIST:
      case ENOTDIR: break;
      case ENOENT:  return 409; /* Conflict */
      case EPERM:
      default:      return 403; /* Forbidden */
    }

    /* [RFC4918] 9.3.1 MKCOL Status Codes
     *   405 (Method Not Allowed) -
     *     MKCOL can only be executed on an unmapped URL.
     */
    if (overwrite < 0)  /*(mod_webdav_mkcol() passes overwrite = -1)*/
        return (errno != ENOTDIR)
          ? 405  /* Method Not Allowed */
          : 409; /* Conflict */

  #ifdef __COVERITY__
    force_assert(2 <= dst->path->used);
    force_assert(2 <= dst->rel_path->used);
  #endif

    struct stat st;
    int status;
    dst->path->ptr[dst->path->used-2] = '\0'; /*(trailing slash)*/
    status = lstat(dst->path->ptr, &st);
    dst->path->ptr[dst->path->used-2] = '/';  /*(restore slash)*/
    if (0 != status) /* still ENOTDIR or *just* disappeared */
        return 409; /* Conflict */

    if (!overwrite) /* copying into a non-dir ? */
        return 409; /* Conflict */

    if (S_ISDIR(st.st_mode))
        return 0;

    dst->path->ptr[dst->path->used-2] = '\0'; /*(trailing slash)*/
    dst->rel_path->ptr[dst->rel_path->used-2] = '\0';
    status = webdav_delete_file(pconf, dst);
    dst->path->ptr[dst->path->used-2] = '/';  /*(restore slash)*/
    dst->rel_path->ptr[dst->rel_path->used-2] = '/';
    if (0 != status)
        return status;

    webdav_parent_modified(pconf, dst->path);
    return (0 == mkdir(dst->path->ptr, WEBDAV_DIR_MODE))
      ? 0
      : 409; /* Conflict */
}


static int
webdav_copymove_dir (const plugin_config * const pconf,
                     physical_st * const src,
                     physical_st * const dst,
                     buffer * const b,
                     int flags)
{
    /* NOTE: merging collections is NON-CONFORMANT behavior
     *       (specified in [RFC4918])
     *
     * However, merging collections during COPY/MOVE might be expected behavior
     * by client, as merging is the behavior of unix cp -r (recursive copy) as
     * well as how Microsoft Windows Explorer performs folder copies.
     *
     * [RFC4918] 9.8.4 COPY and Overwriting Destination Resources
     *   When a collection is overwritten, the membership of the destination
     *   collection after the successful COPY request MUST be the same
     *   membership as the source collection immediately before the COPY. Thus,
     *   merging the membership of the source and destination collections
     *   together in the destination is not a compliant behavior.
     * [Ed: strange how non-compliance statement is immediately followed by:]
     *   In general, if clients require the state of the destination URL to be
     *   wiped out prior to a COPY (e.g., to force live properties to be reset),
     *   then the client could send a DELETE to the destination before the COPY
     *   request to ensure this reset.
     * [Ed: if non-compliant merge behavior is the default here, and were it to
     *  not be desired by client, client could send a DELETE to the destination
     *  before issuing COPY.  There is no easy way to obtain merge behavior
     *  (were it not the non-compliant default here) unless the client recurses
     *  into the source and destination, and creates a list of objects that need
     *  to be copied.  This could fail or miss files due to racing with other
     *  clients.  All of this might forget to emphasize that wiping out an
     *  existing destination collection (a recursive operation) is dangerous and
     *  would happen if the client set Overwrite: T or omitted setting Overwrite
     *  since Overwrite: T is default (client must explicitly set Overwrite: F)]
     * [RFC4918] 9.9.3 MOVE and the Overwrite Header
     *   If a resource exists at the destination and the Overwrite header is
     *   "T", then prior to performing the move, the server MUST perform a
     *   DELETE with "Depth: infinity" on the destination resource. If the
     *   Overwrite header is set to "F", then the operation will fail.
     */

    /* NOTE: aborting if 507 Insufficient Storage is NON-CONFORMANT behavior
     *       [RFC4918] specifies that as much as possible of COPY or MOVE
     *       should be completed.
     */

    /* ??? upon encountering errors, should src->rel_path or dst->rel_path
     *     be used in XML error ??? */

    struct stat st;
    int status;
    int dfd;

    int make_destdir = 1;
    const int overwrite = (flags & WEBDAV_FLAG_OVERWRITE);
    if (flags & WEBDAV_FLAG_MOVE_RENAME) {
      #ifndef RENAME_NOREPLACE /*(renameat2() not well-supported yet)*/
        if (!overwrite) {
            if (0 == lstat(dst->path->ptr, &st) || errno != ENOENT) {
                webdav_xml_response_status(b, src->rel_path, 412);
                return 412; /* Precondition Failed */
            }
            /* TOC-TOU race between lstat() and rename(),
             * but this is reasonable attempt to not overwrite existing entity*/
        }
        if (0 == rename(src->path->ptr, dst->path->ptr))
      #else
        if (0 == renameat2(AT_FDCWD, src->path->ptr,
                           AT_FDCWD, dst->path->ptr,
                           overwrite ? 0 : RENAME_NOREPLACE))
      #endif
        {
            webdav_prop_move_uri_col(pconf, src->rel_path, dst->rel_path);
            return 0;
        }
        else {
            switch (errno) {
              case EEXIST:
              case ENOTEMPTY:
                if (!overwrite) {
                        webdav_xml_response_status(b, src->rel_path, 412);
                        return 412; /* Precondition Failed */
                }
                make_destdir = 0;
                break;
              case ENOTDIR:
                if (!overwrite) {
                        webdav_xml_response_status(b, src->rel_path, 409);
                        return 409; /* Conflict */
                }

              #ifdef __COVERITY__
                force_assert(2 <= dst->path->used);
              #endif

                dst->path->ptr[dst->path->used-2] = '\0'; /*(trailing slash)*/
                status = lstat(dst->path->ptr, &st);
                dst->path->ptr[dst->path->used-2] = '/';  /*(restore slash)*/
                if (0 == status) {
                    if (S_ISDIR(st.st_mode)) {
                        make_destdir = 0;
                        break;
                    }

                  #ifdef __COVERITY__
                    force_assert(2 <= dst->rel_path->used);
                  #endif

                    dst->path->ptr[dst->path->used-2] = '\0'; /*(remove slash)*/
                    dst->rel_path->ptr[dst->rel_path->used-2] = '\0';
                    status = webdav_delete_file(pconf, dst);
                    dst->path->ptr[dst->path->used-2] = '/'; /*(restore slash)*/
                    dst->rel_path->ptr[dst->rel_path->used-2] = '/';
                    if (0 != status) {
                        webdav_xml_response_status(b, src->rel_path, status);
                        return status;
                    }

                    if (0 == rename(src->path->ptr, dst->path->ptr)) {
                        webdav_prop_move_uri_col(pconf, src->rel_path,
                                                        dst->rel_path);
                        return 0;
                    }
                }
                break;
              case EXDEV:
                flags &= ~WEBDAV_FLAG_MOVE_RENAME;
                flags |= WEBDAV_FLAG_MOVE_XDEV;
                /* (if overwrite, then could switch to WEBDAV_FLAG_COPY_XDEV
                 *  and set a flag so that before returning from this routine,
                 *  directory is deleted recursively, instead of deleting each
                 *  file after each copy.  Only reliable if overwrite is set
                 *  since if it is not set, an error would leave file copies in
                 *  two places and would be difficult to recover if !overwrite)
                 * (collections typically do not cross devices, so this is not
                 *  expected to be a common case) */
                break;
              default:
                break;
            }
        }
    }

    if (make_destdir) {
        if (0 != (status = webdav_mkdir(pconf, dst, overwrite))) {
            webdav_xml_response_status(b, src->rel_path, status);
            return status;
        }
    }

    webdav_prop_copy_uri(pconf, src->rel_path, dst->rel_path);

    /* copy from src to dst (and, if move, then delete src)
     * src and dst are modified in place to extend path,
     * so be sure to restore to base each loop iter */

    const uint32_t src_path_used     = src->path->used;
    const uint32_t src_rel_path_used = src->rel_path->used;
    const uint32_t dst_path_used     = dst->path->used;
    const uint32_t dst_rel_path_used = dst->rel_path->used;

    dfd = fdevent_open_dirname(src->path->ptr, 0);
    DIR * const srcdir = (dfd >= 0) ? fdopendir(dfd) : NULL;
    if (NULL == srcdir) {
        if (dfd >= 0) close(dfd);
        webdav_xml_response_status(b, src->rel_path, 403);
        return 403; /* Forbidden */
    }
    mode_t d_type;
    int multi_status = 0;
    struct dirent *de;
    while (NULL != (de = readdir(srcdir))) {
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue; /* ignore "." and ".." */

      #ifdef _DIRENT_HAVE_D_TYPE
        if (de->d_type != DT_UNKNOWN)
            d_type = DTTOIF(de->d_type);
        else
      #endif
        {
            if (0 != fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW))
                continue; /* file *just* disappeared? */
            d_type = st.st_mode;
        }

        const uint32_t len = (uint32_t) _D_EXACT_NAMLEN(de);
        if (flags & WEBDAV_FLAG_LC_NAMES) /*(needed at least for rel_path)*/
            webdav_str_len_to_lower(de->d_name, len);

        buffer_append_string_len(src->path,     de->d_name, len);
        buffer_append_string_len(dst->path,     de->d_name, len);
        buffer_append_string_len(src->rel_path, de->d_name, len);
        buffer_append_string_len(dst->rel_path, de->d_name, len);

        if (S_ISDIR(d_type)) { /* recursive call; depth first */
            buffer_append_string_len(src->path,     CONST_STR_LEN("/"));
            buffer_append_string_len(dst->path,     CONST_STR_LEN("/"));
            buffer_append_string_len(src->rel_path, CONST_STR_LEN("/"));
            buffer_append_string_len(dst->rel_path, CONST_STR_LEN("/"));
            status = webdav_copymove_dir(pconf, src, dst, b, flags);
            if (0 != status)
               multi_status = 1;
        }
        else if (S_ISREG(d_type)) {
            status = webdav_copymove_file(pconf, src, dst, &flags);
            if (0 != status)
                webdav_xml_response_status(b, src->rel_path, status);
        }
      #if 0
        else if (S_ISLNK(d_type)) {
            /*(might entertain support in future, including readlink()
             * and changing dst symlink to be relative to new location.
             * (or, if absolute to the old location, then absolute to new)
             * Be sure to hard-link using linkat() w/o AT_SYMLINK_FOLLOW)*/
        }
      #endif
        else {
            status = 0;
        }

        src->path->ptr[    (src->path->used     = src_path_used)    -1] = '\0';
        src->rel_path->ptr[(src->rel_path->used = src_rel_path_used)-1] = '\0';
        dst->path->ptr[    (dst->path->used     = dst_path_used)    -1] = '\0';
        dst->rel_path->ptr[(dst->rel_path->used = dst_rel_path_used)-1] = '\0';

        if (507 == status) {
            multi_status = 507; /* Insufficient Storage */
            break;
        }
    }
    closedir(srcdir);

    if (0 == multi_status) {
        if (flags & (WEBDAV_FLAG_MOVE_RENAME|WEBDAV_FLAG_MOVE_XDEV)) {
            status = webdav_delete_dir(pconf, src, b, flags); /* content */
            if (0 != status) {
                webdav_xml_response_status(b, src->rel_path, status);
                multi_status = 1;
            }
        }
    }

    return multi_status;
}


typedef struct webdav_propfind_bufs {
  connection * restrict con;
  const plugin_config * restrict pconf;
  physical_st * restrict dst;
  buffer * restrict b;
  buffer * restrict b_200;
  buffer * restrict b_404;
  webdav_property_names proplist;
  int allprop;
  int propname;
  int lockdiscovery;
  int depth;
  struct stat st;
} webdav_propfind_bufs;


enum webdav_live_props_e {
  WEBDAV_PROP_UNSET = -1             /* (enum value to avoid compiler warning)*/
 ,WEBDAV_PROP_ALL = 0                /* (ALL not really a prop; internal use) */
 /*,WEBDAV_PROP_CREATIONDATE*/       /* (located in database, if present) */
 /*,WEBDAV_PROP_DISPLAYNAME*/        /* (located in database, if present) */
 /*,WEBDAV_PROP_GETCONTENTLANGUAGE*/ /* (located in database, if present) */
 ,WEBDAV_PROP_GETCONTENTLENGTH
 ,WEBDAV_PROP_GETCONTENTTYPE
 ,WEBDAV_PROP_GETETAG
 ,WEBDAV_PROP_GETLASTMODIFIED
 /*,WEBDAV_PROP_LOCKDISCOVERY*/      /* (located in database, if present) */
 ,WEBDAV_PROP_RESOURCETYPE
 /*,WEBDAV_PROP_SOURCE*/             /* not implemented; removed in RFC4918 */
 ,WEBDAV_PROP_SUPPORTEDLOCK
};


#ifdef USE_PROPPATCH

struct live_prop_list {
  const char *prop;
  const uint32_t len;
  enum webdav_live_props_e pnum;
};

static const struct live_prop_list live_properties[] = { /*(namespace "DAV:")*/
 /* { CONST_STR_LEN("creationdate"),       WEBDAV_PROP_CREATIONDATE }*/
 /*,{ CONST_STR_LEN("displayname"),        WEBDAV_PROP_DISPLAYNAME }*/
 /*,{ CONST_STR_LEN("getcontentlanguage"), WEBDAV_PROP_GETCONTENTLANGUAGE}*/
  { CONST_STR_LEN("getcontentlength"),     WEBDAV_PROP_GETCONTENTLENGTH }
 ,{ CONST_STR_LEN("getcontenttype"),       WEBDAV_PROP_GETCONTENTTYPE }
 ,{ CONST_STR_LEN("getetag"),              WEBDAV_PROP_GETETAG }
 ,{ CONST_STR_LEN("getlastmodified"),      WEBDAV_PROP_GETLASTMODIFIED }
 #ifdef USE_LOCKS
 /*,{ CONST_STR_LEN("lockdiscovery"),      WEBDAV_PROP_LOCKDISCOVERY }*/
 #endif
 ,{ CONST_STR_LEN("resourcetype"),         WEBDAV_PROP_RESOURCETYPE }
 /*,{ CONST_STR_LEN("source"),             WEBDAV_PROP_SOURCE }*/
 #ifdef USE_LOCKS
 ,{ CONST_STR_LEN("supportedlock"),        WEBDAV_PROP_SUPPORTEDLOCK }
 #endif

 ,{ NULL, 0, WEBDAV_PROP_UNSET }
};

/* protected live properties
 * (must also protect creationdate and lockdiscovery in database) */
static const struct live_prop_list protected_props[] = { /*(namespace "DAV:")*/
  { CONST_STR_LEN("creationdate"),         WEBDAV_PROP_UNSET
                                             /*WEBDAV_PROP_CREATIONDATE*/ }
 /*,{ CONST_STR_LEN("displayname"),        WEBDAV_PROP_DISPLAYNAME }*/
 /*,{ CONST_STR_LEN("getcontentlanguage"), WEBDAV_PROP_GETCONTENTLANGUAGE}*/
 ,{ CONST_STR_LEN("getcontentlength"),     WEBDAV_PROP_GETCONTENTLENGTH }
 ,{ CONST_STR_LEN("getcontenttype"),       WEBDAV_PROP_GETCONTENTTYPE }
 ,{ CONST_STR_LEN("getetag"),              WEBDAV_PROP_GETETAG }
 ,{ CONST_STR_LEN("getlastmodified"),      WEBDAV_PROP_GETLASTMODIFIED }
 ,{ CONST_STR_LEN("lockdiscovery"),        WEBDAV_PROP_UNSET
                                             /*WEBDAV_PROP_LOCKDISCOVERY*/ }
 ,{ CONST_STR_LEN("resourcetype"),         WEBDAV_PROP_RESOURCETYPE }
 /*,{ CONST_STR_LEN("source"),             WEBDAV_PROP_SOURCE }*/
 ,{ CONST_STR_LEN("supportedlock"),        WEBDAV_PROP_SUPPORTEDLOCK }

 ,{ NULL, 0, WEBDAV_PROP_UNSET }
};

#endif


static int
webdav_propfind_live_props (const webdav_propfind_bufs * const restrict pb,
                           const enum webdav_live_props_e pnum)
{
    buffer * const restrict b = pb->b_200;
    switch (pnum) {
      case WEBDAV_PROP_ALL:
        /*(fall through)*/
      /*case WEBDAV_PROP_CREATIONDATE:*/  /* (located in database, if present)*/
      #if 0
      case WEBDAV_PROP_CREATIONDATE: {
        /* st->st_ctim
         * defined by POSIX.1-2008 as last file status change timestamp
         * and is no long create-time (as it may have been on older filesystems)
         * Therefore, this should return Not Found.
         * [RFC4918] 15.1 creationdate Property
         *   The DAV:creationdate property SHOULD be defined on all DAV
         *   compliant resources. If present, it contains a timestamp of the
         *   moment when the resource was created. Servers that are incapable
         *   of persistently recording the creation date SHOULD instead leave
         *   it undefined (i.e. report "Not Found").
         * (future: might store creationdate in database when PUT creates file
         *  or LOCK creates empty file, or MKCOL creates collection (dir),
         *  i.e. wherever the status is 201 Created)
         */
        struct tm tm;
        char ctime_buf[sizeof("2005-08-18T07:27:16Z")];
        if (__builtin_expect( (NULL != gmtime_r(&pb->st.st_ctime, &tm)), 1)) {
            buffer_append_string_len(b, CONST_STR_LEN(
              "<D:creationdate ns0:dt=\"dateTime.tz\">"));
            buffer_append_string_len(b, ctime_buf,
                                     strftime(ctime_buf, sizeof(ctime_buf),
                                              "%Y-%m-%dT%TZ", &tm));
            buffer_append_string_len(b, CONST_STR_LEN(
              "</D:creationdate>"));
        }
        else if (pnum != WEBDAV_PROP_ALL)
            return -1; /* invalid; report 'not found' */
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      }
      #endif
      /*case WEBDAV_PROP_DISPLAYNAME:*/   /* (located in database, if present)*/
      /*case WEBDAV_PROP_GETCONTENTLANGUAGE:*/  /* (located in db, if present)*/
      #if 0
      case WEBDAV_PROP_GETCONTENTLANGUAGE:
        /* [RFC4918] 15.3 getcontentlanguage Property
         *   SHOULD NOT be protected, so that clients can reset the language.
         *   [...]
         *   The DAV:getcontentlanguage property MUST be defined on any
         *   DAV-compliant resource that returns the Content-Language header on
         *   a GET.
         * (future: server does not currently set Content-Language and this
         *  module would need to somehow find out if another module set it)
         */
        buffer_append_string_len(b, CONST_STR_LEN(
          "<D:getcontentlanguage>en</D:getcontentlanguage>"));
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      #endif
      case WEBDAV_PROP_GETCONTENTLENGTH:
        buffer_append_string_len(b, CONST_STR_LEN(
          "<D:getcontentlength>"));
        buffer_append_int(b, pb->st.st_size);
        buffer_append_string_len(b, CONST_STR_LEN(
          "</D:getcontentlength>"));
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      case WEBDAV_PROP_GETCONTENTTYPE:
        /* [RFC4918] 15.5 getcontenttype Property
         *   Potentially protected if the server prefers to assign content types
         *   on its own (see also discussion in Section 9.7.1).
         * (server currently assigns content types)
         *
         * [RFC4918] 15 DAV Properties
         *   For properties defined based on HTTP GET response headers
         *   (DAV:get*), the header value could include LWS as defined
         *   in [RFC2616], Section 4.2. Server implementors SHOULD strip
         *   LWS from these values before using as WebDAV property
         *   values.
         * e.g. application/xml;charset="utf-8"
         *      instead of: application/xml; charset="utf-8"
         * (documentation-only; no check is done here to remove LWS)
         */
        if (S_ISDIR(pb->st.st_mode)) {
            buffer_append_string_len(b, CONST_STR_LEN(
              "<D:getcontenttype>httpd/unix-directory</D:getcontenttype>"));
        }
        else {
            /* provide content type by extension
             * Note: not currently supporting filesystem xattr */
            const buffer *ct =
              stat_cache_mimetype_by_ext(pb->con, CONST_BUF_LEN(pb->dst->path));
            if (NULL != ct) {
                buffer_append_string_len(b, CONST_STR_LEN(
                  "<D:getcontenttype>"));
                buffer_append_string_buffer(b, ct);
                buffer_append_string_len(b, CONST_STR_LEN(
                  "</D:getcontenttype>"));
            }
            else {
                if (pnum != WEBDAV_PROP_ALL)
                    return -1; /* invalid; report 'not found' */
            }
        }
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      case WEBDAV_PROP_GETETAG:
        if (0 != pb->con->etag_flags) {
            buffer *etagb = pb->con->physical.etag;
            etag_create(etagb, &pb->st, pb->con->etag_flags);
            etag_mutate(etagb, etagb);
            buffer_append_string_len(b, CONST_STR_LEN(
              "<D:getetag>"));
            buffer_append_string_buffer(b, etagb);
            buffer_append_string_len(b, CONST_STR_LEN(
              "</D:getetag>"));
            buffer_clear(etagb);
        }
        else if (pnum != WEBDAV_PROP_ALL)
            return -1; /* invalid; report 'not found' */
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      case WEBDAV_PROP_GETLASTMODIFIED:
        {
            buffer_append_string_len(b, CONST_STR_LEN(
              "<D:getlastmodified ns0:dt=\"dateTime.rfc1123\">"));
            buffer_append_strftime(b, "%a, %d %b %Y %H:%M:%S GMT",
                                   gmtime(&pb->st.st_mtime));
            buffer_append_string_len(b, CONST_STR_LEN(
              "</D:getlastmodified>"));
        }
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      #if 0
      #ifdef USE_LOCKS
      case WEBDAV_PROP_LOCKDISCOVERY:
        /* database query for locks occurs in webdav_propfind_resource_props()*/
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      #endif
      #endif
      case WEBDAV_PROP_RESOURCETYPE:
        if (S_ISDIR(pb->st.st_mode))
            buffer_append_string_len(b, CONST_STR_LEN(
              "<D:resourcetype><D:collection/></D:resourcetype>"));
        else
            buffer_append_string_len(b, CONST_STR_LEN(
              "<D:resourcetype/>"));
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      /*case WEBDAV_PROP_SOURCE:*/        /* not impl; removed in RFC4918 */
      #ifdef USE_LOCKS
      case WEBDAV_PROP_SUPPORTEDLOCK:
        buffer_append_string_len(b, CONST_STR_LEN(
              "<D:supportedlock>"
              "<D:lockentry>"
              "<D:lockscope><D:exclusive/></D:lockscope>"
              "<D:locktype><D:write/></D:locktype>"
              "</D:lockentry>"
              "<D:lockentry>"
              "<D:lockscope><D:shared/></D:lockscope>"
              "<D:locktype><D:write/></D:locktype>"
              "</D:lockentry>"
              "</D:supportedlock>"));
        if (pnum != WEBDAV_PROP_ALL) return 0;/* found *//*(else fall through)*/
        __attribute_fallthrough__
      #endif
      default: /* WEBDAV_PROP_UNSET */
        return -1; /* not found */
    }
    return 0; /* found (WEBDAV_PROP_ALL) */
}


#ifdef USE_LOCKS
static void
webdav_propfind_lockdiscovery_cb (void * const vdata,
                                  const webdav_lockdata * const lockdata)
{
    webdav_xml_activelock((buffer *)vdata, lockdata, NULL, 0);
}
#endif


static void
webdav_propfind_resource_props (const webdav_propfind_bufs * const restrict pb)
{
    const webdav_property_names * const props = &pb->proplist;
    if (props->used) { /* "props" or "allprop"+"include" */
        const webdav_property_name *prop = props->ptr;
        for (int i = 0; i < props->used; ++i, ++prop) {
            if (NULL == prop->name  /*(flag indicating prop is live prop enum)*/
                ? 0 == webdav_propfind_live_props(pb, (enum webdav_live_props_e)
                                                      prop->namelen)
                : 0 == webdav_prop_select_prop(pb->pconf, pb->dst->rel_path,
                                               prop, pb->b_200))
                continue;

            /*(error obtaining prop if reached)*/
            webdav_xml_prop(pb->b_404, prop, NULL, 0);
        }
    }

    if (pb->allprop) {
        webdav_propfind_live_props(pb, WEBDAV_PROP_ALL);
        webdav_prop_select_props(pb->pconf, pb->dst->rel_path, pb->b_200);
    }

  #ifdef USE_LOCKS
    if (pb->lockdiscovery) {
        /* pb->lockdiscovery > 0:
         *   report locks resource or containing (parent) collections
         * pb->lockdiscovery < 0:
         *   report only those locks on specific resource
         * While this is not compliant with RFC, it may reduces quite a bit of
         * redundancy for propfind on Depth: 1 and Depth: infinity when there
         * are locks on parent collections.  The client receiving this propfind
         * XML response should easily know that locks on collections apply to
         * the members of those collections and to further nested collections
         *
         * future: might be many, many fewer database queries if make a single
         * query for the locks in the collection directory tree and parse the
         * results, rather than querying the database for each resource */
        buffer_append_string_len(pb->b_200, CONST_STR_LEN(
          "<D:lockdiscovery>"));
        webdav_lock_activelocks(pb->pconf, pb->dst->rel_path,
                                (pb->lockdiscovery > 0),
                                webdav_propfind_lockdiscovery_cb, pb->b_200);
        buffer_append_string_len(pb->b_200, CONST_STR_LEN(
          "</D:lockdiscovery>"));
    }
  #endif
}


static void
webdav_propfind_resource_propnames (const webdav_propfind_bufs *
                                      const restrict pb)
{
    static const char live_propnames[] =
      "<getcontentlength/>\n"
      "<getcontenttype/>\n"
      "<getetag/>\n"
      "<getlastmodified/>\n"
      "<resourcetype/>\n"
     #ifdef USE_LOCKS
      "<supportedlock/>\n"
      "<lockdiscovery/>\n"
     #endif
      ;
    /* list live_properties which are not in database, plus "lockdiscovery" */
    buffer_append_string_len(pb->b_200,live_propnames,sizeof(live_propnames)-1);

    /* list properties in database 'properties' table for resource */
    webdav_prop_select_propnames(pb->pconf, pb->dst->rel_path, pb->b_200);
}


__attribute_cold__
static void
webdav_propfind_resource_403 (const webdav_propfind_bufs * const restrict pb)
{
    buffer * const restrict b = pb->b;
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:response>\n"));
    webdav_xml_href(b, pb->dst->rel_path);
    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:propstat>\n"));
    webdav_xml_status(b, 403); /* Forbidden */
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:propstat>\n"
      "</D:response>\n"));
}


static void
webdav_propfind_resource (const webdav_propfind_bufs * const restrict pb)
{
    buffer_clear(pb->b_200);
    buffer_clear(pb->b_404);

    if (!pb->propname)
        webdav_propfind_resource_props(pb);
    else
        webdav_propfind_resource_propnames(pb);

    /* buffer could get very large for large directory (or Depth: infinity)
     * attempt to allocate in 8K chunks, rather than default realloc in
     * 64-byte chunks (see buffer.h) which will lead to exponentially more
     * expensive copy behavior as buffer is resized over and over and over
     *
     * future: avoid (potential) excessive memory usage by accumulating output
     *         in temporary file
     */
    buffer * const restrict b     = pb->b;
    buffer * const restrict b_200 = pb->b_200;
    buffer * const restrict b_404 = pb->b_404;
    if (b->size - b->used < b_200->used + b_404->used + 1024) {
        size_t sz = b->used + BUFFER_MAX_REUSE_SIZE
                  + b_200->used + b_404->used + 1024;
        /*(optimization; buffer is extended as needed)*/
        buffer_string_prepare_append(b, sz & (BUFFER_MAX_REUSE_SIZE-1));
    }

    buffer_append_string_len(b, CONST_STR_LEN(
      "<D:response>\n"));
    webdav_xml_href(b, pb->dst->rel_path);
    if (b_200->used > 1)  /* !unset and !blank */
        webdav_xml_propstat(b, b_200, 200);
    if (b_404->used > 1)  /* !unset and !blank */
        webdav_xml_propstat(b, b_404, 404);
    buffer_append_string_len(b, CONST_STR_LEN(
      "</D:response>\n"));
}


static void
webdav_propfind_dir (webdav_propfind_bufs * const restrict pb)
{
    const physical_st * const dst = pb->dst;
    const int dfd = fdevent_open_dirname(dst->path->ptr, 0);
    DIR * const dir = (dfd >= 0) ? fdopendir(dfd) : NULL;
    if (NULL == dir) {
        int errnum = errno;
        if (dfd >= 0) close(dfd);
        if (errnum != ENOENT)
            webdav_propfind_resource_403(pb); /* Forbidden */
        return;
    }

    webdav_propfind_resource(pb);

    if (pb->lockdiscovery > 0)
        pb->lockdiscovery = -pb->lockdiscovery; /*(check locks on node only)*/

    /* dst is modified in place to extend path,
     * so be sure to restore to base each loop iter */
    const uint32_t dst_path_used     = dst->path->used;
    const uint32_t dst_rel_path_used = dst->rel_path->used;
    const int flags =
      (pb->con->conf.force_lowercase_filenames ? WEBDAV_FLAG_LC_NAMES : 0);
    struct dirent *de;
    while (NULL != (de = readdir(dir))) {
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue; /* ignore "." and ".." */

        if (0 != fstatat(dfd, de->d_name, &pb->st, AT_SYMLINK_NOFOLLOW))
            continue; /* file *just* disappeared? */

        const uint32_t len = (uint32_t) _D_EXACT_NAMLEN(de);
        if (flags & WEBDAV_FLAG_LC_NAMES) /*(needed by rel_path)*/
            webdav_str_len_to_lower(de->d_name, len);
        buffer_append_string_len(dst->path, de->d_name, len);
        buffer_append_string_len(dst->rel_path, de->d_name, len);
        if (S_ISDIR(pb->st.st_mode)) {
            buffer_append_string_len(dst->path,     CONST_STR_LEN("/"));
            buffer_append_string_len(dst->rel_path, CONST_STR_LEN("/"));
        }

        if (S_ISDIR(pb->st.st_mode) && -1 == pb->depth)
            webdav_propfind_dir(pb); /* recurse */
        else
            webdav_propfind_resource(pb);

        dst->path->ptr[    (dst->path->used     = dst_path_used)    -1] = '\0';
        dst->rel_path->ptr[(dst->rel_path->used = dst_rel_path_used)-1] = '\0';
    }
    closedir(dir);
}


static int
webdav_open_chunk_file_rd (chunk * const c)
{
    if (c->file.fd < 0) /* open file if not already open *//*permit symlink*/
        c->file.fd = fdevent_open_cloexec(c->mem->ptr, 1, O_RDONLY, 0);
    return c->file.fd;
}


static int
webdav_mmap_file_rd (void ** const addr, const size_t length,
                   const int fd, const off_t offset)
{
    /*(caller must ensure offset is properly aligned to mmap requirements)*/

    if (0 == length) {
        *addr = NULL; /*(something other than MAP_FAILED)*/
        return 0;
    }

  #ifdef HAVE_MMAP

    *addr = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, offset);
    if (*addr == MAP_FAILED && errno == EINVAL)
        *addr = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);
    return (*addr != MAP_FAILED ? 0 : -1);

  #else

    return -1;

  #endif
}


static char *
webdav_mmap_file_chunk (chunk * const c)
{
    /*(request body provided in temporary file, so ok to mmap().
     * Otherwise, must check defined(ENABLE_MMAP)) */
    /* chunk_reset() or chunk_free() will clean up mmap'd chunk */
    /* close c->file.fd only after mmap() succeeds, since it will not
     * be able to be re-opened if it was a tmpfile that was unlinked */
    /*assert(c->type == FILE_CHUNK);*/
    if (MAP_FAILED != c->file.mmap.start)
        return c->file.mmap.start + c->offset;

    if (webdav_open_chunk_file_rd(c) < 0)
        return NULL;

    webdav_mmap_file_rd((void **)&c->file.mmap.start, (size_t)c->file.length,
                        c->file.fd, 0);

    if (MAP_FAILED == c->file.mmap.start)
        return NULL;

    close(c->file.fd);
    c->file.fd = -1;
    c->file.mmap.length = c->file.length;
    return c->file.mmap.start + c->offset;
}


#if defined(USE_PROPPATCH) || defined(USE_LOCKS)
__attribute_noinline__
static xmlDoc *
webdav_parse_chunkqueue (connection * const con,
                         const plugin_config * const pconf)
{
    /* read the chunks in to the XML document */
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
    /* XXX: evaluate adding more xmlParserOptions */
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOERROR | XML_PARSE_NOWARNING
                          | XML_PARSE_PEDANTIC| XML_PARSE_NONET);
    char *xmlstr;
    chunkqueue * const cq = con->request_content_queue;
    size_t weWant = cq->bytes_in - cq->bytes_out;
    int err = XML_ERR_OK;

    while (weWant) {
        size_t weHave = 0;
        chunk *c = cq->first;
        char buf[16384];
      #ifdef __COVERITY__
        force_assert(0 == weWant || c != NULL);
      #endif

        if (c->type == MEM_CHUNK) {
            xmlstr = c->mem->ptr + c->offset;
            weHave = buffer_string_length(c->mem) - c->offset;
        }
        else if (c->type == FILE_CHUNK) {
            xmlstr = webdav_mmap_file_chunk(c);
            /*xmlstr = c->file.mmap.start + c->offset;*/
            if (NULL != xmlstr) {
                weHave = c->file.length - c->offset;
            }
            else {
                switch (errno) {
                  case ENOSYS: case ENODEV: case EINVAL: break;
                  default:
                    log_perror(con->errh, __FILE__, __LINE__,
                               "open() or mmap() '%*.s'",
                               BUFFER_INTLEN_PTR(c->mem));
                }
                if (webdav_open_chunk_file_rd(c) < 0) {
                    log_perror(con->errh, __FILE__, __LINE__,
                               "open() '%*.s'",
                               BUFFER_INTLEN_PTR(c->mem));
                    err = XML_IO_UNKNOWN;
                    break;
                }
                ssize_t rd = -1;
                do {
                    if (-1 ==lseek(c->file.fd,c->file.start+c->offset,SEEK_SET))
                        break;
                    off_t len = c->file.length - c->offset;
                    if (len > (off_t)sizeof(buf)) len = (off_t)sizeof(buf);
                    rd = read(c->file.fd, buf, (size_t)len);
                } while (-1 == rd && errno == EINTR);
                if (rd >= 0) {
                    xmlstr = buf;
                    weHave = (size_t)rd;
                }
                else {
                    log_perror(con->errh, __FILE__, __LINE__,
                               "read() '%*.s'",
                               BUFFER_INTLEN_PTR(c->mem));
                    err = XML_IO_UNKNOWN;
                    break;
                }
            }
        }
        else {
            log_error(con->errh, __FILE__, __LINE__,
                      "unrecognized chunk type: %d", c->type);
            err = XML_IO_UNKNOWN;
            break;
        }

        if (weHave > weWant) weHave = weWant;

        if (pconf->log_xml)
            log_error(con->errh, __FILE__, __LINE__,
                      "XML-request-body: %.*s", (int)weHave, xmlstr);

        if (XML_ERR_OK != (err = xmlParseChunk(ctxt, xmlstr, weHave, 0))) {
            log_error(con->errh, __FILE__, __LINE__,
                      "xmlParseChunk failed at: %lld %zu %d",
                      (long long int)cq->bytes_out, weHave, err);
            break;
        }

        weWant -= weHave;
        chunkqueue_mark_written(cq, weHave);
    }

    if (XML_ERR_OK == err) {
        switch ((err = xmlParseChunk(ctxt, 0, 0, 1))) {
          case XML_ERR_DOCUMENT_END:
          case XML_ERR_OK:
            if (ctxt->wellFormed) {
                xmlDoc * const xml = ctxt->myDoc;
                xmlFreeParserCtxt(ctxt);
                return xml;
            }
            break;
          default:
            log_error(con->errh, __FILE__, __LINE__,
                      "xmlParseChunk failed at final packet: %d", err);
            break;
        }
    }

    xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);
    return NULL;
}
#endif


#ifdef USE_LOCKS

struct webdav_lock_token_submitted_st {
  buffer *tokens;
  int used;
  int size;
  const buffer *authn_user;
  buffer *b;
  int nlocks;
  int slocks;
  int smatch;
};


static void
webdav_lock_token_submitted_cb (void * const vdata,
                                const webdav_lockdata * const lockdata)
{
    /* RFE: improve support for shared locks
     * (instead of treating match of any shared lock as sufficient,
     *  even when there are different lockroots)
     * keep track of matched shared locks and unmatched shared locks and
     * ensure that each lockroot with shared locks has at least one match
     * (Will need to allocate strings for each URI with shared lock and keep
     *  track whether or not a shared lock has been matched for that URI.
     *  After walking all locks, must walk looking for unmatched URIs,
     *  and must free these strings) */

    /* [RFC4918] 6.4 Lock Creator and Privileges
     *   When a locked resource is modified, a server MUST check that the
     *   authenticated principal matches the lock creator (in addition to
     *   checking for valid lock token submission).
     */

    struct webdav_lock_token_submitted_st * const cbdata =
      (struct webdav_lock_token_submitted_st *)vdata;
    const buffer * const locktoken = &lockdata->locktoken;
    const int shared = (lockdata->lockscope->used != sizeof("exclusive"));

    ++cbdata->nlocks;
    if (shared) ++cbdata->slocks;

    for (int i = 0; i < cbdata->used; ++i) {
        const buffer * const token = &cbdata->tokens[i];
        /* locktoken match (locktoken not '\0' terminated) */
        if (buffer_is_equal_string(token, CONST_BUF_LEN(locktoken))) {
            /*(0 length owner if no auth required to lock; not recommended)*/
            if (buffer_string_is_empty(lockdata->owner)/*no lock owner;match*/
                || buffer_is_equal_string(cbdata->authn_user,
                                          CONST_BUF_LEN(lockdata->owner))) {
                if (shared) ++cbdata->smatch;
                return; /* authenticated lock owner match */
            }
        }
    }

    /* no match with lock tokens in request */
    if (!shared)
        webdav_xml_href(cbdata->b, &lockdata->lockroot);
}


/**
 * check if request provides necessary locks to access the resource
 */
static int
webdav_has_lock (connection * const con,
                 const plugin_config * const pconf,
                 const buffer * const uri)
{
    /* Note with regard to exclusive locks on collections: client should not be
     * able to obtain an exclusive lock on a collection if there are existing
     * locks on resource members inside the collection.  Therefore, there is no
     * need to check here for locks on resource members inside collections.
     * (This ignores the possibility that an admin or some other privileged
     * or out-of-band process has added locks in spite of lock on collection.)
     * Revisit to properly support shared locks. */

    struct webdav_lock_token_submitted_st cbdata;
    cbdata.b = buffer_init();
    cbdata.tokens = NULL;
    cbdata.used  = 0;
    cbdata.size  = 0;
    cbdata.nlocks = 0;
    cbdata.slocks = 0;
    cbdata.smatch = 0;

    /* XXX: maybe add config switch to require that authentication occurred? */
    buffer owner = { NULL, 0, 0 };/*owner (not authenticated)(auth_user unset)*/
    data_string * const authn_user = (data_string *)
      array_get_element_klen(con->environment,
                             CONST_STR_LEN("REMOTE_USER"));
    cbdata.authn_user = authn_user ? authn_user->value : &owner;

    const buffer * const h =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("If"));

    if (!buffer_is_empty(h)) {
        /* parse "If" request header for submitted lock tokens
         * While the below not a pedantic, validating parse, if the header
         * is non-conformant or contains unencoded characters, the result
         * will be misidentified or ignored lock tokens, which will result
         * in fail closed -- secure default behavior -- if those lock
         * tokens are required.  It is highly unlikely that misparsing the "If"
         * request header will result in a valid lock token since lock tokens
         * should be unique, and opaquelocktoken should be globally unique */
        char *p = h->ptr;
        do {
          #if 0
            while (*p == ' ' || *p == '\t') ++p;
            if (*p == '<') { /* Resource-Tag */
                do { ++p; } while (*p != '>' && *p != '\0');
                if (*p == '\0') break;
                do { ++p; } while (*p == ' ' || *p == '\t');
            }
          #endif

            while (*p != '(' && *p != '\0') ++p;

            /* begin List in No-tag-list or Tagged-list
             *   List = "(" 1*Condition ")"
             *   Condition = ["Not"] (State-token | "[" entity-tag "]")
             */
            int notflag = 0;
            while (*p != '\0' && *++p != ')') {
                while (*p == ' ' || *p == '\t') ++p;
                if (   (p[0] & 0xdf) == 'N'
                    && (p[1] & 0xdf) == 'O'
                    && (p[2] & 0xdf) == 'T') {
                    notflag = 1;
                    p += 3;
                    while (*p == ' ' || *p == '\t') ++p;
                }
                if (*p != '<') { /* '<' begins State-token (Coded-URL) */
                    if (*p != '[') break; /* invalid syntax */
                    /* '[' and ']' wrap entity-tag */
                    char *etag = p+1;
                    do { ++p; } while (*p != ']' && *p != '\0');
                    if (*p != ']') break; /* invalid syntax */
                    if (p == etag) continue; /* ignore entity-tag if empty */
                    if (notflag) continue;/* ignore entity-tag in NOT context */
                    if (0 == con->etag_flags) continue; /* ignore entity-tag */
                    struct stat st;
                    if (0 != lstat(con->physical.path->ptr, &st)) {
                        http_status_set_error(con,412);/* Precondition Failed */
                        return 0;
                    }
                    if (S_ISDIR(st.st_mode)) continue;/*we ignore etag if dir*/
                    buffer *etagb = con->physical.etag;
                    etag_create(etagb, &st, con->etag_flags);
                    etag_mutate(etagb, etagb);
                    *p = '\0';
                    int ematch = etag_is_equal(etagb, etag, 0);
                    *p = ']';
                    if (!ematch) {
                        http_status_set_error(con,412);/* Precondition Failed */
                        return 0;
                    }
                    continue;
                }

                if (p[1] == 'D'
                    && 0 == strncmp(p, "<DAV:no-lock>",
                                    sizeof("<DAV:no-lock>")-1)) {
                    if (0 == notflag) {
                        http_status_set_error(con,412);/* Precondition Failed */
                        return 0;
                    }
                    p += sizeof("<DAV:no-lock>")-2; /* point p to '>' */
                    continue;
                }

                /* State-token (Coded-URL)
                 *   Coded-URL = "<" absolute-URI ">"
                 *   ; No linear whitespace (LWS) allowed in Coded-URL
                 *   ; absolute-URI defined in RFC 3986, Section 4.3
                 */
                if (cbdata.size == cbdata.used) {
                    if (cbdata.size == 16) { /* arbitrary limit */
                        http_status_set_error(con, 400); /* Bad Request */
                        return 0;
                    }
                    cbdata.tokens =
                      realloc(cbdata.tokens, sizeof(*(cbdata.tokens)) * 16);
                    force_assert(cbdata.tokens); /*(see above limit)*/
                }
                cbdata.tokens[cbdata.used].ptr = p+1;

                do { ++p; } while (*p != '>' && *p != '\0');
                if (*p == '\0') break; /* (*p != '>') */

                cbdata.tokens[cbdata.used].used =
                  (uint32_t)(p - cbdata.tokens[cbdata.used].ptr + 1);
                ++cbdata.used;
            }
        } while (*p++ == ')'); /* end of List in No-tag-list or Tagged-list */
    }

    webdav_lock_activelocks(pconf, uri, 1,
                            webdav_lock_token_submitted_cb, &cbdata);

    if (NULL != cbdata.tokens)
        free(cbdata.tokens);

    int has_lock = 1;

    if (0 != cbdata.b->used)
        has_lock = 0;
    else if (0 == cbdata.nlocks) { /* resource is not locked at all */
        /* error if lock provided on source and no locks present on source;
         * not error if no locks on Destination, but "If" provided for source */
        if (cbdata.used && uri == con->physical.rel_path) {
            has_lock = -1;
            http_status_set_error(con, 412); /* Precondition Failed */
        }
      #if 0  /*(treat no locks as if caller is holding an appropriate lock)*/
        else {
            has_lock = 0;
            webdav_xml_href(cbdata.b, uri);
        }
      #endif
    }

    /*(XXX: overly simplistic shared lock matching allows any match of shared
     * locks even when there are shared locks on multiple different lockroots.
     * Failure is misreported since unmatched shared locks are not added to
     * cbdata.b) */
    if (cbdata.slocks && !cbdata.smatch)
        has_lock = 0;

    if (!has_lock)
        webdav_xml_doc_error_lock_token_submitted(con, cbdata.b);

    buffer_free(cbdata.b);

    return (has_lock > 0);
}

#else  /* ! defined(USE_LOCKS) */

#define webdav_has_lock(con, pconf, uri) 1

#endif /* ! defined(USE_LOCKS) */


static handler_t
mod_webdav_propfind (connection * const con, const plugin_config * const pconf)
{
    if (con->request.content_length) {
      #ifdef USE_PROPPATCH
        if (con->state == CON_STATE_READ_POST) {
            handler_t rc = connection_handle_read_post_state(pconf->srv, con);
            if (rc != HANDLER_GO_ON) return rc;
        }
      #else
        /* PROPFIND is idempotent and safe, so even if parsing XML input is not
         * supported, live properties can still be produced, so treat as allprop
         * request.  NOTE: this behavior is NOT RFC CONFORMANT (and, well, if
         * compiled without XML support, this WebDAV implementation is already
         * non-compliant since it is missing support for XML request body).
         * RFC-compliant behavior would reject an ignored request body with
         *   415 Unsupported Media Type */
       #if 0
        http_status_set_error(con, 415); /* Unsupported Media Type */
        return HANDLER_FINISHED;
       #endif
      #endif
    }

    webdav_propfind_bufs pb;

    /* [RFC4918] 9.1 PROPFIND Method
     *   Servers MUST support "0" and "1" depth requests on WebDAV-compliant
     *   resources and SHOULD support "infinity" requests. In practice, support
     *   for infinite-depth requests MAY be disabled, due to the performance and
     *   security concerns associated with this behavior. Servers SHOULD treat
     *   a request without a Depth header as if a "Depth: infinity" header was
     *   included.
     */
    pb.allprop      = 0;
    pb.propname     = 0;
    pb.lockdiscovery= 0;
    pb.depth        = webdav_parse_Depth(con);

    /* future: might add config option to enable Depth: infinity
     * (Depth: infinity is supported if this rejection is removed) */
    if (-1 == pb.depth) {
        webdav_xml_doc_error_propfind_finite_depth(con);
        return HANDLER_FINISHED;
    }

    if (0 != lstat(con->physical.path->ptr, &pb.st)) {
        http_status_set_error(con, (errno == ENOENT) ? 404 : 403);
        return HANDLER_FINISHED;
    }
    else if (S_ISDIR(pb.st.st_mode)) {
        if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
            buffer *vb = http_header_request_get(con, HTTP_HEADER_OTHER,
                                                 CONST_STR_LEN("User-Agent"));
            if (vb && 0 == strncmp(vb->ptr, "Microsoft-WebDAV-MiniRedir/",
                                   sizeof("Microsoft-WebDAV-MiniRedir/")-1)) {
                /* workaround Microsoft-WebDAV-MiniRedir bug */
                /* (MS File Explorer unable to open folder if not redirected) */
                http_response_redirect_to_directory(pconf->srv, con, 308);
                return HANDLER_FINISHED;
            }
            /* set "Content-Location" instead of sending 308 redirect to dir */
            if (!http_response_redirect_to_directory(pconf->srv, con, 0))
                return HANDLER_FINISHED;
            buffer_append_string_len(con->physical.path,    CONST_STR_LEN("/"));
            buffer_append_string_len(con->physical.rel_path,CONST_STR_LEN("/"));
        }
    }
    else if (con->physical.path->ptr[con->physical.path->used - 2] == '/') {
        http_status_set_error(con, 403);
        return HANDLER_FINISHED;
    }
    else if (0 != pb.depth) {
        http_status_set_error(con, 403);
        return HANDLER_FINISHED;
    }

    pb.proplist.ptr  = NULL;
    pb.proplist.used = 0;
    pb.proplist.size = 0;

  #ifdef USE_PROPPATCH
    xmlDocPtr xml = NULL;
    const xmlNode *rootnode = NULL;
    if (con->request.content_length) {
        if (NULL == (xml = webdav_parse_chunkqueue(con, pconf))) {
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }
        rootnode = xmlDocGetRootElement(xml);
    }

    if (NULL != rootnode
        && 0 == webdav_xmlstrcmp_fixed(rootnode->name, "propfind")) {
        for (const xmlNode *cmd = rootnode->children; cmd; cmd = cmd->next) {
            if (0 == webdav_xmlstrcmp_fixed(cmd->name, "allprop"))
                pb.allprop = pb.lockdiscovery = 1;
            else if (0 == webdav_xmlstrcmp_fixed(cmd->name, "propname"))
                pb.propname = 1;
            else if (0 != webdav_xmlstrcmp_fixed(cmd->name, "prop")
                     && 0 != webdav_xmlstrcmp_fixed(cmd->name, "include"))
                continue;

            /* "prop" or "include": get prop by name */
            for (const xmlNode *prop = cmd->children; prop; prop = prop->next) {
                if (prop->type == XML_TEXT_NODE)
                    continue; /* ignore WS */

                if (prop->ns && '\0' == *(char *)prop->ns->href
                             && '\0' != *(char *)prop->ns->prefix) {
                    log_error(con->errh, __FILE__, __LINE__,
                              "no name space for: %s", prop->name);
                    /* 422 Unprocessable Entity */
                    http_status_set_error(con, 422);
                    free(pb.proplist.ptr);
                    xmlFreeDoc(xml);
                    return HANDLER_FINISHED;
                }

                /* add property to requested list */
                if (pb.proplist.size == pb.proplist.used) {
                    if (pb.proplist.size == 32) {
                        /* arbitrarily chosen limit of 32 */
                        log_error(con->errh, __FILE__, __LINE__,
                                  "too many properties in request (> 32)");
                        http_status_set_error(con, 400); /* Bad Request */
                        free(pb.proplist.ptr);
                        xmlFreeDoc(xml);
                        return HANDLER_FINISHED;
                    }
                    pb.proplist.ptr =
                      realloc(pb.proplist.ptr, sizeof(*(pb.proplist.ptr)) * 32);
                    force_assert(pb.proplist.ptr); /*(see above limit)*/
                }

                const size_t namelen = strlen((char *)prop->name);
                if (prop->ns && 0 == strcmp((char *)prop->ns->href, "DAV:")) {
                    if (namelen == sizeof("lockdiscovery")-1
                        && 0 == memcmp(prop->name,
                                       CONST_STR_LEN("lockdiscovery"))) {
                        pb.lockdiscovery = 1;
                        continue;
                    }
                    const struct live_prop_list *list = live_properties;
                    while (0 != list->len
                           && (list->len != namelen
                               || 0 != memcmp(prop->name,list->prop,list->len)))
                        ++list;
                    if (NULL != list->prop) {
                        if (cmd->name[0] == 'p') { /* "prop", not "include" */
                            pb.proplist.ptr[pb.proplist.used].name = NULL;
                            pb.proplist.ptr[pb.proplist.used].namelen =
                              list->pnum;
                            pb.proplist.used++;
                        } /* (else skip; will already be part of allprop) */
                        continue;
                    }
                    if (cmd->name[0] == 'i') /* allprop "include", not "prop" */
                        continue; /*(all props in db returned with allprop)*/
                    /* dead props or props in "DAV:" ns not handed above */
                }

                /* save pointers directly into parsed xmlDoc
                 * Therefore, MUST NOT call xmlFreeDoc(xml)
                 * until also done with pb.proplist */
                webdav_property_name * const propname =
                  pb.proplist.ptr + pb.proplist.used++;
                if (prop->ns) {
                    propname->ns = (char *)prop->ns->href;
                    propname->nslen = strlen(propname->ns);
                }
                else {
                    propname->ns = "";
                    propname->nslen = 0;
                }
                propname->name = (char *)prop->name;
                propname->namelen = namelen;
            }
        }
    }
  #endif

    if (NULL == pb.proplist.ptr && !pb.propname)
        pb.allprop = pb.lockdiscovery = 1;

    pb.con   = con;
    pb.pconf = pconf;
    pb.dst   = &con->physical;
    pb.b     = /*(optimization; buf extended as needed)*/
      chunkqueue_append_buffer_open_sz(con->write_queue, BUFFER_MAX_REUSE_SIZE);
    pb.b_200 = buffer_init();
    pb.b_404 = buffer_init();

    buffer_string_prepare_copy(pb.b_200, BUFFER_MAX_REUSE_SIZE-1);
    buffer_string_prepare_copy(pb.b_404, BUFFER_MAX_REUSE_SIZE-1);

    webdav_xml_doctype(pb.b, con);
    buffer_append_string_len(pb.b, CONST_STR_LEN(
      "<D:multistatus xmlns:D=\"DAV:\" " MOD_WEBDAV_XMLNS_NS0 ">\n"));

    if (0 != pb.depth) /*(must be collection or else error returned above)*/
        webdav_propfind_dir(&pb);
    else
        webdav_propfind_resource(&pb);

    buffer_append_string_len(pb.b, CONST_STR_LEN(
      "</D:multistatus>\n"));

    if (pconf->log_xml)
        log_error(con->errh, __FILE__, __LINE__, "XML-response-body: %.*s",
                  BUFFER_INTLEN_PTR(pb.b));

    http_status_set_fin(con, 207); /* Multi-status */

    buffer_free(pb.b_404);
    buffer_free(pb.b_200);
  #ifdef USE_PROPPATCH
    if (pb.proplist.ptr)
        free(pb.proplist.ptr);
    if (NULL != xml)
        xmlFreeDoc(xml);
  #endif

    return HANDLER_FINISHED;
}


static handler_t
mod_webdav_mkcol (connection * const con, const plugin_config * const pconf)
{
    const int status = webdav_mkdir(pconf, &con->physical, -1);
    if (0 == status)
        http_status_set_fin(con, 201); /* Created */
    else
        http_status_set_error(con, status);

    return HANDLER_FINISHED;
}


static handler_t
mod_webdav_delete (connection * const con, const plugin_config * const pconf)
{
    /* reject DELETE if original URI sent with fragment ('litmus' warning) */
    if (NULL != strchr(con->request.orig_uri->ptr, '#')) {
        http_status_set_error(con, 403);
        return HANDLER_FINISHED;
    }

    struct stat st;
    if (-1 == lstat(con->physical.path->ptr, &st)) {
        http_status_set_error(con, (errno == ENOENT) ? 404 : 403);
        return HANDLER_FINISHED;
    }

    if (0 != webdav_if_match_or_unmodified_since(con, &st)) {
        http_status_set_error(con, 412); /* Precondition Failed */
        return HANDLER_FINISHED;
    }

    if (S_ISDIR(st.st_mode)) {
        if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
          #if 0 /*(issues warning for /usr/bin/litmus copymove test)*/
            http_response_redirect_to_directory(pconf->srv, con, 308);
            return HANDLER_FINISHED; /* 308 Permanent Redirect */
            /* Alternatively, could append '/' to con->physical.path
             * and con->physical.rel_path, set Content-Location in
             * response headers, and continue to serve the request */
          #else
            buffer_append_string_len(con->physical.path,    CONST_STR_LEN("/"));
            buffer_append_string_len(con->physical.rel_path,CONST_STR_LEN("/"));
           #if 0 /*(Content-Location not very useful to client after DELETE)*/
            /*(? should it be request.uri or orig_uri ?)*/
            /*(should be url-encoded path)*/
            buffer_append_string_len(con->request.uri, CONST_STR_LEN("/"));
            http_header_response_set(con, HTTP_HEADER_CONTENT_LOCATION,
                                     CONST_STR_LEN("Content-Location"),
                                     CONST_BUF_LEN(con->request.uri));
           #endif
          #endif
        }
        /* require "infinity" if Depth request header provided */
        if (-1 != webdav_parse_Depth(con)) {
            /* [RFC4918] 9.6.1 DELETE for Collections
             *   The DELETE method on a collection MUST act as if a
             *   "Depth: infinity" header was used on it. A client MUST NOT
             *   submit a Depth header with a DELETE on a collection with any
             *   value but infinity.
             */
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }

        buffer * const ms = buffer_init(); /* multi-status */

        const int flags = (con->conf.force_lowercase_filenames)
          ? WEBDAV_FLAG_LC_NAMES
          : 0;
        if (0 == webdav_delete_dir(pconf, &con->physical, ms, flags)) {
            /* Note: this does not destroy locks if an error occurs,
             * which is not a problem if lock is only on the collection
             * being moved, but might need finer updates if there are
             * locks on internal elements that are successfully deleted */
            webdav_lock_delete_uri_col(pconf, con->physical.rel_path);
            http_status_set_fin(con, 204); /* No Content */
        }
        else {
            webdav_xml_doc_multistatus(con, pconf, ms); /* 207 Multi-status */
        }

        buffer_free(ms);
        /* invalidate stat cache of src if DELETE, whether or not successful */
        stat_cache_delete_dir(pconf->srv, CONST_BUF_LEN(con->physical.path));
    }
    else if (con->physical.path->ptr[con->physical.path->used - 2] == '/')
        http_status_set_error(con, 403);
    else {
        const int status = webdav_delete_file(pconf, &con->physical);
        if (0 == status) {
            webdav_lock_delete_uri(pconf, con->physical.rel_path);
            http_status_set_fin(con, 204); /* No Content */
        }
        else
            http_status_set_error(con, status);
    }

    return HANDLER_FINISHED;
}


static ssize_t
mod_webdav_write_cq_first_chunk (connection * const con, chunkqueue * const cq,
                                 const int fd)
{
    /* (Note: copying might take some time, temporarily pausing server) */
    chunk *c = cq->first;
    ssize_t wr = 0;

    switch(c->type) {
    case FILE_CHUNK:
        if (NULL != webdav_mmap_file_chunk(c)) {
            do {
                wr = write(fd, c->file.mmap.start+c->offset,
                           c->file.length - c->offset);
            } while (-1 == wr && errno == EINTR);
            break;
        }
        else {
            switch (errno) {
              case ENOSYS: case ENODEV: case EINVAL: break;
              default:
                log_perror(con->errh, __FILE__, __LINE__,
                           "open() or mmap() '%*.s'",
                           BUFFER_INTLEN_PTR(c->mem));
            }

            if (webdav_open_chunk_file_rd(c) < 0) {
                http_status_set_error(con, 500); /* Internal Server Error */
                return -1;
            }
            ssize_t rd = -1;
            char buf[16384];
            do {
                if (-1 == lseek(c->file.fd, c->file.start+c->offset, SEEK_SET))
                    break;
                off_t len = c->file.length - c->offset;
                if (len > (off_t)sizeof(buf)) len = (off_t)sizeof(buf);
                rd = read(c->file.fd, buf, (size_t)len);
            } while (-1 == rd && errno == EINTR);
            if (rd >= 0) {
                do {
                    wr = write(fd, buf, (size_t)rd);
                } while (-1 == wr && errno == EINTR);
                break;
            }
            else {
                log_perror(con->errh, __FILE__, __LINE__,
                           "read() '%*.s'",
                           BUFFER_INTLEN_PTR(c->mem));
                http_status_set_error(con, 500); /* Internal Server Error */
                return -1;
            }
        }
    case MEM_CHUNK:
        do {
            wr = write(fd, c->mem->ptr + c->offset,
                       buffer_string_length(c->mem) - c->offset);
        } while (-1 == wr && errno == EINTR);
        break;
    }

    if (wr > 0) {
        chunkqueue_mark_written(cq, wr);
    }
    else if (wr < 0)
        http_status_set_error(con, (errno == ENOSPC) ? 507 : 403);

    return wr;
}


__attribute_noinline__
static int
mod_webdav_write_cq (connection* const con, chunkqueue* const cq, const int fd)
{
    chunkqueue_remove_finished_chunks(cq);
    while (!chunkqueue_is_empty(cq)) {
        if (mod_webdav_write_cq_first_chunk(con, cq, fd) < 0) return 0;
    }
    return 1;
}


#if (defined(__linux__) || defined(__CYGWIN__)) && defined(O_TMPFILE)
static int
mod_webdav_write_single_file_chunk (connection* const con, chunkqueue* const cq)
{
    /* cq might have mem chunks after initial tempfile chunk
     * due to chunkqueue_steal() if request body is small */
    /*assert(cq->first->type == FILE_CHUNK);*/
    /*assert(cq->first->next != NULL);*/
    chunk * const c = cq->first;
    cq->first = c->next;
    if (mod_webdav_write_cq(con, cq, c->file.fd)) {
        /*assert(cq->first == NULL);*/
        c->next = NULL;
        cq->first = cq->last = c;
        return 1;
    }
    else {
        /*assert(cq->first != NULL);*/
        c->next = cq->first;
        cq->first = c;
        return 0;
    }
}
#endif


static handler_t
mod_webdav_put_0 (connection * const con, const plugin_config * const pconf)
{
    if (0 != webdav_if_match_or_unmodified_since(con, NULL)) {
        http_status_set_error(con, 412); /* Precondition Failed */
        return HANDLER_FINISHED;
    }

    /* special-case PUT 0-length file */
    int fd;
    fd = fdevent_open_cloexec(con->physical.path->ptr, 0,
                              O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
                              WEBDAV_FILE_MODE);
    if (fd >= 0) {
        if (0 != con->etag_flags) {
            /*(skip sending etag if fstat() error; not expected)*/
            struct stat st;
            if (0 == fstat(fd, &st)) webdav_response_etag(pconf, con, &st);
        }
        close(fd);
        webdav_parent_modified(pconf, con->physical.path);
        http_status_set_fin(con, 201); /* Created */
        return HANDLER_FINISHED;
    }
    else if (errno == EISDIR) {
        http_status_set_error(con, 405); /* Method Not Allowed */
        return HANDLER_FINISHED;
    }

    if (errno == ELOOP)
        webdav_delete_file(pconf, &con->physical); /*(ignore result)*/
        /*(attempt unlink(); target might be symlink
         * and above O_NOFOLLOW resulted in ELOOP)*/

    fd = fdevent_open_cloexec(con->physical.path->ptr, 0,
                              O_WRONLY | O_CREAT | O_TRUNC,
                              WEBDAV_FILE_MODE);
    if (fd >= 0) {
        close(fd);
        http_status_set_fin(con, 204); /* No Content */
        return HANDLER_FINISHED;
    }

    http_status_set_error(con, 500); /* Internal Server Error */
    return HANDLER_FINISHED;
}


static handler_t
mod_webdav_put_prep (connection * const con, const plugin_config * const pconf)
{
    if (NULL != http_header_request_get(con, HTTP_HEADER_OTHER,
                                        CONST_STR_LEN("Content-Range"))) {
        if (pconf->deprecated_unsafe_partial_put_compat) return HANDLER_GO_ON;
        /* [RFC7231] 4.3.4 PUT
         *   An origin server that allows PUT on a given target resource MUST
         *   send a 400 (Bad Request) response to a PUT request that contains a
         *   Content-Range header field (Section 4.2 of [RFC7233]), since the
         *   payload is likely to be partial content that has been mistakenly
         *   PUT as a full representation.
         */
        http_status_set_error(con, 400); /* Bad Request */
        return HANDLER_FINISHED;
    }

    const uint32_t used = con->physical.path->used;
    char *slash = con->physical.path->ptr + used - 2;
    if (*slash == '/') { /* disallow PUT on a collection (path ends in '/') */
        http_status_set_error(con, 400); /* Bad Request */
        return HANDLER_FINISHED;
    }

    /* special-case PUT 0-length file */
    if (0 == con->request.content_length)
        return mod_webdav_put_0(con, pconf);

    /* Create temporary file in target directory (to store reqbody as received)
     * Temporary file is unlinked so that if receiving reqbody fails,
     * temp file is automatically cleaned up when fd is closed.
     * While being received, temporary file is not part of directory listings.
     * While this might result in extra copying, it is simple and robust. */
    int fd;
    size_t len = buffer_string_length(con->physical.path);
  #if (defined(__linux__) || defined(__CYGWIN__)) && defined(O_TMPFILE)
    slash = memrchr(con->physical.path->ptr, '/', len);
    if (slash == con->physical.path->ptr) slash = NULL;
    if (slash) *slash = '\0';
    fd = fdevent_open_cloexec(con->physical.path->ptr, 1,
                              O_RDWR | O_TMPFILE | O_APPEND, WEBDAV_FILE_MODE);
    if (slash) *slash = '/';
    if (fd < 0)
  #endif
    {
        buffer_append_string_len(con->physical.path, CONST_STR_LEN("-XXXXXX"));
        fd = fdevent_mkstemp_append(con->physical.path->ptr);
        if (fd >= 0) unlink(con->physical.path->ptr);
        buffer_string_set_length(con->physical.path, len);
    }
    if (fd < 0) {
        http_status_set_error(con, 500); /* Internal Server Error */
        return HANDLER_FINISHED;
    }

    /* copy all chunks even though expecting (at most) single MEM_CHUNK chunk
     * (still, loop on partial writes)
     * (Note: copying might take some time, temporarily pausing server)
     * (error status is set if error occurs) */
    chunkqueue * const cq = con->request_content_queue;
    off_t cqlen = chunkqueue_length(cq);
    if (!mod_webdav_write_cq(con, cq, fd)) {
        close(fd);
        return HANDLER_FINISHED;
    }

    chunkqueue_reset(cq);
    if (0 != cqlen)  /*(con->physical.path copied, then c->mem cleared below)*/
        chunkqueue_append_file_fd(cq, con->physical.path, fd, 0, cqlen);
    else {
        /*(must be non-zero for fd to be appended, then reset to 0-length)*/
        chunkqueue_append_file_fd(cq, con->physical.path, fd, 0, 1);
        cq->last->file.length = 0;
        cq->bytes_in = 0;
    }
    buffer_clear(cq->last->mem); /* file already unlink()ed */
    chunkqueue_set_tempdirs(cq, cq->tempdirs, INTMAX_MAX);
    /* force huge cq->upload_temp_file_size since chunkqueue_set_tempdirs()
     * might truncate upload_temp_file_size to chunk.c:MAX_TEMPFILE_SIZE */
    cq->upload_temp_file_size = INTMAX_MAX;
    cq->last->file.is_temp = 1;

    return HANDLER_GO_ON;
}


#if (defined(__linux__) || defined(__CYGWIN__)) && defined(O_TMPFILE)
static int
mod_webdav_put_linkat_rename (connection * const con,
                              const plugin_config * const pconf,
                              const char * const pathtemp)
{
    chunkqueue * const cq = con->request_content_queue;
    chunk *c = cq->first;

    char pathproc[32] = "/proc/self/fd/";
    li_itostrn(pathproc+sizeof("/proc/self/fd/")-1,
               sizeof(pathproc)-(sizeof("/proc/self/fd/")-1), (long)c->file.fd);
    if (0 == linkat(AT_FDCWD, pathproc, AT_FDCWD, pathtemp, AT_SYMLINK_FOLLOW)){
        struct stat st;
      #ifdef RENAME_NOREPLACE /*(renameat2() not well-supported yet)*/
        if (0 == renameat2(AT_FDCWD, pathtemp,
                           AT_FDCWD, con->physical.path->ptr, RENAME_NOREPLACE))
            http_status_set_fin(con, 201); /* Created */
        else if (0 == rename(pathtemp, con->physical.path->ptr))
            http_status_set_fin(con, 204); /* No Content */ /*(replaced)*/
        else
      #else
        http_status_set_fin(con, 0 == lstat(con->physical.path->ptr, &st)
                                 ? 204   /* No Content */
                                 : 201); /* Created */
        if (201 == http_status_get(con))
            webdav_parent_modified(pconf, con->physical.path);
        if (0 != rename(pathtemp, con->physical.path->ptr))
      #endif
        {
            if (errno == EISDIR)
                http_status_set_error(con, 405); /* Method Not Allowed */
            else
                http_status_set_error(con, 403); /* Forbidden */
            unlink(pathtemp);
        }

        if (0 != con->etag_flags && http_status_get(con) < 300) { /*(201, 204)*/
            /*(skip sending etag if fstat() error; not expected)*/
            if (0 == fstat(c->file.fd, &st))
                webdav_response_etag(pconf, con, &st);
        }

        chunkqueue_mark_written(cq, c->file.length);
        return 1;
    }

    return 0;
}
#endif


__attribute_cold__
static handler_t
mod_webdav_put_deprecated_unsafe_partial_put_compat (connection * const con,
                                                     const plugin_config *pconf,
                                                     const buffer * const h)
{
    /* historical code performed very limited range parse (repeated here) */
    /* we only support <num>- ... */
    const char *num = h->ptr;
    off_t offset;
    char *err;
    if (0 != strncmp(num, "bytes", sizeof("bytes")-1)) {
        http_status_set_error(con, 501); /* Not Implemented */
        return HANDLER_FINISHED;
    }
    num += 5; /* +5 for "bytes" */
    offset = strtoll(num, &err, 10); /*(strtoll() ignores leading whitespace)*/
    if (num == err || *err != '-' || offset < 0) {
        http_status_set_error(con, 501); /* Not Implemented */
        return HANDLER_FINISHED;
    }

    const int fd = fdevent_open_cloexec(con->physical.path->ptr, 0,
                                        O_WRONLY, WEBDAV_FILE_MODE);
    if (fd < 0) {
        http_status_set_error(con, (errno == ENOENT) ? 404 : 403);
        return HANDLER_FINISHED;
    }

    if (-1 == lseek(fd, offset, SEEK_SET)) {
        close(fd);
        http_status_set_error(con, 500); /* Internal Server Error */
        return HANDLER_FINISHED;
    }

    /* copy all chunks even though expecting single chunk
     * (still, loop on partial writes)
     * (Note: copying might take some time, temporarily pausing server)
     * (error status is set if error occurs) */
    mod_webdav_write_cq(con, con->request_content_queue, fd);

    struct stat st;
    if (0 != con->etag_flags && !http_status_is_set(con)) {
        /*(skip sending etag if fstat() error; not expected)*/
        if (0 != fstat(fd, &st)) con->etag_flags = 0;
    }

    const int wc = close(fd);
    if (0 != wc && !http_status_is_set(con))
        http_status_set_error(con, (errno == ENOSPC) ? 507 : 403);

    if (!http_status_is_set(con)) {
        http_status_set_fin(con, 204); /* No Content */
        if (0 != con->etag_flags) webdav_response_etag(pconf, con, &st);
    }

    return HANDLER_FINISHED;
}


static handler_t
mod_webdav_put (connection * const con, const plugin_config * const pconf)
{
    if (con->state == CON_STATE_READ_POST) {
        int first_read = chunkqueue_is_empty(con->request_content_queue);
        handler_t rc = connection_handle_read_post_state(pconf->srv, con);
        if (rc != HANDLER_GO_ON) {
            if (first_read && rc == HANDLER_WAIT_FOR_EVENT
                && 0 != webdav_if_match_or_unmodified_since(con, NULL)) {
                http_status_set_error(con, 412); /* Precondition Failed */
                return HANDLER_FINISHED;
            }
            return rc;
        }
    }

    if (0 != webdav_if_match_or_unmodified_since(con, NULL)) {
        http_status_set_error(con, 412); /* Precondition Failed */
        return HANDLER_FINISHED;
    }

    if (pconf->deprecated_unsafe_partial_put_compat) {
        const buffer * const h =
          http_header_request_get(con, HTTP_HEADER_OTHER,
                                  CONST_STR_LEN("Content-Range"));
        if (NULL != h)
            return
              mod_webdav_put_deprecated_unsafe_partial_put_compat(con,pconf,h);
    }

    /* construct temporary filename in same directory as target
     * (expect cq contains exactly one chunk:
     *    the temporary FILE_CHUNK created in mod_webdav_put_prep())
     * (do not reuse c->mem buffer; if tmpfile was unlinked, c->mem is blank)
     * (since temporary file was unlinked, no guarantee of unique name,
     *  so add pid and fd to avoid conflict with an unlikely parallel
     *  PUT request being handled by same server pid (presumably by
     *  same client using same lock token)) */
    chunkqueue * const cq = con->request_content_queue;
    chunk *c = cq->first;

    /* future: might support client specifying getcontenttype property
     * using Content-Type request header.  However, [RFC4918] 9.7.1 notes:
     *   Many servers do not allow configuring the Content-Type on a
     *   per-resource basis in the first place. Thus, clients can't always
     *   rely on the ability to directly influence the content type by
     *   including a Content-Type request header
     */

    /*(similar to beginning of webdav_linktmp_rename())*/
    buffer * const tmpb = pconf->tmpb;
    buffer_copy_buffer(tmpb, con->physical.path);
    buffer_append_string_len(tmpb, CONST_STR_LEN("."));
    buffer_append_int(tmpb, (long)getpid());
    buffer_append_string_len(tmpb, CONST_STR_LEN("."));
    if (c->type == MEM_CHUNK)
        buffer_append_uint_hex_lc(tmpb, (uintptr_t)pconf); /*(stack/heap addr)*/
    else
        buffer_append_int(tmpb, (long)c->file.fd);
    buffer_append_string_len(tmpb, CONST_STR_LEN("~"));

    if (buffer_string_length(tmpb) >= PATH_MAX) { /*(temp file path too long)*/
        http_status_set_error(con, 500); /* Internal Server Error */
        return HANDLER_FINISHED;
    }

    const char *pathtemp = tmpb->ptr;

  #if (defined(__linux__) || defined(__CYGWIN__)) && defined(O_TMPFILE)
    if (c->type == FILE_CHUNK) { /*(reqbody contained in single tempfile)*/
        if (NULL != c->next) {
            /* if request body <= 64k, in-memory chunks might have been
             * moved to cq instead of appended to first chunk FILE_CHUNK */
            if (!mod_webdav_write_single_file_chunk(con, cq))
                return HANDLER_FINISHED;
        }
        if (mod_webdav_put_linkat_rename(con, pconf, pathtemp))
            return HANDLER_FINISHED;
        /* attempt traditional copy (below) if linkat() failed for any reason */
    }
  #endif

    const int fd = fdevent_open_cloexec(pathtemp, 0,
                                        O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
                                        WEBDAV_FILE_MODE);
    if (fd < 0) {
        http_status_set_error(con, 500); /* Internal Server Error */
        return HANDLER_FINISHED;
    }

    /* copy all chunks even though expecting single chunk
     * (still, loop on partial writes)
     * (Note: copying might take some time, temporarily pausing server)
     * (error status is set if error occurs) */
    mod_webdav_write_cq(con, cq, fd);

    struct stat st;
    if (0 != con->etag_flags && !http_status_is_set(con)) {
        /*(skip sending etag if fstat() error; not expected)*/
        if (0 != fstat(fd, &st)) con->etag_flags = 0;
    }

    const int wc = close(fd);
    if (0 != wc && !http_status_is_set(con))
        http_status_set_error(con, (errno == ENOSPC) ? 507 : 403);

    if (!http_status_is_set(con)) {
        struct stat ste;
        http_status_set_fin(con, 0 == lstat(con->physical.path->ptr, &ste)
                                 ? 204   /* No Content */
                                 : 201); /* Created */
        if (201 == http_status_get(con))
            webdav_parent_modified(pconf, con->physical.path);
        if (0 == rename(pathtemp, con->physical.path->ptr)) {
            if (0 != con->etag_flags) webdav_response_etag(pconf, con, &st);
        }
        else {
            if (errno == EISDIR)
                http_status_set_error(con, 405); /* Method Not Allowed */
            else
                http_status_set_error(con, 500); /* Internal Server Error */
            unlink(pathtemp);
        }
    }
    else
        unlink(pathtemp);

    return HANDLER_FINISHED;
}


static handler_t
mod_webdav_copymove_b (connection * const con, const plugin_config * const pconf, buffer * const dst_path, buffer * const dst_rel_path)
{
    int flags = WEBDAV_FLAG_OVERWRITE /*(default)*/
              | (con->conf.force_lowercase_filenames
                  ? WEBDAV_FLAG_LC_NAMES
                  : 0)
              | (con->request.http_method == HTTP_METHOD_MOVE
                  ? WEBDAV_FLAG_MOVE_RENAME
                  : WEBDAV_FLAG_COPY_LINK);

    const buffer * const h =
      http_header_request_get(con,HTTP_HEADER_OTHER,CONST_STR_LEN("Overwrite"));
    if (NULL != h) {
        if (h->used != 2
            || ((h->ptr[0] & 0xdf) != 'F' && (h->ptr[0] & 0xdf) != 'T'))  {
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }
        if ((h->ptr[0] & 0xdf) == 'F')
            flags &= ~WEBDAV_FLAG_OVERWRITE;
    }

    /* parse Destination
     *
     * http://127.0.0.1:1025/dav/litmus/copydest
     *
     * - host has to match Host: header in request
     *   (or else would need to check that Destination is reachable from server
     *    and authentication credentials grant privileges on Destination)
     * - query string on Destination, if present, is discarded
     *
     * NOTE: Destination path is relative to document root and IS NOT re-run
     * through other modules on server (such as aliasing or rewrite or userdir)
     */
    const buffer * const destination =
      http_header_request_get(con, HTTP_HEADER_OTHER,
                              CONST_STR_LEN("Destination"));
    if (NULL == destination) {
        http_status_set_error(con, 400); /* Bad Request */
        return HANDLER_FINISHED;
    }
  #ifdef __COVERITY__
    force_assert(2 <= destination->used);
  #endif

    const char *sep = destination->ptr, *start;
    if (*sep != '/') { /* path-absolute or absolute-URI form */
        start = sep;
        sep = start + buffer_string_length(con->uri.scheme);
        if (0 != strncmp(start, con->uri.scheme->ptr, sep - start)
            || sep[0] != ':' || sep[1] != '/' || sep[2] != '/') {
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }
        start = sep + 3;

        if (NULL == (sep = strchr(start, '/'))) {
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }
        if (!buffer_is_equal_string(con->uri.authority, start, sep - start)
               /* skip login info (even though it should not be present) */
            && (NULL == (start = (char *)memchr(start, '@', sep - start))
                || (++start, !buffer_is_equal_string(con->uri.authority,
                                                     start, sep - start)))) {
            /* not the same host */
            http_status_set_error(con, 502); /* Bad Gateway */
            return HANDLER_FINISHED;
        }
    }
    start = sep; /* starts with '/' */

    physical_st dst;
    dst.path     = dst_path;
    dst.rel_path = dst_rel_path;

    /* destination: remove query string, urldecode, path_simplify
     * and (maybe) lowercase for consistent destination URI path */
    buffer_copy_string_len(dst_rel_path, start,
                           NULL == (sep = strchr(start, '?'))
                             ? destination->ptr + destination->used-1 - start
                             : sep - start);
    if (buffer_string_length(dst_rel_path) >= PATH_MAX) {
        http_status_set_error(con, 403); /* Forbidden */
        return HANDLER_FINISHED;
    }
    buffer_urldecode_path(dst_rel_path);
    if (!buffer_is_valid_UTF8(dst_rel_path)) {
        /* invalid UTF-8 after url-decode */
        http_status_set_error(con, 400);
        return HANDLER_FINISHED;
    }
    buffer_path_simplify(dst_rel_path, dst_rel_path);
    if (buffer_string_is_empty(dst_rel_path) || dst_rel_path->ptr[0] != '/') {
        http_status_set_error(con, 400);
        return HANDLER_FINISHED;
    }

    if (flags & WEBDAV_FLAG_LC_NAMES)
        buffer_to_lower(dst_rel_path);

    /* Destination physical path
     * src con->physical.path might have been remapped with mod_alias.
     *   (but mod_alias does not modify con->physical.rel_path)
     * Find matching prefix to support use of mod_alias to remap webdav root.
     * Aliasing of paths underneath the webdav root might not work.
     * Likewise, mod_rewrite URL rewriting might thwart this comparison.
     * Use mod_redirect instead of mod_alias to remap paths *under* webdav root.
     * Use mod_redirect instead of mod_rewrite on *any* parts of path to webdav.
     * (Related, use mod_auth to protect webdav root, but avoid attempting to
     *  use mod_auth on paths underneath webdav root, as Destination is not
     *  validated with mod_auth)
     *
     * tl;dr: webdav paths and webdav properties are managed by mod_webdav,
     *        so do not modify paths externally or else undefined behavior
     *        or corruption may occur
     *
     * find matching URI prefix (lowercased if WEBDAV_FLAG_LC_NAMES)
     * (con->physical.rel_path and dst_rel_path will always match leading '/')
     * check if remaining con->physical.rel_path matches suffix of
     *   con->physical.path so that we can use the prefix to remap
     *   Destination physical path */
  #ifdef __COVERITY__
    force_assert(0 != con->physical.rel_path->used);
  #endif
    uint32_t i, remain;
    {
        const char * const p1 = con->physical.rel_path->ptr;
        const char * const p2 = dst_rel_path->ptr;
        for (i = 0; p1[i] && p1[i] == p2[i]; ++i) ;
        while (i != 0 && p1[--i] != '/') ; /* find matching directory path */
    }
    remain = con->physical.rel_path->used - 1 - i;
    if (con->physical.path->used - 1 <= remain) { /*(should not happen)*/
        http_status_set_error(con, 403); /* Forbidden */
        return HANDLER_FINISHED;
    }
    if (0 == memcmp(con->physical.rel_path->ptr+i, /*(suffix match)*/
                    con->physical.path->ptr + con->physical.path->used-1-remain,
                    remain)) { /*(suffix match)*/
      #ifdef __COVERITY__
        force_assert(2 <= dst_rel_path->used);
      #endif
        buffer_copy_string_len(dst_path, con->physical.path->ptr,
                               con->physical.path->used - 1 - remain);
        buffer_append_string_len(dst_path,
                                 dst_rel_path->ptr+i,
                                 dst_rel_path->used - 1 - i);
        if (buffer_string_length(dst_path) >= PATH_MAX) {
            http_status_set_error(con, 403); /* Forbidden */
            return HANDLER_FINISHED;
        }
    }
    else { /*(not expected; some other module mucked with path or rel_path)*/
        /* unable to perform physical path remap here;
         * assume doc_root/rel_path and no remapping */
      #ifdef __COVERITY__
        force_assert(2 <= con->physical.doc_root->used);
        force_assert(2 <= dst_path->used);
      #endif
        buffer_copy_buffer(dst_path, con->physical.doc_root);
        if (dst_path->ptr[dst_path->used-2] == '/')
            --dst_path->used; /* since dst_rel_path begins with '/' */
        buffer_append_string_buffer(dst_path, dst_rel_path);
        if (buffer_string_length(dst_rel_path) >= PATH_MAX) {
            http_status_set_error(con, 403); /* Forbidden */
            return HANDLER_FINISHED;
        }
    }

    if (con->physical.path->used <= dst_path->used
        && 0 == memcmp(con->physical.path->ptr, dst_path->ptr,
                       con->physical.path->used-1)
        && (con->physical.path->ptr[con->physical.path->used-2] == '/'
            || dst_path->ptr[con->physical.path->used-1] == '/'
            || dst_path->ptr[con->physical.path->used-1] == '\0')) {
        /* dst must not be nested under (or same as) src */
        http_status_set_error(con, 403); /* Forbidden */
        return HANDLER_FINISHED;
    }

    struct stat st;
    if (-1 == lstat(con->physical.path->ptr, &st)) {
        /* don't known about it yet, unlink will fail too */
        http_status_set_error(con, (errno == ENOENT) ? 404 : 403);
        return HANDLER_FINISHED;
    }

    if (0 != webdav_if_match_or_unmodified_since(con, &st)) {
        http_status_set_error(con, 412); /* Precondition Failed */
        return HANDLER_FINISHED;
    }

    if (S_ISDIR(st.st_mode)) {
        if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
            http_response_redirect_to_directory(pconf->srv, con, 308);
            return HANDLER_FINISHED; /* 308 Permanent Redirect */
            /* Alternatively, could append '/' to con->physical.path
             * and con->physical.rel_path, set Content-Location in
             * response headers, and continue to serve the request. */
        }

        /* ensure Destination paths end with '/' since dst is a collection */
      #ifdef __COVERITY__
        force_assert(2 <= dst_rel_path->used);
      #endif
        if (dst_rel_path->ptr[dst_rel_path->used - 2] != '/') {
            buffer_append_slash(dst_rel_path);
            buffer_append_slash(dst_path);
        }

        /* check for lock on destination (after ensuring dst ends in '/') */
        if (!webdav_has_lock(con, pconf, dst_rel_path))
            return HANDLER_FINISHED; /* 423 Locked */

        const int depth = webdav_parse_Depth(con);
        if (1 == depth) {
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }
        if (0 == depth) {
            if (con->request.http_method == HTTP_METHOD_MOVE) {
                http_status_set_error(con, 400); /* Bad Request */
                return HANDLER_FINISHED;
            }
            /* optionally create collection, then copy properties */
            int status;
            if (0 == lstat(dst_path->ptr, &st)) {
                if (S_ISDIR(st.st_mode))
                    status = 204; /* No Content */
                else if (flags & WEBDAV_FLAG_OVERWRITE) {
                    status = webdav_mkdir(pconf, &dst, 1);
                    if (0 == status) status = 204; /* No Content */
                }
                else
                    status = 412; /* Precondition Failed */
            }
            else if (errno == ENOENT) {
                status = webdav_mkdir(pconf, &dst,
                                      !!(flags & WEBDAV_FLAG_OVERWRITE));
                if (0 == status) status = 201; /* Created */
            }
            else
                status = 403; /* Forbidden */
            if (status < 300) {
                http_status_set_fin(con, status);
                webdav_prop_copy_uri(pconf,con->physical.rel_path,dst.rel_path);
            }
            else
                http_status_set_error(con, status);
            return HANDLER_FINISHED;
        }

        /* ensure destination is not nested in source */
        if (dst_rel_path->ptr[dst_rel_path->used - 2] != '/') {
            buffer_append_slash(dst_rel_path);
            buffer_append_slash(dst_path);
        }

        buffer * const ms = buffer_init(); /* multi-status */
        if (0 == webdav_copymove_dir(pconf, &con->physical, &dst, ms, flags)) {
            if (con->request.http_method == HTTP_METHOD_MOVE)
                webdav_lock_delete_uri_col(pconf, con->physical.rel_path);
            /*(requiring lock on destination requires MKCOL create dst first)
             *(if no lock support, return 200 OK unconditionally
             * instead of 200 OK or 201 Created; not fully RFC-conformant)*/
            http_status_set_fin(con, 200); /* OK */
        }
        else {
            /* Note: this does not destroy any locks if any error occurs,
             * which is not a problem if lock is only on the collection
             * being moved, but might need finer updates if there are
             * locks on internal elements that are successfully moved */
            webdav_xml_doc_multistatus(con, pconf, ms); /* 207 Multi-status */
        }
        buffer_free(ms);
        /* invalidate stat cache of src if MOVE, whether or not successful */
        if (con->request.http_method == HTTP_METHOD_MOVE)
            stat_cache_delete_dir(pconf->srv,CONST_BUF_LEN(con->physical.path));
        return HANDLER_FINISHED;
    }
    else if (con->physical.path->ptr[con->physical.path->used - 2] == '/') {
        http_status_set_error(con, 403); /* Forbidden */
        return HANDLER_FINISHED;
    }
    else {
        /* check if client has lock for destination
         * Note: requiring a lock on non-collection means that destination
         * should always exist since the issuance of the lock creates the
         * resource, so client will always have to provide Overwrite: T
         * for direct operations on non-collections (files) */
        if (!webdav_has_lock(con, pconf, dst_rel_path))
            return HANDLER_FINISHED; /* 423 Locked */

        /* check if destination exists
         * (Destination should exist since lock is required,
         *  and obtaining a lock will create the resource) */
        int rc = lstat(dst_path->ptr, &st);
        if (0 == rc && S_ISDIR(st.st_mode)) {
            /* file to dir/
             * append basename to physical path
             * future: might set Content-Location if dst_path does not end '/'*/
            if (NULL != (sep = strrchr(con->physical.path->ptr, '/'))) {
              #ifdef __COVERITY__
                force_assert(0 != dst_path->used);
              #endif
                size_t len = con->physical.path->used - 1
                           - (sep - con->physical.path->ptr);
                if (dst_path->ptr[dst_path->used-1] == '/') {
                    ++sep; /*(avoid double-slash in path)*/
                    --len;
                }
                buffer_append_string_len(dst_path, sep, len);
                buffer_append_string_len(dst_rel_path, sep, len);
                if (buffer_string_length(dst_path) >= PATH_MAX) {
                    http_status_set_error(con, 403); /* Forbidden */
                    return HANDLER_FINISHED;
                }
                rc = lstat(dst_path->ptr, &st);
                /* target (parent collection) already exists */
                http_status_set_fin(con, 204); /* No Content */
            }
        }

        if (-1 == rc) {
            char *slash;
            switch (errno) {
              case ENOENT:
                if (http_status_is_set(con)) break;
                /* check that parent collection exists */
                if ((slash = strrchr(dst_path->ptr, '/'))) {
                    *slash = '\0';
                    if (0 == lstat(dst_path->ptr, &st) && S_ISDIR(st.st_mode)) {
                        *slash = '/';
                        /* new entity will be created */
                        if (!http_status_is_set(con)) {
                            webdav_parent_modified(pconf, dst_path);
                            http_status_set_fin(con, 201); /* Created */
                        }
                        break;
                    }
                }
                /* fall through */
              /*case ENOTDIR:*/
              default:
                http_status_set_error(con, 409); /* Conflict */
                return HANDLER_FINISHED;
            }
        }
        else if (!(flags & WEBDAV_FLAG_OVERWRITE)) {
            /* destination exists, but overwrite is not set */
            http_status_set_error(con, 412); /* Precondition Failed */
            return HANDLER_FINISHED;
        }
        else if (S_ISDIR(st.st_mode)) {
            /* destination exists, but is a dir, not a file */
            http_status_set_error(con, 409); /* Conflict */
            return HANDLER_FINISHED;
        }
        else { /* resource already exists */
            http_status_set_fin(con, 204); /* No Content */
        }

        rc = webdav_copymove_file(pconf, &con->physical, &dst, &flags);
        if (0 == rc) {
            if (con->request.http_method == HTTP_METHOD_MOVE)
                webdav_lock_delete_uri(pconf, con->physical.rel_path);
        }
        else
            http_status_set_error(con, rc);

        return HANDLER_FINISHED;
    }
}


static handler_t
mod_webdav_copymove (connection * const con, const plugin_config * const pconf)
{
    buffer *dst_path = buffer_init();
    buffer *dst_rel_path = buffer_init();
    handler_t rc = mod_webdav_copymove_b(con, pconf, dst_path, dst_rel_path);
    buffer_free(dst_rel_path);
    buffer_free(dst_path);
    return rc;
}


#ifdef USE_PROPPATCH
static handler_t
mod_webdav_proppatch (connection * const con, const plugin_config * const pconf)
{
    if (!pconf->sql) {
        http_header_response_set(con, HTTP_HEADER_OTHER,
                                 CONST_STR_LEN("Allow"),
                                 CONST_STR_LEN("GET, HEAD, PROPFIND, DELETE, "
                                               "MKCOL, PUT, MOVE, COPY"));
        http_status_set_error(con, 405); /* Method Not Allowed */
        return HANDLER_FINISHED;
    }

    if (0 == con->request.content_length) {
        http_status_set_error(con, 400); /* Bad Request */
        return HANDLER_FINISHED;
    }

    if (con->state == CON_STATE_READ_POST) {
        handler_t rc = connection_handle_read_post_state(pconf->srv, con);
        if (rc != HANDLER_GO_ON) return rc;
    }

    struct stat st;
    if (0 != lstat(con->physical.path->ptr, &st)) {
        http_status_set_error(con, (errno == ENOENT) ? 404 : 403);
        return HANDLER_FINISHED;
    }

    if (0 != webdav_if_match_or_unmodified_since(con, &st)) {
        http_status_set_error(con, 412); /* Precondition Failed */
        return HANDLER_FINISHED;
    }

    if (S_ISDIR(st.st_mode)) {
        if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
            buffer *vb = http_header_request_get(con, HTTP_HEADER_OTHER,
                                                 CONST_STR_LEN("User-Agent"));
            if (vb && 0 == strncmp(vb->ptr, "Microsoft-WebDAV-MiniRedir/",
                                   sizeof("Microsoft-WebDAV-MiniRedir/")-1)) {
                /* workaround Microsoft-WebDAV-MiniRedir bug */
                /* (might not be necessary for PROPPATCH here,
                 *  but match behavior in mod_webdav_propfind() for PROPFIND) */
                http_response_redirect_to_directory(pconf->srv, con, 308);
                return HANDLER_FINISHED;
            }
            /* set "Content-Location" instead of sending 308 redirect to dir */
            if (!http_response_redirect_to_directory(pconf->srv, con, 0))
                return HANDLER_FINISHED;
            buffer_append_string_len(con->physical.path,    CONST_STR_LEN("/"));
            buffer_append_string_len(con->physical.rel_path,CONST_STR_LEN("/"));
        }
    }
    else if (con->physical.path->ptr[con->physical.path->used - 2] == '/') {
        http_status_set_error(con, 403);
        return HANDLER_FINISHED;
    }

    xmlDocPtr const xml = webdav_parse_chunkqueue(con, pconf);
    if (NULL == xml) {
        http_status_set_error(con, 400); /* Bad Request */
        return HANDLER_FINISHED;
    }

    const xmlNode * const rootnode = xmlDocGetRootElement(xml);
    if (NULL == rootnode
        || 0 != webdav_xmlstrcmp_fixed(rootnode->name, "propertyupdate")) {
        http_status_set_error(con, 422); /* Unprocessable Entity */
        xmlFreeDoc(xml);
        return HANDLER_FINISHED;
    }

    if (!webdav_db_transaction_begin_immediate(pconf)) {
        http_status_set_error(con, 500); /* Internal Server Error */
        xmlFreeDoc(xml);
        return HANDLER_FINISHED;
    }

    /* NOTE: selectively providing multi-status response is NON-CONFORMANT
     *       (specified in [RFC4918])
     * However, PROPPATCH is all-or-nothing, so client should be able to
     * unequivocably know that all items in PROPPATCH succeeded if it receives
     * 204 No Content, or that items that are not listed with a failure status
     * in a multi-status response have the status of 424 Failed Dependency,
     * without the server having to be explicit. */

    /* UPDATE request, we know 'set' and 'remove' */
    buffer *ms = NULL; /*(multi-status)*/
    int update;
    for (const xmlNode *cmd = rootnode->children; cmd; cmd = cmd->next) {
        if (!(update = (0 == webdav_xmlstrcmp_fixed(cmd->name, "set")))) {
            if (0 != webdav_xmlstrcmp_fixed(cmd->name, "remove"))
                continue; /* skip; not "set" or "remove" */
        }

        for (const xmlNode *props = cmd->children; props; props = props->next) {
            if (0 != webdav_xmlstrcmp_fixed(props->name, "prop"))
                continue;

            const xmlNode *prop = props->children;
            /* libxml2 will keep those blank (whitespace only) nodes */
            while (NULL != prop && xmlIsBlankNode(prop))
                prop = prop->next;
            if (NULL == prop)
                continue;
            if (prop->ns && '\0' == *(char *)prop->ns->href
                         && '\0' != *(char *)prop->ns->prefix) {
                /* error: missing namespace for property */
                log_error(con->errh, __FILE__, __LINE__,
                          "no namespace for: %s", prop->name);
                if (!ms) ms = buffer_init();      /* Unprocessable Entity */
                webdav_xml_propstat_status(ms, "", (char *)prop->name, 422);
                continue;
            }

            /* XXX: ??? should blank namespace be normalized to "DAV:" ???
             *      ??? should this also be done in propfind requests ??? */

            if (prop->ns && 0 == strcmp((char *)prop->ns->href, "DAV:")) {
                const size_t namelen = strlen((char *)prop->name);
                const struct live_prop_list *list = protected_props;
                while (0 != list->len
                       && (list->len != namelen
                           || 0 != memcmp(prop->name, list->prop, list->len)))
                    ++list;
                if (NULL != list->prop) {
                    /* error <DAV:cannot-modify-protected-property/> */
                    if (!ms) ms = buffer_init();
                    webdav_xml_propstat_protected(ms, (char *)prop->name,
                                                  namelen, 403); /* Forbidden */
                    continue;
                }
            }

            if (update) {
                if (!prop->children) continue;
                char * const propval = prop->children
                  ? (char *)xmlNodeListGetString(xml, prop->children, 0)
                  : NULL;
                webdav_prop_update(pconf, con->physical.rel_path,
                                   (char *)prop->name,
                                   prop->ns ? (char *)prop->ns->href : "",
                                   propval ? propval : "");
                xmlFree(propval);
            }
            else
                webdav_prop_delete(pconf, con->physical.rel_path,
                                   (char *)prop->name,
                                   prop->ns ? (char *)prop->ns->href : "");
        }
    }

    if (NULL == ms
          ? webdav_db_transaction_commit(pconf)
          : webdav_db_transaction_rollback(pconf)) {
        if (NULL == ms) {
            buffer *vb = http_header_request_get(con, HTTP_HEADER_OTHER,
                                                 CONST_STR_LEN("User-Agent"));
            if (vb && 0 == strncmp(vb->ptr, "Microsoft-WebDAV-MiniRedir/",
                                   sizeof("Microsoft-WebDAV-MiniRedir/")-1)) {
                /* workaround Microsoft-WebDAV-MiniRedir bug; 204 not handled */
                /* 200 without response body or 204 both incorrectly interpreted
                 * as 507 Insufficient Storage by Microsoft-WebDAV-MiniRedir. */
                ms = buffer_init(); /* 207 Multi-status */
                webdav_xml_response_status(ms, con->physical.path, 200);
            }
        }
        if (NULL == ms)
            http_status_set_fin(con, 204); /* No Content */
        else /* 207 Multi-status */
            webdav_xml_doc_multistatus_response(con, pconf, ms);
    }
    else
        http_status_set_error(con, 500); /* Internal Server Error */

    if (NULL != ms)
        buffer_free(ms);

    xmlFreeDoc(xml);
    return HANDLER_FINISHED;
}
#endif


#ifdef USE_LOCKS
struct webdav_conflicting_lock_st {
  webdav_lockdata *lockdata;
  buffer *b;
};


static void
webdav_conflicting_lock_cb (void * const vdata,
                            const webdav_lockdata * const lockdata)
{
    /* lock is not available if someone else has exclusive lock or if
     * client requested exclusive lock and others have shared locks */
    struct webdav_conflicting_lock_st * const cbdata =
      (struct webdav_conflicting_lock_st *)vdata;
    if (lockdata->lockscope->used == sizeof("exclusive")
        || cbdata->lockdata->lockscope->used == sizeof("exclusive"))
        webdav_xml_href(cbdata->b, &lockdata->lockroot);
}


static handler_t
mod_webdav_lock (connection * const con, const plugin_config * const pconf)
{
    /**
     * a mac wants to write
     *
     * LOCK /dav/expire.txt HTTP/1.1\r\n
     * User-Agent: WebDAVFS/1.3 (01308000) Darwin/8.1.0 (Power Macintosh)\r\n
     * Accept: * / *\r\n
     * Depth: 0\r\n
     * Timeout: Second-600\r\n
     * Content-Type: text/xml; charset=\"utf-8\"\r\n
     * Content-Length: 229\r\n
     * Connection: keep-alive\r\n
     * Host: 192.168.178.23:1025\r\n
     * \r\n
     * <?xml version=\"1.0\" encoding=\"utf-8\"?>\n
     * <D:lockinfo xmlns:D=\"DAV:\">\n
     *  <D:lockscope><D:exclusive/></D:lockscope>\n
     *  <D:locktype><D:write/></D:locktype>\n
     *  <D:owner>\n
     *   <D:href>http://www.apple.com/webdav_fs/</D:href>\n
     *  </D:owner>\n
     * </D:lockinfo>\n
     */

    if (con->request.content_length) {
        if (con->state == CON_STATE_READ_POST) {
            handler_t rc = connection_handle_read_post_state(pconf->srv, con);
            if (rc != HANDLER_GO_ON) return rc;
        }
    }

    /* XXX: maybe add config switch to require that authentication occurred? */
    buffer owner = { NULL, 0, 0 };/*owner (not authenticated)(auth_user unset)*/
    data_string * const authn_user = (data_string *)
      array_get_element_klen(con->environment, CONST_STR_LEN("REMOTE_USER"));

    /* future: make max timeout configurable (e.g. pconf->lock_timeout_max)
     *
     * [RFC4918] 10.7 Timeout Request Header
     *   The "Second" TimeType specifies the number of seconds that will elapse
     *   between granting of the lock at the server, and the automatic removal
     *   of the lock. The timeout value for TimeType "Second" MUST NOT be
     *   greater than 2^32-1.
     */

    webdav_lockdata lockdata = {
      { NULL, 0, 0 }, /* locktoken */
      { con->physical.rel_path->ptr,con->physical.rel_path->used,0},/*lockroot*/
      { NULL, 0, 0 }, /* ownerinfo */
      (authn_user ? authn_user->value : &owner), /* owner */
      NULL, /* lockscope */
      NULL, /* locktype  */
      -1,   /* depth */
      600   /* timeout (arbitrary default lock timeout: 10 minutes) */
    };

    const buffer *h =
      http_header_request_get(con, HTTP_HEADER_OTHER, CONST_STR_LEN("Timeout"));
    if (!buffer_is_empty(h)) {
        /* loosely parse Timeout request header and ignore "infinity" timeout */
        /* future: might implement config param for upper limit for timeout */
        const char *p = h->ptr;
        do {
            if ((*p | 0x20) == 's'
                && buffer_eq_icase_ssn(p, CONST_STR_LEN("second-"))) {
                long t = strtol(p+sizeof("second-")-1, NULL, 10);
                if (0 < t && t < lockdata.timeout)
                    lockdata.timeout = t > 5 ? t : 5;
                    /*(arbitrary min timeout: 5 secs)*/
                else if (sizeof(long) != sizeof(int) && t > INT32_MAX)
                    lockdata.timeout = INT32_MAX;
                    /* while UINT32_MAX is actual limit in RFC4918,
                     * sqlite more easily supports int, though could be
                     * changed to use int64 to for the timeout param.
                     * The "limitation" between timeouts that are many
                     * *years* long does not really matter in reality. */
                break;
            }
          #if 0
            else if ((*p | 0x20) == 'i'
                     && buffer_eq_icase_ssn(p, CONST_STR_LEN("infinity"))) {
                lockdata.timeout = INT32_MAX;
                break;
            }
          #endif
            while (*p != ',' && *p != '\0') ++p;
            while (*p == ' ' || *p == '\t') ++p;
        } while (*p != '\0');
    }

    if (con->request.content_length) {
        lockdata.depth = webdav_parse_Depth(con);
        if (1 == lockdata.depth) {
            /* [RFC4918] 9.10.3 Depth and Locking
             *   Values other than 0 or infinity MUST NOT be used
             *   with the Depth header on a LOCK method.
             */
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }

        xmlDocPtr const xml = webdav_parse_chunkqueue(con, pconf);
        if (NULL == xml) {
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }

        const xmlNode * const rootnode = xmlDocGetRootElement(xml);
        if (NULL == rootnode
            || 0 != webdav_xmlstrcmp_fixed(rootnode->name, "lockinfo")) {
            http_status_set_error(con, 422); /* Unprocessable Entity */
            xmlFreeDoc(xml);
            return HANDLER_FINISHED;
        }

        const xmlNode *lockinfo = rootnode->children;
        for (; lockinfo; lockinfo = lockinfo->next) {
            if (0 == webdav_xmlstrcmp_fixed(lockinfo->name, "lockscope")) {
                const xmlNode *value = lockinfo->children;
                for (; value; value = value->next) {
                    if (0 == webdav_xmlstrcmp_fixed(value->name, "exclusive"))
                        lockdata.lockscope=(const buffer *)&lockscope_exclusive;
                    else if (0 == webdav_xmlstrcmp_fixed(value->name, "shared"))
                        lockdata.lockscope=(const buffer *)&lockscope_shared;
                    else {
                        lockdata.lockscope=NULL; /* trigger error below loop */
                        break;
                    }
                }
            }
            else if (0 == webdav_xmlstrcmp_fixed(lockinfo->name, "locktype")) {
                const xmlNode *value = lockinfo->children;
                for (; value; value = value->next) {
                    if (0 == webdav_xmlstrcmp_fixed(value->name, "write"))
                        lockdata.locktype = (const buffer *)&locktype_write;
                    else {
                        lockdata.locktype = NULL;/* trigger error below loop */
                        break;
                    }
                }
            }
            else if (0 == webdav_xmlstrcmp_fixed(lockinfo->name, "owner")) {
                if (lockinfo->children)
                    lockdata.ownerinfo.ptr =
                      (char *)xmlNodeListGetString(xml, lockinfo->children, 0);
                if (lockdata.ownerinfo.ptr)
                    lockdata.ownerinfo.used = strlen(lockdata.ownerinfo.ptr)+1;
            }
        }

      do { /*(resources are cleaned up after code block)*/

        if (NULL == lockdata.lockscope || NULL == lockdata.locktype) {
            /*(missing lockscope and locktype in lock request)*/
            http_status_set_error(con, 422); /* Unprocessable Entity */
            break; /* clean up resources and return HANDLER_FINISHED */
        }

        /* check lock prior to potentially creating new resource,
         * and prior to using entropy to create uuid */
        struct webdav_conflicting_lock_st cbdata;
        cbdata.lockdata = &lockdata;
        cbdata.b = buffer_init();
        webdav_lock_activelocks(pconf, &lockdata.lockroot,
                                (0 == lockdata.depth ? 1 : -1),
                                webdav_conflicting_lock_cb, &cbdata);
        if (0 != cbdata.b->used) {
            /* 423 Locked */
            webdav_xml_doc_error_no_conflicting_lock(con, cbdata.b);
            buffer_free(cbdata.b);
            break; /* clean up resources and return HANDLER_FINISHED */
        }
        buffer_free(cbdata.b);

        int created = 0;
        struct stat st;
        if (0 != lstat(con->physical.path->ptr, &st)) {
            /* [RFC4918] 7.3 Write Locks and Unmapped URLs
             *   A successful lock request to an unmapped URL MUST result in
             *   the creation of a locked (non-collection) resource with empty
             *   content.
             *   [...]
             *   The response MUST indicate that a resource was created, by
             *   use of the "201 Created" response code (a LOCK request to an
             *   existing resource instead will result in 200 OK).
             * [RFC4918] 9.10.4 Locking Unmapped URLs
             *   A successful LOCK method MUST result in the creation of an
             *   empty resource that is locked (and that is not a collection)
             *   when a resource did not previously exist at that URL. Later on,
             *   the lock may go away but the empty resource remains. Empty
             *   resources MUST then appear in PROPFIND responses including that
             *   URL in the response scope. A server MUST respond successfully
             *   to a GET request to an empty resource, either by using a 204
             *   No Content response, or by using 200 OK with a Content-Length
             *   header indicating zero length
             *
             * unmapped resource; create empty file
             * (open() should fail if path ends in '/', but does not on some OS.
             *  This is desired behavior since collection should be created
             *  with MKCOL, and not via LOCK on an unmapped resource) */
            const int fd =
              (errno == ENOENT
               && con->physical.path->ptr[con->physical.path->used-2] != '/')
              ? fdevent_open_cloexec(con->physical.path->ptr, 0,
                                     O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
                                     WEBDAV_FILE_MODE)
              : -1;
            if (fd >= 0) {
                /*(skip sending etag if fstat() error; not expected)*/
                if (0 != fstat(fd, &st)) con->etag_flags = 0;
                close(fd);
                created = 1;
                webdav_parent_modified(pconf, con->physical.path);
            }
            else if (errno != EEXIST) {
                http_status_set_error(con, 403); /* Forbidden */
                break; /* clean up resources and return HANDLER_FINISHED */
            }
            else if (0 != lstat(con->physical.path->ptr, &st)) {
                http_status_set_error(con, 403); /* Forbidden */
                break; /* clean up resources and return HANDLER_FINISHED */
            }
            lockdata.depth = 0; /* force Depth: 0 on non-collections */
        }

        if (!created) {
            if (0 != webdav_if_match_or_unmodified_since(con, &st)) {
                http_status_set_error(con, 412); /* Precondition Failed */
                break; /* clean up resources and return HANDLER_FINISHED */
            }
        }

        if (created) {
        }
        else if (S_ISDIR(st.st_mode)) {
            if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
                /* 308 Permanent Redirect */
                http_response_redirect_to_directory(pconf->srv, con, 308);
                break; /* clean up resources and return HANDLER_FINISHED */
                /* Alternatively, could append '/' to con->physical.path
                 * and con->physical.rel_path, set Content-Location in
                 * response headers, and continue to serve the request */
            }
        }
        else if (con->physical.path->ptr[con->physical.path->used - 2] == '/') {
            http_status_set_error(con, 403); /* Forbidden */
            break; /* clean up resources and return HANDLER_FINISHED */
        }
        else if (0 != lockdata.depth)
            lockdata.depth = 0; /* force Depth: 0 on non-collections */

        /* create locktoken
         * (uuid_unparse() output is 36 chars + '\0') */
        uuid_t id;
        char lockstr[sizeof("<urn:uuid:>") + 36] = "<urn:uuid:";
        lockdata.locktoken.ptr = lockstr+1;         /*(without surrounding <>)*/
        lockdata.locktoken.used = sizeof(lockstr)-2;/*(without surrounding <>)*/
        uuid_generate(id);
        uuid_unparse(id, lockstr+sizeof("<urn:uuid:")-1);

        /* XXX: consider fix TOC-TOU race condition by starting transaction
         * and re-running webdav_lock_activelocks() check before running
         * webdav_lock_acquire() (but both routines would need to be modified
         * to defer calling sqlite3_reset(stmt) to be part of transaction) */
        if (webdav_lock_acquire(pconf, &lockdata)) {
            lockstr[sizeof(lockstr)-2] = '>';
            http_header_response_set(con, HTTP_HEADER_OTHER,
                                     CONST_STR_LEN("Lock-Token"),
                                     lockstr, sizeof(lockstr)-1);
            webdav_xml_doc_lock_acquired(con, pconf, &lockdata);
            if (0 != con->etag_flags && !S_ISDIR(st.st_mode))
                webdav_response_etag(pconf, con, &st);
            http_status_set_fin(con, created ? 201 : 200); /* Created | OK */
        }
        else /*(database error obtaining lock)*/
            http_status_set_error(con, 500); /* Internal Server Error */

      } while (0); /*(resources are cleaned up after code block)*/

        xmlFree(lockdata.ownerinfo.ptr);
        xmlFreeDoc(xml);
        return HANDLER_FINISHED;
    }
    else {
        h = http_header_request_get(con,HTTP_HEADER_OTHER,CONST_STR_LEN("If"));
        if (NULL == h
            || h->used < 6 || h->ptr[1] != '<' || h->ptr[h->used-3] != '>') {
            /*(rejects value with trailing LWS, even though RFC-permitted)*/
            http_status_set_error(con, 400); /* Bad Request */
            return HANDLER_FINISHED;
        }
        /* remove (< >) around token */
        lockdata.locktoken.ptr = h->ptr+2;
        lockdata.locktoken.used = h->used-4;
        /*(future: fill in from database, though exclusive write lock is the
         * only lock supported at the moment)*/
        lockdata.lockscope = (const buffer *)&lockscope_exclusive;
        lockdata.locktype  = (const buffer *)&locktype_write;
        lockdata.depth     = 0;

        if (webdav_lock_refresh(pconf, &lockdata)) {
            webdav_xml_doc_lock_acquired(con, pconf, &lockdata);
            http_status_set_fin(con, 200); /* OK */
        }
        else
            http_status_set_error(con, 412); /* Precondition Failed */

        return HANDLER_FINISHED;
    }
}
#endif


#ifdef USE_LOCKS
static handler_t
mod_webdav_unlock (connection * const con, const plugin_config * const pconf)
{
    const buffer * const h =
      http_header_request_get(con, HTTP_HEADER_OTHER,
                              CONST_STR_LEN("Lock-Token"));
    if (NULL == h
        || h->used < 4 || h->ptr[0] != '<' || h->ptr[h->used-2] != '>') {
        /*(rejects value with trailing LWS, even though RFC-permitted)*/
        http_status_set_error(con, 400); /* Bad Request */
        return HANDLER_FINISHED;
    }

    buffer owner = { NULL, 0, 0 };/*owner (not authenticated)(auth_user unset)*/
    data_string * const authn_user = (data_string *)
      array_get_element_klen(con->environment, CONST_STR_LEN("REMOTE_USER"));

    webdav_lockdata lockdata = {
      { h->ptr+1, h->used-2, 0 }, /* locktoken (remove < > around token) */
      { con->physical.rel_path->ptr,con->physical.rel_path->used,0},/*lockroot*/
      { NULL, 0, 0 }, /* ownerinfo (unused for unlock) */
      (authn_user ? authn_user->value : &owner), /* owner */
      NULL, /* lockscope (unused for unlock) */
      NULL, /* locktype  (unused for unlock) */
      0,    /* depth     (unused for unlock) */
      0     /* timeout   (unused for unlock) */
    };

    /* check URI (lockroot) and depth in scope for locktoken and authorized */
    switch (webdav_lock_match(pconf, &lockdata)) {
      case  0:
        if (webdav_lock_release(pconf, &lockdata)) {
            http_status_set_fin(con, 204); /* No Content */
            return HANDLER_FINISHED;
        }
        /* fall through */
      default:
      case -1: /* lock does not exist */
      case -2: /* URI not in scope of locktoken and depth */
        /* 409 Conflict */
        webdav_xml_doc_error_lock_token_matches_request_uri(con);
        return HANDLER_FINISHED;
      case -3: /* not owner/not authorized to remove lock */
        http_status_set_error(con, 403); /* Forbidden */
        return HANDLER_FINISHED;
    }
}
#endif


SUBREQUEST_FUNC(mod_webdav_subrequest_handler)
{
    const plugin_config * const pconf =
      (plugin_config *)con->plugin_ctx[((plugin_data *)p_d)->id];
    if (NULL == pconf) return HANDLER_GO_ON; /*(should not happen)*/
    UNUSED(srv);

    switch (con->request.http_method) {
    case HTTP_METHOD_PROPFIND:
        return mod_webdav_propfind(con, pconf);
    case HTTP_METHOD_MKCOL:
        return mod_webdav_mkcol(con, pconf);
    case HTTP_METHOD_DELETE:
        return mod_webdav_delete(con, pconf);
    case HTTP_METHOD_PUT:
        return mod_webdav_put(con, pconf);
    case HTTP_METHOD_MOVE:
    case HTTP_METHOD_COPY:
        return mod_webdav_copymove(con, pconf);
   #ifdef USE_PROPPATCH
    case HTTP_METHOD_PROPPATCH:
        return mod_webdav_proppatch(con, pconf);
   #endif
   #ifdef USE_LOCKS
    case HTTP_METHOD_LOCK:
        return mod_webdav_lock(con, pconf);
    case HTTP_METHOD_UNLOCK:
        return mod_webdav_unlock(con, pconf);
   #endif
    default:
        http_status_set_error(con, 501); /* Not Implemented */
        return HANDLER_FINISHED;
    }
}


PHYSICALPATH_FUNC(mod_webdav_physical_handler)
{
    /* physical path is set up */
    /*assert(0 != con->physical.path->used);*/
  #ifdef __COVERITY__
    force_assert(2 <= con->physical.path->used);
  #endif

    int check_readonly = 0;
    int check_lock_src = 0;
    int reject_reqbody = 0;

    /* check for WebDAV request methods handled by this module */
    switch (con->request.http_method) {
      case HTTP_METHOD_GET:
      case HTTP_METHOD_HEAD:
      case HTTP_METHOD_POST:
      default:
        return HANDLER_GO_ON;
      case HTTP_METHOD_PROPFIND:
      case HTTP_METHOD_LOCK:
        break;
      case HTTP_METHOD_UNLOCK:
        reject_reqbody = 1;
        break;
      case HTTP_METHOD_DELETE:
      case HTTP_METHOD_MOVE:
        reject_reqbody = 1; /*(fall through)*/ __attribute_fallthrough__
      case HTTP_METHOD_PROPPATCH:
      case HTTP_METHOD_PUT:
        check_readonly = check_lock_src = 1;
        break;
      case HTTP_METHOD_COPY:
      case HTTP_METHOD_MKCOL:
        check_readonly = reject_reqbody = 1;
        break;
    }

    plugin_config pconf;
    mod_webdav_patch_connection(srv, con, (plugin_data *)p_d, &pconf);
    if (!pconf.enabled) return HANDLER_GO_ON;

    if (check_readonly && pconf.is_readonly) {
        http_status_set_error(con, 403); /* Forbidden */
        return HANDLER_FINISHED;
    }

    if (reject_reqbody && con->request.content_length) {
        /* [RFC4918] 8.4 Required Bodies in Requests
         *   Servers MUST examine all requests for a body, even when a
         *   body was not expected. In cases where a request body is
         *   present but would be ignored by a server, the server MUST
         *   reject the request with 415 (Unsupported Media Type).
         */
        http_status_set_error(con, 415); /* Unsupported Media Type */
        return HANDLER_FINISHED;
    }

    if (check_lock_src && !webdav_has_lock(con, &pconf, con->physical.rel_path))
        return HANDLER_FINISHED; /* 423 Locked */

    /* initial setup for methods */
    switch (con->request.http_method) {
      case HTTP_METHOD_PUT:
        if (mod_webdav_put_prep(con, &pconf) == HANDLER_FINISHED)
            return HANDLER_FINISHED;
        break;
      default:
        break;
    }

    con->mode = ((plugin_data *)p_d)->id;
    con->conf.stream_request_body = 0;
    con->plugin_ctx[((plugin_data *)p_d)->id] = &pconf;
    const handler_t rc =
      mod_webdav_subrequest_handler(srv, con, p_d); /*p->handle_subrequest()*/
    if (rc == HANDLER_FINISHED || rc == HANDLER_ERROR)
        con->plugin_ctx[((plugin_data *)p_d)->id] = NULL;
    else {  /* e.g. HANDLER_WAIT_FOR_RD */
        plugin_config * const save_pconf =
          (plugin_config *)malloc(sizeof(pconf));
        force_assert(save_pconf);
        memcpy(save_pconf, &pconf, sizeof(pconf));
        con->plugin_ctx[((plugin_data *)p_d)->id] = save_pconf;
    }
    return rc;
}


CONNECTION_FUNC(mod_webdav_handle_reset) {
    /* free plugin_config if allocated and saved to per-request storage */
    void ** const restrict dptr = &con->plugin_ctx[((plugin_data *)p_d)->id];
    if (*dptr) {
        free(*dptr);
        *dptr = NULL;
        chunkqueue_set_tempdirs(con->request_content_queue, /* reset sz */
                                con->request_content_queue->tempdirs, 0);
    }
    UNUSED(srv);
    return HANDLER_GO_ON;
}
