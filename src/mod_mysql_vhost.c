#include "first.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <mysql.h>

#include "base.h"
#include "plugin.h"
#include "fdevent.h"
#include "log.h"

#include "stat_cache.h"

/*
 * Plugin for lighttpd to use MySQL
 *   for domain to directory lookups,
 *   i.e virtual hosts (vhosts).
 *
 * /ada@riksnet.se 2004-12-06
 */

typedef struct {
    MYSQL *mysql;
    const buffer *mysql_query;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

typedef struct {
	buffer	*server_name;
	buffer	*document_root;
} plugin_connection_data;

INIT_FUNC(mod_mysql_vhost_init) {
    return calloc(1, sizeof(plugin_data));
}

/* cleanup the mysql connections */
FREE_FUNC(mod_mysql_vhost_cleanup) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 1: /* mysql-vhost.db */
                mysql_close(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }
}

static void* mod_mysql_vhost_connection_data(request_st * const r, void *p_d)
{
	plugin_data *p = p_d;
	plugin_connection_data *c = r->plugin_ctx[p->id];

	if (c) return c;
	c = calloc(1, sizeof(*c));
	force_assert(c);

	c->server_name = buffer_init();
	c->document_root = buffer_init();

	return r->plugin_ctx[p->id] = c;
}

REQUEST_FUNC(mod_mysql_vhost_handle_request_reset) {
	plugin_data *p = p_d;
	plugin_connection_data *c = r->plugin_ctx[p->id];

	if (!c) return HANDLER_GO_ON;

	buffer_free(c->server_name);
	buffer_free(c->document_root);

	free(c);

	r->plugin_ctx[p->id] = NULL;
	return HANDLER_GO_ON;
}

static void mod_mysql_vhost_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* mysql-vhost.sql */
        pconf->mysql_query = cpv->v.b;
        break;
      case 1: /* mysql-vhost.db */
        if (cpv->vtype == T_CONFIG_LOCAL)
            pconf->mysql = cpv->v.v;
        break;
      case 2: /* mysql-vhost.user */
      case 3: /* mysql-vhost.pass */
      case 4: /* mysql-vhost.sock */
      case 5: /* mysql-vhost.hostname */
      case 6: /* mysql-vhost.port */
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_mysql_vhost_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_mysql_vhost_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_mysql_vhost_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_mysql_vhost_merge_config(&p->conf,
                                         p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

static MYSQL * mod_mysql_vhost_db_setup (server *srv, const char *dbname, const char *user, const char *pass, const char *sock, const char *host, unsigned short port) {
    /* required:
     * - database
     * - username
     *
     * optional:
     * - password, default: empty
     * - socket, default: mysql default
     * - hostname, if set overrides socket
     * - port, default: 3306
     */

    MYSQL * const my = mysql_init(NULL);
    if (NULL == my) {
        log_error(srv->errh, __FILE__, __LINE__,
          "mysql_init() failed, exiting...");
        return NULL;
    }

  #if MYSQL_VERSION_ID >= 50013
    /* in mysql versions above 5.0.3 the reconnect flag is off by default */
    char reconnect = 1;
    mysql_options(my, MYSQL_OPT_RECONNECT, &reconnect);
  #endif

    unsigned long flags = 0;
  #if MYSQL_VERSION_ID >= 40100
    /* CLIENT_MULTI_STATEMENTS first appeared in 4.1 */
    flags |= CLIENT_MULTI_STATEMENTS;
  #endif

    if (!mysql_real_connect(my, host, user, pass, dbname, port, sock, flags)) {
        log_error(srv->errh, __FILE__, __LINE__, "%s", mysql_error(my));
        mysql_close(my);
        return NULL;
    }

    fdevent_setfd_cloexec(my->net.fd);
    return my;
}

SETDEFAULTS_FUNC(mod_mysql_vhost_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("mysql-vhost.sql"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mysql-vhost.db"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mysql-vhost.user"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mysql-vhost.pass"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mysql-vhost.sock"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mysql-vhost.hostname"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mysql-vhost.port"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    log_error(srv->errh, __FILE__, __LINE__,
      "mod_mysql_vhost is deprecated and will be removed in a future version; "
      "please migrate to use mod_vhostdb_mysql");

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_mysql_vhost"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        const char *dbname=NULL, *user=NULL, *pass=NULL, *host=NULL, *sock=NULL;
        unsigned short port = 0;
        config_plugin_value_t *db = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* mysql_vhost.sql */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.b = NULL;
                break;
              case 1: /* mysql_vhost.db */
                if (!buffer_is_blank(cpv->v.b)) {
                    db = cpv;
                    dbname = cpv->v.b->ptr;
                }
                break;
              case 2: /* mysql_vhost.user */
                if (!buffer_is_blank(cpv->v.b))
                    user = cpv->v.b->ptr;
                break;
              case 3: /* mysql_vhost.pass */
                if (!buffer_is_blank(cpv->v.b))
                    pass = cpv->v.b->ptr;
                break;
              case 4: /* mysql_vhost.sock */
                if (!buffer_is_blank(cpv->v.b))
                    sock = cpv->v.b->ptr;
                break;
              case 5: /* mysql_vhost.hostname */
                if (!buffer_is_blank(cpv->v.b))
                    host = cpv->v.b->ptr;
                break;
              case 6: /* mysql_vhost.port */
                port = cpv->v.shrt;
                break;
              default:/* should not happen */
                break;
            }
        }

        if (dbname && user) {
            cpv = db;
            cpv->v.v =
              mod_mysql_vhost_db_setup(srv,dbname,user,pass,sock,host,port);
            if (NULL == db->v.v) return HANDLER_ERROR;
            cpv->vtype = T_CONFIG_LOCAL;
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_mysql_vhost_merge_config(&p->defaults, cpv);
    }

    log_error(srv->errh, __FILE__, __LINE__,
      "Warning: mod_%s is deprecated "
      "and will be removed from a future lighttpd release in early 2022. "
      "https://wiki.lighttpd.net/Docs_ConfigurationOptions#Deprecated",
      p->self->name);

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_mysql_vhost_handle_docroot) {
	plugin_data *p = p_d;
	plugin_connection_data *c;

	unsigned  cols;
	MYSQL_ROW row;
	MYSQL_RES *result = NULL;

	/* no host specified? */
	if (buffer_is_blank(&r->uri.authority)) return HANDLER_GO_ON;

	mod_mysql_vhost_patch_config(r, p);

	if (!p->conf.mysql) return HANDLER_GO_ON;
	if (!p->conf.mysql_query) return HANDLER_GO_ON;

	/* sets up connection data if not done yet */
	c = mod_mysql_vhost_connection_data(r, p_d);

	/* check if cached this connection */
	if (buffer_is_equal(c->server_name, &r->uri.authority)) goto GO_ON;

	/* build and run SQL query */
	buffer * const b = r->tmp_buf;
	buffer_clear(b);
	for (const char *ptr = p->conf.mysql_query->ptr, *d; *ptr; ptr = d+1) {
		if (NULL != (d = strchr(ptr, '?'))) {
			/* escape the uri.authority */
			unsigned long to_len;
			buffer_append_string_len(b, ptr, (size_t)(d - ptr));
			buffer_string_prepare_append(b, buffer_clen(&r->uri.authority) * 2);
			to_len = mysql_real_escape_string(p->conf.mysql,
					b->ptr + buffer_clen(b),
					BUF_PTR_LEN(&r->uri.authority));
			if ((unsigned long)~0 == to_len) goto ERR500;
			buffer_commit(b, to_len);
		} else {
			d = p->conf.mysql_query->ptr + buffer_clen(p->conf.mysql_query);
			buffer_append_string_len(b, ptr, (size_t)(d - ptr));
			break;
		}
	}
	if (mysql_real_query(p->conf.mysql, BUF_PTR_LEN(b))) {
		log_error(r->conf.errh, __FILE__, __LINE__, "%s", mysql_error(p->conf.mysql));
		goto ERR500;
	}
	result = mysql_store_result(p->conf.mysql);
	cols = mysql_num_fields(result);
	row = mysql_fetch_row(result);
	if (!row || cols < 1) {
		/* no such virtual host */
		mysql_free_result(result);
#if MYSQL_VERSION_ID >= 40100
		while (mysql_next_result(p->conf.mysql) == 0);
#endif
		return HANDLER_GO_ON;
	}

	/* sanity check that really is a directory */
	buffer_copy_string(b, row[0]);
	buffer_append_slash(b);

	if (!stat_cache_path_isdir(b)) {
		log_perror(r->conf.errh, __FILE__, __LINE__, "%s", b->ptr);
		goto ERR500;
	}

	/* cache the data */
	buffer_copy_buffer(c->server_name, &r->uri.authority);
	buffer_copy_buffer(c->document_root, b);

	mysql_free_result(result);
#if MYSQL_VERSION_ID >= 40100
	while (mysql_next_result(p->conf.mysql) == 0);
#endif

	/* fix virtual server and docroot */
GO_ON:
	if (!buffer_is_blank(c->server_name)) {
		r->server_name = &r->server_name_buf;
		buffer_copy_buffer(&r->server_name_buf, c->server_name);
	}
	buffer_copy_buffer(&r->physical.doc_root, c->document_root);

	return HANDLER_GO_ON;

ERR500:
	if (result) mysql_free_result(result);
#if MYSQL_VERSION_ID >= 40100
	while (mysql_next_result(p->conf.mysql) == 0);
#endif
	r->http_status = 500; /* Internal Error */
	r->handler_module = NULL;
	return HANDLER_FINISHED;
}


int mod_mysql_vhost_plugin_init(plugin *p);
int mod_mysql_vhost_plugin_init(plugin *p) {
	p->version        = LIGHTTPD_VERSION_ID;
	p->name           = "mysql_vhost";

	p->init           = mod_mysql_vhost_init;
	p->cleanup        = mod_mysql_vhost_cleanup;
	p->handle_request_reset = mod_mysql_vhost_handle_request_reset;

	p->set_defaults   = mod_mysql_vhost_set_defaults;
	p->handle_docroot = mod_mysql_vhost_handle_docroot;

	return 0;
}
