#ifndef _HTTP_AUTH_H_
#define _HTTP_AUTH_H_
#include "first.h"

#include "server.h"
#include "plugin.h"

#if defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER)
# define USE_LDAP
# include <ldap.h>
#endif

typedef enum {
	AUTH_BACKEND_UNSET,
	AUTH_BACKEND_PLAIN,
	AUTH_BACKEND_LDAP,
	AUTH_BACKEND_HTPASSWD,
	AUTH_BACKEND_HTDIGEST
} auth_backend_t;

typedef struct {
	/* auth */
	array  *auth_require;

	buffer *auth_plain_groupfile;
	buffer *auth_plain_userfile;

	buffer *auth_htdigest_userfile;
	buffer *auth_htpasswd_userfile;

	buffer *auth_backend_conf;

	buffer *auth_ldap_hostname;
	buffer *auth_ldap_basedn;
	buffer *auth_ldap_binddn;
	buffer *auth_ldap_bindpw;
	buffer *auth_ldap_filter;
	buffer *auth_ldap_cafile;
	unsigned short auth_ldap_starttls;
	unsigned short auth_ldap_allow_empty_pw;

	unsigned short auth_debug;

	/* generated */
	auth_backend_t auth_backend;

#ifdef USE_LDAP
	LDAP *ldap;

	buffer *ldap_filter_pre;
	buffer *ldap_filter_post;
#endif
} mod_auth_plugin_config;

typedef struct {
	PLUGIN_DATA;
	buffer *tmp_buf;

	buffer *auth_user;

#ifdef USE_LDAP
	buffer *ldap_filter;
#endif

	mod_auth_plugin_config **config_storage;

	mod_auth_plugin_config conf, *anon_conf; /* this is only used as long as no handler_ctx is setup */
} mod_auth_plugin_data;

int http_auth_basic_password_compare(server *srv, mod_auth_plugin_data *p, buffer *username, buffer *realm, const char *pw);
int http_auth_get_password_digest(server *srv, mod_auth_plugin_data *p, const char *username, const char *realm, unsigned char HA1[16]);

#endif
