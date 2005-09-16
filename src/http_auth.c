#include "config.h"

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#elif defined(__linux__)
/* linux needs _XOPEN_SOURCE */
# define _XOPEN_SOURCE
#endif

#ifdef HAVE_LIBCRYPT
# define HAVE_CRYPT
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include "server.h"
#include "log.h"
#include "http_auth.h"
#include "http_auth_digest.h"
#include "stream.h"

#ifdef USE_OPENSSL
# include <openssl/md5.h>
#else
# include "md5_global.h"
# include "md5.h"
#endif


#ifdef USE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
	misc_conv,
		NULL
};
#endif

static const char base64_pad = '=';

static const short base64_reverse_table[256] = {
	        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
		        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
		        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
		        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};


static unsigned char * base64_decode(buffer *out, const char *in) {
	unsigned char *result;
	int ch, j = 0, k;
	size_t i;
	
	size_t in_len = strlen(in);
	
	buffer_prepare_copy(out, in_len);
	
	result = (unsigned char *)out->ptr;
	
	ch = in[0];
	/* run through the whole string, converting as we go */
	for (i = 0; i < in_len; i++) {
		ch = in[i];
		
		if (ch == '\0') break;
		
		if (ch == base64_pad) break;
		
		ch = base64_reverse_table[ch];
		if (ch < 0) continue;
		
		switch(i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >>2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
	}
	k = j;
	/* mop things up if we ended on a boundary */
	if (ch == base64_pad) {
		switch(i % 4) {
		case 0:
		case 1:
			return NULL;
		case 2:
			k++;
		case 3:
			result[k++] = 0;
		}
	}
	result[k] = '\0';
	
	out->used = k;
	
	return result;
}

static int http_auth_get_password(server *srv, mod_auth_plugin_data *p, buffer *username, buffer *realm, buffer *password) {
	int ret = -1;
	
	if (!username->used|| !realm->used) return -1;
	
	if (p->conf.auth_backend == AUTH_BACKEND_HTDIGEST) {
		stream f;
		char * f_line;
		
		if (buffer_is_empty(p->conf.auth_htdigest_userfile)) return -1;
		
		if (0 != stream_open(&f, p->conf.auth_htdigest_userfile)) {
			log_error_write(srv, __FILE__, __LINE__, "sbss", "opening digest-userfile", p->conf.auth_htdigest_userfile, "failed:", strerror(errno));
			
			return -1;
		}
		
		f_line = f.start;
		
		while (f_line - f.start != f.size) {
			char *f_user, *f_pwd, *e, *f_realm;
			size_t u_len, pwd_len, r_len;
			
			f_user = f_line;
			
			/* 
			 * htdigest format
			 * 
			 * user:realm:md5(user:realm:password) 
			 */
			
			if (NULL == (f_realm = memchr(f_user, ':', f.size - (f_user - f.start) ))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", 
						"parsed error in", p->conf.auth_htdigest_userfile, 
						"expected 'username:realm:hashed password'");
				
				stream_close(&f);
				
				return -1;
			}
			
			if (NULL == (f_pwd = memchr(f_realm + 1, ':', f.size - (f_realm + 1 - f.start)))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", 
						"parsed error in", p->conf.auth_plain_userfile, 
						"expected 'username:realm:hashed password'");
				
				stream_close(&f);
				
				return -1;
			}
			
			/* get pointers to the fields */
			u_len = f_realm - f_user; 
			f_realm++;
			r_len = f_pwd - f_realm;
			f_pwd++;
			
			if (NULL != (e = memchr(f_pwd, '\n', f.size - (f_pwd - f.start)))) {
				pwd_len = e - f_pwd;
			} else {
				pwd_len = f.size - (f_pwd - f.start);
			}
			
			if (username->used - 1 == u_len &&
			    (realm->used - 1 == r_len) &&
			    (0 == strncmp(username->ptr, f_user, u_len)) &&
			    (0 == strncmp(realm->ptr, f_realm, r_len))) {
				/* found */
				
				buffer_copy_string_len(password, f_pwd, pwd_len);
				
				ret = 0;
				break;
			}
			
			/* EOL */
			if (!e) break;
			
			f_line = e + 1;
		}
		
		stream_close(&f);
	} else if (p->conf.auth_backend == AUTH_BACKEND_HTPASSWD ||
		   p->conf.auth_backend == AUTH_BACKEND_PLAIN) {
		stream f;
		char * f_line;
		buffer *auth_fn;
		
		auth_fn = (p->conf.auth_backend == AUTH_BACKEND_HTPASSWD) ? p->conf.auth_htpasswd_userfile : p->conf.auth_plain_userfile;
		
		if (buffer_is_empty(auth_fn)) return -1;
		
		if (0 != stream_open(&f, auth_fn)) {
			log_error_write(srv, __FILE__, __LINE__, "sbss", 
					"opening plain-userfile", auth_fn, "failed:", strerror(errno));
			
			return -1;
		}
		
		f_line = f.start;
		
		while (f_line - f.start != f.size) {
			char *f_user, *f_pwd, *e;
			size_t u_len, pwd_len;
			
			f_user = f_line;
			
			/* 
			 * htpasswd format
			 * 
			 * user:crypted passwd
			 */
			
			if (NULL == (f_pwd = memchr(f_user, ':', f.size - (f_user - f.start) ))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", 
						"parsed error in", auth_fn, 
						"expected 'username:hashed password'");
				
				stream_close(&f);
				
				return -1;
			}
			
			/* get pointers to the fields */
			u_len = f_pwd - f_user; 
			f_pwd++;
			
			if (NULL != (e = memchr(f_pwd, '\n', f.size - (f_pwd - f.start)))) {
				pwd_len = e - f_pwd;
			} else {
				pwd_len = f.size - (f_pwd - f.start);
			}
			
			if (username->used - 1 == u_len &&
			    (0 == strncmp(username->ptr, f_user, u_len))) {
				/* found */
				
				buffer_copy_string_len(password, f_pwd, pwd_len);
				
				ret = 0;
				break;
			}
			
			/* EOL */
			if (!e) break;
			
			f_line = e + 1;
		}
		
		stream_close(&f);
	} else if (p->conf.auth_backend == AUTH_BACKEND_LDAP) {
		ret = 0;
	} else {
		return -1;
	}
	
	return ret;
}

static int http_auth_match_rules(server *srv, mod_auth_plugin_data *p, const char *url, const char *username, const char *group, const char *host) {
	const char *r = NULL, *rules = NULL;
	size_t i;
	int username_len;
	data_string *require;
	array *req;
	
	UNUSED(group);
	UNUSED(host);

	/* check what has to be match to fullfil the request */
	/* search auth-directives for path */
	for (i = 0; i < p->conf.auth_require->used; i++) {
		if (p->conf.auth_require->data[i]->key->used == 0) continue;
		
		if (0 == strncmp(url, p->conf.auth_require->data[i]->key->ptr, p->conf.auth_require->data[i]->key->used - 1)) {
			break;
		}
	}
	
	if (i == p->conf.auth_require->used) {
		return -1;
	}

	req = ((data_array *)(p->conf.auth_require->data[i]))->value;

	require = (data_string *)array_get_element(req, "require");
	
	/* if we get here, the user we got a authed user */
	if (0 == strcmp(require->value->ptr, "valid-user")) {
		return 0;
	}
	
	/* user=name1|group=name3|host=name4 */
	
	/* seperate the string by | */
#if 0
	log_error_write(srv, __FILE__, __LINE__, "sb", "rules", require->value);
#endif	
	
	username_len = username ? strlen(username) : 0;
	
	r = rules = require->value->ptr;
	
	while (1) {
		const char *eq;
		const char *k, *v, *e;
		int k_len, v_len, r_len;
		
		e = strchr(r, '|');
		
		if (e) {
			r_len = e - r;
		} else {
			r_len = strlen(rules) - (r - rules);
		}
		
		/* from r to r + r_len is a rule */
		
		if (0 == strncmp(r, "valid-user", r_len)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "valid-user cannot be combined with other require rules");
			return -1;
		}
		
		/* search for = in the rules */
		if (NULL == (eq = strchr(r, '='))) {
			log_error_write(srv, __FILE__, __LINE__, "s", "= is missing");
			return -1;
		}
		
		/* = out of range */
		if (eq > r + r_len) {
			log_error_write(srv, __FILE__, __LINE__, "s", "= out of range");
			
			return -1;
		}
		
		/* the part before the = is user|group|host */
		
		k = r;
		k_len = eq - r;
		v = eq + 1;
		v_len = r_len - k_len - 1;
		
		if (k_len == 4) {
			if (0 == strncmp(k, "user", k_len)) {
				if (username && 
				    username_len == v_len &&
				    0 == strncmp(username, v, v_len)) {
					return 0;
				}
			} else if (0 == strncmp(k, "host", k_len)) {
				log_error_write(srv, __FILE__, __LINE__, "s", "host ... (not implemented)");
			} else {
				log_error_write(srv, __FILE__, __LINE__, "s", "unknown key");
				return -1;
			}
		} else if (k_len == 5) {
			if (0 == strncmp(k, "group", k_len)) {
				log_error_write(srv, __FILE__, __LINE__, "s", "group ... (not implemented)");
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ss", "unknown key", k);
				return -1;
			}
		} else {
			log_error_write(srv, __FILE__, __LINE__, "s", "unknown  key");
			return -1;
		}
		
		if (!e) break;
		r = e + 1;
	}
	
	log_error_write(srv, __FILE__, __LINE__, "s", "nothing matched");
	
	return -1;
}

/**
 * 
 * 
 * @param password password-string from the auth-backend
 * @param pw       password-string from the client
 */

static int http_auth_basic_password_compare(server *srv, mod_auth_plugin_data *p, array *req, buffer *username, buffer *realm, buffer *password, const char *pw) {
	UNUSED(srv);
	UNUSED(req);

	if (p->conf.auth_backend == AUTH_BACKEND_HTDIGEST) {
		/* 
		 * htdigest format
		 * 
		 * user:realm:md5(user:realm:password) 
		 */
		
		MD5_CTX Md5Ctx;
		HASH HA1;
		char a1[256];
		
		MD5_Init(&Md5Ctx);
		MD5_Update(&Md5Ctx, (unsigned char *)username->ptr, username->used - 1);
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)realm->ptr, realm->used - 1);
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)pw, strlen(pw));
		MD5_Final(HA1, &Md5Ctx);
		
		CvtHex(HA1, a1);
		
		if (0 == strcmp(password->ptr, a1)) {
			return 0;
		}
	} else if (p->conf.auth_backend == AUTH_BACKEND_HTPASSWD) { 
#ifdef HAVE_CRYPT	
		char salt[32];
		char *crypted;
		size_t salt_len = 0;
		/* 
		 * htpasswd format
		 * 
		 * user:crypted password
		 */

		/* 
		 *  Algorithm      Salt
		 *  CRYPT_STD_DES   2-character (Default)
		 *  CRYPT_EXT_DES   9-character
		 *  CRYPT_MD5       12-character beginning with $1$
		 *  CRYPT_BLOWFISH  16-character beginning with $2$
		 */

		if (password->used < 13 + 1) {
			fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
			return -1;
		}

		if (password->used == 13 + 1) {
			/* a simple DES password is 2 + 11 characters */
			salt_len = 2;
		} else if (password->ptr[0] == '$' && password->ptr[2] == '$') {
			char *dollar = NULL;
		
			if (NULL == (dollar = strchr(password->ptr + 3, '$'))) {
				fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
				return -1;
			}

			salt_len = dollar - password->ptr;
		}

		if (salt_len - 1 > sizeof(salt)) {
			fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
			return -1;
		}

		strncpy(salt, password->ptr, salt_len);

		salt[salt_len] = '\0';
		
		crypted = crypt(pw, salt);

		if (0 == strcmp(password->ptr, crypted)) {
			return 0;
		} else {
			fprintf(stderr, "%s.%d\n", __FILE__, __LINE__);
		}
	
#endif	
	} else if (p->conf.auth_backend == AUTH_BACKEND_PLAIN) { 
		if (0 == strcmp(password->ptr, pw)) {
			return 0;
		}
	} else if (p->conf.auth_backend == AUTH_BACKEND_PAM) { 
#ifdef USE_PAM
		pam_handle_t *pamh=NULL;
		int retval;
		
		retval = pam_start("lighttpd", username->ptr, &conv, &pamh);
		
		if (retval == PAM_SUCCESS)
			retval = pam_authenticate(pamh, 0);    /* is user really user? */
		
		if (retval == PAM_SUCCESS)
			retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */
		
		/* This is where we have been authorized or not. */
		
		if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
			pamh = NULL;
			log_error_write(srv, __FILE__, __LINE__, "s", "failed to release authenticator");
		}
		
		if (retval == PAM_SUCCESS) {
			log_error_write(srv, __FILE__, __LINE__, "s", "Authenticated");
			return 0;
		} else {
			log_error_write(srv, __FILE__, __LINE__, "s", "Not Authenticated");
		}
#endif
	} else if (p->conf.auth_backend == AUTH_BACKEND_LDAP) { 
#ifdef USE_LDAP
		LDAP *ldap;
		LDAPMessage *lm, *first;
		char *dn;
		int ret;
		char *attrs[] = { LDAP_NO_ATTRS, NULL };
		size_t i;
		
		/* for now we stay synchronous */
		
		/* 
		 * 1. connect anonymously (done in plugin init)
		 * 2. get DN for uid = username
		 * 3. auth against ldap server
		 * 4. (optional) check a field
		 * 5. disconnect
		 * 
		 */
		
		/* check username
		 * 
		 * we have to protect us againt username which modifies out filter in
		 * a unpleasant way
		 */
		
		for (i = 0; i < username->used - 1; i++) {
			char c = username->ptr[i];
			
			if (!isalpha(c) &&
			    !isdigit(c)) {
				
				log_error_write(srv, __FILE__, __LINE__, "sbd", 
					"ldap: invalid character (a-zA-Z0-9 allowed) in username:", username, i);
				
				return -1;
			}
		}
		
		
		
		/* build filter */
		buffer_copy_string_buffer(p->ldap_filter, p->conf.ldap_filter_pre);
		buffer_append_string_buffer(p->ldap_filter, username);
		buffer_append_string_buffer(p->ldap_filter, p->conf.ldap_filter_post);
		
		
		/* 2. */
		if (LDAP_SUCCESS != (ret = ldap_search_s(p->conf.ldap, p->conf.auth_ldap_basedn->ptr, LDAP_SCOPE_SUBTREE, p->ldap_filter->ptr, attrs, 0, &lm))) {
			log_error_write(srv, __FILE__, __LINE__, "sssb", 
					"ldap:", ldap_err2string(ret), "filter:", p->ldap_filter);
			
			return -1;
		}
		
		if (NULL == (first = ldap_first_entry(p->conf.ldap, lm))) {
			log_error_write(srv, __FILE__, __LINE__, "s", "ldap ...");
			
			ldap_msgfree(lm);
			
			return -1;
		}
		
		if (NULL == (dn = ldap_get_dn(p->conf.ldap, first))) {
			log_error_write(srv, __FILE__, __LINE__, "s", "ldap ...");
			
			ldap_msgfree(lm);
			
			return -1;
		}
		
		ldap_msgfree(lm);
		
		
		/* 3. */
		if (NULL == (ldap = ldap_init(p->conf.auth_ldap_hostname->ptr, LDAP_PORT))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "ldap ...", strerror(errno));
			return -1;
		}
		
		ret = LDAP_VERSION3;
		if (LDAP_OPT_SUCCESS != (ret = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ret))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));
			
			ldap_unbind_s(ldap);
			
			return -1;
		}
		
		if (p->conf.auth_ldap_starttls == 1) {
	 		if (LDAP_OPT_SUCCESS != (ret = ldap_start_tls_s(ldap, NULL,  NULL))) {
	 			log_error_write(srv, __FILE__, __LINE__, "ss", "ldap startTLS failed:", ldap_err2string(ret));
		
				ldap_unbind_s(ldap);
				
				return -1;
	 		}
 		}

		
		if (LDAP_SUCCESS != (ret = ldap_simple_bind_s(ldap, dn, pw))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "ldap:", ldap_err2string(ret));
			
			ldap_unbind_s(ldap);
			
			return -1;
		}
		
		/* 5. */
		ldap_unbind_s(ldap);
		
		/* everything worked, good, access granted */
		
		return 0;
#endif
	}
	return -1;
}

int http_auth_basic_check(server *srv, connection *con, mod_auth_plugin_data *p, array *req, buffer *url, const char *realm_str) {
	buffer *username, *password;
	char *pw;
	
	data_string *realm;
	
	realm = (data_string *)array_get_element(req, "realm");
	
	username = buffer_init();
	password = buffer_init();
	
	base64_decode(username, realm_str);
	
	/* r2 == user:password */
	if (NULL == (pw = strchr(username->ptr, ':'))) {
		buffer_free(username);
		
		log_error_write(srv, __FILE__, __LINE__, "sb", ": is missing in", username);
		
		return 0;
	}
	
	*pw++ = '\0';
	
	username->used = pw - username->ptr;
	
	/* copy password to r1 */
	if (http_auth_get_password(srv, p, username, realm->value, password)) {
		buffer_free(username);
		buffer_free(password);
		
		log_error_write(srv, __FILE__, __LINE__, "s", "get_password failed");
		
		return 0;
	}
	
	/* password doesn't match */
	if (http_auth_basic_password_compare(srv, p, req, username, realm->value, password, pw)) {
		log_error_write(srv, __FILE__, __LINE__, "sbb", "password doesn't match for", con->uri.path, username);
		
		buffer_free(username);
		buffer_free(password);
		
		return 0;
	}
	
	/* value is our allow-rules */
	if (http_auth_match_rules(srv, p, url->ptr, username->ptr, NULL, NULL)) {
		buffer_free(username);
		buffer_free(password);
		
		log_error_write(srv, __FILE__, __LINE__, "s", "rules didn't match");
		
		return 0;
	}
	
	/* remember the username */
	buffer_copy_string_buffer(p->auth_user, username);
	
	buffer_free(username);
	buffer_free(password);
	
	return 1;
}

typedef struct {
	const char *key;
	int key_len;
	char **ptr;
} digest_kv;

int http_auth_digest_check(server *srv, connection *con, mod_auth_plugin_data *p, array *req, buffer *url, const char *realm_str) {
	char a1[256];
	char a2[256];
	
	char *username;
	char *realm;
	char *nonce;
	char *uri;
	char *algorithm;
	char *qop;
	char *cnonce;
	char *nc;
	char *respons;
	
	char *e, *c;
	const char *m = NULL;
	int i;
	buffer *password, *b, *username_buf, *realm_buf;
	
	MD5_CTX Md5Ctx;
	HASH HA1;
	HASH HA2;
	HASH RespHash;
	HASHHEX HA2Hex;
	

	/* init pointers */
#define S(x) \
	x, sizeof(x)-1, NULL
	digest_kv dkv[10] = {
		{ S("username=") },
		{ S("realm=") },
		{ S("nonce=") },
		{ S("uri=") },
		{ S("algorithm=") },
		{ S("qop=") },
		{ S("cnonce=") },
		{ S("nc=") },
		{ S("response=") },
		
		{ NULL, 0, NULL }
	};
#undef S
	
	dkv[0].ptr = &username;
	dkv[1].ptr = &realm;
	dkv[2].ptr = &nonce;
	dkv[3].ptr = &uri;
	dkv[4].ptr = &algorithm;
	dkv[5].ptr = &qop;
	dkv[6].ptr = &cnonce;
	dkv[7].ptr = &nc;
	dkv[8].ptr = &respons;
	dkv[9].ptr = NULL;
	
	UNUSED(req);
	
	for (i = 0; dkv[i].key; i++) {
		*(dkv[i].ptr) = NULL;
	}
	
	
	if (p->conf.auth_backend != AUTH_BACKEND_HTDIGEST &&
	    p->conf.auth_backend != AUTH_BACKEND_PLAIN) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"digest: unsupported backend (only htdigest or plain)");
		
		return -1;
	}
	
	b = buffer_init_string(realm_str);
	
	/* parse credentials from client */
	for (c = b->ptr; *c; c++) {
		for (i = 0; dkv[i].key; i++) {
			if ((0 == strncmp(c, dkv[i].key, dkv[i].key_len))) {
				if ((c[dkv[i].key_len] == '"') && 
				    (NULL != (e = strchr(c + dkv[i].key_len + 1, '"')))) {
					/* value with "..." */
					*(dkv[i].ptr) = c + dkv[i].key_len + 1;
					c = e;
	
					*e = '\0';
				} else if (NULL != (e = strchr(c + dkv[i].key_len, ','))) {
					/* value without "...", terminated by ',' */
					*(dkv[i].ptr) = c + dkv[i].key_len;
					c = e;
					
					*e = '\0';
				} else {
					/* value without "...", terminated by EOL */
					*(dkv[i].ptr) = c + dkv[i].key_len;
					c += strlen(c) - 1;
				}
			}
		}
	}
	
	if (p->conf.auth_debug > 1) {
		log_error_write(srv, __FILE__, __LINE__, "ss", "username", username);
		log_error_write(srv, __FILE__, __LINE__, "ss", "realm", realm);
		log_error_write(srv, __FILE__, __LINE__, "ss", "nonce", nonce);
		log_error_write(srv, __FILE__, __LINE__, "ss", "uri", uri);
		log_error_write(srv, __FILE__, __LINE__, "ss", "algorigthm", algorithm);
		log_error_write(srv, __FILE__, __LINE__, "ss", "qop", qop);
		log_error_write(srv, __FILE__, __LINE__, "ss", "cnonce", cnonce);
		log_error_write(srv, __FILE__, __LINE__, "ss", "nc", nc);
		log_error_write(srv, __FILE__, __LINE__, "ss", "response", respons);
	}
	
	/* check if everything is transmitted */
	if (!username || 
	    !realm ||
	    !nonce ||
	    !uri ||
	    (qop && !nc && !cnonce) ||
	    !respons ) {
		/* missing field */
		
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"digest: missing field");
		return -1;
	}

	m = get_http_method_name(con->request.http_method);	

	/* password-string == HA1 */
	password = buffer_init();
	username_buf = buffer_init_string(username);
	realm_buf = buffer_init_string(realm);
	if (http_auth_get_password(srv, p, username_buf, realm_buf, password)) {
		buffer_free(password);
		buffer_free(b);
		buffer_free(username_buf);
		buffer_free(realm_buf);
		return 0;
	}
	
	buffer_free(username_buf);
	buffer_free(realm_buf);
	
	if (p->conf.auth_backend == AUTH_BACKEND_PLAIN) {
		/* generate password from plain-text */
		MD5_Init(&Md5Ctx);
		MD5_Update(&Md5Ctx, (unsigned char *)username, strlen(username));
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)realm, strlen(realm));
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)password->ptr, password->used - 1);
		MD5_Final(HA1, &Md5Ctx);
	} else if (p->conf.auth_backend == AUTH_BACKEND_HTDIGEST) {
		/* HA1 */
		/* transform the 32-byte-hex-md5 to a 16-byte-md5 */
		for (i = 0; i < HASHLEN; i++) {
			HA1[i] = hex2int(password->ptr[i*2]) << 4; 
			HA1[i] |= hex2int(password->ptr[i*2+1]); 
		}
	} else {
		/* we already check that above */
		SEGFAULT();
	}
	
	buffer_free(password);
	
	if (algorithm &&
	    strcasecmp(algorithm, "md5-sess") == 0) {
		MD5_Init(&Md5Ctx);
		MD5_Update(&Md5Ctx, (unsigned char *)HA1, 16);
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)nonce, strlen(nonce));
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)cnonce, strlen(cnonce));
		MD5_Final(HA1, &Md5Ctx);
	}
	
	CvtHex(HA1, a1);
	
	/* calculate H(A2) */
	MD5_Init(&Md5Ctx);
	MD5_Update(&Md5Ctx, (unsigned char *)m, strlen(m));
	MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
	MD5_Update(&Md5Ctx, (unsigned char *)uri, strlen(uri));
	if (qop && strcasecmp(qop, "auth-int") == 0) {
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)"", HASHHEXLEN);
	}
	MD5_Final(HA2, &Md5Ctx);
	CvtHex(HA2, HA2Hex);
	
	/* calculate response */
	MD5_Init(&Md5Ctx);
	MD5_Update(&Md5Ctx, (unsigned char *)a1, HASHHEXLEN);
	MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
	MD5_Update(&Md5Ctx, (unsigned char *)nonce, strlen(nonce));
	MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
	if (qop && *qop) {
		MD5_Update(&Md5Ctx, (unsigned char *)nc, strlen(nc));
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)cnonce, strlen(cnonce));
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
		MD5_Update(&Md5Ctx, (unsigned char *)qop, strlen(qop));
		MD5_Update(&Md5Ctx, (unsigned char *)":", 1);
	};
	MD5_Update(&Md5Ctx, (unsigned char *)HA2Hex, HASHHEXLEN);
	MD5_Final(RespHash, &Md5Ctx);
	CvtHex(RespHash, a2);
	
	if (0 != strcmp(a2, respons)) {
		/* digest not ok */
		
		if (p->conf.auth_debug) {
			log_error_write(srv, __FILE__, __LINE__, "sss", 
				"digest: digest mismatch", a2, respons);
		}
		
		log_error_write(srv, __FILE__, __LINE__, "sss", 
				"digest: auth failed for", username, "wrong password");
		
		buffer_free(b);
		return 0;
	}
	
	/* value is our allow-rules */
	if (http_auth_match_rules(srv, p, url->ptr, username, NULL, NULL)) {
		buffer_free(b);
		
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"digest: rules did match");
		
		return 0;
	}
	
	/* remember the username */
	buffer_copy_string(p->auth_user, username);
	
	buffer_free(b);
	
	if (p->conf.auth_debug) {
		log_error_write(srv, __FILE__, __LINE__, "s", 
				"digest: auth ok");
	}
	return 1;
}


int http_auth_digest_generate_nonce(server *srv, mod_auth_plugin_data *p, buffer *fn, char out[33]) {
	HASH h;
	MD5_CTX Md5Ctx;
	char hh[32];
	
	UNUSED(p);

	/* generate shared-secret */
	MD5_Init(&Md5Ctx);
	MD5_Update(&Md5Ctx, (unsigned char *)fn->ptr, fn->used - 1);
	MD5_Update(&Md5Ctx, (unsigned char *)"+", 1);
	
	/* we assume sizeof(time_t) == 4 here, but if not it ain't a problem at all */
	ltostr(hh, srv->cur_ts);
	MD5_Update(&Md5Ctx, (unsigned char *)hh, strlen(hh));
	ltostr(hh, rand());
	MD5_Update(&Md5Ctx, (unsigned char *)hh, strlen(hh));
	
	MD5_Final(h, &Md5Ctx);
	
	CvtHex(h, out);
	
	return 0;
}
